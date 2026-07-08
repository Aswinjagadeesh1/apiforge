"""API2:2023 — Broken Authentication via weak JWT signing secret.

Logic:
  1. Take an authenticated user's HS256 JWT.
  2. Attempt to verify its signature against a list of common weak secrets.
  3. If any secret validates the token, the signing key is guessable — an
     attacker can forge tokens for any user (including admins).

This is a purely local/offline crack against the token we already hold; it does
not brute-force the live server, so it is safe and fast.
"""
from __future__ import annotations

from typing import Optional

import jwt  # PyJWT

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

# Common weak secrets seen in real APIs, CTFs, and default configs.
WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "admin", "test",
    "jwt", "jwtsecret", "jwt_secret", "key", "private", "mysecret",
    "crapi", "crAPI", "supersecret", "secretkey", "your-256-bit-secret",
    "qwerty", "letmein", "default", "token", "auth", "signature",
    "s3cr3t", "password123", "root", "master", "0000", "1234",
]


class JWTWeakSecretCheck(BaseCheck):
    check_id = "API2_JWT_WEAK_SECRET"
    name = "Broken Authentication — Weak JWT Signing Secret"
    owasp_category = "API2:2023 Broken Authentication"
    cwe = "CWE-326"
    severity = Severity.CRITICAL
    cvss_score = 9.1

    _reported = False  # only report once per scan (token-level, not per-endpoint)

    def is_applicable(self, endpoint: Endpoint) -> bool:
        # This is a token property, not an endpoint property. We only need to
        # run it once, so apply to the first GET endpoint we see.
        return endpoint.method == "GET" and not self._reported

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user = sessions.get("user_a")
        if not (user and user.authenticated and user.token):
            return None

        token = user.token

        # Only HS-family (symmetric) tokens use a crackable secret.
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            return None
        alg = header.get("alg", "")
        if not alg.startswith("HS"):
            return None  # RS/ES tokens use key pairs, not a shared secret

        cracked: Optional[str] = None
        for secret in WEAK_SECRETS:
            try:
                jwt.decode(token, secret, algorithms=[alg])
                cracked = secret
                break
            except jwt.InvalidSignatureError:
                continue
            except jwt.PyJWTError:
                # signature might match but claims (exp, etc.) fail — that still
                # means the SECRET is correct, so treat as cracked.
                try:
                    jwt.decode(
                        token, secret, algorithms=[alg],
                        options={"verify_exp": False, "verify_aud": False},
                    )
                    cracked = secret
                    break
                except jwt.InvalidSignatureError:
                    continue
                except jwt.PyJWTError:
                    continue

        if cracked is None:
            self._reported = True  # don't retry on every endpoint
            return None

        self._reported = True
        return self._finding(
            endpoint=endpoint,
            description=(
                f"The API signs JWTs using the {alg} algorithm with a weak, "
                f"guessable secret ('{cracked}'). An attacker who guesses this "
                f"secret can forge valid tokens for any user, including "
                f"administrators, resulting in a complete authentication bypass."
            ),
            poc_request=(
                f"Offline signature crack against a valid {alg} token.\n"
                f"Recovered secret: {cracked!r}\n"
                f"An attacker can now sign arbitrary tokens with this key."
            ),
            poc_response=(
                f"Token signature validated with secret {cracked!r}."
            ),
            remediation=(
                "Use a long, high-entropy, randomly-generated signing secret "
                "(at least 256 bits) stored securely outside the codebase. "
                "Rotate the secret if it may have been exposed. Consider "
                "asymmetric algorithms (RS256) so the signing key never leaves "
                "the auth server."
            ),
        )

