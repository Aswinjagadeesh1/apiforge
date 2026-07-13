# APIForge

**Automated OWASP API Top 10 vulnerability detection from Postman collections and OpenAPI/Swagger specs.**

APIForge takes an API description (a Postman collection *or* an OpenAPI/Swagger file) plus test-user credentials, authenticates the users, runs a suite of OWASP API Top 10 security checks across every endpoint, and produces a pentest-ready Excel report — turning hours of manual API testing into a single command.

Fully local. No cloud. No telemetry. Open source (Apache 2.0).

## Highlights

- **Two input formats** — Postman Collection v2.1 *and* OpenAPI/Swagger (2.0 & 3.x), auto-detected.
- **Multi-user, stateful testing** — authenticates two regular users (and optionally an admin) to detect real authorization flaws (BOLA, BFLA, privilege escalation).
- **9 checks across 5 OWASP API categories** (API1-API5).
- **Role-aware privilege escalation** — admin baseline + path heuristics + content verification to keep findings trustworthy.
- **Configurable, not hardcoded** — login field, password field, auth header/scheme, BOLA identifier/owner fields, and optional admin role are all set via config, so new APIs need config changes, not code changes.
- **Pentest-shaped output** — Excel report with severity, CVSS, CWE, OWASP category, PoC request/response, and remediation.
- **Low false positives** — every check verifies a baseline (and, where relevant, response content) before reporting.

## Checks implemented

| Check | OWASP | CWE | Severity | What it does |
|---|---|---|---|---|
| BOLA (numeric ID) | API1:2023 | CWE-639 | HIGH | Swaps a numeric object ID between two users |
| BOLA (dynamic discovery) | API1:2023 | CWE-639 | HIGH | Discovers object IDs from list endpoints, tests cross-user access |
| BFLA (admin functions) | API5:2023 | CWE-285 | HIGH | Reaches admin-like endpoints as a regular user |
| Privilege Escalation (role-aware) | API5:2023 | CWE-285 | HIGH | Uses an admin baseline to confirm a regular user performs admin-capable actions with real data |
| Mass Assignment | API3:2023 | CWE-915 | HIGH | Injects isAdmin/role and checks acceptance |
| Sensitive Data Exposure | API3:2023 | CWE-200 | MEDIUM | Flags secret/PII fields in responses |
| JWT alg:none | API2:2023 | CWE-347 | CRITICAL | Forges an unsigned token; flags if accepted |
| JWT weak secret | API2:2023 | CWE-326 | CRITICAL | Brute-forces HS256 secrets against a wordlist |
| Rate Limiting | API4:2023 | CWE-307 | MEDIUM | Bursts sensitive endpoints, flags missing throttling |

The check engine is plugin-based (apiforge/checks/base.py) — a new check is one class plus a line in apiforge/checks/__init__.py.

## Install

```bash
git clone https://github.com/NishanthGE/apiforge.git
cd apiforge
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Quick start

1. Describe your users in a JSON config (users.json):

```json
{
  "login_endpoint": "/identity/api/auth/login",
  "token_json_path": "token",
  "user_a": { "email": "usera@test.com", "password": "Password123!" },
  "user_b": { "email": "userb@test.com", "password": "Password123!" }
}
```

2. Run the scan:

```bash
apiforge -c api.postman.json -u users.json -b http://localhost:8888 -o report.xlsx --json report.json
```

APIForge auto-detects whether -c is a Postman collection or an OpenAPI/Swagger spec.

## Configuration reference

All per-API behavior lives in the users config, so different APIs are handled by editing config, not code.

| Field | Purpose | Default |
|---|---|---|
| login_endpoint | Path appended to base URL for login | (required) |
| token_json_path | Dotted path to the token in the login response | auto-detected |
| login_field | Identity field name (email, username, user, ...) | email |
| password_field | Password field name (password, pass, ...) | password |
| auth_header | Header used to send the token | Authorization |
| auth_scheme | Scheme prefix (Bearer, or "" for a raw token) | Bearer |
| bola_id_fields | Identifier field names for dynamic BOLA | common defaults |
| bola_owner_field | Field indicating object ownership | user |
| user_a, user_b | Two regular test accounts | (required) |
| user_admin | Optional admin account — enables role-aware privilege escalation | none |

### Enabling role-aware privilege escalation

Add an admin account to the config. When present, APIForge logs it in and, for each admin-looking endpoint, confirms whether a regular user can perform the same action and receive privileged data:

```json
{
  "login_endpoint": "/identity/api/auth/login",
  "token_json_path": "token",
  "user_a": { "email": "usera@test.com", "password": "Password123!" },
  "user_b": { "email": "userb@test.com", "password": "Password123!" },
  "user_admin": { "email": "admin@example.com", "password": "Admin!123" }
}
```

The escalation check flags an endpoint only when all hold: the admin can use it, an unauthenticated request is rejected, a regular user can also use it, and the regular user receives non-empty (privileged) data. This three-way comparison plus content check keeps false positives near zero.

### Example — an API using username + custom header (e.g. Pixi)

```json
{
  "login_endpoint": "/api/login",
  "token_json_path": "token",
  "login_field": "user",
  "password_field": "pass",
  "auth_header": "x-access-token",
  "auth_scheme": "",
  "user_a": { "user": "test1@test.com", "password": "Password1!" },
  "user_b": { "user": "test2@test.com", "password": "Password1!" }
}
```

## Validated against

- **OWASP crAPI** (Postman) — RS256 JWT, complex microservices; role-aware escalation tested with the seeded admin account
- **VAmPI** (Postman) — lightweight Flask API, HS256 JWT, clear object ownership (dynamic BOLA fires here)
- **OWASP Pixi** (OpenAPI/Swagger) — MEAN stack, x-access-token auth

A bundled mock server gives a zero-setup demo:

```bash
python -m samples.vuln_server
apiforge -c samples/vulnshop.postman.json -u samples/users.json -b http://localhost:8899 -o report.xlsx
```

## Methodology

Every check follows a baseline -> attack -> compare pattern: establish legitimate behaviour, send the malicious/unauthorized request, and only report when the API behaves incorrectly relative to the baseline. This evidence-based approach is what keeps false positives low. APIForge performs dynamic (DAST) testing against a running API and focuses on the authentication and authorization flaws that cause most real-world API breaches.

## Architecture

```
input (postman OR openapi) --> Parser --> [Endpoints]
users.json --> Authenticator --> {user_a, user_b, admin? sessions}
                                     |
                       Scanner <-----+
                         |  for each (endpoint, applicable check):
                         |      check.run(endpoint, sessions, executor)
                         v
                      [Findings] --> Reporter --> report.xlsx / report.json
```

- parser/postman.py — Postman v2.1 parsing + variable resolution
- parser/openapi.py — OpenAPI/Swagger 2.0 & 3.x parsing
- auth/jwt_auth.py — login + flexible identity/password fields + token extraction
- executor/http_executor.py — shared async HTTP client with configurable auth header
- checks/ — one file per security check (plugin-based)
- scanner.py — runs applicable checks across endpoints, deduplicates findings
- reporter/report.py — Excel + JSON output
- cli.py — command-line interface, format auto-detection, config wiring

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

## Roadmap

- Pre-request script handling (for collections that set tokens/IDs dynamically)
- Additional checks: CORS misconfiguration, SSRF, verbose errors, improper inventory
- Response-content diffing for even more precise authorization findings
- Word/PDF report export and an executive-summary sheet
- OAuth 2.0 and API-key authentication flows

## License

Apache License 2.0 — see LICENSE.
