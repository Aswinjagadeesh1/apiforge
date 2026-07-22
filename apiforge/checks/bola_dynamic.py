"""API1:2023 — BOLA via dynamic ID discovery (config-driven).

Approach:
  1. Call a list-style GET endpoint as User A.
  2. From the list, find objects owned by User A (via an owner field) and
     extract their identifiers (via configurable id fields).
  3. Build the detail path (list path + /{identifier}).
  4. Confirm User A can read it, then have User B request the same object.
  5. If User B receives User A's object, object-level auth is broken.

Identifier field names and the owner field are CONFIGURABLE (read from the
users config), so this works on any API without code changes:

    "bola_id_fields": ["id", "_id", "book_title", "username", "title"],
    "bola_owner_field": "user"

Defaults cover common cases if the config omits them.
"""
from __future__ import annotations

from typing import Any, Optional

from apiforge.checks.base import BaseCheck
from apiforge.executor.http_executor import HttpExecutor
from apiforge.models import Endpoint, Finding, Severity, UserSession

# Class-level config, populated by the CLI before scanning (see cli.py).
DEFAULT_ID_FIELDS = ["id", "_id", "uuid", "order_id", "user_id",
                     "vehicle_id", "book_title", "title", "username", "name", "slug"]
DEFAULT_OWNER_FIELD = "user"


def _find_owned_objects(data: Any, owner_field: str, owner_value: str,
                        id_fields: list[str]) -> list[str]:
    """Return identifiers of objects whose owner_field == owner_value."""
    found: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            # Is this dict an object owned by our user?
            owner = obj.get(owner_field)
            if owner is not None and str(owner) == str(owner_value):
                for f in id_fields:
                    if f in obj and isinstance(obj[f], (str, int)):
                        found.append(str(obj[f]))
                        break
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(data)
    return found


class BolaDynamicCheck(BaseCheck):
    check_id = "API1_BOLA_DYNAMIC"
    name = "BOLA via Dynamic ID Discovery"
    owasp_category = "API1:2023 Broken Object Level Authorization"
    cwe = "CWE-639"
    severity = Severity.HIGH
    cvss_score = 7.5

    # Set by the CLI from config; fall back to defaults.
    id_fields: list[str] = DEFAULT_ID_FIELDS
    owner_field: str = DEFAULT_OWNER_FIELD

    def is_applicable(self, endpoint: Endpoint) -> bool:
        if endpoint.method != "GET":
            return False
        last = endpoint.path.rstrip("/").split("/")[-1]
        return not (last.isdigit() or "{" in last)

    async def run(
        self,
        endpoint: Endpoint,
        sessions: dict[str, UserSession],
        executor: HttpExecutor,
    ) -> Optional[Finding]:
        user_a = sessions.get("user_a")
        user_b = sessions.get("user_b")
        if not (user_a and user_b and user_a.authenticated and user_b.authenticated):
            return None

        # 1. Get the list as User A.
        resp_a = await executor.send("GET", endpoint.path, token=user_a.token,
                                     headers=endpoint.headers, query=endpoint.query)
        if resp_a is None or resp_a.status_code != 200:
            return None
        try:
            data_a = resp_a.json()
        except ValueError:
            return None

        # 2. Find objects owned by User A (owner_field == user_a's label).
        #    user_a.email holds the identity value we logged in with.
        owner_val = user_a.email
        owned = _find_owned_objects(data_a, self.owner_field, owner_val, self.id_fields)
        if not owned:
            return None

        base = endpoint.path.rstrip("/")
        target_id = owned[0]
        detail_path = f"{base}/{target_id}"

        # 3. Confirm User A can read the object.
        a_detail = await executor.send("GET", detail_path, token=user_a.token)
        if a_detail is None or a_detail.status_code != 200 or not a_detail.text.strip():
            return None

        # 4. Attack: User B requests User A's object.
        b_detail = await executor.send("GET", detail_path, token=user_b.token)
        if b_detail is None:
            return None

        # 5. Vuln: B gets 200 with A's data.
        if b_detail.status_code == 200 and b_detail.text.strip() == a_detail.text.strip():
            return self._finding(
                endpoint=Endpoint(name=endpoint.name, method="GET",
                                  raw_url=detail_path, path=detail_path),
                attack_response=b_detail,
                description=(
                    f"User B accessed object '{target_id}' owned by User A at "
                    f"'{detail_path}'. The identifier was discovered dynamically "
                    f"from User A's list at '{endpoint.path}' (owner field "
                    f"'{self.owner_field}'). The server returned identical data to "
                    f"a non-owner, confirming missing object-level authorization."
                ),
                poc_request=(
                    f"GET {detail_path}\n"
                    f"Authorization: <USER_B_TOKEN>\n"
                    f"(object '{target_id}' belongs to User A)"
                ),
                poc_response=f"HTTP {b_detail.status_code}\n{self._truncate(b_detail.text)}",
                remediation=(
                    f"Add a server-side ownership check to {detail_path}: verify "
                    f"the authenticated user owns object '{target_id}' (per the "
                    f"'{self.owner_field}' field) before returning it. Unguessable "
                    f"identifiers are not a substitute for this check."
                ),
            )
        return None
