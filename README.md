# APIForge

**Automated OWASP API Top 10 vulnerability detection from Postman collections.**

APIForge takes a Postman collection plus two test-user credentials, authenticates
both users, runs a set of OWASP API Top 10 security checks across every endpoint,
and produces a pentest-ready Excel report — turning hours of manual API testing
into a single command.

Fully local. No cloud. No telemetry. Open source (Apache 2.0).

---

## Why APIForge

| | APIForge |
|---|---|
| **Input** | Postman collection (native) |
| **Execution** | 100% local, no cloud calls |
| **Multi-user** | Orchestrates two sessions for real BOLA/BFLA detection |
| **Output** | Excel report in pentest-deliverable format (CVSS, CWE, OWASP, PoC, remediation) |
| **License** | Apache 2.0 |

---

## Install

```bash
git clone <your-repo-url>
cd apiforge
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -e .
```

---

## Quick start

**1. Describe your users** in a JSON file (`users.json`):

```json
{
  "login_endpoint": "/identity/api/auth/login",
  "token_json_path": "token",
  "user_a": { "email": "usera@test.com", "password": "Password123!" },
  "user_b": { "email": "userb@test.com", "password": "Password123!" }
}
```

- `login_endpoint` — path appended to `--base-url` for login.
- `token_json_path` — dotted path to the token in the login response
  (e.g. `token`, `data.access_token`). Optional; common keys are auto-detected.

**2. Run the scan:**

```bash
apiforge \
  --collection my_api.postman.json \
  --users users.json \
  --base-url http://localhost:8888 \
  --output report.xlsx \
  --json report.json
```

Options: `--env` to supply a Postman environment file for `{{variable}}`
resolution; `--json` to also emit machine-readable output.

---

## Try it against the bundled vulnerable server

APIForge ships with a deliberately vulnerable mock API so you can see it work
immediately, no external setup required.

```bash
# Terminal 1 — start the vulnerable target
python -m samples.vuln_server

# Terminal 2 — scan it
apiforge \
  --collection samples/vulnshop.postman.json \
  --users samples/users.json \
  --base-url http://localhost:8899 \
  --output report.xlsx
```

You should see BOLA, BFLA, and Mass Assignment findings.

For realistic testing, point APIForge at [OWASP crAPI](https://github.com/OWASP/crAPI).

---

## Checks implemented (MVP)

| Check | OWASP | CWE | What it does |
|---|---|---|---|
| BOLA (numeric ID) | API1:2023 | CWE-639 | Accesses user A's object with user B's token |
| BFLA (admin) | API5:2023 | CWE-285 | Reaches admin endpoints as a regular user |
| Mass Assignment | API3:2023 | CWE-915 | Injects `isAdmin`/`role` and checks acceptance |
| Sensitive Data Exposure | API3:2023 | CWE-200 | Flags secret/PII fields in responses |

The check engine is plugin-based (`apiforge/checks/base.py`) — adding a new check
means dropping in one class and registering it in `apiforge/checks/__init__.py`.

---

## Architecture

```
collection.json ──▶ PostmanParser ──▶ [Endpoints]
users.json ──────▶ JWTAuthenticator ▶ {user_a, user_b sessions}
                                          │
                        Scanner ◀─────────┘
                          │  for each (endpoint, applicable check):
                          │      check.run(endpoint, sessions, executor)
                          ▼
                       [Findings] ──▶ Reporter ──▶ report.xlsx / report.json
```

- `parser/postman.py` — Postman v2.1 parsing + `{{variable}}` resolution
- `auth/jwt_auth.py` — login + flexible token extraction
- `executor/http_executor.py` — shared async HTTP client
- `checks/` — one file per security check
- `scanner.py` — orchestrates applicable checks across endpoints
- `reporter/report.py` — Excel + JSON output
- `cli.py` — command-line interface

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

---

## Roadmap (post-MVP)

- OpenAPI / Swagger and HAR input
- OAuth 2.0, session-cookie, and API-key auth
- Additional checks: JWT alg:none / weak secret, rate limiting, CORS, verbose errors, old API versions
- Word/PDF report export
- YAML-based custom checks

---

## License

Apache License 2.0 — see `LICENSE`.
