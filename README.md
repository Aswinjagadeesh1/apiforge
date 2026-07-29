# APIForge

**Automated OWASP API Top 10 vulnerability detection from Postman collections and OpenAPI/Swagger specs.**

APIForge takes an API description (a Postman collection *or* an OpenAPI/Swagger file) plus test-user credentials, authenticates the users, runs a suite of OWASP API Top 10 security checks across every endpoint, and produces pentest-ready reports — turning hours of manual API testing into a single command.

Fully local. No cloud. No telemetry. Open source (Apache 2.0).

## Highlights

- **Two input formats** — Postman Collection v2.1 *and* OpenAPI/Swagger (2.0 & 3.x), auto-detected.
- **Multi-user, stateful testing** — authenticates two regular users (and optionally an admin) to detect real authorization flaws (BOLA, BFLA, privilege escalation) that traffic-driven scanners miss.
- **12 checks across 6 OWASP API categories** (API1–API5, API7, API8).
- **Evidence-based findings** — every finding carries the real request and response that proved it, rendered as an annotated proof-of-concept image embedded in the report. Findings are reproducible by hand, not vague alerts.
- **Root-cause grouping** — the same flaw across many endpoints is reported as one finding listing all affected endpoints, not N duplicates, so counts stay honest.
- **In-band *and* blind SSRF detection** — blind SSRF is confirmed via a local out-of-band listener (no cloud collaborator), for targets that can reach the scanning host (localhost / Docker / same network / lab).
- **Configurable, not hardcoded** — login field, password field, auth header/scheme, BOLA identifier/owner fields, and optional admin role are all set via config, so new APIs need config changes, not code changes.
- **Pentest-shaped output** — Word, Excel, and JSON. Each finding has severity, CVSS, CWE, OWASP category, affected endpoints, description, annotated PoC, impact, and remediation.
- **Low false positives by design** — every check verifies a baseline (and, where relevant, response content) before reporting.

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
| SSRF (in-band + blind) | API7:2023 | CWE-918 | HIGH | Injects internal/metadata URLs into fetchable params; confirms in-band via metadata content and blind via out-of-band callback |
| Security Misconfiguration (verbose errors) | API8:2023 | CWE-209 | MEDIUM | Triggers errors and flags leaked stack traces, DB errors, and source paths |
| CORS Misconfiguration | API8:2023 | CWE-942 | MEDIUM | Forges an Origin header; flags reflected origin with credentials |

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
  "user_b": { "email": "userb@test.com", "password": "Password123!" },
  "user_admin": { "email": "admin@example.com", "password": "Admin!123" }
}
```

2. Run the scan:

```bash
apiforge -c api.postman.json -u users.json -b http://localhost:8888 \
  -o report.xlsx --json report.json --word report.docx
```

APIForge auto-detects whether -c is a Postman collection or an OpenAPI/Swagger spec.

To enable blind SSRF detection (starts a local out-of-band listener; use only on a trusted/lab network, since the listener binds all interfaces so the target can call back):

```bash
apiforge -c api.postman.json -u users.json -b http://localhost:8888 \
  -o report.xlsx --word report.docx --blind-ssrf
```

## Reports

- **Word (.docx)** — cover, scope, terms, colour-coded severity legend, executive summary with a native editable severity chart, and per-finding sections (severity, affected endpoints, OWASP category, description, annotated PoC, impact, remediation).
- **Excel (.xlsx)** — executive summary sheet, findings sheet (one row per grouped finding, with a link to the evidence), and a PoC sheet of embedded annotated screenshots.
- **JSON** — granular, one entry per endpoint (not grouped), for automation and re-testing.

Findings are **grouped by root cause**: one flaw affecting many endpoints becomes a single finding listing every affected endpoint (with per-endpoint PoCs), while the JSON output stays per-endpoint. The CLI, Word, and Excel counts all reconcile to the grouped total.

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
| user_admin | Optional admin account (enables role-aware escalation) | (optional) |

## Validation status

APIForge distinguishes **shipped** (runs and produces output) from **validated** (findings manually reproduced by hand). The distinction is deliberate.

- **crAPI (OWASP)** — every reported finding manually verified as a true positive, **zero false positives**. Includes a confirmed **blind SSRF** true positive on the `mechanic_api` flow, detected via out-of-band callback. Evidence committed under `validation/`.
- **SSRF check** — validated end-to-end on a bundled deliberately-vulnerable test app (`samples/ssrf_test_server.py`): in-band flagged, blind flagged via OOB, safe endpoint not flagged.

Note: crAPI is deliberately vulnerable, so a clean pass there proves the *process* works, not precision on healthy APIs. A measured false-positive rate across diverse, mostly-secure APIs is the current validation focus.

A bundled mock server gives a zero-setup demo:

```bash
python -m samples.vuln_server
apiforge -c samples/vulnshop.postman.json -u samples/users.json -b http://localhost:8899 -o report.xlsx
```

## Methodology

Every check follows a **baseline → attack → compare** pattern: establish legitimate behaviour, send the malicious/unauthorized request, and only report when the API behaves incorrectly relative to the baseline. This evidence-based approach is what keeps false positives low. APIForge performs dynamic (DAST) testing against a running API and focuses on the authentication and authorization flaws that cause most real-world API breaches.

**Scope, stated honestly:** APIForge automates the **authorization layer** of API testing (who can access what) plus common technical flaws (JWT, SSRF, misconfiguration). Application-specific *business-logic* flaws (price manipulation, workflow bypass, race conditions) still require a human tester — no automated tool reliably finds these — and APIForge is designed to free testers to focus there. Payload-level encrypted APIs need the encryption scheme supplied to be testable.

## Architecture

```
input (postman OR openapi) --> Parser --> [Endpoints]
users.json --> Authenticator --> {user_a, user_b, admin? sessions}
                                     |
                       Scanner <-----+
                         |  for each (endpoint, applicable check):
                         |      check.run(endpoint, sessions, executor)
                         v
                      [Findings] --> group by root cause --> Reporter --> report.docx / .xlsx / .json
```

- parser/postman.py — Postman v2.1 parsing + variable resolution
- parser/openapi.py — OpenAPI/Swagger 2.0 & 3.x parsing
- auth/jwt_auth.py — login + flexible identity/password fields + token extraction
- executor/http_executor.py — shared async HTTP client with configurable auth header
- executor/oob_listener.py — local out-of-band listener for blind-SSRF confirmation
- checks/ — one file per security check (plugin-based)
- scanner.py — runs applicable checks across endpoints, deduplicates and cross-check-dedups findings
- reporter/report.py — Excel + JSON output and root-cause grouping
- reporter/report_word.py — Word (.docx) report with annotated PoC, impact, and remediation
- reporter/poc_render.py — annotated request/response evidence images
- cli.py — command-line interface, format auto-detection, config wiring

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -q
```

## Roadmap

- Measured false-positive rate across a corpus of diverse, mostly-secure APIs
- Pre-request script handling (for collections that set tokens/IDs dynamically)
- Additional checks (JWT kid injection, HTTP method tampering, improper inventory)
- Burp/ZAP capture import (for APIs without a ready collection)
- Config-driven business-rule checks (tester supplies the rule; the tool tests it)
- OAuth 2.0 and API-key authentication flows
- Payload transform layer for encrypted-body APIs (tester supplies encrypt/decrypt)

## License

Apache License 2.0 — see LICENSE.
