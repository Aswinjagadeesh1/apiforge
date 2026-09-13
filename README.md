# APIForge

**Specification-driven API security testing with multi-user authorization checks and evidence-based reporting.**

APIForge is a college team project that tests running REST APIs described by Postman collections or OpenAPI/Swagger specifications. It combines authorization checks with selected authentication, SSRF, and configuration checks, and exports findings for manual verification.

## Team and repository provenance

This repository is maintained by **Aswin T. J. (Aswinjagadeesh1)** as a copy of the team's [original APIForge repository](https://github.com/NishanthGE/apiforge), shared with permission. The original Git history and Apache 2.0 licence are retained.

The accompanying manuscript credits **Aswin T. J., Nishanth G. E., Sahana S., and Akash K. S.**, Department of Computer Science and Engineering (Cyber Security), Sri Krishna College of Engineering and Technology, Coimbatore. APIForge is collaborative work; hosting this copy does not imply sole authorship of its implementation.

## Relationship to the paper

The accompanying manuscript, *A Specification-Driven Automated API Security Testing Framework*, is not yet published. It documents an earlier version focused on BOLA and selected checks within OWASP API1-API5.

Development continued after the manuscript was prepared. The current implementation registers **12 checks across seven OWASP API Security Top 10 (2023) categories: API1-API5, API7, and API8**. It also includes direct-token authentication and optional blind-SSRF checks. Current repository capabilities should be distinguished from the scope and validation reported in the manuscript.

## Intended use

Use only against systems you own or are explicitly authorised to test. Checks can modify application state and issue bursts of requests; begin with the bundled lab and disposable test accounts. Reports may contain credentials or response data and should be reviewed before sharing.

## Highlights

- **Two input formats** — Postman Collection v2.1 *and* OpenAPI/Swagger (2.0 & 3.x), auto-detected.
- **Multi-user, stateful testing** — authenticates two regular users (and optionally an admin) to investigate authorization flaws such as BOLA, BFLA, and privilege escalation.
- **12 checks across 7 OWASP API categories** (API1–API5, API7, API8).
- **Evidence-based findings** — findings include request/response evidence for manual verification, rendered as an annotated proof-of-concept image embedded in the report. Findings are reproducible by hand, not vague alerts.
- **Root-cause grouping** — the same flaw across many endpoints is reported as one finding listing all affected endpoints, not N duplicates, so counts stay honest.
- **In-band *and* blind SSRF detection** — blind SSRF is confirmed via a local out-of-band listener (no cloud collaborator), for targets that can reach the scanning host (localhost / Docker / same network / lab).
- **Configurable, not hardcoded** — login field, password field, auth header/scheme, BOLA identifier/owner fields, and optional admin role are all set via config, so new APIs need config changes, not code changes.
- **Pentest-shaped output** — Word, Excel, and JSON. Each finding has severity, CVSS, CWE, OWASP category, affected endpoints, description, annotated PoC, impact, and remediation.
- **Baseline comparison** — checks use baseline and response comparisons where applicable; this does not establish a measured false-positive rate.

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

Requires **Python 3.11+**. For a private repository, GitHub access is required to clone it.

Linux/macOS:

```bash
git clone https://github.com/Aswinjagadeesh1/apiforge.git
cd apiforge
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Windows PowerShell (after cloning and entering the repository):

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

On Windows, use `.\.venv\Scripts\apiforge.exe` in place of `apiforge` in the commands below. For YAML OpenAPI files, also install `PyYAML` in the same environment (`python -m pip install pyyaml`); it is not currently declared in the package dependencies. The examples use local specification files.

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

APIForge auto-detects whether `-c` is a Postman collection or an OpenAPI/Swagger spec.

Existing test-user tokens can be supplied instead of login credentials:

```json
{
  "user_a": { "token": "REPLACE_WITH_USER_A_TEST_TOKEN" },
  "user_b": { "token": "REPLACE_WITH_USER_B_TEST_TOKEN" }
}
```

`login_endpoint` is unnecessary when all users supply tokens. Tokens must remain valid during the scan. These placeholders are not working credentials.

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
| login_endpoint | Path appended to base URL for login | Required for credential login; omitted in token-only mode |
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

- **crAPI (OWASP)** — the upstream project reports manual verification of its recorded findings, with no false positives in those runs. Includes a confirmed **blind SSRF** true positive on the `mechanic_api` flow, detected via out-of-band callback. Evidence committed under `validation/`.
- **SSRF check** — validated end-to-end on a bundled deliberately-vulnerable test app (`samples/ssrf_test_server.py`): in-band flagged, blind flagged via OOB, safe endpoint not flagged.

Note: crAPI is deliberately vulnerable, so a clean pass there proves the *process* works, not precision on healthy APIs. A measured false-positive rate across diverse, mostly-secure APIs is the current validation focus.

After installing dependencies, run the bundled mock server in one terminal and scan it from a second terminal:

```bash
python -m samples.vuln_server
apiforge -c samples/vulnshop.postman.json -u samples/users.json -b http://localhost:8899 -o report.xlsx
```

## Methodology

The central testing workflow follows a **baseline → attack → compare** pattern: establish legitimate behaviour, send the malicious/unauthorized request, and only report when the API behaves incorrectly relative to the baseline. These comparisons provide evidence for review; findings still require manual verification. APIForge performs dynamic (DAST) testing against a running API and focuses on the authentication and authorization flaws that cause most real-world API breaches.

**Scope, stated honestly:** APIForge automates the **authorization layer** of API testing (who can access what) plus common technical flaws (JWT, SSRF, misconfiguration). Application-specific *business-logic* flaws (price manipulation, workflow bypass, race conditions) still require a human tester — these are outside this implementation’s general-purpose coverage — and APIForge is designed to free testers to focus there. Payload-level encrypted APIs need the encryption scheme supplied to be testable.

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

Apache License 2.0 — see [LICENSE](LICENSE). Original licence and attribution notices are retained.
