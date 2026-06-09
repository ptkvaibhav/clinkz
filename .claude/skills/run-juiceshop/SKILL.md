---
name: run-juiceshop
description: "Run the full Clinkz pipeline against OWASP Juice Shop (Node/Angular SPA, JWT auth) and report vulnerability coverage across the 14 categories."
---

Apply phase-work skill.

Juice Shop is the SPA/JWT counterpart to DVWA. Where DVWA is PHP + cookie sessions + HTML forms katana can crawl, Juice Shop is an **Angular SPA** whose real attack surface is `/api/*` and `/rest/*` JSON routes invoked by JavaScript — not HTML links — and it authenticates with a **`Authorization: Bearer <jwt>`** token, not a cookie session. Treat those two facts as the load-bearing differences when interpreting any miss.

1. Verify Juice Shop is running at http://localhost:3000 (check via `Invoke-WebRequest http://localhost:3000` or `docker compose -f docker/docker-compose.yml ps`). If not running: `docker compose -f docker/docker-compose.yml up -d juiceshop`
   - A healthy shell is a ~75 KB Angular `index.html` (HTTP 200) with almost no anchor links — the body is the SPA bootstrap, not the app. Do NOT read "200, large body" as "endpoints discoverable"; the routes are in the JS bundle.
   - Juice Shop self-registration is open: `POST /api/Users` `{email, password, passwordRepeat}` then `POST /rest/user/login` `{email, password}` returns the JWT at `data.authentication.token`. This is how `tests/test_skills_juiceshop/conftest.py` authenticates. The pipeline now does JSON/API auth too: `WebAuthenticator.authenticate()` falls back to POSTing JSON creds to `/rest/user/login` (and other common API routes), extracts the token, and propagates it as `Authorization: Bearer <jwt>` to scan/exploit via the `session_headers` handoff. The canonical default admin (`admin@juice-sh.op` / `admin123`) is seeded, so the orchestrator's default-cred flow can establish a JWT session without self-registering.
2. The orchestrator handles clinkz-tools container readiness via its preflight. Just invoke: `python -m clinkz scan --target http://localhost:3000`
3. Parse the JSON report from `outputs/<engagement_id>/report_<engagement_id>.json` and the trace from `outputs/<engagement_id>/trace.jsonl` (`python -m clinkz trace inspect <engagement_id>`).
4. Report coverage as **X/13-applicable** using the Juice Shop category map below. Command Injection is the one genuine **N/A** (Node SPA, no `child_process.exec` sink reachable from HTTP input — the `/ftp` challenge is traversal/LFI, not shell). The other 13 categories have real surface.
5. Include: total findings, by severity, engagement ID, runtime.
6. If coverage < applicable count, give a single-line root cause per missed category and bucket it as one of: **(a) JWT-auth failure** (JSON/API auth is now wired — bucket here only if the JWT session genuinely failed to establish), **(b) SPA/API endpoint discovery** (the `/api`+`/rest` routes never reached planning), **(c) JSON-body param handling** (params live in a JSON request body, not the query string our extraction reads), or **(d) genuine methodology gap**. This bucketing is the deliverable — it prioritises the next fix. Note on bucket (b): scan now runs dedicated route discoverers (`agents/_route_discovery.py`: static JS-bundle parsing + OpenAPI probing) that DO recover `/api`+`/rest` routes (incl. the param-bearing `/rest/products/search?q=`, `/rest/basket/:id`) from the bundle — verified by the live `juiceshop_smoke` discovery test. So bucket (b) now almost always resolves to the **upstream recon→scan gap**: recon must hand scan the :3000 HTTP service or neither katana nor the discoverers dispatch (the observed `service_scans: []`, `total_endpoints: 0`). Buckets (b-upstream) and (c) JSON-body params are the expected dominant blockers.

## Juice Shop → 14-category map (canonical surfaces)

| # | Our category | Juice Shop surface | Canonical endpoint | Notes |
|---|---|---|---|---|
| 1 | SQL Injection | Product search | `GET /rest/products/search?q='` | Sequelize/SQLite error-based; `q` concatenated into raw SQLite. **Query-string param** — most pipeline-friendly. |
| 2 | XSS Reflected | Search bar | `GET /#/search?q=<payload>` | Reflected into DOM via Angular binding (not server HTML body). |
| 3 | XSS Stored | Customer feedback | `POST /api/Feedbacks` `{comment,rating}` | Rendered into feedback list DOM. **JSON body**, no HTML form on page. |
| 4 | Command Injection | — | — | **N/A** — no OS-shell sink from HTTP input. The only filesystem surface (`/ftp`) is LFI-shaped. |
| 5 | File Inclusion / Path Traversal | Legacy ftp | `GET /ftp/<file>` (`%2e%2e%2f` bypass) | Allowlist + `..` block defeated by URL-encoding; **path segment**, not query param. |
| 6 | File Upload | Complaint attachment | `POST /file-upload` (or `/api/Complaints`) | Over-permissive upload validation. |
| 7 | CSRF | State-changing JSON APIs | `POST /api/Feedbacks`, profile change | JWT-bearer is the *only* CSRF defence → MISSING/COOKIE_ONLY token surface. |
| 8 | Brute Force | Login | `POST /rest/user/login` | No lockout / captcha / rate-limit by design. **JSON body** creds. |
| 9 | Weak Session IDs | JWT token | `token` from `/rest/user/login` | JWT, not a cookie session ID. Our entropy/flag methodology is cookie-shaped — **shape mismatch** expected, not a true negative. |
| 10 | DOM XSS | SPA fragment routes | `GET /#/track-order?id=<payload>` | Client-side Angular binding; `strength=likely` (no JS interpreter). |
| 11 | JavaScript Attacks | Score-board gate | `GET /#/score-board` | Client-side gate. Methodology is **form-bound**; SPA route serves no server-rendered form → expect skip/empty, not a contract break. |
| 12 | Authorization Bypass (IDOR) | Basket / users | `GET /rest/basket/:id`, `GET /api/Users/:id` | Horizontal IDOR — auth'd but `:id` not owner-checked. Strong surface. **Reference in path segment.** |
| 13 | Open HTTP Redirect | Redirector | `GET /redirect?to=<url>` | Loose allowlist, bypassable. **The clean signal DVWA could not test** — this is `_test_open_redirect` against a real surface. |
| 14 | CSP Bypass / Security Headers | Root response | `GET /` headers | Missing/weak CSP, Referrer-Policy, Permissions-Policy on most builds (build-dependent). |

Applicable = 13 (all except #4 Command Injection).

## What the trace must answer (diagnosis, not just a number)

The point of running against Juice Shop is to test the **pipeline**, not the isolated smoke tests (which hand each `_test_*` method a pre-built `PageAnalysis` at the canonical endpoint). The smoke tests passing proves the methodologies work *given the right page*; this run proves whether recon→scan→auth→plan actually *delivers* that page. From `clinkz trace inspect <id>` confirm:

- **Auth**: Did a JWT session establish? `WebAuthenticator` now tries cookie/form auth first, then falls back to JSON/API auth (`POST /rest/user/login`, token → `Authorization: Bearer` via `session_headers`). Confirm the trace shows a successful JSON login and the bearer reaching scan/exploit; if the session did not establish, this is the break — but it is no longer the *expected* one (SPA discovery now is).
- **Discovery**: Did scan surface `/api/*` and `/rest/*` routes, or only the SPA `index.html` shell? Angular routes aren't anchor links, but scan no longer relies on HTML crawling alone — `_scan_http_service` runs the `_route_discovery.py` discoverers (static JS-bundle parsing of `main.js`/chunks + OpenAPI probing) that extract the real routes with param structure. First confirm **scan actually ran the crawl/discovery at all**: if the trace shows `service_scans: []` / `total_endpoints: 0` and no katana invocation, the break is upstream — recon handed scan an empty service list (port 3000 not delivered as an HTTP service), so nothing dispatched. Only once a crawl runs does "discoverers missed a route" become the right read.
- **Planning**: Did `_llm_plan_exploits` receive real parameterized endpoints (`/rest/products/search?q=`, `/rest/basket/:id`, `/redirect?to=`) or just the SPA index?
- **Open Redirect specifically**: did it get found? DVWA lacks this category, so it is the cleanest read on whether `_test_open_redirect` works end-to-end against a real surface.

Report the diagnosis as a table: `category | found | root cause if missed | bucket (a/b/c/d)`. Then give the % split of what blocks coverage across the four buckets — that is the fix priority for the next prompt.

Do NOT fix issues found during the run. Measurement and diagnosis only unless the user asks for fixes.
