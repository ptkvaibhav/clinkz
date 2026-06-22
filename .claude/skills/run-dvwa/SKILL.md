---
name: run-dvwa
description: "Run the full Clinkz pipeline against DVWA and report vulnerability coverage across the 14 categories."
---

Apply phase-work skill.

1. Verify DVWA is running at http://localhost:8080 (check via curl or docker compose ps). If not running: docker compose -f docker/docker-compose.yml up -d dvwa
   - The `clinkz-dvwa` entrypoint (`docker/dvwa-init.sh`) now auto-creates the DVWA database on startup (POSTs `setup.php`'s create_db once Apache is up), so a fresh container is login-ready with admin/password. Without an initialised DB, login silently fails and every crawl sees only `login.php`.
   - If you ever see login failing (modules 302 back to `login.php`), force a clean DB: `docker compose -f docker/docker-compose.yml up -d --force-recreate dvwa`, or manually `curl --data "create_db=Create / Reset Database" http://localhost:8080/setup.php`.
2. The orchestrator handles clinkz-tools container readiness via its preflight. Just invoke: python -m clinkz scan --target http://localhost:8080
3. Parse the JSON report from outputs/
4. Report coverage as X/14 with a breakdown table across: SQL Injection, XSS Reflected, XSS Stored, Command Injection, File Inclusion, File Upload, CSRF, Brute Force, Weak Session IDs, DOM XSS, JavaScript Attacks, Authorization Bypass, Open HTTP Redirect, CSP Bypass.
5. Include: total findings, by severity, engagement ID, runtime.
6. If coverage < target, briefly note which categories were missed and why (single-line each).
7. NoSQL Injection (`_test_nosqli`, a Tier-1 primitive beyond the 14 categories — see `docs/ROADMAP.md`) is **N/A on DVWA** (PHP/MySQL, no NoSQL backend): expect **zero** nosqli findings. The methodology emits only on a real NoSQL signal (operator match-set widening or a `$where` channel) and rejects SQL errors, so a nosqli finding here is a regression, not a catch.
8. XXE (`_test_xxe`, a Tier-1 primitive beyond the 14 categories — see `docs/ROADMAP.md`) is **N/A on DVWA** (no endpoint parses an XML request body; the upload handler rejects non-images without parsing XML): expect **zero** xxe findings. Phase-1 candidacy requires the endpoint to actually parse XML (entity expansion / XML parse-error / malformed-vs-well-formed divergence), so an xxe finding here is a regression, not a catch.

Do NOT fix issues found during the run. Measurement only unless the user asks for fixes.
