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

Do NOT fix issues found during the run. Measurement only unless the user asks for fixes.
