---
name: run-dvwa
description: "Run full Clinkz pipeline against DVWA and report vulnerability coverage"
---
DVWA is the **target**, not the tool runtime. Only start DVWA here — the
orchestrator's own pre-flight now handles the `clinkz-tools` container
(auto-build, auto-start, binary identity check).

1. Verify DVWA is reachable at http://localhost:8080.
   If not, start only the DVWA service:
   `docker compose -f docker/docker-compose.yml up -d dvwa`

2. Run the full pentest pipeline:
   `python -m clinkz scan --target http://localhost:8080`
   (container readiness is handled automatically; do not set
   `TOOL_EXEC_MODE` — docker is the default).

3. Parse the JSON report produced in the working directory
   (`report_<engagement-id>.json`) and compare findings against the
   14 DVWA vulnerability categories:
   SQL Injection, XSS Reflected, XSS Stored, Command Injection,
   File Inclusion, File Upload, CSRF, Brute Force, Weak Session IDs,
   DOM XSS, JavaScript Attacks, Authorization Bypass, Open HTTP Redirect,
   CSP Bypass.

4. Report coverage as X/14 with details on what was found and what was
   missed.
