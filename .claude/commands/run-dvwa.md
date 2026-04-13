---
description: "Run full Clinkz pipeline against DVWA and report vulnerability coverage"
---
Verify DVWA is running at http://localhost:8080 (check docker compose -f docker/docker-compose.yml ps).
If not running, start it.

Run the full pentest pipeline: python -m clinkz scan --target http://localhost:8080

After completion, compare findings against the 14 DVWA vulnerability categories:
SQL Injection, XSS Reflected, XSS Stored, Command Injection, File Inclusion,
File Upload, CSRF, Brute Force, Weak Session IDs, DOM XSS, JavaScript Attacks,
Authorization Bypass, Open HTTP Redirect, CSP Bypass.

Report coverage as X/14 with details on what was found and what was missed.
