---
name: wstg-methodology
description: "Load OWASP WSTG methodology context for implementing exploit skills and test coverage"
---
Read the WSTG skills files in src/clinkz/knowledge/ for vulnerability testing
methodology. These define the deterministic _test_* methods in the Exploit Agent.

Vulnerability classes: SQLi, XSS (reflected/stored/DOM), Command Injection,
File Inclusion (LFI/RFI), File Upload, CSRF, IDOR, Brute Force,
Open Redirect, Security Headers, Weak Session IDs, Authorization Bypass.

Each skill is a CONTRACT: if the vulnerability is present and the skill runs,
it MUST be found. Skills are tested in CI against DVWA.
