# OWASP WSTG-CLNT-01: DOM-Based XSS Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting

## Step 1 — Identify DOM sinks

Look at JavaScript code for dangerous patterns:
`document.write()`, `innerHTML`, `outerHTML`, `eval()`,
`setTimeout`/`setInterval` with string args, `location.href` assignment.

## Step 2 — Identify DOM sources

Where does user input enter JS: `location.hash`, `location.search`,
`document.referrer`, `window.name`, `postMessage`.

## Step 3 — Test source-to-sink flow

Modify the source and check if it reaches the sink.

Example: if URL hash is used in `document.write()`:
`http://target/page#<script>alert(1)</script>`

## Step 4 — Document

Source, sink, payload, evidence.
