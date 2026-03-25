# OWASP WSTG-SESS-01/02/03: Session Management Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/01-Testing_for_Session_Management_Schema

## Step 1 — Analyze session token

Collect 5-10 session tokens by logging in/out.
Check: are they sequential? timestamp-based? short?
Randomness test: do tokens share common prefixes?

## Step 2 — Check cookie attributes

- `HttpOnly` flag set? (prevents JS access)
- `Secure` flag set? (prevents transmission over HTTP)
- `SameSite` attribute? (prevents CSRF)
- Expiration set? (or session-only?)

## Step 3 — Test session fixation

Set a known session cookie BEFORE logging in.
After login: is the session ID the SAME? → vulnerable.
Expected: session should change after authentication.

## Step 4 — Test session invalidation

Log in → copy session cookie → log out.
Use copied cookie → still valid? → logout doesn't destroy session.

## Step 5 — Document each finding with evidence
