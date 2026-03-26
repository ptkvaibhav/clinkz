# OWASP WSTG-SESS-05: CSRF Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery

## Step 1 — Identify state-changing requests

Any form that modifies data: password change, profile update,
transfer funds, delete account, create user.

## Step 2 — Check for anti-CSRF token

Is there a hidden field with a random token? (`csrf_token`, `_token`, etc.)
Is the token validated? Remove it and resubmit — does it still work?

## Step 3 — Test token validation

- Submit with empty token → works? → CSRF vulnerable
- Submit with wrong token → works? → CSRF vulnerable
- Submit without token field → works? → CSRF vulnerable

## Step 4 — Test via GET method

Can the same action be performed via GET instead of POST?
If yes: CSRF is trivially exploitable via image tag or link.

## Step 5 — Document

Affected action, missing/weak token, proof that action succeeds
without valid CSRF token.
