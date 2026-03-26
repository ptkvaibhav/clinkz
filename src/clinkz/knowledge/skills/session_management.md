# Session Management — Operational Skill

How to maintain an authenticated session across requests:

1. The cookie jar persists cookies automatically between requests
2. When you authenticate, the session cookies are stored
3. For ALL subsequent requests, cookies are automatically included
4. If you get redirected to login page — your session expired,
   re-authenticate using stored credentials
5. NEVER manually set cookies that override the cookie jar
6. To verify your session is valid: send GET to a protected page,
   check if you get content (not login redirect)

## Session Validation

Before starting exploitation, verify your session:
```
GET /index.php HTTP/1.1
Cookie: PHPSESSID=abc123; security=low

→ 200 OK + page content = session valid
→ 302 → /login.php = session expired, re-authenticate
→ 403 Forbidden = session valid but insufficient privileges
```

## Session Expiry Detection

Watch for these signals that your session has expired:
- Response redirects to login page (302 → /login)
- Response body contains login form HTML
- Response status is 401 Unauthorized
- Response size dramatically different from previous authenticated responses

## Re-authentication Procedure

1. Detect session expiry from one of the signals above
2. Retrieve stored credentials (from credential store or task context)
3. Re-authenticate using the same procedure that worked initially
4. Continue exploitation with the new session cookies

## Multi-Session Scenarios

When testing IDOR or privilege escalation:
- Maintain multiple sessions (different users) simultaneously
- Label each session clearly: `session_admin`, `session_user1`
- Compare responses between sessions to detect authorization issues
