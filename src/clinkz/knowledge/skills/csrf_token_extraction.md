# CSRF Token Extraction — Authentication Skill

How to authenticate to a web app with CSRF protection:

1. Send GET to login page
2. Parse the HTML response for hidden input fields — look for names
   like csrf_token, user_token, _token, _csrf, csrfmiddlewaretoken
3. Also extract any cookies set in the response (Set-Cookie headers)
4. Send POST to login page with: username, password, the CSRF token
   value, using the cookies from step 2
5. Check response: redirect to dashboard/home = success, redirect
   back to login = failure
6. If success: store ALL cookies from the response chain as the
   authenticated session

## Common Mistakes to Avoid

- Using cookies from a DIFFERENT request than the one that gave
  you the CSRF token — they must match
- Not following redirects — the final cookie jar after redirects
  is what matters
- Not URL-encoding the token value
- Sending the CSRF token in a header when the form expects it in the body
- Forgetting to include the token field NAME (e.g., `user_token=<value>`,
  not just `<value>`)

## Example Flow

```
GET /login HTTP/1.1
→ Response: Set-Cookie: PHPSESSID=abc123
→ Body: <input type="hidden" name="user_token" value="d4e5f6...">

POST /login HTTP/1.1
Cookie: PHPSESSID=abc123
Content-Type: application/x-www-form-urlencoded

username=admin&password=password&user_token=d4e5f6...&Login=Login
→ Response: 302 → /index.php (success)
→ Set-Cookie: PHPSESSID=abc123; security=low
```
