# OWASP WSTG-ATHN-03: Brute Force Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism

## Step 1 — Check for lockout policy

Try 5 wrong passwords for admin — is the account locked?
Try 10 wrong passwords — still no lockout? → brute-forceable.

## Step 2 — Check for rate limiting

Send 20 login requests in 10 seconds — are any blocked?
No blocking? → vulnerable to automated brute force.

## Step 3 — Test with common credentials

- `admin:admin`
- `admin:password`
- `admin:123456`
- `admin:admin123`
- `root:root`
- `root:toor`
- `test:test`
- `guest:guest`

## Step 4 — Report default credentials

If login succeeds with any default/common credential:
Report: DEFAULT CREDENTIALS finding.

## Step 5 — Document

Lack of lockout, lack of rate limiting, successful credential(s),
number of attempts needed.
