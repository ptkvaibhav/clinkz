# OWASP WSTG-INPV-05: SQL Injection Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection

## Step 1 — Identify injection points

Test EVERY parameter that could reach a database query: search fields,
login forms, user ID lookups, dropdown selections, hidden fields,
cookies, HTTP headers (Referer, X-Forwarded-For).

## Step 2 — Error-based detection

Send: `'` (single quote) — look for SQL error in response.

DB-specific errors:
- MySQL: `You have an error in SQL syntax`
- PostgreSQL: `ERROR: syntax error`
- MSSQL: `Unclosed quotation mark`
- SQLite: `SQLITE_ERROR`
- Oracle: `ORA-`

## Step 3 — Boolean-based detection

Send: `1 AND 1=1` → record response (true condition)
Send: `1 AND 1=2` → compare response (false condition)

Different responses = boolean-based blind SQLi.

## Step 4 — Time-based detection

Send: `1' AND SLEEP(5)--` (MySQL)
Send: `1'; WAITFOR DELAY '0:0:5'--` (MSSQL)
Send: `1' AND pg_sleep(5)--` (PostgreSQL)

Response takes 5+ seconds = time-based blind SQLi.

## Step 5 — Once confirmed, use sqlmap

Use `sql_injection_testing` capability with the confirmed parameter.
Pass the authenticated session cookies.
Let sqlmap handle extraction — it's faster and more reliable than
manual UNION SELECT.

## Step 6 — Document

Record: injection point, injection type, DB type, extracted data sample.
