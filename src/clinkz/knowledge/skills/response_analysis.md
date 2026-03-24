# Response Analysis — Analytical Skill

How to analyze HTTP responses for vulnerability indicators:

## 1. Size Comparison

Record baseline response size. Significant difference (>10%)
indicates the input affected server behavior.
```
Baseline: GET /search?q=normal → 4523 bytes
Test:     GET /search?q=' → 3102 bytes (31% smaller → error page)
Test:     GET /search?q=normal' AND '1'='1 → 4523 bytes (same → injected successfully)
```

## 2. Error Detection

Search for keywords in the response body:
- **MySQL**: `You have an error in your SQL syntax`, `mysql_`, `mysqli_`
- **PostgreSQL**: `PG::SyntaxError`, `ERROR: syntax error at or near`
- **SQLite**: `sqlite3.OperationalError`, `SQLITE_ERROR`
- **MSSQL**: `Microsoft OLE DB`, `unclosed quotation mark`
- **Oracle**: `ORA-`, `PLS-`
- **General**: `error`, `warning`, `exception`, `syntax`, `stack trace`,
  `ODBC`, `unexpected`, `fatal`

## 3. Reflection Detection

Search for your exact input string in the response body. Note WHERE
it appears:
- **HTML body**: `<div>YOUR_INPUT</div>` → XSS candidate
- **HTML attribute**: `<input value="YOUR_INPUT">` → attribute breakout
- **JavaScript**: `var x = 'YOUR_INPUT';` → JS injection
- **HTML comment**: `<!-- YOUR_INPUT -->` → comment breakout
- **URL/href**: `<a href="YOUR_INPUT">` → javascript: protocol

## 4. Timing Analysis

If response took significantly longer (>3 seconds more than baseline),
time-based injection may work:
```
Baseline: GET /user?id=1 → 200ms
Test:     GET /user?id=1' AND SLEEP(5)-- → 5200ms (TIME-BASED SQLi)
```

## 5. Status Code Changes

- `200 → 500` = injection caused server error
- `200 → 302` = unexpected redirect (auth bypass or error handling)
- `200 → 403` = WAF or access control triggered
- `200 → 200` but different body = blind injection candidate

## 6. Redirect Changes

Unexpected redirect may indicate:
- Authentication bypass (redirect to admin panel)
- Error handling (redirect to error page)
- Input-dependent routing (open redirect candidate)

## 7. Important

Response bodies can be very large. Focus on the RELEVANT section,
not the entire HTML page. Search for your input string, error
keywords, or known patterns rather than reading the full response.
