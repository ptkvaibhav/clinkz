# Behavior Observation — Foundational Skill

How to observe and understand application behavior before exploiting:

## Step 1: Establish Baseline

Send a NORMAL request first — record the baseline response
(size, status, key content).
```
GET /vulnerabilities/sqli/?id=1&Submit=Submit
→ Status: 200, Size: 4832 bytes
→ Content: "ID: 1, First name: admin, Surname: admin"
```

## Step 2: Observe Change

Send the SAME request with a slightly modified parameter —
record how the response changes.
```
GET /vulnerabilities/sqli/?id=2&Submit=Submit
→ Status: 200, Size: 4840 bytes
→ Content: "ID: 2, First name: Gordon, Surname: Brown"
```

## Step 3: Classify the Behavior

Based on the difference between baseline and modified responses:

- **Input echoed in response** → reflection-based vuln (XSS, SSTI)
- **Input causes data lookup** → data-retrieval vuln (SQLi, LDAP injection)
- **Input used in file operation** → path-based vuln (LFI, RFI)
- **Input used in command** → execution vuln (OS command injection)
- **Input used in URL fetch** → network vuln (SSRF)
- **Input used in template** → template injection (SSTI)
- **Input used in XML processing** → XXE

## Step 4: Understand the Application Logic

Ask yourself:
- What is this feature FOR? (search, user lookup, file viewer, calculator?)
- What does the server DO with my input? (query DB? include file? run command?)
- What OUTPUT does it produce? (user data? file content? error message? nothing?)

## Step 5: Form Your Hypothesis

```
"This parameter is used in a SQL WHERE clause because when I
change the value, different user records are returned. If I
inject SQL syntax, I can modify the query."
```

```
"This parameter is used in a file include because the value
looks like a filename and changing it to a non-existent file
causes an error mentioning 'include()'. If I use path traversal,
I can read arbitrary files."
```

## Step 6: Test Your Hypothesis

Send ONE targeted probe — not a spray of payloads.

```
# Hypothesis: SQL WHERE clause
GET /vulnerabilities/sqli/?id=1' AND '1'='1&Submit=Submit
→ Same response as id=1 → Hypothesis CONFIRMED (input is in SQL query)

# Hypothesis: File include
GET /vulnerabilities/fi/?page=../../etc/passwd
→ Response contains "root:x:0:0" → Hypothesis CONFIRMED
```

## Anti-Patterns to Avoid

- Spraying 50 payloads without observing any responses
- Skipping the baseline request
- Testing for XSS on an endpoint that does database lookups (wrong vuln class)
- Not recording response sizes for comparison
- Moving to exploitation before understanding what the server does with input
