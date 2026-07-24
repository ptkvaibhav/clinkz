# Command injection — `_test_cmdi`

Adaptive six-phase payload-injection methodology (reflection / fingerprint /
synthesize / verify pattern with LLM-driven payload synthesis). Confirm on
**command output in command-output position in a 2xx/3xx** — never on an
echo-canary reflected in a 4xx/5xx / stack trace.

## Echo-canary candidacy (phase 1)

Phase-1 candidacy runs a reflection-guarded **echo-canary** probe
(`<sep>echo <canary>`) so command injection surfaces even when the base command
writes only to stderr (e.g. DVWA's `ping <bad-host>`, dropped by `shell_exec`)
and bare-separator probes look inert (LESSONS #15 — the CMDi premise miss).

## Reflection-honest verification (phase 5)

- An indicator surfacing in an **error response** (HTTP 5xx or a shell/stack-trace
  error page) is rejected as input reflection — genuine command output comes back
  in a normal 2xx/3xx response in command-output position (`_cmdi_body_has_error`).
- The echo-scaffold reflection guard is **encoding-robust** — it decodes
  `echo%20<canary>` / entity forms before checking.

This closes the Juice Shop a07df54b phantom, where three "high" RCEs confirmed
off a 500 page that merely reflected the `;echo PWNED` payload string (Node, no
shell sink).

The `_cmdi_body_has_error` helper + the encoding-robust scaffold guard are reused
by SSTI phase 5 (arithmetic eval / RCE canary). See [ssti](ssti.md).
