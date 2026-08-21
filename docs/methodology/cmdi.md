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

## The channel is chosen by measurement, not by the model (phases 1, 3, 4)

Phase 1's echo-canary sweep runs **unconditionally** and reports WHICH separator
carried the marker (`ShellPrimitives.marker_separator`). When one did, phase 4
builds `<original><sep>echo <marker>` deterministically and never calls the LLM:
the defining effect is already demonstrable on a channel nothing else produces,
so there is nothing left to decide.

The sweep used to be skipped whenever a bare separator diverged — which is every
DVWA level — so the strongest primitive this class has went unrecorded, the model
ranked `blind_time` first, and phase 4 built a `sleep`.

## The time channel is a paired differential (phase 5)

`time_delta` compares against **this endpoint's own baseline**, interleaved and
repeated (`_CMDI_TIME_REPEATS` pairs, every delta ≥ `_CMDI_TIME_MIN_DELTA`), and
renders both arms of every pair into the evidence.

The predecessor timed one request against a fixed 4.0-second constant and never
read the baseline it was passed. DVWA's exec page runs `ping -c 4`: the untouched
baseline measures **4.04s**, so the oracle confirmed command injection on a
request carrying no payload, and the never-sent control (which measured 8.00s on
`test;sleep 5` with the separator removed) correctly killed six ladder findings.

An absolute threshold cannot be rescued by raising it — the number that separates
"slow page" from "our sleep ran" is a property of the endpoint. Full measurements:
[defining-effect-oracles.md](defining-effect-oracles.md).
