# Lessons (index)

A small, append-only archive so the same error is not made twice.

- **Consulted** during planning ONLY when a task resembles a past failure. Not
  read by default — do not open it for unrelated work.
- **Appended to** ONLY after an error worth not repeating.
- Each lesson has a **stable id** (`#14`–`#33`) cited elsewhere as `LESSONS #N`.
  Ids are historical — do NOT renumber (the sequence begins at #14; earlier ids
  are retired). Full narratives live in
  [`docs/lessons/README.md`](../docs/lessons/README.md); this file is the index
  (title + the rule each produced). Append a new lesson with the next id, add its
  narrative there, and add a one-line pointer here.

## Index

- **#14 — "Works in isolation, fails in pipeline" = poisoned session state, not a request diff.** Diff the *recorded* requests and suspect state an earlier phase mutated; a crawler must never follow a security-posture-changing link (`is_state_changing_url`). → [narrative](../docs/lessons/README.md#lesson-14)
- **#15 — Verify the premise before fixing.** Run the smoke test first instead of trusting the brief — a bare-separator CMDi probe is inert when the command writes only to stderr. → [narrative](../docs/lessons/README.md#lesson-15)
- **#16 — "katana only surfaces login.php" was an uninitialised DVWA DB.** Confirm the target's data plane is initialised before blaming the code path; an "authenticated" smoke test must prove the session is authed (PHPSESSID alone ≠ authed). → [narrative](../docs/lessons/README.md#lesson-16)
- **#17 — An LLM-populated `list[str]` field is a latent crash.** Type it `list[dict[str, Any]]` + a coercing validator; a broad `except` around model construction hides a schema mismatch as a silent feature outage. → [narrative](../docs/lessons/README.md#lesson-17)
- **#18 — The smoke fixture forces the deterministic fallback, never the live-LLM path (the false-green precedent).** A keyless/silent-LLM harness proves only the fallback; verification keyed on LLM-produced fields needs a live-vocabulary test and must reject on missing evidence, not an unrecognised label. → [narrative](../docs/lessons/README.md#lesson-18)
- **#19 — "The target ships an OpenAPI spec" — Juice Shop ships none.** Probe the RUNNING target for an asserted artifact before building on it; keep the deterministic fallback. → [narrative](../docs/lessons/README.md#lesson-19)
- **#20 — Multi-line commit messages on Windows.** Write the message to a file and use `git commit -F` / `gh pr create --body-file`; `-m $var` breaks when the body contains `"`. → [narrative](../docs/lessons/README.md#lesson-20)
- **#21 — The PowerShell tool channel has degraded mid-session.** If PowerShell tool calls fail in a non-syntax way, switch to the Bash tool. → [narrative](../docs/lessons/README.md#lesson-21)
- **#22 — A "justified non-finding" must be proven where the vuln is LIVE.** Stand up an instance with the challenge enabled (`safetyMode=disabled`) before calling a non-finding justified; a mocked-engine unit suite hides real detection bugs; use `TOOL_EXEC_MODE=local` for the in-process HTTP path. → [narrative](../docs/lessons/README.md#lesson-22)
- **#23 — A test `ToolBase` subclass leaks into resolver discovery.** Reap garbage (`gc.collect()`) at the point that reads a global `__subclasses__()` registry; a leaking fixture cannot self-evict. → [narrative](../docs/lessons/README.md#lesson-23)
- **#24 — Piping the keyless gate through `tail`/`&&` reports the pipe's exit, not pytest's.** Capture pytest's own exit code directly (`… > out.txt 2>&1; echo "EXIT=$?"`). → [narrative](../docs/lessons/README.md#lesson-24)
- **#25 — "The module exists" — verify the running target's VERSION ships it.** Curl the running target for an asserted module as step 0 (a frozen vuln-app image predates the cheat-sheet); curl-works-but-Python-fails on localhost is the dotless `domain=localhost` cookie trap. → [narrative](../docs/lessons/README.md#lesson-25)
- **#26 — Reusing a signature/matcher across a new response channel needs a content-shape check.** A line-anchored regex tuned for a raw channel fails on a wrapped/embedded one; reproduce the real wrapped response in a test. → [narrative](../docs/lessons/README.md#lesson-26)
- **#27 — Uniform confirm across a graded control = the oracle matches the benign response.** Treat uniform-confirm-at-every-security-level (incl. impossible) as a prime phantom signal; prove the wire reached the app; an acceptance marker must never be a substring the app emits on its benign/failure path. → [narrative](../docs/lessons/README.md#lesson-27)
- **#28 — A phase-2-confirmed primitive: phase-4 must prefer the deterministic build over the live LLM.** The LLM paraphrases/mangles a proven payload (a dead `%00`); back a stack-conditioned branch with a deterministic protocol artifact (PHPSESSID), never the flaky LLM tech list alone. → [narrative](../docs/lessons/README.md#lesson-28)
- **#29 — Confirms NOTHING in-pipeline but passes its isolated skill test = a DISPATCH gap.** Check the endpoint even REACHED the method with the params it needs (read the trace's per-endpoint phase events); pair an isolated `_test_*` test with a through-dispatch test; a first-seen dedup loses the richer duplicate. → [narrative](../docs/lessons/README.md#lesson-29)
- **#30 — A "FALSE POSITIVE" call can itself be a misdiagnosis.** Reconstruct the EXACT request the code issued (read the recorded `tool_invocations`/trace) before calling a full-pipeline finding a phantom; `_build_request_url` REPLACES same-named params (never doubles). → [narrative](../docs/lessons/README.md#lesson-30)
- **#31 — The live Log4Shell OOB channel is `jndi:dns://<collab>:<dns_port>/<nonce>`, not `ldap://`.** Empirically probe which callback fires from the live target's runtime before coding the OOB channel; `host.docker.internal` can resolve IPv6-first inside a container. → [narrative](../docs/lessons/README.md#lesson-31)
- **#32 — A driver's verdict logic can report a real PASS as INCOMPLETE.** Read where the methodology actually put the confirmation (`finding.evidence`), not an assumed attribute; read the raw finding output before trusting a verdict line. → [narrative](../docs/lessons/README.md#lesson-32)
- **#33 — Prove "X changes nothing emitted" with an A/B that holds structure constant.** Vary ONLY X, never diff two differently-structured runs; a "nothing reads Y" grep must match the READER symbol only (a write/recompute call is not a read). → [narrative](../docs/lessons/README.md#lesson-33)
