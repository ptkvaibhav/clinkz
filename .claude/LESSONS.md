# Lessons

This file records recurring mistakes and their fixes — a small, append-only archive
so the same error is not made twice.

- **Consulted** during planning ONLY when a task resembles a past failure. It is not
  read by default; do not open it for unrelated work.
- **Appended to** ONLY after an error worth not repeating. Each entry is concise:
  what went wrong, then the fix.
- Do not pre-seed it. Entries accumulate organically from real errors.

## Lessons

- **"Works in isolation, fails in pipeline" can be poisoned server-side session state, not a request-shape diff.** DVWA SQLi/XSS confirmed nothing in the pipeline while their smoke tests passed. The pipeline requests were byte-for-byte correct (Submit param, GET/POST, `security=low` cookie all fine) — the difference was that the crawl phase had GET-visited `security.php?phpids=on`, enabling DVWA's session-scoped PHPIDS WAF for the whole shared engagement session, so every injection returned a 58-byte block page. Fix: when a methodology works standalone but not in-pipeline, diff the actual recorded requests AND consider server/session state the earlier phases mutated — don't assume it's the request. A black-box crawler must never follow links that change the target's security posture (WAF/security toggles, logout); added `agents/_url_safety.py::is_state_changing_url` as the crawl/plan chokepoint.
- **Verify the premise before fixing — "passes in smoke" was false for one of three.** CMDi was assumed to work in isolation, but its phase-1 candidacy actually failed in smoke too: bare-separator probes against base value `test` produce identical output because `ping <bad-host>` writes only to stderr (dropped by `shell_exec`). Running the smoke test first (instead of trusting the brief) surfaced this and turned a "pipeline-only" assumption into a real methodology bug + a separate fix.
