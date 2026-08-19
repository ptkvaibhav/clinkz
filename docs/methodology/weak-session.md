# Weak session — `_test_weak_session`

Four-phase behavioral methodology. Session-token predictability is a
**deterministic gate**, and since 2026-08-19 **no LLM is called on the verdict
path at all**.

The gate itself was already deterministic; what the model still produced was an
advisory rationale that phase 4 copies verbatim into the finding's `evidence`
list. Model prose sitting in an evidence field beside measurements is a claim
nobody made, and across the recorded phase-3 calls the advisory changed the
verdict zero times — so the call bought nothing and carried a fabrication surface
into the deliverable. Removed rather than filtered: an advisory that may not be
quoted has no consumer. See
[deterministic-verdict-classes.md](deterministic-verdict-classes.md).

## Deterministic predictability gate (impossible-level honesty)

`_deterministic_session_weaknesses`: a predictability type
(`sequential`/`time_correlated`/`predictable_format`/`low_entropy`) requires
ground-truth corroboration —

- an integer arithmetic progression,
- a recent unix-timestamp window (**including a *constant* token equal to the
  current wall-clock second**, since fast sampling returns the same PHP `time()`
  value for every read — `abs(now-v)<=120`; a static numeric ID that is not "now"
  stays a non-weakness),
- a cracked md5/sha1/sha256 preimage (bounded brute force of consecutive integers
  + recent timestamps, `usedforsecurity=False`), or
- measured Shannon entropy below a bits floor.

So DVWA-impossible's `bin2hex(random_bytes(20))` (160-bit) can never be labelled
predictable regardless of LLM output, and a missing `SameSite` on an
HttpOnly+Secure cookie is a cookie-hardening note, never a HIGH weak-session
finding. Low (sequential int) / medium (`time()`) / high (`md5(int)`) still
confirm; impossible does not falsely emit.
