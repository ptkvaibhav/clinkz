# IDOR — `_test_idor`

Confirm on an **authorization boundary actually crossed** (out-of-allotment id
rejected; forged id serves another principal's record) — never on a content-length
/ body delta with no boundary present.

## Verification-honest emission

IDOR gates the phase-3/4 LLM checkpoints behind a deterministic divergence check
(a probe must differ from baseline in status, length, or normalised body
fingerprint) — identical responses make no LLM call and emit nothing. Five guards
keep that honest:

1. **Auth-form / credential / CSRF-token params** (`username`, `password`,
   `Login`/`submit`, `user_token`, and any `csrf`/`token`/`nonce`/`captcha` name)
   are **not object references** and are excluded from candidacy at the top of
   phase 1 before any probe.
2. **Divergence fingerprint** (`_idor_body_fingerprint`) folds long hex runs in
   addition to numbers/whitespace, so a page that regenerates a per-request CSRF
   token (e.g. DVWA `login.php`, identical length 1524→1524 but a fresh
   `user_token` each GET) does NOT read as divergence — closing the phantom where
   login-form params emitted IDOR findings.
3. **Reflection-sink exclusion** — phase 1 sends a canary probe and, if the canary
   is echoed AND substituting the original value back where it reflected
   reconstructs the baseline fingerprint, the param is a reflection sink (e.g.
   DVWA `xss_r`'s `name` → "Hello &lt;value&gt;") and is excluded before any LLM
   call; the phase-5 echo branch that read a reflected reference as "new identifier
   echoed" is removed.
4. **Phase-5 resource honesty** — a verified IDOR's response must be another
   principal's actual record, so phase 5 rejects error/not-found/denied pages and
   responses that collapse to a fraction of a substantial baseline (the
   `view_source_all.php?id=<garbage>` 33484→1730 phantom).
5. **Phase-5 authz-boundary precondition** — an IDOR is the bypass of an
   authorization *boundary*, so phase 5 is passed the phase-2 `primitives` and
   refuses to verify when `authz_check_present` is False: if phase 2's
   out-of-allotment probe (`id=99999999` / all-zero UUID) was served a normal 2xx
   instead of 401/403/redirect-to-login, the endpoint is a boundary-less public
   lookup and content that merely differs between `id=2` and `id=3` is it doing its
   job, not an authz break (engagement ec39350b confirmed `info.php?id=2→3` despite
   `id=99999999`→200 — a 200-on-garbage endpoint with no control to cross); a
   genuine IDOR whose out-of-range id IS rejected still verifies.

## Probe-URL construction

Probe URLs are built so a same-named query param is **replaced in place**
(`_build_request_url`), never appended as a duplicate (`?id=a&id=b`).
`_build_request_url` resolves `:id`/`{id}` **path-segment placeholders** first
(`_resolve_path_params`) from the task params, or a benign default (`1`) so the
base fetch never requests a literal `:id` — so discovered templated SPA/API routes
like `/rest/basket/:id` are probed by substituting into the path (the real IDOR
probe `/rest/basket/2`) rather than appending a stray `?id=`.
