# SQLi — `_test_sqli`

Six-phase injection-family methodology (map → fingerprint → rank → synthesize →
verify → emit). Confirm on the **defining effect** (DB-error signature, boolean
row-set delta, or a UNION **data row in a *successful* non-error response**) —
never on a marker reflected in the body or inside an inline/4xx/5xx DB error.

## Breakout + column-count + reflection guard (Juice Shop 8df94e28)

- **Breakout context** (`InjectionPrimitives.break_prefix`): phase 2 discovers
  the breakout with a paired boolean tautology (`<closer> OR 1=1` vs
  `<closer> AND 1=2`) over candidate closers (`''`, `'`, `')`, `'))`, …) — the
  closer that *balances* the surrounding query (parses to 2xx and diverges
  true/false) — plus the **UNION column count** (`union_columns`) via
  `UNION SELECT NULL,…` enumeration. Cracks the canonical
  `/rest/products/search?q=` case (`((name LIKE '%<v>%' …))` needs `'))`, 9
  columns) that a bare `'` never reaches.
- **Phase 4** conditions synthesis on dialect + break_prefix + column count and
  **prefers the empirically-grounded deterministic build** when a breakout is
  known (an LLM guess that ignores the closer/column-count is the bug — same
  discipline as LESSONS #18/#28).
- **Phase 5 reflection-honesty:** a union/error marker echoed in a 4xx/5xx error
  response is input reflection, not data/error — rejected (the `/redirect?to=`
  406 phantom, finding #14). Two further 2xx reflection guards:
  - the **union** branch rejects a marker that survives only inside a verbatim
    echo of the submitted payload — `_marker_only_in_payload_echo` blanks the
    entity- **and backslash-**de-escaped payload echo via
    `_normalise_for_echo_compare` (HTML-unescape + undo `\X`→`X` + collapse
    whitespace, so an `addslashes`/`mysqli_real_escape_string` sink that turns
    the payload's `'` into `\'` STILL matches the blank), then requires the
    marker elsewhere (DVWA `csrf/test_credentials.php`'s
    `Wrong password for '<input>'` = the 1b8101dd phantom; DVWA xss_s/high
    `mtxMessage` escaped-echo phantom);
  - the **error_string** branch rejects an LLM indicator already present in the
    benign baseline body (page chrome — a generic `"SQL"` indicator matching
    DVWA's left-nav on the `xss_r` page = the b9dc3627 phantom).
- The genuine `/sqli/` `First name:` UNION data row still confirms, and a real
  DB-error signature (`has_db_error`) still confirms error-based regardless of
  the indicator. `_sqli_has_db_error` combines generic + dialect error tables so
  a real `SQLITE_ERROR` 500 still confirms; `(status=…)` is threaded into the
  union/error observed strings so the Step-3b backstop catches any SQLi phantom
  that slips phase 5.

## Escaping-robust marker-echo guard (impossible-level honesty)

The escaping-robust reflection guard above is the SQLi half of the DVWA
per-level honesty regression (low/medium confirm, high/impossible do not falsely
emit). See [dvwa per-level honesty](dvwa-per-level-honesty.md).

## Cookie-injection vector (Bucket-B DVWA `high`)

DVWA blind-SQLi `high` reads `$id = $_COOKIE['id']` — a cookie-borne injection
point invisible to `input_params` (HTML fields ∪ query keys ∪ endpoint params).

- **Dedicated carrier** `_cookie_send_probe` (`ParamLocation.COOKIE`) clones the
  ambient auth jar and overrides the ONE target cookie with the **URL-encoded**
  payload (clean on curl AND aiohttp's `SimpleCookie`; the server URL-decodes
  `$_COOKIE`), leaving session/auth cookies ambient. `_http_get`/`_http_post`
  gain a `cookie_overrides` arg (via `_effective_cookies`) that never mutates
  `_session_cookies`. The shared `_send_probe` is left untouched.
- **On-demand harvest** (`_harvest_injectable_cookies` in `_fetch_page`): find
  same-origin cookie-setter forms the page references (DVWA's `cookie-input.php`,
  basename-`cookie` heuristic), submit each once with benign values in a scratch
  request, harvest the non-session `Set-Cookie` names — bounded
  (`_MAX_COOKIE_SETTERS`), cached, scope + `is_state_changing_url` guarded,
  session-safe. Session/auth cookies (`_SESSION_COOKIE_NAMES` ∪ live
  `_session_cookies` keys) are excluded; only app-data cookies (`id`) are
  injectable.
- `_test_sqli` runs the six-phase methodology over `page.injectable_cookies` with
  a synthetic name `\x00cookie:<name>` (NUL-prefixed so it never collides with a
  same-named query param); phase 6 strips the sentinel to `id (cookie)`. The
  escaping-robust reflection guard applies unchanged through the carrier. N/A by
  construction on impossible (parameterised query) — no phantom.

## Session-indirection vector (DVWA `sqli/high`) — `ParamLocation.SESSION`

DVWA sqli/high reads `$id = $_SESSION['id']`, set cross-request via
`session-input.php` and read by `/vulnerabilities/sqli/`'s query — a **param-less
trigger** with no injectable input visible to `input_params`. Built general
(injection-family-agnostic carrier), wired to SQLi as first consumer.

- **Models** (`models/scan.py`): `ParamLocation.SESSION`,
  `SessionVector(setter_url, field)`, `Endpoint.session_setters`.
- **Discovery + queueing**: scan-side `find_session_setter_urls` (`_url_safety.py`)
  scrapes same-origin session-setter refs (incl. `onclick`/JS `popUp`) from the
  trigger HTML; `scan._apply_session_setter_annotations` stamps them onto the
  trigger `Endpoint.session_setters`; `_applicable_methods_for_endpoint` queues
  `_test_sqli` for any session-annotated param-less trigger.
- **Carrier** `_session_send_probe` (dedicated, shared `_send_probe` untouched):
  a set-then-observe (`_session_write_and_fetch`) — POST the payload to the setter
  field (benign siblings) so the server updates the `$_SESSION` slot keyed by the
  ambient session, GET the trigger, observe ONLY the trigger. Rides the ambient
  session, never mutates `_session_cookies`.
- **Link gate** (`_harvest_session_vectors`/`_probe_session_setter`) establishes
  the setter→session→trigger channel with BENIGN values only via (a) a unique
  marker reflected on the trigger, or (b) **value-dependent divergence** — a
  benign matching value (`_SESSION_LINK_HIT_VALUE="1"`) renders a trigger result a
  non-matching random marker does not. Signal (b) is load-bearing because DVWA
  high's `ID:` echo is row-gated (a non-matching marker yields no row). The gate
  NEVER confirms SQLi (benign values, no SQL) — phase 5 does, on a real effect.
- `_test_sqli` runs the methodology over `page.session_vectors` with a synthetic
  `\x00session:<field>` name; phase 6 strips it to `id (session)`.

### SQLi echo-sink honesty (the load-bearing phantom guards)

The session vector exposed two reflection blind-spots in the SHARED SQLi
methodology (both also latent on the DVWA low/medium query path, which echoes
`ID:{$id}`):

1. **Phase-2 breakout discovery** (`_sqli_discover_break_prefix`) mistook the
   `ID:` echo of two different payloads for a predicate divergence — the integer
   `user_id` coerces `'1 OR 1=1 -- -'` to `1`, so BOTH empty-closer probes match
   admin and differ only by the echoed payload — wrongly accepting the empty
   numeric closer over the genuine `'`. Fixed with `_diverges_beyond_payload_echo`
   (blank each body's own escaping-robust echoed payload before comparing; a real
   result-set divergence survives, so medium's numeric `''` is still accepted
   while high's spurious echo-`''` is rejected). AND the breakout probe must
   terminate with `-- -` (not the bare confirmed `comment_syntax[0]`): MySQL/
   MariaDB only treat `--` as a comment when followed by whitespace, so a bare
   `--` leaves the appended `' LIMIT 1` un-commented and the genuine `'` closer
   errors → `break_prefix=None` (matches `_sqli_count_union_columns`/phase-4,
   which hardcode `-- -`).
2. **Phase-5 union branch** accepted a union marker echoed inside an INLINE
   (status-200) DB error — DVWA renders `mysqli_error()` inline, so the 4xx/5xx
   guard never fires and the full-payload echo strip misses the partial fragment
   the parser reports (`near '<marker>'-- -'`). Fixed: a genuine UNION row comes
   from a SUCCESSFUL query, so reject when `_sqli_has_db_error(body)`; error_based
   confirms honestly on the signature instead.

**Live-validated on the real pipeline at all four DVWA levels** (LESSONS #18):
high confirms the session vector HONESTLY (error-based `1'` → genuine MariaDB
syntax error via `POST session-input.php [id=1'] → GET /sqli/`, NOT the union
phantom) alongside cookie `sqli_blind` (boolean) + fi; medium confirms `sqli/`
(error-based) + `sqli_blind` (boolean), numeric `''`; low confirms `sqli/`
(error-based) + `sqli_blind` (time-blind SLEEP) + brute `username`; impossible
emits none (PDO parameterized). N/A by construction at impossible.

## Context adaptation — the ladder tries the OTHER SQL context (gap G5)

At DVWA `medium` the SQLi methodology ran **9 verifications and emitted 0**; at
`high`, **15 and 0**. Two generic causes, neither about payload quality:

1. **A verification that could not run.** `_normalise_indicator_type` mapped the
   synthesis LLM's `content_diff` label onto the boolean oracle, which needs BOTH
   shapes — with no `control_payload` it returned `"boolean_blind missing
   control_payload"` **having sent nothing**, burning a ladder rung. It happened
   three times across the medium/high runs, always on a UNION payload the model
   mislabelled. `content_diff` without a control now falls through to
   payload-shape inference, which routes the payload to the check it can pass.
2. **Every rung re-sent the same quoted break.** Phase-4 synthesis defaults to a
   string-literal break (`1' AND '1'='1`). On a target that escapes quotes, every
   ranked type sends a variant of the same inert shape and the ladder never asks
   the other question.

`_sqli_adapt_context` runs after all ranked types fail: the same deterministic
`content_diff` oracle, in the **numeric / unquoted** context —
`{v} AND 1=1` vs `{v} AND 1=2`, `OR`, a commented variant, an arithmetic variant,
and a double-quoted variant, where `{v}` is the parameter's **own observed
baseline value**, discovered at runtime. These are injection *shapes*, not payloads
for a particular app: the injection either sits inside a quoted string literal or
is interpolated as a bare term, and a filter that neutralises one leaves the other
untouched.

It adds **reach, never a new way to confirm** — the oracle is the unchanged
boolean differential, so nothing that could not confirm before can confirm now.

**Batch 3 measured it and the premise did not hold.** Across six D1 runs the ladder
fired 110 rungs and confirmed **nothing**, while phase-4 synthesis produced the
bare-numeric shape by itself wherever one applied. It is now gated, bounded and
instrumented rather than trusted — full record and the decision in
[dvwa-sqli-context-ladder.md](dvwa-sqli-context-ladder.md).

## The boolean-blind oracle carries its own control (gap G14)

`_sqli_verify_boolean_differential` is the `content_diff` oracle for both the ranked
types and the ladder. It sends **`baseline → true → false` as one interleaved
triple** and repeats the whole triple `_SQLI_BOOLEAN_REPEATS` (3) times. A repeat
confirms when the true body differs from the false body, the true shape sits within
`_SQLI_BOOLEAN_TRUE_TOLERANCE` (10 B) of **its own** baseline, and the false shape
diverges from that baseline by more than the true shape and by at least
`_SQLI_BOOLEAN_FALSE_MIN_DELTA` (3 B). The confirmation additionally requires the
signed `false − true` size to be **identical in every repeat**.

This is strictly **stronger** than the single pair it replaces — a delta that
appeared once no longer confirms, and each repeat is judged against a
contemporaneous baseline, which removes page drift as a confound instead of
tolerating it. Why strengthen rather than loosen: a thin differential's problem was
never the gate, it was that the evidence did not *show* the delta was stable.
Engagement `fe234e99` demoted a real `boolean_blind` SQLi on a six-byte delta
(`true=4842B false=4848B`) called "normal response variance". The evidence now reads

```
stable boolean differential: baseline=[4842, 4842, 4842]B true=[4842, 4842, 4842]B
false=[4848, 4848, 4848]B over 3 controlled repeats; true-vs-baseline=0B (<=10),
false-vs-baseline=6B (>=3), false-minus-true=+6B identical in every repeat
```

and there is nothing left for a suspicion to grab: **a stable, reproducible,
controlled differential is deterministic proof regardless of its size in bytes.**
The string is threaded into both the `Response:` line and `indicator_observed=`, so
the finding answers "is this delta stable?" without a reader trusting a summary.

Every failure names a deterministic cause from a closed vocabulary —
`response_invariant_to_payload`, `true_shape_diverged_from_baseline`,
`false_shape_not_divergent_from_baseline`, `differential_not_reproducible`,
`missing_control_payload` — which the ladder reuses for its per-rung diagnosis.
