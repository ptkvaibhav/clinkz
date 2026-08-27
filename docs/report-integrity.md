# Report integrity — the document may not contradict itself

`src/clinkz/agents/_report_integrity.py`

Three sections of the client deliverable read **one field each** and stated a
conclusion the rest of the same document refuted. That is a worse failure than a
missing section: a client reads the conclusion and has no reason to check it, and
every one of these is visible on the first page without tooling.

The pattern is the one `reconcile_with_model_stamp` already establishes — a claim
is reconciled against the run's own record, at **both** the build seam (so
`report.json` carries the reconciled claim) and the render seam (so a stored
bundle re-renders honestly). Every function in the module is pure and reads only
what the **engine** declared; a response body has no route into any of them.

---

## 1. The testing window is measured, not the report's own clock

`test_start` and `test_end` were `input_data.get(...) or datetime.now(UTC)` and
**nobody ever passed either**. So both ends were the report-generation instant:
`9317e813` ran 4,597s and its PDF said zero, rendered directly beneath
*Authorized window* — the one place the document evidences that testing happened
inside the window the client agreed to.

**The producer is the governor**, because it is the only component every
dispatched request passes through. `EngagementGovernor._stamp_request_window()`
runs on the *authorized* path only (a refused request is not a request the
engagement made) and `stats()` emits `first_request_at` / `last_request_at`. The
orchestrator hands both to the Report agent.

### The rule, and its one exception

> Whenever any request was sent, `test_end > test_start`, or the render fails.

`assert_testing_window_renderable` raises `TestingWindowError`. The exception is
a bundle carrying **no stamp at all** — the *absence of the key* is what tells a
new bundle apart from an old one. A bundle written by this version always has
`first_request_at`, so a degenerate window there is a defect and fails loudly; an
older bundle has no honest value to substitute and renders

```
not recorded — this engagement's requests were not stamped with a window, so the
times below are the report-generation clock and are NOT evidence of when testing ran
```

A zero-length window is **never** rendered as though it had been measured.

### Recovering a stored bundle's window

`clinkz report-pdf` reads `outputs/<id>/actions.jsonl` when the report carries no
stamp (`request_window_from_log`). That log is the governor's own writer and sits
inside the bundle, so the window is *recovered*, not invented — but it is
**narrower** than the governor's, because the log records state-changing requests
and browser navigations rather than every GET. The provenance therefore renders
beside the window rather than being folded away, and a live stamp is never
overridden.

---

## 2. Authentication: a negative claim is only as good as the check behind it

`3c47a0de` rendered

> **Authenticated state:** NOT established — this engagement examined only the
> surface reachable without a login

and, three sections later, *"Anything behind authentication was not examined"* —
above **22 findings** at `/vulnerabilities/sqli/`, `/exec/`, `/fi/` and
`/upload/`, every one of them behind DVWA's login.

### Root cause: the sweep's session never reached the record

`_authentication_summary()` reads exactly two fields — `_role_sessions` and
`_auth_assertion` — and only `_authenticate_roles` (the **supplied**-credential
path) writes them. The **default-credential sweep** takes a different route:
`_attempt_login` on success calls `_cred_store.mark_valid(...)` with the session
cookies, the cookie-jar path and any bearer token. That is what every later phase
reads, and it is how the ladder reached the vulnerable modules — the run log says
`DEFAULT CRED VALID: admin:*** on http://clinkz-dvwa:80/login.php` on **all four**
ladder levels.

So a run that was logged in for its whole duration reported that it had never
logged in.

`_register_swept_session` fixes it: the session is filed under
`SWEPT_CREDENTIAL_ROLE` (`default-credential-sweep`) — deliberately *not* a
supplied role name, because "a credential the client handed us" and "one this
engine guessed" are different provenance and the client is entitled to know which
opened the door. `_session_material_source` is set on **both** routes.

`established` stays `False`. Holding session material and having **proven** a
session are different facts: *we posted a password and got a cookie* is the
assumed-not-proven claim this codebase refuses everywhere else, and
`_role_session_handoff` skips it, so an unproven session never travels as a
principal an access-control oracle could compare against.

### The reconciliation

`authentication_verdict(auth, finding_count)` returns one of four states:

| State | When | May assert "no session"? |
|---|---|---|
| `PROVEN` | an assertion established the session | — |
| `DISPROVEN` | an assertion **ran** and found no boundary discriminator | **yes**, with its `why_unproven` |
| `INCONSISTENT` | the record says no session and the run's output refutes it | **no** |
| `NOT_ATTEMPTED` | no session, nothing contradicting that | **yes** |

Two engine facts refute a `authenticated=false` record:

1. **Session material held** — `session_material_held`, the sweep's case.
2. **Findings with no assertion** — confirmed findings exist and `assertion is
   null`, so *no check ever ran*. A negative resting on a check that never
   executed is the same defect as `0 findings identified. Risk rating:
   Informational`.

`INCONSISTENT` renders

> **Authenticated state:** INCONSISTENT — session evidence present, record
> absent.

with the contradictions listed, and the *What was NOT tested* item is rewritten
by `reconciled_not_tested_reason` — at the render seam too, because a stored
bundle carries the sentence its original run wrote and a corrected header does
not un-write it three sections later. The reconciliation only ever **tightens**.

---

## 3. The control-arm page names the rule that governs

The section header promised *"the row says which rule applies instead"*. **19 of
29 rows** across the two generated PDFs said only which rule does **not** govern
them:

> this class confirms on its defining effect rather than on a marker in a
> response body, so the never-sent-control rule does not govern it

Nineteen verbatim repetitions of an absence invite a client to read the strongest
evidence in the document — a browser-witnessed nonce, a rejected broken signature
— as unverified.

A class the never-sent rule does not bind is **not** a class with no control; it
is a class whose control is a different rule. So the **producer declares it**:
`VulnClass.control_arm.governing_rule` (with `evidence_key`, the field in the
finding's own structured evidence carrying the observation that rule turned on).
Required for every class in `CONTROL_EXEMPT_CLASSES`; the row renders

```
brute_force  governed by its own rule
  a POSITIVE control: every attempt is proven to have REACHED the authentication
  handler and been answered with an auth failure, so 'no lockout' is a measurement
  rather than a failure to arrive.
  Observed: positive_control=all 8 attempts reached the authentication handler
```

`control_arm_row` raises `ControlArmRuleMissingError` on a row that names no rule,
so the render fails rather than shipping the twentieth repetition.

### Reading the observation

`declared_observation(evidence, key)` tries two shapes, and neither is reachable
by the host under test:

1. `structured_evidence_field` — one token out of a fully-structured entry
   (`control_silent` inside P7's `primitive=… executed=… control_silent=…`).
   First, because it is precise.
2. An entry whose **first token** is `key=` — the whole entry is one prose
   observation. Anchoring at position 0 is what makes this safe: every entry
   carrying target bytes is written by the engine with its own `Request: ` /
   `Response: ` prefix, so a body cannot occupy position 0. Same distinction that
   spared the juice-shop authentication bypass — `startswith` where `re.search`
   would have scanned on into the target's own text.

The quoted observation is capped at `_MAX_OBSERVATION_CHARS` and the cut is
stated; the finding's own evidence block carries the entry in full.

### The guard's domain is computed

`tests/test_agents/test_report_integrity.py` computes the domain from
`CONTROL_EXEMPT_CLASSES` and asserts **both** directions — a new exempt class
with no rule fails the build, and a rule on a class the never-sent rule *does*
bind fails too (that row reports its dispatched arm's verdict, so a second
answer to the same question would go unread). `_test_tier2_technique` and
`_test_tier3_technique` are outside the domain by construction: they are not in
`_BY_METHOD`, they construct no `Finding` (all three exits `return []`), and no
control-arm row can ever name them.

---

## 4. IDOR attribution carries no target data

`attributing_values` was `field=value` pairs out of the **owning principal's**
record — the first target data an IDOR finding has ever carried. Bounding each to
80 characters bounded *volume, not sensitivity*: on a client engagement that
value is a real customer's email or postal address, in a document that gets
emailed.

Attribution does not need it. `attributing_fields` renders

```
field=<name> owner_fp=<hash> caller_fp=<hash|absent>
```

- `owner_fp` — equal on the crossing arm and B's own authorized read: *this is
  B's record*.
- `caller_fp` — different, or `absent`: *and it is not A's*.

Together that is the whole claim. The field **name** survives because it is
schema, not data — `billing.email` is the application's own vocabulary and is
what a remediation has to name. The fingerprint is `credential_shapes.fingerprint`
— per-process salted, so two lines in one bundle can be compared and nothing in
it can be replayed or reversed. Same trade as `AuthArtifact.principal`: the claim
survives, the value never lands.

---

## 5. Cost, and the document's own name

**`$0.00` beside "a LOWER BOUND" reads as a wrong number rather than an honest
one.** The engagement did not cost nothing — it consumed 92,225 tokens of a model
with no declared rate. `spend_cost_line` renders `not priced (no declared rate
for: claude-sonnet-5)`; a partly-priced run reads `at least $1.25 (a LOWER
BOUND…)`; a fully-priced one is a plain number.

**The two PDFs were titled by two different rules**, because
`EngagementScope.name` is the operator's `--scope` label when one was supplied
and the raw `--target` string when one was not. `document_title` is one rule used
by the cover, the page footer and the `/Info` dictionary, so those three can
never disagree: the target is always named, and the operator's label is added
only when it says something the scope entry does not already carry.
