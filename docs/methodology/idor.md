# IDOR — `_test_idor`

Confirm on an object **positively attributable to another principal**, proven on
four dispatched arms plus that principal's own authorized read. Never on a
content or length delta, and never with one authenticated principal.

## The defining effect, and why it needs a second identity

An IDOR confirmation is a claim that principal A was served an object belonging
to principal B. Everything hard about it is in *belonging*: that is a relation
between a response and an identity, not a property of a response. A response that
differs from A's own is not evidence, because so does a public catalogue record,
so does an error page, and so does the next row of a table anyone may read.

`models/vuln_classes.py` has said so since the registry was written —
"Requires at least two authenticated roles to prove that an authorization
boundary was crossed. With a single role (or none) the class can only report
candidates" — and the report rendered that verbatim while the oracle emitted
`high`/CONFIRMED on a single role **49 times**. A limitation only the report
knows about is a disclaimer, not a rule. It is now a field
(`MultiPrincipalRequirement`) the code reads, enforced in two places.

## The four arms

| arm | carried as | what it must show |
|---|---|---|
| `self` | A, `ref(A)` | A's own object — the identity values the crossing arm must NOT have returned |
| `crossing` | A, `ref(B)` | an object positively attributable to B |
| `nonexistent` | A, `ref(∅)` | must differ **materially** from `crossing` |
| `anonymous` | no session, `ref(B)` | must NOT return it — if it does the object is public |

Plus a fifth observation that is **not a control**: `owner_read`, B's own
authorized read of the same reference. That is what makes `ref(B)` attributable,
and it is the arm a single-role engagement cannot dispatch.

Decision order (`agents/_idor_oracle.py::decide_idor`), which is the order a
reviewer would ask the questions in:

1. Did the crossing arm resolve at all?
2. Is the object PUBLIC (the anonymous arm was served it)? ⇒ **not applicable**,
   no lead. A lead per public endpoint is a permanent false alarm, and a
   permanent false alarm trains an operator to skim the section where a real one
   will appear.
3. Did the control refuse (`ref(∅)` differs materially from `ref(B)`)? ⇒ a
   control-arm KILL, disclosed at the shared `_run_control_arm` seam.
4. Is the crossing response A's own object read back? And is the difference from
   A's own just our reference **echoed**? (see *Reflection* below)
5. Is it positively attributable to B? Without a second principal the answer is a
   **lead**, never a finding.

## The inversion — `ref(∅)` was the precondition and is now the control

Phase 5 used to open with:

```python
if not primitives.authz_check_present:
    return False, "no authorization boundary observed ... public lookup, nothing to bypass"
```

Phase 2 sent an out-of-allotment reference (`id=99999999` / the all-zero UUID)
and phase 5 required the target to have REFUSED it. Measured over the trace
corpus (2,955 engagements, 147 with IDOR phases, offline —
`docs/methodology/idor-crawl-coverage.md` records the method):

| | |
|---|---|
| phase-5 verifications run | 717 |
| refusals attributable to that one gate | **616 of 668 (92.2%)** |
| phase-2 fingerprints recording `authz_check_present` False | **1,226 of 1,256 (97.6%)** |

The gate is not merely strict, it is backwards. An application that answers 404
for an id nobody owns and 200 for a neighbour's record is *discriminating
perfectly* — it is the textbook IDOR — and that is precisely the shape the
precondition read as "no boundary exists". Engagement `9317e813` solved
`basketAccess` and `forgedFeedback` while emitting zero IDOR findings **and zero
IDOR leads**: all 51 of its phase-5 verifications died on this line.

`authz_check_present` is still computed and still recorded — it is a real
observation and `rank_idor` reads it — it just no longer decides.

## The control must round-trip

`ref(∅)` is compared against `ref(B)` through the same handler, encoder and
template, so it is synthesized in the reference's **own shape**
(`synthesize_absent_reference`):

* **numeric** → far outside the issued range, derived from the references
  actually observed rather than the old constant `99999999`, which is a
  plausible primary key on any system with eight-figure ids;
* **uuid** → a fresh v4, built from a seeded RNG so a replay re-derives it;
* **hashed / opaque** → the same length and character classes, decided for the
  whole value (a hex value stays hex; a mixed token keeps letters as letters).

A minted `clinkzdecoyidor48211` would be **encoding-invariant**: it fails to
parse as an identifier, takes the target's generic error path, differs from
everything, and would pass on a vulnerable target and a phantom alike — the same
failure `sqli_inert_control` exists to avoid. So `_run_control_arm` takes a
caller-supplied `decoy` for the classes in `DIFFERENTIAL_CONTROL_CLASSES`, and
still owns the recording, the ledger row, the trace and the disclosure.

The shape copied is the **crossing arm's** reference, not whichever value was
collected first: on a parameter whose baseline was `x` and whose crossing
reference was `longreference123`, the first observed value produced a
one-character control for a sixteen-character reference.

## Attribution

Two routes, in strength order (`attribution_between`):

1. **`identical_rendering`** — the crossing arm and B's own read normalise to the
   same fingerprint. One handler served one record to two principals.
2. **`stable_fields`** — the renderings differ (an API envelope naming the
   caller, chrome carrying A's own name) but ≥2 of B's field VALUES came back to
   A **and are not values A's own record carries**. Subtracting A's record is the
   load-bearing half: every field the template renders for everybody is in A's
   record too, so the residue is what is specific to B. One shared value is a
   property of the template, not of the principal.

## Reflection is NOT covered by the control

A parameter that echoes its input defeats every other arm at once: `ref(∅)` is
echoed too (so the control sees a different string and *refuses*, correctly), and
B's read of the same reference echoes the same string back (so it reads as an
identical rendering). Three arms agreeing on an artifact of one substitution is
not three pieces of evidence. So reflection keeps its own guard,
`reflection_explains`, applied before attribution: substitute A's own reference
back in for the echoed one and compare normalised bodies — the same test phase 1
makes on a pure reflection sink, and the same echo guard the injection classes
make on their own payloads.

Two of the old hand-written guards ARE subsumed by the control: an error page and
a response that collapses to a fraction of a substantial baseline are both "the
response is a property of the handler", which `ref(∅)` reproduces exactly.

## The two tiers, enforced in two places

**Tier 1 (multi-role) MAY CONFIRM.** ≥2 proven principals, positive attribution
against B's own authorized read.

**Tier 2 (single-role) MAY ONLY LEAD.** `why_unconfirmed =
single_role_cannot_attribute`, registered in `UNPROVEN_WHY_UNCONFIRMED`. The lead
carries every arm that was dispatched and says what supplying a second credential
would buy. "Not A's" is satisfied identically by a public catalogue record, so
three negatives are not a positive.

Enforced at the methodology (phase 5 refuses and writes the lead) **and** at
`_persist_finding` (deterministic ground 9,
`_fp_ground_insufficient_principals`), because a rule a class has to remember is
a rule that holds until the twenty-fifth class is written. Ground 9 compares a
registry declaration against the run's own principal list — both engine facts, so
nothing the target sends can influence it in either direction, and it needs no
structured-evidence reader.

A direct methodology invocation (a smoke suite, a replay, a driver) holds no
principals and is therefore in the single-role tier. That is the honest answer
rather than an exemption: an invocation with no second identity cannot attribute
an object to one.

## Carrying an arm as a named principal

`_role_sessions` now reaches Exploit (`role_sessions` on the phase message →
`parse_role_sessions` → `ExploitAgent._principals`). Arms are carried by
`_as_principal`, which swaps the ambient session material and declares a session
mode at the HTTP chokepoint:

* `ambient` — the shared jar is read and written. Every ordinary probe, and the
  `self`/`crossing`/`nonexistent` arms when the primary role IS A.
* `isolated` — the jar is untouched in both directions; the explicit cookies and
  headers are the only session material. **New**, and required: under `ambient`
  curl still passes `-c <jar>`, so role B's `Set-Cookie` would overwrite the
  engagement's own session and every later probe would silently become B.
* `none` — no session material at all. The anonymous arm, declared rather than
  arranged.

`_as_principal` is not re-entrant: nesting raises, because concurrent use would
send one principal's session under another's label, which is the one mistake an
access-control oracle cannot survive. Only an `ambient` response is
`session_bearing`, so a role-B 401 is never read by the session sentinel as our
own session expiring.

## Verification-honest emission (retained guards)

IDOR still gates the phase-3/4 LLM checkpoints behind a deterministic divergence
check, and these still hold:

1. **Auth-form / credential / CSRF-token params** (`username`, `password`,
   `Login`/`submit`, `user_token`, and any `csrf`/`token`/`nonce`/`captcha` name)
   are not object references and are excluded at the top of phase 1 before any
   probe.
2. **Divergence fingerprint** (`idor_body_fingerprint`, now the ONE rule in
   `_idor_oracle` that the agent delegates to) folds long hex runs in addition to
   numbers/whitespace, so a page regenerating a per-request CSRF token does not
   read as divergence.
3. **Reflection-sink exclusion** in phase 1, before any LLM call.

## Probe-URL construction

Probe URLs are built so a same-named query param is **replaced in place**
(`_build_request_url`), never appended as a duplicate (`?id=a&id=b`).
`_build_request_url` resolves `:id`/`{id}` **path-segment placeholders** first
(`_resolve_path_params`) from the task params, or a benign default (`1`) so the
base fetch never requests a literal `:id` — so discovered templated SPA/API routes
like `/rest/basket/:id` are probed by substituting into the path (the real IDOR
probe `/rest/basket/2`) rather than appending a stray `?id=`.

## Known gap — the class has to be PLANNED against a record handler

The oracle fix is necessary and not sufficient. Across the whole four-level DVWA
ladder the IDOR bucket held tasks for exactly two endpoints, both source viewers,
and never for `/vulnerabilities/authbypass/`, `/vulnerabilities/bac/` or
`/vulnerabilities/api/`. **Detail →
[idor-crawl-coverage.md](idor-crawl-coverage.md).**
