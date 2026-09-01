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
| `self` | A, the **anchored** `ref(A)` | A's own object, proven A's from A's own session |
| `crossing` | A, `ref(B)` | a record naming an owning principal that is not A |
| `nonexistent` | A, `ref(∅)` | must differ **materially** from `crossing` |
| `anonymous` | no session, `ref(B)` | must be **dispatched** and must NOT return it |

Plus a fifth observation that is **not a control**: `owner_read`, B's own
authorized read of the same reference. It is **corroboration** — see
*Attribution* — and it is the arm a single-role engagement cannot dispatch.

Decision order (`agents/_idor_oracle.py::decide_idor`), which is the order a
reviewer would ask the questions in:

0. Is `ref(A)` A's? Unanchored ⇒ **abstain** (see *Anchoring* below). Then the
   dispatch assertion: `ref(self) != ref(crossing)` and `ref(self)` is the
   anchored reference. A violation is a **loud refusal**, not a quiet abstain.
1. Did the crossing arm resolve at all?
2. Is the object PUBLIC? An anonymous 200 on `ref(B)` is **disqualifying, full
   stop** ⇒ **not applicable**, no lead. A lead per public endpoint is a
   permanent false alarm, and a permanent false alarm trains an operator to skim
   the section where a real one will appear. An anonymous arm that was never
   dispatched refused nothing and abstains.
3. Did the control refuse (`ref(∅)` differs materially from `ref(B)`)? ⇒ a
   control-arm KILL, disclosed at the shared `_run_control_arm` seam.
4. Is the crossing response A's own object read back? And is the difference from
   A's own just our reference **echoed**? (see *Reflection* below)
5. Does the OBJECT name an owner who is not A? No owning field ⇒ **abstain**.
6. Which direction did the arm run in?

## Anchoring — `ref(A)` is A's, or there is no crossing to grade

The self arm used to carry whatever value the **crawl** observed in the
parameter, and phase 4 produced `ref(B)` by varying it. A crawl-observed value
is a fact about whichever session was crawling, and on the 2026-08-31 Juice Shop
envelope those were different identities:

| | recorded run 3 | what it actually was |
|---|---|---|
| crawl saw | `id=1` | admin's basket (`UserId: 1`) |
| A | `jim` | **user 2** |
| `self` arm | `GET /rest/basket/1` as jim | admin's record — the real crossing |
| `crossing` arm | `GET /rest/basket/2` as jim | **jim's own record** |
| `owner_read` | `GET /rest/basket/2` as admin | jim's record again |

Every downstream arm cleared, because every one of them is a comparison and **a
comparison does not know which side it is standing on**. The control refused
(900043392 returned `data:null`), the anonymous arm was turned away (401), and
`identical_rendering` matched — admin reading jim's basket returns jim's basket.
Five findings shipped from that, on all four ladder-equivalent endpoints.

So `ref(A)` is now **discovered first, from A's own session**
(`anchor_self_reference`, dispatched by `_idor_anchor`): a bounded set of
candidate references is probed **as A**, and the anchor is the first whose record
names A as its owner. A's identity values come from
`Principal.identity_tokens()` — the operator-supplied username and the identity
claims of the bearer token the target issued **us**, decoded through the one JWT
decoder in the codebase — and never from a response, so a target cannot nominate
one of its records as ours.

**Unanchorable ⇒ the class abstains**, with the reason
`self_reference_not_anchored_to_the_caller` and an `UnprovenExploitLead` naming
what is missing. A crossing you cannot anchor is not a crossing. That is the
honest answer for a reference that is not user-owned at all (a product id), for
an endpoint whose records do not name their owner, and for a session whose
identity we cannot read.

`ref(B)` is then varied from the **anchored** reference, and the assertion
`ref(self) != ref(crossing)` runs both before dispatch and again on what was
actually sent.

**What the sweep costs.** At most `_IDOR_ANCHOR_CANDIDATE_LIMIT` (6) probes per
candidate parameter, carried as A, and it stops at the FIRST record naming the
caller — two requests on the Juice Shop basket. Bounded because an anchor that
needs a wide sweep is one the endpoint does not support: an application that
names a record's owner names it on the caller's own record, which sits within a
step or two of whatever the crawl saw. A wider sweep would not find an anchor,
it would find more strangers' records. Non-numeric formats get only the values
the endpoint was already SEEN to accept — enumerating opaque identifiers is not
discovery, it is noise aimed at a client's target.

**The reflection guard needs a floor, for the same reason.** Substitution is
global, so with `ref(B)="1"` and `ref(A)="2"` rewriting every `1` in
`{"id":1,"UserId":1}` yields `{"id":2,"UserId":2}` — A's own record byte for
byte, which reads as a perfect echo. `reflection_explains` therefore abstains
below `_MIN_ECHOABLE_REFERENCE_LEN` (4) and is not asked at all of a body that
carries an owning field: a record is not an echo of its own identifier. The
short-reference sink is covered by phase 1's canary probe, which mints a token
distinctive by construction.

**And the same folding bites one step earlier.** `idor_normalise_body` folds
digit runs, so *is this A's own object read back?* cannot be answered by a
fingerprint on the commonest shape there is — two baskets differing only in
`UserId`. That step asks `names_the_caller` first and falls back to the
fingerprint only for a body that names no owner. The folding stays: it is what
makes two renderings of ONE record compare equal, which is a different job.

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

## Attribution — from the OBJECT, not from a comparison

`identical_rendering` — the crossing response fingerprinting equal to B's own
authorized read — used to BE the attribution, and it is **vacuous in exactly the
direction the direction rule requires**. A is the least-privileged identity, so
B outranks it; an outranking B reading A's record returns A's record, and
"identical to B's read" is then satisfied by *B can also read this*, which is
the feature B exists for. Direction needs A least-privileged; attribution-by-
`owner_read` needs B not to outrank A. **Both cannot hold**, and it was the
attribution half that was wrong.

The claim now rests on an **owning field** (`owner_claim`): a field the
application itself uses to name a record's owner, carrying a value that is not
the caller's. `UserId: 1` in a body served to user 2 is unforgeable in a way a
fingerprint comparison is not.

Two routes, in strength order:

1. **`owning_field_names_principal`** — the owning value **is an identity this
   engagement holds**, and it is not the caller's (`email: admin@juice-sh.op` in
   a body served to jim). The comparison is against what *we* hold, so no
   response can satisfy it by choosing its own bytes.
2. **`owning_field_not_caller`** — the field's NAME is one an application uses
   to name an owner (`OWNER_FIELD_NAME_TOKENS`), its value is none of the
   caller's identity values, and the caller's own **anchored** record carries a
   *different* value under the same field. Absence is not difference: a field
   the caller's record does not carry says nothing about whose the crossing
   record is.

**No owning field ⇒ abstain** (`crossing_response_names_no_owning_principal`).
That is what retires the public-catalogue shape without a decoration-tolerant
differ: a public record has no owning principal to name.

**The price, stated rather than discovered later.** An endpoint whose per-user
records carry no owner — a source listing, a document, a file served by
sequential id — can no longer confirm. That is a real recall loss and it is the
direction chosen deliberately: `identical_rendering` is satisfied by an
outranking B reading A's record, so keeping it meant confirming the feature.
The loss is pinned as
`test_a_record_that_names_no_owner_leads_and_that_costs_recall`, in a test named
after it, rather than left to surface as a silent gap. Closing it needs a new
observation — something that establishes ownership without the record saying
so — and not a weaker version of this one.

A field is admitted for reading two ways, and the second needs no vocabulary at
all: its NAME is owner-shaped, **or** its VALUE is an identity we hold. DVWA's
records have no `UserId` anywhere — `First name: bob` names bob because bob is a
principal of this engagement, and nothing about the field's name was needed to
know it. The name vocabulary is a field-**selection** list and can only ever
withhold a confirmation, never license one: a name it does not know is a field
that is not read, so the endpoint abstains.

**`owner_read` is kept, dispatched and reported as `corroboration`.** It is
worth reporting that a second principal agrees; no branch turns on it.

### The public-record gate

An anonymous 200 on `ref(B)` is **disqualifying, full stop** — not one input to
a difference test. `/rest/products/:id/reviews` served 200 anonymously and still
confirmed, because the anonymous body carried a per-caller `"liked":true`
decoration on the **same review** (same `_id`), 13 bytes that made
`materially_differs` True. If an anonymous caller is served the resource there
is no boundary to cross, whatever else the bytes do.

An anonymous arm that was never **dispatched** refused nothing and abstains
(`anonymous_control_arm_not_dispatched`) — the same rule `ControlVerdict`
applies to every other arm.

### The evidence carries names and fingerprints, never values

`attributing_fields` renders one line per field:

```
field=<name> owner_fp=<hash> caller_fp=<hash|absent>
```

`owner_fp` is the fingerprint of the owning value the crossing response carried;
`caller_fp` is what the caller's own anchored record carries under that field, or
`absent`. Together that is the whole claim — *this record names an owner, and it
is not us* — and it is the same claim the values were making.

It used to render `field=value` out of the **owning principal's** record — the
first target data this class has ever carried into a deliverable. Bounding each
value to 80 characters bounds *volume, not sensitivity*: on a client engagement an
attributing value is a real customer's email or postal address, in a document
that gets emailed. The field NAME survives because it is schema rather than data
— `billing.email` is the application's own vocabulary, and it is what a
remediation has to name. The fingerprint is
`engagement/credential_shapes.py::fingerprint`, per-process salted, so two lines
in one bundle correlate and nothing in it replays or reverses. Same trade as
`AuthArtifact.principal`: the claim survives, the value never lands.

## Reflection is NOT covered by the control

A parameter that echoes its input defeats every other arm at once: `ref(∅)` is
echoed too (so the control sees a different string and *refuses*, correctly), and
B's read of the same reference echoes the same string back (so the corroboration
reads as an identical rendering). Three arms agreeing on an artifact of one
substitution is not three pieces of evidence. So reflection keeps its own guard,
`reflection_explains`, applied before attribution: substitute A's own reference
back in for the echoed one and compare normalised bodies — the same test phase 1
makes on a pure reflection sink, and the same echo guard the injection classes
make on their own payloads.

Two of the old hand-written guards ARE subsumed by the control: an error page and
a response that collapses to a fraction of a substantial baseline are both "the
response is a property of the handler", which `ref(∅)` reproduces exactly.

## The two tiers, enforced in two places

**Tier 1 (multi-role) MAY CONFIRM.** ≥2 proven principals, an anchored `ref(A)`
and an owning field naming somebody who is not the caller.

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

Holding two principals is necessary and not sufficient: see *Which identity the
crossing runs FROM* below for the second half of the same claim.

## Which identity the crossing runs FROM

Two principals make a crossing arm dispatchable. They do not make it meaningful.

Read the four-arm table again with an administrator as A. The crossing resolves;
the never-issued reference refuses; an anonymous caller is turned away; the
record names a customer as its owner. Every arm clears — and what was observed
is an administrator reading a customer's record, which in most applications is
the feature that administrator exists for. The oracle would emit
`high`/CONFIRMED on an application behaving exactly as designed.

That is not a corner case. It is the commonest engagement shape there is: a
client hands over one admin or service account, because that is the credential
they have to give. So the direction the arm runs in is not a refinement of the
claim, it is half of it.

**A is the LEAST privileged identity the engagement holds**, and the candidate
owners are everyone A does not outrank:

| A's rank vs the owner's | dispatched? | why |
| --- | --- | --- |
| below | yes | no role A holds authorizes the read |
| equal | yes | peers — two customers, neither entitled to the other's record |
| above | no | the read may be an entitlement, and nothing in band separates the two |

Equal rank is not a weaker case, it is the cleanest one available: there is no
hierarchy to appeal to at all.

### The rank is declared, never inferred

`privilege` is an optional integer on each role in the credential file — lower is
less privileged, and only the relative order is ever read:

```json
{"credentials": [
  {"role": "admin", "username": "...", "password": "...", "privilege": 10},
  {"role": "customer", "username": "...", "password": "...", "privilege": 0}
]}
```

Nothing infers it from the role LABEL. A label is free text an operator picked
for their own application — `svc-reporting`, `l2`, `tier3` — and reading a
hierarchy out of it is the consumer-guesses-what-the-producer-meant pattern that
has already cost this codebase a component's field names (`injectable` vs
`vulnerable`), a tool's output model, and a version's provenance. Here it would
cost something worse than a dead capability: it would manufacture the exact false
positive the rule exists to prevent, and manufacture it confidently.

### An undeclared rank costs the confirmation, not the observation

The arms still dispatch and are still recorded in full. What changes is the
verdict: `why_unconfirmed = privilege_order_undeclared_crossing_may_be_authorized`,
registered in `UNPROVEN_WHY_UNCONFIRMED`, with the attribution route reported
beside it — because the attribution SUCCEEDED, and the operator needs to see that
the only thing between this lead and a finding is one line of their credential
file.

`privilege_order` reports `known=False` if **any** participating principal
declared nothing: a partial hierarchy is not a hierarchy. It is vacuously `True`
below two principals, since there is no pair to order — and those runs are
refused one step earlier by the tier rule anyway, under the reason that names the
observation they actually lack.

Ties break on role name, so the order is a function of the principal SET and not
of handoff order. An engagement whose arms depend on dict ordering cannot be
compared against its own baseline — the same reason the exploit plan refuses to
break a tie on the crawler's emission sequence.

### Enforced in two places, like the tier rule

The methodology refuses first (phase 5 grades the direction as step 6, after
attribution, so the lead can say what it did prove), and `_persist_finding`
carries deterministic **ground 10**
(`_fp_ground_undeclared_privilege_order`). Both halves are engine facts — a
registry declaration and the run's own principal list — so nothing the target
sends reaches this ground in either direction, and it needs no
structured-evidence reader.

Grounds 9 and 10 are mutually exclusive by construction: ground 10 stands down
whenever the run holds fewer principals than the registry requires, so a
single-role run demotes under `single_role_cannot_attribute` and not under a
reason naming the wrong missing observation.

The registry's `limitation` says all of this in the client's words, because a
rule the code enforces and the report does not mention is a trap for the
operator who supplied two credentials and wondered why nothing confirmed.

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
