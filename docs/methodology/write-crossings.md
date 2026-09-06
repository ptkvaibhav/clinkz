# Write crossings — `_test_write_crossing`

**Status: BUILT.** `_test_write_crossing` · oracle in `agents/_write_crossing.py`
· unit suite in `tests/test_agents/test_write_crossing.py` · driven suite in
`tests/test_agents/test_write_crossing_dispatch.py` · authorization refusals in
`tests/test_safety/test_write_crossing_authorization.py`.

Agreed before code, the way B1 was. What follows is the specification as it was
written, unchanged, with a **§10 What was BUILT** at the foot naming the five
places the implementation is stricter than the spec and the one place the spec
was under-specified — because a spec silently edited to match its code is a spec
that has stopped being a check on it.

Confirm that principal A **created or modified an object attributable to
principal B**. Proven on the object, read back and attributed by the owning-field
rule — never on the status code the write returned.

Successor to the four-arm read oracle ([`idor.md`](idor.md)), not a variant of
it. The read oracle proves *A was served B's object*. This proves *A wrote an
object that is B's*. Different defining effect, different arms, different
destructive category, and — decided below — a different dispatch class.

---

## 1. The defining effect

> A request issued **as A** caused the application to create or modify an object
> that a subsequent read attributes to **B**.

Three clauses, each load-bearing:

* **as A** — the write carries A's session, and only A's. `_as_principal` is the
  carrier; `session_mode` records which of the three values applied
  (invariant 37). A write whose principal cannot be named proves nothing about
  crossing a boundary.
* **caused** — the object exists after the write and did not before, or its
  field changed value across the write. Established against a control, §3.
* **attributable to B** — the read-back carries an **owning field** whose value
  names B. Same rule as the read oracle (`_idor_oracle.owning_fields` /
  `owner_claim`), same two routes in the same strength order, reused verbatim
  rather than re-derived.

### What is deliberately NOT the effect

**The status code.** `201 Created` proves a record was created; it says nothing
about what the record says it belongs to. Every framework that discards an
unbound field returns the same 201 as one that honours it. This is the identical
error mass assignment already refuses to make ("most frameworks return 201 and
discard the extra field silently", `models/vuln_classes.py`), and it is refused
here for the same reason.

**The write's own response body.** An echo of the submitted `UserId` proves the
handler reflects its input. Frameworks reflect before discarding. Only a
**separate read** of the persisted object is evidence, and it must be a read that
did not carry the write.

### Why this is not mass assignment

`_test_mass_assignment` is close enough that the distinction has to be written
down, because folding this into it is the failure mode.

| | mass assignment | write crossing |
|---|---|---|
| claim | a field the client never offers was honoured | an object was written **attributed to another principal** |
| candidate field | one the **server shows and the client does not offer** (`candidate_fields`) | one that **names an owner**, offered or not |
| value written | a synthetic marker (`clinkz-probe-role`, `0.01`) | **B's real reference**, discovered by probing as B |
| control | the same create **omitting** the field | §3 — four arms, control first |
| attribution | none. The object is A's | the whole claim |

The precondition is what excludes `forgedFeedback`: `candidate_fields` subtracts
`client_offered`, and Juice Shop's feedback API *does* offer `UserId`. Mass
assignment correctly declines — a field the form already has "is not mass
assignment, it is the form". It is, however, a write crossing, because the value
A puts in it is B's.

---

## 2. What must be discovered before an arm is dispatched

Both are **abstentions**, not degradations to a lead. A write that cannot be
proven must not be *sent*: unlike a read arm, an unprovable write still changes
the client's data.

**(a) The endpoint's write must be readable back.** A write we cannot read back
is a write we cannot attribute. Readability is established *before the first
payload*, by writing an ordinary self-attributed object as A and locating it in a
subsequent read (the collection GET the API schema learner already fetches, or
the `Location`/`id` the create returned resolved as an item read). Not locatable
⇒ **ABSTAIN**, `why_unconfirmed = "write_crossing_not_readable_back"`.

**(b) The created object must name an owner.** Run `owning_fields()` over the
self-attributed object from (a). Empty ⇒ **ABSTAIN**,
`why_unconfirmed = "write_crossing_object_names_no_owner"`. An object with no
owning field cannot be crossed into, for the identical reason a public catalogue
record cannot be crossed into on the read side: there is nobody it belongs to.

**(c) `ref(B)` must be a reference the caller can name.** The mirror of invariant
33's `ref(A)`: the owner value written must be **discovered by probing as B**
(B's own read of its own object, read off the owning field), never synthesised,
never incremented off A's. No B session ⇒ the class cannot confirm at all, §5.

Note the asymmetry with the read oracle, and it is deliberate: reads need
`ref(A)` anchored because the *self* arm must be A's; writes need `ref(B)`
discovered because the *payload* must be B's. Both are the same law — a reference
the caller owns, or abstain.

---

## 3. The arms

Five dispatched arms. **The control runs first** — §4.

| # | arm | sent as | body | what it must show |
|---|---|---|---|---|
| 1 | `control_self` | A | owner field = **`ref(A)`** | the write lands and reads back attributed to **A** |
| 2 | `control_absent` | A | owner field = **`ref(∅)`**, a never-issued reference | the write is **rejected**, or lands attributed to A, or lands unattributed — anything but attributed to ∅ |
| 3 | `crossing` | A | owner field = **`ref(B)`** | the object reads back attributed to **B** |
| 4 | `anonymous` | **no session** | owner field = `ref(B)` | must be **dispatched**, and must **not** succeed |
| 5 | `owner_read` | **B** | — | B's authorized read of B's own object, for `ref(B)` and for corroboration |

Arm 5 is not a control. It is the attribution source, and it is the arm a
single-role engagement cannot dispatch — §5.

### What each arm refuses

**`control_self` is the liveness control.** It answers "does this endpoint honour
the owning field at all, from this principal, in this shape?" An endpoint that
ignores the field entirely writes A's object either way, and without arm 1 that
is indistinguishable from a server correctly overriding a hostile value. Arm 1
must **succeed** — if A cannot even attribute an object to itself, arm 3
attributing one to B is not a crossing, it is a coincidence, and the class
abstains.

**`control_absent` is the never-issued control** — the direct analogue of the
read oracle's `nonexistent` arm and the discipline of invariant 27. `ref(∅)` is
synthesised by `synthesize_absent_reference` (already built, `_idor_oracle.py`),
so it is shaped exactly like a real reference and refers to nobody. If the server
writes an object attributed to a principal that does not exist, the handler is
not honouring an owner field — it is storing an opaque string — and the
"crossing" in arm 3 is that same string storage. **Arm 2 confirming kills the
finding**, and the kill is disclosed as a lead through `_run_control_arm_first`
like every other kill (invariant 28).

**`anonymous` is disqualifying, full stop** (invariant 34). If an unauthenticated
request can create an object attributed to B, A's session was not what crossed
anything — the endpoint is simply open, which is a different finding with a
different remediation. An arm never *dispatched* refused nothing and abstains.

### Decision order

0. Preconditions (a)(b)(c) — any failure ⇒ ABSTAIN, nothing sent.
1. `control_absent` dispatched? No ⇒ abstain (an un-sent control cannot license
   an irreversible write — the rule commit `1a969af` just established).
2. `control_absent` attributed to ∅? Yes ⇒ **refuse**, disclose the kill.
3. `control_self` attributed to A? No ⇒ abstain (endpoint does not honour the
   field; nothing was proven and nothing more should be written).
4. `anonymous` dispatched? No ⇒ abstain. Succeeded? Yes ⇒ **disqualify**.
5. `crossing` read back — `owner_claim()` over the persisted object.
   `OWNING_FIELD_NAMES_PRINCIPAL` (the value is an identity we hold, and it is
   not A's) ⇒ **CONFIRM**. `OWNING_FIELD_NOT_CALLER` ⇒ confirm only with arm 5
   corroborating; without arm 5, **lead**.
6. Reflection guard: the crossing's attribution must be read from the **persisted
   object**, never from the write's response. Kept as its own guard, exactly as
   the read oracle keeps reflection outside `owner_claim` (invariant 31).

---

## 4. Control-before-payload applies, and it is the same generalisation

> "A prototype write, a persisted configuration change, **a write crossing that
> leaves the other principal's object modified**: in every one of those the
> control arm dispatched afterwards is observed through a target the payload has
> already changed."
> — `exploit.py::_run_control_arm_first`

Written when prototype pollution needed it, naming this case. It binds here, and
the reason is sharper for a *modify* than for a *create*:

* **create**: arms 1–3 create three distinct objects. A control dispatched after
  the payload is not corrupted by it — but it is dispatched into a collection the
  payload already grew, and a handler that dedupes, rate-limits, or flips to a
  different code path on the second write grades the control against different
  behaviour. Order matters.
* **modify**: arm 3 has overwritten B's object's owner field. A control
  dispatched afterwards reads an object the payload already changed, exhibits the
  effect, reads `confirmed_on_control`, and **kills the true positive it exists
  to license**. Order is not a convention here; it inverts the result.

So the class uses `_run_control_arm_first`, and the seam owns the order — not the
class. Arms 1, 2 and 4 all precede arm 3.

---

## 5. Multi-principal requirement

`MultiPrincipalRequirement(principals_required=2, …)` — declared in the registry
and read by the code, invariant 32.

Arm 5 is the attribution source, and arm 3's payload needs `ref(B)` discovered by
probing as B (§2c). Neither is available to a single-role engagement, so:

* **two or more principals** ⇒ MAY CONFIRM;
* **one principal** ⇒ MAY ONLY LEAD,
  `why_unconfirmed = "write_crossing_requires_second_principal"`.

Direction (invariant 36) binds identically to the read oracle and is imported
from it rather than re-derived: **A is the least-privileged declared principal**
(`privilege_order().least_privileged`), B is any principal A does not outrank.
Undeclared rank bounds the verdict to a lead. Writing *downhill* — a privileged
principal attributing an object to a less privileged one — is frequently the
application working as designed (an admin filing a ticket on a user's behalf) and
is not evidence.

---

## 6. Destructive category — the decision

**A write crossing gets its own category, `CATEGORY_CROSS_PRINCIPAL_WRITE`, and
it goes in `never_overridable_categories()` — beside session destruction and
security-control toggle. A wildcard authorization does not cover it, and neither
does a benchmark profile.**

`never_overridable_categories()` states the line explicitly: *"The line is not
'how bad is it' … The line is WHO it damages: these two damage the ENGAGEMENT
rather than the target."* A cross-principal write damages **both**, and the
engagement half is what decides it:

* **It damages the engagement.** Every later observation about B is made through
  a B whose data this run modified. B's own reads are the read oracle's
  attribution source (`owner_read`), so a write crossing dispatched early
  corrupts the input of the class most likely to run after it. That is exactly
  the "measurement of a different application" the never-overridable line exists
  to prevent — the same argument that put `security_control_toggle` there.
* **It damages the client in a way they cannot inspect.** A test that writes into
  another user's record is not a record the client deletes "the way they delete
  any record" — the discriminator `TRANSIENT_DISPATCH_CLASSES` uses. They must
  first *discover* it, in an account that is not the one they gave us.

Consequences, each already-built machinery:

* `never_overridable_categories()` gains it, so `BenchmarkProfile` refuses to
  name it — a throwaway target does not make a corrupted engagement worth having.
* `_technique_permitted` extends its terminal wildcard rule: the client must name
  `write_crossing` explicitly, and a run that withholds it says so in the
  report's "not tested" section.
* `safety/destructive.py` stays the **one** vocabulary. The category is added
  there and read from there — never restated in `models/engagement.py`.

This is *stricter* than the sketch that prompted it. Note there is no
`shared_runtime_state` category in `safety/destructive.py` today: prototype
pollution's terminal-ness is carried by `TERMINAL_DISPATCH_CLASSES` and the
`permits_all` refusal, not by a destructive category. So "beside it" resolves to
the never-overridable set, which is where the engagement-damage argument lands
it.

---

## 7. Terminal or transient — decision and reason

**TERMINAL.** `TERMINAL_DISPATCH_CLASSES`, dispatched last, alongside prototype
pollution.

The criterion as the table states it is not "does it persist" — half the
transient classes persist. It is:

> "What makes a class terminal is that its write changes the behaviour of
> requests the class never made, and that no request can put it back."

Both clauses hold, and the first is the one that matters:

* **It changes requests the class never made.** After arm 3, B's collection
  contains an object B did not create, or B's object carries an owner value B did
  not set. `_test_idor`'s `owner_read` arm reads B's objects.
  `_test_mass_assignment` reads the server's own representation to derive
  candidates. Both would be reading a collection this class wrote into, and
  neither can tell. That is the terminal criterion in its exact words.
* **No request puts it back.** Deleting the object requires `CATEGORY_DELETION`,
  which the client-safe default refuses — so the engine *cannot* clean up, and a
  cleanup gated on a destructive permission is not a cleanup. On the modify arm
  there is no delete at all: the original owner value is gone.

Two things follow mechanically:

* `assert_terminal_dispatch_order` covers it — a transient class dispatched after
  a write crossing is a stop-the-run condition, not a warning (invariant 88).
* **`ResidualMutation`**, recorded on the **witnessed effect, not on emission**
  (invariant 89). It names the endpoint, the owning field, and the object
  reference the client must go and remove — in the client-facing document. A
  disclosure that fires only when we also got a finding out of it is a disclosure
  that serves us.

The honest cost: two terminal classes cannot both run last. They partition — the
rotation already yields terminal classes only when transient work is exhausted,
and among terminal classes the order is arbitrary but must be *fixed* and
asserted, because a write crossing dispatched after a prototype pollution is
graded against a polluted process. Cheapest correct rule: **within
`TERMINAL_DISPATCH_CLASSES`, dispatch in declaration order**, and assert it —
write crossing declared **before** prototype pollution, since a write crossing
does not change how the *process* answers, while pollution changes how every
later write is parsed.

---

## 8. Abstentions, restated as a list

Nothing is sent when any of these holds. Every one is an ABSTAIN with a declared
`why_unconfirmed` in `UNPROVEN_WHY_UNCONFIRMED`, never a silent skip.

| condition | reason |
|---|---|
| the write cannot be read back | `write_crossing_not_readable_back` |
| the created object names no owner | `write_crossing_object_names_no_owner` |
| `ref(B)` not discovered by probing as B | `write_crossing_reference_not_owned` |
| fewer than two principals | `write_crossing_requires_second_principal` |
| A's privilege rank undeclared | invariant 36 ground 10, lead |
| `control_absent` could not be dispatched | an un-sent control cannot license a write |
| `control_self` did not attribute to A | endpoint does not honour the field |
| `anonymous` not dispatched | an arm never sent refused nothing |

And two that are dispatched-then-refused, with the kill disclosed:

| condition | verdict |
|---|---|
| `control_absent` landed attributed to ∅ | REFUSE — opaque string storage, not attribution |
| `anonymous` succeeded | DISQUALIFY — the endpoint is open, not crossed |

---

## 9. Acceptance

**Target: `forgedFeedbackChallenge`** — Juice Shop, `POST /api/Feedbacks`
carrying another user's `UserId`. Currently target-confirmed-only with no finding
claiming it.

Per invariant 35, the criterion **asserts the arms**, not the grader:

* five arms dispatched, in the order §3/§4 declares, each with its recorded
  `session_mode` — arms 1, 2, 4 before arm 3;
* arm 3's body carries a `UserId` **discovered from B's own read**, and the trace
  shows the probe that discovered it;
* the attribution comes from a **read of `/api/Feedbacks` after the write**, not
  from the write's response;
* `owner_claim` route recorded, with field name and salted fingerprints — never
  values (invariant 13);
* a `ResidualMutation` naming the feedback object, present whether or not the
  finding emitted;
* `attribute_solves` binds the challenge to **that finding** and its dispatched
  surface (collection `/api/Feedbacks`, not the item route) — the distinction the
  solve-attribution rule already turns on.

Negative acceptance, equally required: an arm-inversion fixture where arm 3 runs
before arm 2 must **fail** the criterion even though the external grader marks
the challenge solved. That is the whole point of invariant 35.


---

## 10. What was BUILT — the deltas

Five things the implementation does that the specification above does not say,
each because building it surfaced something the spec could not have known, plus
one thing the spec left under-specified and how it was resolved.

### 10.1 Arm 5 precedes arm 3, and the order is ASSERTED

§3 lists `owner_read` last in the table and §4 orders arms 1, 2 and 4 before
arm 3. It never orders arm 5. §2(c) implies it — `ref(B)` has to be discovered
before the payload can carry it — but an implication is not a rule, and the
failure it prevents is the one this class exists to avoid: arm 5 reads B's
collection, arm 3 puts an object into that collection, and arm 5 running
afterwards would attribute against data this class contaminated. That is the
payload grading its own evidence, one layer above the control-order defect §4
describes.

So `ARM_DISPATCH_ORDER` is a declared tuple, the arms are recorded as they
dispatch (`WriteArmRecorder.sequence`), and `decide_write_crossing` **refuses**
on an inversion before it grades anything —
`why_unconfirmed = write_crossing_reference_not_owned`, `arms_inverted = True`.
The negative acceptance §9 asks for is a unit fixture whose observations are
byte-identical to a sound run's and whose only difference is the order.

### 10.2 One dispatch per (collection, principal-pair) per run

Not in the spec at all. Terminal ordering orders CLASSES, not tasks, and the
plan legitimately holds several tasks for one collection — two discoverers
spelling a route differently, an item URL beside its collection. Every arm of
this class writes, so a second dispatch is four more objects in another
principal's data to re-answer a question the run has answered. Keyed on
`(origin identity, collection path, A's label, the B candidates)` and traced as
`duplicate_dispatch_suppressed`, so the suppression is visible rather than
silent.

### 10.3 EVERY landed write enters the residual ledger

§7 says the class records a `ResidualMutation`. It does not say how many. The
answer is one per landed write, whichever arm made it: the liveness control, the
never-issued control if the endpoint accepted it, the anonymous arm if it
succeeded, the anchoring probe, and the crossing. **A refused finding with three
landed writes discloses three.** Each names the collection, the object's own
identifier, and that removal is manual — the owner value is named by FIELD and
fingerprinted, never reproduced, because it is another principal's identifier.

### 10.4 The control-dispatch-failure stop is the seam's, and it needed a raise

§3's decision order item 1 is already the rule `_run_control_arm_first` enforces,
so nothing was reimplemented. One thing did have to be added: the carrier does
not raise. `_http_post_json` catches its own transport failures and returns
`status=0`, so an un-sent control would have reached the seam as an arm that was
sent and simply did not land — that is, as a control that REFUSED, licensing a
payload nothing licensed. `ControlArmNotDispatchedError` is raised out of the
class's own `oracle_confirms` so the seam sees `dispatched=False` and skips the
confirming half.

Two further skips were added on the same reasoning, and neither is in the spec:

* the control **confirming** (a reference nobody owns was stored) already kills
  the finding, so arms 4 and 3 are skipped rather than dispatched into B's
  namespace to prove what is already known;
* a reference nobody owns landing attributed to **A** means the server is
  assigning the owner from the session and discarding what the request supplies.
  Arm 1 cannot show that — an honoured `ref(A)` and an overridden one produce the
  same object — so it is caught here, and again nothing is written in B's name.

### 10.5 The never-overridable placement has its own refusal tests

§6 decides the placement. It does not ask for the tests, and a rule nobody has
watched refuse is a rule nobody has tested. Both gates are observed refusing:
a `BenchmarkProfile` naming `cross_principal_write` (rejected at validation,
alone and beside a category a profile may permit) and a wildcard authorization
(`*` / `all` / `any`) leaving `_test_write_crossing` withheld while still
covering every transient class.

### 10.6 The gap: `ref(A)` cannot come from A's identity tokens

The spec's §3 says arm 1 carries `ref(A)` and never says where `ref(A)` comes
from. Taking it from A's identity tokens — the way the read oracle reads the
caller's identity — does not work: those are usernames and email addresses, and a
collection keyed on a numeric `UserId` has never issued them. Arm 1 would fail
for a reason that says nothing about the endpoint.

Resolved with the write §2(a) already describes, promoted to a named probe:
`SELF_ANCHOR` creates an ordinary object as A with the owning field **omitted**,
so the SERVER assigns the owner. One write answers three preconditions —
(a) the write is locatable in a subsequent read, (b) its records name an owner,
and (c) the owner the server named for A is `ref(A)` in the application's own
spelling. `ref(B)` is then looked up under that same field in the pre-write
snapshot arm 5 took.

That also fixed the corroboration, which was circular as first written: checking
that `ref(B)` came from B's snapshot is true by construction, since the snapshot
is where it came from, and a check that cannot fail is not evidence.
`corroborated` is now B's own authorized read, taken AFTER the crossing, being
served the object we filed in B's name — keyed on the marker this attempt minted.
A read contaminates nothing, so the arm-order assertion is unaffected: what may
not follow the payload is a WRITE.

---

## 11. What the LIVE runs found

Every arm dispatched against a running OWASP Juice Shop (`docker/docker-compose.yml`,
container `clinkz-juiceshop`), two real logins, both principals ranked. Three
endpoints, three different outcomes, and **three defects no synthetic fixture
could have produced** — each one the class doing the right thing and reporting
the opposite, because a value it built was wrong in a way a hand-written object
does not reproduce. That is the argument for the live loop, so they are written
down rather than fixed and forgotten.

### 11.1 The three endpoints

| endpoint | outcome | why |
|---|---|---|
| `POST /api/Feedbacks` | **ABSTAIN**, nothing sent past the anchor | the create is captcha-gated; the anchoring write is refused `500`, so `write_crossing_not_readable_back` and no arm follows |
| `POST /api/Addresss` | **REFUSED at the control**, arms 4 and 3 never dispatched | `ref(∅)` landed attributed to the CALLER, so the server assigns the owner from the session and discards what the request supplies. The control working |
| `POST /api/Complaints` | **CONFIRMED** | every arm dispatched in order; a separate read attributes the created object to a principal that is not the caller |

The confirmation was verified independently of the engine, by reading the
collection back by hand: the `control_self` object carries the caller's own
reference and the `crossing` object carries another principal's, both created by
the least-privileged session.

**`forgedFeedbackChallenge` is NOT reached, and the reason is not the oracle.**
`POST /api/Feedbacks` requires a captcha the application serves at
`/rest/captcha`; a request without one is refused `500` and one carrying a wrong
one is refused `401`. Every write arm is rejected before it reaches the handler
this class is asking about, so the class abstains with nothing sent and nothing
left behind. Solving that captcha is a separate capability and a target-specific
one, which the hardcoding rule forbids. **`solved_by_testing` and the
floor-corrected Juice Shop number therefore do not move.** `_test_write_crossing`
is nonetheless declared under `Broken Access Control` in the benchmark driver's
`CATEGORY_CLASSES`, because a class missing from that map cannot attribute a
solve it earns — the failure that costs a number its meaning.

### 11.2 The three defects, and why the unit suite could not see them

Each is pinned by a regression test in `test_write_crossing.py::TestWhatTheLiveRunsFound`.

**An owning field read from a COLLECTION is an indexed path.** `[0].UserId` and
`[9].UserId` name the same field as `UserId` and neither is a key any handler
has. Every arm went out carrying the indexed spelling, the server ignored an
unknown field, all four objects came back unattributed, and the class reported
that the collection's records name no owner while its own snapshot carried one.
It happened **twice**, once per discovery route, which is why the normalisation
is now at the single seam the field crosses on its way to becoming a body key
(`owner_field_key`) rather than at each site.

**A sibling value has to survive the handler's own validation.**
`/api/Addresss` answers `Validation min on mobileNum` and `Validation len on
zipCode` — a `400` that says nothing about the claim, which the class reported as
"this endpoint's writes cannot be read back". Sibling fields exist only to get
the request past validation and cancel out of the differential entirely, so they
now copy the SHAPE of the server's own values — a string's length, a number's
magnitude — and none of the content. Copying the observed value would satisfy the
same validators and write another principal's real address into a new row, which
is a worse thing to leave behind than a placeholder.

**The read-back must be able to FIND our row, and must look where it can land.**
`_observed_records` truncates to five, the right bound for "what does this object
type look like" and the wrong one for "is our row in this list" — a collection
lists oldest first and the row we just created is last. Three arms landed on
`/api/Addresss`, the read-back read five records, every one reported
`landed=False`, and the class reported that the endpoint's writes could not be
read back while disclosing none of the three objects it had left behind. The
read-back also has to try **B's** read: on a per-principal collection an object
that genuinely crossed is no longer in A's scope, so reading only as A reports a
real crossing as a write that did not land.

### 11.3 One more thing the live run corrected: what the finding may NAME

`ref(B)` is preferred verifiably B's, and on `/api/Complaints` no value in the
collection matched the second principal's identity — so it fell back to an owner
reference the collection did carry, user 3 rather than the admin the engagement
held. The oracle graded it route 2
(`OWNING_FIELD_NOT_CALLER`) exactly as it should, and the request line still read
`ref(admin)`. The claim was right and its evidence named the wrong principal.

The finding now names the owner **only when the attribution route named them**.
Route 1 means the owning value IS an identity this engagement holds, so it can be
named; route 2 means it is an owner reference the collection carries that is
neither the caller's nor what the caller's own object holds — a real crossing,
proven, and not a crossing into a principal we can name.
