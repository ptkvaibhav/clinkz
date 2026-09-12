# Register — observed, verified, deliberately not this round

Things measured or reported during a round whose fix belongs to a later one.
Each entry names what was **verified in the tree** versus what is still a
report, so the round that picks one up does not re-derive it and does not
inherit a guess.

Opened 2026-09-10 (tree at `b45b239`), during the default-control audit.

## States

An entry's state says what KIND of thing is open, because the three read very
differently and only one of them is waiting for a target.

| state | meaning |
|---|---|
| **OPEN** | a defect or a gap; the fix is known or findable, and it is scheduled |
| **OPEN — trade** | the fix requires a decision with a real cost on the other side, not just work |
| **UNREACHABLE PRECONDITION** | a gate needs evidence the engine can only produce by first passing that gate. Not *unexercised* — dispatched and measured. Not *not applicable* — the target may well carry the rule. It is a capability the engine does not have, and the deliverable must not describe it as a class waiting for a better target |

---

## R1 · `js` is absent from `STATIC_ASSET_EXTENSIONS`

**Verified.** `agents/_url_shape.py:27` — the set is
`{css, png, jpg, jpeg, gif, svg, ico, woff, woff2, ttf, eot, map, pdf, zip, mp4, webp}`.
No `js`.

Two consumers read it, both in `agents/exploit.py`:

* `_applicable_methods_for_endpoint:6549` — `if ext in _STATIC_ASSET_EXTENSIONS:
  return ["_test_security_headers"]`. A `.js` URL therefore falls through to the
  full class list.
* `_endpoint_generic_rank` — a `.js` path is not graded 4 (static).

**Consequence:** every crawled `.js` bundle is planned as an application
endpoint. Reported as a 72-task consequence on cal.diy; the arithmetic is
consistent with the fall-through but has not been re-measured here.

**Why it is not obviously a one-line fix.** `.map` *is* in the set and `.js` is
not, which reads deliberate: the discovery layer wants bundles fetched
(`JSCallSiteDiscoverer`, `StaticBundleDiscoverer` both mine them), and the same
extension governs both "worth mining" and "worth attacking". Whoever takes this
must check whether adding `js` starves discovery, and see also
`docs/analysis/spa-write-surface-blocker.md` §3 — bundle reach is already the
binding constraint there.

**Measured 2026-09-12: R1 is NOT upstream of endpoint candidacy, and the control
is in the data.** Two of the 32 chunk routes on `e4814440` are `.css`, and `css`
has been in `STATIC_ASSET_EXTENSIONS` throughout — they became endpoints anyway
and consumed an `OPTIONS` probe slot anyway. So whatever emits these endpoints
does not consult the set, and adding `js` would not have stopped the `.js` chunks
either. R1 was named as a prerequisite for the probe-ordering fix
([`probe-bound-ordering.md`](probe-bound-ordering.md) §4) and is not one; the
ordering fix landed without it. R1 stays open on its own merits — it governs how
a `.js` endpoint is PLANNED, which is where its 72-task consequence lives.

**Carried 2026-09-12, unchanged.** Deliberately not bundled with the redaction
round: the open question is still whether adding `js` starves the discoverers
that mine bundles, and that is measured against a discovery run, not a redaction
one.

---

## R2 · `_test_javascript_attacks` emits no phase events across 36 dispatches

**Reported, not verified here.** The class is dispatched and records nothing
through `_trace_methodology_phase`, so the trace cannot distinguish "ran and
found nothing" from "returned early".

Relevant context already in the tree: this is the one form-shaped class that
CLAUDE.md invariant 18 exempts from reading `_injectable_forms`
(*"`_test_javascript_attacks` is the one that does not migrate, and says why"*),
and it is queued unconditionally for every non-static endpoint
(`methods += ["_test_xss_dom", "_test_javascript_attacks", "_test_weak_session"]`).
Unconditional dispatch plus no phase trace is invariant 77's shape: a silence
that cannot be graded as correctly-empty.

---

## R3 · `ResilientLLMClient.last_call_stats` is `None` for any non-Anthropic call

**Verified, and the reported symptom is narrower than "permanently None".**

* `llm/base.py:475` declares `last_call_stats: CallStats | None = None` as the
  contract.
* `llm/anthropic_client.py:622` is the **only** assignment in a provider client.
  `grep -c last_call_stats` is `0` in both `gemini_client.py` and
  `openai_client.py`.
* `llm/fallback.py:414` reads it as
  `stats = getattr(client, "last_call_stats", None)` and returns early on
  `None`, so `self.last_call_stats` is never published for a Gemini- or
  OpenAI-served call.

**Why it matters beyond a missing metric.** `engagement/auth_agent.py:1441`
reads `self._llm.last_call_stats` for exactly one thing — whether the answer it
could not parse was **CUT OFF**. That is invariant 103's three-failures
distinction (unreachable / cut off / answered-but-unusable). On a fallback-served
call the cut-off signal is absent, and the third failure is reported for the
second.

The `getattr(..., None)` is also invariant 82's forbidden shape over a model
that *declares the field* — the default is what turns "this provider does not
report stats" into "the provider reported nothing".

---

## R4 · The two client-side classes: 0 findings, 1 lead, for half a plan

**Reported, not verified here.** `_test_xss_dom` and `_test_javascript_attacks`
are both appended unconditionally to every non-static endpoint's method list,
so together they take two slots per endpoint before any ranking. On a
46-endpoint crawl that is 92 tasks competing inside `exploit_max_plan_tasks`
(default 150).

`_test_xss_dom` carries `("dom_source",)` in `_CLASS_PRECONDITIONS` and the
table's own comment records the prior incident (engagement `2cf65d36`: a shared
script reading `location` made the source-only precondition true
application-wide, DOM-XSS filled the plan, and 21 findings became 10). The
precondition is a **ranking** signal; the unconditional queue above it is not
gated by it. That asymmetry is the thing to look at.

See also R2 — the two entries are probably one investigation.

---

## R5 · `test_orchestrator` performs live DNS

**Reported, not verified here.** A unit suite that resolves a name is a suite
whose result depends on the network, which makes the keyless gate
non-deterministic and slower. Worth locating and stubbing; no honesty
consequence.

---

## R6 · Three business-logic classes are never queued by the deterministic pass

**Verified, and found during this round rather than reported into it.**
Computed as `TIER1_TESTS − {every `_test_*` literal named in
`_applicable_methods_for_endpoint`}`:

* `_test_state_sequence`
* `_test_constraint_violation`
* `_test_repeatability`

All three carry `("form",)` in `_CLASS_PRECONDITIONS`, so the ranking layer
treats them as having a bucket; the coverage pass never creates one. They reach
a plan only when the LLM planner names their endpoint.

This is **not** the SPA blocker — it holds on every target, DVWA included. It is
invariant 51 (*every applicable class is guaranteed one task before the cap*)
evaluated against classes the coverage pass does not consider applicable
anywhere. Detail in `docs/analysis/spa-write-surface-blocker.md` §4.

---

## R7 · The default-control guard is designed but not built

`.claude/skills/clinkz-dev/SKILL.md` §6 defines the law and the computed
domain; `docs/analysis/default-control-audit.md` §3 is the declared
classification it needs. The guard itself — the MIXED/NEVER/ALWAYS/UNCALLED
walk in `tests/`, both directions asserted, the four blind spots named in the
module docstring — is not written. Until it is, §3 is documentation of a
measurement rather than a test that goes red.

---

## R8 · F3 (`llm:<provider>` reachability) — attempted, reverted, re-opened

**Verified, and the revert is the finding.** `docs/analysis/default-control-audit.md`
F3 is real: `llm/fallback.py` declares every provider in a chain with no
reachability key, so `resolve_reachability` skips the record outright and no
`llm:<provider>` ever produces a reachability answer in either direction.

A fix was written and reverted in the same round. It added
`ReachabilityKey.LLM_PROVIDER_WAS_A_CHAIN_PRIMARY`, the two halves it needs on
`EngagementReachability` (`llm_providers_with_credentials`, `llm_chain_primaries`),
a predicate, and a producer in `fallback.py` recording both facts at the
declaration seam — which is the right seam, because the chain's declared order
and the key check are three lines apart there and neither survives to report time.

**Why it came out.** Nothing wired the producer to the consumer.
`provider_chain_observations()` had zero callers — `orchestrator.py`'s
`_build_reachability` is the only place `EngagementReachability` is constructed,
and it never read it — so both new fields stayed at their `frozenset()` default.
Measured against the attempt, with the state the orchestrator actually builds:

```
llm_providers_with_credentials : frozenset()
llm_chain_primaries            : frozenset()
llm:anthropic: holds=False
  -> no API key was configured for anthropic, so every chain it is declared in
     skipped it before reaching a call — an absent credential, not an unused
     capability
```

That sentence is produced from an empty set, for **anthropic** — priority 1 on
every chain of every phase. It is a confident client-facing claim about the
operator's configuration, and it is precisely the WRONG one of the two readings
the key's own docstring says both halves exist to separate: *no credential*
versus *a fallback nothing rotated onto*, the second of which is routing behaving
correctly (invariant 6) and must never alarm (invariant 81).

Before the change the record was skipped and an operator saw nothing. **A record
nobody sees is better than a record that is confidently wrong about the client's
configuration.** The four failing tests — all
`TypeError: declare_component() missing 1 required keyword-only argument` in
`tests/test_observability/test_component_ledger.py`
(`test_no_ledger_installed_means_every_helper_is_a_no_op`,
`test_declared_but_never_invoked_is_not_reported_as_silent`,
`test_no_view_is_a_second_population`,
`test_the_cve_component_has_exactly_one_registration`) — were not the reason for
the revert. They were how it was noticed.

**What a correct fix requires.** Three things, none of them large, all of them
absent from the attempt:

1. **The producer's observations have to reach the consumer.**
   `orchestrator.py::_build_reachability` — the one `EngagementReachability(...)`
   construction — must read `provider_chain_observations()` and pass both sets.
   Until it does, the predicate answers from a default, which is the same defect
   class F3 itself reports.

2. **`ReachabilitySource.ENGINE` must stop being unconditional for this
   predicate.** `_build_reachability` opens with
   `reported = {ReachabilitySource.ENGINE}`, before any producer check, so
   `state.unreported_reason(ENGINE)` is `""` and an ENGINE-sourced predicate can
   never reach the NOT DETERMINED fourth state invariant 80 exists to provide
   (confirmed by the same measurement above). A provider-chain observation is
   exactly the case that needs it: a run whose chains were never walked — credit
   pre-flight refused, zero LLM calls — has said *nothing* about which provider
   was a primary, and that is not the same fact as "none was". Either this
   predicate gets its own source whose membership is conditional on the producer
   having spoken, or ENGINE's unconditional add becomes a real check — and the
   second changes behaviour for the three existing ENGINE predicates, so it is a
   decision, not a patch.

3. **`reset_provider_chain_observations()` has to be wired, and the module-level
   state question answered.** The attempt defined it and called it from nowhere.
   Module-level sets that accumulate across engagements in one process are their
   own defect: `scripts/three_run_envelope.py` runs several engagements per
   process, so run 2's answer would carry run 1's chain walks. Note the sibling
   `reset_account_disabled_providers()` already has that shape — called only from
   tests, never at engagement start — so the gap is pre-existing in
   `llm/fallback.py`'s module state rather than introduced by the F3 fix. Worth
   closing at engagement setup for both, not per-consumer.

**What is NOT in dispute.** The `declare` / `declare_component` half — making
`reachability` a required parameter, and giving a record created without one
`set_reachability_undetermined` instead of a silent `continue` — is sound and
independent of the above. It was reverted only because it is what forces every
caller, including the `llm:<provider>` one, to name a key; landing it without a
correct predicate for that caller is what produced the wrong sentence. It should
come back WITH item 1.

---

## R9 · The three business-logic classes: 85 dispatches, 0 findings, 0 leads

> **CORRECTED 2026-09-12 (second pass) — see
> [`business-logic-verdict-trace.md`](business-logic-verdict-trace.md).** This
> entry's own premise is wrong in two places, and the text below is kept
> unedited as the record of what was believed rather than quietly rewritten.
> What the trace measured:
>
> * `_test_constraint_violation` **does** reach a verdict — 18 times, all
>   `violating_value_refused` on Juice Shop — and **does** emit leads. "No
>   `unproven_leads` entry names them" was a measurement error: the leads are
>   there, in `20fad9dc`, `88a83878`, `cd9b2555` and others.
> * The other two abstain at `exploit.py:33574` (`if intent is None: return []`)
>   on **every** dispatch, and the cause is not the `("form",)` precondition
>   guessed at below. They are dispatched against the RIGHT endpoints —
>   `/rest/basket/:id/checkout`, `/rest/user/erasure-request` — which are RPC
>   **action** endpoints with no collection representation to read, so phase 1's
>   representation source is structurally empty and its rejection source is
>   filled at phase 3, downstream of the gate they never pass.
>
> Split into **R11** (the per-class capability disclosure) and **R12** (correct
> negatives filed as `not_instrumentable`). R9 itself is closed.

**Measured 2026-09-12, and the premise it was registered under is wrong in a way
worth keeping.** Registered as *"never exercised on any target"*. Across the 35
stored bundles carrying a methodology ledger they have been exercised **85
times**:

| class | ledger rows | dispatches |
|---|---|---|
| `methodology:_test_repeatability` | 23 / 35 bundles | **35** |
| `methodology:_test_constraint_violation` | 23 / 35 | **30** |
| `methodology:_test_state_sequence` | 23 / 35 | **20** |

They reach the plan through the LLM planner, which is exactly the route R6 says
is their only one. So the deterministic pass never queues them (R6, unchanged)
and they still run.

**What is true, and is the disclosure issue:** across those 85 dispatches they
produced **zero confirmed findings and zero unproven leads** — no finding title
in any stored bundle matches any of their `title_tokens`, and no
`unproven_leads` entry names them. Each declares `capability=SERVER_SIDE`, whose
contract is *"the defining effect is observable in a server response, so a
finding here is confirmable in-band."* That claim has never been exercised to a
verdict of any kind.

Zero *leads* is the sharper half. Each class's `limitation` says that where the
rule cannot be evidenced from the application's own surface the result is an
unproven lead — so 85 dispatches should have left a trail of leads even against
targets with nothing to find. They left none, which means all 85 abstained
*upstream* of the lead-emitting path. The likely cause is the same write-surface
blocker (`spa-write-surface-blocker.md` §4): their preconditions need a write to
act on, and the `("form",)` precondition they all carry grades 0 on an all-GET
crawl.

**Why this is disclosure and not capability.** `SERVER_SIDE` is read by the
report as a statement about what the engine can prove. A class that has never
reached a verdict on any target is not a class whose in-band confirmability has
been demonstrated. Either the capability is downgraded to match the evidence, or
the classes are shown to reach a verdict on a target that has the surface — and
the second is the better fix, but it is downstream of producer 3
(`options-sweep-measurement.md` §6).

**Method note for whoever picks this up.** Two reading failures to avoid, both
hit while measuring this: ledger components are keyed `methodology:_test_x`, not
`_test_x`, and findings carry **no class key field** — only
`title`/`description`, so a class's emissions must be matched through its
registry `title_tokens`. A naive exact-key scan returns a confident `NONE` for
every class in the engine. Invariant 41's shape, in the measurement rather than
in the engine.

---

## R10 · The gray-box source ingest selects 2,000 files by path spelling

**Verified.** `discovery/js_source_ingest.py::_read_files` — `candidates =
sorted(seen)` then `candidates[:_MAX_FILES]`, `_MAX_FILES = 2000`. The selection
is filesystem path order, so on a monorepo whose early directories are large the
budget can be exhausted before the ingest reaches the route handlers, and the
discoverer returns a small model that is indistinguishable from a codebase with
few call sites.

**Found by the guard, not by reading.**
`tests/test_agents/test_probe_bounds_select_by_relevance.py` computes the domain
of bounded slices over sorted collections (nine sites) and requires each to
declare what it orders by. This one is classified `LEXICAL_REGISTERED`, which the
guard permits **only** while this entry exists — the test asserts the module is
named here.

**Why not fixed in the same round as the probe-bound fix.** That fix reused
`crawl_visit_priority`, an existing, tested relevance function over URLs. There is
no equivalent for source paths, and inventing one would decide which parts of a
client's codebase are worth reading on a guess — while the discoverer it bounds
(producer 3, `JSCallSiteDiscoverer`) is the one the write-surface work is
currently blocked on. Whoever takes this should measure first: on the recorded
Juice Shop and cal.com trees, does 2,000 actually bind?

**Carried 2026-09-12, unchanged.** Still `LEXICAL_REGISTERED` in
`test_probe_bounds_select_by_relevance.py`, which keeps failing the build if this
entry is removed before the ordering is fixed. The measurement it asks for has
not been taken.

---

## R11 · `capability=SERVER_SIDE` on two classes that have never reached a verdict

**Verified, and narrower than R9's version of it.** Across every stored trace,
`_test_repeatability` (102 dispatches) and `_test_state_sequence` (62) have
produced **zero** phase-5 verdicts. Both declare `capability=SERVER_SIDE`, whose
contract the report renders as a statement about what the engine **can prove**:
*"the defining effect is observable in a server response, so a finding here is
confirmable in-band."*

`_test_constraint_violation` is **not** in this entry. It reached a verdict 18
times and keeps `SERVER_SIDE` on the evidence.

**The disclosure half is FIXED in this round.** *Registered, dispatched, and
never able to begin* now has its own artifact: all three classes call
`_record_intent_abstention` at the phase-1 gate, which writes an
`InconclusiveMeasurement` — the existing carrier for a series that RAN and could
support no conclusion — and the report renders it under
`MEASUREMENT_INCONCLUSIVE`. Deliberately not a lead (the class suspects nothing;
164 "candidate single-use action replayed" rows would be invariant 77's permanent
false alarm) and not `not_applicable` (the endpoint may well carry the rule; a
zero measured over part of the input is INDETERMINATE, invariant 101). The shared
renderer was also corrected: it asserted "its own positive control refused the
series" for every producer in that category, which is true of the brute-force
series and false of a class that sends no probe — one caller's mechanism asserted
about another's evidence. Guard:
`tests/test_agents/test_business_logic_abstention_declared.py`.

**What stays open: the `capability` declaration itself.** `SERVER_SIDE` still
reads as *this engine can confirm this class in band*, and for these two that has
never been exercised. The two candidate fixes are a fourth
`ConfirmationCapability` member, or a per-class exercise record derived from the
trace — the second is stronger because it is measured per run rather than declared
once, but it needs a producer that survives into the bundle.

**Why the declaration is not changed here.** The honest fix is to make the classes
reach a verdict, and the blocker is R13 below, not the declaration. A capability
downgrade shipped first would have to be reverted by the round that fixes the
cause — and the run now DISCLOSES the abstention either way, which is the half
that a client actually reads. Detail:
[`business-logic-verdict-trace.md`](business-logic-verdict-trace.md) §4.

---

## R12 · A correct negative filed as `not_instrumentable`

**Verified.** `_emit_business_logic` records every non-confirmation as
`why="not_instrumentable"`, whatever the verdict's own
`why_unconfirmed` says. All 18 `_test_constraint_violation` verdicts carry
`why_unconfirmed="violating_value_refused"` — *the application refused the
out-of-range value, so it enforces the bound its own records imply* — and each was
filed as a lead reading `Candidate Business logic — numeric constraint violation:
quantity persists 0` under "not instrumentable".

That is a measurement of a control WORKING, reported as an unresolved suspicion
about the endpoint, on every well-built endpoint the class will ever meet. It is
invariant 77's permanent-false-alarm shape at the lead layer rather than the alarm
layer: a reader who checks three of these and finds all three benign stops
checking the fourth.

**What it is not.** Not an argument for suppressing the lead. A `quantity_bound`
verdict that refused *because the engine could not read the record back* is a
genuine lead and looks identical from `why="not_instrumentable"` alone. The fix is
to carry the verdict's own `why_unconfirmed` into the lead — which requires each
value to be classified as *the target held* versus *we could not tell*, and every
one added to `UNPROVEN_WHY_UNCONFIRMED` (invariant 40).

---

## R13 · Phase-1 business-logic intent cannot be evidenced on an action endpoint

**State: UNREACHABLE PRECONDITION** (2026-09-12). This is the entry the state was
added for. R13 is not a class waiting for the right target — it is a gate that
needs what only passing the gate produces, and it now has a computed domain, a
guard and a client-facing disclosure. See *The state, computed* below.

**Verified, and it is the cause behind R11.** `_business_logic_intent` evidences
an intent facet from a **representation** (`_observed_records(collection)`) or from
a **rejection** (`self._business_logic_rejections`). On an RPC action endpoint —
`/rest/basket/:id/checkout`, `/rest/user/erasure-request`,
`/rest/repeat-notification` — there is no collection, so the first source is
structurally empty; and the second is filled by `_remember_rejection`, which the
three classes call at **phase 3**, after the malformed control goes out, which is
downstream of the phase-1 gate they never pass.

So the evidence the class needs is a by-product of probes the class never gets to
send, and the abstention is unconditional rather than target-dependent. Measured:
`records_observed` is 0 on 41 of 42 Juice Shop `single_use_action` dispatches and
on 23 of 23 `ordering_constraint` dispatches, while `quantity_bound` — whose
endpoints are REST collections — read records on 38 of 40.

**Not the write-surface blocker.** These classes were dispatched against write
endpoints, repeatedly, on a target that has them. The allocation is good; the
evidence source is what is missing.

**A direction, not a design.** An action endpoint's intent, if it is evidenced at
all, is evidenced by the *related* collection (`/rest/basket/:id` for
`/rest/basket/:id/checkout`) or by a refusal the engine has already collected from
another class's control arm — which would mean seeding
`_business_logic_rejections` before phase 1 rather than during phase 3. Both need
the "is this the same resource" question answered without guessing, and a wrong
answer manufactures an intent the application never declared, which is the one
thing this family is built not to do.

### The state, computed

**The cycle.** `_business_logic_intent` accepts two evidence sources. On an RPC
action endpoint the representation is structurally empty, so the rejection pool
is the only one left — and every writer of that pool is a `_remember_rejection`
call at **phase 3**, inside the three classes it gates, downstream of the phase-1
check the value is needed to pass.

**Measured across 2,989 stored traces:**

| skill | phase-1 | with a representation | phase-5 verdicts |
|---|---|---|---|
| `business_logic_ordering_constraint` | 64 | **0** | **0** |
| `business_logic_single_use_action` | 104 | **1** | **0** |
| `business_logic_quantity_bound` | 50 | 38 | 18 |

Assertions carrying `evidence_source="rejection"`: **zero, ever.** The one
`single_use_action` dispatch that did see a record evidenced `entity_type` and
`ownership_relation` — not the facet it needed.

**Where the strict reading has to soften, and it matters.** The cycle is not
quite closed: `_test_constraint_violation` passes phase 1 off a *collection's*
representation, reaches phase 3, and fills the shared pool for a later class. That
bootstrap edge exists, so "zero reachable paths" overstates it. It is dead for a
second and independent reason: what `_remember_rejection` is handed is the
response to a **malformed-value control** (`clinkz-control-not-a-valid-value`),
which is a SCHEMA refusal — while `_SINGLE_USE_REJECTION_RE` and
`_ORDERING_REJECTION_RE` look for BUSINESS-RULE refusals ("this coupon has
already been used", "must be paid first"). A type error cannot say that. **One
bootstrap edge, dead for a reason of its own** is the accurate statement, and it
is a better guide to the fix than "unreachable" would be: seeding the pool is not
enough, the pool has to be fed a refusal of the right KIND.

**The domain — is anything else this shape?**
`tests/test_agents/test_precondition_sources_are_reachable.py` computes it: an
instance attribute a methodology gate READS whose every *informative* writer sits
in a `_test_*` method or a helper reachable only from one. **11 members.** Nine
are latches — a dedup set, a once-per-run flag, an accumulator read where it is
written. Two have a gate that reads without writing, and they point opposite
ways:

* `_p7_runs_used` — read by `_p7_oracle` against `_MAX_P7_RUNS`. A **CEILING**:
  the empty value PASSES, and being downstream-written is the point.
* `_business_logic_rejections` — read by `_business_logic_intent` as
  **EVIDENCE**: the empty value FAILS. The only member of its class.

Two refinements are what make the sweep see anything at all, and both are the
guard-domain law in miniature: an assignment that can only write the EMPTY value
is not a source but the declaration of an absence (`= []` in `__init__` makes a
naive sweep report **zero** members for the whole tree), and the gate usually
lives in a shared helper rather than the `_test_*` body, so restricting reads to
`_test_*` misses the one member the file exists for.

**Disclosed** (`_record_intent_abstention`). The abstention already wrote an
`InconclusiveMeasurement`, and its sentence was a statement about the TARGET —
*its surface evidenced nothing here*. For the two self-satisfied facets that is
not the whole truth, and a reader told only that goes looking at their own
application. When the representation was empty and the facet is one of the two,
the reason now adds: *this is a limit of the test, not a reading of the endpoint
— the only other evidence this class accepts is the application's own refusal
wording, which the engine collects only from probes it sends AFTER this check has
passed.* `QUANTITY_BOUND` is excluded deliberately: its source is a collection
representation, which is upstream of every gate, and it is the facet that works.

---

## R14 · A registered sweep password is substring-redacted out of URLs, payloads and oracle markers

**Verified, and the KEY half of it is fixed; this entry is the VALUE half.**

`OrchestratorAgent` registers each default-credential candidate for redaction
before it is offered, so one that WORKS is not left in an artifact in plaintext.
The catalogue includes `test`, `root`, `admin` and `password`, and
`register_secret` accepts anything at least `_MIN_REDACTABLE_LEN = 4` characters.
Registered secrets are replaced as **substrings, everywhere**.

Measured on engagement `92c89d0d` (cal.diy, local mode, 1,466 invocations):

| what it corrupted | example |
|---|---|
| a URL in the deliverable | `/auth/forgot-password` → `/auth/forgot-[REDACTED]` (25×) |
| an oracle's own evidence marker | `root:x:0:0:` → `[REDACTED]:x:0:0:` (20×) |
| a class name in the trace | `_test_javascript_attacks` → `_[REDACTED]_javascript_attacks` (20×) |
| a payload | `;sleep 5` prefixed by `[REDACTED]` (10×) |

**Already fixed, separately:** the same substring rule was applied to dict KEYS,
which turned `test_start` into `[REDACTED]_start` and made
`PentestReport.model_validate` reject the report's own dump for two missing
required fields — **no report.json, no Markdown and no PDF on any run where the
sweep fired.** A key is schema, not data
(`engagement/secrets.py::_redact_key`, guarded by
`tests/test_engagement/test_a_key_is_schema_not_data.py`). That is the half that
was a total outage; it is closed.

**Why the value half is NOT fixed here.** Both candidate fixes are safety
decisions, not mechanical ones:

* *Raise the bar for what may be substring-registered.* A length threshold is the
  wrong instrument — `password` is eight characters and still a substring of
  `forgot-password` and `password_field`. The right instrument is a vocabulary of
  words too common to replace globally, which is a new vocabulary to own.
* *Register the guess only when it WORKS.* Argued straight from the registration
  site's own comment — "a default password is public until it WORKS" — and it
  would remove the registration on every run where the sweep finds nothing, which
  is nearly all of them. The cost is the window the comment names: the attempt's
  own action-log body excerpt carries the candidate while it is being tried.

A deliverable whose URLs read `/auth/forgot-[REDACTED]` is degraded but honest;
one that is never written is not. The outage half was taken; the trade-off half
belongs to a round that can weigh it.

### The value half, weighed (2026-09-12) — **State: OPEN — trade**

**Nothing changed in this round. This section is the measurement and the
options.** Three things are new since the entry above was written, and two of
them move the decision.

#### 1 · The outage class is NOT closed

The key fix stopped a KEY from being rewritten. It does not stop a VALUE from
being rewritten into something a required field will not accept. `PentestReport`
declares `medium_count`, so the four-character floor admits `medi`; `medi` is a
substring of the VALUE `"medium"` that `Finding.severity` carries; and `severity`
is one of **four** enum-constrained fields reachable from the report rather than
free `str` (`Finding.severity`, `Finding.status`, `NotTestedItem.category`,
`Service.protocol`). Registering `high` alone is enough: no report.json, no
Markdown, no PDF, the same total outage by a different route.

The comment at the write seam asserted the opposite — *"no field here is more
constrained than `str`, so a `[REDACTED]` substitution cannot invalidate one"* —
and it was false in both halves. Corrected in place, and the positive control
that finds it is held as a STRICT xfail in
`tests/test_engagement/test_whole_structure_transformations.py`, so the day this
is fixed the build says so.

**This escalates R14 from "degraded but honest" to "can still produce no
deliverable at all."**

#### 2 · Boundary-awareness does not fix the cases R14 was opened for

Measured on `92c89d0d`, the bundle the entry's table came from. 711,918 redactions
sit inside a longer string; classifying each by whether the replaced text was at a
token boundary:

| | count | would a boundary rule help? |
|---|---|---|
| at a token boundary | 256,023 | **no** |
| mid-word | 455,895 | yes |

And the four named cases, classified individually:

| case | occurrences | at a boundary? | boundary rule |
|---|---|---|---|
| `/auth/forgot-[REDACTED]` | 6,227 | yes (`-` before, end after) | **does NOT help** |
| `[REDACTED]:x:0:0:` | 64 | yes (start, `:` after) | **does NOT help** |
| `_[REDACTED]_javascript_attacks` | 25 | no | would help — *already fixed by the key rule* |
| `[REDACTED]_field` | 2 | no | would help — *already fixed by the key rule* |

So the two cases that motivate the entry are both at token boundaries, and the
two a boundary rule reaches are both KEYS the key fix already closed. A boundary
rule buys 64% of the raw occurrences and **none of the argument**.

#### 3 · What the 711,918 actually is

Overwhelmingly cal.com's own i18n bundle, where `admin` appears in ordinary
English prose: *"Only the organization's [REDACTED] or owner can manage SSO
settings"*. The crawl fetched the translation chunks and value redaction rewrote
their vocabulary. That is the blast radius on a bundle-heavy target, and it is
also the clue: **the corruption is concentrated in artifacts written far away in
time from the eight credential POSTs that justify the registration.**

### The options

| # | option | closes the outage? | cost |
|---|---|---|---|
| **A** | boundary-aware replacement | no | leaves 256,023 occurrences and both named cases; new rule, no argument served |
| **B** | a length threshold on `register_secret` | no | `password` is eight characters and still eats 6,227 URLs. Wrong axis |
| **C** | a vocabulary of words too common to replace globally | partly | a new vocabulary to own and to keep current against every target's prose; misses any word not in it |
| **D** | register the guess only once it WORKS | yes, for the sweep | the window the registration comment defends: the attempt's own action-log body excerpt carries the candidate while it is being tried |
| **E** | **scoped registration — register for the attempt, unregister on failure** | yes, for the sweep | none that D does not already pay, and it pays it only inside the window |
| **F** | redact values only under credential-bearing keys (provenance, not spelling) | yes | reintroduces exactly the gap the registry exists to close: *"it catches the route nobody thought of"* |
| **G** | exact-leaf-match instead of substring | yes | too weak — `username=x&password=admin` in a body excerpt is one leaf and would survive. This is a real leak, not a theoretical one |
| **H** | refuse at intake when an operator credential collides with the engine's own vocabulary | operator half only | does nothing for the catalogue passwords, which are the ones guaranteed to collide with English |

### The recommendation, and the decision that was delegated

**E, plus H.** They are independent and address the two different registration
sources.

**E — scoped registration.** The registration's lifetime should match the window
in which the secret can leak, not the run. A catalogue password is public until
it works; register it before the POST, and on a failed attempt unregister it.
Artifacts written *during* the attempt keep the redaction, which is the whole of
what the comment at the registration site defends — and it is a handful of action
log lines, not a crawl of a translation bundle. A guess that WORKS stays
registered, because at that moment it stops being public and becomes a live
credential for the client's system. This removes essentially all of the 711,918,
because the crawl and the exploit phase do not run inside a credential POST.

**H — collision refusal at intake.** The delegated decision was whether a
registered secret below some threshold should be refused. **No — length is the
wrong axis**, and the measurement is the argument: `password` is eight characters
and corrupts 6,227 URLs in one bundle. The same instinct on the right axis is a
*collision* check, not a length check: at `register_credential_set`, test the
operator's password against the report model's 125 declared field names and its
four enum vocabularies, and refuse the engagement with a message naming the
collision. That converts a silent total outage into a loud refusal at setup,
costs nothing at runtime, and weakens redaction not at all. It cannot help the
catalogue passwords — `admin` and `root` will collide with any English target —
which is exactly why E is the other half and not an alternative to it.

**Not chosen: F and G**, because both weaken the guarantee rather than narrow its
window, and the module docstring's case for value redaction — a live run wrote
five session JWTs into `trace.jsonl`, one carrying a password hash, with every
writer already redacting correctly — is a case about the route nobody thought of.
E narrows *when* the rule is armed; F and G narrow *what it can catch*.

---

## R15 · The disclosure gate shares the write path's blind spot for a JSON-spelled header

**State: OPEN.** Opened 2026-09-12 by the security review of the in-process
recorder, whose write-path half is FIXED in the same round.

**What was fixed.** `HTTPClientTool._execute_aiohttp` hands its response envelope
to the recorder as a **string**, so the outer `redact_structure` pass saw one
opaque `stdout` value and applied only the string rules — and those cannot find a
target-named cookie inside JSON. `COOKIE_INLINE_RE` wants `set-cookie:`; JSON
spells it `"Set-Cookie":`, with a quote between the name and the colon, and the
model spelling `set_cookie` has an underscore where the pattern needs a hyphen.
The one copy the rule does reach is inside `raw`, where the header sits on its own
line — but `json.dumps` escapes the newlines, so the match's `[^\r\n]+`
runs to the end of the blob and covers nothing before `raw`. **Measured on a synthetic
exchange: 2 of 3 copies of the session cookie survived.** The envelope is now
redacted as a STRUCTURE before it is recorded
(`http_client.py::_redact_envelope_for_the_record`), which is what puts
`response_headers` and `set_cookie` in front of the key-aware branch; the live
envelope is untouched, because the engine needs the real cookie to seat the
session. Guard: the response side of
`tests/test_observability/test_every_exec_mode_records.py::test_the_session_cookie_does_not_survive_into_the_record`,
observed red against the pre-fix code.

**Never observed in the wild, and the zero is the uninformative kind.** Across
every stored bundle: **3,358** in-process invocation records, **3,170** parseable
envelopes, and **zero** carrying a `Set-Cookie` at all. The recorder is one commit
old and the sessions in those runs were seated through `AuthTool`, which records
differently. So the corpus says the leak never fired, not that it could not — the
same survivorship shape as LESSONS #59.

**What stays open: the GATE.** `engagement/artifact_scan.py` detects through
`credential_shapes.find_shapes`, which shares `COOKIE_INLINE_RE` — by design, so
that a shape the redactor removes is a shape the scanner looks for. The
consequence is that the gate had the *same* blind spot and would have certified
such a bundle CLEAN. The write path no longer produces one, but the gate's job is
to catch what the write path missed, from any writer.

**Why a JSON-spelled rule was NOT added.** Measured before writing it, over
315,213 files in `outputs/`: a candidate
`"(?:set[-_])?cookies?"\s*:\s*"…"` rule matches **3,194** unredacted sites, and
**not one of them is a cookie value** — 2,957 are the empty string (the
deliberate "no cookie was sent" record, whose absence cannot state the fact),
214 are the bare name `dvwaSession`, 23 the bare name `PHPSESSID`. As a redaction
rule it is a no-op on the entire corpus; as a detector it is a no-op too, because
`_COOKIE_PAIR_RE` needs a `name=value` pair and none of the 3,194 has one. Adding
an always-on rule with no demonstrable true positive, in the round whose lesson is
that over-redaction cost every deliverable, is the wrong trade — and invariant 77
is explicit that a detector which never fires correctly is one an operator learns
to skim.

**What the round that takes this should do instead.** The gap is not "one missing
regex", it is that the shape vocabulary is defined over the WIRE spelling of a
header while artifacts increasingly carry headers as STRUCTURED JSON. The
candidates are (a) make the gate parse a `.json` artifact and walk it with the
same key-aware rule the writer uses, rather than scanning it as text — which
needs the gate to keep working on the non-JSON artifacts too; or (b) assert at
the writers that no header-bearing structure is ever flattened to a string before
redaction, which is a computed domain over the write sites rather than a
detector. (b) is closer to this codebase's grain: it removes the producer instead
of widening the net.
