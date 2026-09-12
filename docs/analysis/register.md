# Register — observed, verified, deliberately not this round

Things measured or reported during a round whose fix belongs to a later one.
Each entry names what was **verified in the tree** versus what is still a
report, so the round that picks one up does not re-derive it and does not
inherit a guess.

Opened 2026-09-10 (tree at `b45b239`), during the default-control audit.

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
