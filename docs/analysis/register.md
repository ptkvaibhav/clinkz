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
