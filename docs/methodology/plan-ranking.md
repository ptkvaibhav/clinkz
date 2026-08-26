# Phase-3 plan ranking — the fingerprint decides the set

Every six-phase methodology reaches a phase-3 checkpoint that answers one
question — *which exploitation types is this parameter worth attempting, and in
what order?* — and then attempts a bounded prefix of the answer. Two defects
lived in that seam, and both are the same defect wearing different clothes.

The whole layer is `src/clinkz/agents/_plan_ranking.py`: pure, offline-testable,
no request, no configuration, no model. Every number below is reproducible with

```
python scripts/plan_variance_corpus.py
```

which replays the shipped rankers against **every phase-3 ranking the engine has
ever recorded** — 3,998 of them across 2,955 engagement traces — and sends
nothing.

## 1. The order was not a function of the observation

Phase 3 asked a model. The same phase-2 fingerprint presented to the same model
minutes apart came back in a different order:

| | |
|---|---|
| fingerprints ranked more than once | 64 |
| …that produced ≥2 distinct orders | **48** |
| worst case | one SQLi fingerprint ranked **210 times → 16 distinct orders** |

Reproduced within a single process. An engagement whose plan is drawn from a
distribution cannot be re-run, cannot be regression-tested against its own
baseline, and cannot support a claim of the form "this class did not fire because
the target lacks the surface" — because it might just as well not have fired
because the ranking came out differently that minute. **A plan-order defect is a
measurement problem before it is a coverage problem**, which is why it was worth
fixing ahead of anything it was blocking.

## 2. The fingerprint was not read

Phase 2 counts the UNION columns and proves the breakout context. The
deterministic ranking then ignored both. Replayed against the recorded corpus,
the pre-existing fallback rankings keep **770 of the 833** confirmations a
current vocabulary can express:

| class | reachable confirmations | the old fallback ranking reaches | missed |
|---|---|---|---|
| `idor` | 49 | 8 | **41** — every one `horizontal`, dropped by `predictability == "opaque"` |
| `sqli` | 313 | 297 | 16 — 12 of them with the column count already counted |
| `open_redirect` | 59 | 55 | 4 |
| `lfi` | 112 | 110 | 2 |
| `cmdi` | 135 | 135 | 0 |
| `file_upload` | 158 | 158 | 0 |
| `ssrf` | 7 | 7 | 0 |
| **total** | **833** | **770** | **63** |

The IDOR line is one condition: `if primitives.predictability != "opaque"` gated
`horizontal` out of the ranking. Opacity says *you cannot guess the next
identifier*; it says nothing about whether the object behind a known one is
protected. 1,087 of the 1,186 gate-closed IDOR fingerprints in the corpus are
opaque, and `horizontal` is 48 of the 49 recorded IDOR confirmations.

## The shape that replaced it

A ranking returns two things rather than one:

- **`ranked`** — the full order, a pure function of the phase-2 fingerprint;
- **`supported`** — the subset the fingerprint *empirically backs*, i.e. the types
  some phase-2 probe actually observed the precondition for.

`attempt_window` then bounds the attempt list by that split rather than by a bare
`[:3]`. **A supported type is never truncated** — dropping a type the target's own
responses argued for is what truncation should never do — and the cap applies to
the unsupported tail, which is hypothesis rather than evidence. The window is
never *narrower* than the `[:3]` it replaces: with nothing supported it is
exactly `ranked[:3]`.

The tail is never empty either. Phase-2 probes are a sample, not an exhaustion —
the corpus holds three `appended_url` open-redirect confirmations on parameters
whose fingerprint reported that primitive did **not** work — so "the fingerprint
did not back it" is not "the fingerprint refuted it". One probe past the evidence
is the cheapest hedge, and it is also what makes a type no fingerprint ever backs
reachable at all.

That value is measured, not chosen. Over the corpus's 835 confirmations:

| unsupported-tail minimum | confirmations still reached | attempt cost |
|---|---|---|
| 0 | 830 | +0.7% |
| **1** | **833** | **+5.6%** |
| 2 | 833 | +14.6% |

1 is the only setting that buys anything and 2 is strictly dominated. The two
confirmations no setting recovers are the retired `js_protocol` and `file_scheme`
— 833 is the whole reachable set.

## Where the model still is

`sqli` and `cmdi` are **inverted**: no LLM call at all. Each of SQLi's four
in-band types has exactly one phase-2 observation that is its precondition and
phase 2 records all four, so the model had nothing to contribute; for CMDI the
model and this ranking already agreed on the top-3 set 97.9% of the time and on
the leading type 85.8%, and the ranking loses none of the 135 recorded
confirmations.

The other seven keep their checkpoint, under one rule (`merge_llm_ranking`):
**the model orders the supported block; it does not choose the vocabulary and it
does not order the unsupported tail.** Those are evidenced alternatives and
picking between them is a judgement worth having a model for. On the tail the
model is ranking hypotheses against no observation at all — and the corpus has
the instance: a model ranked LFI `error_based_path` (a leaked path, which is
reachability rather than a read, and which this layer never supports) ahead of
`wrapper_extraction`, and the confirmation was `wrapper_extraction`.

## The four SQLi signals

| type | the phase-2 observation that backs it |
|---|---|
| `error_based` | `error_match` — a DB error surfaced in the body |
| `union_based` | `union_columns` — the front query's column count |
| `boolean_blind` | `break_prefix` — the confirmed closing context |
| `time_blind` | `time_match` — a measured delay differential |

Both `break_prefix` and `union_columns` are tested with `is not None`, never for
truthiness: `break_prefix == ""` is a **confirmed** breakout into a value already
in statement position, and reading it as absent throws the proof away exactly
where exploitation is cheapest.

`stacked` is appended on MSSQL/Postgres and is never supported — the dialect
permits multi-statement execution, but nothing observed it surviving the driver.
`auth_bypass` is deliberately absent from the ranking: its applicability is a
protocol artifact on the *request*, not on the dialect, and the agent's own
credential-field gate adds and removes it afterwards.

**Boolean-blind sits above union-based in the canonical order, and that is the one
place this departs from reading the four signals as symmetric.** Three of the
signals are near-necessary for their type — 49/49 `time_blind` confirmations
carry `time_match`, 138/139 `error_based` carry `error_match`, 38/42
`union_based` carry a column count — but only **28 of 79** `boolean_blind`
confirmations carry a `break_prefix`. Phase 2 gives up on the breakout often and
the boolean channel confirms anyway from the quote character alone. Its signal is
sufficient, never necessary, so the type cannot sit at the bottom of the tail:
ranking it last drops 51 confirmations, and every ordering that keeps it off the
bottom scores full parity at identical attempt cost.

## The six holes, and what each was worth

| class | the hole | keyed on now |
|---|---|---|
| `ssrf` | took the capability, ignored it, returned a constant — correct only because its single caller had already made the one decision that mattered | the blind branch lives in the ranker; `content_reflected` backs `reflected_internal`, `fetch_confirmed` backs the two that need an address the fetcher was not given |
| `idor` | omitted `horizontal` when `predictability == "opaque"` | `horizontal` supported unconditionally (phase 3 is past the divergence gate); the authz check splits `parameter_pollution` from `function_level` |
| `nosqli` | default branch returned `[]`, discarding an observed operator set along with the genuinely empty case; and the `$where` branch ranked `nosql_dos` **first** | observed operators / error signatures survive an unresolved context; `where_js_injection` leads and the DoS is last and never supported |
| `ssti` | `sandbox_escape` appeared in no branch and could never be attempted | ranked whenever a syntax was observed evaluating — which is exactly the "engine evaluates, gadget blocked" shape it is for |
| `lfi` | `source_disclosure` reachable only inside the `php://filter` branch | any `php://` wrapper, or a suffix the handler concatenates |
| `open_redirect` | built only from pre-confirmed primitives, so the class could not probe a parameter its own probes had failed on — and four recorded confirmations are on exactly those parameters | every type this ranking owns is ranked; the confirmed ones are the supported set and lead |

Two corrections to that list are worth stating rather than quietly fixing:

- **Neither `js_protocol` nor `allowlist_bypass` is an unreachable member.**
  `js_protocol` and SSRF's `file_scheme` appear in the corpus as *confirming*
  types but are no longer enum members; they were retired, and the replay holds
  those two confirmations out rather than counting them as regressions, because
  no ranking can produce a type the vocabulary does not contain.
  `allowlist_bypass` is absent from the phase-3 ranking for a different reason:
  it has its own dispatch branch — a token harvested from the app, embedded in
  four attacker-URL shapes, verified by its own phase 5. Ranking it as well
  would open a second route to one label whose phase 4 has *no* deterministic
  build, so a model would be asked to invent the payload and a confirmation
  could carry the `allowlist_bypass` label with no harvested token behind it.
  The open-redirect hole is narrower than "a member was unreachable", and is
  worth exactly its four measured confirmations.
- **The NoSQL default branch returning `[]` is right for almost every case it
  covers.** 1,334 of the 1,351 recorded NoSQL rankings carry no operators, no
  error signature and no injectable `$where`; widening those would fire NoSQL
  payloads at 1,334 parameters that showed no sign of a document store, which is a
  target detector rather than a test. The hole is that the branch also swallowed
  the cases where something *was* observed.

And one non-fix: SSRF's ordering stays **impact-first** even though `cloud_metadata`
led every in-band ranking ever made and confirmed zero times. All three in-band
types share one precondition, the window attempts all three either way, and the
phase-5 loop stops at the first confirmation — so ranking a loopback reach ahead
of an instance-metadata read would report the smaller finding on a target where
both hold. None of the corpus's targets was in a cloud. That is a fact about the
corpus, not about the ranking.

## What the replay can and cannot prove

`scripts/plan_variance_corpus.py` reports `kept now` at 835/835. That is **true by
construction and carries no information**: a type that was never attempted never
produced a confirmation to record, so the corpus is censored at the window.

The column that carries information is `kept new` — whether the deterministic
ranking still reaches what the engine is known to have found. It is **833 of 833
reachable confirmations, at +5.6% attempts**, and a broken ranking fails it
loudly: the fallbacks this layer replaced score 770.

The *widening* is not measurable offline for the same censoring reason, and its
benefit is by construction rather than by measurement: a type that is now
attempted and previously was not can confirm, and every extra attempt passes the
same phase-5 oracle and the same never-sent control, so it adds no phantom
exposure. What the replay does bound is the cost.

## The reachability guard

`tests/test_agents/test_plan_ranking.py` computes, per vocabulary, the set of
types no fingerprint in a declared fingerprint space can rank, and fails on any
that is not allow-listed with a reason. Three are:

- `InjectionType.AUTH_BYPASS` — owned by the agent's credential-field gate,
  which keys on a protocol artifact in the *request*;
- `SSRFExploitationType.BLIND_OOB_CONFIRMED` — an outcome the out-of-band reap
  records, not a hypothesis anything dispatches;
- `RedirectBypassType.ALLOWLIST_BYPASS` — dispatched by its own branch, as
  above.

Both directions are asserted, per the guard-domain law: a new unreachable type
fails, and an exemption that outlived what it described fails too. Run against
the *previous* open-redirect ranking the guard names three types at once —
`allowlist_bypass`, `at_syntax` and `protocol_relative` over the same
fingerprint space — so it bites on the defect class rather than on one
instance.
