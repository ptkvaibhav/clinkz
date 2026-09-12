# The cal.diy run that has evidence — measured against the one that did not

**Live, 2026-09-12.** Engagement `918e2b71`, cal.com on `http://127.0.0.1:3100`,
`TOOL_EXEC_MODE=local`, same authorization record as `e4814440`. Replaces
`e4814440` as the reference run for this target, and the reason it can is that it
has artifacts.

| | `e4814440` (2026-09-09) | `918e2b71` (2026-09-12) |
|---|---|---|
| execution mode | local | local |
| **invocation records** | **0** | **1,447** |
| `tool_call` trace rows | 0 | present |
| `run_audit.verdict` | (did not exist) | `auditable` |
| `report.json` / `.md` / `.pdf` | written | written |
| `OPTIONS` probes recoverable from artifacts | **none** | **80** |
| confirmed findings | 6 | 6 |

## 1 · What was unanswerable before, and is now read off disk

`options-sweep-measurement.md` §1 had to answer *"did the OPTIONS sweep run?"* by
**re-running it live outside the engine**, because the bundle held no record
either way. On `918e2b71` the answer is 80 invocation records:

```
OPTIONS http://127.0.0.1:3100/api/book/event
OPTIONS http://127.0.0.1:3100/api/logo
OPTIONS http://127.0.0.1:3100/api/trpc
… 37 more, per pass, two passes
```

Each carries the full request, the full response, the exit code and the duration.
The question is now a `grep`.

## 2 · The probe ordering, live

```
sweep=options_methods  budget=40  candidates=42  probed=40  dropped=2
  probed_by_grade   {1: 3, 2: 35, 5: 2}
  dropped_by_grade  {5: 2}
  ordering_failure  false
  first_omitted     http://127.0.0.1:3100/favicon.ico
```

All three `/api/` routes sit at grade 1 and were probed. The two routes the budget
dropped are grade 5 — static assets — and the report says so, by grade, rather
than reporting a bare "40 of 42". Under the old lexicographic selection the same
three API routes sat at sorted indices 33–35, surviving by six slots.

## 3 · The run is auditable and is NOT baseline-eligible, for an unrelated reason

```
run_audit           verdict: auditable, 1447/1447 recorded
provider_degradation  provider_degraded: true, fallback_count: 0,
                      absence_count: 2, absence_kinds: {chain_exhausted: 2}
                      baseline_eligible: false
```

Worth stating plainly: **`baseline_eligible: false` here is not the audit's
doing.** `run_audit_verdict` is absent from the reconciled block, which is the
designed behaviour — the audit reconciliation only tightens when the verdict is
`indeterminate`, and this run's is `auditable`. The ineligibility is two exhausted
LLM chains on the exploit phase, reported by the register that has always
reported it.

So this run is the reference for **what the engine did to this target** — every
request re-derivable — while remaining ineligible as a *performance* baseline,
and the document says which of those two it is. That distinction is the whole
point of keeping the two witnesses apart.

## 4 · What it cost to get here

The first re-run (`92c89d0d`) ran for an hour, recorded 1,466 invocations, and
wrote **no report at all**: the default-credential sweep registers `test` for
redaction, `redact_structure` substring-replaced dict KEYS, `test_start` became
`[REDACTED]_start`, and `PentestReport.model_validate` rejected the report's own
dump. Fixed in `300a46d` (a key is schema, not data); the VALUE half of the same
registration is R14 and is still lossy — `/auth/forgot-password` renders as
`/auth/forgot-[REDACTED]` in this bundle, and the LFI oracle's `root:x:0:0:`
marker as `[REDACTED]:x:0:0:`.

That is worth knowing before reading `918e2b71`'s findings: **the URLs and payload
strings in it are partially redacted by a rule that should not have touched
them.** The invocation records, the counts and the class identities are intact.

## 5 · `918e2b71` is NOT a client-facing baseline

Stated plainly, because §4 stops one step short of the consequence and a bundle
that is a reference for one purpose gets reached for as a reference for every
purpose.

Measured on the bundle:

| | |
|---|---|
| client-facing URL fields in `report.json` (`target` / `endpoint` / `a_endpoint` / `b_target`) | 18 |
| …carrying a redaction marker | **6** |
| the damaged spelling | `http://127.0.0.1:3100/auth/forgot-[REDACTED]` |
| occurrences in the Markdown deliverable | 13 of its 64 markers |
| redactions sitting inside a longer string, bundle-wide | **728,995** |

**A finding whose endpoint is unreadable is a finding a client cannot act on.**
Six of eighteen is not a blemish on a deliverable, it is a third of the
addresses. So this run is the reference for *what the engine did* — every request
re-derivable from the invocation records, which is what §1 established — and it
is **not** a document to put in front of a client, and not the artifact to
measure client-facing rendering against. Both halves of that sentence have to
travel together.

Two further readings hold, and neither is a client-facing qualification:

* the damage is confined to URL and payload STRINGS. Invocation records, counts,
  class identities and the audit verdict are intact, which is what makes §1–§3
  sound;
* 728,995 is not a measure of how much was at risk. It is overwhelmingly the
  target's own i18n bundle, where the word `admin` appears in ordinary English
  prose — the crawl fetched cal.com's translation chunks and value redaction
  rewrote their vocabulary. That is the scale of the R14 blast radius on a
  bundle-heavy target, and it is the reason the value half cannot be left as
  "degraded but honest" indefinitely.

The successor run that closes R14 is the one to re-measure this section against.
