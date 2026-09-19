# The price before the sweep — cost cap re-derivation and the system-prefix variable

Date: 2026-09-19
Source: 41 stored bundles under `outputs/*/report_*.json` (spend blocks), 218
`trace.jsonl` files (`llm_call` events), `src/clinkz/agents/exploit.py`,
`src/clinkz/agents/prompts/exploit_system.md`, `src/clinkz/llm/spend.py`.

This document is the measurement behind two things: the USD cap the effort sweep
runs under, and a candidate second sweep variable. It reports numbers, not a
recommendation dressed as one — a raw artifact for whoever runs the sweep.

## 0 · Why the cap fires sooner than it ever has

The spend cap converts measured tokens to dollars. Two things just changed what
"measured" means:

1. **Complete token counts** (`feat(llm): a run states what each call consumed`).
   Before it, `GeminiClient` and `OpenAIClient` folded their usage into private
   accumulators and never published `last_call_stats`, so every call served by
   the fallback tail contributed **zero** tokens to the run total; and stats were
   collected in `generate_text` alone, so every `reason`/`research` call
   contributed zero no matter who served it. Both are fixed. A run's token total
   is now the real prompt+output size rather than a floor that silently dropped
   an unknown fraction of its calls.
2. **A USD cap priced at Sonnet rates.** No production run has ever used a USD
   cap — every stored bundle reads `no spend cap`, and the runs that were bounded
   used a *token* cap (400k/800k). So the USD cap is new, and it meets a token
   count that is now higher than the one any prior number was calibrated against.

So a USD cap set from "what it used to allow" would fire far too early. Re-derive
it from measured spend.

## 0.1 · Measured cost (a FLOOR — the stored bundles predate the fix)

41 bundles carry a spend block. **These totals under-count** — they were written
before the completeness fix, so their fallback-tail and `reason`/`research` calls
counted as zero. Read every figure here as a lower bound.

| metric | value (measured, floor) |
|---|---|
| total tokens / run | min 5,615 · median 119,070 · mean 117,461 · p90 214,217 · max 304,012 |
| output share | **74.8%** of all tokens (output dominates — the effort lever acts here) |
| USD/run at Sonnet-5 ($2/$10) | median $0.93 · p90 $1.75 · max $2.58 |
| USD/run at Sonnet-4.6 ($3/$15) | median $1.40 · p90 $2.63 · max $3.87 |

`claude-sonnet-5` is the configured model (`config.py:anthropic_model`); its
first-party rate is **$2 / $10** per MTok. The task's "Sonnet 4.6 pricing"
($3 / $15) prices the same tokens higher — as a *cap* input that errs safe, a
conservative over-estimate is the right direction.

## 0.2 · The price, and the cap

The price table is operator-declared and ships empty by design (`spend.py`
docstring: a built-in table would be right the day it was written and silently
wrong after). Declare the model actually configured:

    CLINKZ_LLM_PRICES='{"claude-sonnet-5": {"input": 2.0, "output": 10.0}}'

(or `{"input": 3.0, "output": 15.0}` to hold the cap to Sonnet-4.6 rates — the
conservative choice.)

**Cap:** the measured max is $3.87/run at Sonnet-4.6 rates, and that is a floor —
the completeness fix pushes the true figure up by the fallback-tail and reasoning
fraction, which the stored bundles cannot show. A **per-run USD cap of ~$8** at
Sonnet-4.6 rates clears the measured max with margin for the correction and for a
high-effort run (the sweep raises effort, and effort is billed as output — the
74.8% that dominates), while still stopping a genuine loop long before it runs
away. The **first live post-fix run confirms the multiplier**; tighten then.
A cap that fires is not a failure — it is now recorded as INDETERMINATE (§0.3),
so a strangled run is legible rather than a short "clean" one.

## 0.3 · A cost halt is INDETERMINATE (built this round)

`feat(report): a run the spend cap halted is INDETERMINATE`. A spend-cap halt
winds the phases down cooperatively, so each reports `complete` and the run used
to read as N findings over a finished target. It now does not: `_run_completion`
sees the halt, `run_completed` goes False, a no-findings run rates **Not
assessed**, the counts render as a floor, and the spend section carries a
**Cost-cap verdict** on every run — `within_budget`, `no_cap`, or the
`indeterminate` that names the halt as absence-generating across the untested
downstream classes. Three states, mirroring `observability/audit.py`
(`degradation.reconcile_with_model_stamp` on this base, since audit.py arrives
with the SPA rounds), derived from the run's own stored blocks so a re-render
reaches the same verdict.

## 2 · The live path sends no system prompt — the candidate second variable

**Report only. Not an assumed improvement.**

The 24 methodology checkpoints run through `exploit._llm_analyze`, which calls
`self._methodology_llm.generate_text(question)` — a plain string. `generate_text`
takes no `system_prompt`; it sends a cache-marked `stable` block only when handed
`PromptSegments`, and a bare string has none. So the checkpoints run **unprimed**,
and because there is no stable prefix there is nothing to cache — the **0% read
rate** is structural, not a tuning miss. ~83% of a run's decisions are made by
these unprimed calls; the deterministic oracle still gates emission, so they hold
regardless.

**What a single stable prefix would contain.** The methodology-invariant guidance
that is identical across all 24 checkpoints — from `exploit_system.md`: the
behavior-first core principle, the per-class confirmation oracles (the honesty
rules — confirm on the defining effect, never a correlate), the reasoning
discipline, and the verdict/output format. Not the ReAct-era tool-usage sections
(`How to Use Tools`, `request_help`), which a single `generate_text` checkpoint
never exercises. `exploit_system.md` is 15,519 chars ≈ **~3,900 tokens**; the
invariant subset is ~2,500–3,900.

**What it costs at the current 0% read rate** (every checkpoint carries the full
prefix, uncached):

* checkpoint calls/run ≈ 83% of the median 79 `llm_call`/run ≈ **~66** (p90: 83%
  of 126 ≈ ~105).
* added input tokens/run ≈ 3,900 × 66 ≈ **~257,000** (p90 ≈ ~410,000).
* at Sonnet input $2–3/MTok ≈ **+$0.51–0.77/run** (median) — of the same order as
  the entire current per-run cost. Sending the prefix uncached roughly doubles
  input spend.

**Why it is only affordable cached.** A stable prefix is written once (~1.25×
input) then read at ~0.1× on every later checkpoint — ~90% off the marginal cost
after the first call. Prompt caching is OFF by default by measurement (invariant
81). So the prefix is a *pair* of moves: enable caching AND send the prefix; the
uncached figure above is the cost of doing the second without the first.

**As a sweep variable.** `prefix ∈ {off, on+cached}` crossed with effort. It is a
candidate, not an improvement: whether priming the checkpoints raises confirmed
findings is unmeasured, and since the deterministic gate decides emission a prefix
can add cost and cache complexity while moving findings not at all. The sweep
would measure it against the floor-corrected baseline the same way it measures
effort — dispatch counts and confirmed findings, never plausibility.

## 3 · The effort sweep (gated behind §0)

`LLM_EFFORT ∈ {low, medium, high}` (the config validator also accepts
`xhigh`/`max`; the round tests the three named), across the DVWA ladder and Juice
Shop. `CallStats.effort` is now populated in every trace (`feat(llm)`), so a run
can say which level it ran under — the precondition for gradeability.

Grade on **ledger dispatch counts and confirmed findings against the
floor-corrected baseline, never plausibility.** Report the curve before
recommending a level. Flat findings across levels means the task is not
thinking-bound — then effort comes down on PLANNING and SUPPRESS first, EMIT last.
A level that moves findings **down** is the informative one: name which class lost
what, because that is coverage and coverage is disclosed.

**This is a live engagement.** It needs the price fixed (done), the DVWA and Juice
Shop containers up, provider keys present with quota, and real spend over hours.
Pre-flight (keys counted not printed, both providers live-pinged, targets
reachable) precedes it; if it cannot run real, the honest outcome is to stop and
say so, not to substitute a keyless harness.
