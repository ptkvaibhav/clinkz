# The effort grid — what `LLM_EFFORT` actually buys

Date: 2026-09-21
Source: 15 live engagements run 2026-09-21, `outputs/<id>/report_*.json` (spend,
findings, component ledger) and `trace.jsonl` (per-call `effort` stamps).
Driver: `scripts`-external grid runner; per-cell logs and the raw result rows are
local-only under the session scratchpad, like every other `outputs/` artifact.

This is the measurement item 3 of `cost-cap-and-system-prefix.md` asked for,
reported before any recommendation. It reports the curve; it does not pick a
level.

## 0 · The design, and the one thing it controls for

`LLM_EFFORT ∈ {low, medium, high}` crossed with the DVWA ladder (four security
levels) and Juice Shop: **15 cells, run strictly sequentially against one lab.**

Sequential is not a convenience. A run sends hundreds of state-changing requests
— 415 on the DVWA baseline — so two engagements against one target would have
the second measuring a target the first wrote into. **Every cell resets its
target first.** DVWA's application state lives in `dvwa-db`, whose volume is
anonymous, so force-recreating both containers gives each run a fresh database;
Juice Shop is in-memory and resets with the container. The DVWA security level is
then **read back from the container** rather than assumed, because the compose
default and the image default disagree (`low` vs `impossible`) and the level is
the ladder's whole independent variable. A cell whose read-back disagreed with
its request was written to refuse rather than run.

The benchmark profile is held constant per target (DVWA: 3 categories; Juice
Shop: 9), so the only variable within a curve is `LLM_EFFORT`.

**Every run in the grid is clean.** All 15 report `run_completed: true`, all 15
were served entirely by the primary provider (`baseline_eligible: true`, zero
fallbacks), and **zero calls across all 15 failed to report usage** — so every
figure below is a measurement, not a floor.

## 1 · The grid

| target | level | effort | id | USD | input tok | output tok | output % | calls | findings |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| dvwa | low | low | `2a2a2d45` | 0.5386 | 58,951 | 42,066 | 41.6% | 79 | 24 |
| dvwa | low | medium | `d06bde48` | 0.5817 | 51,539 | 47,865 | 48.1% | 52 | 25 |
| dvwa | low | high | `dfb92107` | 0.8469 | 37,474 | 77,193 | 67.3% | 62 | 25 |
| dvwa | medium | low | `f68c17af` | 0.5152 | 56,069 | 40,310 | 41.8% | 70 | 20 |
| dvwa | medium | medium | `a821ddeb` | 0.6690 | 54,899 | 55,916 | 50.5% | 65 | 20 |
| dvwa | medium | high | `89d2065a` | 0.9906 | 44,967 | 90,068 | 66.7% | 60 | 20 |
| dvwa | high | low | `b0807101` | 0.4144 | 51,562 | 31,125 | 37.6% | 53 | 18 |
| dvwa | high | medium | `a18a39c7` | 0.5968 | 52,572 | 49,161 | 48.3% | 55 | 18 |
| dvwa | high | high | `d31ea3d2` | 0.9957 | 45,304 | 90,511 | 66.6% | 57 | 17 |
| dvwa | impossible | low | `14db0da8` | 0.4399 | 51,032 | 33,781 | 39.8% | 57 | 7 |
| dvwa | impossible | medium | `dc9c8c0c` | 0.6995 | 52,046 | 59,541 | 53.4% | 61 | 7 |
| dvwa | impossible | high | `cf28f550` | 1.1078 | 44,072 | 101,969 | 69.8% | 62 | 7 |
| juiceshop | — | low | `d8f615b9` | 0.6578 | 70,226 | 51,738 | 42.4% | 117 | 12 |
| juiceshop | — | medium | `8ee200ea` | 0.9001 | 45,774 | 80,856 | 63.8% | 87 | 10 |
| juiceshop | — | high | `f6ff1381` | 1.6042 | 45,592 | 151,299 | 76.8% | 86 | 13 |

Total: **$11.56 over 15 runs, 317 minutes of measured runtime.** The most
expensive cell is $1.60 — **5.0× under the $8 cap**, which was not raised.

## 2 · Output share climbs with effort. It is the whole effect.

Five curves, and they agree:

| curve | low | medium | high |
|---|---:|---:|---:|
| dvwa low | 41.6% | 48.1% | 67.3% |
| dvwa medium | 41.8% | 50.5% | 66.7% |
| dvwa high | 37.6% | 48.3% | 66.6% |
| dvwa impossible | 39.8% | 53.4% | 69.8% |
| juiceshop | 42.4% | 63.8% | 76.8% |

Every DVWA curve lands within **0.7pp of ~67%** at high effort, from four
different security levels — so output share at a given effort is a property of
the **setting**, not of the target. The 42.9% recorded on the pre-grid run was
one point, and specifically the low-effort point.

**Input tokens do not rise; they fall.** DVWA-low goes 58,951 → 51,539 → 37,474
input while output goes 42,066 → 47,865 → 77,193. The prompt is not inflating —
the model is spending more per call and, on most curves, making *fewer* calls
(79 → 52, 117 → 86). So cost tracks output almost alone, which is what makes
effort the one large lever on this engine and input caching the small one.

**So the lever has real headroom.** Cost/run at high effort is 1.6×–2.4× the
low-effort cost on the same cell, and the ceiling is the $8 cap at roughly 5×
further.

## 3 · Findings do not move. This is the result.

| curve | low | medium | high |
|---|---:|---:|---:|
| dvwa low | 24 | 25 | 25 |
| dvwa medium | 20 | 20 | 20 |
| dvwa high | 18 | 18 | **17** |
| dvwa impossible | 7 | 7 | 7 |
| juiceshop | 12 | 10 | **13** |

Nothing climbs with effort. Three of five curves are exactly flat, and
`impossible` is flat at 7 — the expected header-only yield when the target has
nothing else to find, which is a useful negative control: effort did not
manufacture findings against a target that has none.

Dispatch counts are flat too, and that is the sharper half. Per the component
ledger (`methodology:_test_x`, whose `items` count **dispatches**, not findings):

| cell | dispatches | classes that ran |
|---|---:|---:|
| dvwa low / low·med·high | 140 · 142 · 142 | 29 · 29 · 27 |
| dvwa medium / low·med·high | 143 · 140 · 139 | 29 · 29 · 28 |
| dvwa high / low·med·high | 141 · 141 · 141 | 26 · 29 · 29 |
| dvwa impossible / low·med·high | 142 · 141 · 137 | 29 · 28 · 28 |
| juiceshop / low·med·high | 181 · 193 · 197 | 29 · 28 · 28 |

**The engine does the same amount of work at every effort level and spends up to
2.4× as much thinking about it.** That is the "not thinking-bound" reading: the
deterministic oracle gates emission, so a better-reasoned checkpoint changes what
the model *says* and not what the code *confirms*.

### 3.1 · The two cells that moved, named

A level that moves findings **down** is the informative one, so both are named
by title rather than by total. `Finding` carries fourteen fields and none of them
names the emitting class (register R12), so this is a title-level diff.

**DVWA high, 18 → 18 → 17.** One title moved, and only at high effort:

    Local File Inclusion in page parameter      2 · 2 · 1

Every other title is identical 1·1·1 across the three runs. The high-effort run
emitted one LFI finding where low and medium emitted two.

**Juice Shop, 12 → 10 → 13.** Three titles moved:

    Cross-principal write — via the UserId field    0 · 0 · 1
    Idor — via p3 parameter (horizontal)            2 · 1 · 2
    JSON Web Token (JWT) Attack — alg_none          1 · 0 · 1

The medium cell is the one that lost: an IDOR arm and the JWT `alg_none` finding,
both of which low and high both found. That is run-to-run variance in a
concurrent crawl reaching a different endpoint set, not an effort effect — the
same two findings returning at high is what rules effort out as the cause. It is
consistent with the three-run envelope's earlier result that class+param findings
are reproducible while plan *allocation* is the residual.

### 3.2 · A new confirmed finding, and it is a terminal class

`f6ff1381` (Juice Shop, high) emitted the first **confirmed cross-principal
write** this engine has produced:

> Cross-principal write — via the `UserId` field on
> `http://clinkz-juiceshop:3000/api/Complaints` — **confirmed**, high.

It is properly armed: the control was **dispatched first** (invariant 87 — a
control dispatched after a payload whose effect outlives the request observes the
change the payload made), the decoy was refused
(`control_dispatched=True control_oracle_refused=True control_decoy_absent=True`),
and the claim rests on a **separate read** attributing the persisted object to
another principal through the owning field, not on the create's own status or
body (invariant 90). Six `ResidualMutation` rows disclose every object the arms
left behind, across `/api/Complaints` and `/api/Addresss`.

**This is downstream of the dispatcher fix, not of effort.** Every Juice Shop run
dispatched *both* terminal classes several times:

| cell | `_test_prototype_pollution` | `_test_write_crossing` | residual mutations |
|---|---:|---:|---:|
| juiceshop low | 6 | 3 | 3 |
| juiceshop medium | 5 | 3 | 3 |
| juiceshop high | 6 | 6 | 6 |

Under the round-robin that preceded this round, **all three of these runs would
have died on the second terminal dispatch** — which is exactly how engagement
`09945ed7` ended. The drain is what let a target with a real write surface reach
its terminal tail at all.

## 4 · What this does not say

* **It does not rank the levels.** Findings are flat, so on this evidence effort
  buys nothing measurable on the emit path. Pointing the lever at PLANNING and
  SUPPRESS before EMIT — the doc's own ordering — is still untested, and this
  grid does not test it: `LLM_EFFORT` is global, so every call site moved together.
* **It does not measure the prefix variable.** `prefix ∈ {off, on+cached}` was
  the candidate second variable and is untouched here.
* **Two single-run down-moves are not a trend.** The LFI 2→1 and the Juice Shop
  medium dip are each one observation. The three-run envelope exists because
  class+param findings reproduce and plan allocation does not; a claim that
  effort costs coverage would need that envelope run per level.
* **`impossible` at 7 findings is a cap, not a score.** It is the header-only
  yield, and it is flat by construction.

## 5 · Method notes for whoever runs the next grid

* **`Finding` has no class key.** Fourteen fields, none naming the emitter, so
  per-class emission comes off registry `title_tokens` and per-class *work* comes
  off the component ledger, which counts dispatches. Keeping the two populations
  apart is invariant 76; summing across them is the error they prevent.
* **Read the DVWA level back from the container.** `DEFAULT_SECURITY_LEVEL` is
  set by compose, but the image falls back to `impossible`, so a cell that
  assumes its own request is one silently-wrong environment away from grading the
  wrong rung.
* **A degradation block that renders on clean runs is not a degradation flag.**
  Testing `bool(report["provider_degradation"])` marked all 15 runs degraded; the
  block carries `baseline_eligible: true` on a clean run and truthiness cannot
  see the difference. The engine was right and the grading script was wrong — the
  absence-as-measurement shape, in the measurement rather than the engine.
* **Write the result row before anything that can raise.** See register R13.
