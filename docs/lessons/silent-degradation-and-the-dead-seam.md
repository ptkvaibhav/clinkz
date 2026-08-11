# Silent degradation — three defects, one shape, and the gate that now catches them

Three defects shipped independently and were found independently. They are the
same defect.

| # | Component | What it produced | What covered for it | What the run looked like |
|---|---|---|---|---|
| 1 | Exploit LLM planner | an empty completion | the per-class floor | a plan existed |
| 2 | Primary LLM provider | a timeout | provider rotation | an answer arrived |
| 3 | ffuf consumption seam | nothing, ever | the crawler | endpoints existed |

Every time: a component produced **nothing**, a fallback covered, findings
still appeared, and no gate fired.

The common root is not any of the three bugs. It is that **a total is not
evidence about its parts.** A run reporting 21 findings while a whole discovery
tool contributes zero is indistinguishable, from outside, from a run where it
contributed half of them. Nothing in the system measured a part.

## The ffuf seam, in detail — because it is the purest case

`_run_fuzz_tool` read `parsed.paths` and `parsed.directories`.
`FfufOutput` (`tools/ffuf.py`) has neither; it has `results`. Both `hasattr`
checks were False, the seam returned `[]`, and **100% of ffuf's output was
discarded for as long as the seam existed.** Content discovery had never
functioned.

Nothing failed, because an empty list from a fuzzer is exactly what a target
with no hidden content looks like. There is no error, no exception, no log line
— the two possible worlds are byte-identical from the consumer's side.

**The green test suite was part of the mechanism.** `tests/test_agents/test_scan_v2.py`
defined `_MockFuzzOutput` with `paths` and `directories` fields — names no real
tool has ever carried. The mock was written to satisfy the consumer's *guess*
rather than to mirror the real producer, so the test asserted a contract only
the mock honoured. A test over a dead path is worse than no test: it is a
standing claim that the path works.

### The structural fix, not the two-string fix

Correcting `paths` → `results` would have fixed this instance and left the
mechanism. The mechanism is that **the consumer guesses the producer's field
names**, and guessing wrong is silent.

So the contract is declared on the producer:

```python
class ToolOutput(BaseModel):
    def discovered_urls(self) -> list[str]:
        return []

    @classmethod
    def declares_discovery(cls) -> bool:
        return cls.discovered_urls is not ToolOutput.discovered_urls
```

The consumer calls a method that exists on every output type, and the two
failure modes are now distinguishable:

* the output type does not declare `discovered_urls` → a **DEAD SEAM**, logged
  at WARNING and recorded on the ledger as structurally inert;
* the output type declares it and returns nothing → an honest empty result,
  recorded as a zero contribution.

A wrapper that forgets to declare it no longer yields silence.

## The full audit — every wrapper, not just ffuf

Two more dead seams, and four dead capabilities:

| Tool | Output model exposes | Consumer reads | Verdict |
|---|---|---|---|
| ffuf | `results`, `command_line` | `paths`, `directories` | **DEAD** — fixed |
| sqlmap | `vulnerable`, `injection_types`, `dbms` | `getattr(parsed, "injectable", False)` | **DEAD** — fixed |
| katana | `urls` | `endpoints`, `urls` | OK (partly by luck) |
| nmap | `hosts`, `open_ports` | `open_ports`, `hosts` | OK |
| whatweb | `results[].technologies` | same | OK |
| wafw00f | `results[].waf_detected` | same | OK |
| http_client | `status_code`, `response_headers`, `response_body` | same | OK |
| **nikto** | `findings` | — | **UNUSED** — no agent resolves `web_vulnerability_scanning` |
| **nuclei** | `findings` | — | **UNUSED** — no agent resolves `vulnerability_scanning` |
| **subfinder** | `subdomains` | — | **UNUSED** — no agent resolves `subdomain_enumeration` |
| **httpx** | `results` | — | **UNUSED** via `find_tool`; reachable only by chain name |

`sqlmap`'s was the same shape with a worse tell: `getattr(parsed, "injectable",
False)` supplies its own default, so a field name that never existed returns
`False` on every run. **A `getattr` default is how a typo becomes a permanently
dead capability.** Read the attribute directly and a rename fails loudly.

### Two structural defects in the resolver layer

* **The declared fallback chains were nominal.** `try_until_sufficient` walks a
  chain of tool NAMES and hands each to a callback — but every callback ignored
  its `tool_name` argument and re-resolved the capability, returning the same
  first-available class each time. `katana → gospider → hakrawler` ran katana
  three times. Fixed with `ToolResolver.find_tool_by_name`.
* **`TOOL_CHAINS` and declared capabilities disagree.** The chain key
  `subdomain_discovery` matches no capability any tool declares (subfinder
  declares `subdomain_enumeration`), and `find_tool` resolves by declared
  capability while `find_tools_ranked` resolves by chain name — so the two
  lookup paths answer differently for the same capability. httpx is reachable
  by one and not the other.

The four UNUSED wrappers are **reported, not deleted**. A capability nothing
consumes is a dead capability, but wiring three new scanners into the phase
agents is a different piece of work with its own honesty questions (nuclei and
nikto emit findings that would have to pass the same verification-honest
emission gate as everything else). The ledger now names them.

## The gate: a component-contribution ledger

`observability/ledger.py`. Per component: invocations, successes, and — the
number none of the three defects would have survived — **items contributed**.
At end of run, everything invoked that contributed nothing is reported at
WARNING in the run log and in `report.json`.

Four alarm classes, kept apart because they have different fixes:

* `DEAD_SEAM` — the consumer cannot read this producer. Structurally inert, and
  a louder fact than a quiet component.
* `SILENT` — invoked, succeeded, contributed zero. The defect shape.
* `ALL_FAILED` — invoked, never succeeded. Loud already, recorded for completeness.
* `FALLBACK_ACTIVATED` — something covered. Not a defect on its own; a fallback
  that activates is doing its job. But it is the mechanism that hid all three,
  so it is never invisible again.

**"Declared but never invoked" is tracked separately.** A capability the run
never reached for did not degrade — burying the real alarms under every
inapplicable tool is how a gate becomes noise nobody reads.

Two constraints, both earned elsewhere in this codebase:

* **Absent by default**, like the safety governor. No engagement installs one,
  every hook no-ops, and a smoke cell or replay is byte-identical.
* **Never raises from the data path.** An observability layer that can abort a
  scan is worse than the blindness it fixes.

## What the recorded DVWA runs actually show

The four graded P7 engagements (`docs/p7-pipeline-validation.md`), re-read for
this work. In **all four**, the exploit-phase planner call returned empty:

| Level | Engagement | Trace line | Duration | Tokens |
|---|---|---|---|---|
| LOW | `35511096` | 411 | 34.3 s | `None` |
| MEDIUM | `1b23a1ef` | 419 | 32.2 s | `None` |
| HIGH | `946e7036` | 409 | 32.1 s | `None` |
| IMPOSSIBLE | `f4b0c5c8` | 407 | 34.0 s | `None` |

Every one is `provider=anthropic`, `response_summary=""`, ~32–34 s, no token
accounting — the signature `EmptyResponseError` now names: a thinking-capable
model spending the whole `max_tokens` allowance on reasoning, ending the turn
with zero text blocks.

**So in every one of the four runs, the exploit plan came entirely from the
deterministic class floor and the coverage fill.** The LLM planner contributed
zero, four times out of four, and the runs were graded as product results.

### sqli_blind at HIGH — the same cause, not a methodology defect

At HIGH (`946e7036`), the `sqli_blind` endpoint appears in the trace only under
**phase 1** (`injection_point_mapping`) and never progresses. The `sqli` skill
reached phase 6 elsewhere in the same run, so the methodology was working —
it was not pointed at that endpoint past the first phase.

The chain: planner returned empty → the plan is floor + fill → the floor
reserves `_CLASS_FLOOR_TASKS` per class → the `sqli` class's reserved slot went
to the session-indirection carrier (which confirmed, and is the run's one SQLi
finding: *"SQL Injection in id session value"*) → the cookie-borne
`sqli_blind/high` point never got a task that advanced.

**This closes as one cause with the planner outage.** No methodology defect was
found and none should be invented: the component that would have ranked
`sqli_blind` alongside `sqli` contributed nothing.

### brute force at LOW

In the recorded set, brute force **did** confirm at LOW (`35511096`, reaching
phase 4) and stopped at phase 3 at MEDIUM/HIGH/IMPOSSIBLE — which is correct,
since DVWA adds protection above LOW. So the artifacts available here do not
show a brute-force miss at LOW.

What can be said precisely: the planner outage **was** present in the LOW run
too (line 411), so it is an available explanation for a brute-force miss in a
sibling LOW run, and the mechanism is now closed twice over — `EmptyResponseError`
makes an empty completion a retriable failure that rotates the provider, and
the ledger reports the planner's zero contribution even if it recurs.

**Limit stated plainly:** the run labelled `dvwa_high_run1` is not recoverable
by that label from this repository. The analysis above is from the four
engagements that *are* on disk. A miss in a run whose artifacts are gone cannot
be root-caused, only explained by a mechanism that is now instrumented.

## The corpus gate had the same hole

Running `clinkz corpus-replay` properly — rather than claiming it — found that
**ffuf had no parser in the gate**: 304 recorded invocations counted as
`no-parser`. The parser regression gate did not cover the tool whose seam was
dead. Two further defects fell out of fixing that: the baseline was redacted on
write and compared raw, and redaction fingerprints are deliberately salted and
so cannot be a comparison key.

`checked=422` → `checked=1423`, `mismatched=0`, exit 0.

## The rules this leaves

1. **A consumer must never guess a producer's field names.** Declare the
   contract on the producer; a missing declaration is loud.
2. **A `getattr` with a default over a model field is a silent-failure
   generator.** Read the attribute.
3. **A mock must mirror the real model's contract**, not the consumer's
   assumption about it. A mock shaped to the consumer's guess turns the test
   suite into a co-conspirator.
4. **Measure parts, not totals.** "Findings were produced" says nothing about
   which components produced them.
5. **A fallback activating is a fact worth recording**, even when the fallback
   works. It is the thing that makes degradation invisible.
6. **Run the gate before claiming it.** Every defect in this section was found
   by running `corpus-replay`, not by reading it.
