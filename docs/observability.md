# Observability and replay

Every Clinkz engagement is recorded with enough fidelity that any single
tool invocation or agent step can be inspected, diffed, or re-run in
isolation. This document describes the guarantee, the file layout, the
CLI commands, and the testing rule that keeps the guarantee enforced.

## The guarantee

For every engagement Clinkz writes under `outputs/<engagement_id>/`:

| Path                                              | One per                  | Contents |
| ------------------------------------------------- | ------------------------ | -------- |
| `trace.jsonl`                                     | engagement               | append-only JSONL — one event per tool call, LLM call, agent step, message handoff, methodology phase. Summary-grade. |
| `tool_invocations/<seq>_<tool>.json`              | subprocess               | full-fidelity record: exact argv (post-docker-wrap), env overrides, stdin, complete stdout, complete stderr, exit code, duration, parsed Pydantic output. |
| `step_inputs/<step_id>.json`                      | wrapped agent step       | the entire input payload (not a summary), the agent class, the step method name, and replay metadata. |

Two invariants:

1. **Every subprocess produces an invocation file.** `ToolBase._run_subprocess`
   and `ToolBase._run_subprocess_stdin` are the only paths to a tool
   subprocess; both call `TraceWriter.record_tool_invocation`. If a tool
   wrapper bypasses these helpers it bypasses the recorder — don't.
2. **Every wrapped agent step produces a step inputs file.** Agent steps
   that opt into `BaseAgent._record_step("name", inputs=..., replay_info=...)`
   write the input payload at entry and emit an `agent_step` trace event
   on exit. Unwrapped steps don't show up in `step_inputs/` and can't be
   replayed.

## The invocation record schema

```json
{
  "seq": 0,
  "ts": "2026-05-18T17:34:21.123456+00:00",
  "tool_name": "nmap",
  "exec_mode": "docker",
  "cwd": "/work",
  "command": ["docker", "exec", "clinkz-tools", "nmap", "-sV", "..."],
  "env_overrides": {},
  "stdin": null,
  "stdout": "Nmap scan report for ...",
  "stderr": "",
  "exit_code": 0,
  "duration_ms": 1832.41,
  "agent": "recon",
  "step": "service_scan",
  "step_id": "f24c7c3e-...",
  "parsed_output_type": "NmapOutput",
  "parsed_output": { "hosts": [...] },
  "parse_succeeded": true
}
```

`agent`, `step`, and `step_id` are populated automatically from the
active step context (set by `TraceWriter.step` / `BaseAgent._record_step`)
— so as long as the invocation happens inside a wrapped step, you can
trace the call back to its owner without a separate join.

## CLI

### `clinkz tool-invoke <engagement_id> <seq>`

Prints the full invocation record (command, stdout, stderr, exit code,
parsed output). Use this to diagnose a tool failure without re-running
the whole pipeline:

```
$ clinkz tool-invoke 4f1d... 42
seq=42 tool=katana agent=scan step=http_scan rc=0 dur=8421ms
  cmd: docker exec clinkz-tools katana -u http://localhost:8080 -d 3 ...
  parsed: KatanaOutput (succeeded=True)

--- Full record ---
{ ...complete JSON... }
```

### `clinkz tool-invoke <engagement_id> <seq> --replay`

Re-runs the *exact* argv with the recorded `cwd` and `env_overrides`,
then prints a unified diff of stdout/stderr against the original record.
The harness does not re-wrap the command in a docker exec — it replays
what was recorded, so docker-mode invocations replay through docker too.

This is how you confirm whether a flaky tool produced different output
the second time, or whether the original output was deterministic and
the bug is downstream.

### `clinkz step-replay <engagement_id> <step_id>`

Re-runs one recorded agent step in isolation. The replayer:

1. Loads `step_inputs/<step_id>.json`.
2. Re-creates the engagement scope from the recorded payload (or from
   the inputs, if the scope wasn't stored).
3. Instantiates a fresh agent of the recorded class with an in-memory
   `StateStore` and the default `ToolResolver`.
4. Calls the recorded step method with the recorded inputs.
5. Captures the new output and diffs it against the `output_summary`
   from the original `agent_step` trace event.

Seconds, not minutes. Use this when a downstream step blew up — replay
the upstream step on its own to confirm the data it produced was right.

### `clinkz trace inspect <engagement_id>`

The pre-existing readable timeline. Unchanged shape; each `TOOL` row now
carries an `invocation_seq` and an `invocation_file` pointer, which the
two commands above use as their inputs.

## How to wrap a step for replay

Inside a v2 agent method, replace any deterministic step body with:

```python
with self._record_step(
    "port_scan",
    inputs={"target": url_host},
    replay_info={"method_name": "_step_port_scan"},
):
    ports = await self._step_port_scan(url_host)
```

`replay_info.method_name` is what `StepReplayer` calls on a fresh agent
instance. The agent class and engagement id are filled in automatically.

If the step body itself runs `_run_subprocess`, those invocations carry
`agent` and `step` populated to the wrapped step — no extra work.

## When to write a pipeline_smoke test vs a unit test

`tests/test_pipeline_smoke/` is the real-container, real-orchestrator
suite. The rule:

- **Anything that touches a tool wrapper, an agent step, or an
  orchestration path needs a pipeline_smoke test that would have caught
  the bug without it.** Mocked unit tests are insufficient — they let
  the orchestration glue silently drift.
- **Anything that's pure logic (a parser, a model validator, a planner
  prompt-builder) goes in a unit test.** Unit tests are fast; reserve
  the slow tests for the seams that actually break.

A pipeline_smoke test must assert on the trace or findings, not just on
the returned summary dict. The sidecar files are where regressions show
up — a fix that silently stops emitting invocations would pass a return-
value check but fail an `outputs/.../tool_invocations/` check.

Run them explicitly:

```
pytest -m pipeline_smoke tests/test_pipeline_smoke/
```

### Run the live suite on its own — not bundled into `pytest tests/`

These tests drive the real orchestrator against shared containers
(`clinkz-tools`, `clinkz-dvwa`, `clinkz-juiceshop`) and share server-side
session state (the DVWA `PHPSESSID`, the session-scoped `crawled_dvwa_cookies`
crawl). They are also timing-sensitive (real recon scans, a real katana crawl,
LLM retry/backoff). Run them as their **own** invocation with **all three
containers up** — including `clinkz-tools`, without which the crawl-dependent
tests skip:

```
docker compose -f docker/docker-compose.yml up -d   # incl. clinkz-tools
pytest -m pipeline_smoke tests/test_pipeline_smoke/
```

In isolation the suite is green (e.g. 10 passed / 6 skipped with `clinkz-tools`
down; the finding-emission + recon tests pass with it up). It is **excluded
from the keyless gate** (see CLAUDE.md) precisely because bundling it into a
full `pytest tests/` run interleaves it with the other live suites and the
~1.2k unit tests, and the resulting cross-suite session-state/ordering/timing
contention makes `test_recon_fingerprints_*`, the exploit-plan test, and the
`test_finding_emission` trio flake — even though pytest runs serially (there is
no xdist). A deeper per-test isolation fix (fresh session per test, container
health gating, unique engagement ids) is tracked as deferred follow-up; the
operational contract today is "run the live suite separately."

CI must run these. Failures here are blocking — they mean the live
behaviour has drifted from the recorded behaviour.

## Why two recorders, one trace

The `trace.jsonl` summary stays cheap to read and grep (`jq`-friendly).
The full-fidelity sidecar files stay cheap to load individually (`cat`
one stdout dump in milliseconds). The summary line points at the sidecar
file via `invocation_file`, so `clinkz trace inspect` keeps reading
fast, and `clinkz tool-invoke` keeps reading authoritative.

If a future version of the trace needs to embed more data inline, do it
on a new category — never bloat the existing summary lines past 500
chars, or `clinkz trace inspect` becomes unreadable on a real run.

## A bound that decides coverage belongs in the DELIVERABLE, not just the log

`observability/plan_alarms.py`.

`clinkz scan` states five bounds before it dispatches anything — rate,
concurrency, window, token cap, spend cap. The **plan cap** is the sixth, and it
is the one that most directly decides what gets tested: candidate
`(class, endpoint)` pairs are ranked and everything past the cap is dropped. Four
recorded D1 baseline runs each truncated ~1,500 candidates to 150.

That has never been *silent* — `_log_plan_truncation` names every truncated
class, the count, the first omitted endpoint, and separately any ranking
inversion. It was only ever loud in the run log and `trace.jsonl`, and a client
reads neither. So a report could say "we tested the target" over a plan that
dropped the one endpoint a class could have confirmed on, and nothing in the
deliverable would say so.

`PlanTruncation` is recorded per planning pass, carried on
`PentestReport.plan_coverage`, and rendered as a **Plan coverage** section. Two
facts, kept apart because they have different fixes:

| Fact | What it means | The fix |
|------|---------------|---------|
| `dropped_total` | The cap removed a class's tail. The budget working. | A larger cap (`EXPLOIT_MAX_PLAN_TASKS`). |
| `ranking_inversion_count` | A task was dropped from an endpoint where **that class's own attack surface was observed**, while lower-relevance tasks survived. | Not a larger cap — the planner's ordering. It is what cost D1 its weak-session and SQLi findings. |

Summing them would hide the ordering defect inside the budget, the same reason
the contribution ledger keeps `DEAD_SEAM` apart from `SILENT`.

### A reservation is a third fact, and it is not truncation either

`PlanTruncation.cap` is the cap **this pass** was allowed to spend, which is the
configured cap minus whatever another plan source reserved. `reserved`,
`reserved_for` and `configured_cap` ride beside it so the two are never confused.

They are different fixes again. "The cap dropped your tail" is answered by a
larger cap. "A reservation shrank the cap first" is answered by asking whether
the reservation was worth it — and the reader cannot ask that question if the
only number in the report is a cap they cannot reconcile with
`EXPLOIT_MAX_PLAN_TASKS`.

Today the only reserver is the dependency→CVE plan source
(`reserved_for: "component_cve_match"`), sized at
`min(_MAX_COMPONENT_CVE_MATCHES, dispatchable)` before planning and returning
whatever it does not spend. On a run that matched no CVE it is `0` and the
section renders exactly as it did before.

### `kept` is a total, and a total is not evidence about its parts

`PlanTruncation` also carries **`kept_by_class`** — per class, how many of its
tasks survived the cap — and the register's summary carries
**`classes_with_candidates`**, every class the plan held a candidate for at all.

`kept: int` beside `dropped_by_class: dict` is the same shape this codebase has
had to break down before. A class that emitted nothing is one of two entirely
different bugs, and the total cannot tell them apart:

| Observation | What it means | The fix |
|-------------|---------------|---------|
| every candidate dropped, none kept | coverage lost to the cap | a larger cap, or better ranking |
| tasks kept and the class still never ran | the plan reached it and the **dispatcher** did not | the dispatcher — nothing about the cap |

The second is the ffuf shape at class granularity: a component invoked,
succeeding as far as anything checked, contributing zero. Without the
breakdown both look like a quiet class, and a quiet class looks like a target
with nothing to find.

The **class-coverage account** (`scripts/d1_consistency_runner.py::class_coverage`)
reads these to give every dispatchable class exactly one verdict, discriminating
on how far the class's own pipeline got — never on what it says about itself,
because "there was nothing to find" is what a broken class reports too:

* `dispatched_deep` — reached phase 2+; it probed.
* `dispatched_applicability_only` — phase 1 only; its precondition was absent.
  Correct, and falsifiable from the phase-1 payload.
* `dispatched_gate_refused` — refused at the dispatch chokepoint. Correct.
* `never_dispatched_no_candidates` — the plan held nothing for it. Correct, and
  **not an alarm** — the same fifth fact the ledger records as NOT APPLICABLE.
* `never_dispatched_all_candidates_dropped` — ALARM: the cap.
* `no_phase_event_tasks_survived_the_cap` — ALARM: tasks survived the cap
  and the class produced no phase event. It does **not** name the
  dispatcher: a class that returns `[]` at its own entry gate, before its
  first phase trace, is indistinguishable from a class the dispatcher never
  called — and every observed instance so far was the former (a form gate
  reading `page.forms` on a framework target). Read the class's
  applicability gate first.
* `never_dispatched_kept_breakdown_absent` — ALARM: a trace older than
  `kept_by_class` cannot separate the last two, and an indeterminate answer is
  reported rather than rounded to the benign side.

Only the **union** stage is read, for the same reason `dropped_primary_targets`
reads only the union stage: it is the plan that actually dispatched, and the
deterministic stage is its source.

Which class each verdict is about comes from `_CLASS_TRACE_SKILL` in
`agents/exploit.py` — the PRODUCER declaring which `skill` string its own
methodology phases are traced under, rather than a consumer guessing
`_test_x -> "x"` (right for 23 of 24 and wrong for `_test_javascript_attacks`).
`tests/test_agents/test_class_trace_skills.py` walks the call graph and asserts
the declaration against the source, so it cannot become a wish.

The account covers the 24 classes in `_DETERMINISTIC_CATEGORY_ORDER`. The other
six dispatchable methods — `_test_log4shell`, the two tier-2/3 technique
dispatchers and the three business-logic methods — are not planned per endpoint
the same way and are **unaccounted rather than reported**, so 24/24 is not read
as total coverage.

The section renders when the plan **fit**, too: "no class was truncated" is a
claim, and a run that fit inside its cap and a run whose truncation nobody
recorded must not produce identical artifacts.

Absent by default, like the governor, the ledger and the scope-refusal log. A
directly invoked methodology, a replay or a driver installs no register, every
hook no-ops, and the black-box floor is byte-identical. The per-class endpoint
list is capped at 20; **the counts stay exact past the cap**, because a truncated
record of a truncation is the failure the module exists to prevent.

### Two bounds, one rule

The plan cap is not the only bound that decides coverage, and it is not the
first. The Scan agent's endpoint enrichment opens a fixed number of discovered
URLs (`max_visits = 80`), and everything the plan cap can rank has already
survived that budget — a URL never opened yields no endpoint, no parameter and no
form, so it never becomes a candidate `(class, endpoint)` pair at all.

That bound had the exact defect `plan_alarms.py` was built to fix. On the first
non-benchmark engagement:

| stage | count |
| --- | ---: |
| URLs emitted by the crawler | 3,070 |
| after dedup + `is_state_changing_url` | 212 candidates |
| opened by enrichment (`max_visits = 80`) | 80 |
| **never enqueued** | **132 (62%)** |

Loud at INFO in the run log; absent from `report.json`. `CrawlBudgetTruncation`
records it on the same register and the Report agent renders a **Crawl
coverage** section from it, on a clean run too.

Three things are stated apart because they answer different questions:

* **the total** — how much of the discovered surface was never examined;
* **`opened_by_host` beside `dropped_by_host`** — a sum cannot distinguish "this
  host was covered thinly" from "this host was never opened at all", and the
  second is a materially different claim to put in front of a client;
* **`first_omitted`** — the highest-priority URL the budget did not reach, so a
  reader can check the ordering (`crawl_visit_priority`) rather than take it on
  trust.

It also qualifies a number elsewhere in the report. The scope-refusal log counts
requests that were **refused**, and this budget decides which candidates ever
become requests, so "75 refusals across 3 hosts" describes the opened slice of
the out-of-scope surface rather than the surface. The *Crawl coverage* section
says so explicitly rather than leaving the refusal tally to imply more than it
knows.

### One href is one candidate

14 of those 212 candidates (6.6%) were the same links wearing an escape:

```
https://github.com/ptkvaibhav
https://github.com/ptkvaibhav%5C
https://github.com/ptkvaibhav%5C%5C%5C
```

`%5C` is a URL-encoded backslash. A React Server Component flight payload carries
`"href":"/x"` JSON-escaped inside a `<script>`, so a harvester that never
unescapes reads the escape as part of the path — and a nesting level adds
another. Three spellings, three of eighty visits, one link.

`_url_shape.crawl_dedup_key` strips the fragment, a trailing slash and any
trailing escape artifact. It is a **dedup key, not a rewrite**: the caller keeps
the smallest spelling in the group rather than fetching a URL the function
invented. The clean URL is a strict prefix of every mangled one, so "smallest"
picks it whenever it was discovered; when only the mangled spelling exists, that
is what gets opened, unchanged. A path segment genuinely ending in an encoded
backslash is rare but legal, and requesting one directory up from it would be a
request the target never offered.



## What the engine HAS, versus what this engagement could reach

`observability/component_registry.py`.

The contribution ledger measures what each component contributed. It cannot
measure a component that never registers — and until the registry existed,
exactly one call site in the engine declared anything (LLM providers). A vuln
class that never dispatched, a route discoverer that never ran and a tool the
resolver never found all produced the same artifact: **nothing at all**,
indistinguishable from never having been built.

### Declaring: three computed domains and one declared one

`declare_all()` runs at engagement start, immediately after `set_active_ledger`,
and declares:

| Source | Domain | Prefix |
|--------|--------|--------|
| Vuln classes | `DISPATCHABLE_TEST_METHODS` — the table the dispatcher itself reads | `methodology:` |
| Route discoverers | `default_discoverers()`, asked for their own `name` | `discoverer:` |
| Tools | every name in `TOOL_CHAINS`, fallbacks included | *(bare binary name)* |
| Static exploit seams | `STATIC_EXPLOIT_COMPONENTS` | *(literal)* |

The first three are **computed**: adding a vuln class, a discoverer or a chain
entry declares it with no edit here. The fourth is the declared half, and it
earns that by a **bidirectional AST assertion** over every string-literal
`name=` at a ledger call site in `src/`:

* `computed − declared` — a new statically-named component nobody declared, which
  the ledger would then only learn about if it happened to run;
* `declared − computed` — an entry that outlived the call site it described,
  which is how a guard rots into documentation of a wish.

A guard with only the first half is what this repo has shipped six times.

### Reachability: a predicate, and a different clock

"Declared and never invoked" has two opposite readings. The component was
reachable and did not run — a defect. Or its precondition was absent — a GraphQL
discoverer on an app with no GraphQL, a SQL class on a target with no
parameterised surface — which is the component working perfectly. Reporting the
second as a defect is how an alarm section stops being read.

So each declaration carries a **predicate key** from a closed vocabulary, and
`reachable_because` is deliberately **not** a string: a free-text reason per
entry is a hand-maintained excuse list. A sentence attached to a predicate
*function* cannot drift the same way, because there is one sentence per
predicate rather than one per component.

The timing is split because it has to be. Existence is knowable at engagement
start — the dispatch table, the discoverer set and the tool chains are static.
Reachability is not: whether the target has a SQL surface is something only Scan
can answer, and the exploit plan does not exist yet. So
`ContributionLedger.resolve_reachability(state)` runs at **report time**, against
an `EngagementReachability` the orchestrator assembles from completed phase
results.

Three states then fall out of one boolean:

| Predicate | Invoked | Rendering |
|-----------|---------|-----------|
| `True` | no | **`BUILT_BUT_NOT_RUN`** — an alarm. Built, reachable this engagement, never ran. |
| `False` | no | NOT APPLICABLE. `component_ledger.unreachable`, carrying the predicate's own sentence. |
| *(any)* | yes | The ledger's ordinary accounting. A predicate would add a second, weaker answer. |

`reachable is None` — never evaluated, which is a direct methodology invocation,
a replay, or a run that stopped before the report — is **not** `False`. It makes
no claim in either direction and never alarms; an observability layer must not
manufacture a defect out of its own absence.

The Markdown renders the unreachable set as a **count with a kind breakdown**,
not a list: every dispatchable class, discoverer and chained tool is declared on
every run, so enumerating the ones a given target had no use for would add dozens
of lines saying nothing happened — and a section a reader learns to skip is where
the one line that matters hides. `report.json` carries the full list with reasons.

### The tool predicate has three different "no"s

A tool that never ran is three distinct situations with three distinct fixes,
and collapsing them is what would make this a permanent false alarm:

* **Nobody asked for its capability.** `nuclei`, `nikto`, `subfinder` are
  deliberately unwired (see `tests/test_tools/test_tool_wiring_decisions.py`), so
  no phase ever reaches for `vulnerability_scanning` or `subdomain_discovery`.
* **It is a declared fallback and the preferred tool answered.** `gobuster`
  behind `ffuf`.
* **It is not available in this execution mode.**

The first needs `ToolResolver.requested_capabilities`, recorded at
`find_tool` / `find_tools` / `find_tools_ranked`. The chain map the predicate
reads is built through `ToolResolver.available_chain()`, which deliberately does
**not** record: a question asked *about* a run must never become part of what the
run did.
