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

The section renders when the plan **fit**, too: "no class was truncated" is a
claim, and a run that fit inside its cap and a run whose truncation nobody
recorded must not produce identical artifacts.

Absent by default, like the governor, the ledger and the scope-refusal log. A
directly invoked methodology, a replay or a driver installs no register, every
hook no-ops, and the black-box floor is byte-identical. The per-class endpoint
list is capped at 20; **the counts stay exact past the cap**, because a truncated
record of a truncation is the failure the module exists to prevent.
