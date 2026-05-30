---
name: phase-work
description: "Load Clinkz v2 development rules of engagement for any phase-implementation or fix task."
---

Read CLAUDE.md and CLINKZ_V2_IMPLEMENTATION.md for full architecture context. The rules below are the operating discipline; CLAUDE.md is the source of truth for architecture.

## Stop and ask — do not guess

This is the most important rule. Most failures on this project came from acting on an unchecked assumption.

- If a requirement is ambiguous, stop and ask. Do not pick an interpretation and run.
- If you discover the task's premise is wrong (the bug isn't where stated, the file doesn't contain what's claimed), stop and report it before doing the work. Do not silently "fix" what you assume was meant.
- Surface inconsistencies and tradeoffs instead of resolving them unilaterally.
- If two files or instructions conflict, flag the conflict — don't pick a side silently.
- Never fabricate file contents, test results, or tool output. Report what is actually there.

## Architecture rules (non-negotiable — see CLAUDE.md)

- Deterministic agent steps + LLM reasoning at named checkpoints. Never free-form ReAct.
- Tool calls go through ToolResolver.find_tool(capability=...). Never direct tool imports, never resolver.get("nmap").
- LLM calls go through the agent's client. Never import openai/anthropic/gemini SDKs outside llm/.
- Agents never talk to each other directly — everything routes through the Orchestrator.
- All data models Pydantic v2. All methods async. Structured logging at step boundaries.
- _test_* methods are contracts: if the vuln is present, the method MUST find it. All 14 are adaptive methodologies.
- Record every technique result (hit or miss) to the persistent KB.
- Per-agent LLM: Gemini for Recon/Scan/Report, Anthropic for Exploit/Research (Exploit pinned, no fallback for methodology checkpoints).

## Testing — real targets gate, not mocks

- A mocked unit test passing does NOT mean the pipeline works. We were burned repeatedly by green unit tests over a broken pipeline.
- Any change to a tool wrapper, agent step, or orchestration path requires a pipeline_smoke or integration test against a real container that would have caught the regression. Mocked unit tests alone are insufficient as the gate.
- When fixing a bug, first add the test that reproduces it, then fix until it passes.

## Scope discipline

- Stay inside the task. Don't refactor adjacent code or remove comments/code you don't understand.
- If you find a bug outside scope, note it as a followup and keep going.
- Don't modify .claude/ unless the task is explicitly Claude Code infrastructure.
- Don't overcomplicate. Prefer the simplest correct construction. If you've written 500 lines, ask whether 50 would do.

## Execution discipline

- Run commands synchronously in the foreground. Never spawn background scripts (.ps1/.sh wrappers, nohup, &, Start-Job) and poll them.
- Never use echo/sleep loops as timers or progress spinners.
- Commit and push are direct foreground commands: git commit then git push. No wrapper scripts.

## Pre-push verification (the three gates from CLAUDE.md)

Before every push, all three must pass. Never bypass with --no-verify, blanket # noqa / # type: ignore, or skip/xfail added solely to keep CI green.

1. Lint: ruff check src/ tests/ and ruff format --check src/ tests/.
2. Tests: pytest tests/ -q --tb=short for unit/agent/tool/orchestrator. Run integration + dvwa_smoke suites when DVWA is up and the change touches scan/exploit/orchestrator.
3. Security review: invoke /security-review on the diff when it touches tools/, scope, credentials, LLM I/O, HTTP/network/subprocess, deserialization, user-path file I/O, MCP, or report rendering. Resolve every finding.

Doc/config-only changes may skip gates 1-2 but gate 3 still applies if runtime behavior can change.

## Commit format

prefix(scope): imperative summary, no trailing period. Push after every commit.
