---
name: phase-work
description: "Load Clinkz v2 development rules of engagement. Invoke at the start of any phase-implementation or fix task."
---

You are doing phase work on Clinkz v2. These rules apply to every task under
this skill unless the user overrides explicitly.

## Foundation reading (always)

- CLAUDE.md — architecture, rules, code style
- CLINKZ_V2_IMPLEMENTATION.md — v2 spec, phases, agent flows

## Architecture rules (non-negotiable)

- Deterministic agent steps + LLM reasoning at checkpoints. Never free-form ReAct.
- Tool calls go through ToolResolver. Never direct tool imports.
- LLM calls go through self.llm. Never direct SDK imports.
- Agents never talk to each other directly. Everything routes through the Orchestrator.
- All data models are Pydantic v2. All methods async. Structured logging at each step.
- _test_* methods are deterministic contracts. If the vuln is present and the method runs, it MUST find it.
- Record technique results to persistent KB after exploitation.
- Tool fallback chains: try ranked alternatives when the primary is insufficient.
- Per-agent LLM: Gemini Flash for Recon/Scan/Report, Claude Opus for Exploit/Research.

## Scope discipline

- Stay inside the scope of the task. Do not refactor adjacent code.
- If you find a bug outside scope, note it and keep going. We fix things in order.
- Do not change the orchestrator flow unless the task says to.
- Do not add or remove files outside the task's explicit scope.
- Do not modify .claude/ files unless the task is about Claude Code infrastructure.

## Verification before commit (always)

1. pytest tests/ -q --tb=short — 0 failures required. Skips are OK if API keys missing.
2. ruff check src/ — 0 errors.
3. ruff format src/ — no changes produced on a clean diff.
4. If the task added tests, they must be in the correct tests/ subdirectory.
5. If the task changed a Pydantic model, search for all consumers and verify they still work.

## Commit format

- Prefix: feat, fix, chore, refactor, test, docs
- Scope in parens when applicable: feat(v2), fix(exploit), chore(claude-code)
- Imperative mood, no period at the end
- One-line summary, blank line, bullet list of what changed if multi-part
- Examples:
  - "feat(v2): deterministic recon agent with LLM checkpoints"
  - "fix(exploit): coerce chaining_opportunities to list[dict] format"

## Push after commit

Always push to origin after committing. Never leave work uncommitted or unpushed at the end of a task.

## If blocked

- Don't invent solutions to missing data. Ask.
- Don't mark something "done" if verification failed.
- If a test fails for reasons unrelated to your change, investigate — don't skip.
