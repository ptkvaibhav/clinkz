---
name: phase-work
description: "Load Clinkz v2 development rules of engagement for any phase-implementation or fix task."
---

You are doing phase work on Clinkz v2. Read CLAUDE.md and CLINKZ_V2_IMPLEMENTATION.md for full context.

## Architecture rules (non-negotiable)

- Deterministic agent steps + LLM reasoning at checkpoints. Never free-form ReAct.
- Tool calls go through ToolResolver. Never direct tool imports.
- LLM calls go through self.llm. Never direct SDK imports.
- Agents never talk to each other directly. Everything routes through the Orchestrator.
- All data models Pydantic v2. All methods async. Structured logging at step boundaries.
- _test_* methods are deterministic contracts — if the vuln is present, the method MUST find it.
- Record technique results to persistent KB after exploitation.
- Tool fallback chains for every capability.
- Per-agent LLM: Gemini Flash for Recon/Scan/Report, Claude Opus for Exploit/Research.

## Scope discipline

- Stay inside the task. Don't refactor adjacent code.
- If you find a bug outside scope, note it and keep going.
- Don't modify .claude/ unless the task is Claude Code infrastructure.

## Verification before commit

- pytest tests/ -q --tb=short — 0 failures required. API-key-gated skips are OK.
- ruff check src/ — 0 errors.
- ruff format src/ — no changes on a clean diff.

## Commit format

Prefix (feat/fix/chore/refactor/test/docs), optional scope in parens, imperative mood, no trailing period. Examples: "feat(v2): deterministic recon agent with LLM checkpoints" / "fix(exploit): coerce chaining_opportunities to list[dict]"

## Push after every commit

Don't leave work uncommitted or unpushed at task end.
