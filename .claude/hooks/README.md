# Enforcement hooks

Guards that encode failures which **actually happened**, not hypotheticals.

| Guard | Blocks | Why |
|---|---|---|
| `outputs_guard.py` | any staged path under `outputs/` (even `git add -f`) | 44 run artifacts once reached a public repo and needed a full history rewrite to purge |
| `secret_guard.py` | credential shapes (`sk-ant-…`, `AKIA…`, `gh[pousr]_…`, PRIVATE KEY blocks) and `.env` files | prevent secret leakage |
| `gates.py` | `ruff check` / `ruff format --check` failures on `src/ tests/` (when code is staged) | PR #84 went red in CI on a format miss a local `ruff check` alone missed |

## Two layers (defence in depth)

1. **Git pre-commit hook** — `.githooks/pre-commit` runs all three guards on every
   commit. This is the universal, fail-closed gate (fires for human and agent
   commits alike). Activate it once per clone:

   ```bash
   git config core.hooksPath .githooks
   ```

2. **Claude Code PreToolUse hook** — registered in `.claude/settings.json`,
   `claude_pretooluse.py` runs the `outputs`/`secret` guards before any
   `git commit` the agent issues. It fires regardless of `core.hooksPath` or
   `--no-verify`, closing the exact agent-driven `git add -f outputs/…` path that
   caused the leak. It fails **open** on internal error so a hook bug can never
   brick a session's Bash — the git hook remains the fail-closed backstop.

Never bypass either layer with `--no-verify` (forbidden by CLAUDE.md's pre-push
gates). Fix the root cause instead.
