# Enforcement hooks

Guards that encode failures which **actually happened**, not hypotheticals.

| Guard | Blocks | Why |
|---|---|---|
| `outputs_guard.py` | any path under `outputs/` (even `git add -f`) | 44 run artifacts once reached a public repo and needed a full history rewrite to purge |
| `secret_guard.py` | credential shapes (`sk-ant-…`, `AKIA…`, `gh[pousr]_…`, PRIVATE KEY blocks) and `.env` files | prevent secret leakage |
| `gates.py` | `ruff check` / `ruff format --check` failures on `src/ tests/` (when code is staged) | PR #84 went red in CI on a format miss a local `ruff check` alone missed |

## Three layers — and which of them can be bypassed

Only the last one is fail-closed. State that plainly rather than assuming defence
in depth: the first two were each defeated from a fresh clone (LESSONS #34).

1. **Claude Code PreToolUse hook** — `claude_pretooluse.py`, registered in
   `.claude/settings.json`. Runs the `outputs`/`secret` guards before any
   `git commit` the agent issues, closing the agent-driven `git add -f outputs/…`
   path that caused the leak. Detection is **fail-closed**: a shell segment is
   flagged when it invokes git and an exact `commit` token appears anywhere after
   it. It deliberately does not parse git's global-option run — the previous
   regex did, and missed `git -C <path> commit` and `git -c k=v commit`, because
   those options take a *separate* argument. Execution stays **fail-open** (any
   internal error returns 0) so a hook bug can never brick a session's Bash —
   which is exactly why this layer is a backstop, not a gate. It also only reads
   the index of `-C`'s target or the session's own repo.

2. **Git pre-commit hook** — `.githooks/pre-commit` runs all three guards on
   every commit, for human and agent alike. Activate it **once per clone**:

   ```bash
   python scripts/bootstrap.py
   ```

   `core.hooksPath` is per-clone *local* config: it is never committed, and a
   fresh clone has no `.git/hooks/pre-commit` either. Until the bootstrap runs
   this layer does not exist. `git commit --no-verify` skips it even once it does.
   `/gates` reports `GATE0_hooksPath` so an unprotected clone is immediately
   visible.

3. **CI `leak-guard` job** — `.github/workflows/ci.yml`. **The fail-closed
   layer.** It runs the same two guards server-side in `--tree` mode:

   ```bash
   python3 .claude/hooks/outputs_guard.py --tree HEAD
   python3 .claude/hooks/secret_guard.py --tree HEAD
   ```

   No local config, no `--no-verify`, and no un-bootstrapped clone can skip it.
   `--tree` asserts on the resulting *tree* rather than on a diff, so neither a
   rewritten base ref nor a squashed range can hide an added path. The job shares
   no setup with `lint-and-test` (no package install, no system deps), so it stays
   fast and reports independently.

Never bypass a layer with `--no-verify` (forbidden by CLAUDE.md's pre-push gates).
Fix the root cause instead. Regression coverage for all three lives in
[`tests/test_hooks/test_commit_guards.py`](../../tests/test_hooks/test_commit_guards.py).
