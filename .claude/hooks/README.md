# Enforcement hooks

Guards that encode failures which **actually happened**, not hypotheticals.

| Guard | Blocks | Why |
|---|---|---|
| `outputs_guard.py` | any path under `outputs/` (even `git add -f`) | 44 run artifacts once reached a public repo and needed a full history rewrite to purge |
| `secret_guard.py` | credential shapes (`sk-ant-…`, `AKIA…`, `gh[pousr]_…`, PRIVATE KEY blocks) and `.env` files | prevent secret leakage |
| `gates.py` | `ruff check` / `ruff format --check` failures on `src/ tests/` (when code is staged) | PR #84 went red in CI on a format miss a local `ruff check` alone missed |
| `context_budget.py` | an always-loaded instruction file over its character budget, or a domain member with no tier | `CLAUDE.md` reached 152,205 chars against a ~150k load limit that truncates **silently** — the gate discipline and the NEVER rules were the last 3,120 characters, i.e. first to be cut |

## Five layers — and which of them can be bypassed

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

2. **Git pre-commit hook** — `.githooks/pre-commit` runs all four guards on
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

4. **CI `metadata-leak-guard` job** — `.github/workflows/metadata-leak-guard.yml`,
   running [`.github/scripts/metadata_leak_guard.py`](../../.github/scripts/metadata_leak_guard.py).
   The other three layers all inspect the **tree**; a PR title, a PR body and a
   commit message are not files, so none of them was ever *capable* of catching a
   `Claude-Session:` trailer or a `claude.ai/code/session` link. That gap class is
   the finding, not any one URL. Fires on `opened, edited, reopened, synchronize`
   — `edited` included deliberately, since a body that opens clean can be edited
   dirty afterwards.

   The job **watches itself fail** before it is trusted: a self-test step feeds the
   detector seeded leaks (and clean text, so a match-everything regex cannot pass
   by being useless), and a second step runs the real entry point against a seeded
   body and requires exit 1. Exit codes are `0` clean · `1` leak · `2` the guard
   could not run — never 1 for a crash, or breakage would read as an alarm.
   Findings name `<source>:<line>` and redact the identifier: a session URL echoed
   into a public Actions log is the same disclosure the guard exists to prevent.

5. **CI `context-budget` job** — `.github/workflows/ci.yml`, running
   [`context_budget.py`](context_budget.py). The fail-closed half of the
   instruction-file bound. The other guards here protect the repository from what
   a commit *adds*; this one protects the agent's own instructions from what they
   *become*. `CLAUDE.md` grew to 152,205 characters against a ~150k load limit
   whose failure mode is a silent cut — so the first symptom would have been rules
   quietly not in effect, with nothing in the transcript naming which. **A bound
   that degrades quietly is not a bound.**

   Two properties earn it a job rather than a step: it needs no install (pure
   stdlib, so it stays fast and reports independently, like `leak-guard`), and it
   must run on **doc-only PRs**, which are exactly the PRs that grow an
   instruction file and exactly the ones CLAUDE.md lets skip gates 1–2.

   Its domain is **computed** — every tracked `CLAUDE.md` in the tree, so a new
   always-loaded file cannot silently escape the budget — while only the tier
   CLASSIFICATION is hand-maintained, and a domain member with no tier **fails**
   rather than being skipped (the guard-domain law, CLAUDE.md invariant 67). It
   measures decoded, newline-normalised **characters**, not bytes: at the split
   `wc -c` said 155,526 where the loader saw 152,205, a 2.2% gap in the direction
   that flatters the file.

   Locally the pre-commit hook runs it with `--staged`, measuring the index rather
   than the working tree — measuring the tree there would let a staged-but-unsaved
   edit through.

Never bypass a layer with `--no-verify` (forbidden by CLAUDE.md's pre-push gates).
Fix the root cause instead. Regression coverage for the first three and the fifth lives in
[`tests/test_hooks/test_commit_guards.py`](../../tests/test_hooks/test_commit_guards.py);
the fourth carries its own self-test, run as a step of the job it guards.
