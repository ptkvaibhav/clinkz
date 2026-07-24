---
description: Prep a PR for external grading — branch fetch, diff vs main, changed src, CI re-derivation, artifacts to attach.
argument-hint: [PR# | branch]
---
Prepare the current branch (or `$ARGUMENTS`) for external grading. This does NOT
grade — it assembles what a grader needs. Report each section.

1. **Fresh state**: `git fetch origin --prune`, then confirm the branch and its
   base: `git rev-parse --abbrev-ref HEAD` and `git log --oneline origin/main..HEAD`.
2. **Diff stat vs main**: `git diff --stat origin/main...HEAD`.
3. **Changed src files**: `git diff --name-only origin/main...HEAD -- src/`
   (and note tests: `git diff --name-only origin/main...HEAD -- tests/`).
4. **Re-derive CI**: run `/gates` (the three gates as ci.yml runs them) and
   report the three exit codes.
5. **Raw artifacts to attach**: list the `outputs/<id>/` run artifacts this
   branch's validation produced (use `/artifacts <id>` per run). They are
   local-only and must be **attached** to the grading submission, not committed —
   print the absolute paths so the operator can attach them.

Output a checklist the operator can hand to a grader.
