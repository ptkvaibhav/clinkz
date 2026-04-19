---
name: prime
description: "Load project context at session start. SessionStart hook already shows git/test status — this loads architecture and current phase."
---

Session context (branch, tests, commits) was shown at session start by the
SessionStart hook. Don't re-run those commands.

Load the following and summarize briefly:
1. Read CLAUDE.md (architecture, rules, code style)
2. Read CLINKZ_V2_IMPLEMENTATION.md (v2 spec, phases, agent flows)
3. Based on recent commit messages (visible from session start), identify
   which phase we're in and what was last completed.

Report:
- Current phase
- Last completed step
- Any open issues from the last session (uncommitted changes, failing tests
  flagged in the session-start output)
- What's likely next

This replaces repeated "Read CLAUDE.md and CLINKZ_V2_IMPLEMENTATION.md" in
every user prompt.
