---
name: prime
description: "Auto-load full project context — architecture, current branch state, recent changes, and active phase. Use at session start to avoid re-explaining context."
---

Load project context for this Claude Code session:

1. Read CLAUDE.md (architecture, rules, code style)
2. Read CLINKZ_V2_IMPLEMENTATION.md (v2 spec, phases, agent flows)
3. Run: git branch --show-current
4. Run: git log --oneline -5 (recent commits)
5. Run: git diff --stat HEAD~3 (what changed recently)
6. Run: pytest tests/ -q --tb=no 2>&1 | tail -5 (current test health)
7. Run: find src/clinkz/agents/ -name "*.py" -not -name "__init__*" | sort
   (which agents exist)
8. Check which phase we're in by reading recent commit messages for
   "feat(v2):" patterns

Report a brief status:
- Current branch
- Last 3 changes
- Test suite health (pass/fail count)
- Which v2 agents are implemented (check for _v1.py vs .py files)
- Current implementation phase based on commit history

Do NOT make any changes. This is read-only context loading.
