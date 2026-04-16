---
name: continue-session
description: "Resume work from a previous session — load recent changes, test state, and pick up where we left off"
---

Resume development from the previous session:

1. Run: git log --oneline -10
2. Run: git diff --stat (any uncommitted changes?)
3. Run: git stash list (any stashed work?)
4. Run: pytest tests/ -q --tb=line 2>&1 | tail -20 (current test state)
5. Read the most recent commit message to understand what was last worked on
6. If there are failing tests, list them
7. If there are uncommitted changes, summarize what they affect

Then suggest what to work on next based on:
- Any failing tests that need fixing
- The implementation phase from CLINKZ_V2_IMPLEMENTATION.md
- Uncommitted work that needs to be completed
