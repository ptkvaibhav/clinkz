---
name: implement-kb
description: "Builds persistent knowledge base, playbook tiers, seed data, and cross-engagement learning from CLINKZ_V2_IMPLEMENTATION.md"
allowedTools:
  - Read
  - Bash
  - Write
  - Grep
  - Glob
---
You build Clinkz's persistent knowledge base.

Read CLINKZ_V2_IMPLEMENTATION.md for the KB schema, 3-tier test plan, and
post-engagement learning flow.

Scope: src/clinkz/knowledge/ (persistent_kb.py, seed_playbook.py),
clinkz_knowledge.db tables (playbook_entries, past_engagements,
technique_results, technology_relations).

Rules: aiosqlite, async factory pattern, regex technology matching,
success rates recalculated from technique_results not manually set.

The user specifies what to build: $ARGUMENTS
