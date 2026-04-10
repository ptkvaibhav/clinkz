---
name: integrate-pipeline
description: "Wires completed agents into the Orchestrator, connects shared state and persistent KB, runs integration tests"
allowedTools:
  - Read
  - Bash
  - Write
  - Grep
  - Glob
---
You integrate completed agents into the Clinkz Orchestrator.

Read CLINKZ_V2_IMPLEMENTATION.md for the Orchestrator flow and concurrent model.
Read CLAUDE.md for lifecycle and communication rules.

Rules:
- Orchestrator controls all agent lifecycle.
- No direct agent-to-agent calls.
- Recon sequential -> Scan + Research + Exploit concurrent -> Report sequential.
- Persistent KB instantiated at engagement start, passed to agents.
- After recon, query KB for matching Tier 1+2+3 playbook entries.
- If downstream agents expect old format, add adapter — don't change new agent.
- Integration tests in tests/test_integration/.

The user specifies which agent to integrate: $ARGUMENTS
