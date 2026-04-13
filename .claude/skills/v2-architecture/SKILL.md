---
name: v2-architecture
description: "Load v2 architecture context — deterministic steps, LLM checkpoints, persistent KB, tool fallback chains, concurrent execution"
---
Read CLINKZ_V2_IMPLEMENTATION.md for full v2 architecture specification.

Key patterns:
- Agents use deterministic steps with LLM reasoning at checkpoints
- Persistent KB (clinkz_knowledge.db) with 3-tier playbook
- Tool fallback chains via TOOL_CHAINS in resolver
- Concurrent execution: Scan + Research + Exploit in parallel
- Post-engagement: record technique success/failure to KB
- LLM assignment: Gemini Flash (Recon/Scan/Report), Claude Opus (Exploit/Research)
