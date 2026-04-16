---
name: architecture-compact
description: "Minimal architecture reference that survives context compaction — key rules and patterns only"
---

CLINKZ V2 CRITICAL RULES (compact-safe reference):

Architecture: Deterministic agent steps + LLM reasoning at checkpoints.
NOT free-form ReAct loops.

Agent flow: Recon (sequential) → Scan + Research + Exploit (concurrent) → Report

Key rules:
- Tool calls through ToolResolver, never direct imports
- LLM calls through self.llm, never direct SDK imports
- No direct agent-to-agent communication, everything via Orchestrator
- All data models are Pydantic v2, all methods async
- _test_* methods are deterministic contracts — if vuln present, MUST find it
- Record all technique results to persistent KB after exploitation
- Tool fallback chains: try ranked alternatives if primary tool insufficient

Per-agent LLM: Gemini Flash (Recon/Scan/Report), Claude Opus (Exploit/Research)

DB: clinkz_knowledge.db (persistent KB), engagement state store (per-run)
3-tier playbook: Tier 1 universal, Tier 2 tech-matched, Tier 3 experimental

Test baseline: DVWA 14/14 categories through full pipeline
