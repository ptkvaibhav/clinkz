# Clinkz Architecture

## Overview

Clinkz is an autonomous, agentic AI system for black-box penetration testing.
It takes a scope definition as input and produces a professional pentest report as output
with no human intervention during the test itself.

## Agent Pipeline

```
Orchestrator (GPT-4o / Claude Opus)
    │
    ├─→ ReconAgent     (subfinder, nmap, httpx, whatweb, wafw00f)
    │       │ discovers hosts, ports, services, technologies
    │       ▼
    ├─→ CrawlAgent     (katana, ffuf)
    │       │ discovers endpoints, directories, parameters
    │       ▼
    ├─→ ExploitAgent   (nuclei, sqlmap, nikto + runtime research)
    │       │ confirms vulnerabilities, collects evidence
    │       ▼
    ├─→ CriticAgent    (LLM-only, no tools)
    │       │ validates findings, removes false positives
    │       ▼
    └─→ ReportAgent    (LLM-only + WeasyPrint)
            │ writes report, renders HTML/PDF
```

## ReAct Loop

Each phase agent runs an observe → reason → act → reflect loop:

```
Observe  →  LLM receives context (scope, prior findings, current state)
   ↓
Reason   →  LLM decides which tool to call (or returns final answer)
   ↓
Act      →  ToolBase.validate_input() → execute() → parse_output()
   ↓
Reflect  →  Tool result added to conversation history
   ↓
[repeat until LLM returns final_answer]
```

## LLM Abstraction Layer

All LLM calls go through `src/clinkz/llm/base.py`:

```python
class LLMClient(ABC):
    async def reason(messages, tools) -> AgentAction   # tool calling
    async def research(query) -> str                    # web-grounded research
    async def generate_text(prompt) -> str              # plain generation
```

The factory (`llm/factory.py`) returns the right implementation based on `LLM_PROVIDER`.
Agent code **never** imports openai/anthropic/etc. directly.

## Tool Abstraction Layer

Every tool inherits from `ToolBase` and implements four methods:

| Method           | Purpose                                         |
|------------------|-------------------------------------------------|
| `get_schema()`   | OpenAI-compatible function schema for LLM       |
| `validate_input` | Validate args + check scope enforcement         |
| `execute()`      | Run subprocess, return raw stdout               |
| `parse_output()` | Convert raw output to Pydantic model            |

## Scope Enforcement

`EngagementScope.contains(target)` is called inside every tool's `validate_input()`.
If a target is out of scope, a `ValueError` is raised before any network activity occurs.

## State Store

SQLite database (`clinkz.db`) tracks:

| Table        | Purpose                                      |
|--------------|----------------------------------------------|
| engagements  | Engagement metadata and status               |
| targets      | Discovered hosts (Host models as JSON)       |
| findings     | Vulnerabilities (Finding models as JSON)     |
| actions      | Every tool invocation with inputs/outputs    |
| attempts     | Retry tracking for failed tool calls         |

## Data Flow

```
scope.json (input)
    │
    ▼
StateStore.create_engagement()
    │
    ├─→ ReconAgent → StateStore.upsert_target()
    ├─→ ExploitAgent → StateStore.add_finding()
    ├─→ CriticAgent → StateStore.mark_finding_validated()
    └─→ ReportAgent → PentestReport → ReportRenderer → report.html / report.pdf
```
