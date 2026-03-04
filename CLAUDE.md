# Clinkz — Agentic AI Penetration Testing System

## What This Is
An autonomous, multi-agent AI system that performs end-to-end black-box penetration testing. It takes a target scope (IPs/domains) as input and produces a professional pentest report as output, with no human intervention in between. Agents collaborate in real-time through an LLM-mediated Orchestrator, dynamically discovering and executing tools as needed.

## Core Architecture: LLM-Mediated Multi-Agent System

### The Orchestrator Pattern
All inter-agent communication flows through a central **Orchestrator Agent**. No agent talks directly to another. The Orchestrator:
- Receives the engagement scope and defines the mission
- Spins up phase agents dynamically as needed
- Routes messages between agents (e.g., Exploit Agent asks for more recon → Orchestrator sends task to Recon Agent → routes result back)
- Monitors progress and decides when phases are complete
- Shuts down agents when their work is done
- Can spin agents back up if a later phase needs them (e.g., re-activating Recon Agent because Exploit Agent found a new subdomain)
- Triggers the Report Agent when exploitation is complete
- Maintains the global engagement context that all agents contribute to

### Agent Lifecycle
Agents are **not** all running from the start. The Orchestrator spins them up on demand:
1. Engagement starts → Orchestrator spins up **Recon Agent**
2. Recon completes → Orchestrator reviews findings, spins up **Scan Agent**
3. Scan completes → Orchestrator reviews, spins up **Exploit Agent**
4. Exploit Agent needs more recon → Orchestrator re-spins **Recon Agent** for targeted task
5. Recon responds → Orchestrator routes result back to **Exploit Agent**
6. Exploitation complete → Orchestrator spins up **Report Agent**
7. Report done → Orchestrator delivers final output, shuts everything down

This is NOT a linear pipeline. The Orchestrator can spin up any agent at any time based on what's happening. Multiple agents CAN run concurrently if the Orchestrator decides that's optimal.

### Message Format
All agent communication uses a standard message envelope:
```python
class AgentMessage(BaseModel):
    id: str                          # Unique message ID
    from_agent: str                  # Sender ("orchestrator", "recon", "scan", etc.)
    to_agent: str                    # Recipient
    message_type: str                # "task", "result", "query", "response", "status"
    content: dict                    # Payload (task details, findings, questions, etc.)
    engagement_id: str               # Links to engagement
    parent_message_id: str | None    # For request/response correlation
    timestamp: datetime
```

### Agent Communication Flow Example
```
Exploit Agent → Orchestrator: "I found subdomain api-internal.target.com in a
    response header. I need it enumerated before I can test it."
Orchestrator (LLM reasons): "This is a recon task. Recon Agent is not running.
    I'll spin it up with a targeted task."
Orchestrator → Recon Agent: "Enumerate api-internal.target.com — ports, services,
    tech stack. Report back."
Recon Agent (runs tools, completes): → Orchestrator: "Here are the results:
    3 open ports, nginx 1.24, Node.js API backend."
Orchestrator → Exploit Agent: "Recon complete for api-internal.target.com.
    Here are the findings: [data]"
Exploit Agent continues exploitation with new intel.
```

## Agents

### Orchestrator Agent
- **Role**: Central coordinator and message router
- **LLM**: Uses the most capable model (Opus/o3) for strategic reasoning
- **Has access to**: Full engagement state, all agent messages, engagement scope
- **Decides**: Which agents to spin up/down, how to route messages, when engagement is complete
- **Does NOT**: Execute tools directly. It delegates ALL tool work to phase agents.

### Recon Agent
- **Role**: Reconnaissance and information gathering specialist
- **Goal**: Given a target, discover as much as possible — subdomains, services, tech stack, OSINT, leaked credentials, organizational intelligence
- **Tool discovery**: Researches what tools it needs at runtime. Checks for MCP servers first, falls back to local CLI tools.
- **Can be spun up multiple times**: Once for initial recon, again later if another agent discovers new targets

### Scan Agent
- **Role**: Crawling, fuzzing, and attack surface mapping
- **Goal**: Given recon results, map every endpoint, parameter, and input vector. Identify suspicious behaviors and anomalies.
- **Tool discovery**: Same as Recon — researches and picks tools dynamically
- **Communicates back**: Can ask Orchestrator to task Recon Agent for additional enumeration if it finds new targets during crawling

### Exploit Agent
- **Role**: Exploitation specialist
- **Goal**: Given scan results and attack surface map, research exploits for the identified technologies, attempt exploitation, validate findings, chain exploits for maximum impact
- **Runtime research**: Searches the web for CVEs, bug bounty writeups, PoC exploits specific to each identified technology
- **Communicates back**: Frequently asks Orchestrator to task Recon/Scan agents for additional intel

### Report Agent
- **Role**: Report generation specialist
- **Goal**: Transform all engagement data into a professional pentest report
- **Multi-pass**: Assembles data → generates narrative → synthesizes remediation → quality review → renders PDF/HTML/JSON
- **Can query other agents**: If a finding needs clarification or additional evidence, asks via Orchestrator

### Critic Agent
- **Role**: Quality assurance — validates findings before they enter the report
- **Reviews**: CVSS scoring accuracy, false positive elimination, evidence completeness, reproduction steps
- **Can reject findings**: Sends them back to Exploit Agent for re-validation via Orchestrator

## Tool Execution: Dynamic Discovery

### How Agents Find and Use Tools
Agents do NOT have hardcoded tool lists. When an agent needs to perform an action:

1. **LLM Reasoning**: The agent's LLM decides what capability it needs (e.g., "I need to scan ports on this host")
2. **Tool Research**: The agent checks what's available:
   a. Query the Tool Resolver for locally installed tools matching the need
   b. Check for available MCP servers that provide the capability
   c. If nothing found, use LLM web search to research what tool would work and how to use it
3. **Execution**:
   a. If MCP server available → connect as MCP client and call the tool
   b. If local CLI tool available → execute via subprocess, parse output using existing parsers
   c. If neither → agent reports to Orchestrator that it lacks the capability

### Tool Resolver (src/clinkz/tools/resolver.py)
Central component that agents query to find tools:
- Maintains a registry of locally installed tools (our existing ToolBase wrappers)
- Discovers running MCP servers on known endpoints
- Returns tool availability and connection method (mcp / local / unavailable)
- Agents call resolver.find_tool(capability="port_scanning") not resolver.get("nmap")

### Existing Tool Wrappers
The existing ToolBase parsers (nmap, subfinder, httpx, etc.) serve as the local execution backend. They are NOT thrown away — they become one execution path that the Tool Resolver can offer.

## Tech Stack
- Python 3.12+ with asyncio for concurrency
- **LLM-agnostic design** — all LLM calls go through `src/clinkz/llm/client.py`
- Supported LLM backends (implement in order):
  1. OpenAI API (GPT-4o / GPT-4o-mini) — first implementation
  2. Anthropic API (Claude Sonnet / Opus) — add second
  3. Google Gemini API (Flash / Pro) — add third
  4. Ollama (local models) — add last, for offline/privacy use cases
- LLM provider is set via config: `LLM_PROVIDER=openai` / `anthropic` / `gemini` / `ollama`
- MCP Python SDK (`mcp[cli]`) for tool server/client protocol
- SQLite for engagement state store + message store (upgrade to PostgreSQL later)
- Docker for sandboxed tool execution
- WeasyPrint + Jinja2 for PDF/HTML report rendering
- Typer for CLI interface

## Project Structure
```
clinkz/
├── CLAUDE.md
├── pyproject.toml
├── README.md
├── src/
│   ├── clinkz/
│   │   ├── __init__.py
│   │   ├── cli.py                  # Typer CLI entry point
│   │   ├── config.py               # Scope config, API keys, settings
│   │   ├── state.py                # Engagement state store + message store (SQLite)
│   │   │
│   │   ├── orchestrator/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py     # Orchestrator Agent — the central brain
│   │   │   ├── lifecycle.py        # Agent lifecycle manager (spin up/down)
│   │   │   ├── router.py           # Message routing logic
│   │   │   └── prompts/
│   │   │       └── orchestrator_system.md
│   │   │
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Base agent class with message handling + ReAct loop
│   │   │   ├── recon.py            # Reconnaissance agent
│   │   │   ├── scan.py             # Scanning/crawling/fuzzing agent
│   │   │   ├── exploit.py          # Exploitation agent
│   │   │   ├── report.py           # Report generation agent
│   │   │   ├── critic.py           # Finding validation agent
│   │   │   └── prompts/
│   │   │       ├── recon_system.md
│   │   │       ├── scan_system.md
│   │   │       ├── exploit_system.md
│   │   │       ├── report_system.md
│   │   │       └── critic_system.md
│   │   │
│   │   ├── comms/
│   │   │   ├── __init__.py
│   │   │   ├── message.py          # AgentMessage model + message types
│   │   │   ├── bus.py              # Message bus (async queue-based, Orchestrator-mediated)
│   │   │   └── protocol.py         # Communication protocol definitions
│   │   │
│   │   ├── llm/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract LLMClient interface
│   │   │   ├── openai_client.py    # OpenAI GPT-4o / GPT-4o-mini
│   │   │   ├── anthropic_client.py # Claude Sonnet / Opus (stub)
│   │   │   ├── gemini_client.py    # Gemini Flash / Pro (stub)
│   │   │   ├── ollama_client.py    # Local models via Ollama (stub)
│   │   │   └── factory.py          # Returns correct client based on config
│   │   │
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # ToolBase ABC (local CLI tool wrapper)
│   │   │   ├── resolver.py         # Tool Resolver — finds tools by capability
│   │   │   ├── mcp_client.py       # MCP client for connecting to MCP tool servers
│   │   │   ├── nmap.py             # Nmap wrapper (local)
│   │   │   ├── ffuf.py             # ffuf wrapper (local)
│   │   │   ├── nuclei.py           # Nuclei wrapper (local)
│   │   │   ├── nikto.py            # Nikto wrapper (local)
│   │   │   ├── sqlmap.py           # sqlmap wrapper (local)
│   │   │   ├── subfinder.py        # Subfinder wrapper (local)
│   │   │   ├── httpx_tool.py       # httpx wrapper (local)
│   │   │   ├── katana.py           # Katana crawler wrapper (local)
│   │   │   ├── whatweb.py          # WhatWeb wrapper (local)
│   │   │   ├── wafw00f.py          # WAF detection wrapper (local)
│   │   │   └── ...                 # Additional tool wrappers
│   │   │
│   │   ├── research/
│   │   │   ├── __init__.py
│   │   │   └── runtime_research.py # Live web search for CVEs, exploits, writeups
│   │   │
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── scope.py            # Scope/engagement config models
│   │   │   ├── finding.py          # Vulnerability finding model
│   │   │   ├── target.py           # Target/host/service models
│   │   │   └── report.py           # Report data models
│   │   │
│   │   └── reporting/
│   │       ├── __init__.py
│   │       ├── generator.py        # Multi-pass report generation
│   │       ├── renderer.py         # PDF/HTML/JSON rendering
│   │       └── templates/
│   │           ├── report.html
│   │           └── styles.css
│   │
├── docker/
│   ├── Dockerfile.tools
│   └── docker-compose.yml
├── tests/
│   ├── __init__.py
│   ├── test_tools/                 # Tool wrapper unit tests
│   ├── test_agents/                # Agent logic tests
│   ├── test_comms/                 # Communication layer tests
│   ├── test_orchestrator/          # Orchestrator tests
│   └── test_integration/           # End-to-end integration tests
└── docs/
    ├── architecture.md
    └── adding-tools.md
```

## Commands
- `python -m clinkz scan --target <domain> --scope <scope.json>`: Run full pentest
- `python -m clinkz recon --target <domain>`: Run only recon phase
- `pytest tests/`: Run all tests
- `pytest tests/test_tools/test_nmap.py -v`: Run single tool test
- `docker compose -f docker/docker-compose.yml up -d`: Start test targets
- `ruff check src/`: Lint
- `ruff format src/`: Format

## Code Style
- Python 3.12+, use type hints everywhere
- Use Pydantic v2 models for all data structures
- Use async/await for all agent execution, tool calls, and LLM calls
- Use structured logging (Python logging module with JSON formatter)
- Docstrings on all public functions and classes
- Follow Google Python Style Guide

## Key Design Decisions
- **LLM-mediated comms**: Agents NEVER talk directly to each other. All messages go through the Orchestrator. The Orchestrator LLM decides how to route.
- **Dynamic lifecycle**: Agents are spun up and shut down by the Orchestrator as needed. An agent can be re-activated if a later phase needs it.
- **Dynamic tool discovery**: Agents research what tools they need at runtime. They use the Tool Resolver to check MCP servers first, then local CLI tools. No hardcoded tool lists in agent code.
- **LLM-agnostic**: All LLM calls go through `llm/base.py`. Never import openai/anthropic/etc directly in agent code.
- **Existing parsers preserved**: The ToolBase wrappers and their parse_output() implementations are the local execution backend. They are called by the Tool Resolver when an agent needs a locally installed tool.
- Tool wrappers return Pydantic models, never raw strings
- The agent ReAct loop is: Observe → Reason (LLM) → Act (tool/message) → Reflect (evaluate)
- All LLM calls go through a single client wrapper that handles retries, logging, and token tracking
- Scope enforcement: every tool execution validates targets against scope before running

## Important Rules
- NEVER import a specific LLM SDK outside of the llm/ directory
- NEVER hardcode API keys. Use environment variables via python-dotenv
- NEVER scan targets outside the defined scope
- NEVER have agents communicate directly — all comms go through Orchestrator
- NEVER hardcode tool names in agent code — agents describe capabilities they need, the Tool Resolver finds the right tool
- All tool outputs must be parsed into structured Pydantic models
- Test tool wrappers against real tool output (save sample outputs in tests/fixtures/)
- Keep agent system prompts in separate .md files under prompts/ directories
- Always push to origin after committing