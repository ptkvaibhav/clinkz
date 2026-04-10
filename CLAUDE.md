# Clinkz — Agentic AI Penetration Testing System

## What This Is
An autonomous, multi-agent AI system that performs end-to-end black-box penetration testing. It takes a target scope (IPs/domains) as input and produces a professional pentest report as output, with no human intervention in between. Agents use **deterministic execution steps with LLM reasoning at checkpoints** — code controls what tests run and in what order, while the LLM analyzes responses, crafts context-aware bypasses, and makes strategic decisions.

## Core Architecture: Deterministic Steps + LLM Checkpoints

### The Pattern
Unlike free-form ReAct loops, Clinkz v2 uses a hybrid approach:
- **Deterministic steps**: Code defines what tools run, what tests execute, and in what order. Each agent has explicit `_step_*` or `_test_*` methods.
- **LLM checkpoints**: At defined points, the LLM analyzes tool output, plans next actions, extracts intelligence, and reasons through results. The LLM never controls the execution loop directly.
- **Persistent Knowledge Base** (`clinkz_knowledge.db`): A separate SQLite database that persists across engagements. Contains a 3-tier unified test plan:
  - **Tier 1 (Universal)**: Run on EVERY engagement — port scan, crawl, fuzz, OWASP Top 10 checks
  - **Tier 2 (Technology-matched)**: Run when tech fingerprint matches (e.g., "Apache 2.4.x → test CVE-2019-0211")
  - **Tier 3 (Experimental)**: New techniques from Research Agent, kept if successful
- **Tool fallback chains**: Every capability has a ranked list of tools via `ToolResolver`. If the first tool's output is insufficient, the next in the chain is tried automatically.
- **Post-engagement learning**: Technique success/failure is recorded to the persistent KB after every engagement, informing future tests.

### The Orchestrator
All inter-agent communication flows through a central **Orchestrator Agent**. No agent talks directly to another. The Orchestrator:
- Receives the engagement scope and defines the mission
- Controls agent lifecycle (spin up/down)
- Routes messages between agents
- Manages concurrent execution phases
- Triggers post-engagement KB commits

### Concurrent Execution Model
```
Recon (sequential) → Default Credential Check → Scan + Research + Exploit (concurrent) → Report (sequential)
```
- **Recon** runs first, sequentially — must complete before anything else starts
- **Scan**, **Research**, and **Exploit** run concurrently, sharing state through the engagement DB
- **Report** runs last, sequentially, after all concurrent agents complete

### Agent Lifecycle
1. Engagement starts → Orchestrator parses scope, enforces boundaries
2. Orchestrator spins up **Recon Agent** (sequential) → waits for completion
3. Default credential check via **WebAuthenticator** (deterministic)
4. Orchestrator starts **Scan + Research + Exploit** agents concurrently
5. Orchestrator monitors completion → stops all when done
6. Orchestrator spins up **Report Agent** (sequential)
7. Post-engagement: commit technique results to persistent KB

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

## Agents

### Orchestrator Agent
- **Role**: Central coordinator and message router
- **LLM**: Uses the most capable model for strategic reasoning
- **Has access to**: Full engagement state, all agent messages, engagement scope
- **Decides**: Which agents to spin up/down, how to route messages, when engagement is complete
- **Does NOT**: Execute tools directly. It delegates ALL tool work to phase agents.

### Recon Agent
- **Role**: Reconnaissance and information gathering specialist
- **Pattern**: 5 deterministic steps with LLM reasoning at checkpoints
  - Step 1: Port scan all ports (TOOL — nmap first, rustscan fallback)
  - Step 2: LLM reviews port scan output (REASONING)
  - Step 3: Service + version scan on open ports (TOOL — nmap -sV -sC)
  - Step 4: LLM reviews, extracts technology list (REASONING)
  - Step 5: Structure output → Orchestrator (CODE)

### Scan Agent
- **Role**: Crawling, fuzzing, and attack surface mapping
- **Pattern**: Tool-driven with LLM supervision and fallback chains
  - Step 1: LLM plans scan strategy based on identified services (PLANNING)
  - Step 2: Service-specific scan methods:
    - HTTP → crawl (katana→gospider fallback) + fuzz (ffuf→gobuster fallback)
    - FTP → enumerate (nmap scripts, manual probe)
    - SSH → version check, auth methods
    - SMB → share listing, null session
    - Database → connection test, default creds
  - Step 3: LLM reviews each tool output, structures into DB (REASONING)
  - Step 4: LLM checkpoint — sufficient coverage? If not → next tool in fallback chain
  - Step 5: Output endpoints + analysis to shared state DB (CODE)

### Research Agent (NEW in v2)
- **Role**: Persistent intelligence brain — cross-engagement knowledge synthesis
- **Pattern**: Concurrent, persistent brain that enriches the engagement
  - Step 1: Query persistent KB for existing knowledge on each technology
  - Step 2: Research NEW vulns via web search (CVEs, HackerOne, blogs, Reddit)
  - Step 3: LLM synthesizes into actionable techniques → runbook entries
  - Step 4: Query related technologies from persistent KB
  - Step 5: LLM adapts past techniques for current target
  - Step 6: Write entries to per-engagement runbook AND persistent playbook
  - Ongoing: As Scan discovers new services/tech → research those too

### Exploit Agent
- **Role**: Exploitation specialist with deterministic test methods
- **Pattern**: LLM plans → deterministic `_test_*` methods execute → LLM reasons through results
  - Step 1: LLM PLANS exploits — reviews scan data + runbook (PLANNING)
  - Step 2: Execute planned exploits via deterministic methods:
    - Tier 1: `_test_*` methods for WSTG coverage (universal)
    - Tier 2: Technology-specific tests from persistent playbook
    - Tier 3: Research Agent techniques from runbook (experimental)
  - Step 3: LLM reasons through results — retry, bypass, adapt (REASONING)
  - Step 4: Results to findings DB (CODE)
  - After: Record technique success/failure to persistent KB

### Report Agent
- **Role**: Report generation specialist
- **Goal**: Pull all findings from DB, generate professional report
- **Output**: For each finding — title, severity, CVSS, endpoint, PoC (request+response), LLM-generated remediation
- **Formats**: JSON + Markdown

### Critic Agent
- **Role**: Quality assurance — validates findings before they enter the report
- **Reviews**: CVSS scoring accuracy, false positive elimination, evidence completeness, reproduction steps
- **Can reject findings**: Sends them back to Exploit Agent for re-validation via Orchestrator

## Tool Execution: Fallback Chains + Dynamic Discovery

### Tool Chains
Every capability has a ranked fallback chain:
```python
TOOL_CHAINS = {
    "web_crawling": ["katana", "gospider", "hakrawler", "zap_spider"],
    "directory_fuzzing": ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    "port_scanning": ["nmap", "masscan", "rustscan"],
    "vulnerability_scanning": ["nuclei", "nikto", "zap_active"],
    "sql_injection_testing": ["sqlmap", "ghauri"],
    "web_fingerprinting": ["whatweb", "wappalyzer", "httpx"],
    "waf_detection": ["wafw00f"],
}
```

### Tool Resolver (src/clinkz/tools/resolver.py)
Central component that agents query to find tools:
- `find_tools_ranked(capability)` → returns tools in preference order, skipping unavailable ones
- `try_until_sufficient(capability, min_results, ...)` → tries each tool in the chain until output meets threshold
- Maintains a registry of locally installed tools (ToolBase wrappers)
- Discovers running MCP servers on known endpoints
- **Tool substitutability principle**: No hard dependency on any single tool. Every capability has alternatives.

### Existing Tool Wrappers
The existing ToolBase parsers (nmap, subfinder, httpx, etc.) serve as the local execution backend. They are called by the Tool Resolver when an agent needs a locally installed tool.

## Tech Stack
- Python 3.12+ with asyncio for concurrency
- **LLM-agnostic design** — all LLM calls go through `src/clinkz/llm/base.py`
- **Per-agent LLM provider selection** via config:
  - Gemini 2.5 Flash — Recon, Scan, and Report agents (fast, cost-effective)
  - Claude Opus — Exploit and Research agents (deep reasoning)
  - LLM provider set via config: `LLM_PROVIDER=gemini` / `anthropic` / `openai` / `ollama`
  - Per-agent override supported
- MCP Python SDK (`mcp[cli]`) for tool server/client protocol
- SQLite for engagement state store + message store
- Separate SQLite DB (`clinkz_knowledge.db`) for persistent knowledge base
- Docker for sandboxed tool execution
- WeasyPrint + Jinja2 for PDF/HTML report rendering
- Typer for CLI interface

## Project Structure
```
clinkz/
├── CLAUDE.md
├── CLINKZ_V2_IMPLEMENTATION.md
├── pyproject.toml
├── README.md
├── .claude/
│   ├── settings.json               # Hooks config (PreCommit: ruff check + format)
│   ├── commands/
│   │   ├── run-dvwa.md             # /project:run-dvwa — full DVWA pipeline test
│   │   ├── test-skill.md           # /project:test-skill <name> — test specific skill
│   │   ├── add-tool.md             # /project:add-tool <name> — scaffold tool wrapper
│   │   └── review-findings.md      # /project:review-findings — review engagement output
│   ├── agents/
│   │   ├── implement-agent.md      # Agent: implement phase agent (v2 pattern)
│   │   ├── implement-kb.md         # Agent: build persistent KB infrastructure
│   │   ├── implement-tools.md      # Agent: create tool wrappers + fallback chains
│   │   ├── integrate-pipeline.md   # Agent: wire agents into Orchestrator
│   │   └── run-engagement.md       # Agent: execute + validate full pipeline
│   └── skills/
│       ├── v2-architecture/
│       │   └── SKILL.md            # Load v2 architecture context
│       ├── wstg-methodology/
│       │   └── SKILL.md            # Load OWASP WSTG methodology context
│       └── tool-patterns/
│           └── SKILL.md            # Load ToolBase wrapper patterns
├── src/
│   ├── clinkz/
│   │   ├── __init__.py
│   │   ├── __main__.py             # python -m clinkz entry point
│   │   ├── cli.py                  # Typer CLI entry point
│   │   ├── config.py               # Scope config, API keys, settings
│   │   ├── state.py                # Engagement state store + message store (SQLite)
│   │   ├── orchestrator.py         # Legacy orchestrator module (thin wrapper)
│   │   │
│   │   ├── orchestrator/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py     # Orchestrator Agent — the central brain
│   │   │   ├── lifecycle.py        # Agent lifecycle manager (spin up/down)
│   │   │   └── prompts/
│   │   │       └── orchestrator_system.md
│   │   │
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Base agent class with deterministic steps + LLM checkpoints
│   │   │   ├── recon.py            # Reconnaissance agent
│   │   │   ├── scan.py             # Scanning/crawling/fuzzing agent
│   │   │   ├── crawl.py            # Crawl agent (Katana/ffuf integration)
│   │   │   ├── exploit.py          # Exploitation agent
│   │   │   ├── research.py         # Research agent (persistent KB integration)
│   │   │   ├── report.py           # Report generation agent
│   │   │   ├── critic.py           # Finding validation agent
│   │   │   └── prompts/
│   │   │       ├── recon_system.md
│   │   │       ├── scan_system.md
│   │   │       ├── exploit_system.md
│   │   │       ├── research_system.md
│   │   │       ├── report_system.md
│   │   │       └── critic_system.md
│   │   │
│   │   ├── comms/
│   │   │   ├── __init__.py
│   │   │   ├── message.py          # AgentMessage model + message types
│   │   │   ├── bus.py              # Message bus (async queue-based, Orchestrator-mediated)
│   │   │   └── protocol.py         # Communication protocol definitions
│   │   │
│   │   ├── credentials/
│   │   │   ├── __init__.py
│   │   │   └── store.py            # Credential store + default credential database
│   │   │
│   │   ├── knowledge/
│   │   │   ├── __init__.py
│   │   │   ├── query.py            # MITRE ATT&CK + OWASP WSTG knowledge base queries
│   │   │   ├── persistent_kb.py    # Cross-engagement persistent knowledge base
│   │   │   └── seed_playbook.py    # Tier 1/2/3 seed data for persistent KB
│   │   │
│   │   ├── llm/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract LLMClient interface
│   │   │   ├── openai_client.py    # OpenAI GPT-4o / GPT-4o-mini
│   │   │   ├── anthropic_client.py # Claude Sonnet / Opus
│   │   │   ├── gemini_client.py    # Gemini Flash / Pro
│   │   │   ├── ollama_client.py    # Local models via Ollama (stub)
│   │   │   └── factory.py          # Returns correct client based on config
│   │   │
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # ToolBase ABC (local CLI tool wrapper)
│   │   │   ├── resolver.py         # Tool Resolver — fallback chains + ranked discovery
│   │   │   ├── mcp_client.py       # MCP client for connecting to MCP tool servers
│   │   │   ├── installer.py        # Tool availability checker and installer
│   │   │   ├── http_client.py      # Built-in HTTP client tool
│   │   │   ├── nmap.py             # Nmap wrapper (local)
│   │   │   ├── ffuf.py             # ffuf wrapper (local)
│   │   │   ├── nuclei.py           # Nuclei wrapper (local)
│   │   │   ├── nikto.py            # Nikto wrapper (local)
│   │   │   ├── sqlmap.py           # sqlmap wrapper (local)
│   │   │   ├── subfinder.py        # Subfinder wrapper (local)
│   │   │   ├── httpx_tool.py       # httpx wrapper (local)
│   │   │   ├── katana.py           # Katana crawler wrapper (local)
│   │   │   ├── whatweb.py          # WhatWeb wrapper (local)
│   │   │   └── wafw00f.py          # WAF detection wrapper (local)
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
├── scripts/
│   └── live_full_pipeline.py       # Demo / example scripts
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
- **Deterministic phases + LLM reasoning at checkpoints**: Code controls what tests run and in what order. LLM analyzes responses and crafts context-aware bypasses. NOT free-form iteration.
- **Behavior-observation-first exploitation**: Observe application behavior before attempting exploits. Payload-list iteration alone is insufficient.
- **Persistent cross-engagement learning**: Technique success/failure recorded to KB. What worked on Apache 2.4 last month informs today's test.
- **Tool substitutability**: Every capability has a ranked fallback chain. No hard dependency on any single tool.
- **LLM-agnostic**: All LLM calls go through `llm/base.py`. Never import openai/anthropic/etc directly in agent code.
- **Existing parsers preserved**: The ToolBase wrappers and their parse_output() implementations are the local execution backend. They are called by the Tool Resolver when an agent needs a locally installed tool.
- Tool wrappers return Pydantic models, never raw strings
- All LLM calls go through a single client wrapper that handles retries, logging, and token tracking
- Scope enforcement: every tool execution validates targets against scope before running

## Important Rules
- NEVER import a specific LLM SDK outside of the llm/ directory
- NEVER hardcode API keys. Use environment variables via python-dotenv
- NEVER scan targets outside the defined scope
- NEVER have agents communicate directly — all comms go through Orchestrator
- NEVER hardcode tool names in agent code — agents describe capabilities they need, the Tool Resolver finds the right tool
- NEVER use free-form LLM loops for exploit execution — use deterministic `_test_*` methods with LLM reasoning at checkpoints only
- ALWAYS record technique results to persistent KB after exploitation
- All tool outputs must be parsed into structured Pydantic models
- Test tool wrappers against real tool output (save sample outputs in tests/fixtures/)
- Keep agent system prompts in separate .md files under prompts/ directories
- Always push to origin after committing
