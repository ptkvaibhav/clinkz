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

All v2 phase agents follow the **deterministic-steps-with-LLM-checkpoints** pattern: a fixed sequence of tool calls and code, with the LLM invoked only at named reasoning checkpoints (planning, classification, synthesis). No free-form ReAct.

### Orchestrator Agent
- **Role**: Central coordinator and message router
- **Default LLM**: Anthropic (Claude) for strategic reasoning, with a resilient fallback to Gemini and OpenAI
- **Phase shape**: Recon (sequential) → **Scan + Research + Exploit run concurrently** sharing SQLite state → Report (sequential)
- **Cross-phase re-spins**: Capped at `MAX_CROSS_PHASE_RESPINS = 3` per engagement
- **Does NOT**: Execute tools directly — delegates all tool work to phase agents.

### Recon Agent (v2)
- **LLM**: Gemini Flash (per-agent override `LLM_PROVIDER_RECON=gemini`)
- **Steps**: Full TCP port scan → LLM analyzes ports → service/version detection → LLM extracts tech stack → web-specific recon → LLM synthesizes summary → structured `ReconResult`
- **Tool discovery**: Always via `ToolResolver.find_tool(capability=...)` — never direct imports

### Scan Agent (v2)
- **LLM**: Gemini Flash
- **Steps**: LLM plans scan strategy → service-specific methods (HTTP / FTP / SSH / SMB / DB) → LLM reviews each tool output → LLM checks coverage sufficiency → expand via fallback chain if insufficient → structured `ScanResult`
- **Fallback chains**: `katana → gospider → hakrawler` for crawling; `ffuf → gobuster → feroxbuster` for fuzzing (declared in `tools/resolver.py::TOOL_CHAINS`)

### Research Agent (v2)
- **LLM**: Anthropic (Claude Opus)
- **Runs concurrently** with Scan and Exploit
- **Steps**: Query persistent KB for tech → web-search new vulns (CVEs, writeups) → LLM synthesizes techniques → query related techs → LLM adapts past techniques → persist to engagement runbook AND `clinkz_knowledge.db`
- **Mid-engagement hook**: `research_additional()` for techs Scan discovers later

### Exploit Agent (v2)
- **LLM**: Anthropic (Claude Opus) — pinned by `LLM_PROVIDER_EXPLOIT=anthropic`
- **Steps**: LLM plans exploits from scan + research data → execute deterministic `_test_*` methods by tier → LLM reasons through results → adaptive retry/bypass → record technique success/failure to persistent KB
- **Adaptive methodologies (W2.1)**: All 14 `_test_*` methods are now adaptive multi-phase methodologies, not deterministic one-shot skills. The payload-injection family (`_test_xss_reflected`, `_test_xss_stored`, `_test_xss_dom`, `_test_sqli`, `_test_cmdi`, `_test_lfi`, `_test_file_upload`, `_test_idor`, `_test_open_redirect`, `_test_javascript_attacks`) uses the six-phase reflection/fingerprint/synthesize/verify pattern with LLM-driven payload synthesis. The behavioral family (`_test_csrf`, `_test_brute_force`, `_test_weak_session`, `_test_security_headers`) uses the four-phase hypothesis/observe/analyze/emit pattern.
- **Tier 2/3**: `_test_tier2_technique` / `_test_tier3_technique` consume Research Agent runbook entries

### Critic Agent
- **Role**: Quality assurance — validates findings before they enter the report
- **Reviews**: CVSS scoring accuracy, false positive elimination, evidence completeness, reproduction steps
- **Can reject findings**: Sends them back to Exploit Agent for re-validation via Orchestrator

### Report Agent
- **LLM**: Zero LLM calls today — pulls findings from the state store and emits structured JSON + a Markdown summary in <30 s. (The LLM-driven multi-pass narrative described in earlier plans is on the W3 horizon.)

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
- **LLM-agnostic design** — all LLM calls go through `src/clinkz/llm/base.py`
- Supported LLM backends:
  1. Anthropic API (Claude Sonnet / Opus) — primary for Exploit + Research agents
  2. Google Gemini API (Flash / Pro) — primary for Recon / Scan / Report agents
  3. OpenAI API (GPT-4o / GPT-4o-mini) — third in the resilient fallback chain
  4. Ollama (local models) — stub, not yet wired into the fallback chain
- LLM provider is set via config: `LLM_PROVIDER=openai` / `anthropic` / `gemini` / `ollama`
- Per-agent provider overrides via `LLM_PROVIDER_<AGENT>` (e.g. `LLM_PROVIDER_EXPLOIT=anthropic`)
- Resilient client (`llm/fallback.py`) automatically rotates providers on rate-limit/timeout
- MCP Python SDK (`mcp[cli]`) for tool server/client protocol
- SQLite — `clinkz.db` for per-engagement state, `clinkz_knowledge.db` for the cross-engagement persistent KB
- Docker for sandboxed tool execution (`clinkz-tools` container; preflight in `tools/docker_preflight.py`)
- Report agent emits JSON + Markdown directly (no Jinja/WeasyPrint pipeline today)
- Typer for CLI interface; `clinkz trace inspect <engagement>` renders execution traces

## Project Structure
```
clinkz/
├── CLAUDE.md
├── CLINKZ_V2_IMPLEMENTATION.md
├── README.md
├── pyproject.toml
├── src/
│   ├── clinkz/
│   │   ├── __init__.py
│   │   ├── __main__.py             # python -m clinkz entry point
│   │   ├── cli.py                  # Typer CLI (scan / recon / crawl / exploit / report / trace)
│   │   ├── config.py               # Settings (env vars, per-agent LLM overrides)
│   │   ├── state.py                # Engagement state store + message store (SQLite)
│   │   │
│   │   ├── orchestrator/
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py     # OrchestratorAgent — sequential Recon → concurrent (Scan + Research + Exploit) → Report
│   │   │   ├── lifecycle.py        # AgentLifecycleManager (spin up/down, re-spin tracking)
│   │   │   └── prompts/orchestrator_system.md
│   │   │
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # BaseAgent — message bus integration + LLM hookup
│   │   │   ├── recon.py            # Recon v2 — deterministic steps + LLM checkpoints
│   │   │   ├── scan.py             # Scan v2  — service-specific methods + fallback chains
│   │   │   ├── crawl.py            # Crawl agent stub (TODO — currently inert)
│   │   │   ├── exploit.py          # Exploit v2 — LLM plans, deterministic _test_* execute, adaptive XSS/SQLi methodologies
│   │   │   ├── research.py         # Research v2 — persistent KB + cross-engagement learning
│   │   │   ├── critic.py           # Finding validation
│   │   │   ├── report.py           # Report agent — emits JSON + Markdown (zero LLM)
│   │   │   └── prompts/            # System prompts (recon, scan, exploit, research, critic, report)
│   │   │
│   │   ├── comms/
│   │   │   ├── __init__.py
│   │   │   ├── message.py          # AgentMessage model + message types
│   │   │   ├── bus.py              # Async message bus (Orchestrator-mediated)
│   │   │   └── protocol.py         # Communication protocol constants
│   │   │
│   │   ├── credentials/
│   │   │   └── store.py            # CredentialStore + default credential database
│   │   │
│   │   ├── knowledge/
│   │   │   ├── __init__.py
│   │   │   ├── query.py            # KnowledgeBase — MITRE ATT&CK + OWASP WSTG/API/LLM queries
│   │   │   ├── persistent_kb.py    # PersistentKnowledgeBase — clinkz_knowledge.db (cross-engagement)
│   │   │   ├── seed_playbook.py    # Tier 1 universal-test seeder
│   │   │   ├── payload_loader.py   # Payload list loader
│   │   │   ├── skills_loader.py    # OWASP WSTG skill snippet loader
│   │   │   ├── mitre_attack.json   # MITRE ATT&CK enterprise dataset
│   │   │   ├── owasp_wstg.json     # OWASP WSTG v4.2 dataset
│   │   │   ├── owasp_api.json      # OWASP API Top 10 (2023)
│   │   │   ├── owasp_llm.json      # OWASP LLM Top 10
│   │   │   ├── payloads.json       # Curated payload lists per vuln class
│   │   │   └── skills/             # Reusable skill snippets (xss_*, sqli_*, wstg_*, ...)
│   │   │
│   │   ├── llm/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract LLMClient interface
│   │   │   ├── factory.py          # Returns correct client per provider/agent
│   │   │   ├── fallback.py         # ResilientLLMClient — per-agent fallback chains
│   │   │   ├── openai_client.py    # OpenAI GPT-4o / GPT-4o-mini
│   │   │   ├── anthropic_client.py # Claude Sonnet / Opus
│   │   │   ├── gemini_client.py    # Gemini Flash / Pro
│   │   │   └── ollama_client.py    # Stub (not yet in fallback chain)
│   │   │
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # ToolBase ABC + ToolOutput
│   │   │   ├── resolver.py         # ToolResolver — capability lookup + ranked fallback chains
│   │   │   ├── mcp_client.py       # MCP client (stdio + HTTP/SSE)
│   │   │   ├── installer.py        # Binary availability checker
│   │   │   ├── binary_identity.py  # Verifies host binary identity (catches namesake imposters)
│   │   │   ├── docker_preflight.py # Ensures clinkz-tools container is up before tool execution
│   │   │   ├── http_client.py      # Built-in HTTP client tool
│   │   │   ├── auth.py             # WebAuthenticator — default-credential testing
│   │   │   ├── nmap.py / subfinder.py / httpx_tool.py / whatweb.py / wafw00f.py
│   │   │   ├── katana.py / ffuf.py / nuclei.py / nikto.py / sqlmap.py
│   │   │
│   │   ├── research/
│   │   │   └── runtime_research.py # Live web search for CVEs, exploits, writeups
│   │   │
│   │   ├── observability/
│   │   │   └── trace.py            # Per-engagement JSONL execution trace
│   │   │
│   │   └── models/
│   │       ├── scope.py            # EngagementScope, ScopeEntry, ScopeType
│   │       ├── target.py           # Host / Service models
│   │       ├── recon.py            # Recon v2 result models
│   │       ├── scan.py             # Scan v2 result models (HTTP/FTP/SSH/SMB/DB)
│   │       ├── methodology.py      # Adaptive XSS/SQLi intermediate-result models
│   │       ├── research.py         # Research v2 result models
│   │       ├── finding.py          # Finding, ExploitPlan, ExploitTask, ExploitResult
│   │       └── report.py           # PentestReport, ExecutiveSummary
│   │
├── docker/
│   ├── Dockerfile.tools
│   ├── Dockerfile.dvwa
│   ├── docker-compose.yml
│   └── dvwa-init.sh
├── scripts/                        # Demo / live integration helpers
│   ├── live_full_pipeline.py
│   ├── test_auth_chain.py
│   └── test_dvwa_exploit_direct.py
├── tests/
│   ├── conftest.py
│   ├── fixtures/                   # Real tool output samples
│   ├── test_tools/                 # Tool wrapper unit tests (incl. resolver chains, binary identity, docker preflight)
│   ├── test_agents/                # Agent logic tests (recon_v2, scan_v2, exploit_v2, research_v2, methodology_xss/sqli, ...)
│   ├── test_comms/                 # Message bus + protocol
│   ├── test_credentials/           # CredentialStore tests
│   ├── test_knowledge/             # query.py, persistent_kb.py, payload_loader.py
│   ├── test_llm/                   # Per-provider client tests + resilient fallback
│   ├── test_orchestrator/          # Orchestrator + lifecycle
│   ├── test_integration/           # End-to-end (DVWA pipeline, recon→exploit flow, concurrent agents)
│   ├── test_skills_dvwa/           # Live DVWA skill smoke suite (marker: dvwa_smoke)
│   ├── test_skills_juiceshop/      # Live Juice Shop skill smoke suite (marker: juiceshop_smoke)
│   └── test_state.py
└── docs/
    ├── architecture.md
    ├── adding-tools.md
    ├── playbooks.md
    └── analysis/                   # Threat model, data flow, control flow, semantic review, dependencies
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
- **Deterministic agent steps + LLM checkpoints**: Phase agents follow fixed step sequences with the LLM invoked only at named reasoning checkpoints. No free-form ReAct loops in v2.
- **LLM-mediated comms**: Agents NEVER talk directly to each other. All messages go through the Orchestrator.
- **Dynamic lifecycle**: Agents are spun up and shut down by the Orchestrator as needed. An agent can be re-activated if a later phase needs it (capped at `MAX_CROSS_PHASE_RESPINS`).
- **Dynamic tool discovery**: Agents call `ToolResolver.find_tool(capability=...)` — never `resolver.get("nmap")`. Resolver checks MCP servers first, then local CLI tools, then walks declared `TOOL_CHAINS` fallback orders.
- **LLM-agnostic + per-agent providers**: All LLM calls go through `llm/base.py`. Never import openai/anthropic/etc directly in agent code. Each agent has a default provider (`recon/scan/report=gemini`, `exploit/research=anthropic`) overridable via `LLM_PROVIDER_<AGENT>`.
- **Resilient client**: `llm/fallback.py::ResilientLLMClient` rotates providers automatically on rate-limit / timeout, with per-provider retry budgets (`LLM_MAX_RETRIES`).
- **Deterministic skills as contracts**: `_test_*` methods are contracts — if the vulnerability is present, the method MUST find it. Adaptive methodologies (XSS-reflected, SQLi) layer LLM-driven synthesis on top of deterministic phases.
- **Persistent KB feedback loop**: Every technique result (success or miss) is recorded to `clinkz_knowledge.db` so future engagements adapt.
- **Existing parsers preserved**: The ToolBase wrappers and their `parse_output()` implementations remain the local execution backend.
- Tool wrappers return Pydantic models, never raw strings
- Scope enforcement: every tool execution validates targets against scope before running
- **Execution traces**: Each engagement writes `outputs/<engagement_id>/trace.jsonl` capturing tool calls, LLM calls, agent steps, data handoffs, and methodology-phase events. Inspect with `clinkz trace inspect <engagement_id>`.

## Pre-Push Verification
Every change must pass three gates before `git push`. If a gate fails, fix the root cause — never bypass with `--no-verify`, blanket `# noqa`/`# type: ignore`, or skip/xfail added solely to keep CI green.

1. **Lint** — `ruff check src/ tests/` and `ruff format --check src/ tests/`. Use `ruff format src/ tests/` to auto-format. All warnings must be resolved or explicitly justified inline.
2. **Audit (tests)** — `pytest tests/ -q --tb=short --ignore=tests/test_skills_dvwa --ignore=tests/test_integration` for unit/agent/tool/orchestrator tests on every change. Run the integration and DVWA skill suites (`pytest tests/test_integration/` and `pytest tests/test_skills_dvwa/ -m dvwa_smoke`) when DVWA is up and the change touches scan/exploit/orchestrator paths.
3. **Security review** — Invoke the `security-review` skill (`/security-review`) on the diff whenever the change touches: tool execution (`src/clinkz/tools/`), scope enforcement, credential handling/storage, LLM input/output, HTTP/network/subprocess calls, deserialization, file I/O on user-controlled paths, MCP server interactions, or report rendering. Resolve every finding before pushing — never ship command/SQL injection, unsafe deserialization, secret leakage, hardcoded credentials, SSRF, path traversal, or scope-bypass code paths.

Doc/config-only changes (no `.py` modified) may skip gates 1–2, but gate 3 still applies if the change can affect runtime behavior (new permission, new tool entry, new hook, new payload list, etc.).

## Important Rules
- NEVER import a specific LLM SDK outside of the llm/ directory
- NEVER hardcode API keys. Use environment variables via python-dotenv
- NEVER scan targets outside the defined scope
- NEVER have agents communicate directly — all comms go through Orchestrator
- NEVER hardcode tool names in agent code — agents describe capabilities they need, the Tool Resolver finds the right tool
- All tool outputs must be parsed into structured Pydantic models
- Test tool wrappers against real tool output (save sample outputs in tests/fixtures/)
- Keep agent system prompts in separate .md files under prompts/ directories
- Run the **Pre-Push Verification** gates above before every `git push`
- Always push to origin after committing (and after pre-push verification passes)

