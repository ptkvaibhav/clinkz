# Agentic AI Penetration Testing System (Clinkz)

## What This Is
An autonomous, agentic AI system that performs end-to-end black-box penetration testing. It takes a target scope (IPs/domains) as input and produces a professional pentest report as output, with no human intervention in between.

## Architecture
- **Multi-agent design** using a ReAct (Reasoning + Acting) loop
- **Orchestrator Agent**: high-level strategy, phase transitions (uses Claude Opus sparingly)
- **Phase Agents**: Recon, Crawl, Exploit, Report (use Claude Sonnet for speed)
- **Critic Agent**: validates findings, eliminates false positives before reporting
- **No static knowledge base** — the Exploit Agent performs live web search at runtime to find CVEs, exploit PoCs, and bug bounty writeups for each identified technology

## Tech Stack
- Python 3.12+ with asyncio for concurrency
- LangGraph for agent orchestration (fall back to custom ReAct if too complex)
- **LLM-agnostic design** — all LLM calls go through `src/clinkz/llm/client.py`
- Supported LLM backends (implement in order):
  1. OpenAI API (GPT-4o / GPT-4o-mini) — first implementation, well-documented tool calling
  2. Anthropic API (Claude Sonnet / Opus) — add second
  3. Google Gemini API (Flash / Pro) — add third, has built-in search grounding
  4. Ollama (local models) — add last, for offline/privacy use cases
- LLM provider is set via config: `LLM_PROVIDER=openai` / `anthropic` / `gemini` / `ollama`
- SQLite for engagement state store (upgrade to PostgreSQL later)
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
│   │   ├── orchestrator.py         # Orchestrator agent (phase transitions)
│   │   ├── state.py                # Engagement state store (SQLite)
│   │   ├── llm/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Abstract LLMClient interface
│   │   │   ├── openai_client.py    # OpenAI GPT-4o / GPT-4o-mini
│   │   │   ├── anthropic_client.py # Claude Sonnet / Opus
│   │   │   ├── gemini_client.py    # Gemini Flash / Pro
│   │   │   ├── ollama_client.py    # Local models via Ollama
│   │   │   └── factory.py          # Returns correct client based on config
│   │   ├── agents/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Base agent class with ReAct loop
│   │   │   ├── recon.py            # Reconnaissance agent
│   │   │   ├── crawl.py            # Crawling/fuzzing agent
│   │   │   ├── exploit.py          # Exploitation agent
│   │   │   ├── report.py           # Report generation agent
│   │   │   └── critic.py           # Finding validation agent
│   │   ├── tools/
│   │   │   ├── __init__.py
│   │   │   ├── base.py             # Tool Abstraction Layer (TAL) base class
│   │   │   ├── nmap.py             # Nmap wrapper
│   │   │   ├── ffuf.py             # ffuf wrapper
│   │   │   ├── nuclei.py           # Nuclei wrapper
│   │   │   ├── nikto.py            # Nikto wrapper
│   │   │   ├── sqlmap.py           # sqlmap wrapper
│   │   │   ├── subfinder.py        # Subfinder wrapper
│   │   │   ├── httpx_tool.py       # httpx wrapper
│   │   │   ├── katana.py           # Katana crawler wrapper
│   │   │   ├── whatweb.py          # WhatWeb wrapper
│   │   │   ├── wafw00f.py          # WAF detection wrapper
│   │   │   └── ...                 # Additional tool wrappers
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── scope.py            # Scope/engagement config models
│   │   │   ├── finding.py          # Vulnerability finding model
│   │   │   ├── target.py           # Target/host/service models
│   │   │   └── report.py           # Report data models
│   │   ├── research/
│   │   │   ├── __init__.py
│   │   │   └── runtime_research.py # Live web search for CVEs, exploits, writeups
│   │   └── reporting/
│   │       ├── __init__.py
│   │       ├── generator.py        # Multi-pass report generation
│   │       ├── renderer.py         # PDF/HTML/JSON rendering
│   │       └── templates/          # Jinja2 report templates
│   │           ├── report.html
│   │           └── styles.css
├── docker/
│   ├── Dockerfile.tools            # Base image with all security tools
│   └── docker-compose.yml          # Tool containers + test targets
├── tests/
│   ├── __init__.py
│   ├── test_tools/                 # Tool wrapper unit tests
│   ├── test_agents/                # Agent logic tests
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
- `docker compose -f docker/docker-compose.yml up -d`: Start test targets (Juice Shop, DVWA)
- `ruff check src/`: Lint
- `ruff format src/`: Format

## Code Style
- Python 3.12+, use type hints everywhere
- Use Pydantic v2 models for all data structures (scope, findings, targets, reports)
- Use async/await for tool execution and LLM calls
- Use structured logging (Python logging module with JSON formatter)
- Docstrings on all public functions and classes
- Follow Google Python Style Guide

## Key Design Decisions
- **LLM-agnostic**: All LLM calls go through `llm/base.py` (abstract class). Never import openai/anthropic/etc directly in agent code. Use `llm/factory.py` to get the right client based on config.
- The LLMClient interface exposes: `reason(messages, tools) -> AgentAction`, `research(query) -> str`, `generate_text(prompt) -> str`
- Every tool wrapper inherits from `tools/base.py` and implements: `get_schema()`, `validate_input()`, `execute()`, `parse_output()`
- Tool wrappers return Pydantic models, never raw strings
- The agent loop is: Observe → Reason (LLM call) → Act (tool call) → Reflect (evaluate result)
- All LLM calls go through a single client wrapper that handles retries, logging, and token tracking
- Scope enforcement: every tool wrapper validates target IPs/domains against the scope before execution
- Runtime research: when new tech is identified, Exploit Agent searches the web for CVEs and exploit techniques before attacking

## Important Rules
- NEVER import a specific LLM SDK (openai, anthropic, google.genai, ollama) outside of the llm/ directory. All agent code uses the abstract LLMClient only.
- NEVER hardcode API keys. Use environment variables via python-dotenv
- NEVER scan targets outside the defined scope. Every tool wrapper must check scope
- All tool outputs must be parsed into structured Pydantic models before the agent reasons over them
- Test tool wrappers against real tool output (save sample outputs in tests/fixtures/)
- Keep agent system prompts in separate files under src/clinkz/agents/prompts/ for easy iteration
