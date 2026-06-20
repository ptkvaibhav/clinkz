<p align="center">
  <img src="assets/clinkz-banner.svg" alt="Clinkz — Autonomous AI-Driven Penetration Testing Framework" width="100%"/>
</p>

# Clinkz

**Autonomous AI penetration testing system powered by multi-agent collaboration.**

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/ptkvaibhav/clinkz/actions/workflows/ci.yml/badge.svg)

## Overview

Clinkz is an autonomous, multi-agent AI system that performs end-to-end black-box penetration testing. Give it a target scope and it produces a professional pentest report — no human intervention required.

Agents collaborate in real-time through an LLM-mediated Orchestrator, dynamically discovering and executing security tools as needed. The system follows the MITRE ATT&CK framework and OWASP WSTG methodology to ensure comprehensive coverage.

## Architecture

```
                         ┌──────────────────┐
                         │   Orchestrator   │
                         │  (Central Brain) │
                         └────────┬─────────┘
                                  │
        Recon (sequential) ──► Scan + Research + Exploit (concurrent) ──► Report
              │                    │         │           │
              ▼                    ▼         ▼           ▼
        ┌─────────────────────────────────────────────────────┐
        │                  Tool Resolver                      │
        │      MCP Servers   │   Local CLI (with fallback)    │
        └─────────────────────────────────────────────────────┘
                                  │
                ┌─────────────────┴────────────────┐
                ▼                                  ▼
       Engagement state                 Persistent KB
       (clinkz.db)                      (clinkz_knowledge.db,
                                         cross-engagement)
```

**How it works:**

1. The **Orchestrator** validates scope and runs **Recon** sequentially
2. **Scan**, **Research**, and **Exploit** then run **concurrently**, sharing SQLite state. Exploit's only hard dependency is Scan — it starts as soon as Scan completes and never waits for Research (Research's runbook is folded in only if it has already finished)
3. **Recon** discovers subdomains, ports, services, and tech stack
4. **Scan** crawls + fuzzes every HTTP service and enumerates non-HTTP services (FTP/SSH/SMB/DB). For single-page apps it adds **SPA/API route discovery** (`agents/_route_discovery.py`: static JS-bundle parsing + OpenAPI probing behind a pluggable discoverer seam) to recover `/api`+`/rest` routes — with their param structure — that an HTML/JS crawl can't see. Crawl-safety skips links that mutate the target (WAF/security toggles, logout) so the shared session is never poisoned for later phases
5. **Research** queries the persistent KB for known techniques and live-searches the web for new CVEs/writeups (Gemini 3.1 Flash-Lite with native Search Grounding), under a hard wall-clock budget, persisting results back to the KB
6. **Exploit** plans tests with an LLM and executes deterministic `_test_*` skills (all are adaptive multi-phase methodologies — the injection family spans SQLi, NoSQL, SSTI, XSS, CMDi, LFI, …)
7. **Critic** validates findings; **Report** emits JSON + Markdown

Phase agents follow **deterministic step sequences with LLM checkpoints** (no free-form ReAct). Every technique result is recorded to the persistent KB so future engagements adapt.

## Features

- **Concurrent multi-agent execution** — Scan, Research, and Exploit run in parallel through an LLM-mediated orchestrator
- **Deterministic skills + LLM checkpoints** — Each `_test_*` is a contract: if the vuln is present it MUST be found; LLMs only step in at named planning/synthesis points
- **Adaptive methodologies** — every `_test_*` is a multi-phase methodology: the injection family (SQLi, NoSQL, SSTI, XSS, CMDi, LFI, …) maps → fingerprints (SQL dialect / NoSQL carrier / template engine / shell) → ranks → LLM-synthesizes → verifies; SSTI sends polyglot arithmetic probes and is read-back aware for second-order Pug; CMDi candidacy uses a reflection-guarded echo-canary probe so injection surfaces even when the base command writes only to stderr
- **Session hygiene** — recon/scan map the target without changing it; WAF/security toggles and logout links are never followed, so injection payloads aren't silently WAF-blocked in the exploit phase
- **Cross-engagement learning** — Persistent knowledge base (`clinkz_knowledge.db`) records every technique success/failure; future engagements adapt
- **Dynamic tool discovery + fallback chains** — Agents request capabilities (`web_crawling`, `directory_fuzzing`, ...); the resolver walks declared `TOOL_CHAINS` until output meets threshold
- **Runtime CVE research** — Research Agent live-searches CVEs, bug-bounty writeups, and PoCs per identified technology
- **Credential chaining** — Discovered credentials are stored and reused across agents for authenticated testing
- **Resilient LLM client** — Per-agent provider chains (Anthropic / Gemini / OpenAI) with automatic rotation on rate-limit/timeout
- **MCP protocol support** — Connect external tool servers via the Model Context Protocol
- **Execution traces** — Every engagement writes `outputs/<id>/trace.jsonl` with tool calls, LLM calls, and methodology phases; inspect via `clinkz trace inspect <id>`

## Quick Start

### Prerequisites

- Python 3.12+
- Docker (for sandboxed tool execution and test targets)
- An API key for at least one LLM provider (OpenAI, Anthropic, or Google Gemini)

### Installation

```bash
git clone https://github.com/ptkvaibhav/clinkz.git
cd clinkz
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Configuration

Copy the example environment file and fill in your API keys:

```bash
cp .env.example .env
```

At minimum, set `ANTHROPIC_API_KEY` **and** `GEMINI_API_KEY` — the resilient client rotates between them on rate-limit / timeout. Edit `.env` for full options (see [Configuration](#configuration-1) below).

### Docker Setup

Clinkz runs every security tool inside the `clinkz-tools` container by default (`TOOL_EXEC_MODE=docker`). Build the tools image and start the test targets in one go:

```bash
docker compose -f docker/docker-compose.yml up -d
```

This brings up:

- `clinkz-tools` — the sandboxed tool container (nmap, nuclei, ffuf, sqlmap, ...)
- `clinkz-dvwa` on `http://localhost:8080`
- `clinkz-juiceshop` on `http://localhost:3000`

### Running a Scan

```bash
# Full autonomous pentest against a local DVWA
clinkz scan --target http://localhost:8080

# Override the orchestrator LLM provider for a single run
clinkz scan --target http://localhost:8080 --provider anthropic

# Inspect the execution trace afterwards
clinkz trace inspect <engagement_id>
```

> Note: `recon`, `crawl`, `exploit`, and `report` subcommands exist for future per-phase invocation but are still TODO. Use `scan` for the full pipeline.

## Configuration

All configuration is via environment variables in `.env`. The defaults below are the values produced by `Settings.from_env()` in `src/clinkz/config.py`.

### LLM providers and models

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | Legacy global provider: `openai`, `anthropic`, `gemini`, `ollama` | `openai` |
| `LLM_PROVIDER_DEFAULT` | Default for any agent without an explicit override | `gemini` |
| `LLM_PROVIDER_RECON` | Recon agent provider | `gemini` |
| `LLM_PROVIDER_SCAN` | Scan agent provider | `gemini` |
| `LLM_PROVIDER_REPORT` | Report agent provider | `gemini` |
| `LLM_PROVIDER_EXPLOIT` | Exploit agent provider | `anthropic` |
| `LLM_PROVIDER_RESEARCH` | Research agent provider | `gemini` |
| `ORCHESTRATOR_MODEL` | Model for the Orchestrator agent | `gpt-4o` |
| `AGENT_MODEL` | Model for phase agents (when provider is OpenAI) | `gpt-4o-mini` |
| `ANTHROPIC_MODEL` | Claude model name | `claude-sonnet-4-6` |
| `GEMINI_MODEL` | Gemini model for Recon / Scan / Report (GA; never the `-preview` variant) | `gemini-3.1-flash-lite` |
| `GEMINI_EXPLOIT_MODEL` | Gemini model used when Exploit falls back to Gemini | `gemini-3.1-flash-lite` |
| `GEMINI_RESEARCH_MODEL` | Gemini model for Research (GA; never the `-preview` variant) | `gemini-3.1-flash-lite` |
| `GEMINI_MAX_RPM` | Per-client Gemini requests/minute ceiling (Tier-1 sized) | `30` |
| `RESEARCH_TIME_BUDGET` | Hard wall-clock budget (seconds) for the Research phase | `180` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | Provider API keys | — |
| `GOOGLE_API_KEY` | Legacy alias for `GEMINI_API_KEY` | — |
| `OLLAMA_BASE_URL` | Ollama server URL (Ollama client is currently a stub) | `http://localhost:11434` |
| `LLM_MAX_RETRIES` | Per-provider retry budget before falling over to the next provider | `3` |
| `LLM_RETRY_BASE_DELAY` | Initial exponential backoff delay (seconds) | `2.0` |
| `LLM_RETRY_MAX_DELAY` | Cap on exponential backoff (seconds) | `30.0` |

### Tool execution + state

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PATH` | Per-engagement SQLite database path | `clinkz.db` |
| `TOOL_TIMEOUT` | Tool execution timeout (seconds) | `300` |
| `TOOL_EXEC_MODE` | `docker` (sandboxed) or `local` (host binaries — footgun: namesake binaries can match) | `docker` |
| `DOCKER_CONTAINER` | Docker container name for sandboxed execution | `clinkz-tools` |
| `MCP_SERVERS` | JSON list of MCP server commands or URLs | `[]` |

The cross-engagement persistent KB lives at `clinkz_knowledge.db` (path is fixed today; planned to become configurable).

## Supported Tools

| Tool | Capability | Type |
|------|-----------|------|
| Nmap | Port scanning & service detection | Local CLI / Docker |
| Subfinder | Subdomain enumeration | Local CLI / Docker |
| httpx | HTTP probing & tech detection | Local CLI / Docker |
| WhatWeb | Web technology fingerprinting | Local CLI / Docker |
| wafw00f | WAF detection | Local CLI / Docker |
| Katana | Web crawling | Local CLI / Docker |
| ffuf | Directory & parameter fuzzing | Local CLI / Docker |
| Nuclei | Vulnerability scanning | Local CLI / Docker |
| Nikto | Web server scanning | Local CLI / Docker |
| sqlmap | SQL injection testing | Local CLI / Docker |
| HTTP Client | Custom HTTP requests | Built-in (aiohttp) |
| WebAuthenticator | Default-credential testing (cookie/form + JSON/bearer API auth) | Built-in |
| MCP Servers | Any MCP-compatible tool | MCP Protocol (stdio / HTTP / SSE) |

Tools are discovered dynamically at runtime via `ToolResolver.find_tool(capability=...)` — agents never hardcode tool names. Each capability (e.g. `web_crawling`, `directory_fuzzing`, `port_scanning`) declares a ranked fallback chain in `tools/resolver.py::TOOL_CHAINS`; the resolver walks the chain until a tool is available. Host binary identity is verified at startup (`tools/binary_identity.py`) so a namesake on `$PATH` cannot impersonate a real tool.

## Agents

| Agent | Default LLM | Role |
|-------|-------------|------|
| **Orchestrator** | Anthropic (resilient fallback) | Central coordinator — Recon → concurrent (Scan + Research + Exploit) → Report |
| **Recon** | Gemini Flash | Port scan → service/version → web recon → tech stack |
| **Scan** | Gemini Flash | Crawl + fuzz HTTP, enumerate FTP/SSH/SMB/DB; coverage checkpoint via fallback chains |
| **Research** | Gemini 3.1 Flash-Lite (Search Grounding) | Cross-engagement KB lookup + live web search; rate-limit-aware with a wall-clock budget; persists techniques back to `clinkz_knowledge.db` |
| **Exploit** | Anthropic Claude | LLM plans tests; deterministic `_test_*` skills execute; 16 adaptive multi-phase methodologies (injection family: SQLi, NoSQL, SSTI, …) |
| **Critic** | (LLM-only) | Validates findings, checks CVSS, eliminates false positives |
| **Report** | (no LLM today) | Pulls findings from state store, emits JSON + Markdown |

## Report Output

The current report agent emits:

- `report_<engagement_id>.json` — structured findings (title, severity, CVSS, endpoint, request/response evidence, remediation)
- `report_<engagement_id>.md` — human-readable summary

Each engagement also produces `outputs/<engagement_id>/trace.jsonl` for post-mortem inspection.

Output formats today: **JSON**, **Markdown**. The HTML/PDF Jinja+WeasyPrint pipeline described in earlier plans is on the W3 horizon.

## Testing

```bash
# Run all unit / agent / tool / orchestrator tests (skips live integration + DVWA suites)
pytest tests/ -q --tb=short --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop --ignore=tests/test_integration

# Run integration suite (requires DVWA + tools containers up)
pytest tests/test_integration/

# Run live DVWA skill smoke suite (requires DVWA at http://localhost:8080)
pytest tests/test_skills_dvwa/ -m dvwa_smoke

# Run a single test module
pytest tests/test_tools/test_nmap.py -v
```

The full suite is ~750 tests as of W2.1. API-key-gated tests skip cleanly when no keys are present.

## Project Structure

```
clinkz/
├── src/clinkz/
│   ├── agents/          # Phase agents (recon v2, scan v2, exploit v2, research v2, critic, report)
│   │   └── prompts/     # Agent system prompts (.md per agent)
│   ├── comms/           # Message bus + communication protocol
│   ├── credentials/     # CredentialStore for default-credential chaining
│   ├── knowledge/       # MITRE ATT&CK + OWASP WSTG/API/LLM datasets,
│   │                    # persistent_kb (cross-engagement), seed_playbook (Tier 1)
│   ├── llm/             # LLM abstraction (Anthropic, Gemini, OpenAI, Ollama) + ResilientLLMClient
│   ├── models/          # Pydantic v2 models (scope, target, recon, scan, methodology,
│   │                    # research, finding, report)
│   ├── observability/   # Per-engagement JSONL execution trace
│   ├── orchestrator/    # OrchestratorAgent + AgentLifecycleManager
│   ├── research/        # Runtime web search for CVEs / writeups
│   └── tools/           # ToolBase + ToolResolver (capability + fallback chains),
│                        # binary_identity, docker_preflight, MCP client, individual wrappers
├── scripts/             # Demo / live integration helpers
├── tests/               # Unit, agent, comms, credentials, knowledge, llm,
│                        # orchestrator, integration, skills_dvwa, skills_juiceshop
├── docker/              # Dockerfile.tools + Dockerfile.dvwa + docker-compose.yml
└── docs/                # architecture, adding-tools, playbooks, analysis/*
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to add new tools or agents.

## License

[MIT](LICENSE)

## Disclaimer

**Clinkz is intended for authorized security testing only.** Always obtain explicit written permission before testing any system. Unauthorized use of this tool against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.
