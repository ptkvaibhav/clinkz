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
                         │   Orchestrator    │
                         │  (Central Brain)  │
                         └────────┬─────────┘
                                  │
              ┌───────────┬───────┼───────┬───────────┐
              │           │       │       │           │
        ┌─────┴──┐  ┌────┴──┐ ┌──┴───┐ ┌─┴────┐ ┌───┴────┐
        │ Recon  │  │ Scan  │ │Exploit│ │Critic│ │ Report │
        │ Agent  │  │ Agent │ │ Agent │ │Agent │ │ Agent  │
        └───┬────┘  └───┬───┘ └──┬───┘ └──────┘ └────────┘
            │            │        │
        ┌───┴────────────┴────────┴───┐
        │      Tool Resolver          │
        │  MCP Servers │ Local CLI    │
        └─────────────────────────────┘
```

**How it works:**

1. The **Orchestrator** receives the engagement scope and spins up agents on demand
2. **Recon Agent** discovers subdomains, services, and tech stack
3. **Scan Agent** maps endpoints, parameters, and attack surface
4. **Exploit Agent** researches CVEs in real-time and attempts exploitation
5. **Critic Agent** validates findings, eliminates false positives, scores CVSS
6. **Report Agent** generates a professional pentest report

Agents are not all running from the start — the Orchestrator spins them up and down dynamically. Any agent can request the Orchestrator to re-activate a previous phase agent for additional intelligence.

## Features

- **Multi-Agent Autonomy** — Agents reason, act, and collaborate through an LLM-mediated orchestrator with no human intervention
- **Dynamic Tool Discovery** — Agents describe capabilities they need; the Tool Resolver finds the right tool (MCP server or local CLI)
- **Runtime CVE Research** — Exploit Agent searches the web for CVEs, PoC exploits, and bug bounty writeups specific to discovered technologies
- **Credential Chaining** — Discovered credentials are stored and reused across agents for authenticated testing
- **MITRE ATT&CK + OWASP WSTG** — Built-in knowledge base drives methodology-aware testing
- **MCP Protocol Support** — Connect external tool servers via the Model Context Protocol
- **LLM-Agnostic** — Supports OpenAI, Anthropic, Google Gemini, and Ollama (local models)
- **Professional Reporting** — Multi-pass report generation in HTML, PDF, JSON, and Markdown

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

Copy the example environment file and fill in your API key:

```bash
cp .env.example .env
```

Edit `.env` with your settings (see [Configuration](#configuration-1) below).

### Docker Setup

Start the test targets (DVWA, Juice Shop, etc.):

```bash
docker compose -f docker/docker-compose.yml up -d
```

### Running a Scan

```bash
# Full autonomous pentest
clinkz scan --target example.com --scope scope.json

# Recon phase only
clinkz recon --target example.com
```

## Configuration

All configuration is via environment variables in `.env`:

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | LLM backend: `openai`, `anthropic`, `gemini`, `ollama` | `openai` |
| `ORCHESTRATOR_MODEL` | Model for the Orchestrator agent | `gpt-4o` |
| `AGENT_MODEL` | Model for phase agents | `gpt-4o-mini` |
| `OPENAI_API_KEY` | OpenAI API key | — |
| `ANTHROPIC_API_KEY` | Anthropic API key | — |
| `GEMINI_API_KEY` | Google Gemini API key | — |
| `GOOGLE_API_KEY` | Google API key (legacy alias for `GEMINI_API_KEY`) | — |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.5-flash` |
| `OLLAMA_BASE_URL` | Ollama server URL | `http://localhost:11434` |
| `DB_PATH` | SQLite database path | `clinkz.db` |
| `TOOL_TIMEOUT` | Tool execution timeout (seconds) | `300` |
| `TOOL_EXEC_MODE` | Tool execution mode: `local` or `docker` | `local` |
| `DOCKER_CONTAINER` | Docker container name for sandboxed execution | `clinkz-tools` |
| `MCP_SERVERS` | JSON list of MCP server commands/URLs | `[]` |

## Supported Tools

| Tool | Capability | Type |
|------|-----------|------|
| Nmap | Port scanning & service detection | Local CLI |
| Subfinder | Subdomain enumeration | Local CLI |
| httpx | HTTP probing & tech detection | Local CLI |
| WhatWeb | Web technology fingerprinting | Local CLI |
| wafw00f | WAF detection | Local CLI |
| Katana | Web crawling | Local CLI |
| ffuf | Directory & parameter fuzzing | Local CLI |
| Nuclei | Vulnerability scanning | Local CLI |
| Nikto | Web server scanning | Local CLI |
| sqlmap | SQL injection testing | Local CLI |
| HTTP Client | Custom HTTP requests | Built-in |
| MCP Servers | Any MCP-compatible tool | MCP Protocol |

Tools are discovered dynamically at runtime — agents never hardcode tool names.

## Agents

| Agent | Role |
|-------|------|
| **Orchestrator** | Central coordinator — routes messages, manages agent lifecycle, makes strategic decisions |
| **Recon** | Reconnaissance — discovers subdomains, services, tech stack, OSINT |
| **Scan** | Attack surface mapping — crawls endpoints, fuzzes parameters, identifies input vectors |
| **Exploit** | Exploitation — researches CVEs, attempts exploits, chains vulnerabilities |
| **Critic** | Quality assurance — validates findings, checks CVSS scores, eliminates false positives |
| **Report** | Report generation — produces professional pentest reports with remediation guidance |

## Report Output

The final report includes:

- Executive summary with risk rating
- Detailed findings with CVSS scores
- Proof-of-concept evidence for each vulnerability
- Step-by-step reproduction instructions
- Remediation recommendations prioritized by severity
- MITRE ATT&CK and OWASP WSTG technique references
- Full methodology checklist with coverage statistics

Output formats: **HTML**, **PDF**, **JSON**, **Markdown**

## Testing

```bash
# Run all tests
pytest tests/

# Run a specific test module
pytest tests/test_tools/test_nmap.py -v

# Run with coverage
pytest --cov=clinkz tests/
```

## Project Structure

```
clinkz/
├── src/clinkz/
│   ├── agents/          # Phase agents (recon, scan, exploit, critic, report)
│   │   └── prompts/     # Agent system prompts
│   ├── comms/           # Message bus and communication protocol
│   ├── credentials/     # Credential store for chaining
│   ├── knowledge/       # MITRE ATT&CK, OWASP WSTG/API/LLM knowledge bases
│   ├── llm/             # LLM client abstraction (OpenAI, Anthropic, Gemini, Ollama)
│   ├── models/          # Pydantic models (scope, finding, target, report)
│   ├── orchestrator/    # Orchestrator agent and lifecycle manager
│   ├── reporting/       # Report generator and HTML/PDF renderer
│   ├── research/        # Runtime CVE/exploit research
│   └── tools/           # Tool wrappers and dynamic resolver
├── scripts/             # Demo and example scripts
├── tests/               # Test suite
├── docker/              # Docker configs for sandboxed execution
└── docs/                # Architecture and development docs
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to add new tools or agents.

## License

[MIT](LICENSE)

## Disclaimer

**Clinkz is intended for authorized security testing only.** Always obtain explicit written permission before testing any system. Unauthorized use of this tool against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.
