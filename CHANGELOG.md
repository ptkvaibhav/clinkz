# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-23

### Added

- **Multi-agent orchestration** with deterministic phase control (Recon → Scan → Exploit → Critic → Report) and dynamic agent lifecycle management
- **12 integrated security tools** with Docker-sandboxed execution: Nmap, Subfinder, httpx, WhatWeb, wafw00f, Katana, ffuf, Nuclei, Nikto, sqlmap, HTTP client, and MCP tool servers
- **LLM-agnostic design** — Google Gemini fully implemented; OpenAI, Anthropic, and Ollama client stubs ready for integration
- **MITRE ATT&CK + OWASP WSTG knowledge base** with 342 technique entries driving methodology-aware testing
- **Credential store** with default credential database for authenticated testing and credential chaining across agents
- **MCP client integration** for connecting external tool servers via the Model Context Protocol
- **Dynamic tool discovery** — agents describe capabilities they need; the Tool Resolver finds the right tool at runtime
- **Professional report generation** in HTML, PDF, JSON, and Markdown with CVSS scoring, reproduction steps, and remediation guidance
- **Async message bus** for Orchestrator-mediated inter-agent communication
- **Scope enforcement** — every tool execution validates targets against the engagement scope before running
- **Runtime CVE research** — Exploit Agent searches the web for CVEs, PoC exploits, and bug bounty writeups
- **466 tests** covering tool wrappers, agents, communication layer, orchestrator, models, and reporting
- **Validated against DVWA** — SQL injection and command injection confirmed autonomously in end-to-end testing

[0.1.0]: https://github.com/ptkvaibhav/clinkz/releases/tag/v0.1.0
