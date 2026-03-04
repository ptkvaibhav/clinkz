"""Tool Abstraction Layer (TAL).

All tool wrappers inherit from ToolBase and return Pydantic models.
Never pass raw strings between tools and agents.

Available tools:
    nmap        — Port scanning and service fingerprinting
    subfinder   — Subdomain enumeration
    httpx_tool  — HTTP probing and fingerprinting
    whatweb     — Web technology identification
    wafw00f     — WAF detection
    katana      — Web crawling
    ffuf        — Directory and parameter fuzzing
    nuclei      — Vulnerability scanning
    nikto       — Web server vulnerability scanner
    sqlmap      — SQL injection testing
"""
