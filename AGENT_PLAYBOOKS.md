# Clinkz Agent Playbooks

## Overview

Each agent follows a structured playbook that combines:
1. **Methodology** — the phases and decision logic for the agent's work
2. **Knowledge Base queries** — dynamic lookup of relevant tests based on discoveries
3. **Checklist tracking** — completed/skipped/failed test IDs for auditability

## How Agents Use the Knowledge Base

When an agent discovers a technology, service, or attack surface characteristic,
it queries the KnowledgeBase for applicable tests:

```
Discovered nginx 1.24 → kb.get_techniques_for_technology("nginx 1.24")
  → Returns MITRE T1190, WSTG-CONF-*, WSTG-INFO-*, etc.

Found API endpoint → kb.get_techniques_for_service("api")
  → Returns OWASP API Top 10 tests, relevant WSTG-APIT-* tests

Phase is "exploit" → kb.get_all_for_phase("exploit")
  → Returns all exploitation-relevant tests across all sources
```

## Checklist Tracking Format

Every agent maintains a checklist in its final answer:

```
## Test Checklist
- [x] WSTG-INFO-01 — Search engine discovery (completed: found robots.txt)
- [x] WSTG-INFO-02 — Web server fingerprinting (completed: nginx 1.24)
- [ ] WSTG-INFO-03 — Metafile leakage (skipped: no metafiles found)
- [!] WSTG-INPV-05 — SQL injection (FOUND: blind SQLi in /api/users)
- [-] WSTG-ATHN-01 — Credential transport (failed: tool unavailable)
```

Legend:
- `[x]` = completed, no finding
- `[!]` = completed, finding discovered
- `[ ]` = skipped with reason
- `[-]` = failed with reason

---

## Recon Agent Playbook

### Phase 1: Passive Reconnaissance
1. Search engine discovery (WSTG-INFO-01)
2. DNS enumeration and zone transfer attempts
3. WHOIS and registrar information
4. Certificate transparency log search
5. Technology stack identification from public sources

### Phase 2: Active Reconnaissance
1. Subdomain enumeration (execute_capability: subdomain_enumeration)
2. Port scanning (execute_capability: port_scanning)
3. Service detection and version fingerprinting (execute_capability: service_detection)
4. HTTP probing of discovered hosts (execute_capability: http_probing)
5. Web technology fingerprinting (execute_capability: web_fingerprinting)
6. WAF detection (execute_capability: waf_detection)

### Phase 3: Intelligence Gathering
1. Default credential research for identified technologies
2. CVE research for identified service versions
3. OSINT aggregation (leaked credentials, exposed configs)
4. Attack surface prioritization

### Decision Logic
- If subdomain enumeration finds > 10 subdomains → probe each for HTTP services
- If port scan reveals non-HTTP services → note for manual testing
- If WAF detected → note evasion techniques for Exploit Agent
- If default credentials found for technology → report to Orchestrator immediately

### Knowledge Base Queries
```python
# On startup
kb.get_all_for_phase("recon")
# After discovering each technology
kb.get_techniques_for_technology(tech_name)
# For CVE-specific research
kb.get_cve_techniques(service, version)
```

---

## Scan Agent Playbook

### Phase 1: Web Crawling
1. Full site crawl (execute_capability: web_crawling)
2. JavaScript file analysis for API endpoints
3. robots.txt and sitemap.xml parsing
4. Hidden path discovery via common wordlists

### Phase 2: Directory and File Fuzzing
1. Directory brute-forcing (execute_capability: directory_fuzzing)
2. Backup file discovery (.bak, .old, .swp, ~)
3. Configuration file discovery (.env, .git, web.config)
4. API endpoint discovery (/api/v1, /graphql, /swagger)

### Phase 3: Parameter Discovery
1. URL parameter fuzzing
2. POST body parameter discovery
3. Header injection points
4. Cookie manipulation vectors

### Phase 4: Vulnerability Classification
Tag each endpoint by vulnerability class:
- SQLi candidates (parameters reflected in queries)
- XSS candidates (parameters reflected in responses)
- LFI/RFI candidates (file path parameters)
- SSRF candidates (URL parameters)
- Auth bypass candidates (admin/management paths)
- IDOR candidates (sequential ID parameters)
- Upload candidates (file upload forms)

### Decision Logic
- If login page found → attempt default credentials, map authenticated surface
- If API documentation found → parse all endpoints for structured testing
- If file upload found → prioritize for exploit phase
- If sequential IDs found → flag for IDOR testing

### Knowledge Base Queries
```python
# On startup
kb.get_all_for_phase("scan")
# For each discovered service type
kb.get_techniques_for_service(service_type)
# For specific vulnerability classes
kb.get_tests_by_category("injection")
kb.get_tests_by_category("authentication")
```

---

## Exploit Agent Playbook

### Phase 1: Pre-Attack Research
1. Research CVEs for ALL identified technologies (research_technology)
2. Search for public exploits and PoCs
3. Review scan results for low-hanging fruit
4. Prioritize attack vectors by likelihood and impact

### Phase 2: Authentication Testing
1. Default credential testing (WSTG-ATHN-*)
2. Brute force resistance testing
3. Session management testing (WSTG-SESS-*)
4. Authentication bypass techniques
5. JWT/token manipulation (if applicable)

### Phase 3: Injection Testing
1. SQL injection — all identified parameters (WSTG-INPV-05)
2. Cross-site scripting — reflected and stored (WSTG-INPV-01, INPV-02)
3. Command injection (WSTG-INPV-12)
4. LDAP injection (WSTG-INPV-06)
5. XML injection / XXE (WSTG-INPV-07)
6. Server-side template injection (WSTG-INPV-18)
7. SSRF (WSTG-INPV-19)

### Phase 4: Authorization Testing
1. IDOR / Broken Object Level Authorization (API1)
2. Privilege escalation (vertical)
3. Horizontal authorization bypass
4. Function-level authorization (API5)

### Phase 5: Business Logic Testing
1. Workflow bypass (WSTG-BUSL-*)
2. Rate limiting bypass
3. Mass assignment / parameter pollution

### Phase 6: Advanced Exploitation
1. Exploit chaining (e.g., SQLi → creds → admin → RCE)
2. File upload exploitation
3. Deserialization attacks
4. Race conditions

### Decision Logic
- ALWAYS call research_technology before attacking any technology
- Manual HTTP testing FIRST, automated scanning SECOND
- Call report_finding for EVERY attempt (success AND failure)
- If SQLi found → extract credentials → test credential reuse
- If RCE found → demonstrate impact, do NOT cause damage
- If authentication bypass → map full admin functionality

### Knowledge Base Queries
```python
# On startup
kb.get_all_for_phase("exploit")
# For each technology
kb.get_techniques_for_technology(tech)
kb.get_cve_techniques(service, version)
# For specific attack categories
kb.get_tests_by_category("injection")
kb.get_tests_by_category("authentication")
kb.get_tests_by_category("authorization")
# If target is an AI application
kb.search("prompt injection llm")
```

---

## Critic Agent Playbook

### Validation Checks (in order)
1. **Evidence completeness** — non-info findings MUST have request/response evidence
2. **CVSS accuracy** — score must match described severity
3. **Reproduction steps** — confirmed findings must be reproducible
4. **False positive check** — LLM review for scanner artifacts vs. real vulns
5. **Severity calibration** — compare against OWASP/CVSS standards

### Knowledge Base Queries
```python
# Validate severity against standards
kb.search(finding_title)  # Find matching standard test
# Cross-reference CVSS with OWASP severity guidelines
kb.get_tests_by_category(finding_category)
```

---

## Report Agent Playbook

### Pass 1: Executive Summary
- Risk posture overview (non-technical, 3-5 sentences)
- Severity breakdown (Critical/High/Medium/Low/Info counts)
- Highest-impact findings called out

### Pass 2: Finding Enhancement
- Technical description expansion (what/how/impact)
- Evidence formatting (request/response pairs)
- Remediation specifics (exact patches, config changes, code fixes)
- OWASP/MITRE/CWE reference mapping

### Pass 3: Attack Narrative
- Chronological story of the engagement
- Key decision points and pivots
- Attack chains and their progression

### Knowledge Base Queries
```python
# Map findings to standard references
for finding in findings:
    refs = kb.search(finding["title"])
    # Add OWASP/MITRE IDs to finding references
```
