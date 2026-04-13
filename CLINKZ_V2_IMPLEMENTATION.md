# Clinkz v2: Implementation Plan (Final — with all adjustments)

## Key Adjustments from Review

### 1. Unified Test Plan (replaces separate runbook/playbook/tests)
Single document with three tiers:
- **Tier 1 (Universal):** Run on EVERY engagement. Port scan, crawl, fuzz, 
  OWASP Top 10 checks. Never skipped.
- **Tier 2 (Technology-matched):** Run when tech fingerprint matches. 
  "Apache 2.4.x → test CVE-2019-0211, CVE-2017-9798." 
  "PHP → test type juggling, LFI via php:// wrappers."
  Grows as more technologies are encountered.
- **Tier 3 (Experimental):** New techniques from Research Agent.
  Kept if successful, removed/adjusted if not.
  Source: bug bounty writeups, researcher blogs, adapted past techniques.

Storage: persistent_playbook table in clinkz_knowledge.db
Each entry has: tier (1/2/3), technology_pattern, times_tried, times_succeeded

### 2. Tool Substitutability
Every capability has a RANKED fallback chain:
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
Agent tries first tool. If output is insufficient (< 5 URLs from crawl), 
tries the next. ToolResolver returns ranked list, agent iterates.

### 3. Deterministic Skills = Guaranteed Findings
A skill is a CONTRACT: "If Apache 2.4.25 is present AND this skill runs, 
the vulnerability MUST be found."

Skills are tested in CI:
- test_skill_apache_2425.py runs against DVWA → must find the vuln
- test_skill_sqli.py runs against DVWA /sqli/ → must find SQLi
- If a skill test fails, the skill is BROKEN and must be fixed

Skills are versioned. After each engagement:
- Skills that produced findings: validated, success_count++
- Skills that missed known vulns: flagged for review
- New skills from Research Agent: added as Tier 3 (experimental)

### 4. Claude Code Workflow Enhancement (awesome-claude-code)
Add to the repository:
- .claude/commands/ — custom slash commands for common workflows:
  /project:run-dvwa — runs the full DVWA pipeline test
  /project:test-skill <name> — tests a specific skill against DVWA
  /project:add-tool <name> — scaffolds a new tool wrapper
  /project:review-findings — reviews latest engagement findings
- Hooks: auto-run ruff check + ruff format before every commit
- Skills infrastructure: hooks that load context-appropriate skills

### 5. Agent Flow (Final — incorporating all corrections)

ORCHESTRATOR:
  1. Parse scope, enforce boundaries
  2. Run Recon (sequential) → wait for output
  3. Try default credentials (WebAuthenticator — deterministic)
  4. Start Scan + Research + Exploit concurrently
  5. Monitor completion → stop all when done
  6. Run Report (sequential)
  7. Post-engagement: commit results to persistent KB

RECON:
  Step 1: Port scan all ports (TOOL — always nmap first, rustscan fallback)
  Step 2: LLM reviews output (REASONING)
  Step 3: Service+version scan on open ports (TOOL — nmap -sV -sC)
  Step 4: LLM reviews, extracts technology list (REASONING)
  Step 5: Structure output → Orchestrator (CODE)

SCAN:
  Step 1: LLM plans scan strategy based on identified services (PLANNING)
  Step 2: For each service type, run appropriate tools:
    HTTP → crawl (katana→gospider fallback) + fuzz (ffuf→gobuster fallback)
    FTP → enumerate (nmap scripts, manual probe)
    SSH → version check, auth methods
    SMB → share listing, null session
    Database → connection test, default creds
  Step 3: LLM reviews each tool output, structures into DB (REASONING)
  Step 4: LLM checkpoint: sufficient coverage? (REASONING)
    If no → try next tool in fallback chain, bigger wordlist, deeper crawl
  Step 5: Output endpoints + analysis to shared state DB (CODE)

RESEARCH (concurrent, persistent brain):
  Step 1: Query persistent KB for existing knowledge on each technology
  Step 2: Research NEW vulns via web search (CVEs, HackerOne, blogs, Reddit)
  Step 3: LLM synthesizes into actionable techniques → runbook entries
  Step 4: Query related technologies from persistent KB
  Step 5: LLM adapts past techniques for current target
  Step 6: Write all entries to per-engagement runbook AND persistent playbook
  Ongoing: As Scan discovers new services/tech → research those too

EXPLOIT (concurrent, reads from Scan + Research):
  Step 1: LLM PLANS exploits — reviews scan data + runbook (PLANNING)
  Step 2: Tools + code execute planned exploits:
    - Deterministic _test_* methods for WSTG coverage (Tier 1)
    - Technology-specific tests from persistent playbook (Tier 2)
    - Research Agent techniques from runbook (Tier 3)
  Step 3: LLM reasons through results — retry, bypass, adapt (REASONING)
  Step 4: Results to findings DB (CODE)
  After: Record technique success/failure to persistent KB

REPORT:
  - Pull all findings from DB
  - For each: title, severity, CVSS, endpoint, PoC (request+response)
  - LLM adds remediation per finding
  - Output: JSON + Markdown

## Implementation Phases

### Phase 1: Persistent KB + Recon (Week 1)
- Persistent knowledge base schema + API (clinkz_knowledge.db)
- Unified test plan structure (3 tiers)
- Tool fallback chains in resolver
- Rewrite Recon Agent (deterministic steps)
- Verify against DVWA

### Phase 2: Scan + Research (Week 2)
- Rewrite Scan Agent (tool-driven + LLM supervision + fallback chains)
- Service-specific scan methods (HTTP, FTP, SSH, SMB, DB)
- Build Research Agent with persistent KB integration
- Cross-technology adaptation engine
- Concurrent execution wiring

### Phase 3: Exploit + Integration (Week 3)
- Rewrite Exploit Agent (LLM plans, deterministic methods execute)
- Connect to runbook (reads Research Agent output)
- Endpoint polling from shared state (reads Scan Agent output)
- Full pipeline integration against DVWA
- Target: 12+/14 findings

### Phase 4: Consistency + Skills (Week 4)
- Run 5 consecutive DVWA engagements
- Create skill tests in CI for each DVWA vulnerability
- Fix any flaky skills until 14/14 consistent
- Claude Code workflow setup (commands, hooks)
- Update CLAUDE.md to match v2 architecture exactly

### Phase 5: Expansion (Weeks 5-6)
- Juice Shop testing (Node.js stack)
- First HTB retired machine (multi-service)
- Validate cross-engagement learning
- Second HTB machine (adapted techniques from first)

## First Claude Code Prompt (Phase 1, Day 1-2)

```
Read CLAUDE.md. We are implementing the v2 architecture.
Create branch feat/v2-architecture if not already on it.

PART A — Persistent Knowledge Base:

Create src/clinkz/knowledge/persistent_kb.py:

class PersistentKnowledgeBase:
    """Cross-engagement knowledge base that grows with every pentest.
    Uses a separate SQLite DB (clinkz_knowledge.db) that persists forever."""
    
    def __init__(self, db_path="clinkz_knowledge.db"):
        ...
    
    Tables:
    
    playbook_entries:
      id, tier (1/2/3), technology_pattern (regex), technique_name (unique per tech),
      technique_description, steps (JSON), source_url, source_type,
      cve_id, severity, applicable_vuln_classes (JSON),
      times_tried (int), times_succeeded (int), success_rate (float),
      last_used_date, created_from_engagement, created_at, updated_at
    
    past_engagements:
      id, engagement_id, target_description, technologies (JSON),
      findings_count, findings_summary (JSON), date, duration_minutes
    
    technique_results:
      id, playbook_entry_id (FK), engagement_id, technology_actual,
      success (bool), finding_id, response_summary, adaptation_notes, created_at
    
    technology_relations:
      id, tech_a, tech_b, relation_type, similarity_score (0-1), notes
    
    Methods:
    - add_playbook_entry(tier, technology_pattern, technique_name, ...)
    - get_playbook_for_technology(technology) -> matches by regex pattern
    - get_tier1_tests() -> all universal tests
    - get_tier2_tests(technology) -> technology-specific tests
    - get_tier3_tests(technology) -> experimental tests
    - record_technique_result(entry_id, engagement_id, success, ...)
    - update_success_rates() -> recalculate from technique_results
    - get_related_technologies(technology) -> similar techs
    - add_technology_relation(tech_a, tech_b, relation_type, similarity)
    - record_engagement(engagement_id, target, technologies, findings)
    - get_past_results_for_technology(technology) -> what worked before

PART B — Tool Fallback Chains:

Update src/clinkz/tools/resolver.py:
  - Add TOOL_CHAINS dict mapping capability → ranked list of tool names
  - find_tools_ranked(capability) -> returns tools in preference order
  - If first tool is unavailable, return next in chain
  - Add try_until_sufficient(capability, min_results, ...) method that
    tries each tool in the chain until output meets threshold

PART C — Seed Tier 1 universal tests:

Pre-populate the persistent KB with Tier 1 entries:
  - port_scan_full: "Scan all 65535 ports" (universal, every engagement)
  - service_version_detect: "Identify service versions on open ports"
  - web_crawl: "Deep crawl all HTTP services"
  - directory_fuzz: "Fuzz directories with common.txt"
  - sqli_detection: "Test all input params for SQL injection"
  - xss_detection: "Test all reflected params for XSS"
  - cmdi_detection: "Test suspicious params for command injection"
  - lfi_detection: "Test file-path params for LFI"
  - csrf_detection: "Test state-changing forms for CSRF"
  - file_upload_test: "Test upload forms for unrestricted upload"
  - brute_force_test: "Test login forms for lockout policy"
  - security_headers: "Check all HTTP responses for security headers"

Tests for PersistentKnowledgeBase (all CRUD + pattern matching).
Run pytest. Commit and push.
```

Save this file to your repo. Start a new conversation referencing this 
plan to continue building.
```
