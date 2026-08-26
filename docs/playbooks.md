# Clinkz Playbook Methodology & Knowledge Base Reference

This document describes the structured testing methodology used by Clinkz agents
and the security knowledge base that drives test selection at runtime.

## Two layers of methodology

Clinkz separates **what we aspire to test** (the WSTG/MITRE-aligned methodology
checklists below — REC-XX, SCN-XX, EXP-XX, ...) from **what is wired as
deterministic-skill code** (the `_test_*` methods in `agents/exploit.py` and
the per-service Scan methods).

- The **knowledge base** (`src/clinkz/knowledge/query.py`) is queried by every
  agent at startup to surface methodology-aligned context — WSTG references,
  ATT&CK techniques, payload hints — and is injected into LLM checkpoints.
- The **deterministic skills** are the contract layer: if the vulnerability is
  present and the skill runs, the skill MUST find it. CI proves this against
  DVWA and Juice Shop.
- Two skills today (`_test_xss_reflected`, `_test_sqli`) are **adaptive
  methodologies** — multi-phase deterministic flows with LLM-driven payload
  synthesis at named checkpoints.

The orchestrator calls `kb.get_all_for_phase(phase)` when an agent starts and
`kb.get_techniques_for_technology(tech)` each time a new technology is
discovered, injecting the results into the agent's planning context.

Agents track every test they execute using a standardised checklist format:

```
- [x] TEST-ID — Description (completed: brief result)
- [!] TEST-ID — Description (FOUND: vulnerability details)
- [ ] TEST-ID — Description (skipped: reason)
- [-] TEST-ID — Description (failed: reason)
```

Legend: `[x]` completed no finding, `[!]` finding discovered, `[ ]` skipped, `[-]` failed.

---

## Recon Agent Checklist (REC)

The Recon Agent performs passive and active reconnaissance to build a complete
picture of the target's attack surface.

| ID | Test | ATT&CK / WSTG Reference | Description |
|----|------|--------------------------|-------------|
| REC-01 | Subdomain enumeration | T1595.002 (Active Scanning: Vulnerability Scanning) | Discover all hostnames associated with the target domain |
| REC-02 | DNS record enumeration | T1590.002 (Gather Victim Network Information: DNS) | Enumerate A, AAAA, MX, NS, TXT, CNAME, SOA records |
| REC-03 | Host discovery | T1595.001 (Active Scanning: Scanning IP Blocks) | Identify live hosts from enumerated targets |
| REC-04 | Full port scan | T1046 (Network Service Discovery) | Map ALL open TCP ports on every live host |
| REC-05 | Service fingerprinting | WSTG-INFO-02 (Fingerprint Web Server) | Identify service name and exact version on every open port |
| REC-06 | OS fingerprinting | T1082 (System Information Discovery) | Detect operating system family and version |
| REC-07 | Web technology fingerprinting | WSTG-INFO-08 (Fingerprint Web Application Framework) | Identify server, language, framework, CMS, JS libraries |
| REC-08 | WAF/CDN detection | WSTG-INFO-10 (Map Application Architecture) | Detect Web Application Firewalls and CDN providers |
| REC-09 | Search engine discovery | WSTG-INFO-01 (Conduct Search Engine Discovery) | Find indexed pages, robots.txt, cached content |
| REC-10 | Metafile leakage | WSTG-INFO-03 (Review Webserver Metafiles for Information Leakage) | Check robots.txt, sitemap.xml, security.txt |
| REC-11 | HTTP method enumeration | WSTG-INFO-06 (Identify Application Entry Points) | Discover supported HTTP methods per endpoint |
| REC-12 | CVE research per service | T1190 (Exploit Public-Facing Application) | Search for known CVEs for each service+version |
| REC-13 | Default credential research | T1078.001 (Valid Accounts: Default Accounts) | Research default credentials for every technology |
| REC-14 | OSINT gathering | T1593 (Search Open Websites/Domains) | Find exposed repos, leaked credentials, config files |
| REC-15 | Certificate transparency | T1596.003 (Search Open Technical Databases: Digital Certificates) | Query CT logs for additional hostnames |

### Knowledge base queries used

- `kb.get_all_for_phase("recon")` — returns all entries tagged with `reconnaissance`, `recon`, `information_gathering`, `osint`, `network`, `infrastructure`, `dns`
- `kb.get_techniques_for_technology(tech)` — called per discovered technology
- `kb.get_cve_techniques(service, version)` — returns ATT&CK exploitation techniques (T1190, T1210, T1203, T1068, T1211, T1212, T1189)

---

## Scan Agent Checklist (SCN)

The Scan Agent maps the full attack surface — every endpoint, parameter, and
input vector.

| ID | Test | ATT&CK / WSTG Reference | Description |
|----|------|--------------------------|-------------|
| SCN-01 | Deep recursive crawl | WSTG-INFO-06 (Identify Application Entry Points) | Follow every link, parse forms, extract URLs from JS |
| SCN-02 | Directory fuzzing | WSTG-CONF-05 (Enumerate Infrastructure and Application Admin Interfaces) | Brute-force hidden paths with technology-specific wordlists |
| SCN-03 | Parameter discovery | WSTG-INFO-06 (Identify Application Entry Points) | Discover GET/POST/cookie/header parameters per endpoint |
| SCN-04 | HTTP method enumeration | WSTG-CONF-06 (Test HTTP Methods) | Test GET, POST, PUT, DELETE, OPTIONS, PATCH per endpoint |
| SCN-05 | Default credential testing | T1078.001 (Valid Accounts: Default Accounts) | Try default/stored credentials on every login form |
| SCN-06 | Authenticated crawl | WSTG-ATHN-01 (Testing for Credentials Transported over an Encrypted Channel) | Re-crawl with valid session to map protected surface |
| SCN-07 | Admin panel discovery | WSTG-CONF-05 (Enumerate Admin Interfaces) | Locate /admin, /wp-admin, /phpmyadmin, /manager, etc. |
| SCN-08 | API endpoint discovery | API1 (Broken Object Level Authorization) | Find /api/, /v1/, /graphql, /swagger, /openapi.json |
| SCN-09 | File upload form detection | WSTG-BUSL-08 (Test Upload of Unexpected File Types) | Identify all file upload entry points |
| SCN-10 | Information disclosure | WSTG-INFO-05 (Review Webpage Content for Information Leakage) | Check headers, HTML comments, JS secrets, error messages |
| SCN-11 | Backup/config file detection | WSTG-CONF-04 (Review Old Backup and Unreferenced Files) | Probe for .bak, .old, .zip, .sql, .env, .git/config |
| SCN-12 | Input reflection analysis | WSTG-INPV-01 (Testing for Reflected Cross Site Scripting) | Test if input is reflected in response for each parameter |
| SCN-13 | Error behavior analysis | WSTG-ERRH-01 (Testing for Improper Error Handling) | Send invalid input, check for stack traces, SQL errors |
| SCN-14 | Vulnerability class tagging | — | Classify every parameter: SQLi, XSS, LFI, SSRF, CMDi, IDOR |

### Knowledge base queries used

- `kb.get_all_for_phase("scan")` — returns entries tagged with `web`, `api`, `crawling`, `fuzzing`, `scanning`, `configuration`, `network`, `infrastructure`
- `kb.get_tests_by_category("injection")` — for tagging input vectors
- For API endpoints: OWASP API Top 10 sub-tests (API1–API10)
- For AI/LLM endpoints: OWASP LLM Top 10 tests (LLM01–LLM10)

---

## Exploit Agent Checklist (EXP)

The Exploit Agent proves vulnerabilities are real through manual exploitation
and exploit chaining.

| ID | Test | ATT&CK / WSTG Reference | Description |
|----|------|--------------------------|-------------|
| EXP-01 | Technology research | T1588.005 (Obtain Capabilities: Exploits) | Search CVEs, bug bounty writeups, PoCs per technology |
| EXP-02 | Authentication attempt | T1078 (Valid Accounts) | Try stored/default credentials, SQLi auth bypass |
| EXP-03 | SQL injection | WSTG-INPV-05 (Testing for SQL Injection) | Manual single-quote test, UNION SELECT, error-based, blind |
| EXP-04 | Reflected XSS | WSTG-INPV-01 (Testing for Reflected Cross Site Scripting) | Inject `<script>alert(1)</script>`, test filter bypasses |
| EXP-05 | Stored XSS | WSTG-INPV-02 (Testing for Stored Cross Site Scripting) | Inject persistent payloads in forms, profiles, comments |
| EXP-06 | Command injection | WSTG-INPV-12 (Testing for Command Injection) | Test `; id`, `| whoami`, `\`whoami\``, time-based (`; sleep 5`) |
| EXP-07 | Local file inclusion | WSTG-INPV-11 (Testing for Local File Inclusion) | Traverse with `../../etc/passwd`, PHP wrappers |
| EXP-08 | Remote file inclusion | WSTG-INPV-11.2 (Testing for Remote File Inclusion) | Include external URLs in file parameters |
| EXP-09 | File upload bypass | WSTG-BUSL-08 (Test Upload of Unexpected File Types) | Upload webshells with extension/MIME/null-byte bypasses |
| EXP-10 | SSRF | WSTG-INPV-19 (Testing for Server-Side Request Forgery) | Inject internal URLs in URL parameters |
| EXP-11 | IDOR | API1 (Broken Object Level Authorization) | Manipulate object IDs to access other users' data |
| EXP-12 | Authentication bypass | WSTG-ATHN-04 (Testing for Authentication Bypass) | Force-browse, parameter tampering, JWT manipulation |
| EXP-13 | Session hijacking | WSTG-SESS-01 (Testing for Session Management Schema) | Cookie theft via XSS, session fixation |
| EXP-14 | CSRF | WSTG-SESS-05 (Testing for Cross Site Request Forgery) | Test state-changing actions for missing CSRF tokens |
| EXP-15 | Template injection | WSTG-INPV-18 (Testing for Server-Side Template Injection) | Inject `{{7*7}}` in parameters, check for evaluation |
| EXP-16 | XXE injection | WSTG-INPV-07 (Testing for XML Injection) | Inject external entity declarations in XML inputs |
| EXP-17 | Privilege escalation | T1068 (Exploitation for Privilege Escalation) | Chain findings to elevate access |
| EXP-18 | Exploit chaining | T1210 (Exploitation of Remote Services) | SQLi→creds→admin→upload→RCE; LFI→config→DB dump |
| EXP-19 | Prompt injection | LLM01 (Prompt Injection) | Test AI/LLM endpoints for direct/indirect injection |
| EXP-20 | Finding reporting | — | Call `report_finding` for EVERY confirmed vulnerability |

### Knowledge base queries used

- `kb.get_all_for_phase("exploit")` — returns entries tagged with `web`, `api`, `network`, `injection`, `authentication`, `authorization`, `session`, `cryptography`, `exploitation`, `infrastructure`, `cloud`, `active_directory`
- `kb.get_techniques_for_technology(tech)` — ATT&CK techniques with `pentest_actions`
- `kb.get_tests_by_category("injection")` — all injection-class tests with steps and payloads
- OWASP API sub-tests with specific payloads
- OWASP LLM sub-tests for AI application targets

### Implementation status (W2.1) — deterministic `_test_*` skills

| Checklist ID | Skill in `agents/exploit.py` | Methodology |
|--------------|------------------------------|-------------|
| EXP-04 | `_test_xss_reflected` | **Adaptive** — reflection mapping → char fingerprint → LLM payload synthesis → bypass |
| EXP-03 | `_test_sqli` | **Adaptive** — dialect fingerprint → primitive enumeration → LLM injection-type selection → synthesis |
| EXP-05 | `_test_xss_stored` | Deterministic |
| —      | `_test_xss_dom` | Deterministic (DOM canary + script-context sink scan) |
| EXP-06 | `_test_cmdi` | Deterministic |
| EXP-07 | `_test_lfi` | Deterministic |
| EXP-09 | `_test_file_upload` | Deterministic |
| EXP-14 | `_test_csrf` | Deterministic |
| EXP-11 | `_test_idor` | Deterministic |
| —      | `_test_brute_force` | Deterministic (lockout-policy probe) |
| —      | `_test_open_redirect` | Deterministic |
| —      | `_test_security_headers` | Deterministic |
| EXP-13 | `_test_weak_session` | Deterministic (cookie predictability) |
| —      | `_test_javascript_attacks` | Deterministic (static client-side security-logic + bypass) |
| EXP-XX (Tier 2) | `_test_tier2_technique` | Persistent-KB driven |
| EXP-XX (Tier 3) | `_test_tier3_technique` | Research-Agent runbook driven |

Checklist items without a row above (EXP-08 RFI, EXP-10 SSRF, EXP-12 auth-bypass,
EXP-15 SSTI, EXP-16 XXE, EXP-17 privesc, EXP-18 chaining, EXP-19 prompt
injection) are still aspirational — they live in the WSTG knowledge base and
are surfaced to the Exploit Agent's planner, but no deterministic skill
guarantees coverage yet. They sit on the W3 horizon.

---

## Critic Agent Checklist (CRT)

The Critic Agent validates every finding before it enters the final report.

| ID | Validation Check | Description |
|----|------------------|-------------|
| CRT-01 | Evidence completeness | Confirmed findings MUST have HTTP request/response evidence |
| CRT-02 | CVSS accuracy | Severity must match described impact (Critical = RCE/full compromise) |
| CRT-03 | Reproduction steps | Description must explain how to reproduce the vulnerability |
| CRT-04 | Remediation adequacy | Fix recommendation must be specific and actionable |
| CRT-05 | Scanner-only rejection | Findings with only scanner output (no manual HTTP evidence) are REJECTED |
| CRT-06 | WSTG cross-reference | Match finding to OWASP WSTG test ID for traceability |
| CRT-07 | ATT&CK cross-reference | Map exploitation technique to ATT&CK technique ID |
| CRT-08 | Severity alignment | Verify CVSS aligns with OWASP/MITRE categorisation for the vuln class |
| CRT-09 | False positive check | Reject findings where evidence doesn't actually prove the claim |
| CRT-10 | Informational pass-through | Info-severity findings don't require exploitation evidence |

### Knowledge base queries used

- `kb.get_all_for_phase("critic")` — entries tagged with `web`, `api`, `network`
- `kb.search(finding_title)` — match findings to known test IDs
- Cross-reference CVSS scores against standard severity guidelines per vulnerability class

---

## Report Agent Checklist (RPT)

The Report Agent transforms validated findings into a professional pentest report.

| ID | Report Section | Description |
|----|----------------|-------------|
| RPT-01 | Executive summary | Non-technical overview: purpose, scope, risk rating, critical issues |
| RPT-02 | Finding descriptions | What, how discovered, impact, evidence for each vulnerability |
| RPT-03 | Remediation guidance | Specific fixes referencing code/config, industry standards (OWASP, CIS, NIST) |
| RPT-04 | Attack narrative | Chronological story from recon through exploitation with HTTP evidence |
| RPT-05 | Exploit chain documentation | How findings connected: default creds → admin → upload → RCE |
| RPT-06 | WSTG reference mapping | Map each finding to OWASP WSTG test ID |
| RPT-07 | API Top 10 reference mapping | Map API findings to OWASP API risk IDs (API1–API10) |
| RPT-08 | LLM Top 10 reference mapping | Map AI/LLM findings to LLM risk IDs (LLM01–LLM10) |
| RPT-09 | ATT&CK reference mapping | Map techniques to MITRE ATT&CK IDs (e.g., T1190) |
| RPT-10 | CWE identifiers | Include CWE IDs where applicable |
| RPT-11 | Severity prioritisation | Order findings Critical → High → Medium → Low → Info |
| RPT-12 | Multi-format rendering | JSON + Markdown + PDF, all three from the SAME already-redacted `PentestReport` (ReportLab; WeasyPrint does not import on Windows) |

### Knowledge base queries used

- `kb.get_all_for_phase("report")` — entries tagged with `web`, `api`, `network`
- `kb.search(finding_title)` — resolve standard reference IDs per finding
- Reference IDs included in each finding's references section for traceability

---

## Knowledge Base Coverage

The knowledge base is loaded from JSON files in `src/clinkz/knowledge/` and
indexed at startup by `KnowledgeBase.__init__()`.

| Source | File | Count | Description |
|--------|------|-------|-------------|
| MITRE ATT&CK | `mitre_attack.json` | 14 tactics, 158 techniques | Enterprise ATT&CK techniques with pentest_actions and tool mappings |
| OWASP WSTG | `owasp_wstg.json` | 12 categories, 99 tests | Web Security Testing Guide v4.2 with test_steps per test |
| OWASP API Top 10 | `owasp_api.json` | 10 risks, 44 sub-tests | API Security Top 10 2023 with payloads and test procedures |
| OWASP LLM Top 10 | `owasp_llm.json` | 10 risks, 41 sub-tests | LLM Application Top 10 with prompt injection payloads |
| **Total** | | **342 entries** | All indexed and searchable at runtime |

### How Agents Query the Knowledge Base

The knowledge base supports several query patterns:

1. **Phase-based** (`get_all_for_phase`): When an agent starts, the orchestrator
   fetches all tests applicable to that phase using tag-based filtering. Each
   phase maps to a set of tags (e.g., `recon` → `reconnaissance`, `osint`,
   `network`, `dns`, etc.).

2. **Technology-based** (`get_techniques_for_technology`): When a new technology
   is discovered (e.g., "nginx 1.24"), the system maps it to service tags via
   `_TECH_TAGS` and returns all matching tests. Also performs text search for
   the technology name in test descriptions.

3. **CVE-specific** (`get_cve_techniques`): Returns ATT&CK techniques relevant
   to exploiting known vulnerabilities in a specific service+version (T1190,
   T1210, T1203, T1068, T1211, T1212, T1189).

4. **Category-based** (`get_tests_by_category`): Searches across category names,
   tactic names, and test names for a keyword (e.g., "injection",
   "authentication").

5. **Free-text search** (`search`): Full-text search across all fields —
   names, descriptions, pentest_actions, test_steps, tools, and payloads.
   Tokenised query with AND semantics, ranked by hit count.

### Technology-to-Tag Mapping

The knowledge base maps 50+ technologies to service tags for automatic test
selection. Examples:

| Technology | Tags |
|-----------|------|
| PHP, Java, Python, Node.js | `web`, `api` |
| nginx, Apache, IIS | `web`, `configuration`, `infrastructure` |
| MySQL, PostgreSQL, MongoDB | `web`, `api`, `infrastructure` |
| WordPress, Drupal, Joomla | `web`, `api`, `authentication` |
| Docker, Kubernetes | `infrastructure`, `containers` |
| AWS, Azure, GCP | `cloud`, `infrastructure` |
| JWT, OAuth, SAML | `authentication`, `api`, `web` |
| OpenAI, LLM, ChatGPT, Claude | `ai`, `api` |

When an agent discovers a technology, the knowledge base automatically provides
all relevant tests — no manual test selection required.
