# Clinkz — Agentic AI Penetration Testing System

## Operating Context (read every task)

**ENVIRONMENT:**
- This is a Windows machine. Claude Code runs in PowerShell. Use PowerShell-native command syntax and Windows-aware paths.
- The git pre-commit hook auto-runs ruff on commit. Use foreground commands only — no background scripts or polling loops.

**PLAN-FIRST WORKFLOW:**
- Every task begins with a brief implementation plan before any code.
- The plan must incorporate the git discipline below as standing items.
- During planning, judge whether the task resembles something where a past mistake might recur. ONLY in that case, consult `.claude/LESSONS.md` for a relevant entry. Otherwise do not open it — it is not read by default.
- After completing a task, if you encountered an error worth not repeating, append a concise entry to `.claude/LESSONS.md` (what went wrong, the fix). This is the only time you write to it.

**GIT DISCIPLINE (every push):**
- When a push contains multiple commits, write a single aggregate push summary covering all of them — don't leave assembly to the user.
- Before pushing, check whether the diff makes a structural change (adds/removes/renames a file, agent, tool, model, or config option, or alters architecture). If so, update ALL affected documentation (`README.md`, `CLAUDE.md`, `CLINKZ_V2_IMPLEMENTATION.md`, `docs/`, `CONTRIBUTING.md`) in the same push. Stale docs after a structural change means the task is not done.
- Push to origin after each commit once pre-push gates pass.
- Maintain an open pull request for the working branch against main. On each push, if a PR exists, update its description to reflect the new commits; if none exists, open one with an aggregate description covering the branch's work. The PR description is the human-readable narrative of the branch — keep it current.

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
- **Phase shape**: Recon (sequential) → **Scan + Research + Exploit run concurrently** sharing SQLite state → Report (sequential). Exploit's only hard dependency is Scan — it starts as soon as Scan completes and never blocks on Research (whose runbook is a best-effort handoff, folded in only if already done).
- **Credit pre-flight (`llm/fallback.py::preflight_provider_available`)**: At engagement start (alongside `ensure_container_ready` / `validate_agent_chains`) the Orchestrator makes one cheap Gemini probe **when both a Gemini and an Anthropic key are present**. If it returns a depleted/unavailable signal (429 `RESOURCE_EXHAUSTED`, 503, timeout), Gemini is excluded from every agent's fallback chain for the whole engagement (`_build_agent_llms(exclude_providers={"gemini"})`) and the run completes transparently on Anthropic — logged as "Gemini unavailable — running engagement on Anthropic fallback". This detects depletion up front instead of letting each agent storm bounded 429 retries mid-pipeline, and it keeps the deterministic auth flow working: that flow makes no LLM calls, but it depends on recon's tech-stack extraction, which silently degrades under a depleted primary — routing recon to Anthropic from the start keeps default-credential discovery (and the behind-login crawl) intact.
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
- **SPA/API route discovery (`agents/_route_discovery.py`)**: modern single-page apps invoke their real surface (`/api/...`, `/rest/...`, path-param and concat-built `?q=` routes) from JavaScript at runtime, so an HTML/JS crawl under-reports them — notably the param-bearing routes a methodology needs (`/rest/products/search?q=`, `/rest/basket/:id`). `_scan_http_service` runs a set of pluggable **discoverers** behind the `RouteDiscoverer` protocol and unions the results into `HTTPScanResult.endpoints` (additive — it never replaces katana output; deduped by `(url, method)`). Two implementations today: `StaticBundleDiscoverer` (fetch the SPA shell → follow same-origin `<script src>` + webpack chunk `.js` refs in a bounded BFS → regex-extract route-shaped literals incl. interpolated `${host}/rest/basket/${id}` forms, with path/query param structure) and `OpenAPIDiscoverer` (probe `/openapi.json`, `/v3/api-docs`, … and parse a real spec; else a tight conventional-JSON-root probe). The seam is deliberate: a future `HeadlessDiscoverer` (browser-driven XHR observation) slots in as another protocol impl with no other changes — **not built now, no browser dependency**. Param structure: **path params** are emitted as `:id` segments in the URL (the cheap subset of fix #4; full JSON-body param extraction is still deferred); **query params** ride in `Endpoint.params`. Safety: regex/JSON only (no `eval`), bounded bundle count/bytes and spec size, same-origin-only bundle fetches (defence-in-depth over the tool scope check), and the SPA-200 trap is guarded (spec/root probes require a JSON content-type + parseable body, never a status code alone). Discovery requests carry the engagement session via `_discovery_http_get` (cookies + JWT/bearer headers), which also backs endpoint enrichment. **Recon→scan handoff (resolved):** the prior "Juice Shop hands Scan an empty service list" reading was a stale, pre-fix diagnosis — nmap labels the port-3000 Juice Shop web app `ppp`, which read non-HTTP until the known-web-ports `is_http` fix (`95db88f`), so `_step_execute_scans` routed it to the unsupported-service skip and `service_scans` came back empty. Post-fix recon emits the port-3000 HTTP service (`is_http` True from the port set regardless of the mislabeled name) and scan dispatches the crawl/discovery; locked in by `test_recon_emits_http_service_for_mislabeled_web_port` and `test_scan_dispatches_mislabeled_web_port`. Remaining Juice Shop endpoint delivery is now purely a discovery-layer concern (bundle/OpenAPI), not the handoff.
- **Crawl-safety (`agents/_url_safety.py::is_state_changing_url`)**: discovered links that mutate the target's security posture — WAF/security-level toggles (e.g. DVWA `security.php?phpids=on`), logout — are never visited (enrichment) nor persisted as endpoints. All v2 phases share one engagement session, so following such a link silently poisons it for every later phase. The concrete regression: the enrichment step GET-visited `security.php?phpids=on`, enabling DVWA's PHPIDS WAF, after which every Exploit-phase injection payload returned the generic "Hacking attempt detected and logged." block page and verification confirmed nothing.

### Research Agent (v2)
- **LLM**: Gemini 3.1 Flash-Lite (GA) — `LLM_PROVIDER_RESEARCH=gemini`, model pinned via `GEMINI_RESEARCH_MODEL` (default `gemini-3.1-flash-lite`; never the shut-down `-preview` variant). Fast profile with Anthropic/OpenAI fallback.
- **Live web research via native Gemini Search Grounding**: `GeminiClient.research()` attaches a Google Search tool, so `RuntimeResearcher` retrieves live CVEs/writeups natively. `runtime_research.py` is retained because it *complements* grounding (it adds NVD structured CVE data, then delegates to the grounded `research()`) — it is not a separate/duplicate search path.
- **Runs concurrently** with Scan and Exploit. **Exploit does NOT wait for Research** (Exploit depends on Scan): Research's runbook is folded into Exploit only if Research has already finished; otherwise Exploit starts immediately and Research is collected for the report afterwards.
- **Rate-limit aware**: bounded retries + exponential backoff capped at `LLM_RETRY_MAX_DELAY` then provider fallback (no 503 storm); a configurable RPM ceiling (`GEMINI_MAX_RPM`, default 30, Tier-1 sized); and a hard wall-clock budget (`RESEARCH_TIME_BUDGET`, default 180s) after which it returns whatever techniques it has gathered.
- **Steps**: Query persistent KB for tech → web-search new vulns (CVEs, writeups) → LLM synthesizes techniques → query related techs → LLM adapts past techniques → persist to engagement runbook AND `clinkz_knowledge.db`
- **Mid-engagement hook**: `research_additional()` for techs Scan discovers later

### Exploit Agent (v2)
- **LLM**: Anthropic (Claude Opus) — pinned by `LLM_PROVIDER_EXPLOIT=anthropic`
- **Steps**: LLM plans exploits from scan + research data → execute deterministic `_test_*` methods by tier → LLM reasons through results → adaptive retry/bypass → record technique success/failure to persistent KB
- **Adaptive methodologies (W2.1)**: All 14 `_test_*` methods are now adaptive multi-phase methodologies, not deterministic one-shot skills. The payload-injection family (`_test_xss_reflected`, `_test_xss_stored`, `_test_xss_dom`, `_test_sqli`, `_test_cmdi`, `_test_lfi`, `_test_file_upload`, `_test_idor`, `_test_open_redirect`, `_test_javascript_attacks`) uses the six-phase reflection/fingerprint/synthesize/verify pattern with LLM-driven payload synthesis. The behavioral family (`_test_csrf`, `_test_brute_force`, `_test_weak_session`, `_test_security_headers`) uses the four-phase hypothesis/observe/analyze/emit pattern. CMDi phase-1 candidacy also runs a reflection-guarded **echo-canary** probe (`<sep>echo <canary>`) so command injection surfaces even when the base command writes only to stderr (e.g. DVWA's `ping <bad-host>`, dropped by `shell_exec`) and bare-separator probes look inert.
- **Planning with coverage union**: `_llm_plan_exploits` first structurally dedupes and ranks the crawled endpoints (`_dedupe_and_rank_endpoints`) so canonical vulnerable surfaces (e.g. `/vulnerabilities/fi/`, `/exec/`, `/upload/`, `/brute/`) lead and crawler junk (doubled relative-link paths, source/help viewers, static assets) trails. `_dedupe_and_rank_endpoints` is also the **clean-session chokepoint**: it drops state-changing links (`is_state_changing_url` — WAF/security toggles, logout) so the Exploit phase never re-poisons the shared engagement session, no matter where the endpoint came from. The top `EXPLOIT_PLAN_PROMPT_ENDPOINTS` (default 120, was a hardcoded 50) are shown to the LLM. The LLM plan is then unioned with deterministic per-endpoint coverage (`_merge_coverage` over `_build_deterministic_plan`): every `(endpoint, applicable-method)` the LLM omits is added back (bounded by `EXPLOIT_MAX_PLAN_TASKS`), so the methodology contract ("if the vuln is present, the method MUST be queued against its endpoint") holds regardless of LLM choices.
- **Dispatch (round-robin, no phase deadline by default)**: `_step_execute_exploits` groups planned tasks by vuln-class and dispatches one per class in rotation — every category runs its first task before any category runs its second. By default there is **no exploit phase budget** (`EXPLOIT_PHASE_BUDGET=0`): the full task queue runs to completion and no category is starved by a phase-level clock — operation-level timeouts (per HTTP request, per tool subprocess, per LLM call) are the safety valve. A category is still moved to the back of the rotation once it crosses a soft cap (`exploit_category_max_findings`, default 5 findings, OR `exploit_category_time_budget`, default 90s) — but with no phase budget this only affects ordering/fairness; every task still runs. Set `EXPLOIT_PHASE_BUDGET>0` to restore the old cooperative-stop behaviour (the agent stops dispatching new tasks shortly before the budget elapses and returns cleanly).
- **Verification-honest emission**: A methodology may only emit a finding when its own evidence confirms exploitability. IDOR gates the phase-3/4 LLM checkpoints behind a deterministic divergence check (a probe must differ from baseline in status, length, or normalised body fingerprint) — identical responses make no LLM call and emit nothing. Four further IDOR guards keep that honest: (1) auth-form / credential / CSRF-token params (`username`, `password`, `Login`/`submit`, `user_token`, and any `csrf`/`token`/`nonce`/`captcha` name) are **not object references** and are excluded from candidacy at the top of phase 1 before any probe; (2) the IDOR divergence fingerprint (`_idor_body_fingerprint`) folds long hex runs in addition to numbers/whitespace, so a page that regenerates a per-request CSRF token (e.g. DVWA `login.php`, identical length 1524→1524 but a fresh `user_token` each GET) does NOT read as divergence — closing the phantom where login-form params emitted IDOR findings; (3) **reflection-sink exclusion** — phase 1 sends a canary probe and, if the canary is echoed AND substituting the original value back where it reflected reconstructs the baseline fingerprint, the param is a reflection sink (e.g. DVWA `xss_r`'s `name` → "Hello &lt;value&gt;") and is excluded before any LLM call (a param echoing the value you sent is reflection, never another principal's resource); the phase-5 echo branch that read a reflected reference as "new identifier echoed" is removed; (4) **phase-5 resource honesty** — a verified IDOR's response must be another principal's actual record, so phase 5 rejects error/not-found/denied pages and responses that collapse to a fraction of a substantial baseline (the `view_source_all.php?id=<garbage>` 33484→1730 phantom). Probe URLs are built so a same-named query param is **replaced in place** (`_build_request_url`), never appended as a duplicate (`?id=a&id=b`, whose effective value is server-dependent). `_build_request_url` also resolves `:id`/`{id}` **path-segment placeholders** first (`_resolve_path_params`) from the task params, or a benign default (`1`) so the base fetch never requests a literal `:id`, so discovered templated SPA/API routes like `/rest/basket/:id` are probed by substituting into the path (the real IDOR probe `/rest/basket/2`) rather than appending a stray `?id=`; query params are still appended/replaced as before. Stored XSS emits only when phase-5 verification confirms the payload reflects unescaped in an executable position; a synthesized-but-unverified payload emits nothing.
- **Post-run false-positive marking (Step 3b)**: `_llm_analyze_results` names suspected false positives in `ExploitAnalysis.false_positive_suspects` (typed `list[dict]` — `{id, reason}` — coerced from the LLM's str-or-dict drift). `_mark_false_positive_suspects` then flags each suspect finding `FindingStatus.FALSE_POSITIVE` (in memory and persisted via `state.update_finding`) and annotates it — **without removing it**. The finding still appears in the report tagged `[SUSPECTED FALSE POSITIVE]` for the operator to adjudicate; verification-honest emission remains the primary phantom guard, this is an advisory layer on top.
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
  1. Anthropic API (Claude Sonnet / Opus) — primary for the Exploit agent (pinned)
  2. Google Gemini API — primary for Recon / Scan / Report (`gemini_model`, default `gemini-3.1-flash-lite` GA) and Research (`gemini_research_model`, default `gemini-3.1-flash-lite` GA, with native Search Grounding). Never the shut-down `-preview` variant. Per-client RPM ceiling via `GEMINI_MAX_RPM`.
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
│   │   │   ├── _methodology_helpers.py  # Shared CMDI/LFI phase-1 probe helpers (BaselineProbe, divergence)
│   │   │   ├── _route_discovery.py # SPA/API route discoverers (static JS bundle + OpenAPI) behind RouteDiscoverer seam
│   │   │   ├── _url_safety.py      # is_state_changing_url — crawl/probe guard against session-poisoning links
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
│   │   │   ├── auth.py             # WebAuthenticator — default-cred testing (cookie/form + JSON/bearer API auth)
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
- **Operation-level timeouts are the safety valve**: every long-running operation is independently bounded so a single hang cannot stall an engagement — per tool subprocess and per HTTP request via `ToolBase._run_subprocess` (`asyncio.wait_for(timeout=self.timeout)`), and per LLM call via a hard `LLM_REQUEST_TIMEOUT` (default 120s; Gemini enforces its own 120s ceiling, Anthropic/OpenAI wrap each call in `asyncio.wait_for`). These matter because the exploit phase has no wall-clock deadline by default.
- **Crawl-safety / session hygiene**: recon/scan must map the target without changing it. `agents/_url_safety.py::is_state_changing_url` gates every crawl visit, endpoint emission, and exploit-plan entry so the shared engagement session is never poisoned by following a WAF/security toggle or logout link.
- **LLM JSON parse resilience**: both the exploit *plan* parse (`_llm_plan_exploits`) and the Step-3 *analysis* parse (`_llm_analyze_results`) tolerate malformed LLM JSON via a shared repair helper (`_repair_and_load` → fence-strip, prose-isolate, trailing-comma/truncation repair, re-balance) plus a single re-prompt for strictly valid JSON; on final failure they fall back deterministically (plan) or to an advisory-empty analysis (analysis) — never crashing the phase.
- **Deterministic skills as contracts**: `_test_*` methods are contracts — if the vulnerability is present, the method MUST find it. Adaptive methodologies (XSS-reflected, SQLi) layer LLM-driven synthesis on top of deterministic phases.
- **Persistent KB feedback loop**: Every technique result (success or miss) is recorded to `clinkz_knowledge.db` so future engagements adapt.
- **Existing parsers preserved**: The ToolBase wrappers and their `parse_output()` implementations remain the local execution backend.
- Tool wrappers return Pydantic models, never raw strings
- Scope enforcement: every tool execution validates targets against scope before running
- **Execution traces**: Each engagement writes `outputs/<engagement_id>/trace.jsonl` capturing tool calls, LLM calls, agent steps, data handoffs, and methodology-phase events. Inspect with `clinkz trace inspect <engagement_id>`.

## Pre-Push Verification
Every change must pass three gates before `git push`. If a gate fails, fix the root cause — never bypass with `--no-verify`, blanket `# noqa`/`# type: ignore`, or skip/xfail added solely to keep CI green.

1. **Lint + Cleanup** — `ruff check src/ tests/` and `ruff format --check src/ tests/`. Use `ruff format src/ tests/` to auto-format. All warnings must be resolved or explicitly justified inline. Beyond ruff, clean up every file the diff touches: remove dead code, fix improper naming, strip stale or unnecessary comments, ensure no hardcoded secrets/credentials, and add `None` guards wherever a `None` can reach a dereference.
2. **Audit (tests)** — `pytest tests/ -q --tb=short --ignore=tests/test_skills_dvwa --ignore=tests/test_integration` for unit/agent/tool/orchestrator tests on every change. Run the integration and DVWA skill suites (`pytest tests/test_integration/` and `pytest tests/test_skills_dvwa/ -m dvwa_smoke`) when DVWA is up and the change touches scan/exploit/orchestrator paths.
3. **Security review** — Invoke the `security-review` skill (`/security-review`) on the diff whenever the change touches: tool execution (`src/clinkz/tools/`), scope enforcement, credential handling/storage, LLM input/output, HTTP/network/subprocess calls, deserialization, file I/O on user-controlled paths, MCP server interactions, or report rendering. The review must include semantic analysis, control-flow analysis, data-flow analysis, dependency review, and `pip-audit` (add `npm audit` only if JS dependencies exist). Resolve every finding before pushing — never ship command/SQL injection, unsafe deserialization, secret leakage, hardcoded credentials, SSRF, path traversal, or scope-bypass code paths.

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

