# Clinkz Architecture

## Overview

Clinkz is an autonomous, agentic AI system for black-box penetration testing.
It takes a scope definition as input and produces a pentest report (JSON +
Markdown today; HTML/PDF on the W3 horizon) with no human intervention during
the test.

## Phase shape (v2)

```
Orchestrator
    │
    ▼
ReconAgent             (sequential — full TCP scan + service/version + tech stack)
    │
    ├──► WebAuthenticator  (deterministic default-credential testing)
    │
    ▼
┌─────────────────────────── concurrent ───────────────────────────┐
│                                                                  │
│   ScanAgent       ResearchAgent       ExploitAgent               │
│   (HTTP + FTP +   (persistent KB +    (LLM plans;                │
│    SSH + SMB +     web research;       deterministic _test_*     │
│    DB methods)     writes runbook)     execute; adaptive XSS     │
│                                        and SQLi methodologies)   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
    │                       │                  │
    │ writes endpoints      │ writes runbook   │ writes findings
    ▼                       ▼                  ▼
                  Shared SQLite state (clinkz.db)
                  Persistent KB (clinkz_knowledge.db)
    │
    ▼
CriticAgent      (validates findings — CVSS, evidence completeness,
                  reproduction steps, false-positive rejection)
    │
    ▼
ReportAgent      (zero LLM today — emits JSON + Markdown)
```

Exploit's only hard dependency is Scan: it starts as soon as Scan completes
and never blocks on Research. Research's runbook is folded into Exploit only if
Research has already finished; otherwise Exploit starts immediately and Research
is collected for the report afterwards. Research self-caps at
`RESEARCH_TIME_BUDGET` so it can never hold the engagement open. Cross-phase
re-spins (e.g. Exploit asks for more recon) are capped at
`MAX_CROSS_PHASE_RESPINS = 3` per engagement.

## Deterministic agents with LLM checkpoints

The v2 phase agents do **not** run a free-form ReAct loop. Each follows a
fixed step sequence, and the LLM is invoked only at named reasoning
checkpoints.

### Recon (`agents/recon.py`)

```
1. Full TCP port scan                  (TOOL — deterministic, ToolResolver)
2. LLM analyzes port results           (REASONING checkpoint)
3. Service / version detection         (TOOL — deterministic)
4. LLM extracts tech stack             (REASONING checkpoint)
5. Web-specific recon (conditional)    (TOOL — deterministic)
6. LLM synthesizes summary             (REASONING checkpoint)
7. Build structured ReconResult        (CODE)
```

### Scan (`agents/scan.py`)

```
1. LLM plans scan strategy             (PLANNING checkpoint)
2. Per-service methods (HTTP, FTP,     (TOOL — deterministic per service,
   SSH, SMB, DB); HTTP adds SPA/API     with TOOL_CHAINS fallback +
   route discovery                      _route_discovery.py discoverers)
3. LLM reviews each tool output        (REASONING checkpoint)
4. LLM checks coverage sufficiency     (REASONING checkpoint)
5. Expand coverage if insufficient     (TOOL — conditional)
6. Build structured ScanResult         (CODE)
```

For HTTP services the crawl/fuzz fallback chains are augmented by **SPA/API
route discovery** (`agents/_route_discovery.py`): a set of pluggable
`RouteDiscoverer`s — `StaticBundleDiscoverer` (parse the SPA shell's JS bundles
and webpack chunks for `/api`+`/rest` route literals, including interpolated and
path-param forms) and `OpenAPIDiscoverer` (parse a served OpenAPI/Swagger spec,
else probe a tight set of conventional JSON roots). Results union into
`HTTPScanResult.endpoints` (additive, deduped) and flow to Exploit with their
param structure. The seam is intentional: a future browser-driven
`HeadlessDiscoverer` slots in as another implementation. Discovery fetches carry
the engagement session (cookies + JWT/bearer) and are bounded and same-origin
(safety against SSRF / hostile bundles). Path-param routes (`/rest/basket/:id`)
are emitted as `:id` templates and resolved at probe time by the Exploit URL
builder's `_resolve_path_params`.

### Research (`agents/research.py`) — runs concurrently

```
1. Query persistent KB for tech        (DETERMINISTIC)
2. Web search for new vulns            (TOOL — runtime_research +
                                        native Gemini Search Grounding)
3. LLM synthesizes techniques          (REASONING checkpoint)
4. Query related technologies          (DETERMINISTIC — skipped if budget spent)
5. LLM adapts past techniques          (REASONING checkpoint — skipped if budget spent)
6. Persist to engagement runbook +     (DETERMINISTIC)
   clinkz_knowledge.db
7. Build structured ResearchResult     (CODE)
```

A hard wall-clock deadline (`RESEARCH_TIME_BUDGET`) is armed at the start of the
run: step 2 stops launching web research once it trips and the secondary
related-technology adaptation (steps 4–5) is skipped, so the agent returns
whatever it has rather than stalling on a slow/grounded provider.

`research_additional()` exposes the same flow for technologies Scan
discovers mid-engagement.

### Exploit (`agents/exploit.py`)

```
1. LLM plans exploits from scan +      (PLANNING checkpoint)
   research data
2. Execute by tier:                    (TOOL — deterministic _test_*)
     Tier 1: universal _test_*
     Tier 2: tech-matched playbook
     Tier 3: experimental from runbook
3. LLM reasons through results         (REASONING checkpoint)
4. Adaptive retry / bypass             (TOOL + REASONING)
5. Record technique success/failure    (DETERMINISTIC)
   to persistent KB
6. Structure output                    (CODE)
```

Adaptive methodologies (W2.1) layer multi-phase synthesis on top of two
deterministic skills:

- `_test_xss_reflected` — reflection-context mapping → character-survival
  fingerprint → LLM-driven payload synthesis → bypass attempt
- `_test_sqli` — dialect fingerprint → injection primitive enumeration →
  LLM-driven injection-type selection → payload synthesis

Per-phase intermediate results are modelled in `models/methodology.py`
(`ReflectionPoint`, `CharacterMap`, `SynthesizedPayload`,
`SQLiMethodologyResult`, ...) and persisted in the execution trace.

### Critic + Report

- **Critic** is LLM-only with no tools — validates each finding before it
  enters the report (CVSS accuracy, evidence completeness, FP rejection).
- **Report** is currently zero-LLM — pulls findings from the state store and
  emits JSON + Markdown in <30 s. The LLM-driven multi-pass narrative + HTML/
  PDF rendering remain on the W3 horizon.

## LLM abstraction layer

All LLM calls go through `src/clinkz/llm/base.py`:

```python
class LLMClient(ABC):
    async def reason(messages, tools) -> AgentAction   # tool calling
    async def research(query) -> str                   # web-grounded research
    async def generate_text(prompt) -> str             # plain generation
```

`llm/factory.py` returns the right client per provider. `llm/fallback.py`
wraps it in a `ResilientLLMClient` that rotates providers on rate-limit /
timeout, with per-provider retry budgets (`LLM_MAX_RETRIES`,
`LLM_RETRY_BASE_DELAY`, `LLM_RETRY_MAX_DELAY`).

Each agent has a default provider:

| Agent     | Default provider | Override env var          |
|-----------|------------------|---------------------------|
| Recon     | Gemini Flash     | `LLM_PROVIDER_RECON`      |
| Scan      | Gemini Flash     | `LLM_PROVIDER_SCAN`       |
| Report    | Gemini Flash     | `LLM_PROVIDER_REPORT`     |
| Exploit   | Anthropic Claude | `LLM_PROVIDER_EXPLOIT`    |
| Research  | Gemini 3.1 Flash-Lite (GA) | `LLM_PROVIDER_RESEARCH` |

Research pins its own Gemini model via `GEMINI_RESEARCH_MODEL`
(default `gemini-3.1-flash-lite`) so Recon/Scan/Report keep `GEMINI_MODEL`.
Its `research()` calls use native Gemini Search Grounding for live CVE/writeup
retrieval, and it is rate-limit-aware (`GEMINI_MAX_RPM`, bounded backoff +
fallback) under a hard wall-clock budget (`RESEARCH_TIME_BUDGET`).

Agent code never imports openai / anthropic / google-genai directly.

## Tool abstraction layer

Every local tool inherits from `ToolBase` and implements:

| Method            | Purpose                                       |
|-------------------|-----------------------------------------------|
| `get_schema()`    | OpenAI-compatible function schema for the LLM |
| `validate_input`  | Validate args + check scope enforcement       |
| `execute()`       | Run subprocess, return raw stdout             |
| `parse_output()`  | Convert raw output to a Pydantic model        |

Agents request tools by **capability**, not name:

```python
match = await resolver.find_tool("port_scanning")
if match.source == "mcp":
    result = await match.mcp_client.call_tool(match.name, args)
else:
    tool = match.tool_class(scope=scope)
    result = tool.parse_output(await tool.execute(args))
```

Capabilities have ranked fallback chains (`tools/resolver.py::TOOL_CHAINS`).
The resolver walks the chain until a tool is available or output meets a
threshold (`try_until_sufficient`).

Host binary identity is verified at startup via
`tools/binary_identity.py::verify_binary_identity` so namesake binaries on
`$PATH` (e.g. the Python `httpx` CLI vs. ProjectDiscovery's `httpx`) cannot
impersonate the real tool. By default `TOOL_EXEC_MODE=docker` runs every
tool inside the `clinkz-tools` container; `tools/docker_preflight.py`
ensures the container is up before any tool fires.

## Scope enforcement

`EngagementScope.contains(target)` is called inside every tool's
`validate_input()`. If a target is out of scope, `ValueError` is raised
before any network activity occurs.

## State stores

### Per-engagement (`clinkz.db`)

| Table        | Purpose                                       |
|--------------|-----------------------------------------------|
| engagements  | Engagement metadata and status                |
| targets      | Discovered hosts (`Host` models as JSON)      |
| findings     | Vulnerabilities (`Finding` models as JSON)    |
| endpoints    | Scan-discovered endpoints (Exploit polls)     |
| runbook      | Research-Agent-emitted technique entries      |
| messages     | Agent message log (orchestrator-mediated)     |
| actions      | Every tool invocation with inputs/outputs     |
| attempts     | Retry tracking for failed tool calls          |

### Cross-engagement (`clinkz_knowledge.db`)

| Table                  | Purpose                                       |
|------------------------|-----------------------------------------------|
| playbook_entries       | Tier 1 / 2 / 3 techniques, success rates      |
| past_engagements       | Historical engagements (target, techs, count) |
| technique_results      | Per-engagement per-technique outcomes         |
| technology_relations   | Tech similarity edges for cross-tech transfer |

The persistent KB is what makes Clinkz get smarter over time: every
technique result is recorded, success rates are recomputed, and future
engagements query the KB before reaching for the web.

## Observability

Each engagement writes `outputs/<engagement_id>/trace.jsonl`. Categories:

- `tool_call` — tool name, args, duration, success flag
- `llm_call` — provider, model, prompt size, tokens, latency
- `agent_step` — deterministic step boundary (`recon.port_scan_full`, ...)
- `data_handoff` — Scan→Exploit endpoint write, Research→Exploit runbook write
- `methodology_phase` — adaptive XSS / SQLi phase results

Inspect with:

```bash
clinkz trace inspect <engagement_id>                     # human timeline
clinkz trace inspect <engagement_id> --raw               # JSONL pass-through
clinkz trace inspect <engagement_id> --stage exploit     # filter to one stage
clinkz trace inspect <engagement_id> --category llm_call # filter to one category
```

## Data flow

```
scope.json (input)
    │
    ▼
StateStore.create_engagement()
    │
    ├─► ReconAgent           ─► StateStore.upsert_target()
    ├─► WebAuthenticator     ─► CredentialStore.add()
    ├─► ScanAgent            ─► StateStore.add_endpoint()
    ├─► ResearchAgent        ─► StateStore.add_runbook_entry()
    │                           PersistentKB.add_playbook_entry()
    ├─► ExploitAgent         ─► StateStore.add_finding()
    │                           PersistentKB.record_technique_result()
    ├─► CriticAgent          ─► StateStore.mark_finding_validated()
    └─► ReportAgent          ─► report_<engagement_id>.json
                                report_<engagement_id>.md
```
