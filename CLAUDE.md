# Clinkz — Agentic AI Penetration Testing System

An autonomous, multi-agent AI system that performs end-to-end black-box
penetration testing: it takes a target scope (IPs/domains) and produces a
professional pentest report, no human in the loop. Agents collaborate through an
LLM-mediated Orchestrator, discovering and running tools dynamically.

> **This file is the lean operating core, loaded every session.** Per-methodology
> forensic history → [`docs/methodology/`](docs/methodology/README.md) (one file
> per class); gray-box discovery-engine detail → `docs/discovery-engine-*.md`;
> recurring-mistake narratives → [`.claude/LESSONS.md`](.claude/LESSONS.md) (index)
> → `docs/lessons/`. Fetch on demand — do not restate them here.

## Operating Context (read every task)

**ENVIRONMENT**
- Windows machine. Claude Code runs in PowerShell; a Bash tool is also available.
  Use the right syntax per shell and Windows-aware paths.
- Run `python scripts/bootstrap.py` once per clone — it sets `core.hooksPath` so
  `.githooks/pre-commit` runs the outputs/secret/gates guards. That config is
  per-clone and never committed, so a fresh clone is unprotected until it runs
  (`/gates` reports `GATE0_hooksPath`). CI's `leak-guard` job is the only
  fail-closed layer: no local config or `--no-verify` skips it.
  Use foreground commands only — no background scripts/polling.

**PLAN-FIRST WORKFLOW**
- Every task begins with a brief implementation plan before any code, folding in
  the git discipline below as standing items.
- During planning, consult `.claude/LESSONS.md` **only** when the task resembles a
  past failure; it is not read by default. After a task, append a concise entry
  **only** if you hit an error worth not repeating — the only time you write to it.

**GIT DISCIPLINE (every push)**
- A push with multiple commits gets a single aggregate push summary.
- A **structural change** (adds/removes/renames a file, agent, tool, model, or
  config option, or alters architecture) → update ALL affected docs (`README.md`,
  `CLAUDE.md`, `CLINKZ_V2_IMPLEMENTATION.md`, `docs/`, `CONTRIBUTING.md`) in the
  **same push**. Stale docs = task not done.
- Push to origin after each commit once pre-push gates pass.
- Maintain one open PR for the branch against `main`; keep its description (the
  human-readable branch narrative) current on every push.

## Core Architecture: LLM-Mediated Multi-Agent System

### The Orchestrator pattern
All inter-agent communication flows through a central **Orchestrator Agent** — no
agent talks directly to another. It receives the scope, spins phase agents up/down
**on demand** (not all-at-once), routes messages between them, re-spins an earlier
agent when a later phase needs it (capped at `MAX_CROSS_PHASE_RESPINS = 3`),
triggers the Report Agent, and owns the global engagement context. This is **not**
a linear pipeline; agents can run concurrently when optimal.

**Phase shape:** Recon (sequential) → **Scan + Research + Exploit run concurrently**
sharing SQLite state → Report (sequential). Exploit's only hard dependency is Scan
(it never blocks on Research — Research's runbook is folded in only if already
done). **Credit pre-flight** (`llm/fallback.py::preflight_provider_available`):
with both keys present, one cheap Gemini probe at start; a depleted signal
excludes Gemini from every fallback chain for the engagement and the run completes
on Anthropic — detecting depletion up front instead of storming 429s mid-pipeline.

### Message format
```python
class AgentMessage(BaseModel):
    id: str
    from_agent: str        # "orchestrator", "recon", "scan", ...
    to_agent: str
    message_type: str      # "task" | "result" | "query" | "response" | "status"
    content: dict
    engagement_id: str
    parent_message_id: str | None
    timestamp: datetime
```

All v2 phase agents follow **deterministic steps + LLM checkpoints** — a fixed
sequence of tool calls and code, LLM invoked only at named reasoning checkpoints
(planning, classification, synthesis). No free-form ReAct.

## Agents

- **Orchestrator** — coordinator/router. Anthropic (Claude) primary for strategic
  reasoning, resilient fallback to Gemini then OpenAI. Delegates all tool work.
- **Recon (v2)** — Gemini Flash (`LLM_PROVIDER_RECON=gemini`). Full TCP scan → LLM
  analyses ports → service/version detection → LLM extracts tech stack →
  web-specific recon → LLM synthesizes → `ReconResult`. Tools always via
  `ToolResolver.find_tool(capability=...)`.
- **Scan (v2)** — Gemini Flash. LLM plans strategy → service-specific methods
  (HTTP/FTP/SSH/SMB/DB) → LLM reviews output → coverage check → expand via fallback
  chains (`katana→gospider→hakrawler` crawl; `ffuf→gobuster→feroxbuster` fuzz).
  SPA/API route discovery (`agents/_route_discovery.py`) unions static-JS-bundle +
  OpenAPI discoverers into `HTTPScanResult.endpoints` (additive; param structure
  via `ParamLocation`). **Probe-safety** (`_url_safety.py`) never mutates the
  target while mapping it: `is_state_changing_url` gates navigation (WAF toggle,
  logout — the shared engagement session must never be poisoned) and
  `is_destructive_form_submission` gates submission (credential/account mutation,
  destructive verbs).
- **Research (v2)** — Gemini 3.1 Flash-Lite (GA), pinned via
  `GEMINI_RESEARCH_MODEL` (never `-preview`). Live web research via native Gemini
  Search Grounding + NVD structured CVE data. Runs concurrently with Scan/Exploit;
  rate-limit aware (`GEMINI_MAX_RPM` default 30, `RESEARCH_TIME_BUDGET` default
  180s). Persists to the engagement runbook AND `clinkz_knowledge.db`.
- **Exploit (v2)** — Anthropic Claude Opus (`LLM_PROVIDER_EXPLOIT=anthropic`). LLM
  plans exploits from scan+research → deterministic `_test_*` methods by tier →
  LLM reasons through results → adaptive retry/bypass → records capability outcome
  to the persistent KB. All 19 `_test_*` methods are adaptive multi-phase
  methodologies (six-phase injection family; four-phase behavioral family). The
  **deterministic check GATES the LLM** — no LLM verdict emits on its own; when
  phase-2 has empirically confirmed the primitive, phase-4 prefers the
  deterministic build. **Per-methodology detail (oracles, phantom fixes,
  live-validation, N/A-by-construction) →
  [`docs/methodology/`](docs/methodology/README.md).**
- **Critic** — validates findings before the report (CVSS, FP elimination,
  evidence, repro); can reject back to Exploit.
- **Report** — zero LLM calls; emits JSON + a Markdown summary from the state
  store in <30 s. Findings and **research-leads are separate types in separate
  fields**: `CrossServiceResearchLead` (unproven A→B chains) and
  `UnprovenExploitLead` (single-service, effect not witnessed) render in their own
  UNCONFIRMED sections and are never counted in the totals.

## Gray-box Discovery Engine (`src/clinkz/discovery/`)

A **third plan source** alongside the LLM plan and deterministic coverage, active
when the engagement supplies a source tree (`EngagementScope.source_dir` +
`discovery_base_url`). Model: **Δ-capability × reachability × provable-impact**.
Hypotheses lower to `ExploitTask`s and dispatch through the unchanged round-robin
+ `_persist_finding` chokepoint; discovery failures degrade to black-box. Layered
`ingest → catalog → intent (Δ) → reachability → hypothesis`, keyed on the
language-agnostic `SourceModel` (per-tree ingestor via `select_ingestor`).

Catalog classes: **EGRESS_FETCH** (→ `_test_ssrf`), **FILE_READ** (→ `_test_lfi`),
**LOG_INTERPOLATION** (log4j → `_test_log4shell`, manifest-version-gated).
Confirmation reduces to the same P1–P6 oracles the black-box methodologies use
(blind classes → **P6 out-of-band**), and is **raw-auditable**
(`ConfirmationEvidence` = confirming excerpt + the control it was distinguished
against). **Layer-2 capability learning**: a confirmed discovery finding writes a
per-technology capability fact (YES-only, poisoning-safe); a later engagement
recalls it as a **prior** that re-orders/completes the tested set but **never
emits** (emission stays the live proof). Cross-language (JS/TS Node/Express) and
cross-service (A→B topology, learned `reaches` edges) are built. **Full detail →
`docs/discovery-engine-*.md`.**

## Tool Execution: Dynamic Discovery

Agents never hardcode tool names — they call
`ToolResolver.find_tool(capability="port_scanning")`. The resolver checks MCP
servers first, then local CLI tools (the existing `ToolBase` wrappers, preserved
as the local execution backend), then walks declared `TOOL_CHAINS` fallback
orders. Every tool validates targets against scope **before any network activity**
and returns Pydantic models, never raw strings. If nothing is found the agent
reports the missing capability to the Orchestrator.

## Tech Stack

- Python 3.12+, asyncio everywhere, Pydantic v2 for all models, structured logging.
- **LLM-agnostic**: all calls through `llm/base.py`; never import a provider SDK
  outside `llm/`. Backends: Anthropic (Exploit pinned; Orchestrator primary),
  Gemini (Recon/Scan/Report/Research; `gemini-3.1-flash-lite` GA, never `-preview`),
  OpenAI (fallback tail), Ollama (stub). Per-agent overrides via
  `LLM_PROVIDER_<AGENT>`; `ResilientLLMClient` rotates providers on
  rate-limit/timeout. **Operation-level timeouts** (per HTTP request, tool
  subprocess, and LLM call via `LLM_REQUEST_TIMEOUT`) are the safety valve — the
  exploit phase has no wall-clock deadline by default.
- SQLite: `clinkz.db` (per-engagement state), `clinkz_knowledge.db` (cross-
  engagement KB incl. Layer-2 `capability_facts`/`capability_observations`).
- MCP Python SDK for tool servers; Docker for sandboxed tool execution
  (`clinkz-tools`; `TOOL_EXEC_MODE=local` for the in-process HTTP path).
- Typer CLI; `clinkz trace inspect <engagement>` renders execution traces.

## Project Structure (key paths)

```
src/clinkz/
├── cli.py            # Typer CLI: scan / trace inspect / tool-invoke / step-replay
├── config.py         # Settings (env vars, per-agent LLM overrides)
├── state.py          # SQLite state + message store; findings + research_leads
├── orchestrator/     # OrchestratorAgent, lifecycle, prompts
├── agents/           # recon, scan, exploit, research, critic, report, _route_discovery, _url_safety
├── comms/            # AgentMessage, async bus, protocol
├── discovery/        # Δ-model: ingestor(s), catalog, intent, reachability, hypothesis, engine,
│                     #   topology(+recall), recall, relations, versions
├── knowledge/        # KnowledgeBase, persistent_kb, seeders, MITRE/OWASP datasets, payloads
├── llm/              # base, factory, fallback, {anthropic,gemini,openai,ollama}_client
├── tools/            # ToolBase, resolver, mcp_client, auth, http_client, nmap/ffuf/…
├── oob/              # P6: templates (exfil guardrail), collaborator (receive-only)
├── observability/    # trace.py (JSONL), replay.py
└── models/           # scope, target, recon, scan, methodology, research, finding, report
docker/  scripts/  tests/  docs/
```

## Commands

- `python -m clinkz scan --target <domain> --scope <scope.json>` — full pentest
  (recon → scan/research/exploit → report). The only end-to-end command.
- `python -m clinkz trace inspect <engagement_id>` — render an execution trace.
- `python -m clinkz tool-invoke <engagement_id> <seq> [--replay]` — inspect/replay
  one tool invocation.
- `python -m clinkz step-replay <engagement_id> <step_id>` — re-run one agent step.
- `docker compose -f docker/docker-compose.yml up -d` — start the test targets.

## Code Style

Python 3.12+ type hints; Pydantic v2 models; async/await for all agent/tool/LLM
calls; structured logging; docstrings on public APIs; Google Python Style. Any
field an LLM populates that it might emit as objects is `list[dict[str, Any]]`
with a coercing `@field_validator(mode="before")` — never `list[str]` (a broad
`except` around model construction turns a schema mismatch into a silent outage —
LESSONS #17).

## Key Design Decisions (invariants — non-negotiable)

- **Deterministic steps + LLM checkpoints**; no free-form ReAct.
- **LLM-mediated comms** — agents never talk directly; all messages route through
  the Orchestrator.
- **Dynamic lifecycle** — agents spun up/down on demand; re-spins capped at
  `MAX_CROSS_PHASE_RESPINS`.
- **Dynamic tool discovery** — `ToolResolver.find_tool(capability=...)`, never a
  tool name or direct import.
- **LLM-agnostic + per-agent providers** — never import a provider SDK outside
  `llm/`.
- **Crawl-safety / session hygiene** — `is_state_changing_url` is the chokepoint
  guarding every crawl visit, endpoint emission, and exploit-plan entry; its
  submission counterpart `is_destructive_form_submission` guards every form
  submit at `_submit_form_fields`. **A probe never destroys target state**: a
  credential/account-mutating form is refused, not fuzzed, and a field the
  methodology did not intend to set is omitted — never sent empty-but-present.
- **A new injection *shape* gets a DEDICATED carrier**; leave the shared
  string-only `_send_probe` untouched.
- **Stack-conditioned branches** (`_is_php_stack`, engine fingerprints, dialect)
  are backed by a deterministic protocol artifact (a `PHPSESSID` cookie, a `.php`
  path, a header) — never the flaky LLM tech list alone (LESSONS #28).
- **Deterministic skills as contracts** — if the vuln is present, the `_test_*`
  method MUST find it. Verification-honest emission: emit only when the evidence
  proves the DEFINING security effect. **Never write an observation into evidence
  that was not made**; an effect that was not witnessed is an
  `UnprovenExploitLead` (a distinct type with no path to `_persist_finding`),
  never a finding. **A finding that confirms identically across every level of a
  security-graded control is a phantom by construction** — see
  `docs/methodology/dvwa-per-level-honesty.md`.
- **Suppress, never annotate** — a finding the engagement itself believes is a
  false positive is **demoted** (removed from `findings`, deleted from the store,
  re-recorded as an `UnprovenExploitLead` with `why_unconfirmed`), never emitted
  as `confirmed` carrying a caveat. A caveat inside a confirmed finding is still
  a confirmed finding. Three shapes can never confirm, in any methodology: a
  **conditional execution claim** (speculation about an unobserved downstream
  transform), a **reflection inside a framework error page** (reachability, not
  an executable context), and a **check that determines it is not applicable**
  (which returns no finding, never one whose title says "not applicable").
- **A deterministic observation gates the LLM's list, not just its verdict** — a
  posture/analysis entry contradicted by what we actually observed (a header
  reported missing that is present) is dropped, and severity is recomputed from
  the surviving set.
- **Coverage truncation is never silent** — the plan cap is loud (per class:
  how many candidates were dropped and the first omitted endpoint), each class's
  bucket is ordered by relevance to *that* class, and every applicable class is
  guaranteed one task before the cap applies.
- **Persistent KB feedback loop (Layer-2)** — a confirmed discovery finding writes
  a per-technology capability fact; confidence is a decayed corroboration PRIOR
  from confirming observations only and never gates emission. The older
  technique-success loop is retired (read-only for the report's history).
- **Execution traces** — each engagement writes `outputs/<id>/trace.jsonl` (tool
  calls, LLM calls, agent steps, handoffs, methodology-phase events). `outputs/`
  is local-only by policy — never committed.

## Pre-Push Verification (three gates; never bypass — no `--no-verify`, no blanket `# noqa`/skip)

1. **Lint + cleanup** — `ruff check src/ tests/` and `ruff format --check src/
   tests/`. Clean every file the diff touches (dead code, naming, stale comments,
   `None` guards, no hardcoded secrets). CI pins `ruff==0.15.22`.
2. **Keyless test gate** — **clear the provider keys** so the run is actually
   keyless (`config.py` calls `load_dotenv()` at import, so a present `.env`
   makes `test_exploit_v2` issue LIVE Anthropic calls and the local number is
   from a different suite than CI's — LESSONS #35):
   `ANTHROPIC_API_KEY="" GEMINI_API_KEY="" GOOGLE_API_KEY="" OPENAI_API_KEY=""
   pytest tests/ -q --tb=short
   --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop
   --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration`. Capture
   pytest's own exit code directly (`… > out.txt 2>&1; echo "EXIT=$?"`) — never
   pipe through `tail`/`&&` (LESSONS #24). Run the container gate (integration +
   the `dvwa_smoke`/`juiceshop_smoke`/`pipeline_smoke` suites) separately when
   containers are up and the change touches scan/exploit/orchestrator paths.
3. **Security review** — `/security-review` on the diff when it touches `tools/`,
   scope, credentials, LLM I/O, HTTP/network/subprocess, deserialization,
   user-path file I/O, MCP, or report rendering. Resolve every finding.

Doc/config-only changes (no `.py` modified) may skip gates 1–2; gate 3 still
applies if runtime behavior can change (new hook, permission, tool entry, payload).

## Important Rules (NEVER)

- Import a provider LLM SDK outside `llm/`; hardcode API keys (env vars via
  python-dotenv); scan outside scope (every tool validates scope first).
- Have agents communicate directly — all comms through the Orchestrator.
- Hardcode a tool name in agent code — describe the capability, let the resolver
  find it.
- Hardcode a target/benchmark value in a methodology (no DVWA/Juice Shop string
  baked in) — discover the app's own tokens at runtime.

Tool outputs are always parsed into Pydantic models (tested against real output in
`tests/fixtures/`); agent system prompts live in `prompts/` `.md` files; run the
pre-push gates before every `git push`, and push after committing.
