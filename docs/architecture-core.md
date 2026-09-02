# Core architecture — the full text

> Relocated out of [`CLAUDE.md`](../CLAUDE.md) on 2026-09-02, verbatim.
> CLAUDE.md carries these four sections in CONDENSED form — the operative
> facts only. This file is the pre-split wording, kept so the reasoning
> behind each condensed line stays recoverable. Where the two differ in
> substance, CLAUDE.md is the operating instruction.

See also: [`architecture.md`](architecture.md) for the structural view
(module layout, phase steps, data flow), [`agents.md`](agents.md) for the
per-agent detail, and [`provider-routing.md`](provider-routing.md) for the
routing tail.

## Core Architecture: Orchestrated Multi-Agent System

### The Orchestrator pattern
All inter-agent communication flows through a central **Orchestrator Agent** — no
agent talks directly to another. It receives the scope, spins phase agents up/down
**on demand** (not all-at-once), passes each phase's result to the next, triggers
the Report Agent, and owns the global engagement context. Agents run concurrently
where the phase shape says so, not wherever a router decides.

**What actually runs is the v2 deterministic phase sequence, not LLM-mediated
dynamic routing.** `OrchestratorAgent.run()` is a fixed sequence of `_run_phase`
calls; the message bus carries `task` / `result` / `error` / `status`. The
LLM-routed branch (`_handle_query`, `RESPIN_RECON` / `RESPIN_SCAN` /
`RESPIN_EXPLOIT`, `MAX_CROSS_PHASE_RESPINS = 3`) is still in the code and has
**never fired**: no phase agent constructs a `QUERY` message, so nothing reaches
it in any recorded run. Treat the phase sequence as the architecture and that
branch as unreached code — it is not a capability the engine has, and describing
it as one is how three other claims in this file went stale.

**Phase shape:** Recon (sequential) → **Scan + Research + Exploit run concurrently**
sharing SQLite state → Report (sequential). Exploit's only hard dependency is Scan
(it never blocks on Research — Research's runbook is folded in only if already
done). **Credit pre-flight** (`llm/fallback.py::preflight_provider_available`):
with both keys present, one cheap Gemini probe at start; a depleted signal
excludes Gemini from every **fallback** chain for the engagement (under v2 Gemini
answers only where Anthropic could not) — detecting depletion up front instead of
storming 429s mid-pipeline. **A depleted account is a KNOWN-unusable state, not
an unknown one**: `ProviderAccountError` arrives as an HTTP 400
`invalid_request_error`, so it matches none of the retry predicates and used to
fall into this function's conservative "unknown error, assume available" branch
— keeping a provider that cannot answer in every chain for the whole run. It is
now classified exactly as `providers._classify` classifies it
(`KeyStatus.INVALID`), and the agreement between the two pre-flights is
asserted: the same defect in a second function, and leaving the pair asymmetric
is how the fixed half drifts back.

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
Confirmation reduces to the same P1–P7 oracles the black-box methodologies use
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
  outside `llm/`. **Routing v2: Anthropic is priority 1 for EVERY call on EVERY
  phase** (`claude-sonnet-5` by default — not Opus); Gemini
  (`gemini-3.7-flash`, pinned, never a floating alias) and OpenAI are the
  fallback tail; Ollama is a stub and is in no chain. **The Report agent makes
  zero LLM calls** — `report_llm_provider` exists for interface symmetry and
  nothing reads it at runtime, so listing Report as a Gemini-backed agent (as
  this line did) described a narrative pass that has never existed. Per-agent
  overrides via `LLM_PROVIDER_<AGENT>`, all defaulting to Anthropic;
  `ResilientLLMClient` rotates on rate-limit/timeout, and every rotation is a
  **disqualifying event** — hard failure in `baseline` mode, a
  `provider_degraded` stamp plus permanent baseline-ineligibility in `client`
  mode, and **refused outright in both modes on an emit or suppress path**
  (`llm/call_purpose.py`: a stamp can disclose reduced coverage; it cannot
  disclose a finding that was suppressed and is therefore not in the report).
  **Detail → [`docs/provider-routing.md`](docs/provider-routing.md).**
  **Operation-level timeouts** (per HTTP request, tool subprocess, and LLM call
  via `LLM_REQUEST_TIMEOUT`) are the safety valve — the exploit phase has no
  wall-clock deadline by default.
- SQLite: `clinkz.db` (per-engagement state), `clinkz_knowledge.db` (cross-
  engagement KB incl. Layer-2 `capability_facts`/`capability_observations`).
- **Playwright + Chromium** backs the P7 oracle, and lives in
  `docker/Dockerfile.tools` — where docker tool-mode actually drives it. That
  layer is **self-verifying**: Kali is not a distribution Playwright carries a
  dependency list for, so `--with-deps` can exit 0 having installed a browser
  that never launches; the layer launches it at build time and fails the build
  otherwise. For `TOOL_EXEC_MODE=local` it is an optional host extra
  (`pip install -e '.[browser]' && playwright install chromium`). Optional on
  purpose: absent, the affected classes record unproven leads exactly as before.
- **ReportLab** renders the PDF deliverable, and **pypdf** reads one back for the
  disclosure gate. WeasyPrint was declared for years for a renderer that did not
  exist and is now removed: it resolves GTK/Pango at IMPORT time and does not
  import on Windows, so it could never have been run on the machine that
  produces the bundle. ReportLab is pure Python with the base-14 fonts built in,
  so the document carries no external asset. `jinja2` remains declared and unused
  — stated rather than quietly dropped, since removing a dependency is a separate
  decision from noticing it is unused.
- MCP Python SDK for tool servers; Docker for sandboxed tool execution
  (`clinkz-tools`; `TOOL_EXEC_MODE=local` for the in-process HTTP path).
- Typer CLI; `clinkz trace inspect <engagement>` renders execution traces.
