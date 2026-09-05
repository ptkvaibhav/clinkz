# Clinkz — Agentic AI Penetration Testing System

An autonomous, multi-agent AI system that performs end-to-end black-box
penetration testing: it takes a target scope (IPs/domains) and produces a
professional pentest report, no human in the loop. Agents collaborate through a
central Orchestrator on a deterministic phase sequence, discovering and running
tools dynamically.

> **This file is the lean operating core, loaded every session — and its size is
> a gate** (`.claude/hooks/context_budget.py`, Gate 4 below). It carries RULES:
> the invariants, the gate discipline, the git protocol, the hard NEVERs. It does
> not carry narrative. Detail lives in `docs/` and is fetched on demand — never
> restated here:
>
> | Need | Read |
> |---|---|
> | Why an invariant exists — the incident behind it | [`docs/invariants.md`](docs/invariants.md) |
> | The four condensed sections below, in full | [`docs/architecture-core.md`](docs/architecture-core.md) |
> | What each agent does, and the corrections it carries | [`docs/agents.md`](docs/agents.md) |
> | Every CLI command and offline driver, in full | [`docs/commands.md`](docs/commands.md) |
> | The annotated source tree | [`docs/project-structure.md`](docs/project-structure.md) |
> | Per-methodology forensic history (one file per class) | [`docs/methodology/`](docs/methodology/README.md) |
> | Engagement setup, authenticated scanning, safety rails | [`docs/productization-engagement-safety.md`](docs/productization-engagement-safety.md) |
> | What the deliverable may CLAIM | [`docs/report-integrity.md`](docs/report-integrity.md) |
> | Ledger, alarms, reachability | [`docs/observability.md`](docs/observability.md) |
> | Provider routing and fallback | [`docs/provider-routing.md`](docs/provider-routing.md) |
> | Gray-box discovery engine | `docs/discovery-engine-*.md` |
> | Recurring-mistake narratives | [`.claude/LESSONS.md`](.claude/LESSONS.md) → `docs/lessons/` |

## Operating Context (read every task)

**ENVIRONMENT**
- Windows machine. Claude Code runs in PowerShell; a Bash tool is also available.
  Use the right syntax per shell and Windows-aware paths.
- Run `python scripts/bootstrap.py` once per clone — it sets `core.hooksPath` so
  `.githooks/pre-commit` runs the outputs/secret/gates/context-budget guards. That
  config is per-clone and never committed, so a fresh clone is unprotected until it
  runs (`/gates` reports `GATE0_hooksPath`). CI's `leak-guard` job is the only
  fail-closed layer: no local config or `--no-verify` skips it. It inspects the
  **tree**, so a sibling job `metadata-leak-guard` covers what a tree scan
  structurally cannot see — session links in a PR title/body or a
  `Claude-Session:` commit trailer. Commit attribution is suppressed at source by
  `attribution: {commit: "", pr: "", sessionUrl: false}` in `.claude/settings.json`;
  `sessionUrl` is a separate boolean and the two strings do NOT imply it.
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

## Core Architecture: Orchestrated Multi-Agent System

All inter-agent communication flows through a central **Orchestrator Agent** — no
agent talks directly to another. It receives the scope, spins phase agents up/down
**on demand**, passes each phase's result to the next, triggers the Report Agent,
and owns the global engagement context.

**What actually runs is the v2 deterministic phase sequence, not LLM-mediated
dynamic routing.** `OrchestratorAgent.run()` is a fixed sequence of `_run_phase`
calls; the message bus carries `task` / `result` / `error` / `status`. The
LLM-routed branch (`_handle_query`, `RESPIN_RECON` / `RESPIN_SCAN` /
`RESPIN_EXPLOIT`, `MAX_CROSS_PHASE_RESPINS = 3`) is still in the code and has
**never fired**: the only `QUERY` constructor is the `request_help` tool on
`AgentBase`, which reaches an agent solely through free-form tool dispatch, and
v2's deterministic steps + LLM checkpoints never dispatch it. Treat the phase
sequence as the architecture and that branch as unreached code — it is not a
capability the engine has, and describing it as one is how three other claims in
this file went stale.

**Phase shape:** Recon (sequential) → **Scan + Research + Exploit run concurrently**
sharing SQLite state → Report (sequential). Exploit's only hard dependency is Scan.
**Credit pre-flight** (`llm/fallback.py::preflight_provider_available`) probes once
at start; a depleted account is a KNOWN-unusable state classified exactly as
`providers._classify` classifies it (`KeyStatus.INVALID`), and the agreement
between the two pre-flights is asserted.

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

**Detail → [`docs/agents.md`](docs/agents.md).** Every role is Anthropic-primary
under routing v2 (`claude-sonnet-5` by default — **not Opus**).

| Agent | Role | Load-bearing facts |
|---|---|---|
| **Orchestrator** | Coordinator; delegates all tool work | Opens the engagement gate first, before docker/state/packets |
| **Recon (v2)** | Ports → services → tech stack → package identity → `ReconResult` | `_package_identity.py` is the third component source and names PACKAGES, not servers; a dependency **range** is deliberately not read |
| **Scan (v2)** | Service-specific methods, coverage expansion, API surface | Budgets its own wall clock (`SCAN_TIME_BUDGET`) — the orchestrator's timeout DISCARDS the return value; four discoverers union into `endpoints`, none carrying an application's vocabulary; safe methods only |
| **Research (v2)** | CVE/technique runbook → engagement runbook + `clinkz_knowledge.db` | **Not web-grounded by default** — grounding is declared, weakest-wins, and stamped rather than absorbed |
| **Exploit (v2)** | 25 adaptive `_test_*` methodologies by tier | The deterministic check GATES the LLM; phase-3 ranking is `_plan_ranking.py`, not the model's; P7 is the client-side oracle; TERMINAL classes dispatch last |
| **Chaining** | Composition as a capability (`src/clinkz/chaining/`) | Graded by its WEAKEST link; only ever ADDS |
| **Business logic** | Δ where the developer's intent is the APPLICATION | Intent inferred from the app's own surface, with evidence |
| **Critic** | **Archived** (`agents/_archive/critic.py`) | Registered but invoked in **0 of 2,774** recorded steps; its job is done by deterministic gates on the emitting path |
| **Report** | **Zero LLM calls** — JSON + Markdown + PDF in <30 s | `report_llm_provider` exists for interface symmetry and nothing reads it at runtime; all three documents render from the SAME redacted structure |

## Engagement Setup + Production Safety

**Full detail → [`docs/productization-engagement-safety.md`](docs/productization-engagement-safety.md).**
The hard rules:

- **The gate** (`engagement/gate.py::open_engagement`) is the FIRST statement of
  `OrchestratorAgent.run()`. No `AuthorizationRecord` ⇒ refusal, with no flag to
  skip it. An `EngagementWindow` is a hard stop re-checked on every request.
- **Credentials are never on `EngagementScope`** — the scope is `model_dump()`-ed
  into the state store, so this is structural, not disciplinary.
- **Redaction removes what a secret IS and what it LOOKS LIKE**
  (`engagement/credential_shapes.py`, one vocabulary, always on). Cookie NAMES
  survive, cookie VALUES do not; `redact_structure` is key-aware.
- **`engagement/artifact_scan.py` is the disclosure gate**, re-reading
  `outputs/<id>/` off disk rather than trusting the logic that wrote it. **One
  verdict, two regions** (bundle + companion), every skipped file NAMED, an
  unexplained skip FAILS, and a PDF is read through both its page-text and
  `/Info` channels.
- **The engine's redaction reaches only where the engine writes** — `scripts/`
  drivers go through `scripts/_artifact_io.py`, enforced structurally.
- **The credential the client gave us goes first** — the default-credential sweep
  is `not credentials.authenticating` and nothing else; there is deliberately no
  "…or the supplied credential failed" branch.
- **A login URL is proven by response SHAPE, never by a status code.** Nothing
  proven ⇒ `None`, never the root URL.
- **Authenticated state is PROVEN, not assumed** (`engagement/auth_state.py`) —
  only a boundary discriminator is accepted; a body-length delta is refused.
  Credentials supplied + assertion failed ⇒ the engagement aborts loudly.
- **Only a session-bearing response is evidence about the session**; the raised
  flag is a hypothesis and `assert_authenticated` is the oracle.
- **The rails are absent by default** — `get_active_governor()` is `None` unless
  an engagement installed one, so direct methodology invocation is byte-identical.
  The governor owns rate (5 req/s), concurrency (4), the kill switch, blocking
  detection, the window and the action log, and **never raises from the data path**.
- **`safety/destructive.py` is the one destructive vocabulary**, consulted by both
  the navigation and submission gates. A parameter VALUE is read for semantics only
  when it looks like an identifier the APP chose.
- **`_run_subprocess` gets the halt check ONLY** — a second slot per request would
  deadlock the semaphore and double-count every rate token.
- **The permitted-technique list gates dispatch**, and every withheld class is
  named in the report.
- **`models/vuln_classes.py` is the client-facing class registry**, asserted in
  sync with `DISPATCHABLE_TEST_METHODS`. A dispatch-table entry that can never
  emit is a capability claim, so `_test_tier2_technique` / `_test_tier3_technique`
  are registered `NOT_IMPLEMENTED`.

## Gray-box Discovery Engine (`src/clinkz/discovery/`)

A **third plan source** alongside the LLM plan and deterministic coverage, active
when the engagement supplies a source tree (`EngagementScope.source_dir` +
`discovery_base_url`). Model: **Δ-capability × reachability × provable-impact**.
Hypotheses lower to `ExploitTask`s and dispatch through the unchanged round-robin
+ `_persist_finding` chokepoint; discovery failures degrade to black-box. Catalog
classes: **EGRESS_FETCH** (→ `_test_ssrf`), **FILE_READ** (→ `_test_lfi`),
**LOG_INTERPOLATION** (→ `_test_log4shell`). Confirmation reduces to the same
P1–P7 oracles and is raw-auditable. **Layer-2 capability learning** writes YES-only
per-technology facts that a later engagement recalls as a **prior** — it re-orders
the tested set but **never emits**. **Full detail → `docs/discovery-engine-*.md`.**

## Tool Execution: Dynamic Discovery

Agents never hardcode tool names — they call
`ToolResolver.find_tool(capability="port_scanning")`. The resolver checks MCP
servers first, then local CLI tools, then walks declared `TOOL_CHAINS` fallback
orders. Every tool validates targets against scope **before any network activity**
and returns Pydantic models, never raw strings. If nothing is found the agent
reports the missing capability to the Orchestrator.

## Tech Stack

- Python 3.12+, asyncio everywhere, Pydantic v2 for all models, structured logging.
- **LLM-agnostic**: all calls through `llm/base.py`; never import a provider SDK
  outside `llm/`. **Routing v2: Anthropic is priority 1 for EVERY call on EVERY
  phase**; Gemini (`gemini-3.7-flash`, pinned) and OpenAI are the fallback tail;
  Ollama is a stub and is in no chain. Per-agent overrides via `LLM_PROVIDER_<AGENT>`.
  Every rotation is a **disqualifying event** — hard failure in `baseline` mode, a
  stamp plus permanent baseline-ineligibility in `client` mode, **refused outright
  in both on an emit or suppress path**. **Detail →
  [`docs/provider-routing.md`](docs/provider-routing.md).**
- **Operation-level timeouts** (per HTTP request, tool subprocess, and LLM call via
  `LLM_REQUEST_TIMEOUT`) are the safety valve — the exploit phase has no wall-clock
  deadline by default.
- SQLite: `clinkz.db` (per-engagement state), `clinkz_knowledge.db` (cross-
  engagement KB incl. Layer-2 `capability_facts`/`capability_observations`).
- **Playwright + Chromium** backs P7, and lives in `docker/Dockerfile.tools` where
  docker tool-mode drives it. That layer is **self-verifying** — it launches the
  browser at build time, because `--with-deps` can exit 0 on Kali having installed
  a browser that never launches. Optional for `TOOL_EXEC_MODE=local`; absent, the
  affected classes record unproven leads exactly as before.
- **ReportLab** renders the PDF and **pypdf** reads one back for the disclosure
  gate. **Not WeasyPrint** — it resolves GTK/Pango at import and does not import on
  Windows, so it could never have run on the machine that produces the bundle.
  `jinja2` remains declared and unused — stated rather than quietly dropped.
- **Node** backs one TARGET, not the engine: `docker/protopoll` is a real
  `Object.prototype` — a Python fixture would have been a MODEL of the one
  property the oracle rests on. Standard library only, no `package.json`.
- MCP Python SDK for tool servers; Docker for sandboxed tool execution
  (`clinkz-tools`; `TOOL_EXEC_MODE=local` for the in-process HTTP path).
- Typer CLI; `clinkz trace inspect <engagement>` renders execution traces.

## Project Structure

**Annotated tree → [`docs/project-structure.md`](docs/project-structure.md).**

```
src/clinkz/
├── cli.py            # Typer CLI            ├── comms/         # AgentMessage, bus
├── config.py         # Settings             ├── discovery/     # Δ-model engine
├── state.py          # SQLite state         ├── knowledge/     # KB, CVE catalogue
├── orchestrator/     # OrchestratorAgent    ├── llm/           # providers, purpose
├── agents/           # recon/scan/exploit/  ├── tools/         # ToolBase, resolver
│                     #   research/report +  ├── oob/           # P6 out-of-band
│                     #   the pure helpers   ├── browser/       # P7 client oracle
├── chaining/         # composition oracle   ├── observability/ # trace, ledger
├── engagement/       # gate, secrets, auth  └── models/        # scope, finding, …
├── safety/           # governor, destructive
docker/  scripts/  tests/  docs/
requirements-ci.lock  # the FULL resolved dependency set CI installs (85 packages)
```

## Commands

**Full reference → [`docs/commands.md`](docs/commands.md).** `python -m clinkz …`:

| Command | What it does | Sends traffic? |
|---|---|---|
| `scan --target <t> …` | Full pentest (recon → scan/research/exploit → report). The only end-to-end command. **Refuses to start without an authorization record.** `--dry-run` previews the profile that will ACTUALLY execute. Exit codes are the interface (`cli.py::EXIT_CODES`): 0 completed · 1 failed · 2 bad input · 3 refused · 4 halted · 5 bundle FAILED the disclosure gate | yes |
| `abort <id>` | Kill switch — halt cleanly; the report is still produced | no |
| `actions <id>` | Every state-changing request the run produced | no |
| `artifact-scan <id>` | The disclosure gate, re-run by hand; exits non-zero on a leak | no |
| `report-pdf <id>` | Re-render the client PDF from the stored redacted structure | no |
| `trace inspect <id>` | Render an execution trace | no |
| `tool-invoke <id> <seq>` | Inspect one tool invocation (`--replay` RE-EXECUTES) | with `--replay` |
| `step-replay <id> <step>` | Re-run one agent step | maybe |
| `corpus-replay` | Offline parser regression gate; exits non-zero on drift | no |

Offline drivers in `scripts/`: `regrade_stored_bundles.py`, `regrade_idor_arms.py`,
`plan_variance_corpus.py`, `cve_reservation_corpus.py`,
`record_protopoll_fixtures.py`, `juiceshop_benchmark_run.py --record-floor`.
**Live:** `three_run_envelope.py`.
`docker compose -f docker/docker-compose.yml up -d` starts the test targets.

## Code Style

Python 3.12+ type hints; Pydantic v2 models; async/await for all agent/tool/LLM
calls; structured logging; docstrings on public APIs; Google Python Style. Any
field an LLM populates that it might emit as objects is `list[dict[str, Any]]`
with a coercing `@field_validator(mode="before")` — never `list[str]` (a broad
`except` around model construction turns a schema mismatch into a silent outage —
LESSONS #17).

## Key Design Decisions (invariants — non-negotiable)

**The rule is here; the incident that produced it is in
[`docs/invariants.md`](docs/invariants.md), same order, same numbering.** Read the
detail when you are about to change the code an invariant governs — not by default.

1. **Deterministic steps + LLM checkpoints**; no free-form ReAct.
2. **Orchestrator-mediated comms** — agents never talk directly. The router is the
   deterministic phase sequence, NOT an LLM: `_handle_query`'s `RESPIN_*` branch
   has never fired, and `MAX_CROSS_PHASE_RESPINS` bounds a path nothing reaches.
3. **Agents are spun up/down on demand**, in the order the phase shape declares.
4. **Dynamic tool discovery** — `ToolResolver.find_tool(capability=...)`, never a
   tool name or direct import.
5. **LLM-agnostic + per-agent providers** — never import a provider SDK outside
   `llm/`. Anthropic is priority 1 for every call on every phase; a discovered key
   confers *availability*, never a position.
6. **A fallback is a disqualifying event, and on an emit or suppress path it is
   refused outright — in BOTH run modes** (`llm/call_purpose.py`). A stamp can
   disclose reduced coverage; it cannot disclose a finding that was suppressed.
   Every call site declares its purpose; an unclassified one is a red build.
7. **A run where NOTHING answered is not a clean run** (`llm/degradation.py`).
   Three kinds degrade — `SUBSTITUTION`, `TERMINAL_EXCLUSION`, `CHAIN_EXHAUSTED`;
   `baseline_eligible` FOLLOWS `degraded` rather than re-deriving it. Two
   witnesses: the register, and `model_stamp` for a STORED bundle.
8. **A report about a run that did not happen must say so** — `run_completed` /
   `incomplete_reason`; incomplete + zero findings rates **`Not assessed`**, never
   "Informational", which is a verdict about the target.
9. **A capability lost to routing is STATED, never absorbed.** Research grounding
   is declared by the producer, reported as the WEAKEST any call ran under,
   carried on every runbook entry, and rendered either way. `undeclared` counts as
   ungrounded.
10. **A section that reads one field and contradicts the document's own contents
    is worse than a missing section** (`agents/_report_integrity.py`). Every
    reconciliation is pure, reads only engine-declared fields, only ever TIGHTENS,
    and runs at BOTH the build and render seams. **Detail →
    [`docs/report-integrity.md`](docs/report-integrity.md).**
11. **A session the engine GUESSED is still a session, and the record has to say
    so** — swept credentials file under `SWEPT_CREDENTIAL_ROLE`; `established`
    stays False, because holding session material and having PROVEN a session are
    different facts.
12. **A class the never-sent rule does not bind is not a class with no control —
    it is a class whose control is a DIFFERENT rule, and the row names it**
    (`VulnClass.control_arm.governing_rule` + `evidence_key`).
13. **An IDOR finding proves attribution with NAMES and FINGERPRINTS, never
    values.** The field NAME survives because it is schema, not data.
14. **A bound that decides coverage is reported in the DELIVERABLE, not just the
    log** (`observability/plan_alarms.py`). Truncation and ranking inversions stay
    separate numbers with separate renderings because they have different fixes;
    `kept_breakdown_present` is consulted FIRST, ahead of every benign branch.
15. **The crawl's enrichment budget is that same bound, one layer earlier**
    (`CrawlBudgetTruncation`) — rendered on a clean run too. One href is one
    candidate (`crawl_dedup_key`).
16. **Crawl-safety / session hygiene** — `is_state_changing_url` guards every
    crawl visit, endpoint emission and plan entry; `is_destructive_form_submission`
    guards every submit. **A probe never destroys target state**, and a field the
    methodology did not intend to set is omitted, never sent empty-but-present.
17. **A new injection *shape* gets a DEDICATED carrier**; leave the shared
    string-only `_send_probe` untouched.
18. **How a class READS the target is not the class's business** — a form-shaped
    class reads `_injectable_forms`, a probing class carries through `_send_probe`,
    never the raw layer beneath (`page.forms` is `[]` on any framework target).
    Enforced by an AST guard. `_test_javascript_attacks` is the one that does not
    migrate, and says why.
19. **An upload point is declared by a protocol artifact, never by a URL that
    sounds like one** — a declared `multipart/*` content type plus an
    upload-shaped field name.
20. **A body field is a PATH, not a name** (`agents/_json_body.py`). Only leaves
    are written and **every sibling keeps a benign value** — a rejected request
    never reaches the sink.
21. **Surface mapping never writes to the target.** Every API schema learner takes
    a probe restricted to `GET`/`HEAD`/`OPTIONS`, asserted at the seam.
22. **Stack-conditioned branches** are backed by a deterministic protocol artifact
    — never the flaky LLM tech list alone (LESSONS #28).
23. **P7 confirms a CLIENT-SIDE effect, and only ever PROMOTES**
    (`src/clinkz/browser/`). Everything the page authors is evidence, never a
    verdict input. **A missing browser costs coverage, never honesty** — there is
    no path from a P7 verdict to demoting or suppressing anything. **Detail →
    [`docs/methodology/client-side-execution-p7.md`](docs/methodology/client-side-execution-p7.md).**
24. **An oracle must observe from a machine that can REACH the target.** The
    browser runtime is tied to `TOOL_EXEC_MODE`, never configured separately, so
    the one combination that silently fails every navigation cannot be selected.
25. **A browser is a new destructive surface, and its rails are structural** —
    scope before launch, the governor authorizes, every navigation logged. A safe
    method is not automatically safe. Nothing is clicked, filled or submitted.
26. **Deterministic skills as contracts** — if the vuln is present, the `_test_*`
    method MUST find it. **Never write an observation into evidence that was not
    made**; an unwitnessed effect is an `UnprovenExploitLead`.
27. **No marker oracle confirms without a dispatched control arm that REFUSED**
    (`agents/_control_arm.py`). The control must **round-trip like the payload**.
    `MARKER_ORACLE_CLASSES` / `DIFFERENTIAL_CONTROL_CLASSES` /
    `CONTROL_EXEMPT_CLASSES` partition every dispatchable class; an unclassified
    one is a red build. **Detail →
    [`docs/methodology/never-sent-control.md`](docs/methodology/never-sent-control.md).**
28. **Every kill discloses, wherever it happens** — the lead is written inside
    `_run_control_arm`, the one seam every arm passes, so a class cannot forget
    because a class does not do it. The lead says the class could not PROVE the
    vulnerability, never that the endpoint is clean.
29. **The arm's lookup key is DECLARED by the emitting site, never re-derived.** A
    miss while a sibling arm exists on the same `(test_method, endpoint)` is a
    traced `control_arm_key_mismatch` that still refuses.
30. **An oracle confirms on its class's DEFINING effect, and the arm is what
    proves it does.** **Detail →
    [`docs/methodology/defining-effect-oracles.md`](docs/methodology/defining-effect-oracles.md).**
31. **Whose object is this? is a relation, not a property of a response** —
    four dispatched arms (`self` / `crossing` / `nonexistent` / `anonymous`) plus
    B's own authorized read. The control round-trips like the payload. Reflection
    is deliberately NOT covered by it and keeps its own guard. **Detail →
    [`docs/methodology/idor.md`](docs/methodology/idor.md).**
32. **A class that needs two identities declares it in the registry, and the code
    READS the declaration** (`MultiPrincipalRequirement`). Tier 1 multi-role MAY
    CONFIRM; Tier 2 single-role MAY ONLY LEAD. A limitation only the report knows
    about is a disclaimer.
33. **`ref(A)` is a reference the CALLER owns, or the class abstains — and
    attribution comes off the OBJECT, never off a comparison.** `ref(A)` is
    DISCOVERED by probing as A; unanchorable ⇒ ABSTAIN. The claim rests on an
    OWNING FIELD; no owning field ⇒ ABSTAIN.
34. **An anonymous 200 on `ref(B)` is DISQUALIFYING, full stop.** An arm never
    DISPATCHED refused nothing and abstains.
35. **An acceptance test that reads only an external grader cannot detect an
    oracle that reached the right verdict by the wrong arm.** The criterion must
    assert the ARMS — which request went out, as whom, carrying what.
36. **A crossing arm is evidence only when it runs UPHILL, and which way is up is
    the operator's to declare.** A is the LEAST privileged identity; rank is
    DECLARED (`privilege`), never inferred from a role LABEL. Undeclared bounds
    the verdict to a lead (ground 10).
37. **A request carries the ENGAGEMENT's session, a NAMED principal's, or none —
    one field, three values** (`session_mode`). Only an `ambient` response is
    `session_bearing`. `_as_principal` is not re-entrant.
38. **A control arm's outcome is the PROOF, so a consumer must know WHICH arm it
    read.** The producer declares (`VulnClass.control_arm`); a guard reads only
    what the engine declared, never the `Response:` entry the host controls.
39. **An observation must be attributable to the payload that produced it.**
40. **A deterministic guard whose value is that it needs no model is never gated
    by one.** All **ten** grounds run unconditionally at `_persist_finding`. An
    LLM can no longer suppress anything the code did not already suppress, and
    every ground's `why_unconfirmed` must be in `UNPROVEN_WHY_UNCONFIRMED`.
41. **Silence from a detection path is not evidence of cleanliness.** A review
    that ANSWERED and named nothing is `correctly_empty`; one that never ran is
    `ALL_FAILED`. Both control-flow exceptions are `BaseException`; they differ in
    *who* catches them, not in whether anyone can.
42. **Suppress, never annotate** — a believed false positive is **demoted**, never
    emitted as confirmed carrying a caveat. Four shapes can never confirm: a
    conditional execution claim, a reflection inside a framework error page, a
    check that determines it is not applicable, and a description of a client-side
    control.
43. **One engagement is one target state, so a confirmation SUPERSEDES its lead.**
    Directional: a witnessed effect outranks the absence of one, and there is no
    path by which a lead suppresses a finding.
44. **The suppression runs the same direction as emission: an LLM never overrules
    a deterministic oracle.** The FP cross-check may demote ONLY by naming a
    deterministic contradiction the code itself verified.
45. **A veto that reads the model's PROSE applies only to an effect nobody
    witnessed.** Phase 5 records `literal_landing_witnessed`; a skipped veto is
    logged and traced.
46. **An execution-type branch is a CLAIM, and it confirms only on the observation
    that proves ITS effect.** A branch that cannot prove its effect must never
    pre-empt one that can.
47. **A thin-but-real measurement carries its own control** — a differential is
    proof when it is *reproducible*, not when it is large. Strengthen the proof
    rather than loosen the gate.
48. **Attack the handler, not the listing** — decided on **what came back**, never
    on the path.
49. **A deterministic observation gates the LLM's list, not just its verdict**,
    and severity is recomputed from the surviving set.
50. **A class whose input is fully observed asks no model, and a baseline carries
    the model that produced it.** `security_headers` phase 3 is deterministic end
    to end, asserted on the CALL. Ladder invariance is pinned on fixed
    observations, **and** the shared verdict is pinned.
51. **Coverage truncation is never silent** — per class, how many candidates were
    dropped and the first omitted endpoint; every applicable class is guaranteed
    one task before the cap. A drop on an endpoint carrying the class's **own**
    surface is a separate **RANKING FAILURE**.
52. **A phase-3 ranking is a function of the phase-2 FINGERPRINT, and the bound on
    it is the fingerprint too** (`agents/_plan_ranking.py`). A ranking returns the
    order AND `supported`; `attempt_window` never truncates a supported type. The
    tail is never empty. **Detail →
    [`docs/methodology/plan-ranking.md`](docs/methodology/plan-ranking.md).**
53. **The plan order is a function of the endpoint SET, never of the crawl's
    order** — a concurrent crawler emits a different sequence each run. Ties break
    on structural identity, never traversal order.
54. **`verification_strength` decides emission, and it is a closed vocabulary** —
    classified explicitly in both directions; a test fails on any unclassified
    literal.
55. **A guard never parses text the target controls.** A suppression primitive
    handed to the target is worse than the phantom the guard prevents.
56. **Persistent KB feedback loop (Layer-2)** — YES-only, a decayed corroboration
    prior that never gates emission.
57. **A CVE match on a version string is a LEAD, never a finding**
    (`knowledge/component_cves.py`). **Affected ranges are half-open**
    `[introduced, fixed)`, pinned as PROPERTIES over a generated universe.
    **Provenance gates the CLAIM, never the TEST.** A match becomes an
    `ExploitTask` for a class whose oracle can witness that effect, or an
    `UnprovenExploitLead`. A third outcome does not exist.
58. **The fourth plan source RESERVES its slots, and spends them by version
    provenance.** A run that matched no CVE reserves zero and plans
    byte-identically. Provenance is declared by the PRODUCER
    (`VersionProvenance`), ordered ahead of published severity.
59. **A plan source that gets no slots must still say so** — the tier-2/3 research
    source is always computed and its candidates join the truncation buckets.
60. **The PRODUCER declares what it fingerprinted, too** (`detected_components()`
    / `declares_components()`). A non-declaring wrapper is a loud `DEAD_SEAM`.
61. **A tool named in a `TOOL_CHAINS` entry must DECLARE that capability, and the
    resolver reads the declared ORDER.**
62. **Resolving is not the same as being used, and an unused capability states its
    reason** — verified against the source so it cannot become documentation of a
    wish.
63. **One origin fence** (`agents/_origin.py`) — the host comparison is the
    obvious half, and each new call site re-derives only the obvious half.
64. **"Is this the same string" is the right question for a FENCE and the wrong
    one for a finding's IDENTITY** (`OriginIdentity`). The alias is OBSERVED,
    never inferred; **name-based virtual hosting fails SAFE**, because
    over-merging HIDES a finding and emitting one twice does not.
65. **A phase stopped at its own wall clock is not a run that did not happen.** A
    timeout WITH a result did its work; a timeout with NOTHING still trips the
    banner. **A banner that fires on a third of good runs is one a reader learns
    to skip.**
66. **A mock at a tool or parser seam returns the REAL output model.** A test that
    can only pass against a fiction is worse than no test, because it is counted
    as coverage.
67. **A guard's DOMAIN is computed from the same source of truth as the thing it
    guards; only the CLASSIFICATION is hand-maintained.** Both directions are
    asserted; an exemption is an allow-list entry with a substantive reason, never
    a silent skip. **Detail →
    [`.claude/skills/clinkz-dev/SKILL.md`](.claude/skills/clinkz-dev/SKILL.md).**
68. **Two confirmed findings do not imply the chain between them, and neither does
    a successful second request.** A carriage is proven against a decoy the target
    never issued. Decoy accepted too ⇒ a `ChainResearchLead`, never a finding with
    a caveat.
69. **A yield is what a class's confirmation PROVES, never what the class is named
    after** (`chaining/vocabulary.py::NO_YIELD_REASON`). The carried VALUE is
    excluded from serialisation.
70. **Business-logic intent must be EVIDENCED from the application's own surface**
    — unevidenced ⇒ a lead. **The status code is never the effect** — the
    read-back is.
71. **The destructive refusal is the contract, and the benchmark profile does not
    loosen it.** **Session destruction and security-posture toggles are never
    permittable on any target** — they damage the ENGAGEMENT, not the target.
72. **A total is not evidence about its parts** (`observability/ledger.py`). Four
    alarm classes stay apart because they have different fixes; *declared but
    never invoked* is tracked separately. **Absent by default**, and it never
    raises from the data path. **Detail →
    [`docs/observability.md`](docs/observability.md).**
73. **A benchmark number a client sees must be what TESTING earned.** The floor is
    **measured, never declared**, KEYED by credential set, and no floor ⇒
    `solved_by_testing: null`, not zero. **A solve binds to a FINDING, not to a
    class** — a positive reading that outlives its own evidence is a phantom
    wearing a category label.
74. **A batch is unattended, so a credit lapse must stop it rather than fill it**
    (`scripts/three_run_envelope.py`). A terminal account state refuses the batch;
    an unserved stage ends it. **A metric no run REPORTED is `null`, not zero.**
75. **A recon component that RAISED must not look like a target with nothing to
    find.** Every `except` inside a component-bearing method must reach the ledger
    or carry an allow-list entry with its reason.
76. **A ledger VIEW is not a second population.** The distinction decides whether
    a consumer may SUM.
77. **"Correctly found nothing" is a fifth fact, and it is NOT an alarm.** The
    claim must be **falsifiable, never a self-assessment** — candidates found and
    none emitted is the ffuf shape and stays SILENT. **A permanent false alarm
    trains an operator to skim the section where a real one will appear.**
78. **A component the ledger never hears from is not measurable, so every
    component is DECLARED at engagement start**
    (`observability/component_registry.py`), over three **computed** domains plus
    one declared half held to a bidirectional AST assertion. Methodology `items`
    count DISPATCHES, not findings.
79. **"Declared and never invoked" has two opposite readings, so reachability is a
    COMPUTED PREDICATE and its TIMING is split from the declaration's.** Existence
    is knowable at engagement start; reachability is not. No predicate declarable
    ⇒ a build failure, not a runtime branch.
80. **A predicate may only be evaluated against a producer that SPOKE, so there is
    a FOURTH state: NOT DETERMINED.** A counter left at its default is
    byte-identical to one a producer set to zero. The gate is per-PREDICATE, not
    per-run, and is reconciled against the run-completion banner.
81. **The prompt cache is a ledger component like any other, because it degraded
    exactly like one** — invoked every run, succeeded every time, contributed
    zero. **OFF by default by measurement.** **A ledger where an alarm always
    fires teaches the operator to stop reading it.**
82. **A consumer never guesses a producer's field names.** Never
    `getattr(parsed, "field", default)` over a model — the default is what turns a
    typo into a permanently dead capability. **A mock mirrors the real model's
    contract**, never the consumer's assumption about it.
83. **A parser never assumes it owns the process's stdout, and the fixture must be
    the bytes the tool WRITES.** Whole-blob `json.loads` is correct ONLY for JSON
    the wrapper itself serialised; every parser declares which case it is.
84. **An auth bypass is a defining effect no injection oracle can see, so it gets
    its own indicator** (`agents/_auth_bypass.py`). Three arms; **never
    200-plus-a-cookie**. The identity suppression keys on credential POSSESSION,
    not identity coincidence. **Detail →
    [`docs/methodology/auth-bypass.md`](docs/methodology/auth-bypass.md).**
85. **Execution traces** — each engagement writes `outputs/<id>/trace.jsonl`.
    `outputs/` is local-only by policy — never committed.
86. **Naming an oracle is half a claim; the other half is whether we can DELIVER
    the CVE's input to it** (`KnownComponentCVE.vector`, `CARRIABLE_VECTORS`).
    Catalogue size is bounded by oracle coverage: an entry with no oracle behind
    it is declared lead-only at WRITE time, never discovered to be lead-only at
    run time. Three lead reasons, never merged — no oracle / vector not carried /
    component unidentifiable. **Band C** (DoS, memory safety, local privesc,
    unobservable-config-dependent, indistinguishable info leak) is PERMANENTLY
    lead-only and the deliverable states that as a product property. **Detail →
    [`docs/methodology/sca-catalogue-breadth.md`](docs/methodology/sca-catalogue-breadth.md).**
87. **When the payload's effect outlives the request, the CONTROL runs first**
    (`_run_control_arm_first`). A control dispatched afterwards observes the
    change the payload made, exhibits the effect too, and kills the true
    positive it exists to license. The seam owns the order, not the class; write
    crossings hit the same constraint.
88. **A class whose effect outlives the RUN is TERMINAL, dispatched last, and a
    transient task after one is a stop-the-run condition** — not a warning
    (`TERMINAL_DISPATCH_CLASSES` / `TRANSIENT_DISPATCH_CLASSES`, partitioned over
    the dispatch table; `assert_terminal_dispatch_order` on every dispatch). A
    wildcard authorization does not cover a terminal class.
89. **A change TESTING made that the target cannot undo is stated in the
    client-facing document, naming the key** (`ResidualMutation`). Recorded on
    the WITNESSED effect, not on emission — a disclosure that only fires when we
    also got a finding out of it is a disclosure that serves us. **Detail →
    [`docs/methodology/prototype-pollution.md`](docs/methodology/prototype-pollution.md).**

## Pre-Push Verification (four gates; never bypass — no `--no-verify`, no blanket `# noqa`/skip)

1. **Lint + cleanup** — `ruff check src/ tests/` and `ruff format --check src/
   tests/`. Clean every file the diff touches (dead code, naming, stale comments, `None`
   guards, no hardcoded secrets). CI pins `ruff==0.15.22` — and a `ruff`
   on PATH (or in a stale venv) is routinely an OLDER build that reports a
   different set, so invoke the pinned one explicitly. **The whole dependency
   set is locked**, not just the three CLI packages: CI installs
   `pip install -c requirements-ci.lock -e ".[dev]"` and then asserts the result
   with `python scripts/lockfile.py --check`. Pinning `typer`/`click`/`rich` in
   `pyproject.toml` closed one instance of the class and left ~80 packages free
   to resolve differently on CI than on any developer machine. Regenerate with
   `python scripts/lockfile.py --generate` (resolves for CI's linux/cp312 target,
   so it is reproducible from any machine) and commit the result.
2. **Keyless test gate** — **clear the provider keys** so the run is actually
   keyless (`config.py` calls `load_dotenv()` at import, so a present `.env`
   makes `test_exploit_v2` issue LIVE Anthropic calls and the local number is
   from a different suite than CI's — LESSONS #35):
   `ANTHROPIC_API_KEY="" GEMINI_API_KEY="" GOOGLE_API_KEY="" OPENAI_API_KEY=""
   pytest tests/ -q --tb=short
   --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop
   --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration`.
   The `p7_browser` tests self-skip without a Chromium install, so the gate is
   identical on CI and on a machine that has one. Capture
   pytest's own exit code directly (`… > out.txt 2>&1; echo "EXIT=$?"`) — never
   pipe through `tail`/`&&` (LESSONS #24). Run the container gate (integration +
   the `dvwa_smoke`/`juiceshop_smoke`/`pipeline_smoke` suites) separately when
   containers are up and the change touches scan/exploit/orchestrator paths.
3. **Security review** — `/security-review` on the diff when it touches `tools/`,
   scope, credentials, LLM I/O, HTTP/network/subprocess, deserialization,
   user-path file I/O, MCP, or report rendering. Resolve every finding.
4. **Context budget** — `python .claude/hooks/context_budget.py`. Every
   always-loaded instruction file must stay under its character budget, measured
   in the unit the loader counts. **This gate is the one gates 1–2 may not be
   skipped alongside**: it exists precisely because doc-only edits are what grow
   these files, and the failure it prevents is silent. See below.

Doc/config-only changes (no `.py` modified) may skip gates 1–2. **Gate 4 never
skips** — a doc-only change is exactly the change it guards. Gate 3 still applies
if runtime behavior can change (new hook, permission, tool entry, payload).

### Why gate 4 exists

`CLAUDE.md` reached **152,205 characters against a ~150k load limit** — it grew
every week and the bound it was approaching degrades by *truncating silently*, so
the first symptom would have been rules quietly not in effect with nothing in the
transcript to say which. Same class as the guard-domain law: **a bound that
degrades quietly is not a bound.** The guard fails loudly at a budget far below
the limit, so the file is refused at commit time long before anything is cut, and
the domain is **computed** (every `CLAUDE.md` in the tree, plus `.claude/LESSONS.md`)
rather than a hand-listed path that a new always-loaded file would silently escape.

## Important Rules (NEVER)

- Import a provider LLM SDK outside `llm/`; hardcode API keys (env vars via
  python-dotenv); scan outside scope (every tool validates scope first).
- Have agents communicate directly — all comms through the Orchestrator.
- Hardcode a tool name in agent code — describe the capability, let the resolver
  find it.
- Hardcode a target/benchmark value in a methodology (no DVWA/Juice Shop string
  baked in) — discover the app's own tokens at runtime.
- Grow this file with narrative. A new incident writes its rule here in one line
  and its story in `docs/` — that is what keeps gate 4 green.

Tool outputs are always parsed into Pydantic models (tested against real output in
`tests/fixtures/`); agent system prompts live in `prompts/` `.md` files; run the
pre-push gates before every `git push`, and push after committing.
