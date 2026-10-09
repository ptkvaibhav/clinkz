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
> | Every invariant's full rule text (this file keeps the headline) | [`docs/invariants-rules.md`](docs/invariants-rules.md) |
> | The four condensed sections below, in full | [`docs/architecture-core.md`](docs/architecture-core.md) |
> | What each agent does, and the corrections it carries | [`docs/agents.md`](docs/agents.md) |
> | Every CLI command and offline driver, in full | [`docs/commands.md`](docs/commands.md) |
> | The annotated source tree | [`docs/project-structure.md`](docs/project-structure.md) |
> | Per-methodology forensic history (one file per class) | [`docs/methodology/`](docs/methodology/README.md) |
> | Engagement setup, authenticated scanning, safety rails | [`docs/productization-engagement-safety.md`](docs/productization-engagement-safety.md) |
> | What the deliverable may CLAIM | [`docs/report-integrity.md`](docs/report-integrity.md) |
> | Ledger, alarms, reachability, run auditability | [`docs/observability.md`](docs/observability.md) |
> | Per-round measurements and the open register | [`docs/analysis/register.md`](docs/analysis/register.md) |
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

**Full detail → `docs/architecture-core.md`.**

All inter-agent communication flows through a central **Orchestrator Agent** — no
agent talks directly to another. **What runs is the v2 deterministic phase
sequence, not LLM-mediated dynamic routing**: `OrchestratorAgent.run()` is a fixed
sequence of `_run_phase` calls and the bus carries `task` / `result` / `error` /
`status`. The LLM-routed branch (`_handle_query`, `RESPIN_*`,
`MAX_CROSS_PHASE_RESPINS`) is unreached code — its only `QUERY` constructor is
`request_help`, which v2 never dispatches. Describing it as a capability is how
three other claims in this file went stale.

**Phase shape:** Recon (sequential) → **Scan + Research + Exploit concurrently**
over shared SQLite state → Report (sequential). Exploit's only hard dependency is
Scan. **Credit pre-flight** (`llm/fallback.py::preflight_provider_available`)
probes once at start; a depleted account is `KeyStatus.INVALID`, and the
agreement between the two pre-flights is asserted.

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
sequence of tool calls and code, LLM invoked only at named reasoning checkpoints.
No free-form ReAct.
## Agents

**Detail → `docs/agents.md`.** Every role is Anthropic-primary
under routing v2 (`claude-sonnet-5` by default — **not Opus**).

- **Orchestrator** — coordinator; delegates all tool work, opens the engagement
  gate first, before docker/state/packets.
- **Recon (v2)** — ports → services → tech stack → package identity.
  `_package_identity.py` names PACKAGES, not servers; a dependency **range** is
  deliberately not read.
- **Scan (v2)** — budgets its own wall clock (`SCAN_TIME_BUDGET`), because the
  orchestrator's timeout DISCARDS the return value; four discoverers union into
  `endpoints`; safe methods only.
- **Research (v2)** — **not web-grounded by default**; grounding is declared,
  weakest-wins, and stamped rather than absorbed.
- **Exploit (v2)** — 26 adaptive `_test_*` methodologies by tier. The
  deterministic check GATES the LLM; phase-3 ranking is `_plan_ranking.py`, not
  the model's; P7 is the client-side oracle; TERMINAL classes dispatch last.
- **Chaining** (`src/clinkz/chaining/`) — graded by its WEAKEST link; only ever ADDS.
- **Business logic** — intent inferred from the app's own surface, with evidence.
- **Critic** — **archived** (`agents/_archive/critic.py`); invoked in 0 of 2,774
  recorded steps, its job done by deterministic gates on the emitting path.
- **Report** — **zero LLM calls**; JSON + Markdown + PDF in <30 s, all three
  rendered from the SAME redacted structure. `report_llm_provider` exists for
  interface symmetry and nothing reads it at runtime.
## Engagement Setup + Production Safety

**Full detail → `docs/productization-engagement-safety.md`.**
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
  verdict, two regions**, every skipped file NAMED, an unexplained skip FAILS,
  and a PDF is read through both its page-text and `/Info` channels.
- **The engine's redaction reaches only where the engine writes** — `scripts/`
  drivers go through `scripts/_artifact_io.py`, and anything that assembles a
  credential set registers it (`register_credential_set`). Both are enforced
  over a computed domain, not by discipline.
- **The credential the client gave us goes first** — the default-credential sweep
  is `not credentials.authenticating` and nothing else; there is deliberately no
  "…or the supplied credential failed" branch.
- **A login URL is proven by response SHAPE, never by a status code and never by
  a path NAME.** Names order the shape probing; they never gate it. Nothing
  proven ⇒ `None`, never the root URL. **No session verdict rests on a
  destination's SPELLING** — the DOMAIN is computed from the call graph and every
  string-literal test in it is classified; `redirects_to_login` is the one
  `destination_spelling` entry and carries a licence naming every consumer.
- **Session evidence is the DELTA across the credential POST, not the jar** —
  carriage (`session_cookies`) and evidence are separate questions.
- **Authenticated state is PROVEN, not assumed** (`engagement/auth_state.py`) —
  only a boundary discriminator is accepted; a body-length delta is refused.
  Credentials supplied + assertion failed ⇒ the engagement aborts loudly.
- **A login succeeds on POSITIVE evidence only** — session material, or a
  redirect that ACTUALLY occurred (`redirect_chain` non-empty). A 4xx is never
  success. **A 415 is USED**: the same credentials are re-POSTed to the same
  action under the encoding the response named (`ENCODABLE_CONTENT_TYPES`; prose
  is never parsed).
- **The operator's declarations OVERRIDE discovery, never seed it** —
  `login_url` / `login_api_url` / `login_field` / `login_content_type` /
  `assert_url` on `RoleCredential`. A declaration that is discarded is worse than
  no declaration.
- **Only a session-bearing response is evidence about the session**; the raised
  flag is a hypothesis and `assert_authenticated` is the oracle.
- **`Set-Cookie` is carried as a LIST the producer declares** (`set_cookie` /
  `HopResponse.set_cookies`) — a `dict` keeps one of two cookies and the two
  transports keep a DIFFERENT one; no consumer splits a joined header.
- **The rails are absent by default** — `get_active_governor()` is `None` unless
  an engagement installed one, so direct methodology invocation is byte-identical.
  The governor owns rate (5 req/s), concurrency (4), the kill switch, blocking
  detection, the window and the action log, and **never raises from the data
  path**. **`_run_subprocess` gets the halt check ONLY** — a second slot per
  request would deadlock the semaphore and double-count every rate token.
- **`safety/destructive.py` is the one destructive vocabulary**, consulted by both
  the navigation and submission gates. A category no request SHAPE can be
  classified into (`cross_principal_write`) still lives there and is claimed by
  the class's own authorization gate. A parameter VALUE is read for semantics only
  when it looks like an identifier the APP chose.
- **The permitted-technique list gates dispatch**, and every withheld class is
  named in the report. **`models/vuln_classes.py` is the client-facing class
  registry**, asserted in sync with `DISPATCHABLE_TEST_METHODS`; a dispatch-table
  entry that can never emit is registered `NOT_IMPLEMENTED`.
## Gray-box Discovery Engine (`src/clinkz/discovery/`)

**Full detail → `docs/discovery-engine-*.md`.** A **third plan source** alongside
the LLM plan and deterministic coverage, active when the engagement supplies a
source tree (`EngagementScope.source_dir` + `discovery_base_url`). Model:
**Δ-capability × reachability × provable-impact**. Hypotheses lower to
`ExploitTask`s and dispatch through the unchanged round-robin + `_persist_finding`
chokepoint; discovery failures degrade to black-box. Catalog classes:
**EGRESS_FETCH** (→ `_test_ssrf`), **FILE_READ** (→ `_test_lfi`),
**LOG_INTERPOLATION** (→ `_test_log4shell`). Confirmation reduces to the same
P1–P7 oracles. **Layer-2 capability learning** writes YES-only per-technology
facts that a later engagement recalls as a **prior** — it re-orders the tested set
but **never emits**.
## Tool Execution: Dynamic Discovery

Agents never hardcode tool names — they call
`ToolResolver.find_tool(capability="port_scanning")`. The resolver checks MCP
servers first, then local CLI tools, then walks declared `TOOL_CHAINS` fallback
orders. Every tool validates targets against scope **before any network activity**
and returns Pydantic models, never raw strings. If nothing is found the agent
reports the missing capability to the Orchestrator.

## Tech Stack

**Full detail → `docs/architecture-core.md`.**

- Python 3.12+, asyncio everywhere, Pydantic v2 for all models, structured logging.
- **LLM-agnostic**: all calls through `llm/base.py`; never import a provider SDK
  outside `llm/`. **Routing v2: Anthropic is priority 1 for EVERY call on EVERY
  phase**; Gemini (`gemini-3.7-flash`, pinned) and OpenAI are the fallback tail;
  Ollama is a stub in no chain. Per-agent overrides via `LLM_PROVIDER_<AGENT>`.
  Every rotation is a **disqualifying event**. **Detail →
  `docs/provider-routing.md`.**
- **Operation-level timeouts** (per HTTP request, tool subprocess, and LLM call
  via `LLM_REQUEST_TIMEOUT`) are the safety valve — the exploit phase has no
  wall-clock deadline by default.
- SQLite: `clinkz.db` (per-engagement state), `clinkz_knowledge.db` (cross-
  engagement KB incl. Layer-2 `capability_facts` / `capability_observations`).
- **Playwright + Chromium** backs P7 and lives in `docker/Dockerfile.tools`. That
  layer is **self-verifying** — it launches the browser at build time, because
  `--with-deps` can exit 0 having installed a browser that never launches.
  Optional for `TOOL_EXEC_MODE=local`; absent, the affected classes record
  unproven leads exactly as before.
- **ReportLab** renders the PDF and **pypdf** reads one back for the disclosure
  gate. **Not WeasyPrint** — it resolves GTK/Pango at import and cannot run on the
  machine that produces the bundle. `jinja2` remains declared and unused.
- **Node** backs one TARGET, not the engine: `docker/protopoll` is a real
  `Object.prototype`. Standard library only, no `package.json`.
- MCP Python SDK for tool servers; Docker for sandboxed tool execution
  (`clinkz-tools`; `TOOL_EXEC_MODE=local` for the in-process HTTP path).
- Typer CLI; `clinkz trace inspect <engagement>` renders execution traces.
## Project Structure

**Annotated tree → `docs/project-structure.md`.**
`src/clinkz/` holds `cli.py`, `config.py`, `state.py` and the packages
`agents/` (recon · scan · exploit · research · report + pure helpers),
`orchestrator/`, `comms/`, `llm/`, `tools/`, `knowledge/`, `discovery/`,
`chaining/`, `engagement/`, `safety/`, `browser/`, `oob/`, `observability/`,
`models/`. Beside it: `docker/`, `scripts/`, `tests/`, `docs/`, and
`requirements-ci.lock` — the FULL resolved dependency set CI installs.
## Commands

**Full reference → `docs/commands.md`.** `python -m clinkz …`:
`scan --target <t>` is the only end-to-end command and **refuses to start without
an authorization record** (`--dry-run` previews the profile that will ACTUALLY
execute; it sends traffic, everything below does not unless noted). `abort <id>`
is the kill switch and still produces the report; `actions <id>` lists every
state-changing request; `artifact-scan <id>` re-runs the disclosure gate;
`report-pdf <id>` re-renders from the stored redacted structure; `trace inspect
<id>` renders a trace; `tool-invoke <id> <seq>` inspects one invocation
(**`--replay` RE-EXECUTES**); `step-replay <id> <step>` re-runs one agent step;
`corpus-replay` is the offline parser regression gate.

**Exit codes are the interface** (`cli.py::EXIT_CODES`): 0 completed · 1 failed ·
2 bad input · 3 refused · 4 halted · 5 bundle FAILED the disclosure gate.

Offline drivers in `scripts/`: `regrade_stored_bundles.py`, `regrade_idor_arms.py`,
`plan_variance_corpus.py`, `cve_reservation_corpus.py`,
`record_protopoll_fixtures.py`, `juiceshop_benchmark_run.py --record-floor`,
`auth_agent_corpus.py`, `candidate_set_regression.py`. **Live:** `three_run_envelope.py`,
`live_adaptive_auth_validation.py`.
`docker compose -f docker/docker-compose.yml up -d` starts the test targets.
## Code Style

Python 3.12+ type hints; Pydantic v2 models; async/await for all agent/tool/LLM
calls; structured logging; docstrings on public APIs; Google Python Style. Any
field an LLM populates that it might emit as objects is `list[dict[str, Any]]`
with a coercing `@field_validator(mode="before")` — never `list[str]` (a broad
`except` around model construction turns a schema mismatch into a silent outage —
LESSONS #17).

## Key Design Decisions (invariants — non-negotiable)

**Each line is the RULE, and it binds as written. The full rule text is in
[`docs/invariants-rules.md`](docs/invariants-rules.md) and the incident that
produced it in [`docs/invariants.md`](docs/invariants.md) — same numbering.**
Read both before changing the code an invariant governs; not by default. A new
invariant lands here as ONE line and in both docs in full.

1. **Deterministic steps + LLM checkpoints**; no free-form ReAct.
2. **Orchestrator-mediated comms** — agents never talk directly.
3. **Agents are spun up/down on demand**, in the order the phase shape declares.
4. **Dynamic tool discovery** — `ToolResolver.find_tool(capability=...)`, never a tool name or direct import.
5. **LLM-agnostic + per-agent providers** — never import a provider SDK outside `llm/`. Anthropic is priority 1 for every call on every phase.
6. **A fallback is a disqualifying event, and on an emit or suppress path it is refused outright — in BOTH run modes** (`llm/call_purpose.py`).
7. **A run where NOTHING answered is not a clean run** (`llm/degradation.py`).
8. **A report about a run that did not happen must say so** — `run_completed` / `incomplete_reason`; incomplete + zero findings rates **`Not assessed`**, never "Informational", which is a verdict about the target.
9. **A capability lost to routing is STATED, never absorbed.**
10. **A section that reads one field and contradicts the document's own contents is worse than a missing section** (`agents/_report_integrity.py`). → `docs/report-integrity.md`
11. **A session the engine GUESSED is still a session, and the record has to say so** — swept credentials file under `SWEPT_CREDENTIAL_ROLE`; `established` stays False, because holding session material and having PROVEN a session are different facts.
12. **A class the never-sent rule does not bind is not a class with no control — it is a class whose control is a DIFFERENT rule, and the row names it** (`VulnClass.control_arm.governing_rule` + `evidence_key`).
13. **An IDOR finding proves attribution with NAMES and FINGERPRINTS, never values.**
14. **A bound that decides coverage is reported in the DELIVERABLE, not just the log** (`observability/plan_alarms.py`).
15. **The crawl's enrichment budget is that same bound, one layer earlier** (`CrawlBudgetTruncation`) — rendered on a clean run too.
16. **Crawl-safety / session hygiene** — `is_state_changing_url` guards every crawl visit, endpoint emission and plan entry; `is_destructive_form_submission` guards every submit. **A probe never destroys target state.**
17. **A new injection *shape* gets a DEDICATED carrier**; leave the shared string-only `_send_probe` untouched.
18. **How a class READS the target is not the class's business** — a form-shaped class reads `_injectable_forms`, a probing class carries through `_send_probe`, never the raw layer beneath (`page.forms` is `[]` on any framework target).
19. **An upload point is declared by a protocol artifact, never by a URL that sounds like one** — a declared `multipart/*` content type plus an upload-shaped field name.
20. **A body field is a PATH, not a name** (`agents/_json_body.py`).
21. **Surface mapping never writes to the target.**
22. **Stack-conditioned branches** are backed by a deterministic protocol artifact — never the flaky LLM tech list alone (LESSONS #28).
23. **P7 confirms a CLIENT-SIDE effect, and only ever PROMOTES** (`src/clinkz/browser/`). → `docs/methodology/client-side-execution-p7.md`
24. **An oracle must observe from a machine that can REACH the target.**
25. **A browser is a new destructive surface, and its rails are structural** — scope before launch, the governor authorizes, every navigation logged.
26. **Deterministic skills as contracts** — if the vuln is present, the `_test_*` method MUST find it.
27. **No marker oracle confirms without a dispatched control arm that REFUSED** (`agents/_control_arm.py`). → `docs/methodology/never-sent-control.md`
28. **Every kill discloses, wherever it happens** — the lead is written inside `_run_control_arm`, the one seam every arm passes, so a class cannot forget because a class does not do it.
29. **The arm's lookup key is DECLARED by the emitting site, never re-derived.**
30. **An oracle confirms on its class's DEFINING effect, and the arm is what proves it does.** → `docs/methodology/defining-effect-oracles.md`
31. **Whose object is this? is a relation, not a property of a response** — four dispatched arms (`self` / `crossing` / `nonexistent` / `anonymous`) plus B's own authorized read. → `docs/methodology/idor.md`
32. **A class that needs two identities declares it in the registry, and the code READS the declaration** (`MultiPrincipalRequirement`).
33. **`ref(A)` is a reference the CALLER owns, or the class abstains — and attribution comes off the OBJECT, never off a comparison.**
34. **An anonymous 200 on `ref(B)` is DISQUALIFYING, full stop.**
35. **An acceptance test that reads only an external grader cannot detect an oracle that reached the right verdict by the wrong arm.**
36. **A crossing arm is evidence only when it runs UPHILL, and which way is up is the operator's to declare.**
37. **A request carries the ENGAGEMENT's session, a NAMED principal's, or none — one field, three values** (`session_mode`).
38. **A control arm's outcome is the PROOF, so a consumer must know WHICH arm it read.**
39. **An observation must be attributable to the payload that produced it.**
40. **A deterministic guard whose value is that it needs no model is never gated by one.** All ten grounds run unconditionally at `_persist_finding`.
41. **Silence from a detection path is not evidence of cleanliness.**
42. **Suppress, never annotate** — a believed false positive is **demoted**, never emitted as confirmed carrying a caveat.
43. **One engagement is one target state, so a confirmation SUPERSEDES its lead.**
44. **The suppression runs the same direction as emission: an LLM never overrules a deterministic oracle.**
45. **A veto that reads the model's PROSE applies only to an effect nobody witnessed.**
46. **An execution-type branch is a CLAIM, and it confirms only on the observation that proves ITS effect.**
47. **A thin-but-real measurement carries its own control** — a differential is proof when it is *reproducible*, not when it is large.
48. **Attack the handler, not the listing** — decided on **what came back**, never on the path.
49. **A deterministic observation gates the LLM's list, not just its verdict**, and severity is recomputed from the surviving set.
50. **A class whose input is fully observed asks no model, and a baseline carries the model that produced it.**
51. **Coverage truncation is never silent** — per class, how many candidates were dropped and the first omitted endpoint; every applicable class is guaranteed one task before the cap.
52. **A phase-3 ranking is a function of the phase-2 FINGERPRINT, and the bound on it is the fingerprint too** (`agents/_plan_ranking.py`). → `docs/methodology/plan-ranking.md`
53. **The plan order is a function of the endpoint SET, never of the crawl's order** — a concurrent crawler emits a different sequence each run.
54. **`verification_strength` decides emission, and it is a closed vocabulary** — classified explicitly in both directions; a test fails on any unclassified literal.
55. **A guard never parses text the target controls.**
56. **Persistent KB feedback loop (Layer-2)** — YES-only, a decayed corroboration prior that never gates emission.
57. **A CVE match on a version string is a LEAD, never a finding** (`knowledge/component_cves.py`).
58. **The fourth plan source RESERVES its slots, and spends them by version provenance.**
59. **A plan source that gets no slots must still say so** — the tier-2/3 research source is always computed and its candidates join the truncation buckets.
60. **The PRODUCER declares what it fingerprinted, too** (`detected_components()` / `declares_components()`).
61. **A tool named in a `TOOL_CHAINS` entry must DECLARE that capability, and the resolver reads the declared ORDER.**
62. **Resolving is not the same as being used, and an unused capability states its reason** — verified against the source so it cannot become documentation of a wish.
63. **One origin fence** (`agents/_origin.py`) — the host comparison is the obvious half, and each new call site re-derives only the obvious half.
64. **"Is this the same string" is the right question for a FENCE and the wrong one for a finding's IDENTITY** (`OriginIdentity`).
65. **A phase stopped at its own wall clock is not a run that did not happen.**
66. **A mock at a tool or parser seam returns the REAL output model.**
67. **A guard's DOMAIN is computed from the same source of truth as the thing it guards; only the CLASSIFICATION is hand-maintained.** → `.claude/skills/clinkz-dev/SKILL.md`
68. **Two confirmed findings do not imply the chain between them, and neither does a successful second request.**
69. **A yield is what a class's confirmation PROVES, never what the class is named after** (`chaining/vocabulary.py::NO_YIELD_REASON`).
70. **Business-logic intent must be EVIDENCED from the application's own surface** — unevidenced ⇒ a lead.
71. **The destructive refusal is the contract, and the benchmark profile does not loosen it.** Session destruction, security-posture toggles and cross-principal writes are never permittable on any target.
72. **A total is not evidence about its parts** (`observability/ledger.py`). → `docs/observability.md`
73. **A benchmark number a client sees must be what TESTING earned.**
74. **A batch is unattended, so a credit lapse must stop it rather than fill it** (`scripts/three_run_envelope.py`).
75. **A recon component that RAISED must not look like a target with nothing to find.**
76. **A ledger VIEW is not a second population.**
77. **"Correctly found nothing" is a fifth fact, and it is NOT an alarm.**
78. **A component the ledger never hears from is not measurable, so every component is DECLARED at engagement start** (`observability/component_registry.py`), over three **computed** domains plus one declared half held to a bidirectional AST assertion.
79. **"Declared and never invoked" has two opposite readings, so reachability is a COMPUTED PREDICATE and its TIMING is split from the declaration's.**
80. **A predicate may only be evaluated against a producer that SPOKE, so there is a FOURTH state: NOT DETERMINED.**
81. **The prompt cache is a ledger component like any other, because it degraded exactly like one** — invoked every run, succeeded every time, contributed zero.
82. **A consumer never guesses a producer's field names.**
83. **A parser never assumes it owns the process's stdout, and the fixture must be the bytes the tool WRITES.**
84. **An auth bypass is a defining effect no injection oracle can see, so it gets its own indicator** (`agents/_auth_bypass.py`). → `docs/methodology/auth-bypass.md`
85. **Execution traces** — each engagement writes `outputs/<id>/trace.jsonl`.
86. **Naming an oracle is half a claim; the other half is whether we can DELIVER the CVE's input to it** (`KnownComponentCVE.vector`, `CARRIABLE_VECTORS`). → `docs/methodology/sca-catalogue-breadth.md`
87. **When the payload's effect outlives the request, the CONTROL runs first** (`_run_control_arm_first`) — a control dispatched afterwards observes the change the payload made and kills the true positive it exists to license.
88. **A class whose effect outlives the RUN is TERMINAL, dispatched last, and a transient task after one is a stop-the-run condition** (`TERMINAL_DISPATCH_CLASSES` / `TRANSIENT_DISPATCH_CLASSES`; `assert_terminal_dispatch_order`).
89. **A change TESTING made that the target cannot undo is stated in the client-facing document, naming the key** (`ResidualMutation`) — recorded on the WITNESSED effect, on every landed write whichever arm made it. → `docs/methodology/prototype-pollution.md`
90. **A write is a crossing when a SEPARATE read attributes the persisted object to another principal** (`agents/_write_crossing.py`) — never the status code, never the create's own body. → `docs/methodology/write-crossings.md`
91. **"The POST set no cookie" has TWO causes and a boolean collapses them** — an empty `Set-Cookie` delta beside a non-empty carried jar is `INDETERMINATE` (`LoginVerdict`) and DEFERS to `assert_authenticated`, bounded by `_session_survived`. → `docs/methodology/authentication-shapes.md`
92. **A credential POST is bounded by the component that can see it, and the stop the TARGET declares outranks the budget WE assumed.** → `docs/methodology/credential-attempts-and-lockout.md`
93. **An absence that holds only up to N is reported WITH N, and N is ours** (`attempt_ceiling`). → `docs/methodology/brute-force.md`
94. **A verdict rule with no correct live firing is a dead instrument, and the corpus decides which.** → `docs/methodology/authentication-shapes.md`
95. **A measurement that refused itself is not a clean result, and a truncated sweep is not a negative.**
96. **A bound the budget cannot SEE bounds nothing, so every credential sender is classified.** → `docs/methodology/credential-attempts-and-lockout.md`
97. **A scope entry that names a port BINDS that port** (`models/scope.py::declared_port` / `_port_binds`). → `docs/productization-engagement-safety.md`
98. **The authentication path gets the control arm the exploit path already has.** → `docs/methodology/authentication-shapes.md`
99. **A remedy the run's own observations contradict is worse than no remedy.**
100. **A marker that survives an UNBLOCKED response is the application's own vocabulary, not evidence of blocking** (`safety/governor.py`).
101. **A zero measured over PART of the input is INDETERMINATE, never NOT APPLICABLE** (`agents/_package_identity.py`).
102. **A destination composed at runtime is not a reading problem, so the model PROPOSES and `assert_authenticated` DECIDES** (`engagement/auth_agent.py`), from two call sites both guarded by "no session was seated". → `docs/methodology/adaptive-authentication.md`
103. **Session material has TWO carriers, and the response declares which** — a `Set-Cookie` or a body token (`DispatchResponse.session_headers`). → `docs/methodology/adaptive-authentication.md`
104. **A gate refuses to grade evidence it does not hold, and an absent measurement is never a permissive one.**
105. **A tool execution that leaves no invocation record is an unauditable run, and every execution mode is asserted to emit** (`tools/base.py::_emit_trace_records` / `_emit_inprocess_invocation`). → `docs/observability.md`
106. **A bound that selects by SPELLING lets the alphabet decide coverage** (`agents/_api_schema.py::_select_routes`). → `docs/analysis/probe-bound-ordering.md`
107. **Registered, dispatched, and never able to begin is its own state.** → `docs/analysis/business-logic-verdict-trace.md`
108. **A transformation applied to a whole structure distinguishes the structure's own vocabulary from the content it carries** — a KEY is schema, a value is data, and a walk that never asked has answered "content" (`engagement/secrets.py::_redact_key`).
109. **A gate that needs evidence only passing the gate can produce is its own state — UNREACHABLE PRECONDITION, not unexercised and not not-applicable.**
110. **A registration is scoped to WHERE the secret can appear, and a credential that spells the engine's own schema is refused at INTAKE.**
111. **A verb the engine could not READ is its own state, never a GET it measured** (`models/scan.py::MethodEvidence`; `NAMED` / `PLATFORM_DEFAULT` / `UNREAD`).
112. **A call site we SAW and could not address is a third state, and a route the source DECLARES is a different fact from a call it MAKES.**
113. **The target may not author the structure of the document that judges it** (`engagement/render_safety.py`).
114. **A pattern-based exclusion fails toward LESS output, so it needs a DENOMINATOR control, not a shape control.**
115. **A regression check compares SETS, not counts** — every pair a baseline CONFIRMED must be PLANNED later, else `truncated`/`absent`; no record ⇒ NOT DETERMINED. → `docs/analysis/r29-write-crossing-candidate-set.md`
116. **A session the operator SUPPLIED is proven by the same assertion and never trusted** (`RoleCredential.session`). → `docs/productization-engagement-safety.md`
117. **A credential goes only to a destination something OBSERVED to be a login** — a rendered password form's action, an operator declaration, or a route the adaptive layer proved. → `docs/productization-engagement-safety.md`
118. **"The credentials are wrong" requires a refusal ATTRIBUTABLE to the credential** (`credential_refused`: a 401, or a marker the control lacks), and quotes it.

## Pre-Push Verification (four gates; never bypass — no `--no-verify`, no blanket `# noqa`/skip)

1. **Lint + cleanup** — `ruff check src/ tests/` and `ruff format --check src/
   tests/`. Clean every file the diff touches (dead code, naming, stale comments,
   `None` guards, no hardcoded secrets). CI pins `ruff==0.15.22`, and a `ruff` on
   PATH is routinely an OLDER build reporting a different set — invoke the pinned
   one explicitly. **The whole dependency set is locked**: CI runs
   `pip install -c requirements-ci.lock -e ".[dev]"` then asserts it with
   `python scripts/lockfile.py --check`. Regenerate with
   `python scripts/lockfile.py --generate` and commit the result.
2. **Keyless test gate** — **clear the provider keys** so the run is actually
   keyless (`config.py` calls `load_dotenv()` at import, so a present `.env` makes
   `test_exploit_v2` issue LIVE Anthropic calls — LESSONS #35):
   `ANTHROPIC_API_KEY="" GEMINI_API_KEY="" GOOGLE_API_KEY="" OPENAI_API_KEY=""
   pytest tests/ -q --tb=short
   --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop
   --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration`.
   Capture pytest's own exit code directly (`… > out.txt 2>&1; echo "EXIT=$?"`) —
   never pipe through `tail`/`&&` (LESSONS #24). Run the container gate
   (integration + the `dvwa_smoke`/`juiceshop_smoke`/`pipeline_smoke` suites)
   separately when containers are up and the change touches
   scan/exploit/orchestrator paths.
3. **Security review** — `/security-review` on the diff when it touches `tools/`,
   scope, credentials, LLM I/O, HTTP/network/subprocess, deserialization,
   user-path file I/O, MCP, or report rendering. Resolve every finding.
4. **Context budget** — `python .claude/hooks/context_budget.py`. Every
   always-loaded instruction file must stay under its character budget.
   **This gate is the one gates 1–2 may not be skipped alongside**: doc-only edits
   are what grow these files, and the failure it prevents is silent. `CLAUDE.md`
   reached **152,205 characters against a ~150k load limit**, and that bound
   degrades by *truncating quietly* — the first symptom would have been rules not
   in effect. **A bound that degrades quietly is not a bound.** The domain is
   **computed** (every `CLAUDE.md` in the tree, plus `.claude/LESSONS.md`), so a
   new always-loaded file cannot escape it.

Doc/config-only changes (no `.py` modified) may skip gates 1–2. **Gate 4 never
skips** — a doc-only change is exactly the change it guards. Gate 3 still applies
if runtime behavior can change (new hook, permission, tool entry, payload).

## Important Rules (NEVER)

- Import a provider LLM SDK outside `llm/`; hardcode API keys (env vars via
  python-dotenv); scan outside scope (every tool validates scope first).
- Have agents communicate directly — all comms through the Orchestrator.
- Hardcode a tool name in agent code — describe the capability, let the resolver
  find it.
- Hardcode a target/benchmark value in a methodology (no DVWA/Juice Shop string
  baked in) — discover the app's own tokens at runtime.
- Grow this file with narrative. A new invariant writes its headline here in one
  line, its full text in `docs/invariants-rules.md` and its story in
  `docs/invariants.md` — that is what keeps gate 4 green.

Tool outputs are always parsed into Pydantic models (tested against real output in
`tests/fixtures/`); agent system prompts live in `prompts/` `.md` files; run the
pre-push gates before every `git push`, and push after committing.
