# Clinkz — Agentic AI Penetration Testing System

An autonomous, multi-agent AI system that performs end-to-end black-box
penetration testing: it takes a target scope (IPs/domains) and produces a
professional pentest report, no human in the loop. Agents collaborate through an
LLM-mediated Orchestrator, discovering and running tools dynamically.

> **This file is the lean operating core, loaded every session.** Per-methodology
> forensic history → [`docs/methodology/`](docs/methodology/README.md) (one file
> per class); gray-box discovery-engine detail → `docs/discovery-engine-*.md`;
> engagement setup / authenticated scanning / safety rails →
> [`docs/productization-engagement-safety.md`](docs/productization-engagement-safety.md);
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
  **The phase budgets its own wall clock** (`SCAN_TIME_BUDGET`, default 900 s):
  the orchestrator's phase timeout is a force-kill that DISCARDS the agent's
  return value, so an over-running scan delivers not a smaller attack surface but
  **none** — coverage expansion and enrichment stop instead, and the partial map
  is returned and named in the coverage gaps.
  **API surface discovery** (`agents/_route_discovery.py`) unions four
  discoverers into `HTTPScanResult.endpoints` (additive; param structure via
  `ParamLocation`), and **none of them carries any application's vocabulary** —
  a hardcoded endpoint/body/route-word table reports the same surface whether or
  not the target has it, which is recall, not discovery:
  `JSCallSiteDiscoverer` reads the frontend's own **HTTP call sites**
  (`agents/_js_api_mining.py` — fetch/XHR/axios/HttpClient/navigation → method,
  URL template, query params, body shape, resolving minified class-field
  bindings backwards from the call site and scoping a body shape to its
  enclosing function); `StaticBundleDiscoverer` (route literals under the
  conventional `api`/`rest` prefixes); `OpenAPIDiscoverer`; `GraphQLDiscoverer`
  (introspection when open, **recorded as disabled** when not — never guessed).
  What the source cannot say is learned from the live target with **safe methods
  only** (`agents/_api_schema.py`): `OPTIONS` for a resource's `Allow` (never
  `Access-Control-Allow-Methods`, a blanket CORS policy that manufactured 105
  phantom endpoints), and a collection's own `GET` representation for the fields
  its writes accept. A `{}`-POST schema probe is deliberately **not** built: it
  CREATED records on the live target. The login body comes from the shape the
  **authenticator proved**, the one schema no other source can reach.
  **Probe-safety** (`_url_safety.py`) never mutates the
  target while mapping it: `is_state_changing_url` gates navigation (WAF toggle,
  logout — the shared engagement session must never be poisoned) and
  `is_destructive_form_submission` gates submission (credential/account mutation,
  destructive verbs). Enrichment opens a bounded number of discovered URLs; WHICH
  ones is `_url_shape.crawl_visit_priority` (application pages before assets,
  viewers and doubled-path artifacts), never the crawler's emission order, and it
  records the **response features** each page showed — `Endpoint.sets_cookies`
  (cookie NAMES only; a value is authentication material) and `has_form` — which
  are the observations the Exploit planner's class preconditions rank on.
- **Research (v2)** — Gemini 3.1 Flash-Lite (GA), pinned via
  `GEMINI_RESEARCH_MODEL` (never `-preview`). Live web research via native Gemini
  Search Grounding + NVD structured CVE data. Runs concurrently with Scan/Exploit;
  rate-limit aware (`GEMINI_MAX_RPM` default 30, `RESEARCH_TIME_BUDGET` default
  180s). Persists to the engagement runbook AND `clinkz_knowledge.db`.
- **Exploit (v2)** — Anthropic Claude Opus (`LLM_PROVIDER_EXPLOIT=anthropic`). LLM
  plans exploits from scan+research → deterministic `_test_*` methods by tier →
  LLM reasons through results → adaptive retry/bypass → records capability outcome
  to the persistent KB. **P7** (`src/clinkz/browser/`, disabled by default via
  `CLIENT_ORACLE_MODE`) is the client-side execution oracle the DOM-XSS,
  client-rendered XSS and CSP classes confirm through. All 19 `_test_*` methods are adaptive multi-phase
  methodologies (six-phase injection family; four-phase behavioral family). The
  **deterministic check GATES the LLM** — no LLM verdict emits on its own; when
  phase-2 has empirically confirmed the primitive, phase-4 prefers the
  deterministic build. **Per-methodology detail (oracles, phantom fixes,
  live-validation, N/A-by-construction) →
  [`docs/methodology/`](docs/methodology/README.md).**
- **Critic** — validates findings before the report (CVSS, FP elimination,
  evidence, repro); can reject back to Exploit.
- **Report** — zero LLM calls; emits JSON + a Markdown summary from the state
  store in <30 s. Client-ready header (authorization record verbatim, window,
  in-scope AND out-of-scope, authentication proof, testing conduct), remediation
  attached per class from `models/vuln_classes.py`, and a generated **"What was
  NOT tested"** section (excluded hosts, unauthorized techniques, classes with no
  client-side oracle / no methodology, safety-rail refusals, any halt) — built
  from the registry and the run's own action log so it cannot drift. Findings and
  **research-leads are separate types in separate fields**: `CrossServiceResearchLead` (unproven A→B chains) and
  `UnprovenExploitLead` (single-service, effect not witnessed) render in their own
  UNCONFIRMED sections and are never counted in the totals.

## Engagement Setup + Production Safety (`src/clinkz/engagement/`, `src/clinkz/safety/`)

The layer that makes a run against a **non-benchmark** target possible. **Full
detail → `docs/productization-engagement-safety.md`.**

- **The gate** (`engagement/gate.py::open_engagement`) is the FIRST statement of
  `OrchestratorAgent.run()` — before docker, before state, before a packet. No
  `AuthorizationRecord` (authorizing party + role + contact, authorization
  reference, permitted techniques, emergency contact; every field required, no
  partially-populated shape) ⇒ refusal, with no flag to skip it. An
  `EngagementWindow` is a hard stop re-checked on every request.
- **Credentials are never on `EngagementScope`** — the scope is `model_dump()`-ed
  into the state store, so keeping the `CredentialSet` off it is structural, not
  disciplinary. `SecretStr` passwords; git-tracked credential files are refused
  outright; `engagement/secrets.py` is the redaction chokepoint every artifact
  writer runs through — **including the report**, which used to be the one
  writer that did not (short-secret limit stated, not hidden).
- **Redaction removes what a secret IS and what it LOOKS LIKE.** Value-only
  redaction cannot remove credential material the engagement *captures* rather
  than the operator *supplies* — a session token the target issued was never
  registered. `engagement/credential_shapes.py` is the **one shape vocabulary**
  (JWT gated on a decoding header, `Authorization`/`Cookie`/`Set-Cookie` values,
  vendor keys, PEM blocks), always on, registry or not. A token becomes a
  **fingerprint** — salted hash prefix + `alg`/`iss`/`sub` + claim NAMES — which
  correlates within a bundle and replays nowhere. Cookie NAMES survive, cookie
  VALUES do not. `redact_structure` is **key-aware**, because a `Set-Cookie`
  value has no intrinsic shape and only the key identifies it.
- **`engagement/artifact_scan.py` is the disclosure gate**, run automatically
  after every writer has flushed: it re-reads `outputs/<id>/` off disk and
  refuses to certify the bundle on the strength of the logic that wrote it. **A
  guarantee asserted by the same logic that produces it is not checked at all** —
  the previous check searched for *configured* secret values and truthfully
  reported zero leaks about the wrong question. Definite shapes FAIL the run
  loudly (`DO NOT SHARE`); the entropy heuristic is advisory-only and lives ONLY
  in the gate — an entropy rule on the write path would shred evidence made of
  alarming-looking strings, and a gate that cried wolf would be ignored. The scan
  report never reproduces what it found. `clinkz artifact-scan <id>` re-runs it
  over any bundle and exits non-zero.
- **Authenticated state is PROVEN, not assumed** (`engagement/auth_state.py`).
  The same URL is fetched with the session and deliberately without it
  (`HTTPClientTool`'s `no_session` — the shared cookie jar would otherwise make
  the "anonymous" control carry our own session), and only a boundary
  discriminator is accepted: login redirect, status class, login form, session
  marker, identity echo. **A body-length delta is a correlate and is refused.**
  Credentials supplied + assertion failed ⇒ the engagement aborts loudly.
  `SessionSentinel` rides the governor's response observers, because the code
  that lost the session is the code that will not notice.
- **Only a session-bearing response is evidence about the session.** The HTTP
  chokepoint is the only code that knows whether a request carried the session,
  so it passes `session_bearing` through `observe_response`; a session-free
  response is ignored in BOTH directions (it neither counts as a loss nor resets
  a streak). Without it the sentinel reads the engine's own anonymous control —
  whose 401 *is the proof the session works* — as proof the session broke.
  **The raised flag is a hypothesis; `assert_authenticated` is the oracle**: the
  Orchestrator re-proves the session before re-authenticating, records a false
  alarm when it survives, and counts `reauthentications` on **success only** (it
  used to count the attempt, before anything was tried). Consecutive-counting
  alone cannot survive a concurrent phase — any interleaved 200 resets it — so a
  scattered-loss `escalation` ceiling also earns one check.
- **The rails are absent by default** — `get_active_governor()` is `None` unless
  an engagement installed one and every hook no-ops, so direct methodology
  invocation (smoke suites, replays, drivers) is byte-identical. The governor
  (`safety/governor.py`) owns rate (5 req/s), concurrency (4), the kill switch
  (`clinkz abort` → `outputs/<id>/HALT`), blocking detection, the window, and the
  action log. **It never raises from the data path** — it returns a refusal the
  callers already handle; `_run_phase` polls `halted` and winds down so the
  report is still produced.
- **`safety/destructive.py` is the one destructive vocabulary**, consulted by
  both `is_state_changing_url` (navigation) and `is_destructive_form_submission`
  (submission), over path + method + field names + label text. The predecessor's
  rules are preserved verbatim, so it can only refuse MORE. **A parameter VALUE
  is read for semantics only when it looks like an identifier the APP chose**
  (`_PLAIN_VALUE`) — our own payloads carry `drop`/`rm`/`passwd`, and reading
  them back as application semantics would refuse the engine's own probes and
  silently reduce an authorized engagement to a crawler.
- **`_run_subprocess` gets the halt check ONLY** — it is reached from inside the
  HTTP chokepoint, so a second slot per request would deadlock the semaphore and
  double-count every rate token. Self-flooding tools are paced by their own flags
  (`ffuf -rate`).
- **The permitted-technique list gates dispatch**, refused before the page fetch,
  and every withheld class is named in the report.
- **`models/vuln_classes.py` is the client-facing class registry** (label,
  capability, limitation, remediation), asserted in sync with the Exploit Agent's
  dispatch table: a class it dispatches but the registry has never heard of is
  BOTH invisible in the report and ungated by authorization.

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
  outside `llm/`. Backends: Anthropic (Exploit pinned; Orchestrator primary),
  Gemini (Recon/Scan/Report/Research; `gemini-3.1-flash-lite` GA, never `-preview`),
  OpenAI (fallback tail), Ollama (stub). Per-agent overrides via
  `LLM_PROVIDER_<AGENT>`; `ResilientLLMClient` rotates providers on
  rate-limit/timeout. **Operation-level timeouts** (per HTTP request, tool
  subprocess, and LLM call via `LLM_REQUEST_TIMEOUT`) are the safety valve — the
  exploit phase has no wall-clock deadline by default.
- SQLite: `clinkz.db` (per-engagement state), `clinkz_knowledge.db` (cross-
  engagement KB incl. Layer-2 `capability_facts`/`capability_observations`).
- **Playwright + Chromium** is an OPTIONAL extra (`pip install -e '.[browser]' &&
  playwright install chromium`; baked into `docker/Dockerfile.tools`) backing the
  P7 oracle. Optional on purpose: absent, the affected classes record unproven
  leads exactly as before.
- MCP Python SDK for tool servers; Docker for sandboxed tool execution
  (`clinkz-tools`; `TOOL_EXEC_MODE=local` for the in-process HTTP path).
- Typer CLI; `clinkz trace inspect <engagement>` renders execution traces.

## Project Structure (key paths)

```
src/clinkz/
├── cli.py            # Typer CLI: scan / abort / actions / artifact-scan / trace inspect /
│                     #   tool-invoke / step-replay
├── config.py         # Settings (env vars, per-agent LLM overrides)
├── state.py          # SQLite state + message store; findings + research_leads
├── orchestrator/     # OrchestratorAgent, lifecycle, prompts
├── agents/           # recon, scan, exploit, research, critic, report, _route_discovery,
│                     #   _js_api_mining (what does the frontend CALL?), _api_schema
│                     #   (what does the live target ACCEPT? — safe methods only),
│                     #   _json_body (addressing a field INSIDE a structure),
│                     #   _url_safety (may we fetch it?), _url_shape (in what order?)
├── engagement/       # gate (the refusals), secrets (credentials + redaction chokepoint),
│                     #   credential_shapes (what a secret LOOKS like — one vocabulary,
│                     #   shared by the redactor and the gate), artifact_scan (the
│                     #   disclosure gate over outputs/<id>/),
│                     #   auth_state (detect / PROVE / maintain), dryrun
├── safety/           # destructive (default-deny classifier), governor (rate, concurrency,
│                     #   kill switch, blocking, window), action_log
├── comms/            # AgentMessage, async bus, protocol
├── discovery/        # Δ-model: ingestor(s), catalog, intent, reachability, hypothesis, engine,
│                     #   topology(+recall), recall, relations, versions
├── knowledge/        # KnowledgeBase, persistent_kb, seeders, MITRE/OWASP datasets, payloads
├── llm/              # base, factory, fallback, {anthropic,gemini,openai,ollama}_client
├── tools/            # ToolBase, resolver, mcp_client, auth, http_client, nmap/ffuf/…
├── oob/              # P6: templates (exfil guardrail), collaborator (receive-only)
├── browser/          # P7 client-side execution oracle: templates (witness carrier),
│                     #   witness (the verdict — page text NEVER decides), csp_policy
│                     #   (what a served policy leaves reachable), oracle (Playwright)
├── observability/    # trace.py (JSONL), replay.py
└── models/           # scope, engagement (authorization/window/credentials/policy),
                      #   vuln_classes, target, recon, scan, methodology, research,
                      #   finding, report
docker/  scripts/  tests/  docs/
```

## Commands

- `python -m clinkz scan --target <domain> --scope <scope.json>
  --authorization <auth.json> [--credentials <creds.json>] [--dry-run]
  [--rate N] [--max-concurrency N]` — full pentest (recon → scan/research/
  exploit → report). The only end-to-end command. **Refuses to start without an
  authorization record**; `--dry-run` enumerates what it WOULD do and sends
  nothing.
- `python -m clinkz abort <engagement_id>` — kill switch: halt immediately and
  cleanly (the report is still produced).
- `python -m clinkz actions <engagement_id> [--outcome sent|refused] [--raw]` —
  every state-changing request the run produced: "what did it do to my app?".
- `python -m clinkz artifact-scan <engagement_id> [--raw]` — the disclosure gate,
  re-run by hand: does this bundle still carry credential material? Exits
  non-zero if so. Runs automatically at the end of every engagement.
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
- **A body field is a PATH, not a name** (`agents/_json_body.py`) —
  `config.app.name`, `items[0].sku`. Written into place with `set_json_path`, so
  the body that goes out has the shape the target declared; only **leaves** are
  written (replacing a container destroys the object holding the field under
  test) and **every sibling keeps a benign value** — an endpoint that validates
  its input rejects a body whose unrelated fields were blanked or dropped, and a
  rejected request never reaches the sink. The G8 form rule, generalized to
  structure. On the response side the echo guard undoes **JSON** escaping too (a
  JSON API re-encodes the payload on the way out, so `<` returns as `<` and
  the guard cannot otherwise find the echo it exists to blank), and
  `locate_in_body` reports *where* a marker landed — `data[0].comment` is a
  stored record, `errors[0].msg` is the API quoting us back.
- **Surface mapping never writes to the target.** Every API schema learner takes
  a probe restricted to `GET`/`HEAD`/`OPTIONS`, asserted at the seam. The
  rejected alternative is instructive: a `{}`-POST read for its validation error
  answered `201 Created` on two of six live endpoints and *created an account*
  during discovery, for one field name.
- **Stack-conditioned branches** (`_is_php_stack`, engine fingerprints, dialect)
  are backed by a deterministic protocol artifact (a `PHPSESSID` cookie, a `.php`
  path, a header) — never the flaky LLM tech list alone (LESSONS #28).
- **P7 confirms a CLIENT-SIDE effect, and only ever PROMOTES**
  (`src/clinkz/browser/`, **detail →
  [`docs/methodology/client-side-execution-p7.md`](docs/methodology/client-side-execution-p7.md)**).
  A Clinkz-minted single-use nonce returns **by a call from inside the page's JS
  context** to a Clinkz-owned in-page binding, while a second nonce minted
  alongside and **injected nowhere** stays silent — inert reflected bytes cannot
  call a function, which is the confounder that made every prior DOM-XSS
  "confirmation" a phantom. The channel is a function call, **not** a network
  callback, because `connect-src` is governed independently of `script-src` and a
  beacon would report "did not execute" about a page that did. `bypass_csp` is
  asserted OFF and recorded, so a CSP finding answers *did script execute under
  the served policy*. **Everything the page authors is evidence, never a verdict
  input** — `WitnessVerdict.decide()` reads three engine-owned booleans, so a
  console line saying "Refused to execute" cannot suppress a witnessed execution.
  Disabled by default (`CLIENT_ORACLE_MODE`), resolved by **capability**; absent,
  broken or out-of-budget ⇒ the `UnprovenExploitLead` stands unchanged. **A
  missing browser costs coverage, never honesty**, and there is no path from a P7
  verdict to demoting or suppressing anything.
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
  a confirmed finding. Four shapes can never confirm, in any methodology: a
  **conditional execution claim** (speculation about an unobserved downstream
  transform), a **reflection inside a framework error page** (reachability, not
  an executable context), a **check that determines it is not applicable**
  (which returns no finding, never one whose title says "not applicable"), and a
  **description of a client-side control** — that the page computes a token in
  JS is reachability; the effect is the server ACCEPTING a value we rebuilt from
  the page's own chain while rejecting an equal-shaped control. **Whether the
  confirming attempt runs is never the LLM's call** — gate it on a deterministic
  signal, or the class's only reachable outcome is the description
  ([client-side-logic](docs/methodology/client-side-logic.md)).
- **The suppression runs the same direction as emission: an LLM never overrules a
  deterministic oracle.** The FP cross-check may demote ONLY by naming a
  deterministic **contradiction in the evidence** that the code itself verified
  (`_fp_deterministic_contradiction` — an encoded character the payload needed,
  malformed/self-inconsistent evidence, a speculative execution claim, an
  error-page reflection, or an observation that merely restates the rationale). "The
  differential is small" and "this looks like a false positive" name no
  contradiction and demote nothing. Emission-side and suppression-side are the same
  rule: **a deterministic signal decides, in both directions.** The mechanism ground
  is additionally applied at the emission chokepoint (`_persist_finding`), so a
  candidate whose observation merely restates its own rationale is a lead whether or
  not a reviewer noticed it.
- **A veto that reads the model's PROSE applies only to an effect nobody
  witnessed.** A speculative-execution claim ("if a later layer decodes this, it
  executes") contradicts nothing once the deterministic side has seen the payload
  land byte-for-byte in an executable position — and prose varies run to run
  while a measurement does not, so such a veto over a measurement is a coin flip
  that drops live vulnerabilities. Phase 5 records the witness
  (`literal_landing_witnessed`); the gate and the FP cross-check both read it,
  and a skipped veto is logged and traced (`prose_veto_overruled_by_witness`) —
  the suppression that did not happen is as auditable as one that did.
- **An execution-type branch is a CLAIM, and it confirms only on the observation
  that proves ITS effect** — a family whose branches share one verifier drifts
  into confirming the weakest of them. Each upload branch declares
  (effect, proving observation) in `_FILE_UPLOAD_BRANCH_EFFECT`; only branches
  this engine can actually observe may confirm (`_FILE_UPLOAD_CONFIRMABLE_TYPES`),
  the rest emit leads naming both halves. And a branch that cannot prove its
  effect must never **pre-empt** one that can: the LLM ranks within each half,
  the confirmable half runs first, so which branch is tried is the model's call
  and whether the class may confirm is not.
- **A thin-but-real measurement carries its own control** — a differential is
  proof when it is *reproducible*, not when it is large. The boolean-blind oracle
  sends baseline/true/false as one interleaved triple, repeats it, requires the
  signed delta identical in every repeat, and renders all of it into the evidence.
  Strengthen the proof rather than loosen the gate.
- **Attack the handler, not the listing** — an endpoint whose response is its own
  script source is refused as an exploitation target at the dispatch chokepoint
  (`_serves_own_source` in `_execute_task`). Decided on **what came back**, never
  on the path: a path fragment is not evidence about a route, and grading a bare
  `/source/` segment as noise once cost a real finding.
- **A deterministic observation gates the LLM's list, not just its verdict** — a
  posture/analysis entry contradicted by what we actually observed (a header
  reported missing that is present) is dropped, and severity is recomputed from
  the surviving set.
- **Coverage truncation is never silent** — the plan cap is loud (per class:
  how many candidates were dropped and the first omitted endpoint), each class's
  bucket is ordered by relevance to *that* class, and every applicable class is
  guaranteed one task before the cap applies. A drop on an endpoint carrying the
  class's **own** surface, while lower-relevance tasks survive, is logged
  separately as a **RANKING FAILURE**: an ordering defect reads nothing like
  tail truncation and must not hide inside it.
- **The plan order is a function of the endpoint SET, never of the crawl's
  order** — a concurrent crawler emits a different sequence each run, so any tie
  broken by traversal order makes the engagement non-reproducible. Ranking scores
  a **(class, endpoint) PAIR** on three class-specific signals — a parameter of
  the shape the class attacks, an **observed** precondition it needs
  (`Endpoint.sets_cookies` / `has_form` / `session_setters`), and a path naming
  its surface — then breaks ties on how many matched, then on generic surface
  value, then on the endpoint's structural identity. Every Tier-1 class carries
  signals (`_CLASS_PATH_TOKENS` / `_CLASS_PARAM_NAMES` / `_CLASS_PRECONDITIONS`);
  a class with no entry ranks on nothing and its answer hides in a tie bucket.
  Same rule for the crawl's enrichment budget (`crawl_visit_priority`) and for
  which duplicate represents a collapsed route. **A class with a task is not a
  class that can fire** — the floor reserves its best endpoint even when the LLM
  named that class somewhere worse.
- **`verification_strength` decides emission, and it is a closed vocabulary** — a
  methodology's own `"likely"` means the defining effect was NOT witnessed, while
  `_make_finding` stamps `CONFIRMED` unconditionally, so a `likely` result
  reaching an emit is a finding that contradicts itself in its own evidence.
  Classified explicitly in both directions
  (`_CONFIRMING_VERIFICATION_STRENGTHS` / `_NON_CONFIRMING_…`; a test fails on any
  unclassified literal), enforced per class AND at `_persist_finding`.
- **A guard never parses text the target controls** — evidence entries hold raw
  response bytes, and a value read out of them is a value the *host under test*
  can choose. `_evidence_strength` reads only fully-structured `key=value`
  entries, so a page echoing `strength=likely` cannot suppress a genuine finding.
  A suppression primitive handed to the target is worse than the phantom the
  guard prevents.
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
