# Clinkz — Agentic AI Penetration Testing System

An autonomous, multi-agent AI system that performs end-to-end black-box
penetration testing: it takes a target scope (IPs/domains) and produces a
professional pentest report, no human in the loop. Agents collaborate through a
central Orchestrator on a deterministic phase sequence, discovering and running
tools dynamically.

> **This file is the lean operating core, loaded every session.** Per-methodology
> forensic history → [`docs/methodology/`](docs/methodology/README.md) (one file
> per class); gray-box discovery-engine detail → `docs/discovery-engine-*.md`;
> engagement setup / authenticated scanning / safety rails →
> [`docs/productization-engagement-safety.md`](docs/productization-engagement-safety.md);
> what the deliverable may CLAIM (testing window, authentication state, control-arm
> rows, IDOR evidence, cost) → [`docs/report-integrity.md`](docs/report-integrity.md);
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

## Agents

- **Orchestrator** — coordinator. Anthropic primary, like every other role under
  routing v2 (**detail → [`docs/provider-routing.md`](docs/provider-routing.md)**).
  Delegates all tool work.
- **Recon (v2)** — Anthropic (`LLM_PROVIDER_RECON=anthropic`). Full TCP scan → LLM
  analyses ports → service/version detection → LLM extracts tech stack →
  web-specific recon → **package identity** → LLM synthesizes → `ReconResult`.
  Tools always via `ToolResolver.find_tool(capability=...)`.
  **`agents/_package_identity.py` is the third component source, and it names
  PACKAGES where the other two name SERVERS.** `whatweb` reads headers and page
  markers, `nmap -sV` resolves a banner through its signature database, and
  neither has ever emitted a row called `lodash` — so the five dependency-SCA
  entries in `component_cves.py` had no possible producer and their zeros were
  never an observation about a target. It reads npm lockfiles and exact
  manifest pins from a supplied `--source` tree (`LOCKFILE` / `MANIFEST`) and
  the license/coordinate strings baked into the bundles the target itself
  served (`ARTIFACT_STRING`), declaring through the same
  `detected_components()` contract the fingerprinters answer — a second
  inventory path is the `hasattr(r, "technologies")` seam again, so the
  producer declares rather than the consumer guessing. A dependency **range**
  is deliberately not read: `^4.17.20` is what was asked for, not what arrived,
  and reading its floor as an observation is the fabrication the whole path
  refuses.
- **Scan (v2)** — Anthropic. LLM plans strategy → service-specific methods
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
- **Research (v2)** — Anthropic, like every role under routing v2. **Its answers
  are therefore NOT web-grounded by default, and that is stamped rather than
  absorbed.** It led with Gemini Flash-Lite for exactly one reason — native
  Search Grounding — and the Anthropic path has no equivalent, so a research
  answer is a recollection of a training corpus: every CVE disclosed after the
  serving model's cutoff is invisible, with no signal in the text that anything
  is missing. `LLMClient.RESEARCH_GROUNDING` is declared by every client,
  `ResilientLLMClient.research_grounding()` reports the provider that ANSWERED,
  `ResearchResult.grounding` is the WEAKEST grounding any call in the phase ran
  under, every runbook `Technique` carries it (a runbook entry persists to the
  cross-engagement KB, so the caveat must outlive the run), and the report
  renders a *Research grounding* section either way — stating explicitly that
  the limitation does not reach the findings, since a CVE from research is a
  LEAD that must reach one of our own oracles. `undeclared` counts as
  ungrounded. NVD structured CVE data is a separate feed and is unaffected.
  Runs concurrently with Scan/Exploit; rate-limit aware (`GEMINI_MAX_RPM`
  default 30 when it falls back, `RESEARCH_TIME_BUDGET` default 180s). Persists
  to the engagement runbook AND `clinkz_knowledge.db`.
- **Exploit (v2)** — Anthropic (`LLM_PROVIDER_EXPLOIT=anthropic`), on whatever
  `ANTHROPIC_MODEL` resolves to — `claude-sonnet-5` by default. **Not Opus**: this
  line said Opus and no configuration ever selected it. LLM
  plans exploits from scan+research → deterministic `_test_*` methods by tier →
  LLM reasons through results → adaptive retry/bypass → records capability outcome
  to the persistent KB. **Phase 3 — which exploitation types a parameter is worth
  attempting — is `agents/_plan_ranking.py`, not the model's to answer alone**
  (**detail → [`docs/methodology/plan-ranking.md`](docs/methodology/plan-ranking.md)**). **P7** (`src/clinkz/browser/`) is the client-side
  execution oracle the DOM-XSS, client-rendered XSS and CSP classes confirm
  through. It runs **where the target is reachable**: in docker tool-mode the
  browser is driven inside `clinkz-tools`, because
  `resolve_target_for_docker_mode` has rewritten the target to a
  container-network alias a host browser can neither resolve nor route to.
  `CLIENT_ORACLE_MODE` is `auto` by default — the Orchestrator provisions it for
  every engagement, while a **directly invoked** agent (unit suite, replay,
  smoke cell) never self-resolves one, so the black-box floor stays
  byte-identical. All 24 `_test_*` methods are adaptive multi-phase
  methodologies (six-phase injection family; four-phase behavioral family). The
  **deterministic check GATES the LLM** — no LLM verdict emits on its own; when
  phase-2 has empirically confirmed the primitive, phase-4 prefers the
  deterministic build. **Per-methodology detail (oracles, phantom fixes,
  live-validation, N/A-by-construction) →
  [`docs/methodology/`](docs/methodology/README.md); the five Phase-3 classes and
  the control each confirms against →
  [`docs/methodology/phase3-new-classes.md`](docs/methodology/phase3-new-classes.md);
  what a real affected-range predicate would cost, and which Band A shapes have
  an oracle waiting with no catalogue entry to feed it →
  [`docs/methodology/sca-catalogue-breadth.md`](docs/methodology/sca-catalogue-breadth.md);
  chaining + business logic + the benchmark profile →
  [`docs/methodology/chaining-and-business-logic.md`](docs/methodology/chaining-and-business-logic.md).**
- **Chaining (`src/clinkz/chaining/`)** — a first-class capability, not a
  post-processing pass. A chain is an ordered composition where step N's OUTPUT
  becomes step N+1's INPUT, graded by its WEAKEST link (`compose_soundness`,
  reused from cross-service, not reinvented), emitted CONFIRMED only when EVERY
  link is independently confirmed by a P1–P7 oracle. Runs after the FP pass, so a
  demoted finding can never head a chain, and it **only ever ADDS**: a chain is a
  new finding alongside its components, which keep the severity their own oracles
  gave them. Every SSRF so far proved the FETCH and stopped; pointing the same
  channel at an internal address is the second observation that turns a primitive
  into an incident.
- **Business logic** (`agents/_business_logic.py` + three `_test_*` classes) — Δ
  where the developer's intent is the APPLICATION. Intent is inferred from the
  app's own surface and every finding states the intent, its EVIDENCE, and the
  observation exceeding it.
- **Critic** — **archived** (`agents/_archive/critic.py`). It was registered in
  the lifecycle manager, described here as validating findings before the report,
  and invoked in **0 of 2,774 recorded agent steps**: registration made it
  constructible, never called. Its stated job is done by deterministic gates on
  the emitting path — the FP cross-check + `_fp_deterministic_contradiction`,
  `verification_strength` enforced at `_persist_finding`, CVSS computed in the
  report — and an LLM reviewer after those could only overrule them, which the
  invariants forbid in that direction.
- **Report** — zero LLM calls; emits JSON + a Markdown summary + **the PDF
  deliverable** (`agents/_report_pdf.py`, ReportLab) from the state store in
  <30 s. **All three documents render from the SAME redacted structure** — the
  dump goes through `redact_structure` (key-aware, so a `Set-Cookie` value
  is removed on the strength of its key) and is validated back into a
  `PentestReport` that the Markdown and PDF renderers read. Markdown used to
  render from the live report and be string-scrubbed afterwards, by which point
  the key is gone; that also let the shape matcher absorb the renderer's own
  punctuation, so the two documents reported different fingerprints for one
  secret. ReportLab and **not WeasyPrint**: WeasyPrint resolves GTK/Pango at
  import and does not import on Windows, so the renderer could not be executed —
  let alone verified — on the machine that produces the bundle. The PDF's
  differentiating section is **the control arm for every confirmed finding**,
  top-level and immediately after the executive summary rather than an appendix:
  "it confirmed" and "the control refused" are one claim, and a document showing
  only the positive arm is asking to be believed. Read through
  `_control_arm.control_verdict_from_evidence` — the producer's own reader, so a
  response body cannot write its own verdict into the table. Unproven leads are
  a first-class section with every `why_unconfirmed`, and every bound that
  decided coverage renders on a clean run too. The `/Info` dictionary is
  populated from the report's own fields and nothing else, because it is the
  channel no page-text scan reads. Regenerable offline with
  `clinkz report-pdf <id>`; a render failure inside a live engagement is logged
  at ERROR and loses the PDF, never the findings.
  Client-ready header (authorization record verbatim, window,
  in-scope AND out-of-scope, authentication proof, testing conduct), remediation
  attached per class from `models/vuln_classes.py`, and a generated **"What was
  NOT tested"** section (excluded hosts, unauthorized techniques, classes with no
  client-side oracle / no methodology, safety-rail refusals, any halt) — built
  from the registry and the run's own action log so it cannot drift. **"No
  oracle exists" and "the oracle ran and said no" are separate categories**
  (`no_client_side_oracle` / `client_oracle_found_nothing`), chosen from what P7
  actually did this run (`ExploitResult.client_oracle`): the first
  non-benchmark run filed three classes as having no client-side oracle while
  P7 executed 40 times and correctly refused every candidate — the product's
  best behaviour, reported as a gap in the product. **The LLM budget is
  enforced only because the CLI now HANDS its `SpendLedger` to the
  orchestrator**; it used to build one, print the pre-dispatch bounds line from
  it and drop it, so `--token-cap` bound nothing and `token_cap: null` was the
  honest half of that pair.
  Findings and **research-leads are separate types in separate fields**: `CrossServiceResearchLead` (unproven A→B chains),
  `UnprovenExploitLead` (single-service, effect not witnessed) and
  `ChainResearchLead` (a composition the decoy control did not discriminate)
  render in their own UNCONFIRMED sections and are never counted in the totals. A
  CONFIRMED chain is counted ONCE — as an ordinary finding — and its link-by-link
  composition renders in a separate section that adds no count. `model_stamp`
  records which model actually SERVED each LLM stage, read from the run's own
  `llm_call` trace events rather than from configuration — a fallback means the
  provider that answered is not the one that was asked, and it is the one that
  answered which shaped the output. **A recorded baseline without it is not a
  baseline** (see the determinism invariant below).

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
- **A guard's ROOT is part of its verdict, so the gate covers two regions.** It
  reported CLEAN over 3,123 files while a live JWT sat one directory up, in
  `outputs/d8_auth_bypass_live_validation.json` — true, and about a region chosen
  so as to exclude where the leak landed (the same shape as a tree-scanning leak
  guard that cannot see a PR's own text). `REGION_BUNDLE` is `outputs/<id>/`;
  `REGION_COMPANION` is everything else under the outputs root that no
  engagement's gate covers — loose driver files, `outputs/_juiceshop_benchmark/`
  and friends. **One verdict, two regions**, because the operator's question is
  "may I share this directory"; findings carry their region and render apart,
  because "the directory around your bundle is not shareable" is a different
  instruction from "your bundle leaked". A directory named like an engagement id
  is somebody else's bundle and is never swept in. Every `summary_line` states
  its coverage — a CLEAN that does not say what it looked at is how this
  survived.
- **Every file the gate does not read is NAMED, and an unexplained one FAILS.**
  A silently skipped file is the mechanism behind every guard here that
  certified a region it never looked at. `_SKIP_ALLOWED` is an allow-list keyed
  by suffix, each entry carrying *the reason that suffix is not read*, and
  anything skipped without one — unreadable, unparseable, over the size cap — is
  a `SkippedFile` with an empty reason that makes `clean` False. Counts sit in
  `summary_line` beside the scanned ones. The reasons are **disclosures, not
  absolutions**: `.db` is skipped because there is no SQLite reader here, not
  because a SQLite file is safe — its TEXT columns are plaintext in page data,
  and the reason string says so. Over a real bundle this surfaced 20 state
  databases that had been inside a CLEAN verdict unread.
- **A PDF is read through TWO channels, because each is blind to the other.**
  Page text is in Flate-compressed content streams (a byte scan of the file
  finds nothing); document metadata is in a separate `/Info` dictionary that
  never appears in page text. Measured both ways, not assumed. Both are pulled
  via `pypdf` — the only dependency declared here that anything imports — into
  one blob with `[metadata]` / `[page N]` markers so a line number still names
  the channel. `.pdf` used to sit in the skip list, so every PDF was certified
  unopened; a PDF that cannot be parsed is now an unexplained skip, not a clean
  file.
- **The engine's redaction reaches only where the engine writes.** A `scripts/`
  driver tees the HTTP chokepoint and serialises the exchanges itself, so it
  wrote past every writer: a complete RS256 session JWT plus the lab password in
  plaintext, while `report.json` from the same run was clean. Driver artifacts go
  through `scripts/_artifact_io.py` — a CALL SITE of `redact_structure`, never a
  second redactor — and a hardcoded lab password is a **third intake route** that
  registers on the way in like the other two. Enforced structurally by
  `tests/test_engagement/test_driver_artifact_writes.py`, which reads every
  `scripts/*.py` and refuses a raw `write_text`/`write_bytes` unless allow-listed
  with a reason: drivers are exactly what a `src/`-and-`tests/` grep misses.
- **The credential the client gave us goes first.** The default-credential
  sweep ran unconditionally ahead of the supplied credential: 52 requests of
  `admin/admin`, `root/root`, `admin/password`, `test/test` across six routes,
  landing in the client's authentication logs as credential stuffing — from an
  authorized test, before that test did the thing it was authorized to do.
  Guessing is what you do when you have not been handed a key, so
  `_should_sweep_default_credentials()` is `not credentials.authenticating` and
  nothing else. There is deliberately no "…or the supplied credential failed"
  branch: that path ABORTS (below), so the sweep is not merely deferred past a
  failure but unreachable after one — falling back to guessing passwords the
  moment the client's own credential is rejected is the same log entry this
  removes.
- **A login URL is proven by response SHAPE, never by a status code.** A
  single-page application serves its shell for every path it does not recognise,
  so `/login.php` answers **200 with 9903 bytes of Angular** on a Node target
  that has never had a PHP file — and a `status < 400` HEAD probe accepted it,
  which is how six credential POSTs landed on `/login.php` at a Node app.
  `_serves_a_login_form` GETs the body (a HEAD cannot see this) and requires the
  marker no catch-all produces by accident: an `<input type="password">` beside
  an identity-shaped field. Nothing proven ⇒ **`None`**, not the root URL: the
  "fall back to the root as the login page" strategy is deleted, because a root
  URL is not a login page, it is where a credential POST goes when nobody proved
  anything. A JSON login API serves no form and is found by
  `detect_auth_mechanism`, which is the component that knows how to ask.
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
  BOTH invisible in the report and ungated by authorization. `DISCOVERY_CLASSES`
  and `COMPOSITION_CLASSES` (`attack_chain`) emit findings without a dispatch
  entry — they are never *planned against an endpoint* — so they are held apart
  from that sync assertion and gated by registry KEY instead. **That sync
  assertion's domain is `DISPATCHABLE_TEST_METHODS`**, the table the dispatcher
  itself reads; it used to be `_CLASS_PATH_TOKENS` — a *ranking signal* map
  holding 27 of the 30 — so the two classes with no registry entry at all were
  outside the check that exists to find them. **A dispatch-table entry that can
  never emit is a capability claim**, so `_test_tier2_technique` /
  `_test_tier3_technique` are registered `NOT_IMPLEMENTED`
  (`_apply_technique` has three exits, all `return []`: it sends no request and
  constructs no `Finding`), which is what puts them in *What was NOT tested* and
  makes every dispatched technique task a ledger row instead of silence.

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

## Project Structure (key paths)

```
src/clinkz/
├── cli.py            # Typer CLI: scan / abort / actions / artifact-scan / report-pdf /
│                     #   trace inspect / tool-invoke / step-replay / corpus-replay
├── config.py         # Settings (env vars, per-agent LLM overrides, outputs_root —
│                     #   read via outputs_root() at CALL time, never as a default arg)
├── state.py          # SQLite state + message store; findings + research_leads
├── orchestrator/     # OrchestratorAgent, lifecycle, prompts
├── agents/           # recon, scan, exploit, research, report, _report_pdf (the
│                     #   PDF deliverable — THIRD renderer of the same redacted
│                     #   structure; control arms are its top-level section),
│                     #   _route_discovery,
│                     #   _package_identity (which PACKAGES is this built from? —
│                     #   npm lockfile/manifest + served-bundle version strings;
│                     #   the third component source, declaring through the SAME
│                     #   detected_components() contract — pure, offline-testable),
│                     #   _js_api_mining (what does the frontend CALL?), _api_schema
│                     #   (what does the live target ACCEPT? — safe methods only),
│                     #   _json_body (addressing a field INSIDE a structure),
│                     #   _url_safety (may we fetch it?), _url_shape (in what order?),
│                     #   _origin (THE scheme+host fence — one helper, six call sites),
│                     #   _plan_ranking (phase 3: which types is this parameter
│                     #   worth attempting? — the fingerprint decides the SET,
│                     #   the cap guards the unsupported tail; pure, replayable),
│                     #   _secret_exposure / _input_validation / _mass_assignment /
│                     #   _crypto_tokens (the four new classes' pure logic, offline-testable)
│                     #   _business_logic (intent inferred from the app's OWN surface,
│                     #   with the evidence — offline-testable),
│                     #   _auth_bypass (THE one vocabulary for "did this response log us
│                     #   in?" — artifact reader + the three-arm differential),
│                     #   _principal (a NAMED authenticated identity + the handoff
│                     #   that carries one — the wire _role_sessions was missing;
│                     #   + privilege_order: which identity a crossing runs FROM,
│                     #   declared by the operator, never read off a role label),
│                     #   _idor_oracle (the four-arm access-control oracle: whose
│                     #   object is this? — pure, offline-testable),
│                     #   _control_arm (the never-sent control + attribution + WHICH
│                     #   arm produced a status: what an oracle must clear before it
│                     #   may confirm — offline-testable),
│                     #   _report_integrity (what the report may CLAIM, reconciled
│                     #   against the run's OWN record: the testing WINDOW, the
│                     #   authentication state, the cost, the document's name —
│                     #   pure, read by all three renderers at BOTH seams),
│                     #   _archive/ (built, registered, invoked zero times: critic)
├── chaining/         # composition as a capability: vocabulary (what each class YIELDS /
│                     #   REQUIRES), harvest (finding -> artifact, via the DECLARED yield),
│                     #   planner, composition (THE ORACLE — the decoy control), impact
├── engagement/       # gate (the refusals), cli_inputs (operator flags -> validated models:
│                     #   target/scope classification, authorization assembly),
│                     #   resume (rebuild a stopped run's REPORT, never its testing),
│                     #   secrets (credentials + redaction chokepoint),
│                     #   credential_shapes (what a secret LOOKS like — one vocabulary,
│                     #   shared by the redactor and the gate), artifact_scan (the
│                     #   disclosure gate: outputs/<id>/ AND the companion region
│                     #   beside it — a guard's ROOT is part of its verdict),
│                     #   auth_state (detect / PROVE / maintain), dryrun
├── safety/           # destructive (default-deny classifier + subresource_guard_spec, the
│                     #   vocabulary shipped INTO the browser), governor (rate, concurrency,
│                     #   kill switch, blocking, window), action_log (+ browser navigations),
│                     #   benchmark (the explicit throwaway-target opt-in — absent by default)
├── comms/            # AgentMessage, async bus, protocol
├── discovery/        # Δ-model: ingestor(s) (detect_ingestor reports a MISS; a tree in an
│                     #   uningestable language is stated in the report, not silently
│                     #   black-box), catalog, intent, reachability, hypothesis, engine,
│                     #   topology(+recall), recall, relations, versions
├── knowledge/        # KnowledgeBase, persistent_kb, seeders, MITRE/OWASP datasets, payloads,
│                     #   component_cves (published CVE ↔ observed version — a LEAD, never
│                     #   a finding; ordered by VERSION PROVENANCE, see the
│                     #   dependency→CVE rule below)
├── llm/              # base (+ ResearchGrounding: does research() see the live web?),
│                     #   call_purpose (does this call's answer EMIT, SUPPRESS, or
│                     #   only PLAN? -> whether a fallback is refused),
│                     #   degradation (substitution AND absence: an exhausted chain
│                     #   substitutes nothing, so it wrote nothing),
│                     #   factory, fallback, providers, spend,
│                     #   {anthropic,gemini,openai,ollama}_client
├── tools/            # ToolBase (discovery + fingerprint contracts), resolver, mcp_client,
│                     #   auth, http_client, component_names (one name/version split rule),
│                     #   nmap/ffuf/whatweb/httpx/sqlmap/…
├── oob/              # P6: templates (exfil guardrail), collaborator (receive-only)
├── browser/          # P7 client-side execution oracle: templates (witness carrier),
│                     #   witness (the verdict — page text NEVER decides), csp_policy
│                     #   (what a served policy leaves reachable), oracle (rails +
│                     #   runtime choice), _container_runner (the browser-driving half —
│                     #   ZERO clinkz imports, so it runs in the tools container)
├── observability/    # trace.py (JSONL), replay.py, corpus_replay.py (offline gate),
│                     #   ledger.py (what each component CONTRIBUTED — the silent-
│                     #   degradation gate), component_registry.py (what the engine HAS,
│                     #   declared at start + a COMPUTED reachability predicate settled
│                     #   at report time), plan_alarms.py (what the task cap
│                     #   DROPPED, and separately whether the ORDERING held)
└── models/           # scope, engagement (authorization/window/credentials/policy),
                      #   vuln_classes (+ ControlArm: which of a class's OWN channels
                      #   dispatch their own control; + MultiPrincipalRequirement:
                      #   how many identities a class needs before it may CONFIRM),
                      #   target,
                      #   recon (+ VersionProvenance: how a version was OBSERVED;
                      #   + inventory_summary: the deliverable's own VIEW of it),
                      #   scan, methodology,
                      #   research,
                      #   finding, report
docker/  scripts/  tests/  docs/
requirements-ci.lock  # the FULL resolved dependency set CI installs (85 packages),
                      #   generated by scripts/lockfile.py --generate and enforced
                      #   as a pip `-c` constraint + a --check assertion in CI
```

## Commands

- `python -m clinkz scan --target <url|host|ip|cidr> [--scope <entry|scope.json>]
  [--exclude <entry>] [--authorization <auth.json> | --auth-* flags |
  --auth-prompt] [--creds <creds.json>] [--source <tree>] [--benchmark-profile
  <bp.json>] [--dry-run] [--rate-limit N] [--max-concurrency N] [--out <dir>]
  [--resume <id>]` — full pentest (recon → scan/research/exploit → report). The
  only end-to-end command. **Refuses to start without an authorization record**
  (`--auth-*` flags refuse with EVERY missing field named — the record has no
  partial shape); `--dry-run` enumerates what it WOULD do, including whether the
  `--source` tree is ingestable, and sends nothing. **It previews the benchmark
  profile that will ACTUALLY execute**, splitting the destructive categories into
  WILL BE REFUSED / WILL BE PERMITTED via the same `permits_category` predicate
  `benchmark_override` consults at dispatch, and rendering the sample classifier
  verdicts through it too. It used to build the refusal list from a module
  constant and never read the attached profile — so a run permitting `deletion`,
  `data_reset` and `unsafe_method` previewed as though all three were refused,
  and *the dry run is what a client authorizes against*: an under-reporting
  preview obtains consent for a different engagement than the one that runs.
  `unsafe_method` was absent from the list entirely and so appeared in neither
  column, on the very runs that permit it. `--out` redirects the whole
  bundle by setting `settings.outputs_root`, which every writer resolves at CALL
  time — a default argument would be bound at import and silently ignore it.
  `--resume` rebuilds an interrupted engagement's report from its persisted
  findings and sends nothing; it does not resume TESTING (phase coverage is not
  persisted, findings are), and the regenerated report says so in its own
  *What was NOT tested* section. **The exit-code contract is the interface**
  (`cli.py::EXIT_CODES`, rendered into `--help`, asserted by the test suite):
  0 completed · 1 failed · 2 bad input · 3 refused before testing · 4 halted ·
  5 completed but the bundle FAILED the disclosure gate.
- `python -m clinkz abort <engagement_id>` — kill switch: halt immediately and
  cleanly (the report is still produced).
- `python -m clinkz actions <engagement_id> [--outcome sent|refused] [--raw]` —
  every state-changing request the run produced: "what did it do to my app?".
- `python -m clinkz artifact-scan <engagement_id> [--bundle-only] [--raw]` — the
  disclosure gate, re-run by hand: does this bundle still carry credential
  material? Covers the engagement directory AND the companion artifacts beside
  it; `--bundle-only` asks the narrower question. Exits non-zero if so. Runs
  automatically at the end of every engagement.
- `python -m clinkz report-pdf <engagement_id> [--outputs-root <dir>] [--out <file>]`
  — re-render the client-facing PDF from `report_<id>.json`. **Offline**: it
  reads the stored, already-redacted structure and sends nothing, which is the
  whole point — three renderers, one source. For a bundle written before the
  governor stamped its request window it recovers the narrower window from that
  bundle's own `actions.jsonl` — the governor's own writer, inside the bundle —
  and renders the provenance beside it rather than presenting it as the full one. Every engagement writes this PDF
  itself; the command exists for a re-render after a layout fix, or for a bundle
  produced before the renderer did. Exits 2 on a missing bundle or unreadable
  report, 1 when the renderer is absent or the document could not be built.
- `python -m clinkz trace inspect <engagement_id>` — render an execution trace.
- `python -m clinkz tool-invoke <engagement_id> <seq> [--replay]` — inspect/replay
  one tool invocation.
- `python -m clinkz step-replay <engagement_id> <step_id>` — re-run one agent step.
- `python scripts/regrade_stored_bundles.py` — **offline** re-grade of every
  stored bundle's confirmed findings against the never-sent control and the
  attribution check. Sends nothing. Reports SURVIVES / **NO_ARM** / REFUSED /
  **UNKNOWN_CLASS** per class, holding "the question was never asked" apart from
  both answers: a stored bundle cannot dispatch a control, and a finding that
  was correct because the target was genuinely vulnerable but would fail its own
  control is a phantom that landed on a real bug. **A title that resolves to no
  `VulnClass` is UNGRADED, not a pass** — every verdict is read off the
  producer's declaration (`MARKER_ORACLE_CLASSES` / `VulnClass.control_arm`, all
  keyed by `_test_*`), and an unresolvable finding reaches none of them, so
  `control_required("") is False` was the consumer supplying an answer the
  producer never gave. The emit side is fixed at the same time:
  `vuln_classes.finding_title()` composes a title from the class's OWN first
  token so `for_finding` cannot fail to resolve it, and `_make_finding` logs an
  `UNCLASSIFIED FINDING` when one does. That matters beyond the re-grade — an
  unresolvable title exits every class-keyed rule, *including*
  `control_required`, so it leaves the never-sent-control gate rather than
  failing it. **And the description is a FALLBACK, which `for_finding` said and
  did not do**: it searched `title + description` as one string, so the longest
  token anywhere won — and a description is
  `Technique: <id>. Parameter: <name>.`, where the parameter name is a value the
  methodology or the target chose, not a class name. `client-side` (11) in
  `Parameter: (client-side fragment)` outranked `dom-based` (9) in the title, so
  P7's flagship browser-witnessed DOM-XSS was filed as
  `_test_javascript_attacks` at all three exploitable ladder levels — wrong
  remediation, wrong declared yield, wrong class in the re-grade. A title that
  resolves is authoritative.
- `python scripts/plan_variance_corpus.py [--outputs-root <dir>] [--json]` —
  **offline** replay of every recorded phase-3 ranking against the deterministic
  ranking layer. Sends nothing; reads only `outputs/*/trace.jsonl`, which already
  carries the phase-2 fingerprint, the order phase 3 produced and the type phase
  5 confirmed. Reports per class what the recorded window kept, what the new one
  keeps, the attempt cost, and how many fingerprints produced more than one
  order. Exits non-zero if the new window loses a confirmation the engine is
  known to have made.
- `python scripts/cve_reservation_corpus.py [--outputs-root <dir>] [--json]` —
  **offline** replay of what the dependency→CVE slot reservation would have cost
  every stored bundle. Sends nothing. Answers the two questions the reservation
  had to earn: a run that matched nothing plans **byte-identically**, and where
  it does apply the displaced Tier-1 count is stated. Neither input is stored
  whole — `report.hosts[].services` is empty on every bundle and `trace.jsonl`
  truncates the recon handoff at 500 chars — so the inventory is recovered by
  the strongest surviving route (report → handoff → the REAL fingerprint parsers
  over recorded stdout) and **the route is printed beside every number**; a
  bundle no route reaches is `UNRECOVERABLE`, never `0 components`, and a bundle
  whose `passes_recorded` is 0 has no baseline rather than a baseline of zero.
  Carries a **positive control** — the same bundles with the observed Apache
  version substituted for one the catalogue matches — because a corpus of zeros
  is evidence only once the instrument has registered a hit; a control that
  reserves nothing exits non-zero and says the zeros prove nothing. A second
  **package-identity control** covers the ingestion path, and its weaker form is
  stated rather than blurred: the Apache arm SUBSTITUTES a version into an
  observation the bundle really made, while this one INJECTS rows no stored
  bundle could ever have observed, because none records a served bundle body or
  a supplied lockfile. It asserts three claims separately — ingestion reaches
  the matcher, a lead-only match reserves nothing, and a lockfile-provenance
  match is ordered ahead of a banner one — the last written against the two
  provenance values BY NAME, because checking that the list is sorted by
  `version_provenance_rank` re-derives the expectation from the sorter's own key
  and passes with the rank table inverted. A run where no bundle carried both
  provenances exits non-zero: the claim passed having compared nothing.
- `python -m clinkz corpus-replay [--rebuild]` — **offline** parser regression gate:
  re-parses every recorded `tool_invocations/` stdout and diffs against
  `tests/fixtures/corpus_replay_baseline.json`; exits non-zero on drift. Sends
  nothing — unlike `tool-invoke --replay`, which RE-EXECUTES the recorded
  command against the live target and always exits 0.
- `python scripts/three_run_envelope.py --authorization <auth.json>
  --benchmark-profile <bp.json> --creds <creds.json> [--scope <scope.json>]
  [--runs 3]` — **LIVE.** N identical Juice Shop benchmark runs, each preserved
  under `outputs/_juiceshop_benchmark/envelope/run_<n>/` because the harness
  overwrites its own results directory every run. Carries the two guards a
  credit lapse needs: a **terminal account state refuses the batch** before
  anything is sent (exit 3) and a run whose `model_stamp` names an unserved
  stage is **not recorded** and ends the batch (exit 4). Variance is computed
  over the recorded runs only.
- `python scripts/juiceshop_benchmark_run.py --record-floor [<engagement id>]` —
  **offline.** Re-derive the crawl-and-authenticate floor from a stored
  zero-dispatch bundle, keyed to the credential set that bundle authenticated
  as. Refuses a run that tested, one whose dispatch count is unmeasurable, one
  with an unserved stage, and one that does not say who it logged in as.
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
- **Orchestrator-mediated comms** — agents never talk directly; all messages
  route through the Orchestrator. What routes them is the v2 deterministic phase
  sequence, NOT an LLM router: `_handle_query`'s `RESPIN_*` branch has never
  fired because no agent constructs a `QUERY`, and
  `MAX_CROSS_PHASE_RESPINS` bounds a path nothing reaches.
- **Agents are spun up/down on demand**, in the order the phase shape declares.
- **Dynamic tool discovery** — `ToolResolver.find_tool(capability=...)`, never a
  tool name or direct import.
- **LLM-agnostic + per-agent providers** — never import a provider SDK outside
  `llm/`. **Anthropic is priority 1 for every call on every phase**; priority is
  declared in `Settings.llm_provider_priority` (validated Anthropic-first) and a
  discovered key confers *availability*, never a position. **Detail →
  [`docs/provider-routing.md`](docs/provider-routing.md).**
- **A fallback is a disqualifying event, and on an emit or suppress path it is
  refused outright — in BOTH run modes** (`llm/call_purpose.py`). `client` mode
  degrades and stamps because a client engagement should not die over a bad
  minute at a provider, and because reduced coverage is something a stamp can
  honestly disclose. That reasoning stops at the two paths where it is false: a
  finding a degraded cross-check DEMOTED is not in the report, so there is no row
  to caveat and nothing separates "the engine did not find it" from "a cheaper
  model decided it was not real". Six of the twelve recorded Gemini-served
  exploit calls were false-positive cross-checks. Every agent call site declares
  its purpose and an unclassified one is a red build, not a permissive default.
- **A run where NOTHING answered is not a clean run** (`llm/degradation.py`).
  `degraded` was `bool(self._events)` and an event was written only on a
  **substitution**; a chain that runs out substitutes nothing, so the worst
  outcome wrote nothing and the eligibility flag computed from that list said
  the run was fit to be a baseline. Engagement `2e21a200` failed recon, scan AND
  exploit with `All providers exhausted`, produced zero findings, and reported
  `provider_degraded: false, baseline_eligible: true`. Three kinds degrade a run
  now — `SUBSTITUTION`, `TERMINAL_EXCLUSION` (a provider lost for the rest of
  the run, so every later call ran a shorter chain and was silent about it) and
  `CHAIN_EXHAUSTED` — the last two carried as **absences**, which have no served
  model and so could not be expressed as a `ProviderFallback` at all.
  `baseline_eligible` now FOLLOWS `degraded` rather than re-deriving it: two
  expressions of one fact drift, and this pair did.
  **Two witnesses, because neither covers both instances.** The register catches
  a raise the trace attributes to the last provider that worked (run `9317e813`,
  one methodology call, `stop_reason=refusal`); `model_stamp` catches the outage
  in a STORED bundle, where the process that knew ended long ago.
  `reconcile_with_model_stamp` refuses a clean claim the run's own stamp
  contradicts, only ever tightening, at **both** the build seam (so `report.json`
  carries it) and the render seam (so an older bundle re-renders honestly).
- **A report about a run that did not happen must say so.** The same engagement
  rendered "0 findings identified. Risk rating: Informational." — the strongest
  claim a pentest report contains, made out of no evidence at all.
  `ExecutiveSummary.run_completed` / `incomplete_reason` are computed by
  `_run_completion` from the orchestrator's `phase_outcomes` AND the model
  stamp's exhausted stages; incomplete + zero findings rates **`Not assessed`**,
  because "Informational" is a verdict about the target. The banner renders
  ahead of the counts in all three documents.
- **A capability lost to routing is STATED, never absorbed.** Research led with
  Gemini for native Search Grounding and the Anthropic path has none, so a
  research answer is bounded by a training cutoff with no signal in the text that
  anything is missing. The producer declares (`LLMClient.RESEARCH_GROUNDING`),
  the resilient client reports who ANSWERED, the phase reports the WEAKEST
  grounding any of its calls ran under, every runbook entry carries it (the claim
  persists to the KB, so the caveat must too), and the report renders it either
  way. `undeclared` counts as ungrounded.
- **A section that reads one field and contradicts the document's own contents is
  worse than a missing section** (`agents/_report_integrity.py`, **detail →
  [`docs/report-integrity.md`](docs/report-integrity.md)**). Three of them
  shipped, all on the first page, all checkable by a client without tooling.
  **The testing window** was `test_start`/`test_end` defaulting to
  `datetime.now(UTC)` because nobody ever passed either, so a 4,597s run rendered
  as zero directly beneath the authorized window — the one place the document
  evidences that testing happened inside it. The producer is now the governor,
  the only component every dispatched request passes through, and the rule is
  *any request sent ⇒ `test_end > test_start`, or the render fails*. Its one
  exception is a bundle carrying **no stamp at all**: the ABSENCE of the key is
  what separates an old bundle from a new one that is lying, so an old bundle
  renders an explicit "not recorded" and `clinkz report-pdf` recovers the
  narrower window from the bundle's own `actions.jsonl`, provenance attached.
  **The authentication state** was one boolean whose negative branch renders the
  strongest sentence in the header — "Anything behind authentication was not
  examined" — above 22 findings behind DVWA's login. Reconciled into four states
  now (`PROVEN` / `DISPROVEN` / `INCONSISTENT` / `NOT_ATTEMPTED`): a negative
  claim is only as good as the check that produced it, and in that run
  `assertion` is `null`, so no check ran. **The cost** was `$0.00` beside "a
  LOWER BOUND", which reads as a wrong number; an engagement whose models carry
  no declared rate is `not priced`. Every reconciliation is pure, reads only
  engine-declared fields, only ever TIGHTENS, and runs at BOTH seams — the build
  seam so `report.json` carries it, the render seam so a stored bundle
  re-renders honestly. Same shape, same reason, as `reconcile_with_model_stamp`.
- **A session the engine GUESSED is still a session, and the record has to say
  so.** `_authentication_summary` reads `_role_sessions` and `_auth_assertion`,
  and only the SUPPLIED-credential path writes them — the default-credential
  sweep's `_attempt_login` wrote its cookies, jar path and bearer token to the
  credential store, which is what every later phase reads. So a run logged in for
  its whole duration reported that it had never logged in, on all four ladder
  levels (`DEFAULT CRED VALID: admin:*** on .../login.php`).
  `_register_swept_session` files it under `SWEPT_CREDENTIAL_ROLE`, deliberately
  not a supplied role name, because "a credential the client handed us" and "one
  this engine guessed" are different provenance. `established` stays False and
  `_role_session_handoff` still skips it: holding session material and having
  PROVEN a session are different facts, and *we posted a password and got a
  cookie* is the assumed-not-proven claim refused everywhere else here.
- **A class the never-sent rule does not bind is not a class with no control — it
  is a class whose control is a DIFFERENT rule, and the row names it.** The
  control-arm section header promises "the row says which rule applies instead"
  and 19 of 29 rows said only which rule does NOT govern them. Nineteen verbatim
  repetitions of an absence invite a client to read the strongest evidence in the
  document — a browser-witnessed nonce, a rejected broken signature — as
  unverified. The PRODUCER declares it (`VulnClass.control_arm.governing_rule`,
  plus `evidence_key`, the field in the finding's OWN structured evidence
  carrying the observation the rule turned on), required for every member of
  `CONTROL_EXEMPT_CLASSES`, and `control_arm_row` raises on a row that names no
  rule. The observation is read by `declared_observation`, which the host under
  test cannot reach: the strict structured reader first, then an entry whose
  FIRST token is `key=` — position 0 is never occupied by target bytes, because
  every entry carrying them is written by the engine with its own `Request: ` /
  `Response: ` prefix.
- **An IDOR finding proves attribution with NAMES and FINGERPRINTS, never
  values.** `attributing_values` reproduced `field=value` pairs out of the OWNING
  principal's record — the first target data this class has ever carried into a
  deliverable — and an 80-character cap bounds volume, not sensitivity: on a
  client engagement that value is a real customer's email or postal address, in a
  document that gets emailed. `attributing_fields` renders
  `field=<name> owner_fp=<hash> caller_fp=<hash|absent>`: equal to the owner's
  own authorized read, different from (or absent in) the caller's, which is the
  whole claim. The field NAME survives because it is schema, not data, and is
  what a remediation has to name. Same trade as `AuthArtifact.principal` — the
  claim survives, the value never lands.
- **A bound that decides coverage is reported in the DELIVERABLE, not just the
  log** (`observability/plan_alarms.py`). The plan cap ranks `(class, endpoint)`
  pairs and drops the tail — four D1 runs each truncated ~1,500 candidates to 150
  — and it was loud only in the run log and `trace.jsonl`, neither of which a
  client reads. Truncation and **ranking inversions** stay separate numbers with
  separate renderings because they have different fixes: a bigger cap covers a
  truncated tail and does nothing for a task dropped from an endpoint carrying
  its own class's observed surface. Rendered on a clean run too.
  **And `kept` is a total, so it is not evidence about its parts**:
  `kept_by_class` + `classes_with_candidates` separate "the cap took every
  candidate this class had" (a bigger cap) from "tasks survived and the class
  still never ran" — indistinguishable before, and the second is the ffuf
  shape at class granularity. That second verdict is
  `no_phase_event_tasks_survived_the_cap`, and it deliberately does **not** name
  the dispatcher: it used to read "the plan reached it and the dispatcher did
  not", which sent maintenance to the wrong file. A class that returns `[]` at
  its own entry gate, before its first phase trace, produces a byte-identical
  shape — and every observed instance was that (a form gate reading `page.forms`
  on a framework target). The alarm names what was observed, and points at the
  class's applicability gate first. The **class-coverage account**
  (`scripts/d1_consistency_runner.py::class_coverage`) gives every dispatchable
  class exactly one verdict on **how far its own pipeline got**, never on what
  it says about itself; "the plan held nothing for it" is the fifth fact and is
  NOT an alarm, an indeterminate answer IS one. Which skill names a class is
  DECLARED by the producer (`_CLASS_TRACE_SKILL`), verified against the call
  graph, because guessing `_test_x → "x"` is right 23 times and wrong for
  `_test_javascript_attacks` — and a mis-guessed skill reports zero coverage,
  which reads exactly like a class that never ran. **`kept_breakdown_present` is
  consulted FIRST, ahead of every benign branch**: all three never-dispatched
  verdicts are read off `kept_by_class`, so its absence decides them before any
  of them is asked. It used to sit last, behind "the plan held no candidate" —
  whose inputs are empty in exactly the same way an absent breakdown's are — so
  a bundle with **no `trace.jsonl` at all** reported thirty correctly-empty
  classes, `alarms: []` and `reached_an_endpoint: 0`: a clean coverage account
  for the whole engine, out of a missing file.
  **Detail → [`docs/observability.md`](docs/observability.md).**
- **The crawl's enrichment budget is that same bound, one layer earlier**
  (`CrawlBudgetTruncation`). It decides which discovered URLs ever BECOME
  endpoints, so everything the plan cap can see has already passed through it —
  and on the first non-benchmark run 3,070 crawled URLs became 212 candidates of
  which the budget opened **80**, leaving 132 (62%) never enqueued at INFO in the
  run log and nowhere in `report.json`. Rendered as a *Crawl coverage* section
  on a clean run too, `opened_by_host` beside `dropped_by_host` because a total
  cannot say whether an entire host went unlooked-at. It also **qualifies the
  refusal tally**: refusals count requests that were REFUSED, and a candidate the
  budget never opened never became a request, so a refusal count describes the
  opened slice of the out-of-scope surface. **One href is one candidate** —
  `crawl_dedup_key` strips a trailing `%5C`, the escape artifact left by reading
  a URL out of a JSON-escaped payload, which arrived as three spellings and spent
  three visits. It is a dedup KEY, not a rewrite: the smallest spelling in the
  group is kept, which is the clean URL when it was discovered and the mangled
  one unchanged when it was not.
- **Crawl-safety / session hygiene** — `is_state_changing_url` is the chokepoint
  guarding every crawl visit, endpoint emission, and exploit-plan entry; its
  submission counterpart `is_destructive_form_submission` guards every form
  submit at `_submit_form_fields`. **A probe never destroys target state**: a
  credential/account-mutating form is refused, not fuzzed, and a field the
  methodology did not intend to set is omitted — never sent empty-but-present.
- **A new injection *shape* gets a DEDICATED carrier**; leave the shared
  string-only `_send_probe` untouched.
- **How a class READS the target is not the class's business** — there are two
  accessors and a class uses them, never the raw layer beneath. `page.forms` is
  `_http_get` + `_FormParser().feed(body)`, so it is `[]` on any
  React/Angular/Vue target: the form exists, it is just rendered after the bytes
  we parsed. `_http_get(page.url, {param: value})` puts the probe in the query
  string whatever the parameter's declared location is. So a form-shaped class
  reads **`_injectable_forms`** (HTML forms first and unchanged, plus the JSON
  and multipart pseudo-forms this agent synthesizes for body-bearing API
  endpoints) and a probing class carries through **`_send_probe`**. Eight of the
  eleven classes read the raw layer and were therefore invisible on a framework
  target while reporting nothing — which reads exactly like a clean result.
  Enforced structurally: `tests/test_agents/test_tier1_migrations.py` AST-walks
  the agent for `self._http_get(url, {k: v})` and fails on any site not
  allow-listed with a reason (the domain is the source, per the guard-domain
  law). **`_test_javascript_attacks` is the one that does NOT migrate** and says
  why: its phase-1 hypothesis is a conjunction of a form AND an inline
  `<script>` block, and its only confirming path needs a hidden field of that
  form written by that script — a pseudo-form has no hidden field by
  construction and a JSON response has no script. Reaching a framework's
  client-side security logic means reading its bundle, which is a new oracle.
- **An upload point is declared by a protocol artifact, never by a URL that
  sounds like one.** The upload pseudo-form is synthesized only when the
  endpoint's DECLARED request content type is `multipart/*` — read off the
  frontend's own `new FormData()` builder by `_js_api_mining`, not guessed — AND
  one of the field names that builder appended is upload-shaped. A multipart
  endpoint with no file part gets no pseudo-form, because there is nothing for an
  upload test to submit and a fabricated one would be a target detector.
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
  Resolved by **capability**; absent, broken or out-of-budget ⇒ the
  `UnprovenExploitLead` stands unchanged. **A missing browser costs coverage,
  never honesty**, and there is no path from a P7 verdict to demoting or
  suppressing anything.
- **An oracle must observe from a machine that can REACH the target.** The
  browser runs where the tools run (docker mode ⇒ inside `clinkz-tools`), because
  the engagement's address is itself a consequence of `TOOL_EXEC_MODE`: docker
  mode rewrites `localhost:8080` to a bridge alias no host browser can resolve,
  and local mode — where a host browser would work — has no port scanner. The
  runtime is therefore **tied to `TOOL_EXEC_MODE`, never configured separately**,
  so the one combination that silently fails every navigation cannot be selected.
  `browser/_container_runner.py` carries the browser-driving half with **zero
  clinkz imports** and both runtimes call it, so a driver and a real engagement
  run the same rails.
- **A browser is a new destructive surface, and its rails are structural.** Scope
  is checked before launch; the governor authorizes the navigation exactly like
  an HTTP probe; **every navigation is written to the action log** (a GET too —
  what is recorded is that a real engine ran the target's code — tallied apart
  from `state_changing_sent` so neither number needs qualifying). Inside the
  page: only the FIRST navigation is ours and every later one is aborted; only
  that authorized request may use a mutating method, so a page cannot
  `fetch('/x',{method:'DELETE'})` what a blocked navigation could not; and a
  **safe method is not automatically safe** — `<img src="/logout">` is a GET that
  destroys the session, so subresource paths are matched against
  `safety/destructive.py::subresource_guard_spec()`, the one vocabulary, shipped
  into the browser as data. Nothing is ever clicked, filled, or submitted. Every
  refusal is recorded on the verdict, never silent.
- **Deterministic skills as contracts** — if the vuln is present, the `_test_*`
  method MUST find it. Verification-honest emission: emit only when the evidence
  proves the DEFINING security effect. **Never write an observation into evidence
  that was not made**; an effect that was not witnessed is an
  `UnprovenExploitLead` (a distinct type with no path to `_persist_finding`),
  never a finding. **A finding that confirms identically across every level of a
  security-graded control is a phantom by construction** — see
  `docs/methodology/dvwa-per-level-honesty.md`.
- **No marker oracle confirms without a dispatched control arm that REFUSED**
  (`agents/_control_arm.py`, **detail →
  [`docs/methodology/never-sent-control.md`](docs/methodology/never-sent-control.md)**).
  Ten classes confirm by finding a string in a body, which is proof only while
  the string has one route in; the first non-benchmark run shipped 14 phantoms
  from two second routes (a Next.js RSC payload echoing the query string
  percent-encoded, and `<span>Linux</span>` matching the bare-word `uname`
  regex). The control is the confirming request with the exploitation primitive
  removed and the marker re-minted, graded by the SAME phase-5 oracle — and it
  must **round-trip like the payload**, because a bare decoy is
  encoding-invariant, refuses everywhere, and would have passed that run
  cleanly. `MARKER_ORACLE_CLASSES` / `DIFFERENTIAL_CONTROL_CLASSES` /
  `CONTROL_EXEMPT_CLASSES` partition every dispatchable class with a stated
  reason; an unclassified one is a red build. The middle table exists because
  **what the decoy must BE differs by oracle kind**: a marker oracle's control
  carries a minted token, because what it must not do is appear in a body; a
  DIFFERENTIAL oracle's control carries a value of the class's own SHAPE, because
  what it must do is round-trip through the same handler and differ only in the
  primitive. Handing `_test_idor` a `clinkzdecoyidor48211` where the endpoint
  expects an integer produces a control that takes the parse-error path, differs
  from everything, and passes on a vulnerable target and a phantom alike.
  `control_required()` is the union, so the RULE stays one rule.
  Enforced at `_persist_finding`, read only from fully-structured evidence so a
  page echoing `never_sent_control=refused` cannot license itself.
- **Every kill discloses, wherever it happens.** The rule had two enforcement
  sites and one disclosure between them: ground 8 at `_persist_finding` wrote an
  `UnprovenExploitLead`, a phase-5 kill returned `continue` and wrote nothing —
  so the 2026-08-20 ladder fired ten arms, recorded **zero** disclosure records,
  and three DVWA levels carrying genuine command injection reported silence that
  reads exactly like a clean target. The lead is now written inside
  `_run_control_arm`, the one seam every arm passes, so a class cannot forget
  because a class does not do it; `_control_arm_kills` /
  `_control_arm_kill_disclosures` make it a count rather than a convention. The
  lead says the class **could not PROVE** the vulnerability — never that the
  endpoint is clean, which the tests refuse in so many words: an oracle whose
  control also confirmed produced no evidence in either direction.
- **The arm's lookup key is DECLARED by the emitting site, never re-derived.**
  `_run_control_arm` files a verdict under the parameter it DISPATCHED against,
  so a class that renames its vector for the report misses its own arm and is
  then refused for not having one. `_test_sqli` at DVWA `high` dispatches
  `\x00session:id` and emits `id (session)`: both arms refused correctly and both
  findings were suppressed as un-armed — low and medium survived only because
  their parameter has one name. `_test_file_upload` had the same shape
  (`uploaded` vs `file`). `_make_finding` takes `control_arm_parameter` from the
  site that did the renaming; a miss while a sibling arm exists on the same
  `(test_method, endpoint)` is a traced `control_arm_key_mismatch` that still
  refuses — an arm dispatched against a different parameter is evidence about
  that parameter.
- **An oracle confirms on its class's DEFINING effect, and the arm is what
  proves it does** (**detail →
  [`docs/methodology/defining-effect-oracles.md`](docs/methodology/defining-effect-oracles.md)**).
  Two oracles were measuring something the endpoint does regardless of the
  payload, and their own control arms said so on targets that really are
  vulnerable. `_test_cmdi`'s `time_delta` compared one reading to an **absolute**
  4.0s constant and never read the baseline it was handed — DVWA's `ping -c 4`
  baseline is 4.04s, so it confirmed on an untouched request; it is now an
  interleaved, repeated differential against that endpoint's own baseline, and
  phase 4 prefers the marker channel phase 1 already PROVED (recorded as
  `ShellPrimitives.marker_separator`) over whatever the model ranks first.
  `_test_file_upload` confirmed on "a nonce we wrote came back", which a PHP
  interpreter reproduces for any `.php` file of bare text — the indicator is now
  a value the interpreter must COMPUTE (`'clinkz'.'exec'.(A*B)`) and that appears
  nowhere in the uploaded bytes. Neither is reachable by weakening the control:
  a decoy that does not round-trip refuses everywhere and proves nothing.
- **Whose object is this? is a relation, not a property of a response — so the
  access-control oracle needs a SECOND identity, and it now has one**
  (`agents/_idor_oracle.py`, `agents/_principal.py`, **detail →
  [`docs/methodology/idor.md`](docs/methodology/idor.md)**). Two defects, one
  class. The **plumbing stopped one layer short**: the Orchestrator logged in
  every supplied role, asserted each session, kept all of them and logged that
  the access-control classes could compare principals — while handing Exploit
  the primary role's cookies and nothing else. And the ORACLE had its control
  inverted: phase 5 opened by requiring the target to have REFUSED an
  out-of-allotment reference, which consumed **616 of 668 phase-5 refusals**
  across 2,955 recorded engagements, because an application that 404s an id
  nobody owns and 200s a neighbour's record discriminates perfectly and that
  gate read the shape as "no boundary exists". `ref(∅)` is now the CONTROL, in
  four dispatched arms — `self` (A, ref(A)), `crossing` (A, ref(B)),
  `nonexistent` (A, ref(∅), must differ materially), `anonymous` (no session,
  ref(B), must NOT return it) — plus B's own authorized read, which is what makes
  ref(B) *attributable* and is the arm one principal cannot dispatch. The control
  round-trips like the payload (numeric far outside the OBSERVED issued range, a
  fresh v4, or the same length and character classes) because a minted marker is
  encoding-invariant and would pass on a vulnerable target and a phantom alike.
  **Reflection is deliberately NOT covered by it**: a sink echoes the control
  too, so the control refuses correctly and the owner's read echoes the same
  string back — three arms agreeing on one substitution — and it keeps its own
  guard.
- **A class that needs two identities declares it in the registry, and the code
  READS the declaration.** `models/vuln_classes.py` has said "requires at least
  two authenticated roles" since it was written, the report rendered that
  verbatim, and the oracle emitted `high`/CONFIRMED on a single role 49 times. A
  limitation only the report knows about is a disclaimer.
  `MultiPrincipalRequirement` makes it a number the emission chokepoint compares
  against the run's own principal list, with the lead reason declared beside it
  (`single_role_cannot_attribute`, registered in `UNPROVEN_WHY_UNCONFIRMED`).
  **Tier 1 multi-role MAY CONFIRM; Tier 2 single-role MAY ONLY LEAD** — "not A's"
  is satisfied identically by a public catalogue record, so three negatives are
  not a positive. Enforced at the methodology AND at `_persist_finding`
  (deterministic ground 9), because a rule a class has to remember is a rule that
  holds until the twenty-fifth class is written. A direct invocation holds no
  principals and is in the single-role tier: that is the honest answer, not an
  exemption.
- **A crossing arm is evidence only when it runs UPHILL, and which way is up is
  the operator's to declare.** Two principals make the arm dispatchable; they do
  not make it meaningful. Every one of the four arms is satisfied by an
  administrator being served a customer's record — which in most applications is
  the feature — and the commonest client engagement supplies exactly one admin or
  service account, so A being the PRIMARY role pointed the oracle at a false
  positive on the shape it will meet most often. A is now the LEAST privileged
  identity the engagement holds (`_principal.privilege_order`), and the candidate
  owners are everyone A does not outrank — equal rank included, since two
  customers are peers and no role either holds authorizes reading the other's
  record. The rank is DECLARED (`privilege` on the role credential, lower is
  less privileged) and never inferred from a role LABEL: a label is free text an
  operator picked for their own application, and reading a hierarchy out of it is
  the consumer-guesses-the-producer pattern that has already cost a component's
  field names, a tool's output model and a version's provenance. An undeclared
  rank does not stop the arms — the crossing dispatches and is recorded — it
  bounds the VERDICT to a lead
  (`privilege_order_undeclared_crossing_may_be_authorized`), which an operator
  clears in one line of their credential file. Enforced at the methodology AND at
  `_persist_finding` (deterministic ground 10), the same pair as the tier rule,
  and the two grounds are mutually exclusive so a lead names the observation that
  was actually missing.
- **A request carries the ENGAGEMENT's session, a NAMED principal's, or none —
  one field, three values** (`tools/http_client.py::session_mode`). `isolated`
  did not exist and both alternatives are wrong for a cross-principal arm: under
  `ambient` curl still passes `-c <jar>`, so role B's `Set-Cookie` overwrites the
  engagement's own session and every later probe silently becomes B; under `none`
  the explicit cookies are dropped and the request carries no principal at all.
  `no_session` stays as shorthand for `none` and is now DERIVED from the mode
  rather than supplied beside it — two booleans that must agree is how the
  session-link leak happened. Only an `ambient` response is `session_bearing`, so
  a role-B 401 is never read as our own session expiring. The agent-side carrier
  (`_as_principal`) swaps the ambient material for the duration of one arm and is
  **not re-entrant**: nesting raises, because concurrent use would send one
  principal's session under another's label.
- **A control arm's outcome is the PROOF, so a consumer must know WHICH arm it
  read.** "Marker-bound" is declared per class, and `_test_sqli` confirms on five
  channels: four are marker matches and `auth_bypass` is a three-arm differential
  whose contradiction and benign arms are DISPATCHED and must refuse. Neither
  string carries that fact — `_test_nosqli` has an `auth_bypass` channel with no
  shape-matched contradiction at all — so the PRODUCER declares it
  (`VulnClass.control_arm`, an unreasoned exemption refused at construction) and
  every consumer reads the declaration. Two read it wrong on the same finding,
  the juice-shop authentication bypass: the offline re-grade filed a CRITICAL as
  `NO_ARM`, and `_fp_ground_error_page` would have demoted it for the two
  `status=401`s that ARE its control refusing — spared only because `re.search`
  stopped at the tautology's `200` first, which is an ordering, not a rule.
  Attributing each status to an arm fixed those two shapes and was the wrong
  depth: the ground was reading the `Response:` entry, which is where the **host
  under test's** bytes land, so a target serving `status=500`, `stack trace` or
  `verified=False` suppressed the finding proving its own vulnerability — and
  the arm-aware reader made that easier, scanning every match per entry where
  `re.search` stopped at the first. **A guard reads only what the engine
  declared** (`response_status`, `reflection_in_error_block`, `verified`),
  through the fully-structured reader a response body cannot satisfy. Same rule,
  same reason, as `_evidence_strength`. No producer declares those two fields
  yet, so that ground fires on nothing today — measured as costing nothing: it
  fired 0/90 on stored bundles and the 14 portfolio phantoms die on the control
  arm and attribution instead. The **live gate does not relax**: the engine can
  dispatch a never-sent arm for the `auth_bypass` channel and does, so
  `_persist_finding` still demands one; a stored bundle can dispatch nothing,
  which is the whole asymmetry.
- **An observation must be attributable to the payload that produced it.** A
  confirmation citing a command-output channel the payload never invoked
  (`;echo <canary>` does not print `uname` output), or minting a marker and then
  citing something else, refutes itself in its own evidence — which shipped
  verbatim seven times.
- **A deterministic guard whose value is that it needs no model is never gated by
  one.** All **ten** grounds run unconditionally at `_persist_finding` over
  every finding, from one declaration (`_deterministic_grounds` — probe plus the
  lead reason it produces, read by the emission gate and the FP cross-check
  alike). Grounds 9 and 10 are the two that read no evidence at all: they
  compare a registry DECLARATION against the run's own principal list — how
  MANY principals it holds, and whether it can say which of them outranks the
  other — both engine facts, so nothing the target sends reaches them in either
  direction. Four of them used to be reachable only *through* the cross-check, i.e.
  only once a model had nominated the finding; on the portfolio run that check
  returned **no opinion at all** and every ground behind it went unconsulted.
  Two consequences are structural, not incidental: an LLM can no longer suppress
  anything the code did not already suppress (a finding reaching the cross-check
  carries no contradiction by construction, and one that does is logged as a
  **bypassed gate**), and every ground's `why_unconfirmed` must be in
  `UNPROVEN_WHY_UNCONFIRMED` — an unregistered reason is normalised to
  `not_instrumentable` ("we lack the access"), which is not what happened and is
  the only part of a lead an operator can act on.
- **Silence from a detection path is not evidence of cleanliness.** The
  cross-check and the emission gate are ledger components. A review that ANSWERED
  and named nothing is `correctly_empty` — the fifth fact, not an alarm; a review
  that never ran is `ok=False` ⇒ `ALL_FAILED`, and `ExploitAnalysis.cross_check_ran`
  (default `False`) carries the distinction to every consumer. What hid it was an
  asymmetry between two siblings: `ProviderPolicyError` was hardened against the
  broad-`except` pattern and `DecisionPathFallbackError` was not, so the refusal
  on the SUPPRESS path became an empty suspect list — the exact shape of a clean
  review. **Both are now `BaseException`**; they differ in *who* catches them, not
  in whether anyone can. The second is caught **explicitly, by name**, at the two
  sites where degrading is correct — an explicit handler is somewhere to log,
  record and disclose the loss; a broad one reaches none of those, and a new
  EMIT/SUPPRESS call site that forgets one now fails loudly.
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
- **One engagement is one target state, so a confirmation SUPERSEDES its lead.**
  A lead saying "execution was not witnessed" and a confirmed finding saying it
  was cannot both be true of the same `(endpoint, parameter, technique)` — a
  deliverable carrying both reads as the report contradicting itself (engagement
  `908b7130` shipped exactly that pair, from a driver that switched DVWA's level
  underneath one engagement id). The confirmation wins and the lead is dropped
  **before** it reaches the store, since the Report agent renders from the table.
  Directional, like every other rule here: a witnessed effect outranks the
  absence of one, and there is no path by which a lead suppresses a finding.
  Matched narrowly — a different parameter, endpoint or technique survives — and
  read from the FINAL finding list, so a demoted finding supersedes nothing.
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
- **A class whose input is fully observed asks no model, and a baseline carries
  the model that produced it.** The header set is captured in phase 2 and every
  WSTG-CONF-07 rule is a pure function of it, so `security_headers` phase 3 is
  deterministic end to end (`_deterministic_security_headers_analysis`, formerly
  the *fallback*) and the LLM is unreachable — asserted on the CALL, since a test
  that only compares verdicts passes against a version that consults the model
  and discards the answer. The evidence: over 1,033 recorded phase-3 calls across
  126 engagements, the same prompt on a byte-identical observation produced the
  version-disclosure entries 27% of the time under `claude-sonnet-5` and 80%
  under `claude-sonnet-4-6`, so **a model bump silently re-baselined the DVWA
  ladder** and read as a posture regression. `Server`/`X-Powered-By` were
  reachable ONLY through that path and are 78% of every weak-header mention ever
  produced; they are now deterministic rules. The residual is stated, not
  absorbed: **129 mentions across 9 header names** the evaluator has no rule for
  (`x-xss-protection` 44, `access-control-allow-origin` 26, `feature-policy` 23,
  `cache-control` 17, `x-frame-options` 8, `location` 4, `x-content-type-options`
  3, `permissions-policy` 3, `x-recruiting` 1 — the last two of those being the
  model naming headers off a page rather than evaluating the set). Ladder
  invariance is pinned as a test on fixed observations: byte-identical headers
  ⇒ byte-identical `(missing, weak, severity)` at all four levels, **and** the
  shared verdict is pinned, because four identical wrongs satisfy the first
  assertion alone.
- **Coverage truncation is never silent** — the plan cap is loud (per class:
  how many candidates were dropped and the first omitted endpoint), each class's
  bucket is ordered by relevance to *that* class, and every applicable class is
  guaranteed one task before the cap applies. A drop on an endpoint carrying the
  class's **own** surface, while lower-relevance tasks survive, is logged
  separately as a **RANKING FAILURE**: an ordering defect reads nothing like
  tail truncation and must not hide inside it.
- **A phase-3 ranking is a function of the phase-2 FINGERPRINT, and the bound
  on it is the fingerprint too** (`agents/_plan_ranking.py`, **detail →
  [`docs/methodology/plan-ranking.md`](docs/methodology/plan-ranking.md)**). Two
  defects, one shape. The ORDER was a model's answer, so the same fingerprint
  ranked 210 times produced 16 different orders and 48 of the 64 fingerprints
  ranked more than once produced at least two — an engagement whose plan is drawn
  from a distribution cannot be re-run or compared against its own baseline, so
  this is a measurement defect before it is a coverage one. And the FINGERPRINT
  WAS NOT READ: phase 2 counts the UNION columns and proves the breakout context
  and the ranking discarded both, while `predictability == "opaque"` — *you
  cannot guess the next identifier* — was read as *there is no horizontal
  access*. Replayed over the recorded corpus the old fallback rankings keep
  **770 of 833 confirmations** a current vocabulary can express, and 41 of the 63
  they miss are IDOR `horizontal` from that one condition.
  A ranking now returns the order AND `supported`, the subset some phase-2 probe
  empirically backed; `attempt_window` never truncates a supported type and
  applies the cap to the unsupported tail, which is hypothesis rather than
  evidence. The tail is never empty, because "the fingerprint did not back it" is
  not "the fingerprint refuted it" — three recorded `appended_url` confirmations
  sit on parameters whose fingerprint said that primitive does not work, and a
  ranking built only out of confirmed primitives could not probe them at all. `sqli` and `cmdi` make no
  phase-3 LLM call; elsewhere the model orders the SUPPORTED block only — on the
  tail it ranks hypotheses against no observation, and it ranked LFI
  `error_based_path` ahead of the `wrapper_extraction` that confirmed. Held by a
  reachability guard whose domain is COMPUTED from each enum, with both
  directions asserted and every exemption reasoned.
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
- **A CVE match on a version string is a LEAD, never a finding**
  (`knowledge/component_cves.py`). The dependency→CVE path runs
  fingerprint → component+version inventory (`ReconResult.components`) → known
  CVE → **our own oracle on the live target**. It reached the reader only after
  the Exploit handoff was unwrapped: the orchestrator passed the recon phase
  ENVELOPE (`{"result": …}`) where Scan and Research are both handed their inner
  result, so every top-level lookup Exploit makes against recon —
  `components`, `tech_stack`, `web_info` — resolved against three envelope keys
  and returned nothing on every engagement ever run. Fixed at the handoff, not
  in the reader: a reader that tolerates both shapes cannot tell you the next
  producer changed. A match either becomes an
  `ExploitTask` for the class whose oracle can witness that CVE's effect — and
  the CVE is then CONTEXT on a normally-proven finding — or an
  `UnprovenExploitLead` saying we have no oracle. A third outcome does not
  exist. Same rule that demoted the sqlmap-only SQLi: somebody else's conclusion
  is not an observation we made. An **unversioned** component matches nothing
  version-bounded (a deliberate recall loss), and an entry that would match
  unconditionally — an unbounded `*` over an alternation of generic servers — is
  refused by a gate, because a lead equally true of every host says nothing
  about this one.
- **The fourth plan source RESERVES its slots, and spends them by version
  provenance.** Being a plan source it could never win a slot in is the same as
  not being one: the Tier-1 interleave fills the plan to
  `exploit_max_plan_tasks`, so by the time the CVE union ran `len(merged) >= cap`
  was already true and every confirmable match took a "the plan cap was reached"
  branch — on every engagement ever run. `_resolve_component_cve_reservation`
  now runs BEFORE planning, sizes the reservation at
  `min(_MAX_COMPONENT_CVE_MATCHES, dispatchable)` — the 16 is a ceiling, never
  the size — and the Tier-1 passes spend `cap - reserved`. Unused reservation
  returns to the Tier-1 fill, so a match deduped away against another source's
  task costs coverage nothing; **a run that matched no CVE reserves zero and
  plans byte-identically**, which is pinned as a test because that is nearly
  every engagement. The reservation is a bound that decides coverage, so it is
  in `report.json` (`plan_coverage.passes[].reserved` / `configured_cap`), not
  only the log.
  **Which matches get the reserved slots is decided by how the VERSION was
  observed** (`models/recon.py::VersionProvenance`, declared by the PRODUCER —
  a consumer parsing `nmap:service` back out to guess the evidence kind is the
  `getattr`-with-a-default pattern again). A `Server:` banner is a string the
  target chose and a back-ported fix defeats it; a lockfile entry or an artifact
  hash is one it cannot easily lie about. `ARTIFACT_STRING` — the version baked
  into a bundle the target served — is its own rank between `MANIFEST` and
  `BANNER` and not a second spelling of the latter: both die to a back-port, but
  a `Server:` header is composed per request and one `ServerTokens` line from
  saying nothing, while a `/*! jQuery v3.4.1 */` comment is in the shipped bytes
  and names the package's own release. `match_components` orders confirmable
  first, then by provenance, THEN by published severity — ahead of severity
  deliberately, because the ordering decides what is TESTED and ranking a
  banner-backed CRITICAL over a lockfile-backed MEDIUM spends the scarce slots
  on the weakest evidence in the system and calls it prioritisation.
  `undeclared` ranks last, like `undeclared` research grounding. Every
  fingerprinting TOOL declares `BANNER` and says why in its own docstring;
  `agents/_package_identity.py` is the producer that declares the three stronger
  values, which is what made `dedupe_components`' provenance tie-break stop
  being a no-op. An AST guard
  (`tests/test_tools/test_component_provenance_declared.py`) fails a
  construction site that declares nothing, so a new reader cannot be silently
  demoted to the weakest rank.
  **The inventory itself is now in the deliverable**
  (`report.component_inventory`, rendered as *Component inventory* in the
  Markdown and the PDF): provenance decides which match is TESTED, so it is a
  bound that decides coverage and belongs beside `plan_coverage` and
  `crawl_coverage`. It also lifts a replay ceiling — `hosts[].services` is empty
  on all 70 stored bundles carrying `plan_coverage`, so no stored report has
  ever carried an inventory and every offline replay had to reconstruct one from
  recorded tool stdout.
  **The provenance rides the task into the finding** (`ComponentCVEContext` on
  `ExploitTask`, stamped onto findings at the `_execute_task` seam). The CVE is
  still context and nothing here can create, promote or rescue a finding — but
  the deliverable now says *which* observation the oracle was pointed at and how
  strong it was, which is the difference between this and a template scanner.
  The evidence line is prose by construction so the structured-evidence readers
  (`_evidence_strength`, the deterministic grounds) cannot mistake a
  target-chosen product name for an engine verdict.
- **A plan source that gets no slots must still say so.** The tier-2/3 research
  source sat behind `if len(tasks) < cap`, which the interleave makes false on
  any saturating target — so `_build_tier23_tasks` was never even CALLED and a
  starved research source looked identical to a research phase that produced no
  techniques. It is now always computed and its candidates join the truncation
  buckets, so the cap refusing them shows up in the report's per-class dropped
  counts. It is deliberately given no reservation of its own: both names it
  produces are registered `NOT_IMPLEMENTED` and construct no `Finding`, while
  the dispatcher fetches the endpoint before calling them — so a reserved slot
  would cost the client's target a real request and a confirming class a real
  task. The fill itself is unchanged.
- **The PRODUCER declares what it fingerprinted, too.** `detected_components()` /
  `declares_components()` is the discovery contract's twin, for the seam that
  used to read `hasattr(r, "technologies")` then `hasattr(r, "tech")` — two
  spellings because two wrappers differ, and a third would have contributed
  nothing silently. A non-declaring wrapper is a loud `DEAD_SEAM`, never an
  empty list.
- **A tool named in a `TOOL_CHAINS` entry must DECLARE that capability, and the
  resolver reads the declared ORDER.** `find_tool` resolves through the
  capability map, so a chain entry the wrapper does not declare is a fallback
  that cannot fire (httpx, nikto — and `subdomain_discovery`, which resolved to
  `None` on every call ever made). The map is built in module-import order, which
  was invisible while every chained capability had one implementer and became a
  silent preference inversion the moment a fallback became real.
- **Resolving is not the same as being used, and an unused capability states its
  reason.** `tests/test_tools/test_tool_wiring_decisions.py` accounts for every
  chained capability as either wired (with its caller) or deliberately unwired
  (with a substantive reason, verified against the source so it cannot become
  documentation of a wish). `vulnerability_scanning` (nuclei/nikto) stays unwired
  because its output is verdicts we would have to confirm ourselves — and the
  confirmable subset, version matching, is what `component_cves.py` already does
  with an explicit affected-range predicate. `subdomain_discovery` (subfinder)
  stays unwired because it expands the TARGET SET, and the target set is the
  authorization boundary: acting on a discovered subdomain would test a host the
  client never authorised.
- **One origin fence** (`agents/_origin.py`). The scheme dimension was missed
  twice in one week by two code paths — that is a missing abstraction, not two
  mistakes, because the host comparison is the obvious half and each new call
  site re-derives only the obvious half.
- **A mock at a tool or parser seam returns the REAL output model.** Gated by
  `tests/test_tools/test_mock_shape_audit.py`: a test-local `ToolOutput`
  subclass is refused unless allow-listed *with a reason*, and the only entries
  are the deliberately-broken producers that ARE the dead-seam alarm's negative
  control. A test that can only pass against a fiction is worse than no test,
  because it is counted as coverage.
- **A guard's DOMAIN is computed from the same source of truth as the thing it
  guards; only the CLASSIFICATION is hand-maintained** (**detail →
  [`.claude/skills/clinkz-dev/SKILL.md`](.claude/skills/clinkz-dev/SKILL.md),
  "The guard-domain law"**). A partition asserted over a domain that excludes
  the unclassified members is a partition of whatever is left — and the members
  a hand-maintained domain forgets are exactly the ones that most need the
  guard, because one omission produced both. `test_control_arm_registry`'s
  `_dispatchable()` was `_CLASS_TRACE_SKILL | _BUSINESS_LOGIC_CLASSES`, 27 of
  the dispatch table's 30, so `_test_log4shell` — the engine's one CVE oracle —
  EXITED the never-sent-control completeness check rather than failing it, and
  the guard was green throughout. Both directions are asserted (`computed -
  declared` catches the new member; `declared - computed` catches the entry that
  outlived what it described), and an exemption is an allow-list entry with a
  substantive reason, never a silent skip. The pattern to copy is
  `test_tool_wiring_decisions.py` (domain = `TOOL_CHAINS`) and
  `test_parser_input_assumptions.py` (domain = an AST walk over the real
  modules).

- **Two confirmed findings do not imply the chain between them, and neither does
  a successful second request.** A carriage is proven against a control: the real
  artifact ACCEPTED and an **equivalently-shaped decoy the target never issued**
  REFUSED (`chaining/composition.py`). An accept-everything endpoint cannot
  produce that observation, and a guess cannot either. Decoy accepted too ⇒ the
  endpoint accepts the SHAPE not the VALUE, and the honest outcome is a
  `ChainResearchLead` naming the link — never a finding with a caveat. The
  carriage's primitive is **P4**, so chaining introduces no new confirmation
  primitive and inherits the zero-FP boundary rather than widening it.
- **A yield is what a class's confirmation PROVES, never what the class is named
  after.** Reflected XSS is *about* stealing a session and this engine has never
  demonstrated exfiltrating one, so it declares no yield and says why
  (`chaining/vocabulary.py::NO_YIELD_REASON`) — declaring the aspiration would
  head a chain whose next link could not be carried, and a chain that cannot be
  carried cannot be falsified. Every dispatchable class is in one table or the
  other. Artifacts are harvested at ONE seam (`_persist_finding`, driven by the
  DECLARED yield), and the carried VALUE is excluded from serialisation — a chain
  carries exactly the material a report must not reproduce, so the evidence
  quotes a shape and a salted fingerprint. Escalation is a function of the
  DEMONSTRATION: only a confirmed composition escalates, and a chain never LOWERS
  what a single link already earned.
- **Business-logic intent must be EVIDENCED from the application's own surface**
  (`agents/_business_logic.py`) — a field in the server's own representation, the
  value range that representation shows, or the app's own words when it refuses.
  Unevidenced ⇒ a lead: unusual-but-intended looks exactly like a flaw from
  outside (a negative balance may be a credit note), and what an application
  *should* do is an opinion. Every finding states intent + evidence + the
  observation exceeding it, built at ONE seam. **The status code is never the
  effect** — the read-back is, because an API that accepts `quantity=-1` and
  stores `1` enforced the constraint, and an idempotent handler answers 200 to a
  replay.
- **The destructive refusal is the contract, and the benchmark profile does not
  loosen it** (`models/engagement.py::BenchmarkProfile`, `safety/benchmark.py`).
  No flag and no partial shape: a verbatim attestation, an explicit per-category
  list (no wildcard), a declaring party and a reference, or the model refuses to
  construct. **Session destruction and security-posture toggles are never
  permittable on any target** — they damage the ENGAGEMENT, not the target.
  Permission is by the category that DECIDED the refusal, never an alias. Absent
  by default like the governor; every permitted request is logged
  `benchmark_permitted:<category>` and the profile is in the report header.
- **A total is not evidence about its parts** (`observability/ledger.py`, **detail
  → [`docs/lessons/silent-degradation-and-the-dead-seam.md`](docs/lessons/silent-degradation-and-the-dead-seam.md)**).
  Three defects shipped with one shape — an empty LLM planner absorbed by the
  class floor, a timeout absorbed by provider fallback, 100% of ffuf's output
  discarded by a duck-typed seam and absorbed by the crawler. Each time a
  component produced NOTHING, a fallback covered, findings still appeared, and
  no gate fired. The ledger records per component invocations, successes and
  **items contributed**, and reports at WARNING (run log + `report.json` +
  the report's *Component contribution* section) every component invoked that
  contributed zero. Four alarm classes stay apart because they have different
  fixes — `DEAD_SEAM` (the consumer cannot read this producer), `SILENT`
  (succeeded, contributed nothing), `ALL_FAILED`, `FALLBACK_ACTIVATED` — and
  *declared but never invoked* is tracked separately, since a capability the run
  never reached for did not degrade. **Absent by default** like the governor,
  and it never raises from the data path.
- **A benchmark number a client sees must be what TESTING earned.** Runs 2 and 3
  of the Juice Shop variance envelope dispatched **zero** methodology tasks and
  still had four challenges marked solved by the target — `errorHandling`,
  `loginAdmin`, `securityPolicy`, `weakPassword` — from authenticating and
  crawling alone. Those are in `solved_total` for every run including the ones
  that tested, so run 1's "7 of 49" is roughly twice what exploitation achieved;
  the honest figure is 3. `reconciliation.json` now carries `solved_by_testing`
  BESIDE `solved_total` (both are true, only one is a claim about this engine),
  plus `methodology_dispatches` and the floor's provenance. The floor is
  **measured, never declared**: written by a run whose ledger shows
  `methodology:*` contributing zero dispatches, carrying the engagement id that
  produced it, and `record_floor` REFUSES any other kind of run — a floor taken
  from a run that tested is this engine subtracting its own results from itself.
  A union across zero-dispatch runs, one-way. **No floor measured ⇒
  `solved_by_testing: null`**, not zero: defaulting to "subtract nothing"
  silently restores the inflated number. `--record-floor` derives one offline
  from a stored bundle and sends nothing.
  **"Any other kind of run" is four kinds, and three of them were found in the
  bundle the stored floor was taken from.** A floor is what authenticating and
  crawling trip **as those principals**, so it is KEYED by the credential set
  (`credential_set_key`, read from the run's own `authentication.roles`) and a
  floor measured under different principals is refused rather than applied:
  adding `jim` beside `admin` adds whatever `jim`'s login trips, and subtracting
  the admin-only floor credits that to testing — the inflation re-entering by
  the door nobody was watching. One record per credential set, unioned only
  within one. A run whose **`model_stamp` names an unserved stage** is refused:
  it dispatched zero because nothing served it, which from the harness's
  position is indistinguishable from a floor observation, and its truncated
  crawl UNDER-measures the floor, which inflates `solved_by_testing`. And a
  ledger carrying **no `methodology:*` row at all** is unmeasurable, not zero —
  those components are declared at engagement start, so their absence means the
  bundle predates that registration (four stored Juice Shop bundles, 6–11
  findings each, would each have qualified as a floor). The stamp is the witness
  because the register is not: `2e21a200` reports `provider_degraded: false,
  baseline_eligible: true` beside a stamp saying nothing served recon, scan or
  exploit. **No stored bundle satisfies all four guards**, so the floor on disk
  is a legacy unkeyed record that applies to nothing and the re-measure is a
  prerequisite, not a nicety.
- **A batch is unattended, so a credit lapse must stop it rather than fill it**
  (`scripts/three_run_envelope.py`). The 2026-08-25 envelope produced three
  bundles and one measurement: runs 2 and 3 died to a depleted Anthropic
  balance. Two guards, both reusing vocabulary that already exists. **Before the
  batch**, `preflight_providers()` — already run at every engagement start —
  classifies a depleted balance or revoked key as `KeyStatus.INVALID`, which is
  what `primary_usable` is False on; the Orchestrator logs it and continues,
  correct for one engagement an operator is watching and wrong for a batch, so
  the batch refuses to start (exit 3, nothing sent). A busy provider
  (`UNREACHABLE`) does NOT refuse — the chain retries, and a three-hour batch
  should not die of a 429 at t=0. **After each run**, a bundle whose
  `model_stamp` names an unserved stage is excluded from the envelope entirely
  and the batch aborts (exit 4): an average over one real run and two dead ones
  is a wrong number, not a wider envelope, and an account condition does not
  clear between runs. **And a metric no run REPORTED is `null`, not zero** — the
  rule `variance` documents and three of its four metrics kept by doing nothing,
  since `recorded.get(key)` is already `None` on a missing key. `findings_emitted`
  is a list and `len(... or [])` broke it in the one place it took an expression
  to keep: an omitted key became `0`, which passes the `is not None` filter and
  widens the envelope downward as a real observation of a run that found nothing.
  `envelope_metrics()` is the one reader, and `isinstance(v, list)` is what
  separates a recorded empty list (a measurement of zero) from an absent key.
- **A recon component that RAISED must not look like a target with nothing to
  find.** Recon is where the component inventory comes from, and an empty
  inventory has two causes indistinguishable from every downstream position: a
  target with no versioned component, or a parser that raised on the tool's real
  bytes (`whatweb` discarded a complete Apache/PHP fingerprint on every run for
  years, silently). The fingerprinter's handler was fixed alone; its two
  siblings in the same file had the identical shape — including
  `_step_service_scan`, the RICHER source, since `nmap -sV` resolves a banner to
  a product AND a version through nmap's own signature database, which is why
  its provenance outranks a `Server:` header. All three record now, and the
  domain is COMPUTED (guard-domain law): every `except` inside a
  component-bearing method must reach the ledger or carry an allow-list entry
  with its reason (`tests/test_agents/test_recon_failures_reach_the_ledger.py`).
- **A ledger VIEW is not a second population.** `exploit.component_cve_match`
  appearing twice in `component_ledger` is `components` (the population) plus a
  by-name reference from `correctly_empty` — one registration, `invocations: 1`.
  Containment, not double registration and not a serialization bug. It was
  pinned for `alarms` alone while three sibling views went unchecked, so the
  domain is now every list key `to_dict()` emits, each classified as a VIEW (and
  its containment asserted) or its own population (with the reason `fallbacks`
  is one). The distinction decides whether a consumer may SUM, and a union would
  stay invisible until a component alarms while carrying real items.
- **"Correctly found nothing" is a fifth fact, and it is NOT an alarm.** A
  GraphQL discoverer on an app with no GraphQL contributes zero forever and is
  working perfectly; reported as a defect it becomes a permanent false alarm,
  and a permanent false alarm trains an operator to skim the section where a
  real one will appear. So a component may declare its **precondition absent**
  and the zero is recorded NOT APPLICABLE with the reason, held apart from the
  alarm list like *never invoked*. The claim must be **falsifiable, never a
  self-assessment** — "there was nothing to find" is what a broken reader says
  too — so the discriminator is how far the component's own pipeline got
  (`_route_discovery.DiscoveryReport`): no input of its kind, or input read
  containing nothing of its shape, is correct; **candidates found and none
  emitted is the ffuf shape and stays SILENT**, and no reason string may talk
  it away. A discoverer that does not declare `contribution_report()` is a
  loud `DEAD_SEAM`, never an assumed zero.
- **A component the ledger never hears from is not measurable, so every
  component is DECLARED at engagement start**
  (`observability/component_registry.py`). The ledger can only measure what
  registers, and exactly one call site in the engine declared anything (LLM
  providers) — so a vuln class that never dispatched, a discoverer that never
  ran and a tool the resolver never found all produced the same artifact:
  nothing at all, indistinguishable from never having been built. `declare_all()`
  runs immediately after `set_active_ledger` and declares every member of three
  **computed** domains — `DISPATCHABLE_TEST_METHODS`, `default_discoverers()`,
  `TOOL_CHAINS` — plus `STATIC_EXPLOIT_COMPONENTS`, the declared half, held to a
  **bidirectional AST assertion** over every string-literal `record_contribution`
  name in `src/` (guard-domain law: `computed − declared` catches a new call
  site, `declared − computed` catches an entry that outlived one). Per-class
  methodology components register at the ONE dispatch seam, keyed on the
  `_test_*` name VERBATIM — never a derived skill, because `_test_x → "x"` is
  right 23 times and wrong once — and their `items` counts DISPATCHES, not
  findings: counting findings would trip SILENT for every clean class on every
  clean run, which is the permanent false alarm this whole section exists to
  prevent.
- **"Declared and never invoked" has two opposite readings, so reachability is a
  COMPUTED PREDICATE and its TIMING is split from the declaration's.** A
  free-text `reachable_because` is a hand-maintained excuse list and would drift
  the way every hand-maintained guard domain here has; a sentence attached to a
  *predicate function* cannot, because there is one per predicate rather than
  one per entry. Existence is knowable at engagement start; reachability is not
  — whether the target has a SQL surface is something only Scan can answer, and
  the plan does not exist yet. So `ContributionLedger.resolve_reachability` runs
  at REPORT time against an `EngagementReachability` the orchestrator assembles
  from completed phase state. Three states fall out mechanically: predicate true
  + not invoked ⇒ **`BUILT_BUT_NOT_RUN`**, a new alarm class (built, reachable,
  did not run); predicate false + not invoked ⇒ NOT APPLICABLE with the
  predicate's own sentence as the reason (`component_ledger.unreachable`,
  enumerated in `report.json` and summarised as a count in the Markdown so
  thirty per-class lines cannot bury the alarm table); no predicate declarable ⇒
  a build failure, not a runtime branch. `reachable is None` — never evaluated,
  a direct invocation or a run that stopped early — is not `False` and never
  alarms. The tool predicate has three distinct "no" answers because they have
  three different fixes: nobody asked for the capability (nuclei, subfinder —
  both deliberately unwired), the tool is a declared fallback and the preferred
  one answered, or it is not available in this execution mode. That first answer
  needs `ToolResolver.requested_capabilities`, and the chain map the predicate
  reads is built through `available_chain()`, which does NOT record — a question
  asked *about* a run must never become part of what the run did.
- **A predicate may only be evaluated against a producer that SPOKE, so there is
  a FOURTH state: NOT DETERMINED.** Every predicate compares a counter against
  zero and then writes a sentence about the CLIENT'S APPLICATION — *no endpoint
  the scan discovered carried this class's surface* — and a counter left at its
  default is byte-identical to one a producer set to zero. An exploit phase that
  errored yields all-zero state, `resolve_reachability` ran on it
  unconditionally, and every methodology class was filed NOT APPLICABLE carrying
  that sentence, in the client PDF under *Built, but not reachable on this
  target*. Not a wrong number: a wrong sentence about a client's application,
  generated from a phase that never ran. **Suppressing a wall of alarms and
  substituting a target claim are different acts**, and the defensive-defaults
  docstring bought the first with the second. Each predicate now declares its
  `ReachabilitySource` (`EXPLOIT_PHASE` / `EXPLOIT_PLAN` / `SCAN_PHASE` /
  `ENGINE`), `EngagementReachability.reported_sources` declares which producers
  delivered — defaulting to NONE, so an unpopulated state answers nothing — and
  a predicate reading a silent producer gets
  `set_reachability_undetermined`: `reachable` stays `None` (no alarm), the
  record leaves `unreachable` (no claim) and lands in
  `component_ledger.reachability_undetermined`, which both documents render as
  *reachability not determined* naming the silent PRODUCER and never a
  per-class sentence. **Both doors are closed**, because gating on the exploit
  result alone leaves the second open: `plan_alarm_summary()` returns the same
  empty `classes_with_candidates` when no register is installed, and a register
  that recorded no pass has said nothing about a plan the planner writes on
  every pass, truncated or not. The gate is per-PREDICATE, not per-run — a dead
  exploit phase must not cost the answers a live scan supports. And it is
  reconciled against the run-completion banner
  (`_report_integrity.reconcile_reachability_claims`, pure, only ever
  tightening, at BOTH seams): a phase can deliver a result whose reasoning step
  nothing served, which the source gate cannot see, and a document whose own
  summary says the run did not complete must not carry target claims derived
  from the phase that did not.
- **The prompt cache is a ledger component like any other, because it degraded
  exactly like one.** It was invoked every run, succeeded every time, and
  contributed **zero**: the breakpoint sat after the engagement-scoped span —
  ~12,500 tokens of observed inventory presented ONCE per run — so 154 recorded
  engagements paid 96,759 cache-WRITE tokens and read back 0. Caching pays from
  the second presentation (`1.25 + 0.10(N-1) < N` ⟺ `N > 1.28`); the deployment
  had `N = 1`, making it ~25% *more* expensive than no caching on that span.
  `PromptSegments` now splits by **how often bytes repeat** — `invariant`
  (engine: role, catalogue, preconditions, worked examples) / `stable`
  (this engagement's observations) / `volatile` (the ask) — and the breakpoint
  goes after `invariant` only. The item the cache contributes is
  `cache_read_input_tokens`, so a write nobody reads trips SILENT in the run
  log and `report.json`. **And it kept tripping, so the cache is now OFF by
  default** (`llm_prompt_cache_enabled`): the smaller span was the right span
  and `N` was still 1. Every trace on disk — 13 breakpoint calls across 13
  engagements, **zero** ever making a second one, 104,589 write tokens against
  0 reads, and no two breakpoint calls closer than 1,692s against a 300s TTL —
  says the second presentation does not exist by either route, in-run or
  cross-run. A permanent SILENT alarm is worse than the cost it names: **a
  ledger where an alarm always fires teaches the operator to stop reading it.**
  The flag and the split stay, because the machinery is correct and only the
  arithmetic failed; a deployment that really re-presents a prefix inside the
  TTL turns it on and re-derives its own hit rate from its own traces.
- **A consumer never guesses a producer's field names.** The PRODUCER declares
  what it contributes (`ToolOutput.discovered_urls` / `declares_discovery`); a
  wrapper that declares nothing is a loud dead seam, not an empty list. Never
  `getattr(parsed, "field", default)` over a model — the default is what turns a
  typo into a permanently dead capability (`sqlmap`'s `injectable` vs
  `vulnerable` returned False on every run for years). **A mock mirrors the real
  model's contract**, never the consumer's assumption about it: `_MockFuzzOutput`
  declared `paths`/`directories`, names no real tool has ever carried, so the
  suite asserted a contract only the mock honoured.
- **A parser never assumes it owns the process's stdout, and the fixture must be
  the bytes the tool WRITES.** `whatweb --log-json=-` keeps writing its brief
  human-readable log to the same stream, so the JSON array and plain-text lines
  interleave, `json.loads` on the blob raised, and 100% of a successful
  fingerprint — Apache 2.4.67, PHP 8.5.6 — was discarded on **every run**,
  starving the whole published-CVE path. The committed fixture was a
  hand-authored clean array, so the unit suite passed throughout, and the
  corpus baseline faithfully locked in `success: false` for 114 of 115 recorded
  invocations. Whole-blob `json.loads` is correct ONLY for JSON the wrapper
  itself serialised; every parser now declares which case it is
  (`tests/test_tools/test_parser_input_assumptions.py`, verified against the
  source so a `self_produced` claim cannot be a wish).
- **An auth bypass is a defining effect no injection oracle can see, so it gets
  its own indicator** (`agents/_auth_bypass.py`, `InjectionType.AUTH_BYPASS`).
  A DB error, a boolean row-set delta and a UNION row are the SQLi oracles; a
  bypass returns 200 and a JWT, so 40 payloads reached a login field, the target
  graded it solved, and the class correctly emitted nothing. The effect is
  **authenticated as a principal whose credential we never supplied**, proven on
  three arms: the tautology returns an auth artifact, the *shape-matched
  contradiction* (one character apart) does NOT, and an ordinary credential
  attempt does not either. **Never 200-plus-a-cookie.**
  Applicability is a deterministic protocol signal (an identity field beside a
  password-shaped one), gated in BOTH directions so the LLM can neither invent
  the class on a search box nor omit it on a login. **The LLM synthesizer is
  structurally unreachable for this type** — its prompt has no `auth_bypass`
  vocabulary, so an LLM-built pair either fails phase 5 as an unknown indicator
  or runs a row-set oracle against a login handler; the deterministic table
  declining ⇒ the class ABSTAINS, recorded. **The identity suppression keys on
  credential POSSESSION, not identity coincidence**: "we logged in legitimately
  and it told us who we are" has two routes — a session for the principal, or a
  valid credential for it — and equality with `_authenticated_as` proxies both
  badly. It suppresses `admin@juice-sh.op'--`, a bypass carrying no password, on
  every app whose first row is the admin. So the session route is closed by a
  **runtime carrier assertion** (all three arms' dispatched args carried no
  cookie jar, cookie dict or auth header — else the identity is KEPT, failing
  safe, with the reason on the verdict) and the credential route by requiring
  BOTH halves in the same request (identity + a password-shaped field whose
  fingerprint matches one we hold). The payload is never a supplied identity.
  **Detail →
  [`docs/methodology/auth-bypass.md`](docs/methodology/auth-bypass.md).**
- **Execution traces** — each engagement writes `outputs/<id>/trace.jsonl` (tool
  calls, LLM calls, agent steps, handoffs, methodology-phase events). `outputs/`
  is local-only by policy — never committed.

## Pre-Push Verification (three gates; never bypass — no `--no-verify`, no blanket `# noqa`/skip)

1. **Lint + cleanup** — `ruff check src/ tests/` and `ruff format --check src/
   tests/`. Clean every file the diff touches (dead code, naming, stale comments,
   `None` guards, no hardcoded secrets). CI pins `ruff==0.15.22` — and a `ruff`
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
