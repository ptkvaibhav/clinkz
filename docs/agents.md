# Agents — operating detail

> Relocated out of [`CLAUDE.md`](../CLAUDE.md) on 2026-09-02, verbatim.
> CLAUDE.md carries the RULE — one line, loaded every session; this file
> carries the incident that produced it. When the two disagree, CLAUDE.md
> is the operating instruction and this is the record of why.

What each agent DOES and the corrections its entry carries. For the
structural view — module layout, phase steps, data flow — see
[`architecture.md`](architecture.md); for per-class methodology detail see
[`methodology/`](methodology/README.md).

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
  byte-identical. All 26 `_test_*` methods are adaptive multi-phase
  methodologies (six-phase injection family; four-phase behavioral family). The
  **deterministic check GATES the LLM** — no LLM verdict emits on its own; when
  phase-2 has empirically confirmed the primitive, phase-4 prefers the
  deterministic build.

  Two of the 26 are **TERMINAL**. `_test_prototype_pollution` writes a key onto
  the target process's own `Object.prototype`, which changes how the
  application answers requests the class never made and persists until the
  process restarts. `_test_write_crossing` creates an object attributed to a
  principal that is not the caller: it is in that principal's collection when
  the run ends, and no request this engine may send removes it, because deleting
  an application record needs `CATEGORY_DELETION` and the client-safe default
  refuses it. Three things follow for both, none of them optional. They dispatch
  **last**, after every other class has finished, because every observation
  after them — including every other class's control arm — would otherwise
  measure a target this run had already altered, and the partition is asserted
  on every dispatch as a stop-the-run condition rather than a warning. Their own
  control arms run **before** their payloads (`_run_control_arm_first`), because
  a control observed afterwards exhibits the effect too and kills the true
  positive it exists to license. And the change is DISCLOSED in the
  client-facing document as a `ResidualMutation` naming the key — the first
  entries in a Clinkz report whose remediation is something the operator must do
  to their own infrastructure because we ran the test. A wildcard authorization
  does not cover either.

  Two consequences of there being **two** of them. Among terminal classes the
  order is `TERMINAL_DISPATCH_CLASSES`'s own declaration order and it is
  REQUIRED, not merely permitted — write crossing before prototype pollution,
  because a crossing does not change how the process parses later writes and a
  prototype write does, so a crossing graded after a pollution is graded on a
  process this run had already altered. And because being last is what starves
  them (the plan's per-class floor walks the category order and stops at the
  cap), they take a **pass-0 slot reservation** computed from that same table:
  a floor rather than a ceiling, remainder returned to the Tier-1 fill, and zero
  on a surface no terminal class reaches — so a run without one plans
  byte-identically. **Detail →
  [`docs/methodology/prototype-pollution.md`](methodology/prototype-pollution.md)
  · [`docs/methodology/write-crossings.md`](methodology/write-crossings.md).** **Per-methodology detail (oracles, phantom fixes,
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
