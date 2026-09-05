# Project structure — the annotated tree

> Relocated out of [`CLAUDE.md`](../CLAUDE.md) on 2026-09-02, verbatim.
> CLAUDE.md carries the RULE — one line, loaded every session; this file
> carries the incident that produced it. When the two disagree, CLAUDE.md
> is the operating instruction and this is the record of why.

Every key path with the question it answers. CLAUDE.md keeps the skeleton;
this is the annotated form.

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
│                     #   _origin (THE scheme+host fence — one helper, six call sites;
│                     #   + OriginIdentity: which origins are ONE SERVICE, from
│                     #   observed resolutions — vhosting fails safe),
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
│                     #   object is this? — ref(A) ANCHORED to the caller's own
│                     #   identity, attribution read off the OBJECT's owning
│                     #   field; pure, offline-testable),
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
│                     #   auth, http_client, redirect_walk (the ONE hop walker — observe
│                     #   the 3xx, resolve against what ANSWERED, scope-check, re-POST or
│                     #   bodyless GET by status; the chain is the DESTINATIONS),
│                     #   component_names (one name/version split rule),
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
