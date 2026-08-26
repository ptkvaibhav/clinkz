# Clinkz v2: Implementation Plan

The north-star vision and the architectural decisions below were the design
brief for the v2 rewrite. Items marked **DONE** are wired and tested. Items
marked **partial** have the deterministic substrate landed but the adaptive
LLM-driven layer still pending. The "On the horizon" section lists what is
genuinely next.

## North-star vision

A multi-agent system where:

- **Agents follow deterministic step sequences** with the LLM invoked only at
  named reasoning checkpoints — no free-form ReAct.
- **Skills are contracts.** If the vulnerability is present and the skill
  runs, the skill MUST find it. CI proves this against DVWA and Juice Shop.
- **The system grows smarter with every engagement.** Every technique result
  (success or miss) is recorded to a persistent KB. Future engagements query
  the KB before reaching for the web.
- **Tools are substitutable.** Agents request capabilities, not tools. Every
  capability has a ranked fallback chain.
- **LLMs are substitutable.** Agents are pinned to providers that suit their
  workload (cheap/high-volume vs. complex reasoning), but a resilient client
  rotates providers on rate-limit / timeout.

## Key architectural decisions

### 1. Unified test plan (3 tiers) — **DONE**
Single playbook stored in `clinkz_knowledge.db` with three tiers:

- **Tier 1 (Universal):** Run on EVERY engagement. Port scan, crawl, fuzz,
  OWASP Top 10 checks. Never skipped.
- **Tier 2 (Technology-matched):** Run when tech fingerprint matches. Grows
  as more technologies are encountered.
- **Tier 3 (Experimental):** New techniques from the Research Agent. Kept if
  successful, removed/adjusted if not.

Storage: `playbook_entries` table. Each entry has `tier (1/2/3)`,
`technology_pattern`, `times_tried`, `times_succeeded`, `success_rate`.
Tier 1 entries are seeded by `knowledge/seed_playbook.py`.

### 2. Tool substitutability — **DONE**
Every capability has a ranked fallback chain in
`tools/resolver.py::TOOL_CHAINS`:

```python
TOOL_CHAINS = {
    "web_crawling":           ["katana", "gospider", "hakrawler", "zap_spider"],
    "directory_fuzzing":      ["ffuf", "gobuster", "feroxbuster", "dirsearch"],
    "port_scanning":          ["nmap", "masscan", "rustscan"],
    "vulnerability_scanning": ["nuclei", "nikto", "zap_active"],
    "sql_injection_testing":  ["sqlmap", "ghauri"],
    "web_fingerprinting":     ["whatweb", "wappalyzer", "httpx"],
    "waf_detection":          ["wafw00f"],
}
```

Agents call `resolver.find_tool(capability=...)` and walk the chain until a
tool is available. `try_until_sufficient(capability, min_results, ...)`
keeps trying tools until output meets a threshold.

### 3. Deterministic skills = guaranteed findings — **DONE**
A skill is a contract: "If the vulnerability is present AND this skill runs,
the vulnerability MUST be found."

CI proves this:

- `tests/test_skills_dvwa/` — direct skill invocation against DVWA
  (15 Tier-1 skills covered, marker `dvwa_smoke`)
- `tests/test_skills_juiceshop/` — same shape against Juice Shop

Cross-engagement learning now lives in the discovery catalog's **Layer-2
capability memory** (`capability_facts` + `capability_observations` +
`technology_relations` transfer edges in `clinkz_knowledge.db`; see
`docs/discovery-engine-capability-learning-design.md`). The **WRITE side** (slice 1):
a confirmed discovery-originated finding UPSERTs a per-technology capability fact.
The **READ side** (slice 2, `discovery/{versions,relations,recall}.py`): deterministic
version predicates (`version_satisfies`) + `bundles`/`successor` transfer edges let
`capability_recall` (a pure READ) reach that fact on a later engagement and **seed a
proof hypothesis** the recognizer could not derive from partial source — recall changes
the path to a finding, never the finding (emission stays the unchanged P1–P6 proof;
live-validated in `docs/discovery-engine-capability-recall-slice2-validation.md`). The
older technique-success loop (`record_technique_result(...)` updating `times_tried` /
`times_succeeded` / `success_rate`) is **retired** — kept read-only for the report's
historical view; `success_rate` is frozen.

### 4. Claude Code workflow — **DONE**
Repository ships with:

- `.claude/skills/run-dvwa/SKILL.md` — runs the full DVWA pipeline and
  reports coverage across the 14 categories
- `.claude/skills/run-juiceshop/SKILL.md` — same shape against OWASP Juice
  Shop (Node/Angular SPA, JWT auth); reports coverage as X/13-applicable
  (Command Injection is N/A on the Node stack)
- `.claude/skills/phase-work/SKILL.md` — loads v2 rules of engagement for
  any phase-implementation or fix task
- `.githooks/pre-commit` — runs the outputs / secret / lint guards before every
  commit; activated per clone by `python scripts/bootstrap.py`
- `.github/workflows/ci.yml` — matching CI gates, plus the `leak-guard` job (the
  fail-closed `outputs/` + credential layer that no local flag can skip)
- `.github/workflows/metadata-leak-guard.yml` + `.github/scripts/metadata_leak_guard.py`
  — the same posture for the surface a tree scan cannot reach: session links in a
  PR title/body or a `Claude-Session:` commit trailer. Self-tests on every run.

### 5. Agent flow — **DONE (with adaptive layer partially in)**

```
ORCHESTRATOR
  1. Parse scope, enforce boundaries                              [DONE]
  2. Recon (sequential)                                           [DONE]
  3. Default credential testing (WebAuthenticator, deterministic; [DONE]
     cookie/form + JSON/bearer API auth → session_headers handoff)
  4. Concurrent: Scan + Research + Exploit                        [DONE]
  5. Monitor completion                                           [DONE]
  6. Report (sequential)                                          [DONE]
  7. Persist results to KB                                        [DONE]

RECON (deterministic + LLM checkpoints)                          [DONE]
  Steps: full TCP scan → LLM analyze ports → service/version →
         LLM extract tech stack → web recon → LLM synthesize →
         structured ReconResult

SCAN (service-specific methods + LLM supervision)                [DONE]
  Steps: LLM plan → per-service methods (HTTP, FTP, SSH, SMB, DB) →
         LLM review each output → LLM coverage checkpoint →
         expand via fallback chain if insufficient → ScanResult

RESEARCH (concurrent, persistent brain)                          [DONE]
  Steps: query persistent KB → web search new vulns → LLM
         synthesize techniques → query related techs → LLM
         adapt past techniques → persist to engagement +
         persistent KB

EXPLOIT (LLM plans, deterministic skills execute)                [DONE]
  Steps: LLM plans tasks from scan + research → execute by tier →
         LLM reasons through results → adaptive retry → record
         success/failure to KB
  Adaptive methodologies (W2.1):
    - _test_xss_reflected: reflection mapping + char fingerprint +
      LLM-driven payload synthesis + bypass                      [DONE]
    - _test_sqli: dialect fingerprint + primitive enumeration +
      LLM-driven injection-type selection + synthesis            [DONE]
    - _test_nosqli: NoSQL carrier fingerprint + operator
      enumeration + LLM injection-type selection + synthesis     [DONE]
      (first new Tier-1 primitive — see docs/ROADMAP.md)
    - _test_ssti: polyglot arithmetic eval + template-engine
      fingerprint + engine-conditioned synthesis + RCE canary    [DONE]
      (second new Tier-1 primitive; read-back aware for
      second-order Pug — see docs/ROADMAP.md)
    - _test_xxe: parser-capability fingerprint + entity payload
      synthesis + in-band file-content verification (4xx-safe)   [DONE]
      (third new Tier-1 primitive — see docs/ROADMAP.md)
    - _test_jwt: token fingerprint + attack ranking + PyJWT
      deterministic forge + fully in-band acceptance verify      [DONE]
      (first Tier-2 primitive — cryptographic token manipulation,
      not injection — see docs/ROADMAP.md)
    - _test_ssrf: URL/fetch-param map + fetch-capability
      fingerprint + deterministic internal-target synthesis +
      in-band reflected-internal verification                    [DONE]
      (second Tier-2 primitive — coerces the in-scope server to
      fetch internal/metadata addresses; in-band only, blind SSRF
      deferred to OOB infra; see docs/ROADMAP.md)
    - Other _test_* skills are also adaptive methodologies       [DONE]

REPORT                                                           [partial]
  - Pulls findings from state store                              [DONE]
  - Emits JSON + Markdown + PDF from ONE redacted structure      [DONE]
  - Control-arm section per confirmed finding (agents/_report_pdf) [DONE]
  - LLM-driven narrative + remediation pass                      [PENDING — W3]
```

## Implementation phases — status

### Phase 1: Persistent KB + Recon — **DONE**
- Persistent KB schema + CRUD (`clinkz_knowledge.db`) — done
- Unified test plan (3 tiers) — done
- Tool fallback chains in resolver — done
- Deterministic Recon Agent — done
- Verified against DVWA — done

### Phase 2: Scan + Research — **DONE**
- Deterministic Scan Agent (service-specific methods + fallback chains) — done
- HTTP / FTP / SSH / SMB / DB scan methods — done
- Crawl-safety: skip state-changing links (`_url_safety.is_state_changing_url`)
  so crawl/enrichment never poisons the shared session (e.g. DVWA PHPIDS) — done
- SPA/API route discovery (`_route_discovery.py`): pluggable `RouteDiscoverer`
  seam — static JS-bundle parsing (shell + webpack chunks; concat + interpolated
  route literals, path/query param structure) and OpenAPI/known-routes probing
  (SPA-200 guarded) — union into `HTTPScanResult.endpoints`; session-carrying,
  same-origin, bounded. Headless discoverer is a documented future slot-in — done
- Research Agent with persistent KB integration — done
- Research with configurable RPM, bounded backoff, and a hard wall-clock budget
  — done. It ran on Gemini 3.1 Flash-Lite with native Search Grounding until
  routing v2 made Anthropic priority 1 on every phase; the Anthropic path has no
  search grounding, so research answers are now bounded by the serving model's
  training cutoff and every artifact says so
  (`docs/provider-routing.md` §8) — the grounding is stamped on every runbook
  entry and rendered in the report rather than absorbed
- Cross-technology adaptation — done
- Concurrent execution wiring (Scan + Research + Exploit); Exploit decoupled
  from Research (depends on Scan only) — done

### Phase 3: Exploit + Integration — **mostly DONE**
- Deterministic Exploit Agent (LLM plans, `_test_*` execute) — done
- Runbook consumption (Tier 2 / Tier 3 from Research) — done
- Endpoint polling from shared SQLite state — done
- Full pipeline integration against DVWA — done
- Clean-session guard: planner (`_dedupe_and_rank_endpoints`) drops
  state-changing links so the exploit phase never re-poisons the session — done
- CMDi phase-1 echo-canary candidacy (reflection-guarded) so injection surfaces
  even when the base command writes only to stderr — done
- LLM JSON parse resilience extended from the plan parse to the Step-3 analysis
  parse (`_repair_and_load` + one re-prompt, graceful fallback) — done
- Methodology correctness — real-attacker confirmation (Juice Shop 8df94e28) — done
  - SQLi: phase-2 breakout-context discovery (`break_prefix`) + UNION column-count
    enumeration (`union_columns`); phase-4 conditions on dialect + breakout +
    columns and prefers the deterministic build when a breakout is known; phase-5
    rejects union/error markers reflected in 4xx/5xx (the `/redirect?to=` 406
    phantom); `_sqli_has_db_error` recognises `SQLITE_ERROR` so error-based still
    confirms; `(status=…)` threaded into evidence for the Step-3b backstop.
  - LFI: PHP wrappers gated on `_is_php_stack` (stack harvested in `run`);
    file-content-only verification (a path in a stack trace no longer confirms);
    static file-server poison-null-byte sub-methodology (`_test_lfi_file_server`,
    `%2500.md` allowlist bypass on `/ftp`), planner-gated for param-less
    file-server routes.
  - Open redirect: **dispatch fix** — the scan crawl-merge
    (`ScanAgent._merge_crawl_endpoints_preferring_params`) upgrades a bare
    katana URL with the enriched `?redirect=` param instead of dropping it, so
    the real `source/<level>.php?redirect=` endpoint reaches the param-gated
    methodology (the gap behind the prior false "live-validated" claim).
    **Confirm-honesty**: primary confirmation is a server-side 3xx whose
    `Location` resolves to the attacker host only (`_open_redirect_phase5_verify`);
    `javascript:`/`data:` removed (that's XSS); body-level redirects demoted to a
    lower-severity DOM signal. **Phase 3 empirical-priority** — floats every
    phase-2-confirmed primitive ahead of the LLM's ranking and re-adds any the LLM
    drops (`_prioritize_confirmed_bypass_types`), so a genuine redirect is never
    mislabeled as a bypass type phase 2 disproved (the `e72ed60a` full-pipeline
    `appended_url` mislabel — genuine off-site 302, wrong label; re-validated
    `75ea835f` → `at_syntax`). Phase 4 prefers the deterministic build when the
    primitive is confirmed. Allowlist bypass (`RedirectBypassType.ALLOWLIST_BYPASS`)
    unchanged — harvest an allowlisted token, embed in an attacker URL, confirm
    the off-site redirect despite a substring allowlist.
- Adaptive methodologies (W2.1):
  - XSS-reflected — done
  - SQLi — done
  - **Pending**: XSS-stored, command injection, LFI, file-upload,
    weak-session, JS-attacks, IDOR, brute-force, open-redirect,
    security-headers — currently still deterministic-only
- Target of 12+/14 DVWA findings — measured per run via `/run-dvwa` skill

### Phase 4: Consistency + Skills — **partial**
- Skill smoke tests in CI for DVWA Tier-1 vulns — done
- Skill smoke tests for Juice Shop SPA-style targets — done
- 5-consecutive-engagement consistency drill — pending
- Claude Code commands + hooks — done (`run-dvwa`, `run-juiceshop`,
  `phase-work`, `pre-commit`, `ci.yml` incl. `leak-guard`, `scripts/bootstrap.py`)
- CLAUDE.md / README / docs alignment with v2 — done (this pass)

### Phase 5: Expansion — **partial**
- Juice Shop testing (SPA / Node.js stack) — first skill suite landed
- HTB retired machines (multi-service, AD) — pending
- Cross-engagement learning validation — pending (depends on consistency
  drill)

## Productization P1 — engagement setup, authenticated scanning, safety rails — **DONE**

The pass that made the engine runnable against an application that is not a
deliberately-vulnerable benchmark. Full detail →
[`docs/productization-engagement-safety.md`](docs/productization-engagement-safety.md).

- **A · Engagement setup.** `AuthorizationRecord` (every field required),
  `EngagementWindow` (hard stop, re-checked per request), `SafetyPolicy`,
  role-labelled `CredentialSet` with `SecretStr` passwords held off the persisted
  scope. `engagement/gate.py::open_engagement` is the first statement of
  `OrchestratorAgent.run()` — no flag skips it. `--dry-run` enumerates and sends
  nothing.
- **B · Authenticated scanning.** Mechanism detection (form / bearer / cookie),
  an authenticated-state **assertion against an anonymous control** that accepts
  only boundary discriminators (a body-length delta is refused), a loud abort
  when credentials were supplied and the assertion fails, mid-run session-loss
  detection at the response chokepoint with re-authentication pushed into the
  live agents, and multi-role sessions for access-control comparison.
- **C · Production safety rails.** A generic default-deny request classifier
  (`safety/destructive.py`) that preserves the predecessor form guard verbatim
  and adds payment / cancellation / key-revocation / bulk-messaging / data-reset;
  a governor (`safety/governor.py`) owning rate, concurrency, kill switch,
  blocking detection, window, and the action log — **absent by default**, so the
  benchmark suites are byte-identical.
- **D · Client-ready report.** Authorization header, scope in *and* out,
  authentication proof, testing conduct, per-class remediation, and a generated
  **"What was NOT tested"** section built from the class registry and the run's
  own action log.

## On the horizon

> **Capability expansion** (new vuln-class primitives — NoSQL/SSTI/XXE, then JWT/SSRF, then a
> real Tier-2/3, then chaining) is tracked as a durable plan-of-record in
> [`docs/ROADMAP.md`](docs/ROADMAP.md). Current position: Tier-1 complete (NoSQL + SSTI + XXE shipped);
> Tier-2 complete — **JWT + SSRF shipped**; next is making Tier-2/3 real (craft-from-knowledge).

In rough priority order:

1. **Adaptive methodologies for the rest of the `_test_*` family.** XSS-reflected
   and SQLi proved the pattern (multi-phase, LLM at synthesis checkpoints,
   intermediate results persisted to trace). Apply the same shape to
   command-injection escape contexts, LFI traversal payload synthesis, file-
   upload bypass selection, and weak-session entropy analysis.
2. **LLM-driven reporting.** Today's report agent is zero-LLM: it renders
   JSON, Markdown and PDF from one already-redacted `PentestReport`. The
   remaining v2 ambition is the multi-pass narrative generator
   (assemble → narrative → remediation → quality review); the RENDERING half is
   done, in ReportLab rather than the Jinja + WeasyPrint pipeline this plan
   named — WeasyPrint resolves GTK/Pango at import and does not import on
   Windows, so it could not be executed or verified on the machine that
   produces the bundle.
3. **Consistency drill.** Run 5 consecutive DVWA engagements end-to-end and
   measure category-level coverage variance. Lock in any remaining flaky
   skills.
4. **HTB / multi-service expansion.** Pick a retired HTB box that exercises
   non-HTTP services (SMB share enumeration, SSH key reuse, AD-style
   credential chaining). Validates Scan's non-HTTP service methods end-to-
   end.
5. **Cross-engagement learning validation.** After the consistency drill,
   verify that techniques flagged successful in run N actually shorten
   run N+1 by being picked up via the persistent KB instead of re-discovered
   via web search.
6. **Ollama client.** Currently a stub. Wiring it into the resilient client
   chain unblocks fully-offline / privacy-sensitive engagements.
