<p align="center">
  <img src="assets/clinkz-banner.svg" alt="Clinkz — Autonomous AI-Driven Penetration Testing Framework" width="100%"/>
</p>

# Clinkz

**Autonomous AI penetration testing system powered by multi-agent collaboration.**

![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![CI](https://github.com/ptkvaibhav/clinkz/actions/workflows/ci.yml/badge.svg)

## Overview

Clinkz is an autonomous, multi-agent AI system that performs end-to-end black-box penetration testing. Give it a target scope and it produces a professional pentest report — no human intervention required.

Agents collaborate through a central Orchestrator on a deterministic phase sequence, dynamically discovering and executing security tools as needed. The system follows the MITRE ATT&CK framework and OWASP WSTG methodology to ensure comprehensive coverage.

## Architecture

```
                         ┌──────────────────┐
                         │   Orchestrator   │
                         │  (Central Brain) │
                         └────────┬─────────┘
                                  │
        Recon (sequential) ──► Scan + Research + Exploit (concurrent) ──► Report
              │                    │         │           │
              ▼                    ▼         ▼           ▼
        ┌─────────────────────────────────────────────────────┐
        │                  Tool Resolver                      │
        │      MCP Servers   │   Local CLI (with fallback)    │
        └─────────────────────────────────────────────────────┘
                                  │
                ┌─────────────────┴────────────────┐
                ▼                                  ▼
       Engagement state                 Persistent KB
       (clinkz.db)                      (clinkz_knowledge.db,
                                         cross-engagement)
```

**How it works:**

1. The **Orchestrator** validates scope and runs **Recon** sequentially
2. **Scan**, **Research**, and **Exploit** then run **concurrently**, sharing SQLite state. Exploit's only hard dependency is Scan — it starts as soon as Scan completes and never waits for Research (Research's runbook is folded in only if it has already finished)
3. **Recon** discovers subdomains, ports, services, and tech stack
4. **Scan** crawls + fuzzes every HTTP service and enumerates non-HTTP services (FTP/SSH/SMB/DB), under its own wall-clock budget (`SCAN_TIME_BUDGET`) so an over-running phase returns a partial attack surface instead of being force-killed and returning none. For single-page apps it adds **API surface discovery** (`agents/_route_discovery.py`, behind a pluggable discoverer seam) — because on an SPA the `/api`+`/rest` routes *are* the surface and an HTML/JS crawl cannot see them. The frontend declares the API contract, so Clinkz reads it: `agents/_js_api_mining.py` mines the served bundles for **HTTP call sites** (fetch/XHR/axios/Angular `HttpClient`/navigation) and recovers each one's method, URL template, query parameters and request **body shape**, resolving minified class-field bindings and scoping a body shape to its enclosing function. OpenAPI and GraphQL introspection are used when served (a *disabled* introspection is reported as such, never guessed around). What the source can't say is learned from the live target using **safe methods only** (`agents/_api_schema.py`): `OPTIONS` for a resource's `Allow` header, and a collection's own `GET` representation for the fields its writes accept. No discoverer carries a hardcoded endpoint, body-field or route-word list for any application. Crawl-safety skips links that mutate the target (WAF/security toggles, logout) so the shared session is never poisoned for later phases
5. **Research** queries the persistent KB for known techniques and the NVD CVE feed, under a hard wall-clock budget, persisting results back to the KB. Under routing v2 its LLM half is **not web-grounded** — that is stamped on every runbook entry and in the report rather than absorbed
6. **Exploit** plans tests with an LLM and executes deterministic `_test_*` skills (all are adaptive multi-phase methodologies — the injection family spans SQLi, NoSQL, SSTI, XSS, CMDi, LFI, …)
7. **Report** emits JSON + Markdown. Findings are gated on the emitting path (`_persist_finding`, `verification_strength`, the deterministic false-positive cross-check), not by a separate review agent — the Critic that used to be described here is archived, having run 0 times in 2,774 recorded steps

Phase agents follow **deterministic step sequences with LLM checkpoints** (no free-form ReAct). Confirmed capabilities are recorded to the persistent KB's Layer-2 capability memory so future engagements adapt.

## Features

- **Concurrent multi-agent execution** — Scan, Research, and Exploit run in parallel through a central orchestrator, on a deterministic phase sequence
- **Deterministic skills + LLM checkpoints** — Each `_test_*` is a contract: if the vuln is present it MUST be found; LLMs only step in at named planning/synthesis points
- **The plan is a function of the observation** — phase 3 (*which exploitation types is this parameter worth attempting?*) derives its order and its fingerprint-supported subset from what phase 2 measured, so the same observation always plans the same way. It used to be a model's answer, and the same fingerprint ranked 210 times produced 16 different orders. SQLi and command injection make no phase-3 model call at all; elsewhere the model orders the evidenced alternatives while the fingerprint decides the vocabulary, and the attempt bound never truncates a type the target's own responses argued for. Replayable offline over every ranking ever recorded (`python scripts/plan_variance_corpus.py`)
- **Adaptive methodologies** — every `_test_*` is a multi-phase methodology: the injection family (SQLi, NoSQL, SSTI, XSS, CMDi, LFI, …) maps → fingerprints (SQL dialect / NoSQL carrier / template engine / shell) → ranks → LLM-synthesizes → verifies; SSTI sends polyglot arithmetic probes and is read-back aware for second-order Pug; CMDi candidacy uses a reflection-guarded echo-canary probe so injection surfaces even when the base command writes only to stderr
- **Gray-box discovery engine** — when an engagement supplies a source tree, `src/clinkz/discovery/` ingests it (bounded regex, no whole-program analysis) and derives *Δ-capability × untrusted-channel-reachability × provable-impact* hypotheses that union into the exploit plan alongside the LLM and deterministic plans. Ingestion is **cross-language** behind a `SourceIngestor` seam (`select_ingestor` picks per source tree): a Java ingestor (servlet / param-bag / typed path-param / log-sink idioms) and a JS/TS **Node/Express backend** ingestor (Express route entrypoints incl. cross-file factory-per-file handlers; `axios`/`fetch`/`fs` sink shapes; `package.json` manifest) — the JS path is **live-proven on OWASP Juice Shop**, surfacing its own-code SSRF (`fetch(req.body.imageUrl)`) and confirming it out-of-band (P6) on the running instance. A class-generic capability catalog holds three classes today — **SSRF** (`openConnection` / `axios.get` egress → `_test_ssrf`), **file read** (`new File(pathParam)` / `fs.readFile` → `_test_lfi`), and **Log4Shell** (`log4j-core` log-sink JNDI egress → `_test_log4shell`) — each learned from the target's own source with no target literal, N/A by construction on a patched/absent instance; the SSRF/file-read classes are language-agnostic (the same catalog entry fires on Java or Node)
- **Out-of-band (P6) confirmation** — a blind capability is confirmed only when an inbound callback bearing a Clinkz-minted, single-use nonce reaches a Clinkz-owned receive-only DNS+HTTP collaborator (zero-FP by construction: the nonce rides only the one outbound probe). Payloads come from CLINKZ-OWNED nonce-only templates (structural exfil guardrail — target data cannot ride the channel). This is the confirmation oracle for blind SSRF and the **Log4Shell flagship** (CVE-2021-44228), live-validated end-to-end on Vulhub Solr 8.11.0 via a `${jndi:dns://…}` callback. Disabled by default (unchanged black-box floor)
- **Client-side execution (P7) confirmation** — three classes (DOM XSS, a reflected/stored XSS whose landing context is client-rendered, and Content-Security-Policy bypass) have no server-side observation that proves the defining effect, so they previously recorded honest *unproven leads*. P7 is the missing witness: a headless browser (`src/clinkz/browser/`, Playwright + Chromium, resolved by capability) loads the page with CSP enforcement **left on**, and the class confirms only when a Clinkz-minted single-use nonce is returned by a call from inside the page's JavaScript context to a Clinkz-owned in-page channel — while a second nonce minted alongside it and injected nowhere stays silent. Inert reflected bytes cannot call a function, which is precisely the confounder that made earlier DOM-XSS "confirmations" phantoms. Nothing the page emits (console text, DOM, headers) can influence a verdict. The browser runs **where the target is reachable** — in the default docker tool-mode that is inside the `clinkz-tools` container, since the engagement's address has been rewritten to a container-network alias no host browser can route to — so P7 is available in an ordinary `clinkz scan` with nothing for the operator to arrange. Live-validated end-to-end through `clinkz scan` across DVWA's four security levels: DOM XSS confirms at low/medium/high and is **silent at impossible**. CSP bypass is a dispatched class (`_test_csp`) among the Exploit agent's **25**, and `csp_bypass` is in the client-facing registry, so it is reachable from an engagement report: the primitives it confirms on are a reused static nonce and a same-origin script gadget under `script-src 'self'`, each witnessed under the policy the response actually served rather than under a relaxed one. Absent or failing, the lead stands unchanged — a missing browser costs coverage, never honesty
- **No marker oracle confirms without a control arm that refused** — ten classes confirm by finding a string in a response body, which is proof only while the string has one route in. A live portfolio site produced 14 phantom HIGHs from two second routes: a Next.js RSC payload echoing the query string back percent-encoded (so *any* value satisfies `marker in body`), and a `<span>Linux</span>` skill badge matching the bare-word `uname` pattern. So the confirming request is re-sent with the exploitation primitive removed and the marker re-minted, graded by the **same** oracle, and it must REFUSE. The control has to round-trip like the payload or it is not a control — a bare alphanumeric decoy is encoding-invariant, refuses everywhere, and would have passed that run cleanly, so a UNION control keeps every space, quote and comment marker and neutralises only the SQL (`UNION` -> `UNIQN`). Every dispatchable class is either bound by the rule or exempt **with a stated reason**; an unclassified one is a red build. Enforced at the emission chokepoint and read only from fully-structured evidence, so a page echoing `never_sent_control=refused` cannot license its own phantom
- **A finding must be attributable to the payload that produced it, and no deterministic guard is gated by a model** — a confirmation citing `uname` output from a payload that ran `echo`, or minting a marker and then citing something else, refutes itself in its own evidence — which shipped verbatim seven times. Eight such grounds are pure functions of a finding's own evidence and all eight run unconditionally where emission is decided. Four of them used to be reachable only through an LLM cross-check that, on the run which shipped those phantoms, returned no opinion at all. Two consequences are structural: an LLM cannot suppress anything the code did not already suppress, and a review that never happened is recorded as such rather than as a review that found nothing
- **Engagement setup** — an engagement refuses to start without an `AuthorizationRecord` (authorizing party, role, contact, authorization reference, permitted-technique list, emergency contact — every field required, no flag to skip it), and an optional `EngagementWindow` is a hard stop re-checked on every request. Credentials arrive from an untracked file or a no-echo prompt, are `SecretStr`, are never attached to the persisted scope, and are redacted at every artifact writer. `--dry-run` enumerates what the engagement WOULD do — targets, classes, the destructive categories that will be refused — and sends nothing
- **The report bundle carries no usable session token** — redaction removes a string both for what it *is* (a registered value) and for what it *looks like* (`credential_shapes.py`: JWTs, `Authorization`/`Cookie`/`Set-Cookie` values, vendor API keys, PEM private keys). Value-only redaction cannot remove credential material the engagement *captures* rather than the operator *supplies*, which is how a live run wrote five session JWTs — one embedding the account's password hash — into its trace with every writer redacting correctly. A token becomes a fingerprint (salted hash prefix + `alg`/`iss`/`sub` + claim NAMES): enough to correlate, useless to replay, and legible about what the payload carried. An independent **disclosure gate** (`clinkz artifact-scan`, also run automatically at the end of every engagement) re-reads the artifacts off disk and fails loudly on any credential shape — because a guarantee asserted by the same logic that produces it is not checked at all. **A guard's root is part of its verdict**: it covers `outputs/<id>/` AND the companion artifacts beside it, after reporting CLEAN over 3,123 files while a live JWT sat one directory up in a validation driver's output. Every verdict names its coverage — including **what it declined to read**: every skipped file carries the reason it was allowed, an unreadable one has no reason and fails the gate, and the counts sit beside the scanned ones. PDFs are read through both of their channels (Flate-compressed page streams and the separate `/Info` metadata dictionary), because each is blind to what the other catches. Driver artifacts are written through the same redaction chokepoint the engine uses
- **Authenticated scanning** — the auth mechanism is *detected* (HTML form / bearer / session cookie), not assumed, and the session is **proven**: the same URL is fetched with the session and deliberately without it, and only a discriminator an authorization boundary produces is accepted (login redirect, status class, login form, session marker, identity echo). A body-length delta is a correlate and is refused. Credentials supplied + assertion failed ⇒ the engagement aborts loudly, because silently scanning an authenticated app anonymously produces an empty report that reads like a clean result. Mid-run session loss is watched at the response chokepoint and re-authenticated into the live agents — but **only a session-bearing response counts as evidence** (the engine's own anonymous control returns 401 *because the session works*, and counting it once produced a run reporting 15 losses and 0 re-authentications), and a raised flag is verified by re-running the assertion before any re-login, so a heuristic never decides on its own; multiple roles give access-control classes two principals to compare
- **Production safety rails** — a generic, default-deny classifier refuses deletion, password/email change, payment, cancellation, key revocation, bulk messaging, data reset, logout, and WAF toggles over path + method + field names + button labels. Conservative rate limit (5 req/s) and concurrency cap (4), a kill switch (`clinkz abort`), WAF/blocking detection that stops rather than hammering, and a per-run action log of every state-changing request actually sent (`clinkz actions`). The rails are absent by default, so direct methodology invocation is unaffected
- **Session hygiene** — recon/scan map the target without changing it; WAF/security toggles and logout links are never followed, so injection payloads aren't silently WAF-blocked in the exploit phase
- **Cross-engagement learning (Layer-2 capability memory)** — a confirmed discovery-originated finding writes a per-technology **capability fact** (+ observation ledger) to `clinkz_knowledge.db` so future engagements adapt at the capability level; the store carries **no target identity** (schema-level exfil guardrail) and its confidence is a decayed corroboration PRIOR from confirming observations only that **never gates emission**. The **load-as-prior READ side** then transfers it: a fact confirmed on one app is recalled on the next via deterministic version predicates + manifest-derived `bundles`/`successor` transfer edges, seeding a proof hypothesis even where the new engagement's own source is too partial to derive it — recall changes the **path** to a finding, never the finding (the live P1–P6 proof still confirms). Live-validated end-to-end (a log4j capability learned on one engagement seeds + confirms Log4Shell on a partial-source engagement a cold start misses). The older technique-success learning loop is retired (kept read-only for the report's historical view)
- **Dynamic tool discovery + fallback chains** — Agents request capabilities (`web_crawling`, `directory_fuzzing`, ...); the resolver walks declared `TOOL_CHAINS` until output meets threshold
- **Runtime CVE research** — Research Agent live-searches CVEs, bug-bounty writeups, and PoCs per identified technology
- **Credential chaining** — Discovered credentials are stored and reused across agents for authenticated testing
- **Resilient LLM client** — Per-agent provider chains (Anthropic / Gemini / OpenAI) with automatic rotation on rate-limit/timeout
- **MCP protocol support** — Connect external tool servers via the Model Context Protocol
- **Execution traces** — Every engagement writes `outputs/<id>/trace.jsonl` with tool calls, LLM calls, and methodology phases; inspect via `clinkz trace inspect <id>`
- **Component-contribution ledger** — Per component (LLM planner, each discovery tool, each parser seam, each provider in the fallback chain): invocations, successes, and *items contributed*. Anything invoked that contributed **zero**, and every fallback activation, is reported loudly in the run log and in `report.json` — so a fallback covering for a dead component can no longer make a run look healthy

## Quick Start

### Prerequisites

- Python 3.12+
- Docker (for sandboxed tool execution and test targets)
- An API key for at least one LLM provider (OpenAI, Anthropic, or Google Gemini)

### Installation

```bash
git clone https://github.com/ptkvaibhav/clinkz.git
cd clinkz
python scripts/bootstrap.py   # FIRST — activates this clone's enforcement hooks
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -c requirements-ci.lock -e ".[dev]"
```

The `-c` is not optional if you intend to compare a local test run against
CI. `requirements-ci.lock` is the **full resolved set CI installs** (84
packages, every one pinned), and without the constraint pip resolves the
unpinned tail freshly on your machine. Pinning three packages in
`pyproject.toml` closed one instance of that and left ~80 free to differ.
Regenerate with `python scripts/lockfile.py --generate` (it resolves for
CI's linux/cp312 target, so it is reproducible from any machine) and commit
the result.

`scripts/bootstrap.py` sets `core.hooksPath` so `.githooks/pre-commit` runs the
leak guards. It is **per clone**: that config is never committed, so until you run
it a `git add -f outputs/… && git commit` succeeds locally. CI's `leak-guard` job
is the fail-closed backstop, and its sibling `metadata-leak-guard` covers the
surface a tree scan cannot see (session links in PR text and commit trailers) —
see [`.claude/hooks/README.md`](.claude/hooks/README.md).

### Configuration

Copy the example environment file and fill in your API keys:

```bash
cp .env.example .env
```

At minimum set `ANTHROPIC_API_KEY`. Anthropic is priority 1 for every call on every phase; `GEMINI_API_KEY` and `OPENAI_API_KEY` are the fallback tail. Edit `.env` for full options (see [Configuration](#configuration-1) below).

**A fallback is a disqualifying event, not free failover.** When the primary fails and a second provider serves the call, the run records it and pays for it: a hard failure in `baseline` mode, and in `client` mode a `provider_degraded` stamp plus permanent baseline-ineligibility. On a call whose answer EMITS or SUPPRESSES a finding the fallback is **refused outright in both modes** — a stamp can disclose reduced coverage, but nothing can disclose a finding that was suppressed and is therefore not in the report. The caller degrades and says so. So a second key buys resilience on *planning* calls and deliberately buys nothing on the two paths that decide what a client reads.

### Docker Setup

Clinkz runs every security tool inside the `clinkz-tools` container by default (`TOOL_EXEC_MODE=docker`). Build the tools image and start the test targets in one go:

```bash
docker compose -f docker/docker-compose.yml up -d
```

This brings up:

- `clinkz-tools` — the sandboxed tool container (nmap, nuclei, ffuf, sqlmap, ...)
- `clinkz-dvwa` on `http://localhost:8080`
- `clinkz-juiceshop` on `http://localhost:3000`
- `clinkz-meridian` on `http://localhost:8090` — the **third authentication
  shape** (JSON login at a non-obvious path, identity field `account`, a session
  cookie on a JSON response, protected routes that deny anonymously with 302 to
  the login page). Not intentionally vulnerable: it exercises the authentication
  path, which DVWA's form+cookie and Juice Shop's JSON+bearer between them
  cannot express. `MERIDIAN_LOGIN_PATH` moves its login page, so the same
  application can be served at `/portal/gateway` and at `/login` — which is how
  you tell an oracle that reads the SHAPE of a redirect from one that reads the
  SPELLING of its destination

### Running a Scan

`clinkz scan --help` is the reference: it states what the engine proves, what it
refuses, every flag, and the exit-code contract.

```bash
# See what an engagement WOULD do -- sends nothing
clinkz scan --target https://app.example.com --dry-run

# A real engagement. --authorization is REQUIRED (or an "authorization" block
# inside the scope file, or the six --auth-* flags, or --auth-prompt); there is
# no flag that skips it.
clinkz scan --target https://app.example.com \
    --scope scope.json \
    --authorization auth.json \
    --creds ../acme-creds.json \
    --rate-limit 3 --max-concurrency 2

# --target takes a URL, a hostname, an IP or a CIDR block. --scope adds more
# in-scope entries (or names a scope document); --exclude carves hosts out and
# takes precedence.
clinkz scan --target 10.10.10.0/24 --exclude 10.10.10.1 -a auth.json

# No authorization file to hand? Be asked for the record instead.
clinkz scan --target app.example.com --auth-prompt

# Gray-box: hand it the application's source tree. The language is detected
# automatically, and if no ingestor matches, the run continues black-box and
# the report says so rather than looking like a gray-box result.
clinkz scan --target https://app.example.com -a auth.json --source ~/src/app

# Write the artifact bundle somewhere other than ./outputs
clinkz scan --target http://localhost:8080 -a auth.json --out /srv/engagements

# Override the orchestrator LLM provider for a single run
clinkz scan --target http://localhost:8080 -a auth.json --provider anthropic

# Rebuild the report of a run that was interrupted, from its persisted
# findings. Sends nothing, and the report states that it was regenerated.
clinkz scan --target unused --resume <engagement_id>

# Bound what the run may spend. --token-cap is measured exactly, needs no rate
# card, and HALTS THE RUN CLEANLY at the cap with its report still written.
clinkz scan --target http://localhost:3000 -a auth.json --token-cap 400000

# --spend-cap-usd is the same bound in dollars, and needs a rate per model in
# CLINKZ_LLM_PRICES: clinkz ships no default rate card, because a built-in
# table would be right the day it was written and silently wrong afterwards.
clinkz scan --target http://localhost:3000 -a auth.json --spend-cap-usd 5.00

# Halt a running engagement immediately and cleanly (the report is still produced)
clinkz abort <engagement_id>

# "What did it do to my app?" -- every state-changing request, sent or refused
clinkz actions <engagement_id>

# "Is this bundle safe to hand over?" -- the disclosure gate, re-run by hand.
# Covers outputs/<id>/ AND the companion artifacts beside it (--bundle-only
# asks the narrower question). Runs automatically at the end of every
# engagement; exits non-zero on a hit.
clinkz artifact-scan <engagement_id>

# Re-render the client-facing PDF from the stored report. Offline; sends nothing.
clinkz report-pdf <engagement_id>

# Inspect the execution trace afterwards
clinkz trace inspect <engagement_id>
```

**Exit codes** (`clinkz scan`), so a wrapper can tell the cases apart:

| Code | Meaning |
|------|---------|
| `0` | Completed — with findings or without. The report was written. |
| `1` | Started, then failed. |
| `2` | Operator input was unusable: a bad flag, a missing or invalid file. |
| `3` | Refused **before** testing: no authorization record, outside the window, or the authenticated-state assertion failed. |
| `4` | Halted mid-run by the kill switch or blocking detection. The report was still written. |
| `5` | Completed, but the artifact bundle **failed the disclosure gate** — do not share it until `clinkz artifact-scan` is clean. |

`auth.json`:

```json
{
  "authorizing_party": "Dana Okafor",
  "authorizing_role": "VP Engineering",
  "authorizing_contact": "dana@example.com",
  "authorization_reference": "SOW-2026-114",
  "permitted_techniques": ["sql_injection", "xss", "idor", "lfi"],
  "emergency_contact": "+1-555-0100 (24h ops bridge)"
}
```

Credentials live in an **untracked** file outside the repo (a git-tracked
credential file is refused outright):

```json
{
  "credentials": [
    {
      "role": "admin",
      "username": "admin@example.com",
      "password": "...",
      "login_url": "https://app.example.com/rest/user/login",
      "assert_url": "https://app.example.com/account",
      "description": "full-access account"
    },
    {"role": "user", "username": "user@example.com", "password": "..."},
    {"role": "anonymous"}
  ]
}
```

Only `role` is required. The other five are per role, and every field lives on
the role entry — **not** at the top level of the file, and not in `scope.json`;
a key at the wrong level is refused by name rather than silently ignored.

| Field | What it does | When you need it |
|-------|--------------|------------------|
| `role` | Labels the principal (`admin` / `user` / `anonymous` / anything meaningful). Required. | Always. **Two authenticating roles is what makes an access-control CONFIRMATION possible.** With one, the IDOR class can establish that a reference nobody owns behaves differently and that an anonymous caller is refused — and still cannot say the object belongs to somebody else, so it reports unproven leads rather than findings ([detail](docs/methodology/idor.md)). `anonymous` names the unauthenticated baseline. |
| `username` / `password` | The credentials. `password` is a `SecretStr` and is registered for redaction on intake. | Any authenticating role. Omit both for `anonymous`. **`username` is also how the access-control classes recognise a role's own records in the target's data** — with a bearer-token login the identity claims are read from the token itself, but a cookie-only session asserts nothing readable, and a role whose identity cannot be read anchors nothing and abstains ([detail](docs/methodology/idor.md)). |
| `login_url` | Where to authenticate **this role**. Overrides the login endpoint discovery found. | The app's login is not at a conventional path (`/login`, `/signin`, `/api/auth`, `/rest/user/login`), or it differs per role. Without it, an undiscoverable login means the engagement **aborts** rather than scanning blind — see below. |
| `assert_url` | A URL known to behave differently authenticated vs anonymous. Tried **first** by the authenticated-state assertion. | The protected surface is named something unconventional, so the assertion's fallback guesses will not find it. |
| `description` | Free-text note, echoed nowhere sensitive. | Documentation for whoever reads the file next. |

**If authentication fails, the engagement stops.** Credentials supplied and the
session not provable is a hard abort before any testing (exit code `3`), with a
message naming what was tried and which of the three causes to fix. The run does
*not* continue anonymously: scanning an authenticated application without a
session produces an empty report that reads like a clean bill of health, which is
worse than no report. Starting with **no** credentials at all is a different and
legitimate case — the run proceeds anonymously and both the log and the report's
authentication section say so explicitly.

> Note: `recon`, `crawl`, `exploit`, and `report` subcommands exist for future per-phase invocation but are still TODO. Use `scan` for the full pipeline.

## Configuration

All configuration is via environment variables in `.env`. The defaults below are the values produced by `Settings.from_env()` in `src/clinkz/config.py`.

### LLM providers and models

**Routing v2: Anthropic is priority 1 for every call, on every phase.** Gemini
and OpenAI are fallback only, and a fallback is a *disqualifying event* — a hard
failure in `baseline` mode, a `provider_degraded` stamp plus permanent
baseline-ineligibility in `client` mode, and **refused outright in both modes on
a call that emits or suppresses a finding**. Full rationale, the call-purpose
rule, and what the run reports about its own routing:
**[`docs/provider-routing.md`](docs/provider-routing.md)**.

| Variable | Description | Default |
|----------|-------------|---------|
| `LLM_PROVIDER` | Legacy top-level provider (last-resort fallback; `openai`/`anthropic`/`gemini`/`ollama`) | `anthropic` |
| `LLM_PROVIDER_DEFAULT` | Default for any agent without an explicit override | `anthropic` |
| `LLM_PROVIDER_RECON` | Recon agent provider | `anthropic` |
| `LLM_PROVIDER_SCAN` | Scan agent provider | `anthropic` |
| `LLM_PROVIDER_REPORT` | Report agent provider — **read by nothing; the Report agent makes zero LLM calls** | `anthropic` |
| `LLM_PROVIDER_EXPLOIT` | Exploit agent provider | `anthropic` |
| `LLM_PROVIDER_RESEARCH` | Research agent provider | `anthropic` |
| `CLINKZ_RUN_MODE` | `client` (a fallback degrades + stamps) or `baseline` (a fallback fails the run) | `client` |
| `ORCHESTRATOR_MODEL` | Model for the Orchestrator agent when the provider is OpenAI | `gpt-4o` |
| `AGENT_MODEL` | Model for phase agents (when provider is OpenAI) | `gpt-4o-mini` |
| `ANTHROPIC_MODEL` | Claude model for every priority-1 call — i.e. every call | `claude-sonnet-5` |
| `GEMINI_MODEL` | Gemini model for any call that fell back (pinned exactly; never a floating alias) | `gemini-3.7-flash` |
| `GEMINI_EXPLOIT_MODEL` | Gemini model used when Exploit falls back to Gemini | `gemini-3.7-flash` |
| `GEMINI_RESEARCH_MODEL` | Gemini model used when Research falls back to Gemini | `gemini-3.7-flash` |
| `GEMINI_THINKING_LEVEL` | `LOW` / `MEDIUM` / `HIGH`. `MINIMAL` is offered by the SDK enum and rejected by the API, so config refuses it | `MEDIUM` |
| `GEMINI_MAX_RPM` | Per-client Gemini requests/minute ceiling (Tier-1 sized) | `30` |
| `RESEARCH_TIME_BUDGET` | Hard wall-clock budget (seconds) for the Research phase | `180` |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GEMINI_API_KEY` | Provider API keys. A detected key confers *availability*, never priority | — |
| `GOOGLE_API_KEY` | Legacy alias for `GEMINI_API_KEY` | — |
| `OLLAMA_BASE_URL` | Ollama server URL (Ollama client is a stub and is in no fallback chain) | `http://localhost:11434` |
| `LLM_REQUEST_TIMEOUT` | Hard timeout (seconds) for a single LLM call | `120.0` |
| `LLM_MAX_RETRIES` | Per-provider retry budget before falling over to the next provider | `3` |
| `LLM_RETRY_BASE_DELAY` | Initial exponential backoff delay (seconds) | `2.0` |
| `LLM_RETRY_MAX_DELAY` | Cap on exponential backoff (seconds) | `30.0` |

**Research is not web-grounded under v2.** It led with Gemini Flash-Lite for
native Search Grounding; the Anthropic path has no equivalent, so a research
answer is bounded by the serving model's training cutoff and its text gives no
sign that anything is missing. This is stamped rather than absorbed: the
grounding travels on every runbook entry and the report carries a **Research
grounding** section stating what it means — and stating explicitly that it does
not reach the findings, since a CVE from research is a lead that must reach one
of this engine's own oracles before it can be a finding.

### Tool execution + state

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PATH` | Per-engagement SQLite database path | `clinkz.db` |
| `TOOL_TIMEOUT` | Tool execution timeout (seconds) | `300` |
| `TOOL_EXEC_MODE` | `docker` (sandboxed) or `local` (host binaries — footgun: namesake binaries can match) | `docker` |
| `DOCKER_CONTAINER` | Docker container name for sandboxed execution | `clinkz-tools` |
| `MCP_SERVERS` | JSON list of MCP server commands or URLs | `[]` |

The cross-engagement persistent KB lives at `clinkz_knowledge.db` (path is fixed today; planned to become configurable).

## Supported Tools

| Tool | Capability | Type |
|------|-----------|------|
| Nmap | Port scanning & service detection | Local CLI / Docker |
| Subfinder | Subdomain enumeration | Local CLI / Docker |
| httpx | HTTP probing & tech detection | Local CLI / Docker |
| WhatWeb | Web technology fingerprinting | Local CLI / Docker |
| wafw00f | WAF detection | Local CLI / Docker |
| Katana | Web crawling | Local CLI / Docker |
| ffuf | Directory & parameter fuzzing | Local CLI / Docker |
| Nuclei | Vulnerability scanning | Local CLI / Docker |
| Nikto | Web server scanning | Local CLI / Docker |
| sqlmap | SQL injection testing | Local CLI / Docker |
| HTTP Client | Custom HTTP requests | Built-in (aiohttp) |
| WebAuthenticator | Default-credential testing (cookie/form + JSON/bearer API auth) | Built-in |
| MCP Servers | Any MCP-compatible tool | MCP Protocol (stdio / HTTP / SSE) |

Tools are discovered dynamically at runtime via `ToolResolver.find_tool(capability=...)` — agents never hardcode tool names. Each capability (e.g. `web_crawling`, `directory_fuzzing`, `port_scanning`) declares a ranked fallback chain in `tools/resolver.py::TOOL_CHAINS`; the resolver walks the chain until a tool is available. Host binary identity is verified at startup (`tools/binary_identity.py`) so a namesake on `$PATH` cannot impersonate a real tool.

## Agents

Every agent runs on Anthropic (routing v2); the "LLM" column says what each one
uses the model *for*, since that is what actually differs.

| Agent | LLM used for | Role |
|-------|--------------|------|
| **Orchestrator** | Nothing on the running path — the phase sequence is deterministic | Central coordinator — Recon → concurrent (Scan + Research + Exploit) → Report |
| **Recon** | Port analysis, tech-stack extraction, synthesis | Port scan → service/version → web recon → tech stack |
| **Scan** | Strategy planning, output review, coverage check | Crawl + fuzz HTTP, enumerate FTP/SSH/SMB/DB; coverage checkpoint via fallback chains |
| **Research** | Query generation + technique synthesis. **Not web-grounded** — see above | Cross-engagement KB lookup + NVD CVE feed; rate-limit-aware with a wall-clock budget; persists techniques back to `clinkz_knowledge.db` |
| **Exploit** | Plans tests, and named checkpoints inside each methodology | Deterministic `_test_*` skills execute; 25 adaptive multi-phase methodologies (injection family: SQLi, NoSQL, SSTI, XXE, …; plus Tier-2 JWT token forgery and SSRF, and one TERMINAL class — server-side prototype pollution — dispatched last because its effect outlives the run) |
| **Report** | **Zero LLM calls** | Pulls findings from state store, emits JSON + Markdown in <30 s |

> **Critic:** archived (`src/clinkz/agents/_archive/critic.py`). It was
> registered in the lifecycle manager and invoked in **0 of 2,774 recorded agent
> steps** — registration made it constructible, never called. Finding validation
> is done by deterministic gates on the emitting path instead: the
> false-positive cross-check, `verification_strength` enforced at
> `_persist_finding`, and CVSS computed in the report.

Four methodology classes decide **without consulting a model at all** —
`security_headers`, `csrf`, `weak_session`, `brute_force`. Their inputs are fully
observed and every rule is a pure function of them, so the LLM was answering a
question the code could already answer, while remaining a live surface on which a
model change could silently re-baseline a class. Each has a test asserting the
model is not *called*, since a test that only compares verdicts passes against a
version that asks and discards the answer.

## Report Output

The current report agent emits:

- `report_<engagement_id>.json` — structured findings (title, severity, CVSS, endpoint, request/response evidence, remediation)
- `report_<engagement_id>.md` — human-readable deliverable

The Markdown report is client-ready: an **authorization header** (who authorized
it, under what reference, over what window, against what scope — in *and* out),
the **authentication outcome** with the discriminator that proved the session,
how the run was conducted (rate, state-changing requests sent, requests refused,
any halt), the findings with remediation, the unconfirmed leads in their own
sections, and a **"What was NOT tested"** section covering excluded hosts,
techniques the client did not authorize, classes with no client-side oracle
(DOM-XSS, CSP enforceability), classes with no methodology (Insecure CAPTCHA,
business logic, races), **shapes a class refuses to confirm on even when the
engagement gave it everything it needs** (an IDOR crossing whose record names no
owner is a lead, because "not mine, not nobody's, not public" is three negatives
a shared record satisfies too), the actions the safety rails refused, and any
coverage
cut short. That section is generated from the class registry and the run's own
action log, so it cannot drift out of date — a client reading "no findings" can
see whether that means "we looked and it is sound" or "we could not look".

Each engagement also produces `outputs/<engagement_id>/trace.jsonl` for
post-mortem inspection and `outputs/<engagement_id>/actions.jsonl` — every
state-changing request the run produced, sent or refused.

Output formats today: **JSON**, **Markdown**, **PDF** — all three rendered from the SAME already-redacted `PentestReport` structure, never from the live findings. The PDF is written at the end of every engagement and regenerable offline with `clinkz report-pdf <engagement_id>`; it leads with the executive summary, then a **control-arm page for every confirmed finding** — the confirming request with its exploitation primitive removed and its marker re-minted, graded by the same oracle, which is the falsifiable half of "confirmed" — then the unproven leads with their `why_unconfirmed`, *What was NOT tested*, and every bound that decided coverage (provider routing, research grounding, plan and crawl truncation) whether or not anything went wrong. ReportLab rather than the Jinja+WeasyPrint pipeline earlier plans named: WeasyPrint resolves GTK/Pango at import and does not import on Windows, so the renderer could not have been executed — let alone verified — on the machine that produces the bundle.

## Testing

```bash
# Keyless gate — unit / agent / tool / orchestrator tests, deterministic and
# container-free (excludes EVERY live/container-dependent suite, so green means
# green with or without containers up).
pytest tests/ -q --tb=short --ignore=tests/test_skills_dvwa --ignore=tests/test_skills_juiceshop --ignore=tests/test_pipeline_smoke --ignore=tests/test_integration

# Container gate — the live suites (require the target containers up; run serially).
pytest tests/test_integration/                          # DVWA + tools containers
pytest tests/test_skills_dvwa/ -m dvwa_smoke            # DVWA at http://localhost:8080
pytest tests/test_skills_juiceshop/ -m juiceshop_smoke  # Juice Shop at http://localhost:3000
pytest -m pipeline_smoke tests/test_pipeline_smoke/     # real orchestrator vs containers

# Run a single test module
pytest tests/test_tools/test_nmap.py -v
```

The full suite is ~750 tests as of W2.1. API-key-gated tests skip cleanly when no keys are present.

## Project Structure

```
clinkz/
├── src/clinkz/
│   ├── agents/          # Phase agents (recon v2, scan v2, exploit v2, research v2, critic, report)
│   │   └── prompts/     # Agent system prompts (.md per agent)
│   ├── comms/           # Message bus + communication protocol
│   ├── credentials/     # CredentialStore for default-credential chaining
│   ├── engagement/      # gate (authorization + window refusals), secrets (credential
│   │                    # intake + redaction), auth_state (detect / PROVE / maintain), dryrun
│   ├── safety/          # destructive (default-deny classifier), governor (rate,
│   │                    # concurrency, kill switch, blocking detection), action_log
│   ├── knowledge/       # MITRE ATT&CK + OWASP WSTG/API/LLM datasets,
│   │                    # persistent_kb (cross-engagement), seed_playbook (Tier 1)
│   ├── llm/             # LLM abstraction (Anthropic, Gemini, OpenAI, Ollama) + ResilientLLMClient
│   ├── models/          # Pydantic v2 models (scope, engagement, vuln_classes, target,
│   │                    # recon, scan, methodology, research, finding, report)
│   ├── observability/   # Per-engagement JSONL execution trace + component ledger
│   ├── orchestrator/    # OrchestratorAgent + AgentLifecycleManager
│   ├── research/        # Runtime web search for CVEs / writeups
│   └── tools/           # ToolBase + ToolResolver (capability + fallback chains),
│                        # binary_identity, docker_preflight, MCP client, individual wrappers
├── scripts/             # Demo / live integration helpers
├── tests/               # Unit, agent, comms, credentials, engagement, knowledge, llm,
│                        # models, orchestrator, safety, integration, skills_dvwa,
│                        # skills_juiceshop
├── docker/              # Dockerfile.tools + Dockerfile.dvwa + meridian/ (the third
│                        #   auth-shape target) + docker-compose.yml
└── docs/                # architecture, adding-tools, playbooks, analysis/*
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code style, and how to add new tools or agents.

## License

[MIT](LICENSE)

## Disclaimer

**Clinkz is intended for authorized security testing only.** Always obtain explicit written permission before testing any system. Unauthorized use of this tool against systems you do not own or have permission to test is illegal and unethical. The authors assume no liability for misuse.
