# Clinkz Architecture

## Overview

Clinkz is an autonomous, agentic AI system for black-box penetration testing.
It takes a scope definition as input and produces a pentest report (JSON +
Markdown today; HTML/PDF on the W3 horizon) with no human intervention during
the test.

## Phase shape (v2)

```
Orchestrator
    │
    ▼
ReconAgent             (sequential — full TCP scan + service/version + tech stack)
    │
    ├──► WebAuthenticator  (deterministic default-credential testing)
    │
    ▼
┌─────────────────────────── concurrent ───────────────────────────┐
│                                                                  │
│   ScanAgent       ResearchAgent       ExploitAgent               │
│   (HTTP + FTP +   (persistent KB +    (LLM plans;                │
│    SSH + SMB +     web research;       deterministic _test_*     │
│    DB methods)     writes runbook)     execute; adaptive XSS     │
│                                        and SQLi methodologies)   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
    │                       │                  │
    │ writes endpoints      │ writes runbook   │ writes findings
    ▼                       ▼                  ▼
                  Shared SQLite state (clinkz.db)
                  Persistent KB (clinkz_knowledge.db)
    │
    ▼
CriticAgent      (validates findings — CVSS, evidence completeness,
                  reproduction steps, false-positive rejection)
    │
    ▼
ReportAgent      (zero LLM today — emits JSON + Markdown)
```

Exploit's only hard dependency is Scan: it starts as soon as Scan completes
and never blocks on Research. Research's runbook is folded into Exploit only if
Research has already finished; otherwise Exploit starts immediately and Research
is collected for the report afterwards. Research self-caps at
`RESEARCH_TIME_BUDGET` so it can never hold the engagement open. Cross-phase
re-spins (e.g. Exploit asks for more recon) are capped at
`MAX_CROSS_PHASE_RESPINS = 3` per engagement.

## Deterministic agents with LLM checkpoints

The v2 phase agents do **not** run a free-form ReAct loop. Each follows a
fixed step sequence, and the LLM is invoked only at named reasoning
checkpoints.

### Recon (`agents/recon.py`)

```
1. Full TCP port scan                  (TOOL — deterministic, ToolResolver)
2. LLM analyzes port results           (REASONING checkpoint)
3. Service / version detection         (TOOL — deterministic)
4. LLM extracts tech stack             (REASONING checkpoint)
5. Web-specific recon (conditional)    (TOOL — deterministic)
6. LLM synthesizes summary             (REASONING checkpoint)
7. Build structured ReconResult        (CODE)
```

### Scan (`agents/scan.py`)

```
1. LLM plans scan strategy             (PLANNING checkpoint)
2. Per-service methods (HTTP, FTP,     (TOOL — deterministic per service,
   SSH, SMB, DB); HTTP adds SPA/API     with TOOL_CHAINS fallback +
   route discovery                      _route_discovery.py discoverers)
3. LLM reviews each tool output        (REASONING checkpoint)
4. LLM checks coverage sufficiency     (REASONING checkpoint)
5. Expand coverage if insufficient     (TOOL — conditional)
6. Build structured ScanResult         (CODE)
```

The phase runs under its **own wall-clock budget** (`SCAN_TIME_BUDGET`, default
900 s). The orchestrator's generic phase timeout is a force-kill that discards
the agent's return value, so an over-running scan produces not a smaller attack
surface but none at all — steps 5 and the enrichment loop consult the budget and
stop, and the partial map is returned with the shortfall named in the coverage
gaps. The orchestrator's own scan timeout is `scan_time_budget + grace`, and both
early-stop paths carry through whatever the agent already delivered.

For HTTP services the crawl/fuzz fallback chains are augmented by **API surface
discovery** (`agents/_route_discovery.py`): a set of pluggable
`RouteDiscoverer`s. **None of them carries a list of endpoint names, body field
names, or route words for any particular application** — such a table reports
the same surface whether or not the target has it, which is recall rather than
discovery, and is how a general capability decays into a target detector.

* `JSCallSiteDiscoverer` — the richest source, and the only one that can learn a
  **method** or a **request body** with no served spec.
  `agents/_js_api_mining.py` reads the frontend's own **HTTP call sites**
  (`fetch`, XHR `.open`, axios, Angular `HttpClient`, and browser *navigation*
  via `location.replace`/`href`), recovering method, URL template, query params
  and body shape. Two things make it work on the minified bundles a target
  actually serves: the URL is resolved **backwards** through the nearest
  preceding class-field binding (`host = this.hostServer + "/api/X"`, where a
  minifier has reused `host` in forty classes), and a body shape is recovered
  from member accesses on the body argument — scoped to the **enclosing
  function** and cut at the response-handling chain, because a fixed window gave
  one endpoint the fields of its neighbour and `.pipe(o => o.data)` reads the
  *response* under the same one-letter name. A body the source never names stays
  unknown; unknown is a fact, not an invitation to guess.
* `StaticBundleDiscoverer` — the same bundles scanned for route *literals* under
  the conventional `api`/`rest` prefixes. Weaker (no method, no body), but it
  catches routes referenced where the call-site reader cannot resolve them.
* `OpenAPIDiscoverer` — parse a served OpenAPI/Swagger spec, including
  `requestBody` schemas into JSON-body params, with local-`$ref` resolution and
  remote-ref rejection as an SSRF guard. With no parseable spec it emits
  **nothing**.
* `GraphQLDiscoverer` — probe conventional GraphQL paths; when introspection is
  open, each query/mutation field becomes an endpoint with its declared argument
  names. When introspection is **disabled** that is recorded as a fact and no
  operations are emitted.

What the source cannot say is then learned from the live target
(`agents/_api_schema.py`) using **safe methods only** — the probe is restricted
to `GET`/`HEAD`/`OPTIONS` and that restriction is asserted at the seam:

* `learn_allowed_methods` — `OPTIONS` per route, read from the resource's own
  `Allow` header. `Access-Control-Allow-Methods` is deliberately **not** read as
  an inventory: it is a blanket CORS policy, and doing so manufactured 105 write
  endpoints out of one wildcard header against a live target.
* `learn_body_schema_from_representation` — a REST collection's records name the
  fields its writes accept, and reading them is a `GET`. Server-managed fields
  (identifiers, ORM timestamps) are stripped; a bare-object *status envelope* is
  not treated as a record. A shape already read from the frontend's source is
  never overwritten by one inferred here.

The obvious third source — POST an empty body and read the validation error — is
**deliberately not built**: measured against the live target, two of six
endpoints answered `201 Created` and the probe *created records*, including an
account, during surface mapping. Error responses are still read when one arrives
(`field_names_from_error`); nothing provokes one. The login body instead comes
from the request shape the **authenticator proved**, which is the one schema no
representation and no frontend destructuring can reach.

Results union into `HTTPScanResult.endpoints` (additive, deduped) and flow to Exploit with
their **param structure and location** (`ParamLocation`: query / json_body /
form_body / path / cookie / session, on `Endpoint.param_locations` +
`content_type`; `cookie`/`session` carry cross-request injection points invisible
to `input_params` — DVWA `sqli_blind/high`'s `$_COOKIE['id']` and `sqli/high`'s
`$_SESSION['id']`). The seam is
intentional: a future browser-driven `HeadlessDiscoverer` slots in as another
implementation. Discovery fetches carry the engagement session (cookies +
JWT/bearer) and are bounded and same-origin (safety against SSRF / hostile
bundles). Path-param routes (`/rest/basket/:id`) are emitted as `:id` templates
and resolved at probe time by the Exploit URL builder's `_resolve_path_params`.

The Exploit phase threads each param's `ParamLocation` (`Endpoint` →
`ExploitTask` → `PageAnalysis`) into a **shared request builder**: `_send_probe`
injects a payload into the correct place — query string, JSON request body
(`_http_post_json`), form body, path segment, or a dedicated cross-request
carrier (`_cookie_send_probe` overrides one ambient cookie; `_session_send_probe`
POSTs a session-setter then GETs the trigger, for setter→session→trigger sinks) —
and the form-shaped
methodologies (stored-XSS / CSRF / brute-force) iterate `_injectable_forms`,
which synthesizes a JSON pseudo-form for body-only endpoints that have no HTML
`<form>`. JSON requests carry the same cookie + JWT-bearer session as form posts.

Inside a structured body a field is a **path**, not a name
(`agents/_json_body.py`): `config.app.name`, `items[0].sku`. `_build_json_body`
writes each one into place with `set_json_path`, so the body that goes out has
the shape the target declared. Two rules keep the probe reaching the sink —
only **leaves** are written (replacing a container would destroy the object
holding the field under test), and every **sibling keeps a benign value**,
because an endpoint that validates its input rejects a body whose unrelated
fields were blanked or dropped and a rejected request never reaches the sink.
That is the form-field rule generalized to structure. The NoSQL operator carrier
delegates to the same builder, so the operator and string carriers cannot
disagree about what a nested field is.

On the response side the echo-comparison guard undoes **JSON** string escaping
alongside HTML entities and SQL backslashes — a JSON API re-encodes the payload
on the way out (`<` → `<`), and without it the guard cannot find the echo
it exists to blank. `locate_in_body` reports *where* in the structure a marker
came back: `data[0].comment` is a record the application stored,
`errors[0].msg` is the API quoting our input back — the JSON analogue of
"reflected in an executable context".

Ranking follows: `_CLASS_PRECONDITIONS` gains `body_param`, so a class whose
injection point is a body field grades an API write as **its own surface**
rather than tying with the site's static routes and being dropped at the plan
cap, and `crawl_visit_priority` lifts a conventional API route above an ordinary
page — on an SPA there are no other pages.

### Research (`agents/research.py`) — runs concurrently

```
1. Query persistent KB for tech        (DETERMINISTIC)
2. Web search for new vulns            (TOOL — runtime_research +
                                        native Gemini Search Grounding)
3. LLM synthesizes techniques          (REASONING checkpoint)
4. Query related technologies          (DETERMINISTIC — skipped if budget spent)
5. LLM adapts past techniques          (REASONING checkpoint — skipped if budget spent)
6. Persist to engagement runbook +     (DETERMINISTIC)
   clinkz_knowledge.db
7. Build structured ResearchResult     (CODE)
```

A hard wall-clock deadline (`RESEARCH_TIME_BUDGET`) is armed at the start of the
run: step 2 stops launching web research once it trips and the secondary
related-technology adaptation (steps 4–5) is skipped, so the agent returns
whatever it has rather than stalling on a slow/grounded provider.

`research_additional()` exposes the same flow for technologies Scan
discovers mid-engagement.

### Exploit (`agents/exploit.py`)

```
1. LLM plans exploits from scan +      (PLANNING checkpoint)
   research data
2. Execute by tier:                    (TOOL — deterministic _test_*)
     Tier 1: universal _test_*
     Tier 2: tech-matched playbook
     Tier 3: experimental from runbook
3. LLM reasons through results         (REASONING checkpoint)
4. Adaptive retry / bypass             (TOOL + REASONING)
5. Record technique success/failure    (DETERMINISTIC)
   to persistent KB
6. Structure output                    (CODE)
```

Adaptive methodologies (W2.1) layer multi-phase synthesis on top of two
deterministic skills:

- `_test_xss_reflected` — reflection-context mapping → character-survival
  fingerprint → LLM-driven payload synthesis → bypass attempt
- `_test_sqli` — dialect fingerprint → injection primitive enumeration →
  LLM-driven injection-type selection → payload synthesis

Per-phase intermediate results are modelled in `models/methodology.py`
(`ReflectionPoint`, `CharacterMap`, `SynthesizedPayload`,
`SQLiMethodologyResult`, ...) and persisted in the execution trace.

### Critic + Report

- **Critic** is LLM-only with no tools — validates each finding before it
  enters the report (CVSS accuracy, evidence completeness, FP rejection).
- **Report** is currently zero-LLM — pulls findings from the state store and
  emits JSON + Markdown in <30 s. The LLM-driven multi-pass narrative + HTML/
  PDF rendering remain on the W3 horizon.

## LLM abstraction layer

All LLM calls go through `src/clinkz/llm/base.py`:

```python
class LLMClient(ABC):
    async def reason(messages, tools) -> AgentAction   # tool calling
    async def research(query) -> str                   # web-grounded research
    async def generate_text(prompt) -> str             # plain generation
```

`llm/factory.py` returns the right client per provider. `llm/fallback.py`
wraps it in a `ResilientLLMClient` that rotates providers on rate-limit /
timeout, with per-provider retry budgets (`LLM_MAX_RETRIES`,
`LLM_RETRY_BASE_DELAY`, `LLM_RETRY_MAX_DELAY`).

Each agent has a default provider:

| Agent     | Default provider | Override env var          |
|-----------|------------------|---------------------------|
| Recon     | Gemini Flash     | `LLM_PROVIDER_RECON`      |
| Scan      | Gemini Flash     | `LLM_PROVIDER_SCAN`       |
| Report    | Gemini Flash     | `LLM_PROVIDER_REPORT`     |
| Exploit   | Anthropic Claude | `LLM_PROVIDER_EXPLOIT`    |
| Research  | Gemini 3.1 Flash-Lite (GA) | `LLM_PROVIDER_RESEARCH` |

Research pins its own Gemini model via `GEMINI_RESEARCH_MODEL`
(default `gemini-3.1-flash-lite`) so Recon/Scan/Report keep `GEMINI_MODEL`.
Its `research()` calls use native Gemini Search Grounding for live CVE/writeup
retrieval, and it is rate-limit-aware (`GEMINI_MAX_RPM`, bounded backoff +
fallback) under a hard wall-clock budget (`RESEARCH_TIME_BUDGET`).

Agent code never imports openai / anthropic / google-genai directly.

## Tool abstraction layer

Every local tool inherits from `ToolBase` and implements:

| Method            | Purpose                                       |
|-------------------|-----------------------------------------------|
| `get_schema()`    | OpenAI-compatible function schema for the LLM |
| `validate_input`  | Validate args + check scope enforcement       |
| `execute()`       | Run subprocess, return raw stdout             |
| `parse_output()`  | Convert raw output to a Pydantic model        |

Agents request tools by **capability**, not name:

```python
match = await resolver.find_tool("port_scanning")
if match.source == "mcp":
    result = await match.mcp_client.call_tool(match.name, args)
else:
    tool = match.tool_class(scope=scope)
    result = tool.parse_output(await tool.execute(args))
```

Capabilities have ranked fallback chains (`tools/resolver.py::TOOL_CHAINS`).
The resolver walks the chain until a tool is available or output meets a
threshold (`try_until_sufficient`).

Host binary identity is verified at startup via
`tools/binary_identity.py::verify_binary_identity` so namesake binaries on
`$PATH` (e.g. the Python `httpx` CLI vs. ProjectDiscovery's `httpx`) cannot
impersonate the real tool. By default `TOOL_EXEC_MODE=docker` runs every
tool inside the `clinkz-tools` container; `tools/docker_preflight.py`
ensures the container is up before any tool fires.

## Scope enforcement

`EngagementScope.contains(target)` is called inside every tool's
`validate_input()`. If a target is out of scope, `ValueError` is raised
before any network activity occurs.

## State stores

### Per-engagement (`clinkz.db`)

| Table        | Purpose                                       |
|--------------|-----------------------------------------------|
| engagements  | Engagement metadata and status                |
| targets      | Discovered hosts (`Host` models as JSON)      |
| findings     | Vulnerabilities (`Finding` models as JSON)    |
| endpoints    | Scan-discovered endpoints (Exploit polls)     |
| runbook      | Research-Agent-emitted technique entries      |
| messages     | Agent message log (orchestrator-mediated)     |
| actions      | Every tool invocation with inputs/outputs     |
| attempts     | Retry tracking for failed tool calls          |

### Cross-engagement (`clinkz_knowledge.db`)

| Table                  | Purpose                                       |
|------------------------|-----------------------------------------------|
| playbook_entries       | Tier 1 / 2 / 3 techniques, success rates      |
| past_engagements       | Historical engagements (target, techs, count) |
| technique_results      | Per-engagement per-technique outcomes         |
| technology_relations   | Tech similarity edges for cross-tech transfer |

The persistent KB is what makes Clinkz get smarter over time: every
technique result is recorded, success rates are recomputed, and future
engagements query the KB before reaching for the web.

## Observability

Each engagement writes `outputs/<engagement_id>/trace.jsonl`. Categories:

- `tool_call` — tool name, args, duration, success flag
- `llm_call` — provider, model, prompt size, tokens, latency
- `agent_step` — deterministic step boundary (`recon.port_scan_full`, ...)
- `data_handoff` — Scan→Exploit endpoint write, Research→Exploit runbook write
- `methodology_phase` — adaptive XSS / SQLi phase results

Inspect with:

```bash
clinkz trace inspect <engagement_id>                     # human timeline
clinkz trace inspect <engagement_id> --raw               # JSONL pass-through
clinkz trace inspect <engagement_id> --stage exploit     # filter to one stage
clinkz trace inspect <engagement_id> --category llm_call # filter to one category
```

## Data flow

```
scope.json (input)
    │
    ▼
StateStore.create_engagement()
    │
    ├─► ReconAgent           ─► StateStore.upsert_target()
    ├─► WebAuthenticator     ─► CredentialStore.add()
    ├─► ScanAgent            ─► StateStore.add_endpoint()
    ├─► ResearchAgent        ─► StateStore.add_runbook_entry()
    │                           PersistentKB.add_playbook_entry()
    ├─► ExploitAgent         ─► StateStore.add_finding()
    │                           PersistentKB.record_technique_result()
    ├─► CriticAgent          ─► StateStore.mark_finding_validated()
    └─► ReportAgent          ─► report_<engagement_id>.json
                                report_<engagement_id>.md
```
