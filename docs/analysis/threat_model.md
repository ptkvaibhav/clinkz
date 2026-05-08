# Clinkz v2 — STRIDE Threat Model

Date: 2026-05-06
Branch: `feat/v2-architecture`
Scope: production code under `src/clinkz/` plus the Docker tools container.

This document enumerates threats per component using the STRIDE taxonomy
(**S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure,
**D**enial of service, **E**levation of privilege). Each threat is scored
on Likelihood × Impact (Low/Med/High) and tagged with one of:

- ✅ **Mitigated** — controls in place that meaningfully reduce risk.
- ⚠️ **Partially mitigated** — control exists but has known gaps.
- 🔴 **Unmitigated** — no current control; recommend follow-up work.
- 📌 **Accepted risk** — known limitation explicitly accepted by design
  (e.g., predictable cookie-jar path inside a single-tenant container).

Trust boundaries: the LLM provider, the target system, and the Docker
tools container are all *outside* the trust boundary of the orchestrator
process. Anything crossing those boundaries is suspect input.

---

## 1. Orchestrator Agent (`src/clinkz/orchestrator/`)

The Orchestrator is the central brain — it routes messages between phase
agents, owns engagement state, and decides which agent runs when.

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| O-1 | **S**poofing | Phase agent forges `from_agent` field to impersonate Orchestrator on the bus | L×M | ⚠️ Partial | `AgentMessage.from_agent` is set by the sender — not authenticated. In-process trust assumed; would matter if the bus crossed processes. |
| O-2 | **T**ampering | Compromised LLM response causes routing decision to spin up the wrong agent | L×M | ⚠️ Partial | `_handle_query` parses LLM text for `RESPIN_RECON` / `RESPIN_SCAN` / `RESPIN_EXPLOIT` keywords (orchestrator.py:737). A prompt-injected response can force a re-spin. Capped by `MAX_CROSS_PHASE_RESPINS=3`. |
| O-3 | **R**epudiation | Orchestrator decisions not auditable | L×L | ✅ Mitigated | `TraceWriter` (`observability/trace.py`) emits structured trace events for every agent step, tool call, and handoff. |
| O-4 | **I**nfo disclosure | `_gather_state_context` dumps target list, findings, credentials into LLM prompts | M×H | ⚠️ Partial | `c.username:***` masks the password but not the username, target, URL, or finding details (orchestrator.py:1409). All sent to the LLM provider. |
| O-5 | **D**oS | An LLM that never emits a final answer keeps `_react_loop` stuck | M×M | ✅ Mitigated | `DEFAULT_MAX_ITERATIONS` per agent (base.py:47), `_PHASE_TIMEOUT=600s` per phase (orchestrator.py:67). |
| O-6 | **D**oS | Cross-phase re-spin chain creates infinite loop | L×M | ✅ Mitigated | `MAX_CROSS_PHASE_RESPINS=3` global cap (orchestrator.py:70). |
| O-7 | **E**levation | LLM returns a routing keyword that bypasses scope checks via re-spin | L×H | ⚠️ Partial | Re-spin still runs through `_run_phase` which spins an agent that itself calls `_check_scope`. The risk is the *task description* (`query_text`) which becomes the agent input — see O-2. |

**Top concerns:** O-2, O-4, O-7 — all rooted in the LLM-as-router pattern.
Defence in depth: deterministic routing for cross-phase queries (don't ask
the LLM "should I re-spin?"; pattern-match the agent's needs from the
QUERY content); strip credentials/findings entirely from `_gather_state_context`
before sending to the LLM.

---

## 2. Phase Agents (`src/clinkz/agents/`)

Six concrete agents (Recon, Scan, Crawl, Exploit, Research, Report,
Critic). They share `BaseAgent`, which runs the ReAct loop, manages the
inbox, and handles meta-tools (`request_help`, `tool_installation`,
`get_skill_reference`).

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| A-1 | **S**poofing | Mid-run inbox accepts any `AgentMessage` without verifying origin | L×M | ⚠️ Partial | `receive_message` (base.py:266) trusts the lifecycle manager. Same in-process trust model as O-1. |
| A-2 | **T**ampering | Tool output (e.g. nmap's parsed banner) is fed back into the LLM and triggers prompt injection | **H×H** | 🔴 Unmitigated | The whole point of a pentest is that target output is hostile. Everything from `tool.parse_output(...)` ends up as a `role="tool"` message in the conversation (base.py:718). No sanitization, no prompt-injection detection. |
| A-3 | **T**ampering | LLM is convinced via prompt injection in target HTML to call a tool with an out-of-scope target | M×H | ✅ Mitigated | `ToolBase._check_scope` runs in every tool's `validate_input` and raises `ValueError`. The agent gets the error back as a tool result and continues. |
| A-4 | **R**epudiation | Agent ReAct decisions not traceable | L×L | ✅ Mitigated | `_trace_step` after every iteration (base.py:195), plus structured logs. |
| A-5 | **I**nfo disclosure | Captured session cookies are passed in `LLMMessage.content` to the provider | M×H | 🔴 Unmitigated | The Exploit Agent receives `session_cookies` in its task content (orchestrator.py:511). On Anthropic/OpenAI/Gemini, these are transmitted in plaintext to the provider (TLS in transit, but stored/logged on the provider's side). No redaction layer. |
| A-6 | **I**nfo disclosure | `tool_installation` meta-tool installs attacker-named packages via apt/pip/go/git | L×H | ⚠️ Partial | The container is single-tenant; if the LLM hallucinates a typosquat package name, it gets installed and run. No allowlist. |
| A-7 | **D**oS | Agent loops on the same tool call forever | L×M | ✅ Mitigated | Repetition detection (base.py:622) and same-URL detection (base.py:659) inject redirect prompts after 3 repeats. |
| A-8 | **D**oS | `_max_consecutive_failures = 3` skips a tool but engagement runs on broken state | L×M | ⚠️ Partial | The agent gets a "skip and move on" instruction (base.py:704) but no rollback. |
| A-9 | **E**levation | `tool_installation` runs `apt`/`pip` inside the tools container as root | M×M | 📌 Accepted | Container is sandbox-by-design (single-tenant, no host volume mounts beyond the workspace). Documented in `docker/`. |

**Top concerns:** A-2 (target prompt injection), A-5 (cookies to LLM
provider), A-6 (LLM-driven package install).

---

## 3. Tool Wrappers (`src/clinkz/tools/`)

ToolBase wrappers translate LLM intent into subprocess calls. Each tool
runs locally (host) or via `docker exec` against the `clinkz-tools`
container, depending on `settings.tool_exec_mode`.

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| T-1 | **S**poofing | Local-mode resolver matches a host binary that shares a name with a pentest tool (e.g. Python's `httpx` CLI vs ProjectDiscovery's) | M×M | ✅ Mitigated | `tool_exec_mode` defaults to `"docker"` (config.py:79). Resolver also has identity probes (`_identity_ok` in resolver.py:643). |
| T-2 | **T**ampering | Command injection via LLM-supplied arguments (target, ports, paths) | L×H | ✅ Mitigated | `_run_subprocess` always uses `asyncio.create_subprocess_exec(*cmd)` with a list — never `shell=True` (base.py:208). LLM args go through `validate_input` per tool. |
| T-3 | **T**ampering | XML/output parser blow-up from malicious target XML (nmap, etc.) | L×M | ✅ Mitigated | `defusedxml` is in deps; recent commit `c15da5e` addressed XML hardening. |
| T-4 | **R**epudiation | Tool execution not audited | L×L | ✅ Mitigated | `state.log_action` + `state.complete_action` per call (base.py:812-826), plus `TraceWriter.tool_call` for stdout/stderr/exit code. |
| T-5 | **I**nfo disclosure | Cookie jar at predictable path `/tmp/clinkz_<engagement>_cookies.txt` inside container | L×M | 📌 Accepted | Marked `# nosec B108` with rationale: container is single-tenant by design. Comment chain in orchestrator.py:515 and tools/auth.py:566. |
| T-6 | **I**nfo disclosure | Subprocess stdout (potentially containing creds in URLs, headers) sent to LLM | M×M | 🔴 Unmitigated | Tool wrappers parse output into Pydantic models, but the model is then `model_dump_json()`'d back into LLM context (base.py:825). Credentials embedded in URLs (`http://user:pass@host`) get dumped. |
| T-7 | **D**oS | Subprocess hangs past `timeout=300s` | L×L | ✅ Mitigated | `asyncio.wait_for(proc.communicate(), timeout=self.timeout)` (base.py:213). |
| T-8 | **E**levation | Tool runs against an out-of-scope target | L×H | ✅ Mitigated | Every tool calls `self._check_scope(target)` in `validate_input`. `EngagementScope.contains` handles URL/host/CIDR normalization (scope.py:71). Excluded targets take precedence. |
| T-9 | **E**levation | Path traversal in `installer.py` writes outside container | L×H | ⚠️ Partial | Installer uses `apt`/`pip`/`go install` semantics — no manual path writing for these. `download` mode writes to a fixed location; need to audit (see follow-up below). |

**Top concerns:** T-6 (creds in tool output → LLM provider).

---

## 4. Persistent Knowledge Base (`src/clinkz/knowledge/persistent_kb.py`)

A separate SQLite database (`clinkz_knowledge.db`) shared across
engagements. Stores playbook entries, technique results, technology
relations, past engagements.

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| K-1 | **S**poofing | Research Agent in one engagement plants a malicious "technique" the next engagement runs blindly | **M×H** | 🔴 Unmitigated | `add_playbook_entry` accepts arbitrary `steps` (list[str]) and `technology_pattern` (regex). Entries are persisted across engagements. A single engagement against a hostile target could write whatever it wants. |
| K-2 | **T**ampering | KB poisoning via crafted `technology_pattern` regex causing ReDoS on every future engagement | L×M | 🔴 Unmitigated | `re.search(pattern, technology, re.IGNORECASE)` (persistent_kb.py:203). No regex compilation timeout. A pathological pattern persists forever. |
| K-3 | **T**ampering | SQL injection in KB writes | L×H | ✅ Mitigated | All writes use parameterized queries (`?` placeholders). |
| K-4 | **R**epudiation | KB rewrites have no provenance | M×L | ⚠️ Partial | Each entry has `created_from_engagement` and `updated_at`, but there's no immutable audit trail — a future engagement could `INSERT OR REPLACE` over an existing row. |
| K-5 | **I**nfo disclosure | KB persists `findings_summary` from past engagements; reading from disk reveals client-engagement details | L×M | 📌 Accepted | The KB file lives on the operator's machine. File-system permissions are the boundary. |
| K-6 | **D**oS | Catastrophic regex in `technology_pattern` slows every subsequent engagement linearly with KB size | L×M | 🔴 Unmitigated | `get_playbook_for_technology` iterates **all** entries and runs the regex on each (persistent_kb.py:201). N regex evals per query. |
| K-7 | **E**levation | None directly | — | — | KB is not a privilege boundary on its own. |

**Top concerns:** K-1, K-2, K-6 — KB poisoning is the highest novel risk
introduced by v2's persistence layer. A single engagement against a
hostile target *and* an LLM with prompt-injection susceptibility is
enough to taint the KB permanently.

---

## 5. State Store (`src/clinkz/state.py`)

Per-engagement SQLite database (`clinkz.db` by default), WAL mode,
holds engagements, targets, findings, actions, attempts, agent_messages,
sessions, endpoints, runbook.

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| S-1 | **S**poofing | Concurrent writes from research/scan/exploit corrupt state | L×M | ✅ Mitigated | WAL mode enabled (state.py:163). aiosqlite serializes writes per connection. |
| S-2 | **T**ampering | SQL injection via untrusted JSON payloads | L×H | ✅ Mitigated | All writes use parameterized queries; JSON blobs are stored as opaque text. |
| S-3 | **R**epudiation | Engagement timeline reconstruction relies on `created_at` strings | L×L | ✅ Mitigated | All tables have `created_at` / `updated_at` strings; trace writer is independent. |
| S-4 | **I**nfo disclosure | Session cookies and credentials stored in plaintext SQLite | **M×H** | 🔴 Unmitigated | `sessions.cookies_json`, `credentials.password` (in `credentials/store.py`). DB file is on disk in the project root by default (`db_path = Path("clinkz.db")`). |
| S-5 | **D**oS | Unbounded growth of `actions` / `agent_messages` tables in long engagements | L×L | ⚠️ Partial | No retention policy. Local-disk concern, not security-critical. |
| S-6 | **E**levation | None directly | — | — | |

**Top concerns:** S-4 — unencrypted creds and session cookies on disk.

---

## 6. LLM Clients (`src/clinkz/llm/`)

Provider-specific implementations behind the abstract `LLMClient`.
`ResilientLLMClient` cycles through a fallback chain on rate-limit /
unavailable errors.

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| L-1 | **S**poofing | Compromised provider DNS / TLS MITM returns attacker-controlled responses | L×H | ⚠️ Partial | We rely on the SDKs' built-in TLS verification. No certificate pinning. |
| L-2 | **T**ampering | Provider response tampered with via the network → tool calls executed against attacker targets | L×H | ⚠️ Partial | `_check_scope` in tools is the last line of defense (T-8). The fallback ordering means a single tampered response just gets one tool call, then the cycle returns to safer paths. |
| L-3 | **R**epudiation | LLM provider doesn't log requests; we have no record on their side | L×L | ✅ Mitigated | We log all prompts/responses locally via `TraceWriter`. |
| L-4 | **I**nfo disclosure | Every prompt with target data, creds, cookies, findings is sent to the LLM provider | **H×H** | 🔴 Unmitigated | This is the architectural choice (LLM-mediated agentic). Compliance concern for real engagements. No on-by-default redaction. |
| L-5 | **I**nfo disclosure | API keys leak via env vars in subprocess — `docker exec` does not forward env, but error logs may print env | L×M | ✅ Mitigated | API keys are loaded from `.env` via `python-dotenv` and read in-process only (config.py:17). Never passed to `_run_subprocess`. |
| L-6 | **D**oS | Provider rate-limit kills engagement | M×M | ✅ Mitigated | `ResilientLLMClient` cycles through chain (`fallback.py`). `validate_agent_chains` fails fast at startup if no provider is configured. |
| L-7 | **E**levation | `tool_installation` schema lets the LLM install software | L×H | (see A-9) | Already covered. |

**Top concerns:** L-4 — every byte of engagement data crosses the LLM
provider boundary.

---

## 7. Docker Tools Container (`docker/`)

The `clinkz-tools` container holds nmap, ffuf, nuclei, sqlmap, etc. The
orchestrator process runs on the host and shells out via `docker exec`.

| # | Category | Threat | L×I | Status | Notes |
|---|---|---|---|---|---|
| D-1 | **S**poofing | Wrong container name in `DOCKER_CONTAINER` env → commands run against another container the user has running | L×M | ⚠️ Partial | `ensure_container_ready` (`tools/docker_preflight.py`) verifies the container exists. Doesn't verify it's the `clinkz-tools` image. |
| D-2 | **T**ampering | Persistent state inside the container leaks between engagements (cookie jar, downloaded payloads, /tmp files) | M×M | ⚠️ Partial | Cookie jar uses engagement-prefixed names (`/tmp/clinkz_<eid>_cookies.txt`), but other tool state is shared. Recommend container restart between engagements. |
| D-3 | **R**epudiation | No host-side logging of arbitrary commands run via `docker exec` | L×L | ✅ Mitigated | `TraceWriter.tool_call` records full argv. |
| D-4 | **I**nfo disclosure | Container has root and access to other containers on the same Docker network (e.g. DVWA at 172.x.x.x) | L×L | 📌 Accepted | This is the *point* — pentest tools need to reach the target. Host network isolation handled by Docker. |
| D-5 | **D**oS | Container runs out of disk from logs, captured payloads, sqlmap traces | L×L | ⚠️ Partial | Visible from leftover `sqlmap_*` directories in repo root (git status shows 4 untracked dirs). No cleanup hook. |
| D-6 | **E**levation | Container escape via known kernel vuln | L×H | 📌 Accepted | Inherent to Docker. Mitigated by keeping the host kernel patched. |

**Top concerns:** D-2 — engagement isolation inside the container is
not airtight.

---

## Special Focus Areas

### Scope Enforcement

`EngagementScope.contains` (scope.py:71) is the chokepoint. Every tool
calls `_check_scope` in `validate_input`. The Orchestrator never executes
tools directly — it spins up agents that use tools. Agents cannot call a
tool without going through the wrapper.

**Failure modes that bypass scope:**

1. ⚠️ The Orchestrator's `_attempt_login` and `_probe_url` helpers
   instantiate `WebAuthenticator` and `HTTPClientTool` directly and rely
   on those tools' own `_check_scope` (orchestrator.py:1190, 1356). This
   *is* enforced — but it's a different code path from agent tool dispatch.
2. ⚠️ `_handle_query`'s `RESPIN_*` keyword routing (orchestrator.py:737)
   takes the LLM's word for which agent to spin up, then passes the raw
   `query_text` (which originally came from another agent's LLM) as the
   new agent's task. The new agent will still scope-check tool calls,
   but the *task description* is unconstrained — could induce the new
   agent to attempt out-of-scope targets repeatedly until the iteration
   limit is hit. Each attempt fails closed, so this is a DoS, not a
   scope bypass. Net status: ✅ scope-safe, ⚠️ wastes iterations.
3. 📌 No per-port enforcement except `allowed_ports` (scope.py:67) which
   is currently advisory — no tool wrapper actually consults it.

### Credential Handling

WebAuthenticator (tools/auth.py) handles login. Credentials enter via
`CredentialStore.seed_defaults` (DVWA `admin:password` etc.) or operator
input. After successful auth, cookies are stored in:

- `sessions.cookies_json` in the state DB (S-4 — plaintext)
- A Netscape cookie jar at `/tmp/clinkz_<eid>_cookies.txt` inside the
  container (T-5 — accepted risk; container is single-tenant)

Credentials in motion:

- ⚠️ Username and password are passed verbatim to the LLM via the
  Exploit Agent task (`exploit_content["authenticated_as"]` is the
  username; the password is *not* sent — orchestrator.py:516, that's
  the right call). The LLM sees the username and the cookie. **Do not
  ever put the password into LLM context.** Currently we don't, but
  there's no test enforcing that.
- 🔴 Logging redaction: `self._logger.info("DEFAULT CRED VALID: %s:%s on %s", cred.username, "***", login_url, tech)` masks the password (orchestrator.py:867). Good. But the surrounding trace events emit the
  whole `cred.model_dump()` chain in some places (search for
  `cred.model_dump()`); needs an audit pass.

### Tool Output as LLM Input

This is the highest-risk surface. Every `tool.parse_output(raw)` becomes
a `role="tool"` LLM message (base.py:783). Target-controlled HTML, HTTP
headers, banners, and DB error messages all flow into the LLM prompt.

A target server that responds with the right HTML can:

- Inject instructions that reframe the LLM's task
- Flip a finding from confirmed → false-positive (or vice-versa)
- Convince the LLM to call `tool_installation` to install a specific
  package (A-6)
- Convince the LLM to call `request_help` and surface arbitrary text
  to the Orchestrator's `_gather_state_context`

Mitigations today:

- Tool wrappers parse to Pydantic models (no raw string fed back)
- Scope checks (T-8) prevent out-of-scope targeting
- Iteration / repetition / failure caps (A-7, A-8)

What's missing:

- 🔴 No marker delimiting "untrusted target output" inside the LLM
  conversation. Modern providers honor explicit `<untrusted>` tags;
  we don't use them.
- 🔴 No content filter on tool output before LLM ingestion (e.g. strip
  obvious prompt-injection markers like "ignore previous instructions").

### Persistent KB Poisoning

A single hostile engagement can taint the KB forever:

1. Target serves HTML that prompt-injects the Research Agent
2. Research Agent calls `add_playbook_entry` with a malicious
   `technique_pattern` regex (catastrophic backtracking) or `steps`
   that subsequent engagements execute
3. Future engagements: every `get_playbook_for_technology` query
   evaluates the bad regex; the malicious entry is treated as
   trusted source material

Mitigations today:

- Tier 1 entries are seeded at engagement start by `seed_tier1_tests`
  (orchestrator.py:193), but they don't *replace* prior tampered Tier 1
  entries — they `INSERT OR IGNORE` semantics from `seed_playbook.py`.
- No regex compile budget, no steps-content allowlist.

---

## Actionable Findings

### Top priority (do before next push that touches an agent)

1. **(A-2, L-4) Mark tool output as untrusted in LLM prompts.** Wrap
   every `role="tool"` content in delimiter tags and add a system-prompt
   instruction that text inside those tags is target-controlled and
   never executable.
2. **(K-1, K-2) Validate playbook entries on write.** Compile the
   regex with a length cap, reject patterns whose `re.compile()` takes
   > 100 ms, allowlist `source_type` values, and forbid Tier 3 entries
   from overwriting Tier 1 / Tier 2 rows.
3. **(S-4) Encrypt session cookies and credential records at rest.**
   Either encrypt the relevant JSON fields with a per-engagement key
   derived from an env var, or move them to an OS keyring. Today the
   plaintext sits in `clinkz.db` next to engagement reports.

### Medium priority

4. **(O-2, O-7) Replace LLM-routed re-spin decisions with deterministic
   routing.** The LLM picks which agent answers; replace with a switch
   on the QUERY content's `needs_agent` field (already populated by
   `request_help`).
5. **(T-6) Redaction layer between tool output and LLM ingestion.**
   Strip basic-auth credentials from URLs (`http://u:p@host` → `http://host`),
   strip `Authorization` headers, strip `Set-Cookie` values past the name.
6. **(A-6) Allowlist for `tool_installation`.** Maintain a registry of
   approved tool names per install method; reject anything else.
7. **(K-6) Index `playbook_entries` by tier and add a per-query regex
   budget.** Move tier filtering to SQL, use compiled-regex cache, cap
   iterations.

### Lower priority

8. **(A-5) Encryption-in-flight to LLM provider** is already TLS; add an
   on-by-default redaction layer for cookies before sending Exploit-Agent
   task content to the LLM.
9. **(D-2) Container reset between engagements** — add a `--fresh-container`
   CLI flag that recreates `clinkz-tools` before the engagement starts.
10. **(scope.allowed_ports)** Currently advisory. Either remove the field
    or wire it into `_check_scope`.
