# Clinkz v2 — Semantic Review

Date: 2026-05-06
Goal: surface ambiguous terms, name collisions, and concept drift across
the codebase. The architecture leans hard on shared vocabulary between
agents, models, and the persistent KB; inconsistencies here cause real
bugs (e.g. an agent dumps a `ScanResult` thinking it's a `ServiceScanResult`).

## Glossary — canonical terms

These are the meanings we should converge on. Where the code currently
uses a different term, the conflict is listed in §"Inconsistencies".

| Term | Canonical meaning | Authoritative module |
|---|---|---|
| **Engagement** | One pentest run from scope intake to report delivery. Identified by a UUID `engagement_id`. | `state.create_engagement` |
| **Scope** | The operator-supplied boundary defining which targets are touchable. | `models/scope.py::EngagementScope` |
| **Target** | A scope entry — IP, CIDR, domain, or URL. | `models/scope.py::ScopeEntry` |
| **Host** | A discovered IP with services. Recon-time concept. | `models/target.py::Host` |
| **Service** | A network service on a host port (nmap-style). Same shape regardless of phase. | `models/target.py::Service` |
| **Endpoint** | A specific HTTP URL+method+param set discovered during scanning. | `models/scan.py::Endpoint` |
| **Finding** | A confirmed (or pending) vulnerability with severity, evidence, remediation. | `models/finding.py::Finding` |
| **Technique** | An actionable exploitation procedure — name + description + ordered steps + vuln class. | `models/research.py::Technique` |
| **Playbook entry** | A persisted technique stored in the KB with a tier, regex match pattern, and success stats. Encompasses a Technique + the tracking data. | `knowledge/persistent_kb.py::playbook_entries` table |
| **Tier 1** | Universal tests run on every engagement, regardless of stack. | `seed_playbook.py` + `get_tier1_tests` |
| **Tier 2** | Tests matched to a specific technology via regex. | `get_tier2_tests` |
| **Tier 3** | Experimental tests created by the Research Agent at engagement time. | `get_tier3_tests` |
| **Tool** | A subclass of `ToolBase` that wraps a CLI binary and parses output to a Pydantic model. | `tools/base.py::ToolBase` |
| **Capability** | A capability string like `"port_scanning"` — the abstraction agents use to find tools without naming them. | `tools/resolver.py::TOOL_CHAINS` |
| **Skill** | A markdown procedure document (e.g. `csrf_token_extraction`) that an agent can pull into its conversation via `get_skill_reference`. | `knowledge/skills_loader.py` |
| **Agent role** | One of recon/scan/exploit/research/report/critic. Used as `from_agent` in messages and as keys in `_AGENT_CLASSES`. | `comms/protocol.py` + `lifecycle.py` |
| **Phase** | The macro-stage of the engagement — Recon (1), Concurrent (2), Report (3). | `orchestrator.py::run` |
| **Methodology** | Per-vuln-class structured trace of a `_test_*` invocation (reflections, dialect, primitives, payload). | `models/methodology.py` |
| **Runbook** | Per-engagement transient list of techniques the Research Agent produced for the Exploit Agent. | `state.runbook` table + `models/research.py::ResearchResult.runbook` |
| **Action** | One tool invocation logged for audit (engagement_id, phase, agent, tool, input, output, status). | `state.actions` table |
| **Trace** | Engagement-scoped observability record of agent steps + tool calls + LLM calls. | `observability/trace.py::TraceWriter` |

## Inconsistencies (rank-ordered by impact)

### 1. 🔴 `ServiceScanResult` defined in two modules with different shapes

```
src/clinkz/models/recon.py:51   class ServiceScanResult — recon-phase service scan output
src/clinkz/models/scan.py:104   class ServiceScanResult — scan-phase per-service result
```

These are entirely different concepts:

- `recon.ServiceScanResult` wraps the output of nmap `-sV -sC` — the
  list of `ReconService` objects with versions and script output.
- `scan.ServiceScanResult` wraps a single per-service scan dispatched
  by service type (HTTP / FTP / SSH / SMB / DB), holding a
  `ServiceResult` union.

Both are imported as `ServiceScanResult`. Anyone reading or grepping
will get burned. Today the orchestrator imports `from clinkz.models.recon import ServiceScanResult` (orchestrator.py:46), but if the import line drifts the bug is silent.

**Fix:** rename `models.scan.ServiceScanResult` to
`PerServiceScanResult` (keeps the role but disambiguates).

### 2. 🔴 `ReconService` vs `Service` — same concept, two models

```
src/clinkz/models/target.py:22   class Service       — canonical storage model
src/clinkz/models/recon.py:24    class ReconService  — recon-phase pipeline model
```

`Service` has `port`, `protocol`, `name`, `product`, `version`, `banner`,
`extra_info`, `scripts`. `ReconService` has `port`, `protocol`,
`service_name`, `version`, `scripts_output`, plus an `is_http`
computed field.

The recon agent's pipeline uses `ReconService`; everything else uses
`Service`. The conversion happens implicitly in `_extract_technologies`
(orchestrator.py:914) where it scans dicts that could be either shape.

**Fix:** `ReconService.is_http` is the only uniquely useful thing — move
it as a method onto `Service` (it already has `get_http_services`),
delete `ReconService`. The rename `service_name → name` is cosmetic but
worth doing.

### 3. ⚠️ `ScanResult` vs `result.scan` vs `summary["phases"]["scan"]` — three spellings

The orchestrator stuffs phase outputs into a dict shaped like:

```
summary["phases"]["scan"] = {"status": ..., "result": ScanResult.model_dump(), ...}
```

The Exploit Agent receives `exploit_content["scan_result"] = results["scan"]["result"]`
(orchestrator.py:504). Inside the Exploit Agent the variable is named
`scan_result_data`. Inside `models/scan.py` the class is `ScanResult`.
Each layer renames the same payload.

**Fix:** stabilise on `scan_result` everywhere. Rename
`results["scan"]["result"]` → `results["scan"]["scan_result"]` in the
phase-result dicts. Same applies to `recon_result`, `research_result`.

### 4. ⚠️ `Technique` model overlaps `playbook_entries` row

Research Agent emits `Technique` (Pydantic). It then writes to the KB
using `add_playbook_entry` which takes individual fields including
`steps`, `technique_name`, `technology_pattern`, `tier`. The
`playbook_entries` table row has *more* fields (success counts,
last_used_date) and *different* names (`technique_name` vs the model's
`name`).

Consequence: there's no round-trip — a Technique object goes to the KB
as a dict, comes back as a different dict. Orchestrator.py:1031 does
`entry["technique_name"]` — entries don't deserialize back into
`Technique`.

**Fix:** introduce `PlaybookEntry` Pydantic model (the persistent shape)
and convert between `Technique` and `PlaybookEntry` at the KB
boundary. Stop passing dicts.

### 5. ⚠️ `summary` field overloaded

Three different things called `summary`:

- `recon_result["summary"]` — free-text recon narrative (parsed by regex
  for tech names in orchestrator.py:962)
- `recon_result["llm_summary"]` — same idea but on the v2 model
  (`recon.py::ReconResult.llm_summary`)
- `engagement_summary["status"]` / `summary["phases"]` — the
  orchestrator's overall result dict

**Fix:** rename `recon_result["summary"]` to
`recon_result["narrative"]` (or remove it — it's only used for regex
extraction that already covers `tech_stack.technologies`).

### 6. ⚠️ `WebReconResult.technologies_found` vs `TechStack.technologies`

`recon.py::WebReconResult.technologies_found` is `list[str]`.
`recon.py::TechStack.technologies` is `list[Technology]` (with name +
version + category).

The orchestrator's `_extract_technologies` reads both and merges
(orchestrator.py:907). The `web_info` strings are lossy duplicates of
the structured `tech_stack` data.

**Fix:** populate `WebReconResult.technologies_found` with `Technology`
objects too, or drop the field and read solely from `tech_stack`.

### 7. ⚠️ `actions` (state table) vs `agent_step` (trace event) vs `tool_call` (trace event)

Three audit trails, partially overlapping:

| Trail | What it records | Where |
|---|---|---|
| `state.actions` | One row per tool call: phase, agent, tool, input, output | `clinkz.db` |
| `TraceWriter.agent_step` | Per ReAct iteration: thought, tool name, args, result, duration | trace file |
| `TraceWriter.tool_call` | Per subprocess: cmd, stdout/stderr summary, exit code, duration | trace file |

A single tool invocation produces 3 records (one in each).

**Fix:** decide which is canonical. Trace files are richer; the
`actions` table is queryable. Both have value. **Document the duplication
explicitly** in `state.py` and `trace.py` so contributors don't add a
fourth.

### 8. 📌 `from_agent="orchestrator"` — magic string

`comms/protocol.py::ORCHESTRATOR = "orchestrator"`. Used everywhere as
a free-form string. Recon, scan, exploit, etc. don't have constants —
they're hardcoded as `"recon"`, `"scan"`, `"exploit"` in
`_AGENT_CLASSES` (lifecycle.py:66) and as comparisons throughout.

**Fix:** `comms/protocol.py::AgentRole` StrEnum with all canonical
roles. Importable everywhere a role string is referenced.

### 9. 📌 "Critic" missing from the agent flow

`agents/critic.py` exists, has a system prompt, has tests. It's
referenced in CLAUDE.md, in CLINKZ_V2_IMPLEMENTATION.md. But
`OrchestratorAgent.run` never calls `_run_phase("critic", ...)`.

This is a control-flow drift (covered in `control_flow.md`) but it's
also a semantic issue: anyone reading docs assumes Critic-validated
findings; in practice, findings go straight from Exploit → Report.

**Fix:** either wire Critic in, or remove it from CLAUDE.md and the
implementation plan.

### 10. 📌 "Skill" overloaded

In Clinkz codebase:
- `knowledge/skills_loader.py::SkillsLoader` — loads markdown skill docs
- `tools/auth.py::WebAuthenticator` — labelled with `capabilities = [...]`

In Claude Code (the harness this project is developed in):
- "Skill" = a Claude Code skill (e.g. `phase-work`, `update-config`)

In the v2 implementation plan ("Phase 4: Consistency + Skills"):
- "Skill test" = a deterministic CI test that verifies a vuln
  detector finds a known vuln on DVWA

Three different meanings *inside the project*. The third (CI skill
tests) is the one most exposed to operators.

**Fix:** rename §3 to "skill contracts" or "vuln-detector contracts" in
docs. The markdown agent reference docs (§1) are the only thing called
"skills" in code; that's the usage to keep.

### 11. 📌 "Capability" — agent-level vs tool-level

`tools/resolver.py::TOOL_CHAINS` keys are capabilities like
`"port_scanning"`, `"web_crawling"`, `"sql_injection_testing"`.

`tools/auth.py::WebAuthenticator.capabilities = ["web_authentication", "login", "session_management"]`.

But the agent system prompts (e.g. recon's) also use the word
"capability" to mean "thing the agent can do" — these are higher level
("identify subdomains", "discover services").

Two meanings:
1. Tool-level: a string in `TOOL_CHAINS` keyed by what the tool *does*.
2. Agent-level: a noun phrase in prose describing the agent's job.

**Fix:** restrict "capability" to tool-level only; use "task type" or
just describe in prose for agent-level.

### 12. 📌 `tier` — int (KB) vs str ("tier 1") in prose

`playbook_entries.tier` is `INTEGER` constrained to `(1, 2, 3)`.
Surface APIs: `get_tier1_tests`, `get_tier2_tests`, `get_tier3_tests`
(separate methods), AND `get_playbook_for_technology` returns rows
with `entry["tier"]` as int.

`ExploitTask.tier` is `int = Field(ge=1, le=3)`.

Documentation prose says "Tier 1", "Tier 2", "Tier 3".

This is fine but **only just**. Don't introduce a `Tier` StrEnum
unless you also reshape SQL — keep ints, use a constants module.

## Inconsistencies — minor (catalog, no fix urgency)

- `Severity` enum values are lowercase (`"critical"`, `"high"`).
  `KnowledgeBase` and `playbook_entries.severity` accept arbitrary
  strings. No validation at the KB boundary.
- `category` — used on `ToolBase.category` ("recon"/"scan"/"exploit"/
  "utility") AND on `Technology.category` ("web_server"/"language"/
  "framework"/"database"/"os"/"other"). Disambiguated by context but
  worth a glance.
- `params` (scan model) vs `parameters` (state.endpoints column) —
  same concept, different spelling.
- `engagement_id` vs `eid` — both used in code; pick one.

## Models that should be merged

| Model A | Model B | Recommendation |
|---|---|---|
| `models.recon.ReconService` | `models.target.Service` | Merge into `Service`, add `is_http` method |
| `models.recon.ServiceScanResult` | `models.scan.ServiceScanResult` | Rename one (recommend `PerServiceScanResult` for the scan-phase model) |
| `models.recon.WebReconResult.technologies_found` | `models.recon.TechStack.technologies` | Drop the lossy `list[str]`, use `list[Technology]` |
| `models.research.Technique` | `playbook_entries` row dict | Add `PlaybookEntry` Pydantic model + clean conversion |

## Fields with unclear semantics

- `Finding.evidence: list[str]` — what format? Currently a free-text
  list. Sometimes it's request/response snippets, sometimes it's
  `MethodologyResult.model_dump_json()`. Worth typing as
  `list[Evidence]` with a discriminated union (RequestResponse,
  Methodology, ScreenshotPath).
- `Finding.target: str` — sometimes a URL, sometimes a host, sometimes
  "host:port". Scope-checked downstream relies on `_extract_host`
  parsing. Document the contract: "either a URL or a bare host".
- `ScanResult.coverage_assessment.sufficient: bool` — true means what?
  Look at `agents/scan.py` to understand the heuristic; not obvious
  from the model.
- `ExploitTask.priority: int` — lower is run first per docstring.
  Not enforced by any sort step that's centrally documented.
- `playbook_entries.applicable_vuln_classes: TEXT (json list)` —
  values? `["sqli", "xss"]` from the seed playbook. No enum; nothing
  validates Tier 3 entries from research from putting `["mysterious"]`
  in there.
- `playbook_entries.source_type` — same problem; documented as
  `"manual" / "research_agent" / "cve_db" / "writeup"` but stored as
  raw text.

## Actionable Findings

1. **Rename `ServiceScanResult` collision.** Pick `PerServiceScanResult`
   for the scan-phase model. Update `models/scan.py`, `agents/scan.py`,
   and any imports. ~30-line patch, prevents real bugs.
2. **Merge `ReconService` into `Service`.** Add `is_http` to `Service`,
   delete `ReconService`, update recon pipeline to use `Service`.
3. **Add `PlaybookEntry` Pydantic model.** Round-trip with KB rows;
   stop passing raw dicts; gives the Research Agent a concrete return
   type.
4. **Rename `recon_result["summary"]` to `recon_result["narrative"]`**
   — disambiguates from `summary["phases"]` etc. in the orchestrator
   return value.
5. **`AgentRole` StrEnum in `comms/protocol.py`.** Replace all the
   `"recon"` / `"scan"` / `"exploit"` magic strings used as router keys.
6. **Document the three audit trails (`actions`, `agent_step`, `tool_call`).**
   Either explain why three exist, or merge two.
7. **Strict-validate `playbook_entries.severity`, `source_type`,
   `applicable_vuln_classes` at insert time** — today nothing prevents
   a hostile Research Agent or future contributor from poisoning these
   fields with garbage that breaks downstream queries.
