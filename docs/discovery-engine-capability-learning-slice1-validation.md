# Capability-learning loop — slice 1 (WRITE side) live validation

Engagement-A validation of the Layer-2 capability memory, run for real (no harness,
live Anthropic LLM, live OOB collaborator) against the exact CVE fixture. Driver:
[`scripts/live_capability_learning_validation.py`](../scripts/live_capability_learning_validation.py).
Raw artifacts: [`outputs/capability-learning/`](../outputs/capability-learning/).

## Environment (re-confirmed live, not from the cheat-sheet)

- **Target:** Vulhub `log4j/CVE-2021-44228` — Apache **Solr 8.11.0** + **log4j-core 2.14.1**
  (`< 2.15` ⇒ JNDI message-lookups un-gated), verified in-container:
  `/opt/solr/server/lib/ext/log4j-core-2.14.1.jar`; `/solr/admin/info/system` → `solr-spec-version 8.11.0`.
- **Confirmation channel:** out-of-band (P6) — a CLINKZ-owned nonce-only
  `${jndi:dns://<collab>:<dns_port>/<nonce>}` reaching the collaborator's DNS leg
  (the empirically-reliable docker-mode channel, design §P6.5.4). No in-band signal.
- **Pre-flight (all green before the run):** `ANTHROPIC_API_KEY` + `GEMINI_API_KEY`
  present (counted, never printed); both providers live-pinged OK; Solr reachable;
  the OOB collaborator started and passed its DNS+HTTP self-round-trip health-check.

## What was proven (from raw artifacts, no self-grading)

### (a) Catalog-state diff — the learning is a real row

`capability_facts` before the run: **0 rows**
([`capability_facts_before.json`](../outputs/capability-learning/capability_facts_before.json) = `[]`).
After — **1 confirmed fact**
([`capability_facts_after.json`](../outputs/capability-learning/capability_facts_after.json)),
written through the **real `run()` seam** (`_execute_task → _persist_finding →
_record_finding_to_kb`, provenance stamped from the discovery task):

```json
{ "technology_key": "log4j-core", "version_predicate": "=2.14.1",
  "primitive_class": "log_interpolation", "sink_shape_id": "log4j.log_sink",
  "confirmation_primitive": "P6", "evidence_grade": "confirmed", "confidence": 0.5,
  "first_seen_engagement": "ee5bfe4c-…", "last_outcome": "confirmed" }
```

Keyed on the **carrying dependency** (`log4j-core`), not the app — the transfer key
(§2.4). The `version_predicate` is the exact observed point (`=2.14.1`). Plus **8
`confirmed` observations**
([`capability_observations_after.json`](../outputs/capability-learning/capability_observations_after.json)),
each with `evidence_ref: "finding:<uuid>:P6"` — a **LINK** into the finding's own
`ConfirmationEvidence`, never a bytes copy (§5.3), and `observed_technology:
"java; log4j; solr"` — a fingerprint *string*, **not a host** (the schema-level exfil
guardrail: no host/URL/IP/port/secret column exists).

### (b) Emission unchanged — the write-back changes nothing confirmed

The honest proof is an **A/B**: the same `_test_log4shell` methodology, fired over the
whole channel bag in one request (all params logged together, as the in-repo
`outputs/p6-log4shell` baseline was produced), run twice:

| write-back | agent | distinct findings |
|---|---|---|
| **OFF** (`persistent_kb=None`, no-op) | `agent_off` | **8** |
| **ON** (`persistent_kb=kb`, fact written) | `agent` | **8** |

`emission identical ON vs OFF: True`, and the ON set **equals the baseline's 8-finding
set** (`in warm not baseline: (none)` / `in baseline not warm: (none)`). Layer-2 adds a
DB; it does not add, drop, or alter a single emitted finding — because the write-back
runs in `_persist_finding` **after** the finding is already emitted, and Layer 2 holds
no path to emission.

> Note on the per-task seam: dispatched as one hypothesis **per channel** (the real
> orchestrator shape), only the `action` channel confirms — a single-param request for
> `core`/`name`/… never reaches Solr's `CREATE`-command log line, so it is never logged.
> That is a property of *Solr's logging*, not the write-back. The bundled
> [`report.json`](../outputs/capability-learning/report.json) therefore reflects the
> seam run's state (the `action` confirm) generated before the A/B; the full 8-finding
> emission set (identical to the baseline) is in
> [`live_run_stdout.log`](../outputs/capability-learning/live_run_stdout.log).

### (c) Confidence is a number, provably unused in emission

`confidence = 0.5` on the fact (one confirming engagement: `1 − 0.5^1 = 0.5`, recency
factor 1.0). It is a **PRIOR only**: no `src/` module reads a capability fact
(`get_capability_facts` has **zero callers in src** — recall is slice 2), and the
write-back's `recompute_capability_confidence` return value is discarded. Confidence
cannot gate a finding — structurally, slice 1 does not read facts back.

## Regression — the technique-loop retirement's blast radius

The retirement removed only the `record_technique_result` **write** from
`exploit::_record_finding_to_kb`; the playbook **read** consumers
(`orchestrator::_log_playbook_matches`, `exploit::get_tier2_tests`) and the report's
historical view (`get_past_results_for_technology` over `technique_results`) are
untouched.

- **Keyless gate:** `1491 passed` (incl. `test_persistent_kb` — `record_technique_result`
  / `update_success_rates` / `get_past_results_for_technology` still green — and
  `test_orchestrator`).
- **Real-container `dvwa_smoke` gate** (live DVWA :8080, DB re-initialised):
  **30 passed, 1 xfailed** — the full playbook-consumer pipeline is unregressed; a
  black-box DVWA finding (no discovery provenance) writes **no** capability fact and
  **no** technique result, exactly the deprecate-replace end-state.

## Verdict

```
(a) capability_facts 0→confirmed log4j-core fact + observations : True
(b) emission unchanged (finding SET identical to baseline)      : True
(c) confidence present as a number, provably unused in emission : True
RESULT: PASS
```
