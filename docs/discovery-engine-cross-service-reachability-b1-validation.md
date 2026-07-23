# Cross-service reachability — slice B1 live validation (the §8 two-service experiment)

**Status: BUILT + LIVE-VALIDATED.** This is the live proof of `docs/discovery-engine-cross-service-reachability-design.md` §8 for the built slice B1 (the reach itself). Run for REAL against a live target + a live OOB collaborator + a live Anthropic exploit LLM, no harness (`scripts/live_cross_service_ssrf_validation.py`). Every claim below is re-derivable from the raw artifacts in `outputs/cross-service-b1/` — no self-graded summary.

## The topology

- **Service A** — OWASP Juice Shop's own-code SSRF egress (`fetch(req.body.imageUrl)` @ `routes/profileImageUrlUpload.ts`), gray-box source-ingested by the JS ingestor and surfaced as an `EGRESS_FETCH` hypothesis (the A2b slice's witness). In scope, running on `:3000`. The SSRF is blind (streams to a file, 302-redirects) and auth-gated, so the honest confirmation channel is **P6 out-of-band** — exactly the §3 precondition under which B is treated as network-isolated from Clinkz.
- **Service B** — an internal service reachable FROM A. The Clinkz OOB collaborator is mounted AT B's internal address (§3 rung 2: "the Clinkz collaborator is mounted at B's internal address, in scope"). Juice Shop (in Docker) reaches the host-side collaborator via `host.docker.internal`, so B's internal address as seen from A is `host.docker.internal:18082`.
- **The reach** — the cross-service SSRF hypothesis (an `EGRESS_FETCH` Δ whose reaching edge crossed the A→B boundary, graded `CROSS_SERVICE_TOPOLOGY`) points A's `imageUrl` param at B's internal URL bearing a single-use nonce.

## The two arms — everything else identical, only the co-location differs

The two arms send the probe to the **same** collaborator (`host.docker.internal:18082`) and differ in exactly one variable: **the declared B**. This isolates the co-location gate (`EngagementScope.addresses_equivalent(collab.callback_zone(), B)` + `scope.contains(B)`) as the sole discriminator between a finding and a phantom.

| arm | declared B | collaborator co-located with B? | outcome |
|---|---|---|---|
| **(b)** | `http://host.docker.internal:18082/` (== the collaborator's address) | **yes** | **cross-service SSRF FINDING** |
| **(c)** | `http://internal-metadata:80/latest/meta-data/` (a *different* in-scope service) | **no** | **research-lead** (`egress_confirmed_but_B_reach_not_observed`) — NO finding |

In **both** arms A egresses to the collaborator (the reap trace shows `callback=True` in both) — so both prove "A egresses somewhere". Arm (c) is the honesty test: that callback proves only plain SSRF, so the system refuses to claim "A reaches internal-metadata" and produces a research-lead instead of a cross-service finding.

## The gradeable-from-raw metric (§8) — all four, from the artifacts

### (a) The cross-service EDGE is discovered — `outputs/cross-service-b1/edge_grade_dump.json`

Both A→B edges the topology composer produced, graded the weakest:

```json
{"hypothesis_id": "hyp:xsvc:egress_fetch...:imageUrl:http://host.docker.internal:18082/",
 "a_endpoint": "http://localhost:3000/profile/image/url", "a_channel": "imageUrl",
 "b_target": "http://host.docker.internal:18082/", "reachability_grade": "cross_service_topology",
 "topology_source": "recon", "reach_confidence": 0.25, "rank_score": 0.1688,
 "test_method": "_test_ssrf", "sink_shape_id": "js.http_egress"}
```

`reachability_grade=cross_service_topology` (min-composed from the intra-function `STATIC_CONFIRMED` `imageUrl` egress edge + the boundary hop), `topology_source=recon` (in-scope adjacency; A does not statically reference B), `test_method=_test_ssrf` (reuses `EGRESS_FETCH` — no new oracle). *(The SOURCE 0.35 upgrade is unit-proven in `test_source_upgrade_when_a_statically_references_b`; the live target has no static reference to B, so it discovers via recon.)*

### (b) CONFIRMED cross-service SSRF, raw-auditable — `report_arm_b.json`

`findings: 1` (HIGH), `research_leads: 0`. The finding carries the P6 pair + control:

- **outbound probe** (from A, carrying the nonce, targeting B): `POST http://localhost:3000/profile/image/url — imageUrl=http://host.docker.internal:18082/spgizgdz4k3s7k6nmbruh6kqne`
- **inbound callback** (recorded AT B, bearing the SAME nonce): `inbound callback: proto=http src=127.0.0.1 host=host.docker.internal:18082 path=/spgizgdz4k3s7k6nmbruh6kqne`
- **the nonce matches** out-and-back: `spgizgdz4k3s7k6nmbruh6kqne` → the unforgeable P6 proof (it existed only in the one probe A forwarded).
- **the never-sent control**: `control_bore_it=False` — a fresh nonce minted but never sent produced no callback.
- **cross-service provenance**: `cross_service=A(...) → B(...) topology_source=recon reachability_grade=cross_service_topology`; `discovery_provenance.confirmation_primitive=P6` (the ACTUAL primitive, not the EGRESS_FETCH obligation's declared P3/P1), `sink_shape_id=js.http_egress`.

### (c) THE PHANTOM CONTROL — `report_arm_c.json` (the honesty test of the whole slice)

`findings: 0` (no cross-service finding emitted), `research_leads: 1`:

```
why_unconfirmed : egress_confirmed_but_B_reach_not_observed
b_target        : http://internal-metadata:80/latest/meta-data/
raw_probe       : POST http://localhost:3000/profile/image/url — imageUrl=http://host.docker.internal:18082/qrjchkyshwahqz23lr3oa55a3y
raw_null        : callback landed at collaborator 'host.docker.internal:18082' which is NOT
                  co-located with B (http://internal-metadata:80/latest/meta-data/) — proves A
                  egresses somewhere, NOT that A reaches internal service B
```

A callback landed (A egressed to the generic collaborator), but the collaborator is not co-located with the declared B, so the system produced a research-lead — **no cross-service finding**. This is the rung-3 trap the design exists to forbid, refused from raw.

### (d) Structural research-lead separation (type-level, not convention)

A `CrossServiceResearchLead` is a different TYPE than `Finding`, persisted to a separate `research_leads` state table, read into a separate `PentestReport.research_leads` field, and rendered in a dedicated *"Cross-service research leads (candidate chains — UNCONFIRMED)"* report section — never counted in the finding totals. Proven at the type/storage level by `tests/test_agents/test_cross_service_ssrf.py::test_research_lead_is_not_a_finding_type` / `::test_research_lead_persisted_to_its_own_table_never_findings` and `tests/test_agents/test_report.py::test_cross_service_research_leads_render_separately_never_counted`. In the live run, arm c's report loaded `0 findings, 1 cross-service research-lead` — the lead is in `research_leads`, never in `findings`.

### The zero-FP invariant, from raw

Both arms sent a probe and both got a callback (`oob_reap … callback=True` in each `trace.jsonl`), yet only the co-located arm emitted a finding. A topology prior changed only which chains were tested and how they were labelled; the unchanged P6 oracle firing **at B** is the sole emission gate. A wrong A→B edge cannot forge the nonce callback (arm c's callback bears a nonce but is not co-located with B → research-lead, never a finding).

## Transparency notes

- **B co-located with the collaborator (arm b)** means the Clinkz collaborator is mounted AT B's internal address — the design's rung-2 realization. `host.docker.internal:18082` is B's internal address as seen from A, and the receive-only collaborator is the instrumented endpoint there.
- **The two arms use one collaborator**, differing only in the declared B, so the experiment isolates the co-location gate as the sole discriminator — nothing else varies between a confirmed cross-service reach and a refused phantom.
- **The P6 cross-service confirmation is deterministic** (OOB has no LLM ranking, exactly like Log4Shell's `_test_log4shell`). The live Anthropic exploit LLM is pinged in pre-flight and the `ExploitAgent` is built with it; the discovery + hypothesis + dispatch (`_execute_task` → `_confirm_cross_service_reach`) path is the real pipeline seam.
- **Pre-flight (STOP-on-fail):** ANTHROPIC key present + a live `generate_text` ping, Juice Shop reachable, the source ingests to the cross-service `EGRESS_FETCH` hypothesis, and the collaborator passes its self-round-trip health-check. `TOOL_EXEC_MODE=local` (host aiohttp), keys count-checked and Anthropic live-pinged before any run claim.

## Raw artifacts

- `outputs/cross-service-b1/edge_grade_dump.json` — the discovered A→B edges (grade + source).
- `outputs/cross-service-b1/report_arm_b.json` / `report_arm_c.json` — both arms' `report.json`.
- `outputs/cross-service-b1/trace_arm_b.jsonl` / `trace_arm_c.jsonl` — the `oob_reap` + emission events.
- `outputs/cross-service-b1/run_summary.json` — both arms + the edge dump.
- `outputs/cross-service-b1/run_log.txt` — the full run log (engagements `568c6d83` arm b / `81825e38` arm c).

Driver: `scripts/live_cross_service_ssrf_validation.py`.
