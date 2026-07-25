# Cross-service reachability — slice B2 (topology LEARNING, the loop half)

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**Status: BUILT.** B1 built *the reach* (compose A's egress with an A→B boundary hop,
grade `CROSS_SERVICE_TOPOLOGY`, confirm ONLY at a collaborator co-located with B).
B2 makes that reach **compound across engagements**: a CONFIRMED A→B reach writes an
abstracted `reaches` topology edge, and a later engagement recalls it to seed a
cross-service chain its cold source could not derive — the live P6 + co-location gate
still being the sole thing that CONFIRMS.

Spec: `docs/discovery-engine-cross-service-reachability-design.md` §6 (catalog
integration) + §6.4 (the role-abstraction poisoning fence) + §7 (the zero-FP
invariant).

---

## The four build pieces

### 1 · `reaches` relation kind + the §6.4 abstraction fence (the load-bearing guarantee)

`technology_relations` previously edged **TECH ↔ TECH** (`bundles`: `apache-solr@8.11.0`
*bundles* `log4j-core@2.14.1`). A `reaches` edge is **SERVICE ↔ SERVICE** — a
*deployment* fact, inherently more target-specific — so the poisoning fence lives at
the **write boundary**, in `relations.py`:

- `abstract_reaches_identity(raw) -> str | None` normalizes an identity to a
  role/tech-class key and **refuses**:
  - a host / IP / URL / `:port` / path shape — a deployment-specific string must NEVER
    enter the cross-engagement KB. Detection is *precise*: it still accepts a recon
    product name that carries a version dot (`Apache Solr 8.11.0` → `apache-solr`) or
    spaces, but rejects a dotted hostname (`internal-db.corp.local`), an IPv4
    (`10.0.0.5`), a bare version (`8.11.0`), a URL, or a `host:port`.
  - a **bare language / runtime** token (`java`, `node-js`, `python`, …) — "every
    X-language app reaches B" is a poisoning-grade over-broad edge, the exact class
    `derive_bundles_edges` refuses for an unversioned app.
  - empty.
- `derive_reaches_edge(a_identity, b_identity, confidence) -> RelationEdge | None`
  builds the edge ONLY when BOTH ends abstract and are not equal (a self-edge is not a
  topology fact). If either end is un-abstractable, it returns `None` and the caller
  keeps the topology **engagement-local** — the confirmed finding still stands, but
  nothing deployment-specific transfers.

**There is no host/IP/URL literal in the fence logic or in any persisted row.**
Identities are supplied from recon/scope (untrusted runtime data), exactly like every
other ingested idiom; the fence only *validates and normalizes shape*.

### 2 · YES-only write-back (`exploit.py::_write_reaches_edge`)

Mirrors the capability loop's YES-only rule and is **structurally** enforced: the write
lives on the CONFIRMED branch of `_confirm_cross_service_reach`, AFTER
`_cross_service_ssrf_emit`. Every non-confirmed outcome — the rung-3 phantom control
(`egress_confirmed_but_B_reach_not_observed`), `blind_unconfirmed_within_window`,
`B_not_instrumentable` — `return`s *before* reaching it, so it is impossible for a
research-lead / unconfirmed / refused reach to persist a durable edge.

- **A's identity** is the *specific* service role, threaded from
  `TopologyContext.origin_identity` → the edge/task's `cross_service_a_identity`
  (`owasp-juice-shop`, not the capability fact's broad app-code key `node-js`). A
  topology reach is a property of the specific service, not the language.
- **B's identity** is `cross_service_b_identity`, recon-derived — **NEVER B's URL**.
- Both are run through `derive_reaches_edge`; an un-abstractable end ⇒ engagement-local
  (logged, no write).

### 3 · Topology recall — a SEPARATE read (`discovery/topology_recall.py`)

`recall_cross_service_edges` is a **pure READ** over the KB `technology_relations`
dump, and it reads **only** `relation_type == 'reaches'` rows. It is **deliberately not
in** `recall.py::_reachable_keys` — that allowlist stays closed to
`bundles`/`successor`, so **a `reaches` edge can never transfer a capability fact**.
Capability transfer and topology transfer are different knowledge kinds and must not
cross (the task's explicit refinement of design §6, which had imagined admitting
`reaches` into `_reachable_keys`).

A recalled `reaches(role-A → role-B)` fires when its A-end matches this engagement's
`origin_identity` and its B-end matches an in-scope B candidate's identity (from
`service_identities`), seeding a cross-service edge via the shared
`build_cross_service_edge`.

### 4 · Load-as-prior (the catalog source)

- `topology_source = 'catalog'`, `reach_confidence = 0.15` — strictly **below** recon
  (0.25): a learned topology is the weakest discovery source, never stronger than
  observing the adjacency now.
- Seeded **only** for B targets the deterministic recon/source pass did not already
  cover (`engine._append_cross_service_edges` runs B1's deterministic pass first, then
  the B2 catalog pass over the uncovered set), so a catalog edge never duplicates nor
  out-ranks a stronger recon/source edge.
- **Still fully proof-gated:** emission stays B1's unchanged co-location + P6 gate. A
  recalled chain is just another candidate the proof engine tries.

---

## The zero-FP invariant across the boundary (§7)

A weak, stale, or wrong cross-service topology prior can only (a) re-order which
candidate chains the proof engine tries, or (b) surface a research-lead. It can NEVER
produce a false finding, because:

1. Emission is reachable ONLY through the unchanged P6 oracle firing at a collaborator
   **co-located with B** (`_persist_finding` is the sole chokepoint).
2. `recall_cross_service_edges` produces only candidate edges — it holds no path to
   `_persist_finding`.
3. The nonce is minted at dispatch and embedded only in the one probe A forwards; a
   callback bearing it can exist only if something executed the egress into B's
   instrumented endpoint. A wrong `reaches` prior cannot forge it, and a
   generic-collaborator callback is *refused* as a cross-service finding (B1's rung-3
   trap).

So a learned topology changes the *tested set / its order / the research-lead list* —
never an emission path.

---

## Scope fence held

No new `PrimitiveClass` / oracle / `_test_*` method; no change to `_persist_finding`;
**no widening of the capability-transfer allowlist** (`_reachable_keys` untouched); no
`similar` edges; no multi-hop chain solver; no sequence/stateful reachability; P1–P6
and B1's co-location gate untouched.

---

## Deterministic proof (keyless)

`tests/test_discovery/test_cross_service_learning.py` +
`tests/test_agents/test_cross_service_learning_writeback.py`:

- **The abstraction fence (validation #1, the primary honesty test):** a
  bespoke/host/IP/URL/bare-language identity can NEVER reach the KB — asserted at the
  fence (`derive_reaches_edge` returns `None`) AND at the KB level (a host-shaped B →
  zero `reaches` rows persisted) AND at the exploit write-back level (an un-abstractable
  B writes no edge while the confirmed finding still stands).
- **No cross-contamination (validation #2):** a `reaches` edge + a capability fact on
  its far end → `capability_recall` returns nothing via the `reaches` edge; the SAME
  shape as a `bundles` edge WOULD transfer (proving the block is specifically the
  `reaches` type, not the fact being unreachable).
- **Topology recall + the catalog seed:** a learned `reaches` seeds a
  `CROSS_SERVICE_TOPOLOGY` / `catalog` / 0.15 edge (< recon 0.25); cold (empty
  relations) → nothing; recon/source-covered targets excluded; un-abstractable origin →
  nothing; B-role mismatch → nothing.
- **The two-engagement mechanic (deterministic half of §8):** with recon adjacency
  WITHHELD, a cold-control (empty KB) yields ZERO cross-service hypotheses while a warm
  run (KB holds the `reaches` edge) seeds exactly one catalog cross-service hypothesis;
  the warm catalog edge ranks strictly below the single-service egress; a real KB
  round-trip (`add_technology_relation` → `get_technology_relations` → recall) confirms
  the write → recall path.
- **YES-only through the real driver:** the co-located arm writes one `reaches` edge;
  the generic-collaborator (research-lead) arm writes none.

## Live validation (§8 two-engagement, no harness)

Driver: `scripts/live_cross_service_topology_learning_validation.py` (Juice Shop A → an
internal B instrumented by the Clinkz collaborator at B's address, a shared
cross-engagement KB, live Anthropic exploit LLM). It is gradeable from raw:
`outputs/cross-service-b2/technology_relations_{before,after}.json` (the abstracted
`reaches` edge, both ends role/class), the cold vs warm edge dumps (0 vs 1
catalog-seeded cross-service hypothesis), and each engagement's `report.json`. The
pre-flight STOPs (never substitutes a harness) unless the Anthropic key live-pings,
Juice Shop is reachable, the source ingests to the cross-service EGRESS_FETCH
hypothesis, and the collaborator passes its self-round-trip health-check.

### Live-run result — PASS (all six §6/§8 checks, verified from raw)

Run against live Juice Shop (`docker cp`'d source) + a live OOB collaborator +
the live Anthropic exploit LLM. Engagements: warm-B = `0297c184`, zero-FP =
`5e905051`. Read directly from the raw artifacts (no trust in the driver's own
summary):

1. **The abstracted `reaches` edge is written, both ends role/class**
   (`technology_relations_after.json`): `owasp-juice-shop → internal-metadata-service`,
   `similarity_score=0.25`, `relation_type=reaches`. **The §6.4 fence holds live:** A's
   real endpoint (`localhost:3000/profile/image/url`) and B's real address
   (`host.docker.internal:18084`) appear **nowhere** in the persisted row — only the
   abstracted roles. `technology_relations_before.json` is `[]`.
2. **Engagement A confirms the cross-service reach** (1 HIGH SSRF finding).
3. **Cold-control B → ZERO cross-service hypotheses** (`engagement_b_cold_edges.json`
   is `[]`): withheld adjacency + empty KB re-derives nothing.
4. **Warm B → one catalog-seeded cross-service hypothesis**
   (`engagement_b_warm_edges.json`): `topology_source=catalog`,
   `reach_confidence=0.15`, `cross_service_a_identity=owasp-juice-shop`,
   `cross_service_b_identity=internal-metadata-service`, on the same `imageUrl` egress
   channel — the withheld chain re-derived purely from the learned edge.
5. **The warm seeded chain is CONFIRMED by the unchanged co-location + P6 gate** — the
   warm finding's evidence is raw-auditable: `confirmation=P6`, the `outbound_probe`
   carrying the nonce, the inbound `callback_nonce`, the never-sent control
   (`control_bore_it=False`), and `topology_source=catalog` /
   `reachability_grade=cross_service_topology`. Recall changed the PATH; the live proof
   confirmed the finding.
6. **Zero-FP:** the zero-FP arm's catalog-seeded chain aimed at a NON-co-located B
   (`internal-metadata-generic`) yields **0 cross-service findings + 1 research-lead**
   (`egress_confirmed_but_B_reach_not_observed`, `topology_source=catalog`) — a learned
   topology is still fully proof-gated by the co-location gate.

**Honest scope of the two-service topology (design §8 / §9 limitation, unchanged from
B1):** service B is instrumented by the receive-only Clinkz collaborator mounted **at
B's address** (the OOB rung), not a full distinct service serving rich in-band content.
The confirmation therefore proves **A reaches B's address** (the nonce callback lands at
B's instrumented endpoint, co-location-gated) — the honest cross-service reach for a B
reachable only through A. It does **not** exercise the in-band P3 rung (a distinctive
B-only marker reflected back), which needs B reachable from Clinkz with its own content
— the harder case the design flags for a later slice. What B2 adds and proves live is
the **learning loop**: a reach A confirmed once is recalled and re-confirmed in a later
engagement that could not observe the adjacency itself.

Raw artifacts (gitignored, regenerated by the driver): `outputs/cross-service-b2/`.
