# Discovery engine — cross-service reachability (design pass)

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**Status: DESIGN ONLY.** No implementation, no stub, no live run. This is the
frontier prior: extend the middle factor of the Δ-model from single-service to
*across a service boundary*. The whole point of the pass is honesty about
**provable-vs-research-lead** — where a cross-service reach can be *confirmed* by
an existing zero-FP oracle, and where it can only ever be an operator
**research-lead**. That line is the deliverable, not a footnote.

Scope fence (design): the cross-service edge model + the SSRF→internal-service
first target + research-leads + the zero-FP invariant + catalog integration + the
proof plan. **Out of scope:** a general multi-hop chain solver, sequence/stateful
reachability (flagged in §9, not designed), and any change to the proof oracles.

---

## §0 · Starting state (verified against `main`)

The Δ-model the whole engine is keyed on:

> **Vulnerability = Δ-Capability × Untrusted-Channel-Reachability × Provable-Impact**

`compute_reachability` (`src/clinkz/discovery/reachability.py`) produces the middle
factor and is **single-service today**. Its module docstring, line 21, states the
exact boundary this pass moves:

> `Cross-service / sequence reachability remain out of scope.`

Two grades exist, both intra-`SourceModel` (`SoundnessGrade` in
`discovery/models.py`):

| grade | `reach_confidence` | meaning (today) |
|---|---|---|
| `STATIC_CONFIRMED` | `0.9` | intra-function taint the ingestor proved (`CallSite.tainted_by` names the channel param; GeoServer `url`→`openConnection`, Flink `filename`→`new File`) |
| `STATIC_HEURISTIC` | `0.5` (`_LOG_SINK_REACH_CONFIDENCE`) | cross-**function**, single-service (Log4Shell: `action` → dispatch → a deep logging call); a loose prior, P6 proves |
| `HYPOTHESIZED` | `0.4` (`_SEED_REACH_CONFIDENCE`) | a Layer-2 recall seeded a channel the source did not re-derive (`hypothesis.py::_seed_from_recall`) |

Every `ReachabilityEdge` binds a `channel_param` at an entrypoint route to a
`primitive_id`/Δ **both belonging to the one ingested `SourceModel`**. The
entrypoint (service A's handler) and the sink (service A's code) never cross a
process boundary. That is precisely what this design changes: the channel enters
at **service A**'s entrypoint, the sink lives in **service B**, and the reach
spans the A→B boundary — where the novel chains a human misses actually live.

What already exists and is **reused unchanged** by this design (all merged in
`main`):

- The `EGRESS_FETCH` capability class + `_test_ssrf` + the P3 (content-we-never-sent)
  and P1 (open/closed differential) in-band oracles (`catalog.py`, `exploit.py`).
- The **P6 out-of-band** machinery: `OOBCollaborator` (receive-only DNS+HTTP,
  mint/correlate/reap, health-check, `dns_authority`), `_oob_send`,
  `_ssrf_oob_confirm_batch`, `_build_oob_confirmation_evidence`,
  `_ssrf_phase6_emit`; the structural exfil guardrail in `oob/templates.py`.
- The Layer-2 loop: `capability_recall` (pure read), `technology_relations`
  (`bundles`/`successor` writers in `relations.py`, `add_technology_relation` /
  `get_technology_relations`), the `_persist_finding → _record_finding_to_kb`
  write-back chokepoint.
- `EngagementScope` (`models/scope.py`) — the multi-target scope + `contains()`
  address-equivalence that already resolves in-scope sibling services (incl. the
  docker-network container-alias path). **A multi-service scope is already
  expressible**; nothing in the scope model needs to change to *name* B.

This design adds **one reachability grade family**, **one topology-discovery step**,
**one relation kind**, and **one structurally-distinct research-lead type** — and
**no new PrimitiveClass, no new proof oracle, no `_persist_finding` path.**

---

## Leading-hypothesis verdict (ratify / refine / refute)

| # | hypothesis | verdict |
|---|---|---|
| 1 | inter-service edge is a first-class hop, graded below intra-service | **RATIFY with refinement** — it is a *composition* of hops, graded by the **weakest** (min) hop; the A→B boundary hop is a new grade family `CROSS_SERVICE_TOPOLOGY`, always `< HYPOTHESIZED`, and since it is always the weakest hop it dominates the composite (§1) |
| 2 | edges discovered deterministic-first (source / recon / catalog-prior) | **RATIFY** — source (A's egress call_site → B's identity) and recon (in-scope adjacency) are deterministic; catalog (learned A→B topology) is a prior only, lowest grade (§2) |
| 3 | first target = SSRF→internal-service, metadata-impact upgrade, reduces to P6 OOB | **RATIFY, and take the position: REUSE `EGRESS_FETCH`, add NO PrimitiveClass** — cross-service is a *reachability+impact* extension of egress-fetch, not a new capability; but the impact upgrade is only *honest* when the confirmation channel is **co-located with B** (§3) |
| 4 | emission stays proof-gated; unprovable reach = research-lead, never a finding | **RATIFY** — same mechanism-level firewall as the capability-learning §5: cross-service reasoning produces only candidate chains + research-leads and holds no path to `_persist_finding` (§4/§7) |

---

## §1 · Paradigm / edge model — the inter-service hop

**Ratify hypothesis 1, with a refinement that makes it more honest than "add one
edge below intra-service."** A cross-service reach is not a single new edge; it is
a **composition** of three links, and its soundness is the **minimum** of the
composed grades (a chain is no stronger than its weakest link):

```
channel(A)  ──edge₁──▶  A's egress call_site (targets B)  ──edge₂ (A→B boundary)──▶  B's entrypoint  ──edge₃──▶  sink(B)
   └── untrusted param      └── EGRESS_FETCH Δ (existing)        └── the NEW hop           └── B's own reachability (existing shape)
        at A's route            STATIC_CONFIRMED/HEURISTIC          CROSS_SERVICE_*             STATIC_* on B's SourceModel (if ingested)
```

- **edge₁** (channel → A's egress) is an *already-built* `ReachabilityEdge`: an
  untrusted param at A reaching A's `URL.openConnection`/`axios`/`fetch` egress is
  exactly what today produces an `EGRESS_FETCH` SSRF hypothesis. Nothing new.
- **edge₃** (B's entrypoint → B's sink) is *also* an already-built shape — it is
  `compute_reachability` over **B's own** `SourceModel`, *if B was source-ingested*.
  For the SSRF→internal-service first target (§3) edge₃ is trivial (the impact is
  "B answered at all" — reaching an internal admin/metadata surface), so B need not
  be ingested; edge₃ only matters when B *also* has a Δ we want to chain into, which
  is the general multi-hop case this pass **does not** solve.
- **edge₂** (the A→B boundary hop) is the **only genuinely new link**: "A actually
  forwards attacker-influenced data to B." It is the least certain hop because A's
  static source alone cannot prove a *runtime* topology fact.

### The new grade

Add one `SoundnessGrade` member, strictly below `HYPOTHESIZED`:

```
CROSS_SERVICE_TOPOLOGY = "cross_service_topology"   # sketch — not implementation
```

Ordering (strongest → weakest):
`STATIC_CONFIRMED (0.9) > STATIC_HEURISTIC (0.5) > HYPOTHESIZED (0.4) > CROSS_SERVICE_TOPOLOGY (≤ 0.35)`.

Because the composite grade is the **min** over the chain and edge₂ is always the
weakest hop, **every cross-service path is graded `CROSS_SERVICE_TOPOLOGY`** — it
can never out-rank a single-service hypothesis. Within the grade, `reach_confidence`
sub-orders by *how edge₂ was discovered* (§2):

| edge₂ discovery source | `reach_confidence` | rationale |
|---|---|---|
| **source** (A's code statically calls a config/const address that resolves to in-scope B) | `0.35` | A's own source proves the call *intent*; runtime reach still unproven |
| **recon** (A and B in scope, B reachable from A's segment, no source proof of the call) | `0.25` | network adjacency, not a proven call |
| **catalog** (a learned "tech-class-of-A tends to call role-of-B" prior) | `0.15` | a cross-engagement prior only |

This mirrors the discipline the log-sink class already established: **reachability
is a prior that *ranks*; the callback/oracle is what *proves*** (`reachability.py`
§4.3). The cross-service grade never gates emission — it only orders the candidate
chains the proof engine tries, and (§4) the unchanged P3/P6 oracle on the live
target is the sole emission gate.

**Why refine rather than rubber-stamp:** the naïve "single edge graded below
intra-service" reading hides that the A-side (edge₁) may be a rock-solid
`STATIC_CONFIRMED` egress while the *whole chain* is still speculative because
edge₂ is a guess. Grading the chain by its A-side would over-rank it. The min-over-
composition rule makes the grade honest: a cross-service chain is exactly as
trustworthy as the topology inference, and no more.

---

## §2 · Topology discovery — how the A→B edge is found

Three sources, deterministic-first, **each a general shape with no host literal in
schema or logic** — identities come from the runtime `EngagementScope`/recon, never
from a string baked into code.

### (a) SOURCE — A's code calls B (deterministic)

The ingestor **already surfaces** A calling out as an `EGRESS_FETCH` `CallSite`
(`URL.openConnection` / `axios` / `fetch` / `http`). The new, deterministic step:
when an egress `CallSite`'s **target host resolves statically** — a string/const/
config-key literal, an env-var default, a service-client base URL — extract that
host identity and test it against the engagement's *other* in-scope services via
`EngagementScope.contains()`. If it resolves to an **in-scope host distinct from A's
own origin**, that egress is an intentional A→B internal call → a `source`-graded
A→B edge.

- General shape: the recognizer extracts *whatever* host/const the source uses and
  checks it against the runtime scope. No `169.254.169.254`, no service name, is
  ever in the schema or the logic — the literal (if any) is in the *target's* source,
  which is untrusted data, exactly like every other ingested idiom.
- Note the deliberate contrast with SSRF: an SSRF egress target is *request-
  controlled* (dynamic); an A→B internal call target is *config/const* (static).
  The static-target recognizer is what distinguishes "A intentionally calls B" from
  "A has an SSRF." Both can coexist on the same egress (a config default the request
  can override) — that is the metadata-impact-upgrade surface of §3.

### (b) RECON — service discovery (deterministic)

Both A and B are in scope; recon has fingerprinted B's internal endpoint; B is
reachable from A's segment (or is an internal-only metadata/admin service). This is
deterministic from **recon + `EngagementScope`**: the set of in-scope services and
their addresses/roles. The A→B edge here is *network adjacency* ("A can plausibly
reach B's address"), weaker than source because it does **not** prove A's code calls
B — only that the wire is open. `EngagementScope.contains()` + the docker-network
sibling-container resolution already compute exactly this adjacency for the scope's
services; recon topology reuses it.

### (c) CATALOG — learned A→B topology (a prior only)

The C-before-B payoff: the Layer-2 loop catching **cross-service signal**. A prior
over which *service-role pairs* tend to be wired — "an app of tech-class X commonly
reaches a cloud-metadata service," "a service-mesh dataplane reaches its control
plane." This is a **prior, never deterministic**: it recalls a candidate A→B edge
at the lowest `reach_confidence` (0.15), which (like a Layer-2 case-b recall seed)
only *ranks a chain for the proof engine to try* — it never emits (§4/§6).

### Deterministic vs prior — summary

| source | deterministic? | grade / conf | provenance |
|---|---|---|---|
| (a) source egress → in-scope B | **yes** (source + scope) | `CROSS_SERVICE_TOPOLOGY` / 0.35 | A's egress `CallSite` + `scope.contains` |
| (b) recon adjacency | **yes** (recon + scope) | `CROSS_SERVICE_TOPOLOGY` / 0.25 | in-scope service set + address equivalence |
| (c) catalog A→B prior | **no** (prior) | `CROSS_SERVICE_TOPOLOGY` / 0.15 | recalled `reaches` edge (§6) |

---

## §3 · SSRF→internal-service — the first concrete target

**Position (taken, not hedged): REUSE `EGRESS_FETCH`; add NO new `PrimitiveClass`,
NO new proof oracle.**

Rationale, grounded in the class-generic catalog discipline:

- The A-side capability *is* egress-fetch — A makes a server-side request to a
  request-influenced URL. That is already `EGRESS_FETCH` → `_test_ssrf` → P1/P3
  in-band, P6 blind. The Δ-model factorizes **capability × reachability × impact**;
  "reaches an internal service B" is a *reachability + impact* fact, **not a new
  capability**. Adding a PrimitiveClass per topology would fork the catalog — the
  exact anti-pattern the file-read and Log4Shell classes avoided ("the abstraction
  extends, it does not fork," `catalog.py`).
- Concretely, a cross-service SSRF hypothesis is an **`EGRESS_FETCH` Δ whose
  reaching edge carries the `CROSS_SERVICE_TOPOLOGY` grade and whose obligation's
  confirmation target is B's internal URL.** `_test_ssrf` already ranks
  `CLOUD_METADATA` / `INTERNAL_SERVICE` and already confirms via `_SSRF_METADATA_
  SIGNATURES` (metadata content), loopback-origin reflection (`_ssrf_internal_
  confirmation_evidence`), and the blind OOB batch (`_ssrf_oob_confirm_batch`).

### The metadata-impact upgrade — done honestly (the crux)

Today `_test_ssrf`'s in-band internal-service confirmation reflects **A's own
loopback** content (`_ssrf_origin(page.url)` is A's origin). The cross-service
*upgrade* is: the reflected/called-back content originates at **service B** (an
internal admin/metadata surface A should never expose), which is strictly higher
impact than reaching A's own loopback.

That upgrade is **only confirmed** when the confirmation channel is **co-located
with B**. There are exactly two honest rungs, and one dishonest trap:

1. **In-band cross-service (P3 — strongest, with a reachability precondition).**
   A's SSRF param points at B's in-scope internal URL; A's response reflects a
   **marker only B serves** (content we never sent, from *B's* data plane).
   Raw-auditable: reflected B-marker + a control (same probe to a non-resolving
   internal host → marker absent). This is a genuine cross-service CONFIRMED finding.
   **Precondition — the honest fine print:** confirming on a *fetched* B-marker
   requires Clinkz to be able to establish B's marker independently, which means
   either (i) a **static known signature** for B's class (`_SSRF_METADATA_SIGNATURES`
   — cloud-metadata is the canonical case: no direct fetch needed, so it works even
   when B is reachable **only** from A), or (ii) B is **also reachable from Clinkz**,
   so `_ssrf_internal_confirmation_evidence` (generalized to mint the marker from B's
   origin instead of A's loopback) can plant/read the marker. A B that is reachable
   **only through A** and has **no** static signature **cannot** use this rung — it
   falls to rung 2 (OOB) or a research-lead. This is exactly why the §8 experiment
   (a Clinkz-unreachable, network-isolated B) is designed around the OOB rung.
2. **Out-of-band cross-service (P6).** B is OOB-instrumented — the Clinkz
   collaborator (or a marker stub) is mounted **at B's internal address, in scope**.
   A's SSRF param points at B's internal URL bearing a Clinkz nonce; **B** receives
   the inbound callback bearing that nonce → the A→B egress is confirmed by the nonce
   match at B. Reduces to the *unchanged* `_oob_send` → `collab.reap` →
   `_build_oob_confirmation_evidence` machinery; zero new proof code. This is
   hypothesis 3's "confirmed by A fetching B's OOB-instrumented internal URL,"
   ratified.
3. **The trap (forbidden as a finding).** A confirmed blind egress where the
   collaborator is a **generic** sink (not at B) proves only "A egresses *somewhere*"
   — it is *already* plain SSRF, and it does **not** prove "A reaches internal
   service B." Emitting a cross-service *finding* off a generic-collaborator callback
   would conflate "A egresses" with "A reaches B" — a phantom. So the design
   **forbids** a cross-service CONFIRMED finding unless the confirmation channel is
   co-located with B (rung 1 or 2). Otherwise the outcome is a **research-lead** (§5),
   never a finding.

So: reuse `EGRESS_FETCH` + the `CROSS_SERVICE_TOPOLOGY` edge + the existing P3/P6
oracles; the only new confirmation nuance is *where the marker/callback originates*
(service B, not A's loopback / a generic collaborator). This is the same reduction
pattern as file-read (reused `_test_lfi`/P3) and Log4Shell (reused P6) — the class
abstraction holds a topology dimension with no fork.

---

## §4 · Cross-boundary proof + the zero-FP mechanism

### How a cross-service hypothesis is CONFIRMED

By the **actual A→B reach being observed**, through an *unchanged* zero-FP oracle:

- **In-band (P3):** A's response reflects a marker only **B** serves — content we
  never sent, from a *different service's* data plane. The oracle is
  content-we-never-sent; the cross-service dimension only changes the marker's
  origin (B, not A's loopback).
- **Out-of-band (P6):** **B** (instrumented / collaborator-at-B) records an inbound
  callback bearing the probe's single-use nonce. The oracle is the unforgeable
  nonce; the cross-service dimension only changes the callback's *position* (at B's
  address, in scope).

Both are the same oracles already built and live-validated (P3 on GeoServer/Solr,
P6 on Solr/GeoServer). No oracle changes.

### The mechanism-level zero-FP argument (mirrors capability-learning §5)

Cross-service *reasoning* — topology discovery (§2), edge grading (§1), catalog
recall (§6) — **only ever produces or re-orders candidate chains and research-leads;
it holds no path to `_persist_finding`.** Emission is gated **exclusively** by the
unchanged P3/P6 oracle firing on the live target. A topology prior can be wrong in
only two directions, and neither can manufacture a finding:

- **False-positive topology** (A does *not* actually reach B): the proof simply
  never fires — no B-marker reflects, no nonce callback lands at B → no emission,
  at most a research-lead. A wrong A→B edge **cannot** manufacture a marker only B
  serves, and **cannot** forge a nonce callback: the P6 unforgeability argument
  transfers verbatim — the nonce is minted at dispatch (`collab.mint`) and embedded
  only in the one probe A forwards; a callback bearing it can exist only if something
  executed the egress into B's instrumented endpoint. There is no reflection channel
  to the collaborator, so the input-reflection confounder is structurally absent.
- **False-negative topology** (A *does* reach B but we lacked the edge): we simply
  do not generate/rank the chain → a missed candidate, never a false finding. Adding
  or removing a topology edge only grows or shrinks the *tested set* and its order.

Therefore cross-service reasoning is **structurally incapable of manufacturing an
emission** — identical to the Layer-2 recall guarantee. The new grade never gates
emission; it only ranks. This is the load-bearing honesty property, and it is
enforced by *where the code can write* (only candidate chains + a separate
research-lead list), not by convention.

---

## §5 · Research-leads — the honest home for the weak prior

A research-lead is the first-class, **structurally distinct** home for every
cross-service chain that is *plausible but unproven*. It is **not a `Finding`** and
**never passes through `_persist_finding`**.

### Shape (sketch — not implementation)

```
CrossServiceResearchLead:                      # a NEW type, NOT a Finding
    candidate_chain:   channel(A) → egress-edge(A) → A→B boundary edge → (sink/impact at B)
    provenance:        per-hop discovery source (source | recon | catalog) + grades
    why_unconfirmed:   one of {
                         egress_confirmed_but_B_reach_not_observed,   # rung-3 trap: generic collaborator only
                         B_not_instrumentable,                        # cannot co-locate a marker/callback at B
                         blind_unconfirmed_within_window,             # OOB at B sent, no callback
                         topology_prior_only,                         # catalog/recon edge, never probed
                       }
    raw_null_result:   the exact probe sent (from A, carrying nonce/target=B's URL)
                       + the null observation (no B-marker / no callback at B)
    grade:             CROSS_SERVICE_TOPOLOGY + composite reach_confidence
```

### Grading / ranking / surfacing

- Ranked by composite `reach_confidence` (source 0.35 > recon 0.25 > catalog 0.15)
  × the capability's `evidence_grade` weight — the same prioritisation prior the
  hypothesis layer already uses, never an emission gate.
- Bounded per engagement (mirror `_MAX_SOURCE_ABSENT_RECALLS`) so a loose prior
  cannot flood the operator.
- Surfaced in a **dedicated report section** — *"Cross-service research leads
  (candidate chains — UNCONFIRMED)"* — separate from confirmed findings, carrying
  the raw null result so the operator sees exactly what was tried and why it did
  not confirm.

### The hard line

A research-lead is **never** a finding, **never** counted in coverage, **never**
marked "confirmed," **never** rendered in the confirmed-findings section, **never**
written to the capability KB as a positive fact. It is an operator worklist item
("here is a plausible A→B chain we could not prove gray/black-box — investigate with
credentials / network access"). Because it is a *different type* than `Finding`, the
"never emitted as confirmed" line is enforced by the type system + the report
renderer, not by a reviewer remembering a convention — a research-lead is
**structurally incapable** of being rendered as a confirmed finding.

This is the same discipline as SSRF's existing `blind_unconfirmed → operator
research-lead`, generalized to the boundary and made a distinct type so cross-service
speculation can never be confused with proof.

---

## §6 · Catalog / loop integration — compounding cross-service signal

### Write-back (reuses the unchanged chokepoint + ONE new relation kind)

A **confirmed** cross-service SSRF is a normal `Finding` (SSRF, `INTERNAL_SERVICE`
or `BLIND_OOB_CONFIRMED`, evidence naming B) and writes back its capability fact
via the **unchanged** `_persist_finding → _record_finding_to_kb` chokepoint —
`EGRESS_FETCH`, the sink shape, keyed on A's carrying technology. **No new write
path for the capability fact.**

The cross-service dimension adds **one new relation kind** to `technology_relations`:
a **service-topology edge** recording that A *reaches* B.

- **Reuse `technology_relations`, add `relation_type = "reaches"`** (alongside
  `bundles` / `successor`; `similar` stays deferred). The machinery is identical:
  `add_technology_relation(tech_a, tech_b, "reaches", confidence)` writes it,
  `get_technology_relations()` reads it, `normalize_tech_identity` normalizes both
  ends, and recall already expands over the relations table. `recall.py::_reachable_
  keys` filters `rtype not in (RELATION_BUNDLES, RELATION_SUCCESSOR)` today; a
  `reaches` edge would be admitted there under a new expansion branch that seeds a
  **cross-service candidate chain** (case-b analogue) at `CROSS_SERVICE_TOPOLOGY`
  grade — a prior that ranks a chain for the proof engine to try, and **never
  emits**.

### The flagged new-shape caveat (the genuine new risk surface)

`technology_relations` today edges **TECH ↔ TECH** (an identity fact:
`apache-solr@8.11.0` *bundles* `log4j-core@2.14.1`). A `reaches` edge is
**SERVICE ↔ SERVICE** — a *deployment* fact, inherently more target-specific than a
technology identity. To keep the generality law and the §5.3 no-target-literal /
poisoning-safety discipline of the capability store:

- **Both ends of a `reaches` edge MUST be a normalized ROLE / tech-class identity**
  — `internal-metadata-service`, `internal-admin-api`, or the service's tech
  fingerprint — **never a host / IP / bespoke internal hostname.** A host string in
  a cross-engagement edge is exactly how a "general" prior degrades into a
  target-specific leak.
- **If B cannot be abstracted to a role/tech class** (a one-off internal hostname
  with no recognizable role), the topology stays **engagement-local** — it may seed a
  chain and produce a research-lead *this* engagement, but it is **not** written to
  the cross-engagement KB. Un-abstractable topology never transfers.
- Like `bundles`, a `reaches` edge is written only for a **specific** service pair,
  never a bare language ("every Java app reaches a metadata service" would be a
  poisoning-grade over-broad edge — refused, exactly as `derive_bundles_edges`
  refuses an unversioned app).

This is the one place cross-service genuinely introduces a new poisoning surface,
and it is fenced at the write boundary: role/tech-class identities only, specific
pairs only, un-abstractable topology stays local.

### Recall — the C-before-B payoff

Once a `reaches(role-of-A → role-of-B)` edge is confirmed on any one engagement, a
later engagement whose fingerprint matches role-of-A **recalls** the edge and seeds
a cross-service candidate chain the cold source could not derive — the loop
compounding cross-service signal over runs. The seed is a `CROSS_SERVICE_TOPOLOGY`
prior; the **live P3/P6 proof at B** is what confirms it. Recall changes the *path*
to a finding; the proof confirms the finding — never the other way round.

---

## §7 · The zero-FP invariant (across services)

> **A weak, stale, or wrong cross-service topology prior can only (a) re-order which
> candidate chains the proof engine tries, or (b) surface a research-lead. It can
> NEVER produce a false finding.**

Proof (the firewall, restated for the boundary):

1. Emission is reachable **only** through the unchanged P3/P6 oracles firing on the
   **live** target (`_persist_finding` is the sole chokepoint; §4).
2. Cross-service code (topology discovery, edge grading, recall, research-lead
   generation) produces **only** candidate chains and a separate research-lead list;
   it holds **no** reference to `_persist_finding`.
3. The oracles are unforgeable across the boundary: **P3** needs content that only
   **B** serves (a wrong A→B edge cannot fabricate B's data plane); **P6** needs a
   callback bearing a nonce minted at dispatch and co-located with **B** (a wrong
   edge cannot forge it, and a generic-collaborator callback is *refused* as a
   cross-service finding — §3 rung-3 trap).
4. Therefore the only things a topology prior changes are the **tested set**, its
   **order**, and the **research-lead list** — none of which is an emission path.
5. A research-lead is a **different type** than `Finding` (§5), so "never emitted as
   confirmed" is a type-system property, not a convention.

Corollary (the honesty control, transplanted from §2 of the operating contract):
a cross-service chain that "confirms" at *every* topology grade regardless of whether
B was actually instrumented would be an oracle matching A's own response — treat any
cross-service confirm that does **not** carry a B-origin marker or a nonce-at-B as a
phantom and demote it to a research-lead.

---

## §8 · Proof plan — the two-service experiment + the raw metric

### The topology

- **Service A** — an app with a confirmed SSRF egress. Reuse a known-good witness:
  GeoServer CVE-2021-40822 (`live_geoserver_discovery.py` shape) or Solr
  RemoteStreaming `stream.url` — A is in scope and source-ingested; its egress
  call_site targets a request-controlled URL.
- **Service B** — an internal metadata/admin service **reachable only from A's
  network segment** (docker network-isolated so the *only* path to B is through A;
  B is in scope but **not** directly reachable from the Clinkz host). B is
  **OOB-instrumented**: the Clinkz `OOBCollaborator` (or a distinctive marker stub)
  is mounted **at B's internal address**.
- **The reach** — A's SSRF param is pointed at **B's internal URL** bearing a Clinkz
  nonce (OOB) or B serves a distinctive marker (in-band).

### Confirmation

- **OOB rung:** the collaborator-at-B records an inbound callback bearing the probe's
  nonce `T` → `BLIND_OOB_CONFIRMED` cross-service (SSRF finding naming B).
- **In-band rung:** A's response reflects B's marker (content only B serves) → P3
  cross-service.

### The gradeable-from-raw metric (defined NOW)

A grader must be able to read all of the following from `outputs/<id>/report.json`
+ `outputs/<id>/trace.jsonl` **without trusting any prose summary** — the same
raw-auditable bar as the P6 / Log4Shell live validations:

1. **The cross-service EDGE is discovered.** The discovery trace carries the A→B
   topology edge with its `discovery_source` (source egress-target / recon adjacency
   / catalog recall) and its `CROSS_SERVICE_TOPOLOGY` grade + `reach_confidence`.
2. **The reach is CONFIRMED at B, raw-auditable.** The finding's
   `ConfirmationEvidence` carries the pair:
   - **OOB:** the outbound probe *from A* carrying nonce `T` **targeting B's internal
     address** + the inbound callback recorded **at B** bearing the **same** `T`.
   - **In-band:** the reflected **B-only marker** + the **without-reach control**
     (same probe to a non-resolving internal host → marker absent).
3. **The zero-FP controls hold, raw-auditable.**
   - A nonce **minted but never sent** produces **no** callback at B (`control_
     confirms = False`).
   - **Egress-denied** (cut the A→B network path, or drop the carrier) → **no**
     callback → **no** finding, only a **research-lead** with the raw null result.
4. **Topology is only a prior.** A run with the A→B edge **removed** still confirms
   the same SSRF *if the oracle fires* (the edge only re-orders/labels; it does not
   gate the oracle), and a run where A **genuinely cannot** reach B (network-cut)
   yields a **research-lead, never a finding** — both readable from raw. This is the
   direct read of the §7 invariant.

**Pass = all four readable from the raw artifacts, no self-grading.** The experiment
is designed to be run under the same live discipline as the prior slices (live
collaborator + live Anthropic exploit LLM, `TOOL_EXEC_MODE=local`, keys
count-checked and both providers live-pinged before any "real run" claim — the
clinkz-dev validation standard). **No implementation and no run in this pass** — the
metric is defined here so the build cell can be graded against it later.

---

## §9 · Honest risks & open questions

1. **The cross-service prior is genuinely weak.** edge₂ (A→B) is the least certain
   hop and dominates the composite grade (§1). This is *by design* — the grade is
   honest about it, and the prior never gates emission (§4/§7) — but it means most
   cold cross-service chains will be **research-leads, not findings**, until B can be
   instrumented. That is the correct, honest outcome, not a shortfall.
2. **Topology blind spots.** Static source misses **dynamic service discovery**
   (service-mesh sidecars, DNS-SRV, k8s service names resolved at runtime, env-injected
   endpoints) — these surface only via recon adjacency (weaker) or catalog prior
   (weakest), and often only as research-leads. Recon adjacency **over-approximates**
   (open wire ≠ A calls B); the min-grade rule keeps that honest but it inflates the
   research-lead list — hence the per-engagement bound (§5).
3. **Async / queue hops are a harder case (flagged, not designed).** A→B via a
   message queue (A publishes, B consumes) has **no synchronous response**, so the
   in-band P3 channel is broken and the P6 callback may be decoupled/delayed beyond
   the reap window. Such chains mostly yield **research-leads**; a real confirmation
   would need a queue-aware OOB channel — **out of scope**, noted as a limitation.
4. **Research-lead precision vs recall.** Too-loose topology priors flood the
   operator; too-tight misses the novel chains that are the whole point. Mitigation:
   rank by composite confidence, bound per engagement, and **require at least a
   source OR recon edge** (not a catalog-prior-alone chain) to surface a lead by
   default — catalog-only chains are the weakest and can sit behind a verbosity flag.
   Getting this dial right is an open question the proof plan (§8) should measure.
5. **Sequence / stateful reachability (flagged, out of scope).** Reaching B may
   require A to be in a particular state (authenticated, a cache primed by a prior
   request). This design handles a **single synchronous A→B hop only**; stateful
   multi-request reach is a note, not a design.
6. **Multi-hop A→B→C is explicitly out of scope.** The composition model (§1)
   *describes* a chain but this pass does **not** build a general multi-hop chain
   solver (scope fence). Only the single A→B boundary hop into an SSRF-impact B is
   designed.
7. **Service-identity abstraction / KB poisoning** (§6) is the one genuinely new
   poisoning surface. The mitigation — role/tech-class identities only, specific
   pairs only, un-abstractable topology stays engagement-local — is a *policy at the
   write boundary*; whether every real internal service abstracts cleanly to a role
   is an open question. When in doubt, **stay engagement-local** (a research-lead),
   never write a host into the cross-engagement KB.

### What MUST stay a research-lead, never a claim

The sharpest honesty line, restated: **a topology prior + a confirmed A-egress-to-a-
generic-collaborator is NOT proof that A reaches internal service B.** It proves only
that A egresses *somewhere* (which is already plain SSRF). A cross-service CONFIRMED
finding requires the confirmation channel to be **co-located with B** — B serves the
reflected marker (P3) or B records the nonce callback (P6). Absent that co-location,
the outcome is a **research-lead**, full stop. Conflating "A egresses" with "A
reaches B" is the cross-service phantom this design exists to forbid.

---

## Appendix — symbols this design touches (for the build cell)

**Reused unchanged:** `EGRESS_FETCH` / `EGRESS_FETCH_JAVA_OPENCONNECTION`
(`catalog.py`), `_test_ssrf` / `_ssrf_internal_confirmation_evidence` /
`_ssrf_oob_confirm_batch` / `_oob_send` / `_build_oob_confirmation_evidence` /
`_ssrf_phase6_emit` (`exploit.py`), `OOBCollaborator` (`oob/collaborator.py`),
`ConfirmationEvidence` (`models/methodology.py`), `_persist_finding` /
`_record_finding_to_kb` (the write-back chokepoint), `capability_recall`
(`recall.py`), `EngagementScope.contains` (`models/scope.py`).

**New (design, to be built later — not in this pass):**
- `SoundnessGrade.CROSS_SERVICE_TOPOLOGY` (`discovery/models.py`) — one enum member,
  ranked below `HYPOTHESIZED`.
- a cross-service topology-discovery step producing composed `ReachabilityEdge`
  chains graded by min-over-hops (§1/§2) — extends `compute_reachability`, does not
  fork it.
- `relation_type = "reaches"` in `technology_relations` (role/tech-class identities
  only, §6) + a recall expansion branch for it.
- a `CrossServiceResearchLead` type + a dedicated report section (§5), structurally
  distinct from `Finding`.

**Deliberately NOT added:** no new `PrimitiveClass`, no new `_test_*` method, no new
proof oracle, no change to `_persist_finding`, no general multi-hop solver.
