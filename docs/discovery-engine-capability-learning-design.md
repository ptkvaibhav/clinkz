# Discovery engine — the capability-catalog LEARNING LOOP (Layer 2)

**Status: design pass only.** No implementation code, no live run, nothing to validate
yet. This doc is the detailed spec that [`discovery-engine-design.md`](./discovery-engine-design.md)
§3.3 / §4.3 / §7 defer ("the learning loop … expressed at the primitive level"). It is
graded as a document before any code is written.

**Scope fence (held hard).** This designs **only** Layer 2 — the per-technology
capability memory, its write-back / load-as-prior loop, its reconciliation with the
existing `knowledge/persistent_kb.py`, and its proof plan. It does **not** touch the
proof engine, Layer 1's P1–P6 oracles, or cross-service reachability (a separate fork).
No target/tech literal appears in any schema or logic below — general shapes only; the
concrete CVEs are named solely as *witnesses* and fixtures (the generality law).

---

## 0. TL;DR

- **Ratify the two-layer split, with two sharpenings** (not a rubber-stamp; §1). Layer 2
  is the **Capability term only** — `Δ = Capability(technology) − Intent(developer)` — so
  a Layer-2 fact is a *capability-recall prior*, **never** a reachability or exploitability
  assertion (Intent + Reachability stay per-engagement). And Layer 2 grows *facts*, not the
  *recognizer*: the source-idiom recognizer in `source_ingest.py` is invariant machinery,
  like Layer 1's oracles.
- **KB reconciliation: deprecate-replace, not coexist** (§2). The technique-success learning
  loop (`technique_results` + `playbook_entries.success_rate`) is retired as a learning
  mechanism; the new Layer-2 store is the **one** cross-engagement learning system.
  `playbook_entries` survives demoted to a static *content* library (Research/Tier-2/3
  methodology text — an input, not a loop, so no conflict). `technology_relations` is
  **reused and finally given a writer** (today it is dormant).
- **Write-back is YES-only** (§3). Confirmed → durable positive capability fact (+ observation).
  Failed / blind_unconfirmed / collaborator_unavailable → an append-only **observation**
  (provenance + engagement-local budget hint) but **never a negative capability fact**.
  Defended as the poisoning-safe choice: remembering YES is budget-bounded and self-correcting
  by proof; remembering NO is unbounded and self-concealing (§3.5).
- **Load-as-prior, never emission** (§4). Recall re-orders and completes *which hypotheses
  are tested*; the unchanged P1–P6 proof engine on the live target is the only thing that
  emits.
- **Zero-FP is structural** (§5): Layer 2 holds no path to `_persist_finding`, and because it
  stores no negative facts it also cannot suppress a hypothesis → it can raise recall without
  risking either a false positive or a memory-induced false negative.

---

## 1. Paradigm — ratify or refute the two-layer split

**Verdict: RATIFIED, with two load-bearing sharpenings.** The split is correct against both
the Δ-model and the code, but the brief's phrasing hides two things that, left implicit, would
let Layer 2 become an FP/FN source. I state them as corrections, not decoration.

### 1.1 The split, mapped onto real symbols

`Δ = Capability(technology) − Intent(developer)`. The two factors have opposite lifetimes:

| | What it answers | Lifetime | Where it lives today |
|---|---|---|---|
| **Layer 1 (INVARIANT)** | "How do I *prove* a capability of class `P`?" | Grows only when a new proof-class is built | `ProofObligation` (`test_method` + `confirmation_primitives` ⊆ P1–P6) — the *invariant half* of a `CapabilityPrimitive` |
| **Layer 2 (GROWS)** | "What capabilities does `T@version` *have*, via what sink-shape → which class `P`?" | Grows every engagement | the *technology-scoped half* of a `CapabilityPrimitive` (`technology_pattern`, `trigger_shape`, `gating_config`, `primitive_class`) — today frozen, hand-authored, 3 entries |

Today's `discovery/catalog.py::CATALOG` **fuses both layers** in one frozen `CapabilityPrimitive`
row. `EGRESS_FETCH_JAVA_OPENCONNECTION` bundles the invariant `proof_obligation`
(`_test_ssrf` / `["P3","P1"]` — Layer 1) with `technology_pattern=r"\bjava\b|servlet"` and a
`trigger_shape` (Layer 2). So the catalog *is already Layer 2* — it is just **seeded with 3
hand-authored facts, technology-INVARIANT (a bare `\bjava\b` regex, not version-scoped), with
no persistence and no growth.** The learning loop is exactly the machinery that turns those 3
frozen rows into a growing, version-scoped, persisted, transfer-capable store.

The clean interface after the split (the *only* structural change Layer 2 asks of the
catalog — Layer 1's oracle logic is untouched):

```
Layer 1  (fixed):   primitive_class            → ProofObligation      # class → P1–P6 oracle
Layer 2  (grows):  (technology_key,            → primitive_class      # a CapabilityFact
                    version_predicate,
                    sink_shape_id)
```

A hypothesis is built by *joining* the two: a Layer-2 fact names `primitive_class`; Layer 1
maps that class to its `ProofObligation`. Zero-FP is inherited at the join (§5): every fact,
however it entered Layer 2, reduces to a **built** P1–P6 oracle or it is not emittable at all
(the §8.1 boundary-as-feature rule).

### 1.2 Sharpening #1 — Layer 2 is the Capability term ONLY

The brief's fact form is "T@version exposes capability C **reachable via sink-shape S**." Read
literally, "reachable" would store reachability — and that would be a bug. **Reachability is
per-engagement** (the actual mounted route + the actual guard/config adjudication over *this*
target's source), computed fresh by `compute_reachability` / `compute_delta`. A Layer-2 fact
records only that *the technology has a sink of shape S that belongs to class P* — a **capability
property of the technology**, not a claim that S is reachable on any given target. So the correct
reading of "reachable via sink-shape S" is **"has a sink of shape S (which, when reached, yields
class P)"** — the *capability*, decoupled from whether it is reached here. Reachability (and
Intent) are recomputed every engagement; only Capability is remembered. This decoupling is what
makes a recalled fact a *prior* and not an assertion (§5).

### 1.3 Sharpening #2 — Layer 2 grows FACTS, not the RECOGNIZER

`sink_shape_id` is a stable id drawn from the **fixed vocabulary of the source-idiom recognizer**
(`JavaSourceIngestor`) — `java.url_openconnection`, `java.file_sink`, `log4j.log_sink`. The
recognizer that *produces* `S` from source is **invariant ingest machinery** (it grows only when
a new source idiom is built, exactly like Layer 1's oracles grow only when a new proof-class is
built). Layer 2 does not learn *how to recognize* a sink; it learns *that `T@version` has one*.
This matters for the "gets smarter" proof (§6): the value of remembering a fact is **not** re-
detecting what the recognizer already finds — it is (a) **ranking** a re-derived hypothesis higher
because it was *proven before*, and (b) **substituting for derivation** when this engagement's
source is coarse/partial/absent and the recognizer *cannot* find S, and (c) **transfer** to a
related technology (§2.4). The one plumbing addition Layer 2 needs from ingest is a stable
`sink_shape_id` label on each `CallSite` — a tag on already-existing detection, not new detection.

> **Refutation considered.** The alternative "one flat learned catalog, no Layer-1/Layer-2 split"
> is rejected: it re-tangles the invariant oracle with the growing fact, so catalog growth would
> risk mutating the proof-reduction (the zero-FP boundary). The split exists *precisely* to keep
> the thing that grows (facts) away from the thing that must never drift (the P1–P6 join). Ratified.

---

## 2. KB reconciliation + Layer-2 schema

### 2.1 Position: deprecate-replace (leave ONE learning system)

The brief demands no two conflicting knowledge systems. Today there are effectively two overlapping
ones, and one of them is nearly dead:

- `playbook_entries` — tiered *technique* content (seeded Tier-1 via `seed_tier1_tests`, plus
  Research-written entries). Read by `orchestrator::_log_playbook_matches`, `research`,
  `exploit::get_tier2_tests`. Carries `times_tried` / `times_succeeded` / `success_rate`.
- `technique_results` — per-run outcomes, written by `exploit::_record_finding_to_kb`
  **success-only** and **Tier-1-substring-match-only**, feeding `success_rate`.
- `technology_relations` — a **reader** (`research::get_related_technologies`) but **no
  production writer** — dormant.

**Position:**

1. **Retire the technique-success LEARNING loop.** `technique_results` + `success_rate` are the
   deprecated technique-level paradigm. They are a poor fit for the Δ-model (a "technique" is an
   *instantiation*; the durable, transferable unit is a *capability*) and are already vestigial
   (success-only writes, name-substring matching, `success_rate` used only as an advisory
   ordering of a research-derived list). **Superseded by** the Layer-2 store, which learns at the
   capability/primitive level where Δ actually operates. `exploit`'s write-back is re-pointed from
   "record technique success" to "record a capability observation" (§3). Keeping technique_results
   as a *second* learning loop would be exactly the two-conflicting-systems the brief forbids, so
   it is retired — the table may be kept read-only for the report's historical view, but nothing
   writes `success_rate` as a prior again.
2. **Demote `playbook_entries` to a static content library.** It stays — but as an *input catalog*
   (methodology text / CVE refs / steps for the Research Tier-2/3 "craft a methodology from KB"
   path), **not** a learning loop. An input is not a competing knowledge *system*, so there is no
   conflict; its `success_rate` feedback columns are frozen.
3. **Reuse `technology_relations`, and give it its first writer.** Layer-2 transfer/inheritance
   (§2.4) rides these edges; the manifest scan populates them (`solr bundles log4j-core`). This is
   the dormant table's first production write path.

Net end-state: **one** learning system (Layer 2), **one** static content library
(`playbook_entries`, no feedback), **one** shared relation edge-table (`technology_relations`,
now written). No two conflicting systems.

### 2.2 Layer-2 tables (in `clinkz_knowledge.db`, alongside the existing schema)

Two tables: a durable **fact** (the aggregate, upserted) and an append-only **observation** ledger
(the provenance). The fact's grade/confidence is *recomputed from its observations* — reusing the
exact `update_success_rates()` recompute mechanic, lifted to the capability level (§7.3 of the
parent doc).

```sql
CREATE TABLE IF NOT EXISTS capability_facts (
    id                    INTEGER PRIMARY KEY,
    technology_key        TEXT NOT NULL,   -- normalized TECH identity, never a target host
                                           -- (e.g. the carrying dependency: 'log4j-core')
    version_predicate     TEXT NOT NULL,   -- '<2.15.0' | '[2.19.0,2.19.1]' | '=2.14.1' | '*'
    primitive_class       TEXT NOT NULL,   -- Layer-1 class enum value: egress_fetch|file_read|log_interpolation|…
    sink_shape_id         TEXT NOT NULL,   -- fixed recognizer-vocabulary id: java.file_sink|log4j.log_sink|…
    input_carriers        TEXT,            -- json: ['query','body_field','path','header']
    confirmation_primitive TEXT,           -- denormalized P-id (authority is Layer-1 catalog)
    gating_config         TEXT,            -- config that subtracts it from Δ (e.g. log4j2.formatMsgNoLookups)
    evidence_grade        TEXT NOT NULL DEFAULT 'derived_unconfirmed',
                                           -- confirmed | derived_unconfirmed | transferred | gated
    confidence            REAL NOT NULL DEFAULT 0.0,   -- 0..1, decayed; PRIOR only, never emission
    first_seen_engagement TEXT,
    last_seen_engagement  TEXT,
    last_outcome          TEXT,
    created_at            TEXT DEFAULT (datetime('now')),
    updated_at            TEXT DEFAULT (datetime('now')),
    UNIQUE(technology_key, version_predicate, primitive_class, sink_shape_id)
);

CREATE TABLE IF NOT EXISTS capability_observations (
    id                    INTEGER PRIMARY KEY,
    capability_fact_id    INTEGER REFERENCES capability_facts(id),
    engagement_id         TEXT NOT NULL,
    observed_technology   TEXT,            -- EXACT fingerprint string, e.g. 'Apache Solr 8.11.0' (a tech, not a host)
    observed_version      TEXT,            -- EXACT observed point version, e.g. '2.14.1' (predicate is a range; this is the point)
    sink_shape_id         TEXT,
    primitive_class       TEXT,
    outcome               TEXT NOT NULL,   -- confirmed | failed_unreachable | failed_gated
                                           --   | blind_unconfirmed | collaborator_unavailable
    confirmation_primitive TEXT,
    reachability_grade    TEXT,            -- SoundnessGrade the edge carried this run
    evidence_ref          TEXT,            -- pointer into engagement's own ConfirmationEvidence, NOT inlined bytes
    created_at            TEXT DEFAULT (datetime('now'))
);
```

**What is deliberately NOT a column: any target identity** — no hostname, URL, IP, port, or
secret. A capability fact is about a *technology*; storing target identity would (a) break
transfer (the fact must be target-agnostic to apply to a new target) and (b) create a
cross-engagement data leak. `observed_technology` is a fingerprint *string*, not a target. This is
the schema-level exfil guardrail (§5.3).

### 2.3 Pydantic models (in `discovery/models.py`, mirroring the existing shapes)

```python
class CapabilityFact(BaseModel):
    technology_key: str
    version_predicate: str = "*"
    primitive_class: PrimitiveClass
    sink_shape_id: str
    input_carriers: list[str] = Field(default_factory=list)
    confirmation_primitive: str = ""
    gating_config: str | None = None
    evidence_grade: str = "derived_unconfirmed"   # confirmed|derived_unconfirmed|transferred|gated
    confidence: float = 0.0                        # PRIOR only — never gates emission
    provenance: list[str] = Field(default_factory=list)

class CapabilityObservation(BaseModel):
    engagement_id: str
    observed_technology: str = ""
    observed_version: str = ""
    sink_shape_id: str = ""
    primitive_class: PrimitiveClass
    outcome: str                                   # confirmed|failed_unreachable|failed_gated|blind_unconfirmed|collaborator_unavailable
    confirmation_primitive: str = ""
    reachability_grade: SoundnessGrade = SoundnessGrade.HYPOTHESIZED
    evidence_ref: str = ""                          # link, not a copy of response bytes

class CapabilityRecall(BaseModel):
    """A fact returned by the load-as-prior query, with WHY it matched."""
    fact: CapabilityFact
    match_kind: str          # 'exact_tech' | 'bundles' | 'similar' | 'successor' | 'version_family'
    match_confidence: float  # fact.confidence × relation similarity × directness
    seeds_reachability_grade: SoundnessGrade  # STATIC_* if source also found S this run, else HYPOTHESIZED
```

### 2.4 Version predicates + `technology_relations`-powered inheritance/transfer

> **Superseded 2026-08-30 (grammar only).** The predicate grammar below gained **half-open
> intervals** `[X,Y)` (plus `(X,Y)` / `(X,Y]`) and SemVer §11 prerelease precedence, because a
> closed upper bound obliges its author to guess the last release before the fix and a guess
> low by one under-matches *silently*. Everything else in this section — conservative
> widening, `*` for an unobservable version, recall-ranks-never-emits — is unchanged. See
> [`methodology/sca-catalogue-breadth.md`](./methodology/sca-catalogue-breadth.md) §1.

**Version predicates** are a tiny deterministic grammar — `<X`, `<=X`, `=X`, `[X,Y]`, `*` — with a
`version_satisfies(observed: str, predicate: str) -> bool` matcher built on the tuple-compare idiom
already in `source_ingest.py` (`_LOG4J_SAFE_VERSION: tuple[int,int,int]`). No LLM. A recall fires
only when the *observed* version satisfies the fact's predicate; a version we cannot observe
(no manifest) yields `*` at query time → the widest, lowest-confidence match (§7 budget risk).
Predicates are **conservative by construction**: a confirmed observation of version `v` widens the
fact's predicate **only** to `=v` (or the exact range the source/CVE evidence states) — never
auto-widened from a single point (staleness mitigation, §7).

**Inheritance/transfer via `technology_relations`.** The key move that makes "Solr bundles
log4j-core → inherits the JNDI capability" concrete: **a capability is keyed on the dependency that
*carries* it, not the app.** Log4Shell's fact is stored under `technology_key='log4j-core'`,
`version_predicate='<2.15.0'` — *not* under `solr`. The manifest scan that already reads
`log4j-core:2.14.1` from `pom.xml` (`_scan_log4j_manifest`) writes a
`technology_relations(tech_a='apache-solr@8.11', tech_b='log4j-core@2.14.1', relation_type='bundles',
similarity_score=1.0)` edge. Recall then expands the fingerprint over these edges:

```
recall(fingerprint, observed_versions, source_model):
    keys ← fingerprint tech keys  ∪  expand via technology_relations (bundles / successor / similar)
    for key in keys:
        for fact in capability_facts where fact.technology_key == key
                                       and version_satisfies(observed_version(key), fact.version_predicate):
            yield CapabilityRecall(fact, match_kind, match_confidence)
```

So **any** log4j-bundling app inherits the JNDI capability the first time it is confirmed on *any*
log4j-bundling app — the dependency-level flywheel. Three relation kinds, three confidence tiers:
`bundles` (manifest-derived, high precision → high transfer confidence); `successor` (version
lineage → high); `similar` (heuristic/LLM cross-tech, e.g. GeoServer's `URL.openConnection` egress →
Solr's — lower precision → **lower** transfer confidence, and its facts are seeded at a lower rank so
an over-broad `similar` edge burns bounded budget, never correctness).

---

## 3. Write-back contract (per proof-engine outcome)

The proof engine already funnels every verified finding through
`exploit::_persist_finding → _record_finding_to_kb`; and it already knows the four non-confirming
outcomes (`confirmed` / `blind_unconfirmed` / `collaborator_unavailable` from the P6 path,
plus in-band `failed`). Layer-2 write-back re-points that same chokepoint. **A hypothesis that
came from discovery carries its `primitive_id`, `sink_shape_id`, exact observed version, and
reachability grade on the `ExploitTask` → `Finding`, so the write-back has the provenance it needs
without new plumbing beyond those fields.**

For each outcome, exactly what is persisted:

| Outcome | `capability_facts` (durable) | `capability_observations` (append-only) | Rationale |
|---|---|---|---|
| **confirmed** | **UPSERT positive fact**: `evidence_grade='confirmed'`, predicate `=observed_version`, bump `confidence`, provenance += engagement id | append `confirmed` + `evidence_ref` (link to the raw ConfirmationEvidence pair) | The flywheel (§7.1 parent). The one thing safe to remember (§3.5). |
| **failed_unreachable** (probe sent, endpoint reached, sink not hit / no effect) | **nothing** | append `failed_unreachable` + `reachability_grade` | "Not reachable on *this* route" is engagement-specific; a negative fact would poison a different target where the same tech is reachable (§3.5). |
| **failed_gated** (Δ said EXPOSED, but a config/guard actually holds here) | **refine** the fact's `gating_config` (positive capability knowledge: "present, gated by X"); grade `gated` | append `failed_gated` | The capability still *exists*; it is gated. This sharpens future **Intent** adjudication — a *positive* refinement, not a "not vulnerable." |
| **blind_unconfirmed** (P6 fired, healthy collaborator, no callback → egress may be filtered) | **nothing** | append `blind_unconfirmed` | Neither confirmed nor refuted; egress filtering is a *network* property of this target, not a *capability* property of the tech. An operator research-lead only (§7.2 parent). |
| **collaborator_unavailable** (no healthy collaborator) | **nothing** | append `collaborator_unavailable` | Says nothing about the target — the *tool* was unavailable. Pure "could-not-test" provenance. |

**Provenance recorded on a confirmed fact:** engagement id · EXACT observed version (point) ·
`sink_shape_id` · `primitive_class` · `confirmation_primitive` · a **link** to the finding's
`ConfirmationEvidence` (never a copy of response bytes — §5.3). This is what makes catalog growth
auditable and lets a reviewer re-derive *why* a fact was learned.

### 3.5 The negative-fact decision (explicit, and defended)

**Decision: a FAILED hypothesis writes an append-only OBSERVATION (provenance + engagement-local
budget hint) and NEVER a durable negative CAPABILITY FACT.** Poisoning-safe over budget-saving.

Defense — the asymmetry is the whole argument:

- **Remembering YES is budget-bounded and self-correcting.** A stale/over-broad positive fact can
  only *generate a hypothesis*, which the unchanged proof engine re-gates on the live target
  (§5). Its worst case is *wasted budget*, and that waste is bounded by the version predicate and
  decayed by confidence. Nothing false is ever emitted.
- **Remembering NO is unbounded and self-concealing.** A negative fact *suppresses* a hypothesis —
  and **nothing re-gates a suppression.** A single per-engagement failure is dominated by
  *engagement-specific* causes: the route was not reachable *here*, egress was filtered *here*, a
  config was set *here*. None of those refute the *technology's* capability. A durable "not
  vulnerable" fact would let one target's local condition silently kill the hypothesis on a
  *different* target where the capability is live and reachable — a **false-negative-poisoning**
  that directly attacks the thesis (zero-FP **and** high recall) and, unlike a wasted probe,
  produces *no artifact* to notice it by.

The budget benefit of "don't re-test the dead pattern" is real but **capturable engagement-locally**
(the reachability observations of *this* run already tell the dispatcher not to re-probe the same
dead channel this engagement) — without cross-engagement poisoning. So we take the poisoning-safe
choice and get the budget benefit anyway, scoped to where it is safe. If, later, budget pressure is
measured to be severe, the safe escalation is a **time-boxed, engagement-local negative cache**,
never a durable negative fact (flagged §8).

---

## 4. Load-as-prior contract

**Where it runs:** in `DiscoveryEngine.discover`, *after* `ingest_path` (source model) and the
recon fingerprint are available, *before* `generate_hypotheses`. One new deterministic step:

```
source_model = ingest_path(source_dir)
active        = match_primitives(source_model, fingerprint)          # unchanged (Layer-1 join)
recalls       = capability_recall(fingerprint, observed_versions, source_model)   # NEW (Layer 2)
deltas        = compute_delta(source_model, active)                   # unchanged (per-engagement)
edges         = compute_reachability(source_model, deltas)           # unchanged (per-engagement)
hypotheses    = generate_hypotheses(..., seeded_by=recalls)          # recalls RANK + COMPLETE
```

**How a recall seeds the search** — two cases, both still proof-gated:

1. **Source ALSO found the sink-shape this run** (full source). The recall does **not** change the
   reachability grade (still earned from *this* target's source — `STATIC_CONFIRMED`/`HEURISTIC`).
   It **boosts `rank_score`** with a `capability_recall` term and upgrades the hypothesis
   provenance ("previously confirmed on engagement A, `T@v`"). Effect: the *same* hypothesis is
   tested **earlier** under budget — the direct answer to §4.3's false-negative-under-budget risk.
2. **Source did NOT find the sink-shape this run** (coarse / partial / absent source — the §3.5
   parent degradation). The recall **seeds a hypothesis anyway**, at a *positive capability* grade
   but a `HYPOTHESIZED` reachability grade (no static path was proven this run). Effect: recall
   **substitutes for derivation** — the vuln is still *tested* where a cold start would not even
   generate the hypothesis. Capped (§7) since these are the most speculative.

**Stated plainly:** *Layer-2 output is a **recall prior**. It changes which hypotheses are
generated and their rank/order. It NEVER emits a finding, and it never marks a target
vulnerable.* Emission is, unchanged, the P1–P6 proof on the live target. A recalled fact that no
longer holds (patched / gated / unreachable) yields a hypothesis the proof engine fails to confirm
→ a non-finding, exactly as if it had never been recalled.

---

## 5. Zero-FP invariant (non-negotiable)

**Claim:** a remembered, stale, patched, transferred, or unreachable capability can **never**
manufacture a false positive — and, because no negative facts exist, can never manufacture a
memory-induced false negative either.

### 5.1 The mechanism (there is exactly one gate that emits)

Every hypothesis — cold-derived or recall-seeded — lowers through the **identical** path:
`DiscoveryHypothesis.to_exploit_task() → ExploitTask → _test_* → the unchanged P1–P6 oracle →
_persist_finding`. **Layer 2 has no other edge into that path.** It can add a hypothesis, reorder
hypotheses, or attach a prior; it holds **no reference to `_persist_finding`** and cannot set a
`verified` flag. Therefore:

> The set of findings Clinkz **emits** is exactly the set the unchanged proof engine confirms on
> the **live target** — **identical whether Layer 2 is empty or full.** Layer 2 changes only the
> **order and completeness of what gets TESTED**, never what gets CONFIRMED.

### 5.2 Failure-mode enumeration (each resolves to non-confirmation, not false emission)

| A recalled fact is… | Where it dies | Terminal backstop |
|---|---|---|
| **Stale** (was real, now patched) | version predicate rejects at query time; if too-wide, source Intent finds the guard → Δ=SANCTIONED → dropped pre-proof; if source absent → proof fails on the patched target | P1–P6 proof |
| **Wrong-version** (`T@v1` recalled on `T@v2`) | `version_satisfies` rejects; if wide, proof fails live | P1–P6 proof |
| **Unreachable** (present, not reachable on this route) | reachability grade stays `HYPOTHESIZED` (recall does not fake reachability); probe sent, no effect | P1–P6 proof |
| **Transferred but false on the new tech** (`bundles`/`similar`) | the edge only *seeds a hypothesis*; the live target is the arbiter | P1–P6 proof |
| **Poisoned / mis-abstracted** | can only *generate* a hypothesis → costs budget, never correctness | P1–P6 proof |

This is §4.3's "prior removes FP risk" logic, extended to the capability layer: **an over-eager
capability memory can never become a wrong finding — the proof engine zeroes it.** And §3.5's
YES-only rule closes the dual gap: since Layer 2 stores no suppression, it cannot silently drop a
hypothesis that the proof engine would otherwise confirm — so a full Layer 2 can only ever *raise*
recall relative to an empty one.

### 5.3 Cannot leak / exfil via remembered facts (the honesty review of the store itself)

Layer 2 is a **fixed-vocabulary** store, structurally incapable of carrying target data or a
payload — the memory-layer analogue of P6's Clinkz-owned, no-target-data payload templates:

- **No target identity is stored** (§2.2): no host/URL/IP/secret — schema-forbidden. A fact is
  about a *technology*, and transfer *requires* it be target-agnostic, so target identity is both
  unnecessary and prohibited. This prevents a cross-engagement leak (target A's host surfacing while
  testing target B).
- **Facts are controlled-vocabulary tuples**, not free text: `primitive_class` (enum),
  `sink_shape_id` (fixed recognizer vocabulary), `version_predicate` (grammar), `gating_config`
  (config name), grade/confidence (numbers). **No raw source snippet, no response bytes, no
  payload** is ever stored — so no source-code or response leakage across engagements, and nothing
  in a fact can be interpolated into a probe.
- **The evidence link is a REF, not a copy** (§3): a fact points into engagement A's *own*
  artifacts; recalling it on engagement B never surfaces A's response bytes to B's operator or LLM.
  And `ConfirmationEvidence` is already redaction-safe upstream (secret values masked; only markers
  / field-names).
- **The recall payload handed to the hypothesis layer / LLM contains only**: `primitive_class`,
  `sink_shape_id`, `version_predicate`, `evidence_grade`, `confidence`. No engagement-A specifics —
  so even the LLM ranking checkpoint cannot be steered by remembered target data.

---

## 6. "Gets smarter" — the two-engagement proof plan

The loop is validated later (when built) by a **two-engagement** experiment with a **gradeable-from-
raw** metric defined **now**. The metric is deliberately not a self-graded summary — it is a diff of
two raw artifacts.

### 6.1 The experiment

- **Engagement A (cold).** A fresh `clinkz_knowledge.db` (empty `capability_facts`). Run against a
  fixture that carries a capability the recognizer *can* cold-derive over several heuristic steps —
  e.g. the log4j log-sink egress on a log4j-bundling Java target: ingest → manifest scan emits the
  vulnerable token → `LOG_INTERPOLATION` primitive matches → log-sink idiom found → **heuristic
  cross-function reachability enumerates MANY candidate channels at `STATIC_HEURISTIC`** → P6
  confirms which reach the logger. On confirm, §3 writes a positive fact keyed on the carrying
  dependency (`log4j-core`, `<2.15.0`).
- **Engagement B (warm).** A **second, different-codebase** log4j-bundling Java fixture (or the same
  fixture with source deliberately *partial*: manifest present, the log-sink source file withheld).
  Layer 2 is queried at ingest time → **HIT** on the `log4j-core <2.15.0` fact via the `bundles`
  edge → the log4shell hypothesis is seeded at a positive-capability prior, ranked above the cold
  `STATIC_HEURISTIC` pack. Live proof still runs and confirms.

### 6.2 The gradeable-from-raw metric (defined now)

Two raw artifacts, no self-grading:

1. **Catalog-state diff** — dump `capability_facts` before A (0 rows) and after A (≥1 row: the
   `log4j-core <2.15.0` / `log_interpolation` / `log4j.log_sink` fact, `evidence_grade='confirmed'`,
   provenance = engagement A + exact version + `evidence_ref`). The row's *existence and content*
   is the learning, visible in the DB dump.
2. **`trace.jsonl` diff (warm B vs a cold-control B)** — for the target hypothesis, compare:
   - `prior_source`: `capability_recall` (warm) vs `cold_derivation` (control);
   - `rank_score` and **dispatch ordinal**: strictly higher / earlier on warm B;
   - **the binary artifact (strongest):** run a cold-control B with the **same partial source**
     (log-sink file withheld). The **cold** control produces **zero** `LOG_INTERPOLATION`
     hypotheses (the recognizer cannot find the withheld sink); the **warm** B produces **one**
     recall-seeded hypothesis, which the live proof then confirms. **Hypothesis-present-vs-absent
     under identical partial source is the unambiguous "gets smarter" signal** — recall substituted
     for derivation.

**The metric, in one line:** *(Δrows in `capability_facts`) ∧ (warm-B surfaces the hypothesis at a
strictly higher prior / earlier dispatch than cold-B — or surfaces it at all where cold-B misses
it), both readable from the raw catalog dump + the two `trace.jsonl` files — with the LIVE P1–P6
proof still confirming on B, so recall changed the **path to** the finding, never the finding.*

### 6.3 Candidate fixtures (from the already-proven ladder; re-confirm live when built)

| Fixture pair | Transfer mode exercised | Relation edge |
|---|---|---|
| log4j capability learned on **Solr 8.11.0 / log4j-core 2.14.1**, re-encountered on a **second log4j-bundling Java fixture** (or Solr with partial source) | dependency inheritance | `bundles` (manifest-derived, high confidence) |
| `EGRESS_FETCH` learned on **GeoServer** (CVE-2021-40822), transferred to **Solr RemoteStreaming** | cross-tech similarity | `similar` (lower confidence — exercises the over-transfer-costs-budget-not-correctness path) |
| `FILE_READ` learned on **Flink** (CVE-2020-17519), re-encountered on **Solr `stream.file`** | same-class recall | `similar` / exact-shape |

All three are *already live-proven pairs* on the current ladder, so each becomes a real
two-engagement run once Layer 2 is built — no new target infrastructure.

---

## 7. Proof-budget interaction (§4.3.1)

**How a better capability prior shifts allocation.** §4.3 of the parent doc names the real risk as
**false-negative under budget exhaustion**: the proof engine is not free, and a weak prior floods it
with candidates so the real vuln never gets tested before the engagement ends. A recall prior
directly attacks this: a *confirmed-before* capability ranks into the **top-N the budget can
afford**, so the real vuln is tested earlier — and via transfer, a **never-before-seen target
inherits the prior on its first engagement**, landing its real vuln in top-N cold. This is the
mechanism by which "gets smarter" becomes "finds the real vuln within budget," not just "remembers."

**The poisoning / staleness risk** is the dual: an over-general fact (predicate too wide, `similar`
edge too loose) burns budget re-testing patched or irrelevant versions. Mitigations, in order of
load:

1. **Version predicates (primary).** A fact recalls only when the observed version satisfies its
   predicate; predicates are conservative (never auto-widened from one point). A patched target's
   version simply fails the predicate → no recall → no budget spent. This is why the manifest-scan
   idiom (exact version) is the sharpest input, and why a version-less fingerprint (`*`) is the
   worst budget case.
2. **Confidence + decay.** `evidence_grade`/`confidence` are recomputed from observations; a fact
   not re-confirmed over K engagements **decays**, lowering its rank so a tight budget skips it
   first. Decay never deletes (audit trail) and never flips to negative (poisoning-safe, §3.5).
3. **Recall-seeded no-source cap.** The most speculative recalls (source-absent, §4 case 2) are
   **capped per engagement**, ranked by confidence — a bloated catalog cannot flood the budget with
   source-unsupported hypotheses.
4. **Transfer-confidence tiers.** `bundles`/`successor` transfers rank above `similar`; a loose
   `similar` edge over-transfers into *bounded* budget, never correctness (§2.4).

The invariant throughout: **confidence/decay/predicates drive PRIORITIZATION ONLY** — a strict
semantic firewall from emission (§7.3 parent). No confidence value ever gates a finding; the
proof engine does.

---

## 8. Open questions / risks (honest)

1. **Cross-service reachability is still weak.** Layer-2 transfer via the `bundles` edge is the
   *dependency*-level analogue and is the tractable slice; true cross-service data-flow (a channel
   in service A reaching a sink in service B) remains the frontier and is a separate fork (out of
   scope here, but Layer 2 must not pretend to solve it).
2. **The negative-fact decision trades budget for poisoning-safety** (§3.5). Defended, but it is a
   *choice*: if measured budget pressure proves severe, the safe escalation is a time-boxed
   *engagement-local* negative cache, never a durable negative fact. Revisit only with measurement.
3. **Version-boundary fuzziness.** Predicates are only as good as the version we can observe. A
   fingerprint with no manifest forces `*` (widest, most budget risk). Partial-version signals
   (a jar name, a banner) need a confidence-graded parse; a wrong version parse either over-recalls
   (bounded budget) or under-recalls (missed prior) — never a false emission.
4. **`technology_relations` quality gates transfer.** A wrong `similar` edge over-transfers (bounded
   budget); a missing `bundles` edge under-transfers (missed recall). `bundles` (manifest-derived)
   is high precision; `similar` (heuristic/LLM) is where over-transfer risk lives — keep
   `similar`-transferred facts at a lower confidence tier and audit the edge writer.
5. **Catalog poisoning via the (future) offline abstraction step** (parent §3.4 / §9). Layer 2's
   structural mitigations (facts only rank, never emit; fixed vocabulary; no negative facts; version
   predicates) bound the blast radius to *budget*, not correctness — but the abstraction step's LLM
   reliability remains the parent doc's open risk, inherited here.
6. **Shared-KB write contention.** `clinkz_knowledge.db` is SQLite; concurrent engagements writing
   `capability_facts`/`capability_observations` need the same care as the existing tables (WAL /
   bounded retries). Operational, not correctness — but real.
7. **Retiring `technique_results` touches a live write path.** `exploit::_record_finding_to_kb` is
   re-pointed (§2.1); the migration must keep the report's historical view working while the
   learning role moves to Layer 2. A clean cutover, not a dual-write, to honor "no two systems."

---

## Appendix — what this doc does NOT design (scope fence)

- The P1–P6 **proof engine** and Layer 1's oracles (fixed; §1 defines only the interface).
- **Cross-service** reachability (separate fork; §8.1).
- The offline **catalog-population / CVE-abstraction** pipeline (parent §3.4) — Layer 2 here is fed
  by *confirmed hypotheses + source ingestion*, the on-engagement write-back; the offline grower is
  the parent doc's Capability Agent, out of scope.
- Any implementation, stub, or live run — this is a design pass, graded as a document first.

---

# Slice 1 build addendum — the WRITE side (persist + retire)

**Status: BUILT.** This section is the *as-built* record for slice 1 of 2. Slice 1 **writes**
capability facts + observations and **retires** the technique-success learning loop; it does **not**
read facts back. The read-as-prior half — `capability_recall`, `version_satisfies`, the
`technology_relations` edge writers, and rank-seeding in `DiscoveryEngine.discover` — is **slice 2**
(scope fence held: none of those exist in slice 1).

## S1.1 Scope split (what slice 1 does / defers)

| Built in slice 1 (WRITE) | Deferred to slice 2 (READ) |
|---|---|
| `capability_facts` + `capability_observations` tables (§2.2) | `version_satisfies()` predicate matcher (§2.4) |
| `CapabilityFact` / `CapabilityObservation` models (§2.3) | `CapabilityRecall` model + `capability_recall()` (§2.3/§4) |
| Write-back per the §3 outcome table (re-pointed chokepoint) | load-as-prior seam in `DiscoveryEngine.discover` (§4) |
| Provenance fields ExploitTask → Finding (§S1.3) | `technology_relations` `bundles`/`similar`/`successor` writers (§2.4) |
| Retire the technique-success loop (§2.1) — clean cutover | rank-seeding / transfer / decay-in-ranking (§7) |
| Confidence recompute (confirming-only; §S1.2 — the correction) | — |

A confirmed fact is persisted with a real `version_predicate` STRING (`=2.14.1`); that string is only
*parsed* at recall time — so writing it now is in-scope and reading it back (the matcher) is slice 2.

## S1.2 The confidence formula — resolving §2.2 ↔ §3.5 (a required correction)

§2.2 says confidence is "recomputed … reusing the exact `update_success_rates()` recompute mechanic."
§3.5 says a per-engagement failure must **never** lower a real technology capability's confidence.
These are **inconsistent**: `update_success_rates()` is `SUM(success)/COUNT(*)` — a succ/tried ratio
that a failure *does* lower. Reusing it for `capability_facts` would let an *engagement-local* failure
(unreachable / egress-filtered / gated **here**) drag down a capability that is real and live on a
**different** target — the exact §3.5 poisoning. **Resolution (binding): confidence is computed from
CONFIRMING observations ONLY, with recency decay.** It is NOT a succ/tried ratio.

```
confidence = corroboration × recency
  corroboration = 1 − CORR_BASE ** k        # k = COUNT(DISTINCT engagement_id) WHERE outcome='confirmed'
  recency       = RECENCY_FLOOR + (1 − RECENCY_FLOOR) × RECENCY_DECAY ** (age_days / RECENCY_HALFLIFE_DAYS)
                                             # age_days = days since MAX(created_at) WHERE outcome='confirmed'
  constants: CORR_BASE=0.5, RECENCY_FLOOR=0.3, RECENCY_DECAY=0.5, RECENCY_HALFLIFE_DAYS=90
```

- **Corroboration saturates toward 1** with distinct confirming engagements: one confirm → 0.5, two → 0.75,
  three → 0.875. A single confirmation is a solid-but-not-certain prior; independent re-confirmation on
  another target corroborates upward. `k ≥ 1` always (a fact only exists after a confirm).
- **Recency decays but never to zero** (floor 0.30): a fact not re-confirmed for a half-life (90 d)
  loses half its *recency* multiplier, lowering rank so a tight budget skips it first (§7.2) — decay
  never deletes and never flips negative.

**Why this cannot penalize a real capability for engagement-local failure (the §3.5 defense, enforced
in SQL, not by convention):** both terms read **only** rows with `outcome='confirmed'` — the
corroboration `COUNT(DISTINCT engagement_id)` and the recency `MAX(created_at)` each carry a
`WHERE outcome='confirmed'` clause. Every non-confirming outcome (`failed_unreachable` /
`blind_unconfirmed` / `collaborator_unavailable` / `failed_gated`) appends an **observation** row that
is *structurally excluded* from both aggregates. Therefore confidence is **monotone non-decreasing in
non-confirming observations**: it can only rise on a new confirmation, or decay with wall-clock time —
never fall because a target filtered egress or gated a config *here*. The recompute runs on each
confirmed UPSERT; non-confirming writes touch the ledger (and engagement-local budget hints) only, and
**never call the recompute**.

**Confidence is a PRIOR only — it never gates emission, structurally.** Slice 1 has no reader of
`capability_facts.confidence` at all (recall is slice 2), and Layer 2 holds no reference to
`_persist_finding`. The emitted finding set is identical whether the fact store is empty or full
(§5.1) — validated by diffing `report.json` against the in-repo baseline (§6.2) and by a grep proving
no emission path reads the column.

## S1.3 Provenance fields — new vs already present (§4 enumeration)

A discovery-originated hypothesis must carry enough provenance for the write-back to key a fact and
build an observation, threaded **hypothesis → `ExploitTask` → `Finding`** (and onto `PageAnalysis` for
the non-confirming ledger path). Bundled as one `DiscoveryProvenance` model (in `models/finding.py`,
plain-`str` enum values to avoid the `discovery/models.py ↔ models/finding.py` import cycle) rather than
scattering flat fields:

| Field | Status | Source |
|---|---|---|
| `primitive_class` | **new** on the bundle | `CallSite.primitive_class` (already existed on the call site) |
| `sink_shape_id` | **new field on `CallSite`** + on the bundle | recognizer vocabulary tag (§1.3) — `java.url_openconnection` / `java.file_sink` / `log4j.log_sink` |
| `observed_version` | **new** on the bundle + `SourceModel.manifest_observed_version` | manifest scan (`_scan_log4j_manifest`) point version, else `""` |
| `technology_key` | **new** on the bundle + `SourceModel.manifest_technology_key` + `DiscoveryHypothesis.technology_key` | manifest carrying-dependency (`log4j-core`), else normalized fingerprint |
| `reachability_grade` | **new** on the bundle | `ReachabilityEdge.soundness_grade` (already existed on the edge) |
| `confirmation_primitive` | **new** on the bundle | `ProofObligation.confirmation_primitives` (already existed) |
| `primitive_id` | **new** on the bundle | `CapabilityPrimitive.id` (already existed) |
| `gating_config` | **new** on the bundle | `CapabilityPrimitive.gating_config` (already existed) |
| `discovery_provenance` | **new** field on `ExploitTask` and on `Finding` | the bundle above; `None` for LLM/deterministic/black-box tasks |

So the only genuinely new *storage* surfaces are: the `DiscoveryProvenance` bundle, `CallSite.sink_shape_id`,
`SourceModel.manifest_technology_key`/`manifest_observed_version`, `DiscoveryHypothesis.technology_key`/
`observed_version`, and `discovery_provenance` on `ExploitTask`/`Finding`/`PageAnalysis`. Everything the
bundle reads from (`primitive_class`, `soundness_grade`, `confirmation_primitives`, `id`, `gating_config`)
already existed — the plumbing is *tagging + threading*, not new detection (§1.3).

## S1.4 KB reconciliation — the clean cutover (§2.1)

- **`record_technique_result` is no longer CALLED** by `exploit::_record_finding_to_kb`. The method,
  `update_success_rates`, and `get_past_results_for_technology` **remain** (the report/research
  historical view still reads `technique_results`); `success_rate` is **frozen** — no new writes as a
  prior. This is a cutover, not a dual-write: the learning role moved entirely to Layer 2.
- **`playbook_entries` stays a static content library** — `_log_playbook_matches` and
  `get_tier2_tests` still read it; its feedback columns are frozen.
- **`technology_relations` is untouched in slice 1** (its first writer is slice 2's transfer edges).
- Net: **one** learning system (Layer 2 `capability_facts`), one static content library, one dormant
  relation table awaiting slice 2. No two conflicting learning loops.

## S1.5 Write-back mechanism (per §3, as built)

The re-pointed chokepoint is `exploit::_persist_finding → _record_finding_to_kb`:

- **confirmed** — the finding carries `discovery_provenance` (stamped from its `ExploitTask` at the
  `_execute_task` seam). `_record_finding_to_kb` UPSERTs a positive fact (`evidence_grade='confirmed'`,
  `version_predicate='=<observed_version>'` or `'*'`, confidence recomputed) and appends a `confirmed`
  observation whose `evidence_ref` is a **link** (`engagement:<id>:finding:<fid>:<Pn>`) into the
  engagement's own `ConfirmationEvidence` — never a bytes copy (§5.3).
- **failed_gated** — refine the fact's `gating_config` (positive knowledge: present-but-gated), grade
  `gated`; append a `failed_gated` observation. (No live methodology surfaces a "gated" verdict yet, so
  this path is unit-exercised via the KB primitive; wiring a gate-detection signal is slice-2+.)
- **failed_unreachable / blind_unconfirmed / collaborator_unavailable** — observation-ledger only, **no
  durable fact** (§3.5). Recorded by `_test_log4shell` / `_test_ssrf` at their terminal non-confirming
  states, **gated on `page.discovery_provenance`** so a *black-box* invocation of the same methodology
  writes nothing (generality: N/A by construction off the discovery path).

A black-box finding (DVWA SQLi, …) has `discovery_provenance=None` → it writes **no** capability fact
and **no** technique result (the loop is retired) — exactly the deprecate-replace end-state.

## S1.6 Honesty / security review of the store (as built)

- **No target identity in the schema** (§5.3): `capability_facts` and `capability_observations` have
  no host/URL/IP/port/secret column. `observed_technology` is a fingerprint *string* (`Apache Solr
  8.11.0`), a tech, not a target. Verified by the DDL and a schema-shape test.
- **`evidence_ref` is a link, not bytes**: it points into the finding's own `ConfirmationEvidence`;
  recalling a fact on a later engagement never surfaces engagement-A response bytes.
- **Controlled-vocabulary only**: no raw source snippet, no response bytes, no payload string is stored
  in any fact or observation — nothing in a fact can be interpolated into a probe (the P6-template
  discipline, at the memory layer).
- **Zero-FP is structural**: Layer 2 stores no negative fact (so it cannot suppress a hypothesis) and
  holds no path to emission (so it cannot manufacture one). Confidence is a number, provably unused in
  any slice-1 emission decision.

---

# Slice 2 build addendum — the READ side (recall + transfer)

**Status: BUILT + live-validated.** Slice 2 is the load-as-prior half. As built:

- **`version_satisfies`** (`discovery/versions.py`) — the §2.4 predicate grammar, deterministic, on
  the shared `parse_version` tuple idiom `source_ingest._parse_semver` now delegates to.
- **`bundles` / `successor` edge writers** (`discovery/relations.py`) — the dormant
  `technology_relations` table's first production writers (deterministic only; `similar` deferred).
- **`capability_recall`** (`discovery/recall.py`) — a **pure READ** over KB-dumped fact + relation rows;
  expands the fingerprint over transfer edges, filters by `version_satisfies`, yields `CapabilityRecall`.
- **Load-as-prior seam** — `DiscoveryEngine.discover(capability_facts=…, technology_relations=…)` computes
  recalls before `generate_hypotheses(seeded_by=…)`, which **boosts** (case a) or **seeds** (case b, at
  `HYPOTHESIZED` reachability, capped). The async orchestrator seam dumps the store as the prior and
  writes the transfer edges back. Trace records `prior_source` + `rank_score` + dispatch ordinal (§6.2).
- **Zero-FP / scope fence held** — recall never emits; emission stays the unchanged P1–P6 proof (§5).

The §6 two-engagement experiment ran for real (Vulhub Solr 8.11.0 / log4j-core 2.14.1, live collaborator +
live Anthropic): `capability_facts`+`technology_relations` 0→1; under identical partial source the
cold-control produced 0 `log_interpolation` hypotheses while the warm run recalled via the `bundles` edge
and seeded 3 (`prior_source=capability_recall`) that the live P6 callback confirmed. As-built + RAW evidence:
[`discovery-engine-capability-recall-slice2-validation.md`](./discovery-engine-capability-recall-slice2-validation.md).

**Still deferred:** `similar` (heuristic/LLM) transfer edges, the offline catalog-population / CVE-abstraction
grower, and cross-service reachability.
