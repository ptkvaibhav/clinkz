"""Discovery-engine data models (first vertical slice).

These are the minimal, concrete-first shapes for the four-layer discovery model
described in ``docs/discovery-engine-design.md``:

    Vulnerability = Δ-Capability × Untrusted-Channel-Reachability × Provable-Impact

The discovery engine produces the first two factors (Δ-capability, channel
reachability) and hands each surviving ``(Δ × reaching-channel)`` pair to the
**existing** proof engine as a falsifiable hypothesis. This slice builds only
enough of each model to carry one real CVE (GeoServer TestWfsPost SSRF,
CVE-2021-40822) end-to-end; the general catalog / cross-service reachability are
explicitly out of scope (next slice).

Every model is Pydantic v2 and payload-free where the design says so: a
:class:`CapabilityPrimitive` describes a *primitive* (technology-invariant
shape), never a target-specific payload — that is what lets discovery transfer.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from clinkz.models.finding import DiscoveryProvenance, ExploitTask
from clinkz.models.scan import ParamLocation

# ---------------------------------------------------------------------------
# Taxonomy enums
# ---------------------------------------------------------------------------


class PrimitiveClass(StrEnum):
    """Capability-primitive taxonomy (§3.2).

    Three classes are exercised today — :attr:`EGRESS_FETCH` (SSRF),
    :attr:`FILE_READ` (path-traversal file read), and :attr:`LOG_INTERPOLATION`
    (the Log4Shell log-sink egress) — proving the catalog holds classes with
    distinct sink shapes, reachability grades and proof primitives. The rest are
    declared so the catalog schema is forward-compatible without a migration.
    """

    EGRESS_FETCH = "egress_fetch"
    FILE_READ = "file_read"
    # Log4Shell class: a request-derived string reaches a logging call whose
    # library (vulnerable log4j-core) interpolates ``${jndi:…}`` lookups into an
    # outbound egress. Conceptually an egress-fetch reached via a *log sink*
    # (design §P6.5.1), modelled as its own class so its distinct source idiom
    # (logging calls), heuristic cross-function reachability and out-of-band (P6)
    # proof never cross-wire with the in-band EGRESS_FETCH SSRF path.
    LOG_INTERPOLATION = "log_interpolation"
    CODE_EVAL = "code_eval"
    QUERY_ESCAPE = "query_escape"
    DESERIALIZE = "deserialize"
    PATH_TRAVERSAL = "path_traversal"
    AUTH_FORGE = "auth_forge"
    STATE_MUTATION = "state_mutation"


class DeltaGrade(StrEnum):
    """Intent-adjudication verdict for a capability present in the stack (§2.4).

    * ``SANCTIONED`` — developer meant it AND constrained it (Δ removed).
    * ``GATED`` — a config flag disables it (Δ removed while the flag holds).
    * ``EXPOSED`` — present, un-gated, no real guard ⇒ this is the Δ.
    """

    SANCTIONED = "sanctioned"
    GATED = "gated"
    EXPOSED = "exposed"


class SoundnessGrade(StrEnum):
    """Reachability-edge soundness (§4.2)."""

    STATIC_CONFIRMED = "static_confirmed"
    STATIC_HEURISTIC = "static_heuristic"
    HYPOTHESIZED = "hypothesized"


class CoverageGrade(StrEnum):
    """How much of the running system the ingested source explains (§2.2)."""

    FULL = "full"
    PARTIAL = "partial"
    ABSENT = "absent"


# ---------------------------------------------------------------------------
# SourceModel — the shared substrate (§2.2)
# ---------------------------------------------------------------------------


class Entrypoint(BaseModel):
    """An untrusted-input entrypoint surfaced from source.

    An HTTP handler that reads untrusted request input. ``route`` is the mounted
    path a black-box crawler would need to have found; ``params`` are the request
    parameters the handler reads (``request.getParameter(...)`` /
    ``params.get(NAME)`` / a typed ``getPathParameter(X.class)``). ``path_params``
    is the subset of ``params`` carried in the URL *path* itself (Flink's typed
    ``:filename`` REST path parameter) rather than the query string / form body —
    the reachability layer maps those to :attr:`ParamLocation.PATH` so the probe
    is carried as a path segment, not a ``?name=`` query.
    """

    route: str
    http_methods: list[str] = Field(default_factory=list)
    handler_symbol: str = ""
    params: list[str] = Field(default_factory=list)
    path_params: list[str] = Field(default_factory=list)
    file: str = ""
    line: int = 0


class CallSite(BaseModel):
    """A capability-bearing call site surfaced from source (§2.2 ``call_sites``).

    ``tainted_by`` names the entrypoint parameter whose value reaches this call
    site *inside the same function* (the intra-function taint of §4.4). ``guard``
    references the guard symbol invoked before the sink, if any. ``sink_shape_id``
    is a stable label from the recognizer's fixed vocabulary (design §1.3 /
    §S1.3) — ``java.url_openconnection`` / ``java.file_sink`` / ``log4j.log_sink`` —
    a *tag on already-existing detection*, not new detection, so the Layer-2
    write-back can key a capability fact on the sink shape. Empty when the idiom
    predates the tag (never gates behaviour).
    """

    primitive_class: PrimitiveClass
    symbol: str
    file: str = ""
    line: int = 0
    tainted_by: str | None = None
    guard_symbol: str | None = None
    sink_shape_id: str = ""


class Guard(BaseModel):
    """A validation/guard surfaced from source (§2.4 config/guard facts).

    The crux of the GeoServer walkthrough: a guard whose two operands are *both*
    attacker-controlled is **bypassable** and must not count as a real guard, or
    Δ under-counts and the vuln is missed (open-question #7). ``gating_config``
    names the config flag whose presence turns the guard into a real one.
    """

    symbol: str
    kind: str = ""
    operands: list[str] = Field(default_factory=list)
    attacker_controlled_operands: list[str] = Field(default_factory=list)
    gating_config: str | None = None
    bypassable_by_default: bool = False
    file: str = ""
    line: int = 0


class SourceModel(BaseModel):
    """A per-engagement, queryable projection of ingested source (§2.2).

    Deliberately shallow (regex / bounded scan, no whole-program analysis). This
    slice populates entrypoints, call sites and guards — enough to surface the
    unlinked TestWfsPost demo servlet that a black-box crawl misses (§10 gap #1).
    """

    entrypoints: list[Entrypoint] = Field(default_factory=list)
    call_sites: list[CallSite] = Field(default_factory=list)
    guards: list[Guard] = Field(default_factory=list)
    coverage_grade: CoverageGrade = CoverageGrade.ABSENT
    files_ingested: int = 0
    technologies: list[str] = Field(default_factory=list)
    # Human-readable manifest-capability verdict, for the trace/report (e.g.
    # "log4j-core 2.14.1 (< 2.15) declared in pom.xml → JNDI message-lookups
    # un-gated"). Empty when no manifest-gated capability was found.
    manifest_evidence: str = ""
    # Structured manifest capability, for the Layer-2 write-back (§S1.3): the
    # carrying dependency the fact is keyed on and the EXACT observed point
    # version. Populated by the manifest recognizer (e.g. ``log4j-core`` /
    # ``2.14.1``); empty when no manifest-gated capability was found. The
    # dependency name is recognizer vocabulary, never a target literal.
    manifest_technology_key: str = ""
    manifest_observed_version: str = ""


# ---------------------------------------------------------------------------
# Capability catalog (§3.2) — the transfer key
# ---------------------------------------------------------------------------


class ProofObligation(BaseModel):
    """The payload-free confirmation recipe a hypothesis must carry (§6.2).

    ``confirmation_primitives`` cites which of P1–P6 the obligation reduces to —
    the zero-FP boundary (§6.1). ``test_method`` binds a Tier-A obligation to an
    existing ``_test_*`` methodology (§6.3). ``carrier_constraints`` are the
    per-instance probe constraints the walkthrough surfaced as the sharpest
    finding (§10 gap #3): e.g. "align the Host header with the injected url host".
    """

    test_method: str
    confirmation_primitives: list[str] = Field(default_factory=list)
    carrier_constraints: list[str] = Field(default_factory=list)
    description: str = ""


class CapabilityPrimitive(BaseModel):
    """A technology-invariant capability shape (§3.1/§3.2) — primitive, not payload.

    Stored keyed on the primitive shape, not any concrete payload, so it transfers
    to targets Clinkz has never seen. This slice seeds exactly one
    (``EGRESS_FETCH`` for a Java HTTP-fetch sink); catalog growth is out of scope.
    """

    id: str
    technology_pattern: str
    name: str
    primitive_class: PrimitiveClass
    trigger_shape: str
    input_carriers: list[str] = Field(default_factory=list)
    effect_class: str = ""
    proof_obligation: ProofObligation
    gating_config: str | None = None
    cwe_refs: list[str] = Field(default_factory=list)
    provenance: list[str] = Field(default_factory=list)
    evidence_grade: str = "bootstrapped"


# ---------------------------------------------------------------------------
# Per-engagement discovery products (§2.4 / §2.5 / §2.6)
# ---------------------------------------------------------------------------


class CapabilityDelta(BaseModel):
    """Δ = Capability − Intent for one primitive at one call site (§2.4)."""

    primitive_id: str
    call_site: CallSite
    present: bool = True
    delta_grade: DeltaGrade = DeltaGrade.EXPOSED
    delta_confidence: float = 0.0
    gated_by: str | None = None
    intent_evidence: str = ""


class ReachabilityEdge(BaseModel):
    """An untrusted channel → Δ-capability edge (§2.5/§4)."""

    channel_param: str
    channel_location: ParamLocation = ParamLocation.QUERY
    primitive_id: str
    entrypoint_route: str
    entrypoint_methods: list[str] = Field(default_factory=list)
    path_evidence: str = ""
    soundness_grade: SoundnessGrade = SoundnessGrade.HYPOTHESIZED
    reach_confidence: float = 0.0


class DiscoveryHypothesis(BaseModel):
    """A falsifiable ``(Δ-capability × reaching-channel × obligation)`` (§2.6).

    Maps 1:1 to a proof-engine job. This slice emits only Tier-A hypotheses that
    bind to an existing ``_test_*`` (zero new proof code); the resulting
    :class:`ExploitTask` rides the Exploit planner's existing plan-union (§2.7).
    """

    id: str
    primitive_id: str
    delta: CapabilityDelta
    edge: ReachabilityEdge
    obligation: ProofObligation
    target_url: str
    endpoint_method: str = "POST"
    endpoint_params: list[str] = Field(default_factory=list)
    param_locations: dict[str, ParamLocation] = Field(default_factory=dict)
    rank_score: float = 0.0
    rationale: str = ""
    # Where this hypothesis came from — the raw §6.2 "gets smarter" metric field.
    # ``cold_derivation`` when the source ingestor derived it this run;
    # ``capability_recall`` when a Layer-2 recall boosted (case a) or SEEDED (case b)
    # it (design §4). A recall never emits — it only changes WHICH hypotheses are
    # tested and their order (§5) — so this labels the PATH to a finding, never the
    # finding.
    prior_source: str = "cold_derivation"
    # Capability-learning provenance (§S1.3), populated by ``generate_hypotheses``
    # from the manifest/fingerprint. ``technology_key`` is the carrying dependency
    # the Layer-2 fact keys on (``log4j-core``) or a normalized fingerprint;
    # ``observed_version`` is the EXACT point version (``2.14.1``) or ``""`` (→ ``*``).
    technology_key: str = ""
    observed_version: str = ""
    gating_config: str | None = None

    def _discovery_provenance(self) -> DiscoveryProvenance:
        """Bundle the capability-learning provenance carried on the lowered task.

        Reads the sink shape, primitive class, reachability grade and confirmation
        primitive off the already-existing sub-objects (§S1.3): only the version
        identity is new. Enables the Layer-2 write-back to key a fact + build an
        observation without further plumbing.
        """
        return DiscoveryProvenance(
            technology_key=self.technology_key,
            observed_version=self.observed_version,
            sink_shape_id=self.delta.call_site.sink_shape_id,
            primitive_class=self.delta.call_site.primitive_class.value,
            primitive_id=self.primitive_id,
            confirmation_primitive="/".join(self.obligation.confirmation_primitives),
            reachability_grade=self.edge.soundness_grade.value,
            gating_config=self.gating_config,
        )

    def to_exploit_task(self) -> ExploitTask:
        """Lower this hypothesis to a Tier-A ``ExploitTask`` for the proof engine.

        The task binds the obligation's ``test_method`` to the reaching channel
        and carries the per-instance ``carrier_constraints`` so the probe honours
        them (§10 gap #3), plus the capability-learning ``discovery_provenance``
        so a confirmed finding writes a capability fact (§S1.5). It enters the
        Exploit planner unioned exactly like the LLM and deterministic plans — no
        dispatch changes.
        """
        return ExploitTask(
            test_method=self.obligation.test_method,
            endpoint_url=self.target_url,
            endpoint_params=list(self.endpoint_params),
            endpoint_method=self.endpoint_method,
            endpoint_content_type=(
                "application/x-www-form-urlencoded"
                if any(loc == ParamLocation.FORM_BODY for loc in self.param_locations.values())
                else None
            ),
            param_locations=dict(self.param_locations),
            carrier_constraints=list(self.obligation.carrier_constraints),
            tier=1,
            technique_name=f"discovery:{self.primitive_id}",
            priority=0,
            discovery_provenance=self._discovery_provenance(),
            prior_source=self.prior_source,
            rank_score=self.rank_score,
        )


# ---------------------------------------------------------------------------
# Layer-2 capability memory (the learning loop, §2.3) — slice 1 WRITE side
# ---------------------------------------------------------------------------


class CapabilityFact(BaseModel):
    """A durable, per-technology capability memory (design §2.3 / §S1.1).

    The transfer-capable unit the learning loop grows: ``T@version`` has a sink of
    shape ``sink_shape_id`` belonging to Layer-1 ``primitive_class`` — a *capability
    property of the technology*, decoupled from whether it was reachable on any one
    target (§1.2). Keyed on the carrying dependency, never a target host (§5.3).
    ``confidence`` is a corroboration-with-recency-decay PRIOR (§S1.2), **never** an
    emission gate. ``provenance`` is a convenience view assembled at read time from
    the observation ledger (the fact table stores only the engagement span); it is
    empty on write.

    ``CapabilityRecall`` (the load-as-prior return shape, §2.3) is deferred to
    slice 2 — slice 1 only WRITES facts, it does not read them back.
    """

    technology_key: str
    version_predicate: str = "*"
    primitive_class: PrimitiveClass
    sink_shape_id: str
    input_carriers: list[str] = Field(default_factory=list)
    confirmation_primitive: str = ""
    gating_config: str | None = None
    evidence_grade: str = "derived_unconfirmed"  # confirmed|derived_unconfirmed|transferred|gated
    confidence: float = 0.0  # PRIOR only — never gates emission
    provenance: list[str] = Field(default_factory=list)


class CapabilityObservation(BaseModel):
    """One append-only provenance row for a proof-engine outcome (design §2.3 / §3).

    Every outcome — confirming or not — leaves an observation. ``evidence_ref`` is a
    LINK into the engagement's own :class:`~clinkz.models.methodology.ConfirmationEvidence`
    (never a copy of response bytes — §5.3). A non-confirming outcome carries no
    durable fact (§3.5), so it is written with ``capability_fact_id=None``.
    """

    engagement_id: str
    observed_technology: str = ""
    observed_version: str = ""
    sink_shape_id: str = ""
    primitive_class: PrimitiveClass
    outcome: (
        str  # confirmed|failed_unreachable|failed_gated|blind_unconfirmed|collaborator_unavailable
    )
    confirmation_primitive: str = ""
    reachability_grade: SoundnessGrade = SoundnessGrade.HYPOTHESIZED
    evidence_ref: str = ""  # link, not a copy of response bytes


class CapabilityRecall(BaseModel):
    """A fact returned by the load-as-prior query, with WHY it matched (design §2.3).

    Slice 2 — the READ side. The output of :func:`~clinkz.discovery.recall.capability_recall`:
    a durable :class:`CapabilityFact` whose technology_key was reached from the recon
    fingerprint (directly, or expanded via a ``technology_relations`` edge) AND whose
    ``version_predicate`` the *observed* version satisfies. A recall is a **prior** —
    it re-orders and completes which hypotheses are TESTED; it never emits a finding
    and never marks a target vulnerable (§5). It carries no engagement-A response
    bytes / target identity — only the fixed-vocabulary fact, the match reason, and
    the observed point version (§5.3).

    Attributes:
        fact: The recalled capability fact (fixed-vocabulary — tech, version
            predicate, primitive_class, sink_shape_id, grade, confidence).
        match_kind: WHY it matched — ``'exact_tech'`` (fingerprint key == fact key),
            ``'bundles'`` (reached via a manifest-derived carrying-dependency edge),
            or ``'successor'`` (reached via a version-lineage edge). ``'similar'`` is
            deferred to a later slice (heuristic/LLM edges).
        match_confidence: ``fact.confidence × relation similarity`` — the ranking
            weight, never an emission gate (§7).
        seeds_reachability_grade: ``STATIC_HEURISTIC`` when THIS run's source also
            found the sink shape (case a — the earned grade is kept from the cold
            edge; this is only advisory), else ``HYPOTHESIZED`` (case b — recall
            substitutes for derivation and must NOT fake reachability, §4).
        observed_version: The EXACT observed point version that satisfied the
            predicate (from the fingerprint / the carrying-dependency edge) — carried
            so a seeded hypothesis re-keys the write-back on the right point version.
        matched_key: The technology key the fact was reached under (the fingerprint
            key for ``exact_tech``; the carrying-dependency key for ``bundles`` /
            ``successor``) — for the trace/rationale.
    """

    fact: CapabilityFact
    match_kind: str
    match_confidence: float = 0.0
    seeds_reachability_grade: SoundnessGrade = SoundnessGrade.HYPOTHESIZED
    observed_version: str = ""
    matched_key: str = ""
