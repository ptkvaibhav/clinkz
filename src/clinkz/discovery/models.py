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

from clinkz.models.finding import ExploitTask
from clinkz.models.scan import ParamLocation

# ---------------------------------------------------------------------------
# Taxonomy enums
# ---------------------------------------------------------------------------


class PrimitiveClass(StrEnum):
    """Capability-primitive taxonomy (§3.2).

    Only :attr:`EGRESS_FETCH` is exercised by this slice; the rest are declared
    so the catalog schema is forward-compatible without a migration next slice.
    """

    EGRESS_FETCH = "egress_fetch"
    FILE_READ = "file_read"
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

    For this slice: an HTTP servlet handler. ``route`` is the mounted path a
    black-box crawler would need to have found; ``params`` are the request
    parameters the handler reads (``request.getParameter(...)``).
    """

    route: str
    http_methods: list[str] = Field(default_factory=list)
    handler_symbol: str = ""
    params: list[str] = Field(default_factory=list)
    file: str = ""
    line: int = 0


class CallSite(BaseModel):
    """A capability-bearing call site surfaced from source (§2.2 ``call_sites``).

    ``tainted_by`` names the entrypoint parameter whose value reaches this call
    site *inside the same function* (the intra-function taint of §4.4). ``guard``
    references the guard symbol invoked before the sink, if any.
    """

    primitive_class: PrimitiveClass
    symbol: str
    file: str = ""
    line: int = 0
    tainted_by: str | None = None
    guard_symbol: str | None = None


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

    def to_exploit_task(self) -> ExploitTask:
        """Lower this hypothesis to a Tier-A ``ExploitTask`` for the proof engine.

        The task binds the obligation's ``test_method`` to the reaching channel
        and carries the per-instance ``carrier_constraints`` so the probe honours
        them (§10 gap #3). It enters the Exploit planner unioned exactly like the
        LLM and deterministic plans — no dispatch changes.
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
        )
