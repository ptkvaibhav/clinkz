"""Hypothesis layer — feeds the proof engine (§2.6, first vertical slice).

Turn each surviving ``(Δ-capability × reaching-channel)`` pair into a falsifiable
:class:`DiscoveryHypothesis` carrying a concrete proof obligation, then lower it to
an ``ExploitTask`` that rides the existing Exploit plan-union (§2.7). This slice
does **convergent** generation only (instantiate a catalogued primitive against a
discovered channel → an existing ``_test_*``); divergent/intent-gap scenario
engineering is out of scope.

The per-instance carrier constraint (§10 gap #3) is attached **here**, derived
from the concrete guard: when the guard reaching the sink is a bypassable
host-match guard, the obligation gains ``align_host_with_injected_url_host`` so the
SSRF probe rewrites the request ``Host`` header to the injected url host — without
it the guard rejects the probe and a genuinely exploitable SSRF fails to confirm.
"""

from __future__ import annotations

from clinkz.discovery.constants import CARRIER_ALIGN_HOST, CARRIER_PATH_TRAVERSAL
from clinkz.discovery.models import (
    CapabilityDelta,
    CapabilityPrimitive,
    DiscoveryHypothesis,
    Guard,
    PrimitiveClass,
    ProofObligation,
    ReachabilityEdge,
    SourceModel,
)
from clinkz.models.scan import ParamLocation

# Weight applied to a primitive's evidence grade in the rank score. Bootstrapped
# (source/CVE-derived) primitives are trusted enough to spend budget on; the score
# stays a prioritisation prior only — the live proof decides emission (§6.4).
_EVIDENCE_WEIGHT = {
    "confirmed-in-the-wild": 1.0,
    "bootstrapped-from-source": 0.9,
    "bootstrapped": 0.7,
}


def _target_url(base_url: str, route: str) -> str:
    """Join the app base URL with the entrypoint's route.

    A servlet route (GeoServer ``/TestWfsPost``) is appended to the context root.
    A **non-servlet param-bag entrypoint** (Solr's shared ``SolrRequestParsers``)
    has no source-derived route — the reachable reflecting handler is a deployment
    fact the operator supplies as ``base_url`` — so an empty route joins to the
    base unchanged (no spurious trailing slash, which Solr's path-exact handlers
    would 404 on).
    """
    base = base_url.rstrip("/")
    route = route.strip("/")
    return f"{base}/{route}" if route else base


def _delta_for(edge: ReachabilityEdge, deltas: list[CapabilityDelta]) -> CapabilityDelta | None:
    """The Δ whose call site this edge's channel taints.

    Intra-function edges bind to the Δ whose ``tainted_by`` is exactly the channel
    param. Heuristic log-sink edges (Log4Shell) are decoupled from any single proven
    param — the sink logs the whole request cross-function — so they associate to a
    representative Δ of the same primitive by primitive_id alone.
    """
    exact = next(
        (
            d
            for d in deltas
            if d.primitive_id == edge.primitive_id and d.call_site.tainted_by == edge.channel_param
        ),
        None,
    )
    if exact is not None:
        return exact
    return next(
        (
            d
            for d in deltas
            if d.primitive_id == edge.primitive_id
            and d.call_site.primitive_class is PrimitiveClass.LOG_INTERPOLATION
        ),
        None,
    )


def _instance_obligation(
    primitive: CapabilityPrimitive, guard: Guard | None, edge: ReachabilityEdge
) -> ProofObligation:
    """Copy the primitive's obligation and attach per-instance carrier constraints.

    Each carrier is discoverable only from the concrete instance (§10 gap #3):

      * the **Host-alignment** constraint when the reaching guard is a bypassable
        host-match guard (EGRESS_FETCH / GeoServer — the SSRF fetch guard compares
        two attacker values); and
      * the **path-segment-traversal** constraint when the reaching channel is a
        URL path parameter (FILE_READ / Flink — the traversal must ride the path
        segment verbatim and stay one opaque segment). The encoding is a property
        of the channel location, not the primitive, so it is added here.
    """
    constraints = list(primitive.proof_obligation.carrier_constraints)
    if guard is not None and guard.kind == "host_match" and guard.bypassable_by_default:
        if CARRIER_ALIGN_HOST not in constraints:
            constraints.append(CARRIER_ALIGN_HOST)
    if edge.channel_location == ParamLocation.PATH and CARRIER_PATH_TRAVERSAL not in constraints:
        constraints.append(CARRIER_PATH_TRAVERSAL)
    return primitive.proof_obligation.model_copy(update={"carrier_constraints": constraints})


def generate_hypotheses(
    source_model: SourceModel,
    primitives: list[CapabilityPrimitive],
    deltas: list[CapabilityDelta],
    edges: list[ReachabilityEdge],
    base_url: str,
) -> list[DiscoveryHypothesis]:
    """Generate ranked Tier-A hypotheses from the Δ-set × reachability edges."""
    primitive_by_id = {p.id: p for p in primitives}
    guard_by_symbol = {g.symbol: g for g in source_model.guards}
    hypotheses: list[DiscoveryHypothesis] = []

    for edge in edges:
        primitive = primitive_by_id.get(edge.primitive_id)
        delta = _delta_for(edge, deltas)
        if primitive is None or delta is None:
            continue
        guard = (
            guard_by_symbol.get(delta.call_site.guard_symbol)
            if delta.call_site.guard_symbol
            else None
        )
        obligation = _instance_obligation(primitive, guard, edge)
        rank = (
            delta.delta_confidence
            * edge.reach_confidence
            * _EVIDENCE_WEIGHT.get(primitive.evidence_grade, 0.7)
        )
        carrier_note = (
            f" (carrier: {', '.join(obligation.carrier_constraints)})"
            if obligation.carrier_constraints
            else ""
        )
        hypotheses.append(
            DiscoveryHypothesis(
                id=f"hyp:{primitive.id}:{edge.channel_param}",
                primitive_id=primitive.id,
                delta=delta,
                edge=edge,
                obligation=obligation,
                target_url=_target_url(base_url, edge.entrypoint_route),
                endpoint_method="POST" if "POST" in edge.entrypoint_methods else "GET",
                endpoint_params=[edge.channel_param],
                param_locations={edge.channel_param: edge.channel_location},
                rank_score=round(rank, 4),
                rationale=(
                    f"{primitive.primitive_class.value} EXPOSED ({delta.delta_grade.value}, "
                    f"conf={delta.delta_confidence}) reachable {edge.soundness_grade.value} via "
                    f"{edge.channel_param!r} on {edge.entrypoint_methods} {edge.entrypoint_route} "
                    f"→ {obligation.test_method} confirming "
                    f"{'/'.join(obligation.confirmation_primitives)}{carrier_note}"
                ),
            )
        )

    hypotheses.sort(key=lambda h: h.rank_score, reverse=True)
    return hypotheses
