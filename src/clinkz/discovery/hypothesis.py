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

import re

from clinkz.discovery.catalog import CATALOG, primitive_by_class
from clinkz.discovery.constants import (
    CARRIER_ALIGN_HOST,
    CARRIER_PATH_TRAVERSAL,
    LOG4J_VULNERABLE_TOKEN,
)
from clinkz.discovery.models import (
    CallSite,
    CapabilityDelta,
    CapabilityPrimitive,
    CapabilityRecall,
    DeltaGrade,
    DiscoveryHypothesis,
    Entrypoint,
    Guard,
    PrimitiveClass,
    ProofObligation,
    ReachabilityEdge,
    SoundnessGrade,
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

# A version substring in a recon fingerprint entry ("Apache Solr 8.11.0" → 8.11.0).
_RE_FINGERPRINT_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

# --- Capability-recall seeding (design §4 / §7) -----------------------------
# Case (a): a recall that corroborates a cold-derived hypothesis BOOSTS its rank
# (never a duplicate) and keeps the earned reachability grade — the same hypothesis
# is tested EARLIER under budget. The boost is additive and confidence-scaled.
_RECALL_RANK_BOOST = 0.5
# Case (b): a recall whose sink shape THIS run's source did not find SEEDS a
# hypothesis at HYPOTHESIZED reachability (recall must not fake reachability). These
# are the most speculative, so both the number of source-absent recalls per
# engagement and the channels each seeds are capped (§7.3).
_MAX_SOURCE_ABSENT_RECALLS = 4
_MAX_SEEDED_CHANNELS = 8
# A seeded edge's reach prior (HYPOTHESIZED — below the intra-function 0.9 and the
# heuristic 0.5) and the extra factor its rank carries, so a source-absent recall
# ranks below both a confirmed-taint and a cold heuristic hypothesis; the live proof
# still decides emission (§5).
_SEED_REACH_CONFIDENCE = 0.4
_SEED_RANK_FACTOR = 0.5
_PRIOR_COLD = "cold_derivation"
_PRIOR_RECALL = "capability_recall"


def _normalize_tech_key(tech: str) -> str:
    """Slugify a fingerprint entry to a technology key ("Apache Solr 8.11.0" → "apache-solr")."""
    without_version = _RE_FINGERPRINT_VERSION.sub("", tech)
    return re.sub(r"[^a-z0-9]+", "-", without_version.lower()).strip("-")


def _technology_identity(
    primitive: CapabilityPrimitive, source_model: SourceModel, fingerprint: list[str]
) -> tuple[str, str]:
    """The ``(technology_key, observed_version)`` a Layer-2 fact is keyed on (§S1.3).

    A manifest-derived carrying dependency (``log4j-core`` / its exact version) is
    the sharpest key when present; otherwise the most specific recon fingerprint
    entry is normalized to a ``(key, version)`` — general, no target literal. Prefers
    a versioned specific entry, then any specific key, then the primitive's own name.
    """
    if primitive.primitive_class is PrimitiveClass.LOG_INTERPOLATION and (
        source_model.manifest_technology_key
    ):
        return source_model.manifest_technology_key, source_model.manifest_observed_version
    versioned: tuple[str, str] | None = None
    generic: str | None = None
    for tech in [*fingerprint, *source_model.technologies]:
        if tech == LOG4J_VULNERABLE_TOKEN:
            continue  # synthetic capability token, not a technology identity
        key = _normalize_tech_key(tech)
        if not key:
            continue
        match = _RE_FINGERPRINT_VERSION.search(tech)
        if match and versioned is None:
            versioned = (key, match.group(1))
        elif generic is None:
            generic = key
    if versioned is not None:
        return versioned
    if generic is not None:
        return generic, ""
    return primitive.name, ""


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
    fingerprint: list[str] | None = None,
    seeded_by: list[CapabilityRecall] | None = None,
) -> list[DiscoveryHypothesis]:
    """Generate ranked Tier-A hypotheses from the Δ-set × reachability edges.

    ``fingerprint`` (the recon technology list) feeds the Layer-2 capability
    identity (§S1.3) each hypothesis carries; omitting it falls back to the source
    model's technologies, so behaviour is unchanged for callers that pass nothing.

    ``seeded_by`` (design §4) is the Layer-2 load-as-prior input. Each cold-derived
    hypothesis is labelled ``cold_derivation``; then the recalls RANK + COMPLETE the
    set without ever emitting (§5):

      * **case (a)** — a recall whose sink shape matches a cold hypothesis BOOSTS its
        rank (tested earlier under budget) and keeps the earned reachability grade —
        NOT a duplicate;
      * **case (b)** — a recall whose sink shape this run's source did not find SEEDS
        a hypothesis anyway, at ``HYPOTHESIZED`` reachability (recall does not fake
        reachability), so the vuln is tested where a cold start would not even
        generate it. The most speculative, so capped (§7.3).

    With no recalls the result is exactly the cold-derived set — unchanged behaviour.
    """
    fingerprint = list(fingerprint or [])
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
        technology_key, observed_version = _technology_identity(
            primitive, source_model, fingerprint
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
                technology_key=technology_key,
                observed_version=observed_version,
                gating_config=primitive.gating_config,
                rank_score=round(rank, 4),
                prior_source=_PRIOR_COLD,
                rationale=(
                    f"{primitive.primitive_class.value} EXPOSED ({delta.delta_grade.value}, "
                    f"conf={delta.delta_confidence}) reachable {edge.soundness_grade.value} via "
                    f"{edge.channel_param!r} on {edge.entrypoint_methods} {edge.entrypoint_route} "
                    f"→ {obligation.test_method} confirming "
                    f"{'/'.join(obligation.confirmation_primitives)}{carrier_note}"
                ),
            )
        )

    if seeded_by:
        hypotheses.extend(_apply_recalls(hypotheses, seeded_by, source_model, base_url))

    hypotheses.sort(key=lambda h: h.rank_score, reverse=True)
    return hypotheses


def _apply_recalls(
    cold_hypotheses: list[DiscoveryHypothesis],
    recalls: list[CapabilityRecall],
    source_model: SourceModel,
    base_url: str,
) -> list[DiscoveryHypothesis]:
    """Apply Layer-2 recalls to the cold set — boost (case a) or seed (case b), §4.

    Case (a) mutates the matching cold hypotheses in place (rank boost + provenance
    upgrade, NOT a duplicate). Case (b) returns freshly seeded hypotheses (the caller
    extends the list). A recall is matched to a cold hypothesis by its Layer-1
    ``(primitive_class, sink_shape_id)`` — the same key the write-back uses.
    """
    seeded: list[DiscoveryHypothesis] = []
    source_absent: list[CapabilityRecall] = []
    for recall in recalls:
        shape = (recall.fact.primitive_class, recall.fact.sink_shape_id)
        matches = [
            h
            for h in cold_hypotheses
            if (h.delta.call_site.primitive_class, h.delta.call_site.sink_shape_id) == shape
        ]
        if matches:
            for hypothesis in matches:
                _boost_from_recall(hypothesis, recall)
        else:
            source_absent.append(recall)

    # Cap the most speculative (source-absent) recalls per engagement, best-first.
    source_absent.sort(key=lambda r: r.match_confidence, reverse=True)
    for recall in source_absent[:_MAX_SOURCE_ABSENT_RECALLS]:
        seeded.extend(_seed_from_recall(recall, source_model, base_url))
    return seeded


def _boost_from_recall(hypothesis: DiscoveryHypothesis, recall: CapabilityRecall) -> None:
    """Case (a): a recall corroborates a cold hypothesis — boost rank, keep the grade.

    The reachability grade is UNCHANGED (still earned from this target's source); only
    ``rank_score`` rises (tested earlier under budget) and the provenance records the
    prior. This mutates in place so the recall is a boost, never a duplicate (§4).
    """
    hypothesis.rank_score = round(
        hypothesis.rank_score + _RECALL_RANK_BOOST * recall.match_confidence, 4
    )
    hypothesis.prior_source = _PRIOR_RECALL
    hypothesis.rationale += (
        f" | recall({recall.match_kind}): previously confirmed "
        f"{recall.fact.technology_key} {recall.fact.version_predicate} "
        f"grade={recall.fact.evidence_grade} conf={recall.fact.confidence}"
    )


def _seed_from_recall(
    recall: CapabilityRecall, source_model: SourceModel, base_url: str
) -> list[DiscoveryHypothesis]:
    """Case (b): seed hypotheses for a recalled capability the source did not re-derive.

    The recalled capability is wired to this engagement's untrusted entrypoint channels
    (bounded) at ``HYPOTHESIZED`` reachability — recall substitutes for derivation but
    must NOT fake reachability, so the live proof (P6 for a log sink) is what confirms
    which channels actually reach the sink. The seeded hypothesis carries the fact's
    ``technology_key`` / ``observed_version`` so a confirmed finding re-keys the
    write-back on the carrying dependency. With no ingested entrypoints there is no
    channel to test → nothing seeded (documented, bounded).
    """
    primitive = primitive_by_class(CATALOG, recall.fact.primitive_class)
    if primitive is None:
        return []  # no built proof obligation for this class — cannot form a job
    seeded: list[DiscoveryHypothesis] = []
    seen_params: set[str] = set()
    for entrypoint in source_model.entrypoints:
        for param in entrypoint.params:
            if param in seen_params:
                continue
            seen_params.add(param)
            seeded.append(_seed_one(recall, primitive, entrypoint, param, base_url))
            if len(seeded) >= _MAX_SEEDED_CHANNELS:
                return seeded
    return seeded


def _seed_one(
    recall: CapabilityRecall,
    primitive: CapabilityPrimitive,
    entrypoint: Entrypoint,
    param: str,
    base_url: str,
) -> DiscoveryHypothesis:
    """Build one case-(b) recall-seeded hypothesis on *param* of *entrypoint*."""
    location = _seed_channel_location(entrypoint, param)
    call_site = CallSite(
        primitive_class=recall.fact.primitive_class,
        symbol=f"recall:{recall.fact.sink_shape_id}",
        tainted_by=param,
        sink_shape_id=recall.fact.sink_shape_id,
    )
    delta = CapabilityDelta(
        primitive_id=primitive.id,
        call_site=call_site,
        present=True,
        delta_grade=DeltaGrade.EXPOSED,
        delta_confidence=recall.match_confidence,
        intent_evidence=(
            f"recalled capability ({recall.match_kind}); source-absent this run — "
            "reachability HYPOTHESIZED, live proof confirms"
        ),
    )
    edge = ReachabilityEdge(
        channel_param=param,
        channel_location=location,
        primitive_id=primitive.id,
        entrypoint_route=entrypoint.route,
        entrypoint_methods=entrypoint.http_methods,
        path_evidence=(
            f"recall-seeded: {recall.fact.technology_key} "
            f"{recall.fact.primitive_class.value} recalled ({recall.match_kind}); "
            f"untrusted param {param!r} plausibly reaches the sink — HYPOTHESIZED, "
            "the live proof is the precise confirmation"
        ),
        soundness_grade=SoundnessGrade.HYPOTHESIZED,
        reach_confidence=_SEED_REACH_CONFIDENCE,
    )
    obligation = _instance_obligation(primitive, None, edge)
    rank = round(
        recall.match_confidence
        * _EVIDENCE_WEIGHT.get(primitive.evidence_grade, 0.7)
        * _SEED_RANK_FACTOR,
        4,
    )
    carrier_note = (
        f" (carrier: {', '.join(obligation.carrier_constraints)})"
        if obligation.carrier_constraints
        else ""
    )
    return DiscoveryHypothesis(
        id=f"hyp:recall:{primitive.id}:{param}",
        primitive_id=primitive.id,
        delta=delta,
        edge=edge,
        obligation=obligation,
        target_url=_target_url(base_url, entrypoint.route),
        endpoint_method="POST" if "POST" in entrypoint.http_methods else "GET",
        endpoint_params=[param],
        param_locations={param: location},
        technology_key=recall.fact.technology_key,
        observed_version=recall.observed_version,
        gating_config=recall.fact.gating_config or primitive.gating_config,
        rank_score=rank,
        prior_source=_PRIOR_RECALL,
        rationale=(
            f"recall-seeded {recall.fact.primitive_class.value} "
            f"({recall.match_kind}, conf={recall.match_confidence}) via {param!r} on "
            f"{entrypoint.http_methods} {entrypoint.route or '/'} → "
            f"{obligation.test_method} confirming "
            f"{'/'.join(obligation.confirmation_primitives)}{carrier_note}"
        ),
    )


def _seed_channel_location(entrypoint: Entrypoint, param: str) -> ParamLocation:
    """Where a seeded channel param rides (mirrors the reachability layer's choice)."""
    if param in entrypoint.path_params:
        return ParamLocation.PATH
    if "POST" in {m.upper() for m in entrypoint.http_methods}:
        return ParamLocation.FORM_BODY
    return ParamLocation.QUERY
