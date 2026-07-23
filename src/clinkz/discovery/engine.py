"""Discovery engine — co-located four-layer vertical (§2.1, first slice).

The design describes four agents (Capability, Intent, Reachability, Hypothesis) in
the Orchestrator's concurrent block. For this **first vertical slice** we co-locate
the layers as one deterministic engine — exactly the pragmatic first build the
design's agent-decomposition note (§2.1 / open-question #11) sanctions — proving
the flow end-to-end before paying the Orchestrator message-bus routing cost. The
engine is a producer: it emits ``ExploitTask``s that the existing Exploit planner
unions into its plan (§2.7); it never confirms or emits findings itself.

Splitting the layers into Orchestrator-wired agents, growing the catalog offline,
and general (cross-function / cross-service) reachability are the next slice.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, Field

from clinkz.discovery.catalog import match_primitives
from clinkz.discovery.hypothesis import generate_hypotheses
from clinkz.discovery.ingestor import select_ingestor
from clinkz.discovery.intent import compute_delta
from clinkz.discovery.models import (
    CapabilityDelta,
    CapabilityPrimitive,
    CapabilityRecall,
    DiscoveryHypothesis,
    PrimitiveClass,
    ReachabilityEdge,
    SourceModel,
)
from clinkz.discovery.reachability import compute_reachability
from clinkz.discovery.recall import capability_recall
from clinkz.discovery.topology import (
    TopologyContext,
    discover_cross_service_edges,
    scan_static_egress_hosts,
)
from clinkz.models.finding import ExploitTask
from clinkz.observability.trace import get_active_trace_writer

logger = logging.getLogger(__name__)


class DiscoveryResult(BaseModel):
    """Everything the discovery pass produced, for the seam and for reporting."""

    source_model: SourceModel = Field(default_factory=SourceModel)
    active_primitives: list[CapabilityPrimitive] = Field(default_factory=list)
    deltas: list[CapabilityDelta] = Field(default_factory=list)
    edges: list[ReachabilityEdge] = Field(default_factory=list)
    hypotheses: list[DiscoveryHypothesis] = Field(default_factory=list)
    # Layer-2 recall priors that applied this run (design §4). For the trace / report;
    # recalls only re-order + complete the hypotheses, they never emit (§5).
    recalls: list[CapabilityRecall] = Field(default_factory=list)

    def exploit_tasks(self) -> list[ExploitTask]:
        """Lower every hypothesis to a Tier-A ``ExploitTask`` for the plan-union."""
        return [h.to_exploit_task() for h in self.hypotheses]


class DiscoveryEngine:
    """Run source-ingestion → capability → intent → reachability → hypothesis.

    The ingestor is selected per source tree by :func:`select_ingestor` (Java / JS),
    so the same engine drives Java and non-Java targets with no other change.
    """

    def discover(
        self,
        source_dir: str,
        fingerprint: Iterable[str],
        base_url: str,
        *,
        capability_facts: list[dict[str, Any]] | None = None,
        technology_relations: list[dict[str, Any]] | None = None,
        topology_context: TopologyContext | None = None,
    ) -> DiscoveryResult:
        """Discover falsifiable hypotheses from *source_dir* against *base_url*.

        Args:
            source_dir: path to the ingestable source tree (gray-box input).
            fingerprint: recon technology fingerprint (e.g. ``["Java", "GeoServer"]``).
            base_url: the app's context-root URL (e.g. ``http://host:8080/geoserver``)
                that discovered servlet routes are joined onto.
            capability_facts: Layer-2 ``capability_facts`` rows dumped from the KB (the
                load-as-prior input, §4). ``None``/empty ⇒ cold start (unchanged).
            technology_relations: Layer-2 ``technology_relations`` rows dumped from the
                KB, over which recall expands the fingerprint (bundles / successor).
            topology_context: Cross-service topology (design §1/§2, slice B1): A's
                origin + the in-scope B set. ``None`` ⇒ single-service engagement,
                no cross-service composition (unchanged behaviour).

        Recall (§4) runs after ingest + fingerprint, before ``generate_hypotheses``:
        the recalls RANK cold-derived hypotheses and COMPLETE the set with seeded ones
        where this run's source was too partial to derive the sink — but never emit
        (§5). With no facts the behaviour is exactly the cold, black-box-plus-source
        pipeline.

        Cross-service topology (design §1/§2) composes A's ``EGRESS_FETCH`` edges with
        the A→B boundary hop, appending ``CROSS_SERVICE_TOPOLOGY``-graded edges — the
        weakest grade, so they rank below every single-service hypothesis and change
        none of their grades or ranks. Additive: with no ``topology_context`` the edge
        set is exactly the single-service set.
        """
        fingerprint = list(fingerprint)
        source_model = select_ingestor(source_dir).ingest_path(source_dir)
        active_primitives = match_primitives(source_model, fingerprint)
        recalls = capability_recall(
            fingerprint, source_model, capability_facts or [], technology_relations or []
        )
        deltas = compute_delta(source_model, active_primitives)
        edges = compute_reachability(source_model, deltas)
        edges = self._append_cross_service_edges(
            edges, active_primitives, source_dir, topology_context
        )
        hypotheses = generate_hypotheses(
            source_model,
            active_primitives,
            deltas,
            edges,
            base_url,
            fingerprint,
            seeded_by=recalls,
        )
        logger.info(
            "discovery: %d active primitives, %d Δ, %d reachability edges, "
            "%d recalls, %d hypotheses",
            len(active_primitives),
            len(deltas),
            len(edges),
            len(recalls),
            len(hypotheses),
        )
        result = DiscoveryResult(
            source_model=source_model,
            active_primitives=active_primitives,
            deltas=deltas,
            edges=edges,
            hypotheses=hypotheses,
            recalls=recalls,
        )
        _emit_discovery_trace(result)
        return result

    @staticmethod
    def _append_cross_service_edges(
        edges: list[ReachabilityEdge],
        active_primitives: list[CapabilityPrimitive],
        source_dir: str,
        topology_context: TopologyContext | None,
    ) -> list[ReachabilityEdge]:
        """Append cross-service A→B edges (design §1/§2), or return *edges* unchanged.

        Composes only A's ``EGRESS_FETCH`` edges (a cross-service SSRF needs A's egress
        channel). With no ``topology_context`` this is a no-op, so the single-service
        edge set — and therefore every single-service hypothesis's grade and rank — is
        byte-identical to before this design.
        """
        if topology_context is None:
            return edges
        egress_ids = {
            p.id for p in active_primitives if p.primitive_class is PrimitiveClass.EGRESS_FETCH
        }
        egress_edges = [e for e in edges if e.primitive_id in egress_ids]
        if not egress_edges:
            return edges
        static_hosts = scan_static_egress_hosts(source_dir)
        cross = discover_cross_service_edges(egress_edges, topology_context, static_hosts)
        return [*edges, *cross]


def _emit_discovery_trace(result: DiscoveryResult) -> None:
    """Emit the §6.2 "gets smarter" metric — one trace line, gradeable from raw.

    Records, per hypothesis in rank order, ``prior_source`` (``capability_recall`` vs
    ``cold_derivation``), ``rank_score``, and the rank ordinal (the dispatch-order
    proxy, since discovery tasks are unioned + dispatched in rank order). The
    warm-vs-cold diff is then a direct read: a cold-control produces zero
    ``log_interpolation`` hypotheses, a warm run one ``capability_recall`` one. No-op
    when no engagement is tracing (the keyless tests set no active writer).
    """
    writer = get_active_trace_writer()
    if writer is None:
        return
    ranked = sorted(result.hypotheses, key=lambda h: h.rank_score, reverse=True)
    rows = [
        {
            "rank_ordinal": ordinal,
            "hypothesis_id": h.id,
            "prior_source": h.prior_source,
            "rank_score": h.rank_score,
            "primitive_class": h.delta.call_site.primitive_class.value,
            "sink_shape_id": h.delta.call_site.sink_shape_id,
            "channel_param": h.edge.channel_param,
            "reachability_grade": h.edge.soundness_grade.value,
            "technology_key": h.technology_key,
            "observed_version": h.observed_version,
        }
        for ordinal, h in enumerate(ranked)
    ]
    recall_count = sum(1 for h in ranked if h.prior_source == "capability_recall")
    writer.data_handoff(
        from_agent="discovery",
        to_agent="exploit",
        data_summary=(
            f"{len(rows)} hypotheses ({recall_count} recall-seeded/-boosted, "
            f"{len(result.recalls)} recalls)"
        ),
        message_type="discovery_hypotheses",
        extra={"discovery_hypotheses": rows, "recall_count": recall_count},
    )
