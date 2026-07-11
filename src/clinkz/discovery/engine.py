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

from pydantic import BaseModel, Field

from clinkz.discovery.catalog import match_primitives
from clinkz.discovery.hypothesis import generate_hypotheses
from clinkz.discovery.intent import compute_delta
from clinkz.discovery.models import (
    CapabilityDelta,
    CapabilityPrimitive,
    DiscoveryHypothesis,
    ReachabilityEdge,
    SourceModel,
)
from clinkz.discovery.reachability import compute_reachability
from clinkz.discovery.source_ingest import JavaSourceIngestor
from clinkz.models.finding import ExploitTask

logger = logging.getLogger(__name__)


class DiscoveryResult(BaseModel):
    """Everything the discovery pass produced, for the seam and for reporting."""

    source_model: SourceModel = Field(default_factory=SourceModel)
    active_primitives: list[CapabilityPrimitive] = Field(default_factory=list)
    deltas: list[CapabilityDelta] = Field(default_factory=list)
    edges: list[ReachabilityEdge] = Field(default_factory=list)
    hypotheses: list[DiscoveryHypothesis] = Field(default_factory=list)

    def exploit_tasks(self) -> list[ExploitTask]:
        """Lower every hypothesis to a Tier-A ``ExploitTask`` for the plan-union."""
        return [h.to_exploit_task() for h in self.hypotheses]


class DiscoveryEngine:
    """Run source-ingestion → capability → intent → reachability → hypothesis."""

    def __init__(self) -> None:
        self._ingestor = JavaSourceIngestor()

    def discover(
        self, source_dir: str, fingerprint: Iterable[str], base_url: str
    ) -> DiscoveryResult:
        """Discover falsifiable hypotheses from *source_dir* against *base_url*.

        Args:
            source_dir: path to the ingestable source tree (gray-box input).
            fingerprint: recon technology fingerprint (e.g. ``["Java", "GeoServer"]``).
            base_url: the app's context-root URL (e.g. ``http://host:8080/geoserver``)
                that discovered servlet routes are joined onto.
        """
        fingerprint = list(fingerprint)
        source_model = self._ingestor.ingest_path(source_dir)
        active_primitives = match_primitives(source_model, fingerprint)
        deltas = compute_delta(source_model, active_primitives)
        edges = compute_reachability(source_model, deltas)
        hypotheses = generate_hypotheses(source_model, active_primitives, deltas, edges, base_url)
        logger.info(
            "discovery: %d active primitives, %d Δ, %d reachability edges, %d hypotheses",
            len(active_primitives),
            len(deltas),
            len(edges),
            len(hypotheses),
        )
        return DiscoveryResult(
            source_model=source_model,
            active_primitives=active_primitives,
            deltas=deltas,
            edges=edges,
            hypotheses=hypotheses,
        )
