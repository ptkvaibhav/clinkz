"""Clinkz discovery engine (first vertical slice).

A **producer feeding the existing Exploit dispatch** (``docs/discovery-engine-
design.md``): it computes Δ-capability and untrusted-channel reachability from
ingested source, then hands each surviving ``(Δ × reaching-channel)`` pair to the
**existing** proof engine as a falsifiable hypothesis. The proof engine remains
the universal, zero-FP gate — novel findings inherit zero-FP by construction.

This package is intentionally a thin, concrete-first vertical proving the flow on
one real CVE (GeoServer TestWfsPost SSRF, CVE-2021-40822); the general catalog,
cross-service reachability, and Orchestrator-wired agents are out of scope.
"""

from __future__ import annotations

from clinkz.discovery.catalog import CATALOG, match_primitives, primitive_by_class
from clinkz.discovery.constants import CARRIER_ALIGN_HOST
from clinkz.discovery.engine import DiscoveryEngine, DiscoveryResult
from clinkz.discovery.hypothesis import generate_hypotheses
from clinkz.discovery.intent import compute_delta
from clinkz.discovery.models import (
    CallSite,
    CapabilityDelta,
    CapabilityFact,
    CapabilityObservation,
    CapabilityPrimitive,
    CapabilityRecall,
    CoverageGrade,
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
from clinkz.discovery.reachability import compute_reachability
from clinkz.discovery.recall import capability_recall
from clinkz.discovery.relations import (
    RelationEdge,
    derive_bundles_edges,
    derive_successor_edges,
    normalize_tech_identity,
)
from clinkz.discovery.source_ingest import JavaSourceIngestor
from clinkz.discovery.versions import (
    parse_version,
    predicate_point_version,
    version_satisfies,
)

__all__ = [
    "CARRIER_ALIGN_HOST",
    "CATALOG",
    "CallSite",
    "CapabilityDelta",
    "CapabilityFact",
    "CapabilityObservation",
    "CapabilityPrimitive",
    "CapabilityRecall",
    "CoverageGrade",
    "DeltaGrade",
    "DiscoveryEngine",
    "DiscoveryHypothesis",
    "DiscoveryResult",
    "Entrypoint",
    "Guard",
    "JavaSourceIngestor",
    "PrimitiveClass",
    "ProofObligation",
    "ReachabilityEdge",
    "RelationEdge",
    "SoundnessGrade",
    "SourceModel",
    "capability_recall",
    "compute_delta",
    "compute_reachability",
    "derive_bundles_edges",
    "derive_successor_edges",
    "generate_hypotheses",
    "match_primitives",
    "normalize_tech_identity",
    "parse_version",
    "predicate_point_version",
    "primitive_by_class",
    "version_satisfies",
]
