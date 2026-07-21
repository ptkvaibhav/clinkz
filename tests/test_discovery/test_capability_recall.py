"""Keyless gate — Layer-2 relation edges + capability recall (design §2.3/§2.4/§4).

The READ side, in isolation from the KB: ``derive_*_edges`` (pure edge writers) and
``capability_recall`` (pure prior) over row dicts shaped exactly like the KB dumps.
The load-bearing scenario is the §6.2 transfer: a ``log4j-core`` fact confirmed on
one engagement is reached, on a **partial-source** engagement whose own source never
re-derives the log sink, via the manifest-derived ``bundles`` edge — the "gets
smarter" mechanism. Recall NEVER emits (§5); these tests assert only that the prior
fires (or correctly does not), not any finding.
"""

from __future__ import annotations

from typing import Any

from clinkz.discovery.models import CallSite, PrimitiveClass, SoundnessGrade, SourceModel
from clinkz.discovery.recall import capability_recall
from clinkz.discovery.relations import (
    RELATION_BUNDLES,
    RELATION_SUCCESSOR,
    derive_bundles_edges,
    derive_successor_edges,
    normalize_tech_identity,
)


def _fact_row(**overrides: Any) -> dict[str, Any]:
    """A ``capability_facts`` row dict (KB-dump shape), defaulted to the log4j fact."""
    row: dict[str, Any] = {
        "id": 1,
        "technology_key": "log4j-core",
        "version_predicate": "=2.14.1",
        "primitive_class": "log_interpolation",
        "sink_shape_id": "log4j.log_sink",
        "input_carriers": '["query", "body_field"]',
        "confirmation_primitive": "P6",
        "gating_config": "log4j2.formatMsgNoLookups",
        "evidence_grade": "confirmed",
        "confidence": 0.5,
        "first_seen_engagement": "engagement-A",
    }
    row.update(overrides)
    return row


def _bundles_row(tech_a: str, tech_b: str, sim: float = 1.0) -> dict[str, Any]:
    return {
        "tech_a": tech_a,
        "tech_b": tech_b,
        "relation_type": RELATION_BUNDLES,
        "similarity_score": sim,
    }


# --- Edge derivation (deterministic writers, §2.4) -----------------------------


def test_bundles_edge_only_for_versioned_specific_apps() -> None:
    """A ``bundles`` edge is emitted for a versioned product, never the bare language."""
    edges = derive_bundles_edges("log4j-core", "2.14.1", ["Java", "Apache Solr 8.11.0"])
    assert len(edges) == 1
    edge = edges[0]
    assert edge.tech_a == "apache-solr@8.11.0"  # specific product bundles the dep
    assert edge.tech_b == "log4j-core@2.14.1"
    assert edge.relation_type == RELATION_BUNDLES
    assert edge.similarity == 1.0
    # 'Java' (no version) never becomes a bundling app — that would be poisoning-broad.
    assert all("java@" not in e.tech_a and e.tech_a != "java" for e in edges)


def test_bundles_edge_none_without_manifest() -> None:
    assert derive_bundles_edges("", "", ["Apache Solr 8.11.0"]) == []


def test_bundles_edge_does_not_relate_dependency_to_itself() -> None:
    edges = derive_bundles_edges("log4j-core", "2.14.1", ["log4j-core 2.14.1"])
    assert edges == []


def test_successor_edges_link_consecutive_versions() -> None:
    edges = derive_successor_edges("log4j-core", ["2.14.1", "2.13.0", "2.14.1", "2.15.0"])
    pairs = [(e.tech_a, e.tech_b) for e in edges]
    assert pairs == [
        ("log4j-core@2.13.0", "log4j-core@2.14.1"),
        ("log4j-core@2.14.1", "log4j-core@2.15.0"),
    ]
    assert all(e.relation_type == RELATION_SUCCESSOR for e in edges)


def test_successor_needs_two_versions() -> None:
    assert derive_successor_edges("log4j-core", ["2.14.1"]) == []


def test_normalize_tech_identity_shared_idiom() -> None:
    assert normalize_tech_identity("Apache Solr 8.11.0") == ("apache-solr", "8.11.0")
    assert normalize_tech_identity("log4j-core@2.14.1") == ("log4j-core", "2.14.1")
    assert normalize_tech_identity("Java") == ("java", "")


# --- Recall (the load-as-prior READ, §4) ---------------------------------------


def test_empty_store_is_cold_start() -> None:
    assert capability_recall(["Java", "Apache Solr 8.11.0"], SourceModel(), [], []) == []


def test_bundles_transfer_hit_partial_source() -> None:
    """The §6.2 core: a log4j fact is recalled via the bundles edge on partial source.

    The engagement's own source never re-derived the log sink (no call site), so this
    is case (b): the recall seeds at HYPOTHESIZED reachability, carrying the exact
    dependency version from the edge so the predicate is checkable.
    """
    facts = [_fact_row()]
    relations = [_bundles_row("apache-solr@8.11.0", "log4j-core@2.14.1")]
    recalls = capability_recall(["Java", "Apache Solr 8.11.0"], SourceModel(), facts, relations)
    assert len(recalls) == 1
    recall = recalls[0]
    assert recall.match_kind == RELATION_BUNDLES
    assert recall.matched_key == "log4j-core"
    assert recall.observed_version == "2.14.1"
    assert recall.fact.primitive_class is PrimitiveClass.LOG_INTERPOLATION
    assert recall.fact.sink_shape_id == "log4j.log_sink"
    assert recall.match_confidence == 0.5  # 0.5 (fact conf) × 1.0 (bundles sim)
    # source did NOT find the shape this run → recall must not fake reachability
    assert recall.seeds_reachability_grade is SoundnessGrade.HYPOTHESIZED


def test_version_predicate_rejects_patched_target() -> None:
    """A fact whose predicate the observed dependency version fails does NOT recall."""
    facts = [_fact_row(version_predicate="=2.13.0")]  # observed dep is 2.14.1
    relations = [_bundles_row("apache-solr@8.11.0", "log4j-core@2.14.1")]
    assert capability_recall(["Apache Solr 8.11.0"], SourceModel(), facts, relations) == []


def test_source_found_shape_seeds_static_heuristic() -> None:
    """Case (a): when THIS run's source also found the sink shape, keep STATIC_*."""
    source = SourceModel(
        call_sites=[
            CallSite(
                primitive_class=PrimitiveClass.LOG_INTERPOLATION,
                symbol="log_interpolation",
                sink_shape_id="log4j.log_sink",
                tainted_by="*request*",
            )
        ]
    )
    facts = [_fact_row()]
    relations = [_bundles_row("apache-solr@8.11.0", "log4j-core@2.14.1")]
    recalls = capability_recall(["Apache Solr 8.11.0"], source, facts, relations)
    assert len(recalls) == 1
    assert recalls[0].seeds_reachability_grade is SoundnessGrade.STATIC_HEURISTIC


def test_exact_tech_match_no_edge_needed() -> None:
    """A fingerprint key that equals the fact key matches directly (exact_tech)."""
    facts = [_fact_row()]
    recalls = capability_recall(["log4j-core 2.14.1"], SourceModel(), facts, [])
    assert len(recalls) == 1
    assert recalls[0].match_kind == "exact_tech"
    assert recalls[0].observed_version == "2.14.1"


def test_unobserved_version_is_widest_but_penalised() -> None:
    """A version we cannot observe still recalls (widest) but at reduced confidence."""
    # fingerprint carries the dep by NAME with no version, no edge, predicate is exact.
    facts = [_fact_row(version_predicate="=2.14.1")]
    recalls = capability_recall(["log4j-core"], SourceModel(), facts, [])
    assert len(recalls) == 1
    assert recalls[0].observed_version == ""
    assert recalls[0].match_confidence == 0.25  # 0.5 × 1.0 × 0.5 (unobserved penalty)


def test_no_matching_technology_no_recall() -> None:
    """A fact for an unrelated tech (no fingerprint key, no edge) does not recall."""
    facts = [_fact_row(technology_key="some-other-lib")]
    relations = [_bundles_row("apache-solr@8.11.0", "log4j-core@2.14.1")]
    assert capability_recall(["Apache Solr 8.11.0"], SourceModel(), facts, relations) == []
