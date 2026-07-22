"""Keyless gate — the load-as-prior seam in DiscoveryEngine.discover (design §4/§6.2).

The "gets smarter" mechanism, proven deterministically end-to-end through the engine
(no KB, no LLM, no container — the KB dumps are passed in as row dicts):

  * **cold-control** (empty store, PARTIAL source) — the recognizer cannot find the
    withheld log sink → ZERO LOG_INTERPOLATION hypotheses.
  * **warm** (the log4j fact + bundles edge, SAME partial source) — recall reaches the
    fact via the bundles edge and SEEDS a hypothesis on the surviving ``action``
    channel at HYPOTHESIZED reachability, ``prior_source=capability_recall``, re-keyed
    on ``log4j-core`` for the write-back.
  * **case (a)** (the fact + FULL source) — the cold-derived hypothesis is BOOSTED
    (rank up, ``prior_source=capability_recall``) and keeps its earned STATIC_HEURISTIC
    grade — a boost, never a duplicate.

Emission is unchanged throughout: recall only re-orders + completes what is TESTED;
the live P6 proof (not exercised here) is the only thing that would confirm (§5).
"""

from __future__ import annotations

from typing import Any

from clinkz.discovery import DiscoveryEngine
from clinkz.discovery.models import PrimitiveClass, SoundnessGrade

FULL = "tests/fixtures/solr_log4shell"
PARTIAL = "tests/fixtures/solr_log4shell_partial"
BASE_URL = "http://localhost:8983/solr/admin/cores"


def _log4j_fact_row() -> dict[str, Any]:
    """The confirmed ``log4j-core <2.15`` fact an Engagement A would have written."""
    return {
        "id": 1,
        "technology_key": "log4j-core",
        "version_predicate": "=2.14.1",
        "primitive_class": "log_interpolation",
        "sink_shape_id": "log4j.log_sink",
        "input_carriers": '["query", "body_field", "path", "header"]',
        "confirmation_primitive": "P6",
        "gating_config": "log4j2.formatMsgNoLookups",
        "evidence_grade": "confirmed",
        "confidence": 0.5,
        "first_seen_engagement": "engagement-A",
    }


def _bundles_edge_row() -> dict[str, Any]:
    """The manifest-derived edge Engagement A would have written (Solr bundles log4j)."""
    return {
        "tech_a": "apache-solr@8.11.0",
        "tech_b": "log4j-core@2.14.1",
        "relation_type": "bundles",
        "similarity_score": 1.0,
    }


def _log_hyps(result: Any) -> list[Any]:
    return [
        h
        for h in result.hypotheses
        if h.delta.call_site.primitive_class is PrimitiveClass.LOG_INTERPOLATION
    ]


def test_cold_control_partial_source_zero_hypotheses() -> None:
    """Empty store + partial source → the recognizer finds no sink → 0 hypotheses."""
    result = DiscoveryEngine().discover(
        PARTIAL, ["Java", "Apache Solr 8.11.0"], BASE_URL, capability_facts=[]
    )
    assert result.recalls == []
    assert _log_hyps(result) == []
    assert result.hypotheses == []


def test_warm_partial_source_seeds_recall_hypothesis() -> None:
    """The fact + bundles edge, SAME partial source → a recall-seeded action hypothesis."""
    result = DiscoveryEngine().discover(
        PARTIAL,
        ["Java", "Apache Solr 8.11.0"],
        BASE_URL,
        capability_facts=[_log4j_fact_row()],
        technology_relations=[_bundles_edge_row()],
    )
    # Recall reached the fact via the bundles edge, carrying the dep version.
    assert len(result.recalls) == 1
    assert result.recalls[0].match_kind == "bundles"
    assert result.recalls[0].observed_version == "2.14.1"

    log_hyps = _log_hyps(result)
    assert log_hyps, "warm B seeded no LOG_INTERPOLATION hypothesis"
    assert all(h.prior_source == "capability_recall" for h in log_hyps)
    # recall must NOT fake reachability — source was absent this run.
    assert all(h.edge.soundness_grade is SoundnessGrade.HYPOTHESIZED for h in log_hyps)
    # the canonical CVE channel survived in the partial source and is seeded.
    action = next((h for h in log_hyps if h.edge.channel_param == "action"), None)
    assert action is not None
    # re-keyed on the carrying dependency so a confirmed finding writes the right fact.
    assert action.technology_key == "log4j-core"
    assert action.observed_version == "2.14.1"
    task = action.to_exploit_task()
    assert task.test_method == "_test_log4shell"
    assert task.prior_source == "capability_recall"
    assert task.discovery_provenance is not None
    assert task.discovery_provenance.technology_key == "log4j-core"
    assert task.discovery_provenance.sink_shape_id == "log4j.log_sink"


def test_hypothesis_present_vs_absent_is_the_signal() -> None:
    """The §6.2 binary: warm surfaces the hypothesis, cold-control under SAME source does not."""
    warm = DiscoveryEngine().discover(
        PARTIAL,
        ["Java", "Apache Solr 8.11.0"],
        BASE_URL,
        capability_facts=[_log4j_fact_row()],
        technology_relations=[_bundles_edge_row()],
    )
    cold = DiscoveryEngine().discover(PARTIAL, ["Java", "Apache Solr 8.11.0"], BASE_URL)
    assert len(_log_hyps(warm)) >= 1
    assert len(_log_hyps(cold)) == 0


def test_case_a_full_source_boosts_not_duplicates() -> None:
    """Full source + the fact → the cold hypothesis is boosted, keeps its grade, no dup."""
    cold = DiscoveryEngine().discover(FULL, ["Java", "Apache Solr 8.11.0"], BASE_URL)
    warm = DiscoveryEngine().discover(
        FULL,
        ["Java", "Apache Solr 8.11.0"],
        BASE_URL,
        capability_facts=[_log4j_fact_row()],
        technology_relations=[_bundles_edge_row()],
    )
    # No new hypotheses — a matching recall boosts, it does not duplicate.
    assert len(warm.hypotheses) == len(cold.hypotheses)
    action_cold = next(h for h in cold.hypotheses if h.edge.channel_param == "action")
    action_warm = next(h for h in warm.hypotheses if h.edge.channel_param == "action")
    assert action_cold.prior_source == "cold_derivation"
    assert action_warm.prior_source == "capability_recall"
    assert action_warm.rank_score > action_cold.rank_score  # tested earlier under budget
    # earned reachability grade is kept (recall does not change it in case a).
    assert action_warm.edge.soundness_grade is action_cold.edge.soundness_grade
