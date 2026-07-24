"""Cross-service topology discovery (design §1/§2, slice B1) — the reach itself.

Covers the deterministic half of the slice:

* ``compose_soundness`` grades a chain by its WEAKEST hop (min-over-composition),
  so a ``STATIC_CONFIRMED`` A-side egress can never lift an A→B chain above
  ``CROSS_SERVICE_TOPOLOGY`` — regardless of hop order (§1).
* topology discovery produces ``CROSS_SERVICE_TOPOLOGY`` edges from RECON adjacency
  (0.25) and the SOURCE upgrade (0.35 when A statically references B), bounded, and
  never for a target A cannot egress to (§2 a+b).
* the engine appends cross-service hypotheses that rank BELOW every single-service
  one and change NONE of their grades or ranks (the regression invariant).
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from clinkz.discovery.engine import DiscoveryEngine
from clinkz.discovery.models import (
    ReachabilityEdge,
    SoundnessGrade,
    compose_soundness,
)
from clinkz.discovery.topology import (
    TopologyContext,
    discover_cross_service_edges,
    scan_static_egress_hosts,
    topology_reach_confidence,
)

_GEOSERVER_FIXTURE = Path(__file__).parent.parent / "fixtures" / "geoserver_TestWfsPost.java"


def _geoserver_src_dir() -> str:
    """A temp dir containing only the GeoServer SSRF fixture (an A-side egress)."""
    d = tempfile.mkdtemp()
    shutil.copy(_GEOSERVER_FIXTURE, d)
    return d


def _egress_edge(grade: SoundnessGrade = SoundnessGrade.STATIC_CONFIRMED) -> ReachabilityEdge:
    return ReachabilityEdge(
        channel_param="url",
        primitive_id="egress_fetch.java_openconnection",
        entrypoint_route="/TestWfsPost",
        entrypoint_methods=["POST"],
        soundness_grade=grade,
        reach_confidence=0.9,
    )


# ---------------------------------------------------------------------------
# compose_soundness — min over hops, impossible to grade by the strongest hop
# ---------------------------------------------------------------------------


def test_compose_soundness_is_the_weakest_hop_regardless_of_order() -> None:
    xsvc = SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    confirmed = SoundnessGrade.STATIC_CONFIRMED
    # A rock-solid A-side egress composed with the boundary hop is STILL the boundary
    # grade — the weakest hop dominates, both orders.
    assert compose_soundness([confirmed, xsvc]) is xsvc
    assert compose_soundness([xsvc, confirmed]) is xsvc
    assert compose_soundness([confirmed, SoundnessGrade.STATIC_HEURISTIC, xsvc]) is xsvc
    # A pure single-service chain keeps its own grade.
    assert compose_soundness([confirmed]) is confirmed
    assert compose_soundness([confirmed, SoundnessGrade.STATIC_HEURISTIC]) is (
        SoundnessGrade.STATIC_HEURISTIC
    )


def test_compose_soundness_rejects_empty() -> None:
    import pytest

    with pytest.raises(ValueError, match="at least one hop"):
        compose_soundness([])


def test_cross_service_is_the_weakest_grade() -> None:
    # CROSS_SERVICE_TOPOLOGY is strictly below HYPOTHESIZED (the whole design premise).
    assert (
        compose_soundness([SoundnessGrade.HYPOTHESIZED, SoundnessGrade.CROSS_SERVICE_TOPOLOGY])
        is SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    )


# ---------------------------------------------------------------------------
# discover_cross_service_edges — recon / source / bounds / gates
# ---------------------------------------------------------------------------


def test_recon_adjacency_edge_is_cross_service_topology_at_0_25() -> None:
    ctx = TopologyContext(origin_host="host-a:8080", internal_services=["http://internal-b:80/x"])
    edges = discover_cross_service_edges([_egress_edge()], ctx, static_egress_hosts=set())
    assert len(edges) == 1
    e = edges[0]
    assert e.soundness_grade is SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    assert e.topology_source == "recon"
    assert e.reach_confidence == 0.25
    assert e.cross_service_target == "http://internal-b:80/x"
    # Reuses A's egress channel (edge₁).
    assert e.channel_param == "url"
    assert e.entrypoint_route == "/TestWfsPost"


def test_source_upgrade_when_a_statically_references_b() -> None:
    ctx = TopologyContext(origin_host="host-a:8080", internal_services=["http://internal-b:80/x"])
    edges = discover_cross_service_edges([_egress_edge()], ctx, static_egress_hosts={"internal-b"})
    assert edges[0].topology_source == "source"
    assert edges[0].reach_confidence == 0.35  # source ranks above recon
    # Still the weakest grade despite the stronger discovery source.
    assert edges[0].soundness_grade is SoundnessGrade.CROSS_SERVICE_TOPOLOGY


def test_no_egress_capability_yields_no_cross_service_edges() -> None:
    ctx = TopologyContext(origin_host="host-a:8080", internal_services=["http://internal-b:80/x"])
    # A has no egress channel → cannot reach B → nothing (the honest gate).
    assert discover_cross_service_edges([], ctx, set()) == []


def test_no_topology_context_is_a_noop() -> None:
    assert discover_cross_service_edges([_egress_edge()], None, {"internal-b"}) == []


def test_service_a_is_never_its_own_cross_service_target() -> None:
    ctx = TopologyContext(
        origin_host="host-a:8080",
        internal_services=["http://host-a:8080/self", "http://internal-b:80/x"],
    )
    edges = discover_cross_service_edges([_egress_edge()], ctx, set())
    targets = {e.cross_service_target for e in edges}
    assert "http://host-a:8080/self" not in targets
    assert "http://internal-b:80/x" in targets


def test_cross_service_edges_are_bounded() -> None:
    many = [f"http://internal-{i}:80/x" for i in range(50)]
    ctx = TopologyContext(origin_host="host-a:8080", internal_services=many)
    edges = discover_cross_service_edges([_egress_edge()], ctx, set())
    assert len(edges) <= 16  # _MAX_CROSS_SERVICE_EDGES


def test_topology_reach_confidence_sub_orders_source_above_recon() -> None:
    assert topology_reach_confidence("source") == 0.35
    assert topology_reach_confidence("recon") == 0.25
    assert topology_reach_confidence("unknown") == 0.25  # falls to the weaker prior


# ---------------------------------------------------------------------------
# scan_static_egress_hosts — extracts static URL-literal hosts (design §2a)
# ---------------------------------------------------------------------------


def test_scan_static_egress_hosts_extracts_url_literal_hosts() -> None:
    d = tempfile.mkdtemp()
    try:
        (Path(d) / "Config.java").write_text(
            'String base = "http://internal-metadata:8081/latest"; // fetch target\n'
            'String other = "https://audit-svc.internal:9000/log";\n',
            encoding="utf-8",
        )
        hosts = scan_static_egress_hosts(d)
    finally:
        shutil.rmtree(d)
    assert "internal-metadata" in hosts
    assert "audit-svc.internal" in hosts


def test_scan_static_egress_hosts_missing_dir_is_empty() -> None:
    assert scan_static_egress_hosts("/nonexistent/path/xyz") == set()


# ---------------------------------------------------------------------------
# Engine integration — cross-service is ADDITIVE, single-service is unchanged
# ---------------------------------------------------------------------------


def test_engine_cross_service_is_additive_and_never_perturbs_single_service() -> None:
    d = _geoserver_src_dir()
    try:
        eng = DiscoveryEngine()
        base = "http://host-a:8080/geoserver"
        cold = eng.discover(d, ["Java", "GeoServer"], base)
        ctx = TopologyContext(
            origin_host="host-a:8080",
            internal_services=["http://169-254-internal:80/latest/meta-data/"],
        )
        warm = eng.discover(d, ["Java", "GeoServer"], base, topology_context=ctx)
    finally:
        shutil.rmtree(d)

    # The single-service egress hypothesis is present in both, byte-identical.
    cold_single = [h for h in cold.hypotheses if not h.edge.cross_service_target]
    warm_single = [h for h in warm.hypotheses if not h.edge.cross_service_target]
    assert len(cold_single) == 1
    assert len(warm_single) == 1
    assert warm_single[0].edge.soundness_grade == cold_single[0].edge.soundness_grade
    assert warm_single[0].rank_score == cold_single[0].rank_score  # rank UNCHANGED

    # A cross-service hypothesis was ADDED, graded weakest, ranked below the single one.
    xsvc = [h for h in warm.hypotheses if h.edge.cross_service_target]
    assert len(xsvc) == 1
    assert xsvc[0].edge.soundness_grade is SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    assert xsvc[0].rank_score < warm_single[0].rank_score


def test_cross_service_hypothesis_lowers_to_ssrf_task_carrying_b() -> None:
    d = _geoserver_src_dir()
    try:
        ctx = TopologyContext(
            origin_host="host-a:8080",
            internal_services=["http://internal-b:80/admin"],
        )
        result = DiscoveryEngine().discover(
            d, ["Java", "GeoServer"], "http://host-a:8080/geoserver", topology_context=ctx
        )
    finally:
        shutil.rmtree(d)
    xsvc = [h for h in result.hypotheses if h.edge.cross_service_target]
    assert len(xsvc) == 1
    task = xsvc[0].to_exploit_task()
    # Reuses EGRESS_FETCH → _test_ssrf, carries B's URL + the discovery source.
    assert task.test_method == "_test_ssrf"
    assert task.cross_service_target == "http://internal-b:80/admin"
    assert task.cross_service_source == "recon"
    assert task.endpoint_url == "http://host-a:8080/geoserver/TestWfsPost"
