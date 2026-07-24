"""Cross-service topology LEARNING (design §6 / §6.4 / §7, slice B2).

The loop half of cross-service reachability: a CONFIRMED A→B reach writes an
abstracted ``reaches`` edge that a later engagement recalls to seed a chain its cold
source could not derive. This suite covers the deterministic, honesty-critical core:

* **The abstraction fence** (§6.4 — the primary honesty test, the A2a no-over-transfer
  equivalent): a bespoke / host / IP / URL / bare-language identity can NEVER reach the
  cross-engagement KB; only a clean role/tech-class pair produces an edge.
* **No cross-contamination** (§6 — the closed allowlist): a ``reaches`` edge cannot
  transfer a CAPABILITY fact — ``capability_recall`` never traverses it.
* **Topology recall** (§6 catalog prior): a learned ``reaches`` edge seeds a
  cross-service edge at ``CROSS_SERVICE_TOPOLOGY`` / ``catalog`` / 0.15 (< recon 0.25).
* **The two-engagement mechanic** (§8, deterministic half): with recon adjacency
  WITHHELD, a cold-control (empty KB) yields ZERO cross-service hypotheses while a warm
  run (KB has the ``reaches`` edge) seeds one — the live P6 half is the driver's job.
"""

from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Any

import pytest

from clinkz.discovery.engine import DiscoveryEngine
from clinkz.discovery.models import (
    PrimitiveClass,
    ReachabilityEdge,
    SoundnessGrade,
)
from clinkz.discovery.recall import capability_recall
from clinkz.discovery.relations import (
    RELATION_BUNDLES,
    RELATION_REACHES,
    RelationEdge,
    abstract_reaches_identity,
    derive_reaches_edge,
)
from clinkz.discovery.topology import (
    TopologyContext,
    topology_reach_confidence,
)
from clinkz.discovery.topology_recall import recall_cross_service_edges
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase

_GEOSERVER_FIXTURE = Path(__file__).parent.parent / "fixtures" / "geoserver_TestWfsPost.java"


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _geoserver_src_dir() -> str:
    d = tempfile.mkdtemp()
    shutil.copy(_GEOSERVER_FIXTURE, d)
    return d


def _egress_edge() -> ReachabilityEdge:
    return ReachabilityEdge(
        channel_param="url",
        primitive_id="egress_fetch.java_openconnection",
        entrypoint_route="/TestWfsPost",
        entrypoint_methods=["POST"],
        soundness_grade=SoundnessGrade.STATIC_CONFIRMED,
        reach_confidence=0.9,
    )


# ===========================================================================
# §6.4 — THE ABSTRACTION FENCE (the primary honesty test)
# ===========================================================================


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Accepted: specific role / tech-class identities.
        ("apache-solr", "apache-solr"),
        ("Apache Solr 8.11.0", "apache-solr"),  # version dropped — role-level keying
        ("internal-metadata-service", "internal-metadata-service"),
        ("OWASP Juice Shop", "owasp-juice-shop"),
        ("nginx 1.24", "nginx"),
        ("GeoServer", "geoserver"),
        # Refused: bare languages / runtimes (over-broad — the bundles discipline).
        ("java", None),
        ("Java", None),
        ("node-js", None),
        ("Node.js", None),
        ("python", None),
        # Refused: host / IP / URL / port shapes — a deployment-specific string.
        ("10.0.0.5", None),
        ("169.254.169.254", None),
        ("internal-db.corp.local", None),
        ("internal-db.corp.local:5432", None),
        ("http://internal/latest/", None),
        ("metadata.google.internal", None),
        ("host:8080", None),
        ("::1", None),
        # Refused: empty / bare version.
        ("", None),
        ("   ", None),
        ("8.11.0", None),
    ],
)
def test_abstract_reaches_identity_fence(raw: str, expected: str | None) -> None:
    assert abstract_reaches_identity(raw) == expected


def test_derive_reaches_edge_builds_only_a_clean_role_pair() -> None:
    edge = derive_reaches_edge("Apache Solr 8.11.0", "internal-metadata-service", 0.35)
    assert edge is not None
    assert edge.tech_a == "apache-solr"
    assert edge.tech_b == "internal-metadata-service"
    assert edge.relation_type == RELATION_REACHES
    assert edge.similarity == 0.35


@pytest.mark.parametrize(
    ("a_id", "b_id"),
    [
        ("apache-solr", "10.0.0.5"),  # B is an IP
        ("apache-solr", "internal-db.corp.local"),  # B is a dotted hostname
        ("apache-solr", "http://internal/"),  # B is a URL
        ("apache-solr", "internal-metadata:8081"),  # B carries a port
        ("apache-solr", ""),  # B unknown / un-abstractable
        ("java", "internal-metadata-service"),  # A is a bare language
        ("10.0.0.5", "internal-metadata-service"),  # A is an IP
    ],
)
def test_derive_reaches_edge_refuses_unabstractable_end(a_id: str, b_id: str) -> None:
    # If EITHER end is un-abstractable, no edge is built ⇒ the topology stays
    # engagement-local and NOTHING deployment-specific enters the KB (§6.4).
    assert derive_reaches_edge(a_id, b_id, 0.35) is None


def test_derive_reaches_edge_refuses_self_edge() -> None:
    assert derive_reaches_edge("apache-solr", "Apache Solr 8.11.0", 0.35) is None


def test_derive_reaches_edge_clamps_confidence_into_db_range() -> None:
    assert derive_reaches_edge("apache-solr", "nginx", 5.0).similarity == 1.0
    assert derive_reaches_edge("apache-solr", "nginx", -1.0).similarity == 0.0


def test_bespoke_hostname_can_never_reach_the_kb_via_the_writer() -> None:
    """VALIDATION #1 (KB-level): a bespoke internal hostname is structurally refused.

    Attempt to persist a ``reaches`` edge whose B-end is a bespoke internal hostname
    (as would happen if a bug passed B's URL/host instead of its recon role) — assert
    ZERO rows land in the cross-engagement KB, while a clean role pair persists. The
    finding itself is unaffected (proven at the exploit layer); here the guarantee is
    that deployment-specific topology is provably incapable of entering shared memory.
    """

    async def scenario() -> tuple[int, int]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            # A host-shaped B is refused by the fence → the writer is never called.
            host_edge = derive_reaches_edge("apache-solr", "internal-db.corp.local", 0.35)
            assert host_edge is None
            ip_edge = derive_reaches_edge("apache-solr", "10.0.0.5:6379", 0.35)
            assert ip_edge is None
            after_refused = len(await kb.get_technology_relations())

            # A clean role pair IS written (the transfer path still works).
            good = derive_reaches_edge("apache-solr", "internal-metadata-service", 0.35)
            assert good is not None
            await kb.add_technology_relation(
                good.tech_a, good.tech_b, good.relation_type, good.similarity, notes="confirmed"
            )
            rows = await kb.get_technology_relations()
            return after_refused, len([r for r in rows if r["relation_type"] == RELATION_REACHES])
        finally:
            await kb.close()

    refused_rows, good_rows = _run(scenario())
    assert refused_rows == 0  # nothing deployment-specific ever persisted
    assert good_rows == 1  # the abstracted role pair did


# ===========================================================================
# §6 — NO CROSS-CONTAMINATION (the two knowledge kinds never cross)
# ===========================================================================


def test_reaches_edge_cannot_transfer_a_capability_fact() -> None:
    """VALIDATION #2: capability_recall must NOT traverse a ``reaches`` edge.

    Seed a capability fact keyed on a far tech + a ``reaches`` edge from the observed
    tech to it, then run ``capability_recall``. It must return NOTHING via the
    ``reaches`` edge — its ``_reachable_keys`` allowlist is closed to
    bundles/successor only. A ``bundles`` edge with the SAME shape WOULD transfer, so
    the block is specifically the ``reaches`` type, not the fact being unreachable.
    """

    async def scenario() -> tuple[int, int]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            # A capability fact on a tech the fingerprint does NOT directly observe.
            fact_id = await kb.upsert_capability_fact(
                technology_key="secret-internal-tech",
                version_predicate="*",
                primitive_class=PrimitiveClass.EGRESS_FETCH.value,
                sink_shape_id="java.url_openconnection",
                engagement_id="e-seed",
            )
            await kb.add_capability_observation(
                engagement_id="e-seed",
                primitive_class=PrimitiveClass.EGRESS_FETCH,
                outcome="confirmed",
                capability_fact_id=fact_id,
            )
            await kb.recompute_capability_confidence(fact_id)
            facts = await kb.get_capability_facts()

            fingerprint = ["Apache Solr 8.11.0"]
            from clinkz.discovery.models import SourceModel

            src = SourceModel()

            # (a) A reaches edge apache-solr → secret-internal-tech must NOT transfer.
            reaches_rows = [
                {
                    "relation_type": RELATION_REACHES,
                    "tech_a": "apache-solr",
                    "tech_b": "secret-internal-tech",
                    "similarity_score": 0.9,
                }
            ]
            via_reaches = capability_recall(fingerprint, src, facts, reaches_rows)

            # (b) Control: the SAME shape as a bundles edge WOULD transfer.
            bundles_rows = [
                {
                    "relation_type": RELATION_BUNDLES,
                    "tech_a": "apache-solr",
                    "tech_b": "secret-internal-tech",
                    "similarity_score": 1.0,
                }
            ]
            via_bundles = capability_recall(fingerprint, src, facts, bundles_rows)
            return len(via_reaches), len(via_bundles)
        finally:
            await kb.close()

    reaches_recalls, bundles_recalls = _run(scenario())
    assert reaches_recalls == 0  # a reaches edge NEVER transfers a capability fact
    assert bundles_recalls == 1  # ...but the fact IS reachable via the allowed kind


# ===========================================================================
# §6 — TOPOLOGY RECALL (the catalog prior, a SEPARATE read)
# ===========================================================================


def _reaches_row(a: str, b: str, sim: float = 0.35) -> dict[str, Any]:
    return {"relation_type": RELATION_REACHES, "tech_a": a, "tech_b": b, "similarity_score": sim}


def test_topology_reach_confidence_catalog_is_below_recon() -> None:
    assert topology_reach_confidence("catalog") == 0.15
    assert topology_reach_confidence("catalog") < topology_reach_confidence("recon")
    assert topology_reach_confidence("recon") == 0.25
    assert topology_reach_confidence("source") == 0.35


def test_recall_seeds_catalog_edge_when_a_learned_reaches_matches() -> None:
    ctx = TopologyContext(
        origin_host="host-a:8080",
        origin_identity="apache-solr",
        internal_services=[],  # recon adjacency WITHHELD
        service_identities={"http://internal-b:80/x": "internal-metadata-service"},
    )
    edges = recall_cross_service_edges(
        [_egress_edge()],
        ctx,
        [_reaches_row("apache-solr", "internal-metadata-service")],
        exclude_targets=set(),
    )
    assert len(edges) == 1
    e = edges[0]
    assert e.topology_source == "catalog"
    assert e.reach_confidence == 0.15
    assert e.soundness_grade is SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    assert e.cross_service_target == "http://internal-b:80/x"
    assert e.cross_service_a_identity == "apache-solr"
    assert e.cross_service_b_identity == "internal-metadata-service"
    assert e.channel_param == "url"  # reuses A's egress channel


def test_recall_is_empty_with_no_learned_reaches() -> None:
    ctx = TopologyContext(
        origin_host="host-a:8080",
        origin_identity="apache-solr",
        service_identities={"http://internal-b:80/x": "internal-metadata-service"},
    )
    assert recall_cross_service_edges([_egress_edge()], ctx, [], set()) == []


def test_recall_skips_targets_already_covered_by_recon_source() -> None:
    ctx = TopologyContext(
        origin_host="host-a:8080",
        origin_identity="apache-solr",
        service_identities={"http://internal-b:80/x": "internal-metadata-service"},
    )
    edges = recall_cross_service_edges(
        [_egress_edge()],
        ctx,
        [_reaches_row("apache-solr", "internal-metadata-service")],
        exclude_targets={"http://internal-b:80/x"},
    )
    assert edges == []  # a catalog edge never duplicates a stronger recon/source edge


def test_recall_requires_the_origin_to_abstract() -> None:
    # A un-abstractable (bare language) → no learned edge can key on it.
    ctx = TopologyContext(
        origin_host="host-a:8080",
        origin_identity="java",
        service_identities={"http://internal-b:80/x": "internal-metadata-service"},
    )
    rows = [_reaches_row("java", "x")]
    assert recall_cross_service_edges([_egress_edge()], ctx, rows, set()) == []


def test_recall_requires_b_role_to_match_the_learned_edge() -> None:
    ctx = TopologyContext(
        origin_host="host-a:8080",
        origin_identity="apache-solr",
        service_identities={"http://internal-b:80/x": "internal-admin-api"},
    )
    # The learned edge reaches a metadata service, but this B is an admin API — no seed.
    edges = recall_cross_service_edges(
        [_egress_edge()],
        ctx,
        [_reaches_row("apache-solr", "internal-metadata-service")],
        exclude_targets=set(),
    )
    assert edges == []


def test_recall_never_seeds_a_only_read() -> None:
    # No egress capability (A cannot reach out) → nothing seeded, and it writes nothing.
    ctx = TopologyContext(
        origin_host="host-a:8080",
        origin_identity="apache-solr",
        service_identities={"http://internal-b:80/x": "internal-metadata-service"},
    )
    assert recall_cross_service_edges([], ctx, [_reaches_row("apache-solr", "x")], set()) == []


# ===========================================================================
# §8 — THE TWO-ENGAGEMENT MECHANIC (deterministic half): warm vs cold-control
# ===========================================================================


def _withheld_adjacency_ctx() -> TopologyContext:
    """A topology context with recon adjacency WITHHELD (no ``internal_services``) but
    B's identity known — so ONLY a learned ``reaches`` prior can re-derive the chain.
    """
    return TopologyContext(
        origin_host="host-a:8080",
        origin_identity="geoserver",
        internal_services=[],  # the recon adjacency is withheld (slice-2 discipline)
        service_identities={"http://internal-b:80/admin": "internal-metadata-service"},
    )


def test_cold_control_yields_zero_cross_service_hypotheses() -> None:
    d = _geoserver_src_dir()
    try:
        result = DiscoveryEngine().discover(
            d,
            ["Java", "GeoServer"],
            "http://host-a:8080/geoserver",
            technology_relations=[],  # EMPTY KB — cold control
            topology_context=_withheld_adjacency_ctx(),
        )
    finally:
        shutil.rmtree(d)
    xsvc = [h for h in result.hypotheses if h.edge.cross_service_target]
    assert xsvc == []  # withheld adjacency + empty KB → no cross-service chain at all


def test_warm_run_seeds_a_catalog_cross_service_hypothesis() -> None:
    d = _geoserver_src_dir()
    try:
        result = DiscoveryEngine().discover(
            d,
            ["Java", "GeoServer"],
            "http://host-a:8080/geoserver",
            technology_relations=[_reaches_row("geoserver", "internal-metadata-service")],
            topology_context=_withheld_adjacency_ctx(),
        )
    finally:
        shutil.rmtree(d)
    xsvc = [h for h in result.hypotheses if h.edge.cross_service_target]
    assert len(xsvc) == 1  # the learned reaches prior re-derived the withheld chain
    h = xsvc[0]
    assert h.edge.topology_source == "catalog"
    assert h.edge.reach_confidence == 0.15
    assert h.edge.soundness_grade is SoundnessGrade.CROSS_SERVICE_TOPOLOGY
    assert h.prior_source == "cold_derivation"  # topology recall is separate from Layer-2
    task = h.to_exploit_task()
    assert task.test_method == "_test_ssrf"
    assert task.cross_service_target == "http://internal-b:80/admin"
    assert task.cross_service_source == "catalog"
    assert task.cross_service_a_identity == "geoserver"
    assert task.cross_service_b_identity == "internal-metadata-service"


def test_warm_catalog_edge_never_outranks_a_single_service_hypothesis() -> None:
    d = _geoserver_src_dir()
    try:
        result = DiscoveryEngine().discover(
            d,
            ["Java", "GeoServer"],
            "http://host-a:8080/geoserver",
            technology_relations=[_reaches_row("geoserver", "internal-metadata-service")],
            topology_context=_withheld_adjacency_ctx(),
        )
    finally:
        shutil.rmtree(d)
    single = [h for h in result.hypotheses if not h.edge.cross_service_target]
    xsvc = [h for h in result.hypotheses if h.edge.cross_service_target]
    assert single and xsvc
    # The learned (weakest) edge ranks strictly below the single-service egress.
    assert xsvc[0].rank_score < single[0].rank_score


def test_transfer_edge_round_trips_and_recalls_over_the_kb() -> None:
    """End-to-end deterministic transfer over a REAL KB (the §8 mechanic, no live P6).

    Engagement A writes the abstracted ``reaches`` edge; engagement B (warm) dumps the
    KB and recalls it to seed the withheld chain, while a cold-control B (empty dump)
    seeds nothing. Mirrors slice-2's two-engagement "gets smarter" over the KB.
    """

    async def scenario() -> tuple[int, int]:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            # --- Engagement A: the write-back persists the abstracted reaches edge ---
            edge = derive_reaches_edge("geoserver", "internal-metadata-service", 0.25)
            assert edge is not None
            await kb.add_technology_relation(
                edge.tech_a, edge.tech_b, edge.relation_type, edge.similarity
            )
            warm_relations = await kb.get_technology_relations()
        finally:
            await kb.close()

        d = _geoserver_src_dir()
        try:
            cold = DiscoveryEngine().discover(
                d,
                ["Java", "GeoServer"],
                "http://host-a:8080/geoserver",
                technology_relations=[],
                topology_context=_withheld_adjacency_ctx(),
            )
            warm = DiscoveryEngine().discover(
                d,
                ["Java", "GeoServer"],
                "http://host-a:8080/geoserver",
                technology_relations=warm_relations,
                topology_context=_withheld_adjacency_ctx(),
            )
        finally:
            shutil.rmtree(d)
        cold_x = [h for h in cold.hypotheses if h.edge.cross_service_target]
        warm_x = [h for h in warm.hypotheses if h.edge.cross_service_target]
        return len(cold_x), len(warm_x)

    cold_count, warm_count = _run(scenario())
    assert cold_count == 0  # cold-control: withheld adjacency + empty KB → nothing
    assert warm_count == 1  # warm: the persisted reaches edge re-derived the chain


def test_reaches_relation_round_trips_through_the_kb() -> None:
    async def scenario() -> RelationEdge | None:
        kb = await PersistentKnowledgeBase.create(":memory:")
        try:
            await kb.add_technology_relation(
                "apache-solr", "internal-metadata-service", RELATION_REACHES, 0.25, notes="conf"
            )
            rows = await kb.get_technology_relations()
            reaches = [r for r in rows if r["relation_type"] == RELATION_REACHES]
            assert len(reaches) == 1
            row = reaches[0]
            return RelationEdge(
                tech_a=row["tech_a"],
                tech_b=row["tech_b"],
                relation_type=row["relation_type"],
                similarity=row["similarity_score"],
            )
        finally:
            await kb.close()

    edge = _run(scenario())
    assert edge is not None
    assert edge.tech_a == "apache-solr"
    assert edge.tech_b == "internal-metadata-service"
    assert edge.similarity == 0.25
