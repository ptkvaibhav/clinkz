"""Topology recall — the load-as-prior READ for learned cross-service reaches (§6, B2).

The Layer-2 read side for the ``reaches`` knowledge kind, and a **deliberately
SEPARATE read** from :func:`clinkz.discovery.recall.capability_recall`. The two are
different knowledge kinds and MUST NOT cross:

  * ``capability_recall`` transfers a *capability fact* (T@version has a sink) over
    ``bundles`` / ``successor`` edges — its ``_reachable_keys`` allowlist is closed
    and ``reaches`` is deliberately NOT in it, so a ``reaches`` edge can never
    transfer a capability fact.
  * ``recall_cross_service_edges`` (here) transfers a *service-topology fact*
    (a role/tech-class A reaches a role/tech-class B) over ``reaches`` edges only —
    it seeds a cross-service candidate CHAIN, never a capability fact.

Like ``capability_recall`` this is a **pure function**: no I/O, no reference to the
proof engine, writes nothing. A recalled ``reaches`` edge only RE-ORDERS / COMPLETES
which cross-service chains get tested — emission stays B1's unchanged co-location +
P6 gate on the live target (§7). A learned topology is the WEAKEST discovery source:
every catalog-recalled edge is graded ``CROSS_SERVICE_TOPOLOGY`` at
``reach_confidence`` 0.15 — strictly below observing the adjacency now (recon 0.25).

The abstraction fence (:func:`~clinkz.discovery.relations.abstract_reaches_identity`)
is applied to BOTH ends of every edge AND to the current engagement's identities, so
a host / IP / URL never matches — the same role/tech-class normalization the write
boundary used, applied symmetrically at read.
"""

from __future__ import annotations

import logging

from clinkz.discovery.models import ReachabilityEdge
from clinkz.discovery.relations import (
    RELATION_REACHES,
    abstract_reaches_identity,
)
from clinkz.discovery.topology import (
    TOPOLOGY_SOURCE_CATALOG,
    TopologyContext,
    _bare_host,
    build_cross_service_edge,
    topology_reach_confidence,
)

logger = logging.getLogger(__name__)

# A learned prior must never flood the plan; independent of the deterministic bound.
_MAX_CATALOG_EDGES = 8
_MAX_CATALOG_B_CANDIDATES = 8


def recall_cross_service_edges(
    egress_edges: list[ReachabilityEdge],
    topology_context: TopologyContext | None,
    technology_relations: list[dict],
    exclude_targets: set[str],
) -> list[ReachabilityEdge]:
    """Seed catalog cross-service edges from learned ``reaches`` priors (§6, B2).

    For each ``reaches`` edge whose A-end matches this engagement's abstracted
    ``origin_identity`` and whose B-end matches an in-scope B candidate's abstracted
    identity (from ``service_identities``), compose A's egress edges with an A→B
    boundary hop graded ``CROSS_SERVICE_TOPOLOGY`` at ``topology_source='catalog'`` /
    ``reach_confidence=0.15``. This is what lets a run whose recon adjacency is
    WITHHELD still test a reach a prior engagement confirmed — the §6/§8
    "gets smarter" transfer. Emission stays the unchanged co-location + P6 gate (§7):
    a stale/wrong learned edge only wastes a probe or surfaces a research-lead.

    Only B candidates NOT already covered by the deterministic recon/source pass
    (``exclude_targets``) are seeded, so a catalog edge never duplicates — and never
    out-ranks — a stronger recon/source edge for the same B. Bounded.

    Args:
        egress_edges: A's single-service ``EGRESS_FETCH`` reachability edges (edge₁);
            with none, A cannot reach out and nothing is seeded (the honest gate).
        topology_context: A's origin/identity + the B-candidate identities, or ``None``.
        technology_relations: All ``technology_relations`` rows dumped from the KB;
            only ``relation_type == 'reaches'`` rows are read here (a SEPARATE read
            from ``capability_recall``, which reads bundles/successor).
        exclude_targets: B URLs already covered by the deterministic pass — not seeded.

    Returns:
        Catalog-recalled cross-service ``ReachabilityEdge`` list (possibly empty),
        bounded. Empty when the store has no matching ``reaches`` edge (cold start).
    """
    if topology_context is None or not egress_edges or not technology_relations:
        return []
    origin_key = abstract_reaches_identity(topology_context.origin_identity)
    if origin_key is None:
        return []  # A un-abstractable → no learned edge can match it

    # role-of-B → the set of learned B-ends A reaches (deduped, abstracted).
    reached_b_roles: set[str] = set()
    for rel in technology_relations:
        if rel.get("relation_type") != RELATION_REACHES:
            continue  # the SEPARATE read — only 'reaches', never bundles/successor
        a_role = abstract_reaches_identity(str(rel.get("tech_a", "")))
        b_role = abstract_reaches_identity(str(rel.get("tech_b", "")))
        if a_role == origin_key and b_role is not None:
            reached_b_roles.add(b_role)
    if not reached_b_roles:
        return []

    origin_host = _bare_host(topology_context.origin_host)
    catalog_conf = topology_reach_confidence(TOPOLOGY_SOURCE_CATALOG)
    edges: list[ReachabilityEdge] = []
    seen_targets: set[str] = set()
    for b_url, b_ident in topology_context.service_identities.items():
        if len(edges) >= _MAX_CATALOG_EDGES or len(seen_targets) >= _MAX_CATALOG_B_CANDIDATES:
            break
        b_host = _bare_host(b_url)
        if (
            not b_host
            or b_host == origin_host
            or b_url in exclude_targets
            or b_host in seen_targets
        ):
            continue  # A is never its own target; skip recon/source-covered + dupes
        if abstract_reaches_identity(b_ident) not in reached_b_roles:
            continue  # this B's role was not among A's learned reaches
        seen_targets.add(b_host)
        for egress in egress_edges:
            if len(edges) >= _MAX_CATALOG_EDGES:
                break
            edges.append(
                build_cross_service_edge(
                    egress,
                    b_url,
                    TOPOLOGY_SOURCE_CATALOG,
                    catalog_conf,
                    b_ident,
                    topology_context.origin_identity,
                )
            )
    if edges:
        logger.info(
            "cross-service topology RECALL: seeded %d catalog A→B edge(s) over %d B "
            "candidate(s) from %d learned reaches role(s)",
            len(edges),
            len(seen_targets),
            len(reached_b_roles),
        )
    return edges
