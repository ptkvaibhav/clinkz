"""Cross-service topology discovery — the A→B boundary hop (design §1/§2, slice B1).

Single-service reachability (:mod:`clinkz.discovery.reachability`) binds a channel to
a Δ-capability **both inside one** ``SourceModel``. This module adds the one genuinely
new link: the **A→B boundary hop**, where an untrusted channel enters at service A's
entrypoint, A's egress forwards attacker-influenced data across a process boundary, and
the sink/impact lives in a *different* in-scope service B. It **extends** reachability
(it composes an already-built A-side egress edge with the boundary hop); it does **not**
fork it, add a ``PrimitiveClass``, or touch a proof oracle.

Two **deterministic** discovery sources are built here (design §2 a+b; the ``catalog``
prior of §2c is slice B2, not built):

* **(a) SOURCE** — A's source statically constructs a URL whose host resolves to an
  in-scope internal service B (a config/const/base-URL literal, *not* the
  request-controlled SSRF target). The static-target recognizer is what distinguishes
  "A intentionally calls B" from "A merely has an SSRF"; both can coexist on one egress
  (a config default the request overrides). ``reach_confidence`` 0.35.
* **(b) RECON** — B is in scope and reachable from A's segment; A has an egress
  capability. Network adjacency, **weaker** than source because it does not prove A's
  code calls B — only that the wire is open. ``reach_confidence`` 0.25.

Every A→B edge is graded :attr:`SoundnessGrade.CROSS_SERVICE_TOPOLOGY` — the WEAKEST
grade — via :func:`~clinkz.discovery.models.compose_soundness` (min over the composed
hops), so a rock-solid ``STATIC_CONFIRMED`` A-side egress can never lift a speculative
A→B chain above the topology grade (§1). The grade never gates emission — it only ranks
the candidate chains the proof engine tries; the unchanged P3/P6 oracle co-located with
B is the sole emission gate (§4/§7).

**Generality law:** no host / IP / URL literal appears in any logic or persisted schema
here. Identities come from the runtime :class:`~clinkz.models.scope.EngagementScope` and
from the TARGET's own source (untrusted data, exactly like every other ingested idiom).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from clinkz.discovery.models import (
    ReachabilityEdge,
    SoundnessGrade,
    compose_soundness,
)

logger = logging.getLogger(__name__)

# Discovery-source sub-ordering WITHIN the cross-service grade (design §1 table).
# source (A statically calls B) > recon (open wire, no proven call). These order
# candidate chains only — never an emission gate.
TOPOLOGY_SOURCE_STATIC = "source"
TOPOLOGY_SOURCE_RECON = "recon"
_REACH_CONFIDENCE_SOURCE = 0.35
_REACH_CONFIDENCE_RECON = 0.25

# Bounds — a loose topology prior must never flood the plan or the scanner.
_MAX_B_CANDIDATES = 8
_MAX_CROSS_SERVICE_EDGES = 16
# Static-egress-host scan bounds (self-contained; touches no existing recognizer).
_MAX_SCAN_FILES = 4000
_MAX_FILE_BYTES = 1_000_000
_SOURCE_EXTENSIONS = frozenset(
    {".java", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".properties", ".xml", ".yml", ".yaml"}
)
# A URL literal in source: ``http(s)://host[:port]``. The host is extracted from the
# TARGET's own source (untrusted data) and only becomes a SOURCE edge when it matches
# an in-scope B — so an incidental URL literal (a namespace, a docs link) that is NOT
# an in-scope service is inert. No host literal lives in this pattern.
_RE_URL_LITERAL = re.compile(r"https?://([A-Za-z0-9_.\-]+(?::\d+)?)", re.IGNORECASE)


class TopologyContext(BaseModel):
    """The runtime topology facts cross-service discovery composes against (§2).

    Built by the caller (the Orchestrator) from the engagement
    :class:`~clinkz.models.scope.EngagementScope` + recon — never from a literal
    baked into code. When absent (single-service engagement) the discovery engine
    skips cross-service composition entirely and behaviour is unchanged.

    Attributes:
        origin_host: Service A's own origin host (``host`` or ``host:port``), so A
            is excluded from its own B-candidate set (a service is never its own
            cross-service target).
        internal_services: Candidate B internal URLs — in-scope services **distinct
            from A**, adjacency-resolved by the caller (in scope ⇒ reachable, incl.
            internal-only metadata/admin surfaces). The recon-adjacency prior (§2b);
            the SOURCE upgrade (§2a) is computed here by matching A's static egress
            hosts against these. Order is the caller's ranking; the first
            :data:`_MAX_B_CANDIDATES` are considered.
    """

    origin_host: str = ""
    internal_services: list[str] = Field(default_factory=list)


def topology_reach_confidence(topology_source: str) -> float:
    """The composed edge's ``reach_confidence`` for a discovery source (design §1).

    source (A statically calls B) 0.35 > recon (open wire) 0.25. Ranking weight
    only — never an emission gate. An unknown source falls to the recon prior (the
    weakest of the two built sources).
    """
    return (
        _REACH_CONFIDENCE_SOURCE
        if topology_source == TOPOLOGY_SOURCE_STATIC
        else _REACH_CONFIDENCE_RECON
    )


def _host_of(url_or_host: str) -> str:
    """Normalized ``host[:port]`` (lowercased) of a URL or bare host string."""
    value = (url_or_host or "").strip()
    if not value:
        return ""
    parsed = urlparse(value if "://" in value else f"//{value}", scheme="")
    host = parsed.hostname or ""
    if not host:
        # Bare ``host:port`` with no scheme that urlparse could not split.
        host = value.split("/", 1)[0].split(":", 1)[0]
    port = parsed.port
    host = host.lower()
    return f"{host}:{port}" if port else host


def _bare_host(url_or_host: str) -> str:
    """The hostname alone (no port), lowercased — for host-only equivalence."""
    return _host_of(url_or_host).split(":", 1)[0]


def scan_static_egress_hosts(source_dir: str) -> set[str]:
    """Bounded scan of A's source for statically-referenced URL hosts (design §2a).

    Extracts the host of every ``http(s)://host[:port]`` **literal** in the source
    tree — a config/const/base-URL egress target A's code names statically (as
    opposed to the request-controlled SSRF target, which is not a literal). Returns
    the set of hosts (bare hostname, lowercased). The caller intersects this with
    the in-scope B set, so an incidental literal that is not an in-scope service is
    inert (no false SOURCE edge). Self-contained (no existing recognizer touched),
    bounded in files + bytes, regex-only. Never raises — an unreadable tree yields
    an empty set (degrades to recon-only adjacency).
    """
    hosts: set[str] = set()
    root = Path(source_dir)
    if not root.exists():
        return hosts
    scanned = 0
    for path in root.rglob("*"):
        if scanned >= _MAX_SCAN_FILES:
            break
        if not path.is_file() or path.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue
        scanned += 1
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for match in _RE_URL_LITERAL.finditer(text):
            bare = match.group(1).split(":", 1)[0].strip().lower()
            if bare:
                hosts.add(bare)
    return hosts


def discover_cross_service_edges(
    egress_edges: list[ReachabilityEdge],
    topology_context: TopologyContext | None,
    static_egress_hosts: set[str],
) -> list[ReachabilityEdge]:
    """Compose A's egress edges with the A→B boundary hop into cross-service edges.

    For each in-scope B candidate (bounded) and each of A's ``EGRESS_FETCH`` edges
    (edge₁ — the already-built egress channel), emit one composed
    :class:`ReachabilityEdge` whose:

      * ``cross_service_target`` is B's internal URL (the confirmation target — the
        sink lives in B, §3);
      * ``soundness_grade`` is :func:`compose_soundness` over ``[edge₁.grade,
        CROSS_SERVICE_TOPOLOGY]`` — always ``CROSS_SERVICE_TOPOLOGY`` (the weakest
        hop dominates, §1), *never* edge₁'s grade;
      * ``reach_confidence`` sub-orders by discovery source (source 0.35 > recon
        0.25), and ``topology_source`` records which.

    A B whose host A statically references (``static_egress_hosts``) is a SOURCE
    edge; otherwise a RECON adjacency edge. Only A's own egress edges are composed,
    so with **no egress capability** (A cannot reach out) nothing is emitted — the
    honest gate: a cross-service SSRF needs A's egress channel. With no
    ``topology_context`` (single-service engagement) the result is empty and
    behaviour is unchanged.

    Args:
        egress_edges: A's single-service ``EGRESS_FETCH`` reachability edges.
        topology_context: The in-scope B set + A's origin, or ``None``.
        static_egress_hosts: Hosts A's source references statically (§2a) — from
            :func:`scan_static_egress_hosts`.

    Returns:
        Cross-service ``ReachabilityEdge`` list (possibly empty), bounded.
    """
    if topology_context is None or not egress_edges:
        return []
    origin = _bare_host(topology_context.origin_host)
    static_bare = {h.split(":", 1)[0] for h in static_egress_hosts}
    edges: list[ReachabilityEdge] = []
    seen_targets: set[str] = set()
    for service in topology_context.internal_services:
        if len(edges) >= _MAX_CROSS_SERVICE_EDGES:
            break
        b_host = _bare_host(service)
        # A is never its own cross-service target; and dedupe repeated B entries.
        if not b_host or b_host == origin or b_host in seen_targets:
            continue
        if len(seen_targets) >= _MAX_B_CANDIDATES:
            break
        seen_targets.add(b_host)
        is_static = b_host in static_bare
        topology_source = TOPOLOGY_SOURCE_STATIC if is_static else TOPOLOGY_SOURCE_RECON
        reach_confidence = _REACH_CONFIDENCE_SOURCE if is_static else _REACH_CONFIDENCE_RECON
        for egress in egress_edges:
            if len(edges) >= _MAX_CROSS_SERVICE_EDGES:
                break
            composed = compose_soundness(
                [egress.soundness_grade, SoundnessGrade.CROSS_SERVICE_TOPOLOGY]
            )
            edges.append(
                ReachabilityEdge(
                    channel_param=egress.channel_param,
                    channel_location=egress.channel_location,
                    primitive_id=egress.primitive_id,
                    entrypoint_route=egress.entrypoint_route,
                    entrypoint_methods=list(egress.entrypoint_methods),
                    path_evidence=(
                        f"cross-service ({topology_source}): A's egress channel "
                        f"{egress.channel_param!r} on {egress.entrypoint_methods} "
                        f"{egress.entrypoint_route or '/'} → in-scope internal service {service} "
                        f"(A-side {egress.soundness_grade.value}, boundary hop "
                        f"{SoundnessGrade.CROSS_SERVICE_TOPOLOGY.value} — composite is the "
                        "weakest hop; the co-located P3/P6 proof at B confirms)"
                    ),
                    soundness_grade=composed,
                    reach_confidence=reach_confidence,
                    cross_service_target=service,
                    topology_source=topology_source,
                )
            )
    if edges:
        logger.info(
            "cross-service topology: %d A→B edge(s) over %d B candidate(s) (%d static hosts)",
            len(edges),
            len(seen_targets),
            len(static_bare),
        )
    return edges
