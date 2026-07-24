"""Deterministic ``technology_relations`` edge derivation for Layer-2 transfer (§2.4).

The dormant ``technology_relations`` table finally gets its first production writers
— **deterministic only**, this slice:

  * **``bundles``** — a manifest-derived edge from an app to the *carrying dependency*
    a capability is keyed on: ``apache-solr@8.11.0 → log4j-core@2.14.1`` (Solr's
    ``pom.xml`` declares log4j-core). Manifest-derived ⇒ high precision ⇒ high
    transfer confidence (similarity 1.0). This is what lets *any* log4j-bundling app
    inherit the JNDI capability the first time it is confirmed on any one of them.
  * **``successor``** — a version-lineage edge between two known versions of the same
    technology key (``log4j-core@2.14.0 → log4j-core@2.14.1``), so a fact learned on
    one point version can transfer across the lineage (slightly lower confidence).

Heuristic / LLM ``similar`` edges are **deferred** to a later slice (they are where
over-transfer risk lives, §2.4 / §8.4).

Everything here is a **pure function** over already-observed identities — no I/O, no
LLM, no target literal. The async caller (the discovery seam) writes the returned
edges via ``PersistentKnowledgeBase.add_technology_relation``; recall reads them back.
The edge identity format is ``<normalized-key>@<version>`` (or a bare key when no
version is observable), and :func:`normalize_tech_identity` is the ONE normalization
both the writer and the reader share — so an edge written this engagement is matched
byte-for-byte on the next.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from clinkz.discovery.versions import parse_version

RELATION_BUNDLES = "bundles"
RELATION_SUCCESSOR = "successor"
# Cross-service topology transfer (design §6, slice B2): a SERVICE↔SERVICE edge —
# "a service of role/tech-class A reaches a service of role/tech-class B". Written
# ONLY on a CONFIRMED cross-service reach (YES-only), and ONLY when BOTH ends
# abstract to a role/tech-class identity (:func:`abstract_reaches_identity`); an
# un-abstractable pair stays engagement-local and is NEVER persisted. It is a
# DIFFERENT knowledge kind than the capability-transfer edges — topology recall
# reads it via a SEPARATE path (:mod:`clinkz.discovery.topology_recall`); it is
# deliberately NOT in ``recall._reachable_keys`` (a ``reaches`` edge must never
# transfer a capability fact — the two kinds do not cross).
RELATION_REACHES = "reaches"

# Transfer-confidence tiers (§2.4): manifest-derived bundling is exact (1.0); a
# version-lineage hop is high but ranks just below it.
BUNDLES_SIMILARITY = 1.0
SUCCESSOR_SIMILARITY = 0.8

_RE_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")

# Bare-language / runtime tokens are too broad to be a ``reaches`` endpoint — "every
# Java app reaches a metadata service" is a poisoning-grade over-broad topology edge,
# the exact class :func:`derive_bundles_edges` refuses for an unversioned app (§6.4).
# A ``reaches`` end must be a SPECIFIC role (``internal-metadata-service``) or a
# specific product (``apache-solr``), never a bare language.
_BARE_LANGUAGE_TOKENS = frozenset(
    {
        "java",
        "node",
        "nodejs",
        "node-js",
        "python",
        "python3",
        "php",
        "ruby",
        "go",
        "golang",
        "dotnet",
        "net",
        "perl",
        "scala",
        "kotlin",
        "rust",
        "c",
        "cpp",
        "javascript",
        "typescript",
    }
)
# Host / IP / URL / port shapes — the deployment-specific strings a ``reaches`` edge
# must NEVER carry into the cross-engagement KB (§6.4). These are refused at the write
# boundary (the abstraction fence). The detection is deliberately PRECISE so it
# rejects a host while still accepting a recon PRODUCT name that happens to contain a
# version dot (``Apache Solr 8.11.0``) or spaces:
#   * a URL scheme / path ⇒ reject;
#   * an explicit ``:<port>`` ⇒ reject;
#   * an IPv4 dotted-quad ⇒ reject;
#   * a whitespace-free DOTTED multi-label token (``internal-db.corp.local`` /
#     ``node.js`` / a bare version ``8.11.0``) ⇒ reject — a real product identity
#     either is a single slug token or carries spaces, never a dotted hostname shape.
_RE_URL_OR_PATH = re.compile(r"(://|/)")
_RE_PORT_SUFFIX = re.compile(r":\d")
_RE_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RE_DOTTED_HOST = re.compile(r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+$")


class RelationEdge(BaseModel):
    """One derived technology-relation edge, ready to persist (a pure value)."""

    tech_a: str
    tech_b: str
    relation_type: str
    similarity: float


def _slug(text: str) -> str:
    """Slugify a technology name to a stable key (``Apache Solr`` → ``apache-solr``)."""
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def normalize_tech_identity(tech: str) -> tuple[str, str]:
    """A technology string → ``(normalized_key, version)`` — the shared identity idiom.

    Handles both the edge-storage form (``log4j-core@2.14.1``) and a free-form recon
    fingerprint entry (``Apache Solr 8.11.0``). Used identically by the edge writer
    and by recall so a written edge is matched consistently later.
    """
    tech = tech.strip()
    if "@" in tech:
        key, _, version = tech.partition("@")
        return _slug(key), version.strip()
    match = _RE_VERSION.search(tech)
    version = match.group(1) if match else ""
    without_version = _RE_VERSION.sub("", tech)
    return _slug(without_version), version


def format_identity(key: str, version: str) -> str:
    """``(key, version)`` → the ``key@version`` edge-identity string (bare key if no version)."""
    key = _slug(key)
    return f"{key}@{version}" if version else key


def derive_bundles_edges(
    manifest_technology_key: str,
    manifest_observed_version: str,
    fingerprint: list[str],
) -> list[RelationEdge]:
    """``bundles`` edges: each SPECIFIC app in the fingerprint carries the manifest dep.

    Deterministic and conservative: an edge is emitted only for a **versioned**
    fingerprint entry (a specific product, e.g. ``Apache Solr 8.11.0``), never the
    bare language (``Java`` — which would assert "every Java app bundles this dep", a
    poisoning-grade over-broad edge). ``manifest_technology_key`` /
    ``manifest_observed_version`` come from the ingestor's manifest scan; with no
    manifest capability nothing is emitted.
    """
    if not manifest_technology_key:
        return []
    dep_key = _slug(manifest_technology_key)
    dep_identity = format_identity(dep_key, manifest_observed_version)
    edges: list[RelationEdge] = []
    seen: set[str] = set()
    for tech in fingerprint:
        key, version = normalize_tech_identity(tech)
        if not key or not version:
            continue  # only a versioned, specific product bundles the dependency
        if key == dep_key:
            continue  # the dependency does not bundle itself
        app_identity = format_identity(key, version)
        if app_identity in seen:
            continue
        seen.add(app_identity)
        edges.append(
            RelationEdge(
                tech_a=app_identity,
                tech_b=dep_identity,
                relation_type=RELATION_BUNDLES,
                similarity=BUNDLES_SIMILARITY,
            )
        )
    return edges


def derive_successor_edges(technology_key: str, versions: list[str]) -> list[RelationEdge]:
    """``successor`` edges linking consecutive known versions of one technology key.

    Version lineage over the distinct, parseable versions we have facts for — sorted,
    then adjacent pairs edged low→high. Deterministic; needs ≥2 distinct versions to
    emit anything (a single-version key has no lineage).
    """
    key = _slug(technology_key)
    parsed: dict[tuple[int, int, int], str] = {}
    for raw in versions:
        semver = parse_version(raw)
        if semver is not None:
            parsed.setdefault(semver, raw)
    ordered = [parsed[sv] for sv in sorted(parsed)]
    edges: list[RelationEdge] = []
    for low, high in zip(ordered, ordered[1:], strict=False):
        edges.append(
            RelationEdge(
                tech_a=format_identity(key, low),
                tech_b=format_identity(key, high),
                relation_type=RELATION_SUCCESSOR,
                similarity=SUCCESSOR_SIMILARITY,
            )
        )
    return edges


def abstract_reaches_identity(raw: str) -> str | None:
    """Abstract a service identity to a role/tech-class for a ``reaches`` edge (§6.4).

    **The load-bearing safety property of slice B2.** A ``reaches`` edge is a
    SERVICE↔SERVICE (deployment) fact — inherently more target-specific than a
    TECH↔TECH identity — so the abstraction fence lives HERE, at the write boundary,
    and refuses anything that is not a clean role / tech-class:

      * empty / whitespace-only ⇒ ``None`` (un-abstractable).
      * a host / IP / URL / ``:port`` / path shape ⇒ ``None`` — a deployment-specific
        string must NEVER enter the cross-engagement KB (the primary honesty test).
        This is enforced structurally: a dotted hostname or IP (``.``), a URL scheme
        (``://``), a path (``/``), or an explicit port (``:<digits>``) is rejected.
      * a **bare language / runtime** token (``java`` / ``node-js`` / ``python`` …)
        ⇒ ``None`` — "every X-language app reaches B" is a poisoning-grade over-broad
        edge, the same class :func:`derive_bundles_edges` refuses for an unversioned
        app.

    Otherwise the identity is slugified to its role/tech-class key (``Apache Solr
    8.11.0`` → ``apache-solr``; ``internal-metadata-service`` stays itself) — the
    version is intentionally dropped: a topology reach is a role property, not a
    point-version property, so role-level keying maximises honest transfer. There is
    **no host / IP / URL literal in this logic** — identities are supplied by the
    caller from recon (untrusted runtime data), and this function only *validates and
    normalizes* the shape.

    Args:
        raw: A candidate service identity (a recon tech-class, a role label, or —
            defensively — anything a caller passed; a host-shaped value is refused).

    Returns:
        The normalized role/tech-class key, or ``None`` when un-abstractable (⇒ the
        topology stays engagement-local and is NOT persisted, §6.4).
    """
    value = (raw or "").strip()
    if not value:
        return None
    # Reject unambiguous host / IP / URL / port shapes BEFORE any normalization (§6.4).
    if _RE_URL_OR_PATH.search(value) or _RE_PORT_SUFFIX.search(value) or value.count(":") >= 2:
        return None  # URL / path / :port / IPv6 — never into the shared KB
    if _RE_IPV4.match(value):
        return None  # IPv4 dotted-quad
    if not any(ch.isspace() for ch in value) and _RE_DOTTED_HOST.match(value):
        return None  # a whitespace-free dotted hostname / bare version — not a product
    # A product name (possibly ``Name X.Y.Z``): strip version numbers, then slugify to
    # the role/tech-class key (the version is intentionally dropped — a topology reach
    # is a role property, not a point-version one).
    key = _slug(_RE_VERSION.sub("", value))
    if not key or key in _BARE_LANGUAGE_TOKENS:
        return None  # empty after slugging, or an over-broad bare-language token
    return key


def derive_reaches_edge(a_identity: str, b_identity: str, confidence: float) -> RelationEdge | None:
    """A ``reaches`` edge for a CONFIRMED A→B cross-service reach, or ``None`` (§6).

    Applies the :func:`abstract_reaches_identity` fence to BOTH ends: the edge is
    built only when A **and** B abstract to a clean role/tech-class. If either end is
    un-abstractable (a host/IP/URL, empty, or a bare language) the function returns
    ``None`` and the caller keeps the topology **engagement-local** — a confirmed
    finding still stands, but nothing is written to the cross-engagement KB (§6.4).
    A self-edge (A and B abstract to the same class) is also refused — "reaches
    itself" is not a topology fact.

    ``confidence`` records how the reach was discovered (source 0.35 / recon 0.25) —
    stored in the edge's ``similarity`` for provenance; it is clamped into the DB's
    ``[0, 1]`` CHECK range. It is NOT the recall seed weight: a recalled ``reaches``
    prior always seeds at the fixed ``catalog`` confidence 0.15 (build item 4), the
    weakest discovery source.

    Args:
        a_identity: Service A's recon tech-class / role (never a host — §6.4).
        b_identity: Service B's recon tech-class / role (never a host — §6.4).
        confidence: Discovery-source confidence of the confirmed reach (provenance).

    Returns:
        The abstracted ``reaches`` :class:`RelationEdge`, or ``None`` (engagement-local).
    """
    a_key = abstract_reaches_identity(a_identity)
    b_key = abstract_reaches_identity(b_identity)
    if a_key is None or b_key is None or a_key == b_key:
        return None
    return RelationEdge(
        tech_a=a_key,
        tech_b=b_key,
        relation_type=RELATION_REACHES,
        similarity=max(0.0, min(1.0, confidence)),
    )
