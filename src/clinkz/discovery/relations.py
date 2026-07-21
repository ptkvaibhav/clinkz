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

# Transfer-confidence tiers (§2.4): manifest-derived bundling is exact (1.0); a
# version-lineage hop is high but ranks just below it.
BUNDLES_SIMILARITY = 1.0
SUCCESSOR_SIMILARITY = 0.8

_RE_VERSION = re.compile(r"(\d+\.\d+(?:\.\d+)?)")


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
