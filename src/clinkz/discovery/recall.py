"""Capability recall — the load-as-prior READ (design §2.3 / §4, slice 2).

``capability_recall`` is the Layer-2 read side: given this engagement's recon
fingerprint + ingested source, and the cross-engagement capability store dumped from
``clinkz_knowledge.db``, return the :class:`~clinkz.discovery.models.CapabilityRecall`
priors that apply here. A recall re-orders and *completes* which hypotheses get
TESTED; it **never emits a finding and never marks a target vulnerable** — emission
stays the unchanged P1–P6 proof on the live target (§5). Accordingly this is a
**pure function**: it performs no I/O, holds no reference to the proof engine, and
writes nothing (not a fact, not an edge).

How a fingerprint reaches a fact (§2.4):

  * **``exact_tech``** — a fingerprint key equals the fact's ``technology_key``.
  * **``bundles``** — a fingerprint app is edged to a carrying dependency the fact is
    keyed on (``apache-solr@8.11.0 → log4j-core@2.14.1``); the dependency's exact
    version rides in the edge, so the version predicate is checkable even when the
    app's own source did not re-derive the sink.
  * **``successor``** — a fingerprint version is linked by a lineage edge to the
    fact's version.

A fact recalls only when the observed version **satisfies the fact's predicate**
(:func:`~clinkz.discovery.versions.version_satisfies`) — the primary staleness guard:
a patched target's version fails the predicate → no recall → no budget spent (§7.1).
A version we cannot observe is the widest, lowest-confidence match (penalised).
"""

from __future__ import annotations

import json
import logging
from typing import Any

from clinkz.discovery.constants import LOG4J_VULNERABLE_TOKEN
from clinkz.discovery.models import (
    CapabilityFact,
    CapabilityRecall,
    PrimitiveClass,
    SoundnessGrade,
    SourceModel,
)
from clinkz.discovery.relations import (
    RELATION_BUNDLES,
    RELATION_SUCCESSOR,
    normalize_tech_identity,
)
from clinkz.discovery.versions import version_satisfies

logger = logging.getLogger(__name__)

# Directness of a match path — a more direct match wins when a fact is reachable by
# more than one route (exact identity beats a bundling hop beats a version-lineage hop).
_MATCH_DIRECTNESS = {"exact_tech": 3, RELATION_BUNDLES: 2, RELATION_SUCCESSOR: 1}
# When the observed version is unknown, a bounded predicate cannot be verified — the
# fact still recalls (widest match, §2.4) but at a reduced confidence so a tight
# budget de-prioritises it first.
_UNOBSERVED_VERSION_PENALTY = 0.5


def capability_recall(
    fingerprint: list[str],
    source_model: SourceModel,
    capability_facts: list[dict[str, Any]],
    technology_relations: list[dict[str, Any]],
) -> list[CapabilityRecall]:
    """Return the capability-recall priors for this engagement (pure, READ-only).

    Args:
        fingerprint: The recon technology fingerprint (``["Java", "Apache Solr 8.11.0"]``).
        source_model: This engagement's ingested source (for the observed manifest
            version and the sink shapes THIS run found — case a vs b, §4).
        capability_facts: All ``capability_facts`` rows dumped from the KB.
        technology_relations: All ``technology_relations`` rows dumped from the KB.

    Returns:
        The matching recalls, highest ``match_confidence`` first. Empty when the store
        is empty or nothing matches — the cold-start behaviour is unchanged.
    """
    if not capability_facts:
        return []

    observed = _observed_identities(fingerprint, source_model)
    reachable = _reachable_keys(observed, technology_relations)
    source_shapes = {
        (cs.primitive_class.value, cs.sink_shape_id) for cs in source_model.call_sites
    }

    recalls: list[CapabilityRecall] = []
    for row in capability_facts:
        fact = _row_to_fact(row)
        if fact is None:
            continue
        key, _ = normalize_tech_identity(fact.technology_key)
        route = reachable.get(key)
        if route is None:
            continue
        match_kind, similarity, observed_version = route
        if observed_version and not version_satisfies(observed_version, fact.version_predicate):
            continue  # patched / wrong-version target — the primary staleness guard (§7.1)
        confidence = fact.confidence * similarity
        if not observed_version:
            confidence *= _UNOBSERVED_VERSION_PENALTY
        source_found_shape = (fact.primitive_class.value, fact.sink_shape_id) in source_shapes
        recalls.append(
            CapabilityRecall(
                fact=fact,
                match_kind=match_kind,
                match_confidence=round(confidence, 4),
                seeds_reachability_grade=(
                    SoundnessGrade.STATIC_HEURISTIC
                    if source_found_shape
                    else SoundnessGrade.HYPOTHESIZED
                ),
                observed_version=observed_version,
                matched_key=key,
            )
        )

    recalls.sort(key=lambda r: r.match_confidence, reverse=True)
    return recalls


def _observed_identities(fingerprint: list[str], source_model: SourceModel) -> dict[str, str]:
    """``key → best observed version`` from the fingerprint + source technologies + manifest.

    A non-empty version wins over an empty one for the same key; the manifest scan's
    exact carrying-dependency version (``log4j-core`` / ``2.14.1``) overrides. The
    synthetic ``LOG4J_VULNERABLE_TOKEN`` is a capability marker, not a technology, and
    is skipped.
    """
    observed: dict[str, str] = {}
    for tech in [*fingerprint, *source_model.technologies]:
        if tech == LOG4J_VULNERABLE_TOKEN:
            continue
        key, version = normalize_tech_identity(tech)
        if not key:
            continue
        if key not in observed or (version and not observed[key]):
            observed[key] = version
    if source_model.manifest_technology_key:
        dep_key, _ = normalize_tech_identity(source_model.manifest_technology_key)
        observed[dep_key] = source_model.manifest_observed_version
    return observed


def _reachable_keys(
    observed: dict[str, str],
    technology_relations: list[dict[str, Any]],
) -> dict[str, tuple[str, float, str]]:
    """Expand the observed keys over transfer edges → ``key → (match_kind, sim, version)``.

    Each observed key is reachable directly (``exact_tech``, sim 1.0). A ``bundles``
    edge carries an observed app to the carrying dependency (with the dependency's own
    version from the edge); a ``successor`` edge is a bidirectional version-lineage
    hop. When a key is reachable by more than one route the most direct wins.
    """
    reachable: dict[str, tuple[str, float, str]] = {}

    def _consider(key: str, kind: str, similarity: float, version: str) -> None:
        if not key:
            return
        incumbent = reachable.get(key)
        rank = (_MATCH_DIRECTNESS.get(kind, 0), similarity)
        if incumbent is None or rank > (_MATCH_DIRECTNESS.get(incumbent[0], 0), incumbent[1]):
            reachable[key] = (kind, similarity, version)

    for key, version in observed.items():
        _consider(key, "exact_tech", 1.0, version)

    for rel in technology_relations:
        rtype = rel.get("relation_type")
        if rtype not in (RELATION_BUNDLES, RELATION_SUCCESSOR):
            continue  # 'similar' (heuristic/LLM) edges are deferred to a later slice
        a_key, a_version = normalize_tech_identity(str(rel.get("tech_a", "")))
        b_key, b_version = normalize_tech_identity(str(rel.get("tech_b", "")))
        similarity = float(rel.get("similarity_score") or 0.0)
        # Forward: an observed app/version reaches the edge's target (dependency or
        # a later lineage version), carrying the target's own version from the edge.
        if a_key in observed:
            _consider(b_key, rtype, similarity, b_version or observed.get(b_key, ""))
        # 'successor' is a symmetric lineage: an observed later version reaches the
        # earlier one too (a fact learned on v2 transfers back to v1's family).
        if rtype == RELATION_SUCCESSOR and b_key in observed:
            _consider(a_key, rtype, similarity, a_version)
    return reachable


def _row_to_fact(row: dict[str, Any]) -> CapabilityFact | None:
    """Build a :class:`CapabilityFact` from a ``capability_facts`` DB row.

    ``input_carriers`` is stored as a JSON string; ``primitive_class`` is a
    :class:`PrimitiveClass` enum value. A row with an unrecognised primitive class is
    skipped (forward-compatible — a class this build does not know can't be tested).
    """
    try:
        primitive_class = PrimitiveClass(str(row["primitive_class"]))
    except (KeyError, ValueError):
        logger.debug("recall: skipping fact with unknown primitive_class: %s", row.get("id"))
        return None
    carriers_raw = row.get("input_carriers")
    carriers: list[str] = []
    if carriers_raw:
        try:
            decoded = json.loads(carriers_raw)
            if isinstance(decoded, list):
                carriers = [str(c) for c in decoded]
        except (TypeError, ValueError):
            carriers = []
    return CapabilityFact(
        technology_key=str(row.get("technology_key", "")),
        version_predicate=str(row.get("version_predicate") or "*"),
        primitive_class=primitive_class,
        sink_shape_id=str(row.get("sink_shape_id", "")),
        input_carriers=carriers,
        confirmation_primitive=str(row.get("confirmation_primitive") or ""),
        gating_config=row.get("gating_config"),
        evidence_grade=str(row.get("evidence_grade") or "derived_unconfirmed"),
        confidence=float(row.get("confidence") or 0.0),
    )
