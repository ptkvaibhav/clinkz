"""Slice A2a validation — JS→JS capability transfer + no-over-transfer (raw artifacts).

Deterministic, no live target / LLM / collaborator: it drives the SAME discovery engine
and the SAME Layer-2 write-back the pipeline uses, and dumps the RAW evidence a grader
re-derives the claim from. It writes to ``outputs/js-a2a-transfer/``:

  * ``capability_facts_after_A.json`` — the KB dump after engagement A's confirmed,
    discovery-provenance write-back. The row is keyed on the PACKAGE (``vuln-fetch-lib``),
    NOT the app — the library-borne case.
  * ``hypotheses_cold_control_B.json`` — engagement B (partial source, EMPTY KB): zero
    egress hypotheses.
  * ``hypotheses_warm_B.json`` — engagement B (same partial source) WITH the package fact
    recalled: one egress hypothesis, ``prior_source == capability_recall``, keyed on the
    package. The cold-vs-warm diff is the "gets smarter" signal.
  * ``no_over_transfer.json`` — the safety half: the app-code SSRF sinks (the axios app and
    the Juice-Shop A2b ESM-factory analogue) STAY fingerprint-keyed (``node-js``), never the
    library they call.

Run: ``python scripts/live_js_transfer_a2a_validation.py``
"""

from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from clinkz.discovery.engine import DiscoveryEngine
from clinkz.discovery.models import DiscoveryHypothesis, PrimitiveClass
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase

_REPO = Path(__file__).resolve().parent.parent
_FIXTURES = _REPO / "tests" / "fixtures"
_OUT = _REPO / "outputs" / "js-a2a-transfer"
_FINGERPRINT = ["Node.js", "Express"]
_BASE_URL = "http://target:3000"


def _egress(hypotheses: list[DiscoveryHypothesis]) -> list[DiscoveryHypothesis]:
    return [
        h for h in hypotheses if h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
    ]


def _hyp_row(h: DiscoveryHypothesis) -> dict:
    return {
        "id": h.id,
        "primitive_class": h.delta.call_site.primitive_class.value,
        "sink_shape_id": h.delta.call_site.sink_shape_id,
        "channel_param": h.edge.channel_param,
        "technology_key": h.technology_key,
        "observed_version": h.observed_version,
        "prior_source": h.prior_source,
        "reachability_grade": h.edge.soundness_grade.value,
        "rank_score": h.rank_score,
        "carrying_dependency": h.delta.call_site.carrying_dependency,
    }


async def main() -> None:
    _OUT.mkdir(parents=True, exist_ok=True)
    engine = DiscoveryEngine()

    # --- Engagement A: full source, library-borne sink -> fact keyed on the PACKAGE ---
    result_a = engine.discover(str(_FIXTURES / "js_transfer_app_a"), _FINGERPRINT, _BASE_URL)
    egress_a = _egress(result_a.hypotheses)
    assert len(egress_a) == 1, f"expected 1 egress hypothesis in A, got {len(egress_a)}"
    provenance = egress_a[0].to_exploit_task().discovery_provenance
    assert provenance is not None and provenance.technology_key == "vuln-fetch-lib", (
        f"A must key on the package, got {provenance.technology_key if provenance else None!r}"
    )

    with tempfile.TemporaryDirectory() as tmp:
        kb = await PersistentKnowledgeBase.create(str(Path(tmp) / "a2a_kb.db"))
        try:
            # The exact write-back ExploitAgent._record_finding_to_kb performs on a
            # confirmed discovery finding.
            fact_id = await kb.upsert_capability_fact(
                technology_key=provenance.technology_key,
                version_predicate=f"={provenance.observed_version}",
                primitive_class=provenance.primitive_class,
                sink_shape_id=provenance.sink_shape_id,
                engagement_id="A",
                confirmation_primitive=provenance.confirmation_primitive,
            )
            await kb.add_capability_observation(
                engagement_id="A",
                primitive_class=provenance.primitive_class,
                outcome="confirmed",
                capability_fact_id=fact_id,
                sink_shape_id=provenance.sink_shape_id,
            )
            await kb.recompute_capability_confidence(fact_id)
            facts = await kb.get_capability_facts()
            relations = await kb.get_technology_relations()
        finally:
            await kb.close()

    (_OUT / "capability_facts_after_A.json").write_text(json.dumps(facts, indent=2, default=str))

    # --- Cold-control B: partial source, EMPTY KB -> zero egress hypotheses ---
    cold = engine.discover(str(_FIXTURES / "js_transfer_app_b"), _FINGERPRINT, _BASE_URL)
    cold_egress = _egress(cold.hypotheses)
    (_OUT / "hypotheses_cold_control_B.json").write_text(
        json.dumps([_hyp_row(h) for h in cold_egress], indent=2)
    )

    # --- Warm B: same partial source, WITH the package fact recalled ---
    warm = engine.discover(
        str(_FIXTURES / "js_transfer_app_b"),
        _FINGERPRINT,
        _BASE_URL,
        capability_facts=facts,
        technology_relations=relations,
    )
    warm_egress = _egress(warm.hypotheses)
    (_OUT / "hypotheses_warm_B.json").write_text(
        json.dumps([_hyp_row(h) for h in warm_egress], indent=2)
    )

    # --- No-over-transfer: app-code sinks STAY fingerprint-keyed (node-js) ---
    over = {}
    for name in ("js_express_ssrf", "js_express_esm_factory"):
        result = engine.discover(str(_FIXTURES / name), _FINGERPRINT, _BASE_URL)
        over[name] = [_hyp_row(h) for h in _egress(result.hypotheses)]
    (_OUT / "no_over_transfer.json").write_text(json.dumps(over, indent=2))

    # --- Console summary (raw, no self-grading) ---
    fact_keys = [(f["technology_key"], f["version_predicate"]) for f in facts]
    print(f"[A]  capability_facts: {fact_keys}")
    print(f"[cold-control B] egress hypotheses: {len(cold_egress)}")
    print(
        f"[warm B] egress hypotheses: {len(warm_egress)} "
        f"({[(h.technology_key, h.prior_source) for h in warm_egress]})"
    )
    for name, rows in over.items():
        keying = [(r["technology_key"], r["carrying_dependency"]) for r in rows]
        print(f"[no-over-transfer] {name}: {keying}")
    print(f"\nRaw artifacts written to {_OUT}")


if __name__ == "__main__":
    asyncio.run(main())
