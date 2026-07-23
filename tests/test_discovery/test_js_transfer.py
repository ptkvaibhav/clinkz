"""JS→JS capability transfer + no-over-transfer regression — discovery slice A2a.

Deterministic, in isolation (no container, no LLM, no collaborator). Proves the
slice-2 "gets smarter" experiment in its JS edition:

  * **Engagement A** ingests an app whose EGRESS_FETCH sink lives in a **bundled local
    package** (``vuln-fetch-lib``); the discovery engine keys the capability on the
    PACKAGE (not the app), and the Layer-2 write-back stores a fact keyed on the package
    (a real temp KB round-trip through :meth:`PersistentKnowledgeBase.upsert_capability_fact`,
    exactly as ``ExploitAgent._record_finding_to_kb`` does).
  * **Cold-control B** (a DIFFERENT app that bundles the same package, its sink source
    withheld, empty KB) derives ZERO egress hypotheses.
  * **Warm B** (same partial source, the package fact recalled from the KB) SEEDS the
    egress hypothesis on the app's channel, ``prior_source == capability_recall`` — recall
    transferred the capability across codebases via the package-keyed fact.

The no-over-transfer regression is the safety half: an **app-code** EGRESS_FETCH sink
(the existing ``js_express_ssrf`` axios app, and the ``js_express_esm_factory`` Juice-Shop
A2b analogue) must STAY fingerprint-keyed (``node-js``) — an app-level capability must not
become library-transferable, or every framework-using app would inherit it.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import pytest_asyncio

from clinkz.discovery.engine import DiscoveryEngine
from clinkz.discovery.models import PrimitiveClass
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase

FIXTURES = Path(__file__).parent.parent / "fixtures"
APP_A = FIXTURES / "js_transfer_app_a"
APP_B = FIXTURES / "js_transfer_app_b"
NODE_FINGERPRINT = ["Node.js", "Express"]
BASE_URL = "http://target:3000"


def _egress(hypotheses):
    return [
        h for h in hypotheses if h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
    ]


@pytest_asyncio.fixture
async def kb(tmp_path):
    instance = await PersistentKnowledgeBase.create(str(tmp_path / "transfer_kb.db"))
    yield instance
    await instance.close()


def test_library_borne_sink_keys_on_the_package_not_the_app():
    # Engagement A — full source. The sink lives in the bundled local package, so the
    # hypothesis (and its lowered task provenance) key on vuln-fetch-lib@2.3.1, NOT the app.
    result = DiscoveryEngine().discover(str(APP_A), NODE_FINGERPRINT, BASE_URL)
    egress = _egress(result.hypotheses)
    assert len(egress) == 1
    hyp = egress[0]
    assert hyp.technology_key == "vuln-fetch-lib"
    assert hyp.observed_version == "2.3.1"
    assert hyp.delta.call_site.carrying_dependency == "vuln-fetch-lib"
    provenance = hyp.to_exploit_task().discovery_provenance
    assert provenance is not None
    assert provenance.technology_key == "vuln-fetch-lib"
    assert provenance.observed_version == "2.3.1"
    assert provenance.sink_shape_id == "js.http_egress"


@pytest.mark.asyncio
async def test_js_to_js_transfer_via_recalled_package_fact(kb):
    # Engagement A → write-back keys the capability fact on the PACKAGE (real KB round-trip,
    # exactly as ExploitAgent._record_finding_to_kb does).
    result_a = DiscoveryEngine().discover(str(APP_A), NODE_FINGERPRINT, BASE_URL)
    provenance = _egress(result_a.hypotheses)[0].to_exploit_task().discovery_provenance
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
    assert len(facts) == 1
    assert facts[0]["technology_key"] == "vuln-fetch-lib"  # keyed on the PACKAGE, not app-a
    assert facts[0]["version_predicate"] == "=2.3.1"
    assert facts[0]["primitive_class"] == "egress_fetch"

    # Cold-control B — same partial source, EMPTY KB → zero egress hypotheses.
    cold = DiscoveryEngine().discover(str(APP_B), NODE_FINGERPRINT, BASE_URL)
    assert _egress(cold.hypotheses) == []

    # Warm B — the package fact recalled from the KB SEEDS the egress hypothesis on
    # app-b's channel, keyed on the package, prior_source == capability_recall.
    relations = await kb.get_technology_relations()
    warm = DiscoveryEngine().discover(
        str(APP_B),
        NODE_FINGERPRINT,
        BASE_URL,
        capability_facts=facts,
        technology_relations=relations,
    )
    warm_egress = _egress(warm.hypotheses)
    assert len(warm_egress) == 1
    seeded = warm_egress[0]
    assert seeded.prior_source == "capability_recall"
    assert seeded.technology_key == "vuln-fetch-lib"
    assert seeded.edge.channel_param == "url"
    assert any(r.fact.technology_key == "vuln-fetch-lib" for r in warm.recalls)


def test_app_code_sink_stays_fingerprint_keyed_axios_app():
    # NO-OVER-TRANSFER: the existing js_express_ssrf app calls axios from its OWN server.js
    # — an app-code sink. It must key on the fingerprint (node-js), NOT axios, or the app's
    # SSRF would falsely transfer to every axios-using app.
    result = DiscoveryEngine().discover(
        str(FIXTURES / "js_express_ssrf"), NODE_FINGERPRINT, BASE_URL
    )
    egress = _egress(result.hypotheses)
    assert len(egress) == 1
    assert egress[0].technology_key == "node-js"
    assert egress[0].delta.call_site.carrying_dependency == ""


def test_app_code_sink_stays_fingerprint_keyed_juiceshop_analogue():
    # NO-OVER-TRANSFER (the A2b Juice Shop case): the SSRF sink is app code in
    # routes/profileImageUrlUpload.ts, calling built-in fetch. It must key on node-js, NOT
    # express (the model-level manifest key) — an app-level capability is not transferable.
    result = DiscoveryEngine().discover(
        str(FIXTURES / "js_express_esm_factory"), NODE_FINGERPRINT, BASE_URL
    )
    egress = _egress(result.hypotheses)
    assert len(egress) == 1
    assert egress[0].technology_key == "node-js"
    assert egress[0].delta.call_site.carrying_dependency == ""
