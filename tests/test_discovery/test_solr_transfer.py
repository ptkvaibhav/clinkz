"""Keyless transfer gate — a SECOND, differently-shaped SSRF through the SAME engine.

Slice 2 proves the discovery engine generalizes: it finds Apache Solr's
``stream.url`` RemoteStreaming SSRF (`Remote-Streaming-Fileread`, Solr 8.8.1) from
real source, reusing the *same* ``EGRESS_FETCH`` capability primitive catalogued
for GeoServer (CVE-2021-40822) — with **no Solr-specific literal** anywhere in the
engine. Every Solr particular is learned from Solr's own source:

  * the channel param ``stream.url`` — resolved from the symbolic constant
    ``CommonParams.STREAM_URL = "stream.url"`` (a non-servlet param-bag read,
    ``params.getParams(...)``, not ``request.getParameter("...")``), and
  * the egress sink — ``new ContentStreamBase.URLStream(new URL(url))``, where
    ``URLStream`` is *discovered* to be a fetch wrapper because its own body calls
    ``url.openConnection()`` one class away.

These tests are the transfer metric made executable: the engine changes are the
general source-ingest axes (below), not a Solr detector. No LLM, no container.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.discovery import CARRIER_ALIGN_HOST, DiscoveryEngine
from clinkz.discovery.models import (
    DeltaGrade,
    ParamLocation,
    PrimitiveClass,
    SoundnessGrade,
)
from clinkz.discovery.source_ingest import (
    JavaSourceIngestor,
    _resolve_param_name,
)

FIXTURE = Path(__file__).parent.parent / "fixtures" / "solr_remote_streaming"
BASE_URL = "http://localhost:8983/solr/demo/debug/dump"


@pytest.fixture(scope="module")
def source_model():
    assert FIXTURE.exists(), f"missing fixture: {FIXTURE}"
    return JavaSourceIngestor().ingest_path(FIXTURE)


@pytest.fixture(scope="module")
def result():
    return DiscoveryEngine().discover(str(FIXTURE), ["Java", "Solr"], BASE_URL)


# --- Source ingestion: the general axes that carry the transfer ---------------


def test_surfaces_non_servlet_param_bag_entrypoint(source_model):
    """A non-servlet request-param reader is an entrypoint (axis 1).

    ``SolrRequestParsers`` does not ``extends HttpServlet`` and reads params from a
    ``SolrParams`` bag — yet it is surfaced as the channel-bearing entrypoint.
    """
    handlers = {e.handler_symbol for e in source_model.entrypoints}
    assert "SolrRequestParsers" in handlers
    ep = next(e for e in source_model.entrypoints if e.handler_symbol == "SolrRequestParsers")
    # Query-carried GET on the operator-supplied reflecting handler (no servlet path).
    assert ep.http_methods == ["GET"]
    assert ep.route == ""


def test_channel_param_resolved_from_symbolic_constant(source_model):
    """``params.getParams(CommonParams.STREAM_URL)`` resolves to ``stream.url`` (axis 2)."""
    params = {p for e in source_model.entrypoints for p in e.params}
    assert "stream.url" in params  # resolved from CommonParams.STREAM_URL = "stream.url"
    # The literal "STREAM_URL" symbol never leaks as a param name.
    assert "STREAM_URL" not in params
    assert "CommonParams.STREAM_URL" not in params


def test_egress_sink_via_cross_class_url_wrapper(source_model):
    """``new URLStream(new URL(stream.url))`` is an EGRESS_FETCH site (axis 3).

    The literal ``openConnection`` lives in ``ContentStreamBase.URLStream`` one
    class away; the ingestor learns ``URLStream`` is a fetch wrapper from its own
    body and treats the wrapped construction as the reachable sink.
    """
    egress = [
        c for c in source_model.call_sites if c.primitive_class == PrimitiveClass.EGRESS_FETCH
    ]
    assert len(egress) == 1, "expected exactly one tainted egress site (the stream.url channel)"
    site = egress[0]
    assert site.symbol == "openConnection"
    assert site.tainted_by == "stream.url"
    # No host-check guard exists on Solr's fetch (unlike GeoServer's validateURL).
    assert site.guard_symbol is None
    assert "SolrRequestParsers.java" in site.file


def test_position_aware_taint_not_the_reused_var_later_binding(source_model):
    """Regression: the reused ``strs`` local must bind the loop to stream.url.

    Solr reassigns one ``String[] strs`` across ``stream.url`` → ``stream.file`` →
    ``stream.body``. A flat last-wins taint map would mis-attribute the URL loop to
    ``stream.body``; the nearest-preceding pairing keeps it ``stream.url``. A
    ``stream.body`` / ``stream.file`` egress site here would be a false channel.
    """
    tainted = {c.tainted_by for c in source_model.call_sites}
    assert tainted == {"stream.url"}
    assert "stream.body" not in tainted
    assert "stream.file" not in tainted


def test_wrapper_discovery_is_selective():
    """Only classes that open a connection are egress wrappers — not their siblings.

    ``URLStream`` (calls ``url.openConnection()``) is a wrapper; ``FileStream`` /
    ``StringStream`` (no URL fetch) are not — proving the discovery is signal-based,
    not name-based.
    """
    text = (FIXTURE / "ContentStreamBase.java").read_text(encoding="utf-8")
    wrappers = JavaSourceIngestor._discover_egress_wrapper_types(text)
    assert "URLStream" in wrappers
    assert "FileStream" not in wrappers
    assert "StringStream" not in wrappers


def test_resolve_param_name_literal_and_symbolic():
    """The name resolver: literal passes through; symbolic resolves via const map."""
    const_map = {"STREAM_URL": "stream.url"}
    assert _resolve_param_name('"stream.url"', const_map) == "stream.url"
    assert _resolve_param_name("CommonParams.STREAM_URL", const_map) == "stream.url"
    assert _resolve_param_name("Unknown.MISSING", const_map) is None


# --- The full chain: same primitive, no carrier, Tier-A _test_ssrf ------------


def test_reuses_geoserver_egress_primitive_no_new_catalog(result):
    """The SAME catalogued EGRESS_FETCH primitive fires — no Solr-specific entry."""
    ids = {p.id for p in result.active_primitives}
    assert ids == {"egress_fetch.java_openconnection"}
    prim = result.active_primitives[0]
    assert prim.primitive_class == PrimitiveClass.EGRESS_FETCH
    assert prim.proof_obligation.test_method == "_test_ssrf"
    assert {"P3", "P1"}.issubset(set(prim.proof_obligation.confirmation_primitives))


def test_intent_exposed_via_no_guard_intent_gap(result):
    """Solr's unguarded fetch is EXPOSED via the intent-gap path (no host guard).

    GeoServer reached EXPOSED through a *bypassable guard*; Solr has no guard at
    all, so it reaches the same verdict through the other adjudication branch —
    the engine's intent layer transfers without change.
    """
    assert len(result.deltas) == 1
    delta = result.deltas[0]
    assert delta.delta_grade == DeltaGrade.EXPOSED
    assert delta.call_site.tainted_by == "stream.url"
    assert "no guard" in delta.intent_evidence.lower()


def test_reachability_query_channel_static_confirmed(result):
    assert len(result.edges) == 1
    edge = result.edges[0]
    assert edge.channel_param == "stream.url"
    assert edge.channel_location == ParamLocation.QUERY
    assert edge.soundness_grade == SoundnessGrade.STATIC_CONFIRMED


def test_hypothesis_binds_test_ssrf_with_no_carrier(result):
    """Tier-A ``_test_ssrf`` at the operator-supplied handler, NO Host carrier.

    Solr has no host-match guard, so the per-instance Host-alignment carrier that
    GeoServer needed is correctly absent — the carrier machinery is guard-driven,
    not vuln-class-driven.
    """
    assert len(result.hypotheses) == 1
    hyp = result.hypotheses[0]
    assert hyp.target_url == BASE_URL  # no trailing slash (path-exact handler)
    assert hyp.obligation.test_method == "_test_ssrf"
    assert hyp.obligation.carrier_constraints == []
    assert CARRIER_ALIGN_HOST not in hyp.obligation.carrier_constraints


def test_hypothesis_lowers_to_tier_a_query_task(result):
    task = result.hypotheses[0].to_exploit_task()
    assert task.test_method == "_test_ssrf"
    assert task.endpoint_url == BASE_URL
    assert task.endpoint_method == "GET"
    assert task.endpoint_params == ["stream.url"]
    assert task.param_locations == {"stream.url": ParamLocation.QUERY}
    assert task.carrier_constraints == []
    assert task.tier == 1
