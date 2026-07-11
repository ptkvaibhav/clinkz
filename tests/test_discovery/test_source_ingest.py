"""Keyless unit gate for Java source ingestion (discovery slice 1).

Runs the deterministic :class:`JavaSourceIngestor` over the real GeoServer
``TestWfsPost.java`` (CVE-2021-40822) checked in under ``tests/fixtures`` and
asserts it surfaces the three facts the walkthrough (§10) depends on:

  1. the ``TestWfsPost`` **entrypoint** (route + request params) — the channel a
     black-box crawl misses because the demo servlet is unlinked (gap #1),
  2. the intra-function ``url → openConnection`` **EGRESS_FETCH** call site, and
  3. the **bypassable host-check guard** (``url`` host vs request ``Host`` header,
     both attacker-controlled; real guard gated on ``ProxyBaseUrl``) — the fact
     Intent must read as bypassable or Δ collapses (gap #2 / open-question #7).

No LLM, no container — pure deterministic extraction.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.discovery.models import CoverageGrade, PrimitiveClass
from clinkz.discovery.source_ingest import JavaSourceIngestor

FIXTURE = Path(__file__).parent.parent / "fixtures" / "geoserver_TestWfsPost.java"


@pytest.fixture(scope="module")
def source_model():
    assert FIXTURE.exists(), f"missing fixture: {FIXTURE}"
    return JavaSourceIngestor().ingest_path(FIXTURE)


def test_surfaces_testwfspost_entrypoint(source_model):
    """The unlinked demo servlet's route + params are surfaced from source."""
    routes = {e.route for e in source_model.entrypoints}
    assert "/TestWfsPost" in routes
    ep = next(e for e in source_model.entrypoints if e.route == "/TestWfsPost")
    assert ep.handler_symbol == "TestWfsPost"
    # The four request parameters the servlet reads.
    assert {"url", "body", "username", "password"}.issubset(set(ep.params))
    # Reachable by both verbs (doGet + doPost delegate to processRequest).
    assert {"GET", "POST"}.issubset(set(ep.http_methods))


def test_surfaces_egress_fetch_call_site_tainted_by_url(source_model):
    """openConnection is surfaced as EGRESS_FETCH, tainted by the ``url`` param."""
    egress = [
        c for c in source_model.call_sites if c.primitive_class == PrimitiveClass.EGRESS_FETCH
    ]
    assert egress, "no EGRESS_FETCH call site found"
    site = egress[0]
    assert site.symbol == "openConnection"
    # Intra-function taint: openConnection receiver → new URL(urlString) → getParameter("url").
    assert site.tainted_by == "url"
    assert site.guard_symbol == "validateURL"
    assert site.line > 0


def test_guard_is_bypassable_not_a_real_guard(source_model):
    """The default host check compares two attacker-controlled values ⇒ bypassable.

    This is the load-bearing adjudication: a naive reader sees "a host check
    exists" and scores it a real guard (Δ collapses, vuln missed). The ingestor
    records that both operands are attacker-controlled and that the *real* guard
    is gated on ``ProxyBaseUrl`` (unset by default).
    """
    assert source_model.guards, "no guard extracted"
    guard = source_model.guards[0]
    assert guard.kind == "host_match"
    assert guard.bypassable_by_default is True
    assert guard.gating_config == "ProxyBaseUrl"
    # Both compared operands trace to attacker-controlled request data.
    assert len(guard.attacker_controlled_operands) == 2


def test_coverage_grade_partial_and_java_tech(source_model):
    assert source_model.coverage_grade == CoverageGrade.PARTIAL
    assert source_model.files_ingested == 1
    assert "Java" in source_model.technologies
