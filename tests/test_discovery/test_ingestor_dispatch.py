"""Language-dispatch tests for the source-ingestor seam — discovery slice A1.

Deterministic, in isolation. Proves :func:`select_ingestor` routes a project to the
right ingestor AND — critically — that extracting the :class:`SourceIngestor`
interface did **not** perturb Java: every existing Java fixture ingests
byte-identically through the dispatch as it did through the old hard-wired call.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.discovery.ingestor import SourceIngestor, select_ingestor
from clinkz.discovery.js_source_ingest import JsSourceIngestor
from clinkz.discovery.source_ingest import JavaSourceIngestor

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Every checked-in Java fixture (single-file + multi-file dirs, with / without a
# manifest) the dispatch must keep routing to the unchanged Java ingestor.
JAVA_FIXTURES = [
    "geoserver_TestWfsPost.java",
    "solr_log4shell",
    "solr_log4shell_partial",
    "solr_log4shell_patched",
    "flink_jobmanager_logs",
    "flink_jobmanager_logs_patched",
    "solr_remote_streaming",
]
JS_FIXTURE = "js_express_ssrf"


def test_selects_js_ingestor_for_node_project():
    ingestor = select_ingestor(FIXTURES / JS_FIXTURE)
    assert isinstance(ingestor, JsSourceIngestor)


@pytest.mark.parametrize("name", JAVA_FIXTURES)
def test_selects_java_ingestor_for_java_project(name):
    ingestor = select_ingestor(FIXTURES / name)
    assert isinstance(ingestor, JavaSourceIngestor)


@pytest.mark.parametrize("name", JAVA_FIXTURES)
def test_java_ingests_byte_identically_through_dispatch(name):
    fixture = FIXTURES / name
    direct = JavaSourceIngestor().ingest_path(fixture)
    dispatched = select_ingestor(fixture).ingest_path(fixture)
    # A full structural dump — the interface extraction must be pure (zero behaviour
    # change), so the two SourceModels are equal field-for-field.
    assert dispatched.model_dump() == direct.model_dump()


def test_both_ingestors_satisfy_the_protocol():
    assert isinstance(JavaSourceIngestor(), SourceIngestor)
    assert isinstance(JsSourceIngestor(), SourceIngestor)


def test_unknown_tree_defaults_to_java(tmp_path):
    # A non-source directory (no Java/JS signal) falls back to the Java ingestor — the
    # unchanged default, so an empty/irrelevant source_dir behaves as before.
    (tmp_path / "README.md").write_text("no source here")
    assert isinstance(select_ingestor(tmp_path), JavaSourceIngestor)
