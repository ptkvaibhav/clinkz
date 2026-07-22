"""JS/TS (Node/Express) source-ingestion tests — discovery slice A1.

Deterministic, in isolation (no container, no LLM, no collaborator). Proves the
:class:`~clinkz.discovery.js_source_ingest.JsSourceIngestor` surfaces the JS sink
shapes that reduce to the EXISTING discovery primitives, and (below) that the
unchanged engine turns that JS ``SourceModel`` into the expected hypotheses — the
full JS-source → engine-hypothesis path, with no Layer-1 fork.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.discovery.js_source_ingest import JsSourceIngestor
from clinkz.discovery.models import CoverageGrade, PrimitiveClass

FIXTURE = Path(__file__).parent.parent / "fixtures" / "js_express_ssrf"


@pytest.fixture(scope="module")
def model():
    return JsSourceIngestor().ingest_path(FIXTURE)


def test_ingests_express_route_entrypoints(model):
    routes = {e.route: e for e in model.entrypoints}
    assert "/fetch" in routes
    assert "/download" in routes
    assert routes["/fetch"].http_methods == ["GET"]
    assert "url" in routes["/fetch"].params
    assert "file" in routes["/download"].params


def test_egress_fetch_call_site_tainted_by_url(model):
    egress = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.EGRESS_FETCH]
    assert len(egress) == 1
    site = egress[0]
    assert site.tainted_by == "url"
    assert site.sink_shape_id == "js.http_egress"
    assert site.symbol == "axios.get"
    assert site.guard_symbol is None


def test_file_read_call_site_tainted_by_file(model):
    reads = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.FILE_READ]
    assert len(reads) == 1
    site = reads[0]
    assert site.tainted_by == "file"
    assert site.sink_shape_id == "js.fs_read"
    assert site.symbol == "fs.readFile"
    # No basename-strip / normalize guard on this read → EXPOSED (no guard symbol).
    assert site.guard_symbol is None


def test_manifest_keys_carrying_dependency_from_lockfile(model):
    # The egress carrying dependency is axios; the lockfile pins the exact point
    # version (1.6.7), which takes precedence over the ^1.6.0 package.json spec.
    assert model.manifest_technology_key == "axios"
    assert model.manifest_observed_version == "1.6.7"
    assert "axios" in model.manifest_evidence


def test_technologies_and_coverage(model):
    assert "Node.js" in model.technologies
    assert "Express" in model.technologies
    assert model.coverage_grade is CoverageGrade.PARTIAL


def test_path_param_rides_url_path(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.2"}}')
    (tmp_path / "routes.js").write_text(
        "const app = require('express')();\n"
        "app.get('/user/:id', (req, res) => {\n"
        "  const id = req.params.id;\n"
        "  fs.readFile(id, 'utf8', (e, d) => res.send(d));\n"
        "});\n"
    )
    model = JsSourceIngestor().ingest_path(tmp_path)
    entry = next(e for e in model.entrypoints if e.route == "/user/:id")
    assert "id" in entry.params
    assert "id" in entry.path_params  # req.params.id rides the URL path segment


def test_basename_guard_makes_file_read_sanctioned(tmp_path):
    # A path.basename() guard on the tainted value is a real guard → the ingestor
    # records it and stamps the call site, so the intent layer reads SANCTIONED.
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.18.2"}}')
    (tmp_path / "app.js").write_text(
        "const path = require('path');\n"
        "app.get('/safe', (req, res) => {\n"
        "  const name = req.query.name;\n"
        "  fs.readFileSync(path.basename(name));\n"
        "});\n"
    )
    model = JsSourceIngestor().ingest_path(tmp_path)
    reads = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.FILE_READ]
    assert len(reads) == 1
    assert reads[0].guard_symbol == "path_basename_strip"
    assert any(g.symbol == "path_basename_strip" for g in model.guards)


def test_constant_url_is_not_egress_surface(tmp_path):
    # A fetch to a constant (non-request) URL is not attack surface — no call site.
    (tmp_path / "package.json").write_text('{"dependencies": {"axios": "1.6.0"}}')
    (tmp_path / "health.js").write_text(
        "app.get('/health', async (req, res) => {\n"
        "  const r = await axios.get('https://status.internal/health');\n"
        "  res.send(r.data);\n"
        "});\n"
    )
    model = JsSourceIngestor().ingest_path(tmp_path)
    assert not [c for c in model.call_sites if c.primitive_class is PrimitiveClass.EGRESS_FETCH]


def test_empty_tree_is_absent(tmp_path):
    model = JsSourceIngestor().ingest_path(tmp_path)
    assert model.entrypoints == []
    assert model.call_sites == []
    assert model.coverage_grade is CoverageGrade.ABSENT
