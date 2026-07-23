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

from clinkz.discovery.catalog import match_primitives
from clinkz.discovery.engine import DiscoveryEngine
from clinkz.discovery.js_source_ingest import JsSourceIngestor
from clinkz.discovery.models import CoverageGrade, PrimitiveClass

FIXTURE = Path(__file__).parent.parent / "fixtures" / "js_express_ssrf"
NODE_FINGERPRINT = ["Node.js", "Express"]
BASE_URL = "http://target:3000"


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


def test_workspace_package_sink_is_library_borne(tmp_path):
    # A sink in a workspace package (declared via `workspaces` globs, not a file: dep)
    # is library-borne and attributed to that package@version from its own package.json.
    (tmp_path / "package.json").write_text(
        '{"name":"root","workspaces":["packages/*"],"dependencies":{"express":"4.19.2"}}'
    )
    (tmp_path / "server.js").write_text(
        "import { proxy } from 'net-lib';\n"
        "const app = require('express')();\n"
        "app.get('/p', proxy());\n"
    )
    pkgdir = tmp_path / "packages" / "net-lib"
    pkgdir.mkdir(parents=True)
    (pkgdir / "package.json").write_text('{"name":"net-lib","version":"3.1.4"}')
    (pkgdir / "index.js").write_text(
        "export function proxy () {\n"
        "  return (req, res) => { const u = req.query.u; fetch(u).then(r => res.send(r)); };\n"
        "}\n"
    )
    model = JsSourceIngestor().ingest_path(tmp_path)
    egress = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.EGRESS_FETCH]
    assert len(egress) == 1
    assert egress[0].carrying_dependency == "net-lib"
    assert egress[0].carrying_version == "3.1.4"
    # The workspace package is also surfaced as an observed technology identity.
    assert "net-lib 3.1.4" in model.technologies


def test_app_code_sink_in_subdir_is_not_attributed(tmp_path):
    # A sink in the app's OWN src/ tree (not a declared dependency directory) carries no
    # carrying dependency — it stays fingerprint-keyed. Only bundled packages are indexed.
    (tmp_path / "package.json").write_text(
        '{"name":"app","dependencies":{"axios":"1.6.0","express":"4.19.2"}}'
    )
    src = tmp_path / "src" / "routes"
    src.mkdir(parents=True)
    (src / "proxy.js").write_text(
        "const axios = require('axios');\n"
        "app.get('/p', (req, res) => { const u = req.query.u; axios.get(u); });\n"
    )
    model = JsSourceIngestor().ingest_path(tmp_path)
    egress = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.EGRESS_FETCH]
    assert len(egress) == 1
    assert egress[0].carrying_dependency == ""
    assert egress[0].carrying_version == ""


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


# --- Full JS-source → engine → hypothesis path (no Layer-1 fork) -------------


def test_engine_activates_primitives_on_js_stack(model):
    # The widened (language-generalized) catalog match activates the EXISTING
    # EGRESS_FETCH + FILE_READ primitives on a Node/Express fingerprint — the same
    # primitives a Java target uses, no new class.
    active = {p.primitive_class for p in match_primitives(model, NODE_FINGERPRINT)}
    assert PrimitiveClass.EGRESS_FETCH in active
    assert PrimitiveClass.FILE_READ in active


def test_engine_yields_egress_fetch_hypothesis_from_js_source():
    result = DiscoveryEngine().discover(str(FIXTURE), NODE_FINGERPRINT, BASE_URL)
    egress = [
        h
        for h in result.hypotheses
        if h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
    ]
    assert len(egress) == 1
    hyp = egress[0]
    assert hyp.edge.channel_param == "url"
    assert hyp.target_url == f"{BASE_URL}/fetch"
    assert hyp.endpoint_method == "GET"
    assert hyp.obligation.test_method == "_test_ssrf"
    assert hyp.delta.call_site.sink_shape_id == "js.http_egress"
    # The lowered ExploitTask rides the existing plan-union unchanged.
    task = hyp.to_exploit_task()
    assert task.test_method == "_test_ssrf"
    assert "url" in task.endpoint_params


def test_engine_yields_file_read_hypothesis_from_js_source():
    result = DiscoveryEngine().discover(str(FIXTURE), NODE_FINGERPRINT, BASE_URL)
    reads = [
        h
        for h in result.hypotheses
        if h.delta.call_site.primitive_class is PrimitiveClass.FILE_READ
    ]
    assert len(reads) == 1
    hyp = reads[0]
    assert hyp.edge.channel_param == "file"
    assert hyp.target_url == f"{BASE_URL}/download"
    assert hyp.obligation.test_method == "_test_lfi"
    assert hyp.delta.call_site.sink_shape_id == "js.fs_read"


def test_result_carries_carrying_dependency_manifest_for_a2():
    # The ingestor emits the MODEL-level carrying-dependency manifest (axios @ the locked
    # version) — used for the bundles transfer edges, NOT the EGRESS_FETCH fact key. This
    # app calls axios from its OWN server.js (an app-code sink), so per slice A2a the
    # EGRESS_FETCH hypothesis keys on the fingerprint (node-js), NOT axios — the app-level
    # capability is not library-transferable. (Library-borne keying is covered in
    # test_js_transfer.py.)
    result = DiscoveryEngine().discover(str(FIXTURE), NODE_FINGERPRINT, BASE_URL)
    assert result.source_model.manifest_technology_key == "axios"
    assert result.source_model.manifest_observed_version == "1.6.7"
    egress = next(
        h
        for h in result.hypotheses
        if h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
    )
    assert egress.technology_key == "node-js"
    assert egress.delta.call_site.carrying_dependency == ""
