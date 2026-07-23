"""Cross-file factory-handler resolution (real-world ESM/TS) — discovery slice A2b.

Deterministic, in isolation. Reproduces the shape OWASP Juice Shop uses — route paths
registered in ``server.ts`` but each handler a FACTORY (``export function make () {
return (req, res) => {…} }``) in a separate routes file, wrapped in middleware. Proves
the hardened :class:`JsSourceIngestor` reaches those cross-file bodies (which the A1
inline-only ingestor missed) and that the unchanged engine hypothesizes the SSRF /
file-read against them. This locks the hardening that let A2b surface a real Juice Shop
own-code SSRF (see ``docs/discovery-engine-js-juiceshop-slice-a2b-validation.md``).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from clinkz.discovery.engine import DiscoveryEngine
from clinkz.discovery.js_source_ingest import JsSourceIngestor
from clinkz.discovery.models import PrimitiveClass

FIXTURE = Path(__file__).parent.parent / "fixtures" / "js_express_esm_factory"
NODE_FINGERPRINT = ["Node.js", "Express"]
BASE_URL = "http://target:3000"


@pytest.fixture(scope="module")
def model():
    return JsSourceIngestor().ingest_path(FIXTURE)


def test_ssrf_sink_resolved_across_files(model):
    # The sink lives in routes/profileImageUrlUpload.ts; the route is registered in
    # server.ts via `asyncHandler(profileImageUrlUpload())`. Cross-file resolution must
    # link them and surface the fetch() sink tainted by the request body param.
    egress = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.EGRESS_FETCH]
    assert len(egress) == 1
    site = egress[0]
    assert site.symbol == "fetch"
    assert site.tainted_by == "imageUrl"
    assert site.sink_shape_id == "js.http_egress"
    # The call site is attributed to the routes file (where the sink is), not server.ts.
    assert site.file.replace("\\", "/").endswith("routes/profileImageUrlUpload.ts")


def test_file_read_sink_resolved_across_files(model):
    reads = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.FILE_READ]
    assert len(reads) == 1
    site = reads[0]
    assert site.symbol == "fs.readFile"
    assert site.tainted_by == "file"
    assert site.file.replace("\\", "/").endswith("routes/download.ts")


def test_entrypoint_route_from_server_carries_handler_params(model):
    # The route path is learned from server.ts; the params from the cross-file body.
    ssrf = next(e for e in model.entrypoints if e.route == "/profile/image/url")
    assert "POST" in ssrf.http_methods
    assert "imageUrl" in ssrf.params
    # server.ts is where the route is registered.
    assert ssrf.file.replace("\\", "/").endswith("server.ts")


def test_engine_yields_ssrf_hypothesis_across_files():
    result = DiscoveryEngine().discover(str(FIXTURE), NODE_FINGERPRINT, BASE_URL)
    egress = [
        h
        for h in result.hypotheses
        if h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
    ]
    assert len(egress) == 1
    hyp = egress[0]
    assert hyp.target_url == f"{BASE_URL}/profile/image/url"
    assert hyp.endpoint_method == "POST"
    assert hyp.endpoint_params == ["imageUrl"]
    assert hyp.obligation.test_method == "_test_ssrf"
    assert hyp.delta.call_site.sink_shape_id == "js.http_egress"


def test_app_use_route_is_recognized(tmp_path):
    # app.use('/path', factory()) is a mounted handler; a bare app.use(mw) is not.
    (tmp_path / "package.json").write_text('{"dependencies": {"express": "4.19.2"}}')
    (tmp_path / "srv.js").write_text(
        "import express from 'express'\n"
        "import { serveFile } from './routes/serveFile'\n"
        "const app = express()\n"
        "app.use(express.json())\n"  # bare middleware — NOT a route
        "app.use('/files/:name', serveFile())\n"  # mounted factory handler — a route
    )
    routes = tmp_path / "routes"
    routes.mkdir()
    (routes / "serveFile.ts").write_text(
        "export function serveFile () {\n"
        "  return (req, res) => {\n"
        "    const name = req.query.name\n"
        "    res.sendFile(name)\n"
        "  }\n"
        "}\n"
    )
    model = JsSourceIngestor().ingest_path(tmp_path)
    routes_seen = {e.route for e in model.entrypoints}
    assert "/files/:name" in routes_seen
    # The bare app.use(express.json()) has no path literal → never a route.
    assert not any(e.route == "" and e.http_methods == ["USE"] for e in model.entrypoints)
    reads = [c for c in model.call_sites if c.primitive_class is PrimitiveClass.FILE_READ]
    assert any(c.tainted_by == "name" for c in reads)
