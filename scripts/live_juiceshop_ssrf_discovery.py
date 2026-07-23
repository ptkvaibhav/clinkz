"""Live generalization proof: the JS ingestor + discovery engine on OWASP Juice Shop.

Slice A2b — proves the discovery engine + the (A2b-hardened) JS source ingestor
GENERALIZE to a real, varied, non-Vulhub, *different-language* target by surfacing and
live-confirming ONE of Juice Shop's OWN-CODE vulns end-to-end through the JS-source
path:

    Juice Shop TypeScript/ESM source  ── JsSourceIngestor (cross-file factory
      resolution) ─▶  DiscoveryEngine.discover  ─▶  EGRESS_FETCH hypothesis
      (POST /profile/image/url, imageUrl, _test_ssrf, js.http_egress)  ─▶  the
      UNCHANGED proof engine confirms it via P6 out-of-band on the LIVE instance.

The SSRF (``routes/profileImageUrlUpload.ts`` — ``fetch(req.body.imageUrl)``) is blind
(streams to a file, 302-redirects — no in-band reflection) and auth-gated
(``authenticatedUsers.get(req.cookies.token)``), so the confirmation is P6: the target
fetches a Clinkz-owned collaborator URL carrying a single-use nonce, and the callback
bearing that nonce confirms the fetch fired. Raw-auditable (the outbound probe carrying
the nonce + the inbound callback bearing the SAME nonce + a never-sent control).

Gray-box honesty: ingest the RUNNING instance's own source. Extract it first::

    docker cp clinkz-juiceshop:/juice-shop <source-dir>

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present, Juice Shop
reachable, the source ingests to the EGRESS_FETCH hypothesis, and the collaborator
starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_juiceshop_ssrf_discovery.py --source <juice-shop-source-dir> \
        [--base http://localhost:3000] \
        [--collab-authority host.docker.internal:18081] [--collab-http-port 18081]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import urllib.request
import uuid
from pathlib import Path

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp (lesson #22).
os.environ.setdefault("TOOL_EXEC_MODE", "local")

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)-26s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
for _noisy in ("httpcore", "httpx", "aiohttp", "urllib3", "google", "anthropic", "openai"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("juiceshop_ssrf_discovery")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_status(url: str, timeout: float = 10.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status
    except urllib.error.HTTPError as exc:  # a served error page still means "reachable"
        return exc.code
    except Exception:  # pragma: no cover - preflight diagnostics
        return 0


def _post_json(base: str, path: str, body: dict, timeout: float = 15.0) -> tuple[int, dict]:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        base + path, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status, json.loads(resp.read().decode("utf-8", "replace") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8", "replace") or "{}")
        except Exception:
            return exc.code, {}
    except Exception:  # pragma: no cover
        return 0, {}


def _register_and_login(base: str) -> str | None:
    """Register a throwaway user and log in, returning the JWT the SSRF gate checks."""
    email = f"a2b_{uuid.uuid4().hex[:12]}@juice-sh.op"
    password = "Disc0very!A2b"
    _post_json(
        base,
        "/api/Users",
        {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1},
            "securityAnswer": "generalization",
        },
    )
    status, payload = _post_json(base, "/rest/user/login", {"email": email, "password": password})
    token = (payload.get("authentication") or {}).get("token")
    if status == 200 and token:
        return token
    return None


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        required=True,
        help="Juice Shop source tree for gray-box ingest (docker cp clinkz-juiceshop:/juice-shop)",
    )
    parser.add_argument("--base", default="http://localhost:3000", help="live Juice Shop base URL")
    parser.add_argument("--collab-authority", default="host.docker.internal:18081")
    parser.add_argument("--collab-http-port", type=int, default=18081)
    parser.add_argument("--collab-dns-port", type=int, default=15354)
    parser.add_argument("--wait-window", type=float, default=25.0)
    args = parser.parse_args()

    base_url = args.base.rstrip("/")
    source_dir = args.source

    # ---- PRE-FLIGHT ----------------------------------------------------------
    _rule("PRE-FLIGHT (keys + Juice Shop + source→hypothesis + collaborator)")
    from clinkz.config import settings

    if not (os.environ.get("ANTHROPIC_API_KEY") or getattr(settings, "anthropic_api_key", None)):
        log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run. No substitute.")
        return 2
    if _http_status(f"{base_url}/rest/admin/application-version") != 200:
        log.error("STOP: Juice Shop not reachable at %s. No substitute.", base_url)
        return 2
    if not Path(source_dir).exists():
        log.error(
            "STOP: source tree %s does not exist (docker cp the running source first).", source_dir
        )
        return 2

    # ---- STEP 1: JS SOURCE → DISCOVERY HYPOTHESIS -----------------------------
    from clinkz.discovery.engine import DiscoveryEngine
    from clinkz.discovery.models import PrimitiveClass

    disc = DiscoveryEngine().discover(
        source_dir, ["Node.js", "Express", "OWASP Juice Shop"], base_url
    )
    egress = [
        h
        for h in disc.hypotheses
        if h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
        and h.edge.channel_param == "imageUrl"
    ]
    if not egress:
        log.error(
            "STOP: JS ingestor did not surface the SSRF EGRESS_FETCH hypothesis. No substitute."
        )
        return 2
    hyp = egress[0]
    task = hyp.to_exploit_task()
    cs = hyp.delta.call_site
    sink_file = cs.file.replace(chr(92), "/").split("/")[-1]
    print("SOURCE→HYPOTHESIS (the JS-source path):")
    print(f"  sink: {cs.symbol}({cs.tainted_by}) @ {sink_file}:{cs.line}")
    print(f"  sink_shape_id: {cs.sink_shape_id}  primitive: {cs.primitive_class.value}")
    print(
        f"  hypothesis: {task.endpoint_method} {task.endpoint_url}  param={task.endpoint_params} "
        f"loc={ {k: v.value for k, v in task.param_locations.items()} }  test={task.test_method}"
    )

    from clinkz.oob import CallbackShape, OOBCollaborator

    settings.oob_wait_window = float(args.wait_window)
    collab = OOBCollaborator(
        zone=args.collab_authority,
        callback_shape=CallbackShape.PATH,
        bind_host="0.0.0.0",  # noqa: S104 — the target container must reach the host collaborator
        http_port=args.collab_http_port,
        dns_port=args.collab_dns_port,
        advertised_ip="127.0.0.1",
    )
    try:
        await collab.start()
    except Exception as exc:
        log.error("STOP: OOB collaborator failed to start: %s. No substitute.", exc)
        return 2
    if not await collab.health_check():
        log.error("STOP: OOB collaborator health-check failed. No substitute.")
        await collab.stop()
        return 2
    print(
        f"OOB collaborator healthy: zone={collab.zone} http_port={args.collab_http_port} "
        f"dns_port={args.collab_dns_port}"
    )

    # ---- STEP 2: AUTHENTICATE (the SSRF is auth-gated) ------------------------
    token = _register_and_login(base_url)
    if not token:
        log.error(
            "STOP: could not register+login to Juice Shop for the auth-gated SSRF. No substitute."
        )
        await collab.stop()
        return 2
    print(f"authenticated Juice Shop user (JWT acquired, {len(token)} chars)")

    from clinkz.agents.exploit import ExploitAgent
    from clinkz.agents.report import ReportAgent
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.methodology import SSRFExploitationType, SSRFMethodologyResult
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    scope = EngagementScope(
        name="A2b JS-discovery generalization — Juice Shop SSRF",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
    )
    db_path = REPO_ROOT / "outputs" / "juiceshop_ssrf_discovery.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    llm = get_llm_client("anthropic")

    oob_confirmed = False
    oob_evidence = None
    zero_fp = False
    async with StateStore(str(db_path)) as state:
        engagement_id = await state.create_engagement(
            "A2b JS-discovery generalization — Juice Shop SSRF", scope.model_dump(mode="json")
        )
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            agent._collaborator = collab
            agent._session_cookies["token"] = token  # authenticate the shared session

            # Build the endpoint page straight from the discovery hypothesis's task.
            page = await agent._fetch_page(
                task.endpoint_url,
                task.endpoint_params,
                method=task.endpoint_method,
                content_type=task.endpoint_content_type,
                param_locations=task.param_locations,
                carrier_constraints=task.carrier_constraints,
                discovery_provenance=task.discovery_provenance,
            )

            # ---- STEP 3a: full _test_ssrf methodology (live LLM in the loop) --
            _rule("FULL _test_ssrf METHODOLOGY (live Anthropic LLM + collaborator)")
            method_findings = await agent._test_ssrf(page)
            print(f"  _test_ssrf emitted {len(method_findings)} finding(s):")
            for f in method_findings:
                print(f"    [{f.severity.value.upper()}] {f.title}")
                await agent._persist_finding(f)
            method_confirmed = any("ssrf" in str(f.title).lower() for f in method_findings)

            # ---- STEP 3b: direct P6 confirm — the raw-auditable evidence pair --
            _rule("P6 CONFIRM — point the discovered SSRF param at the collaborator")
            oob_confirmed, oob_evidence, note = await agent._ssrf_oob_confirm(page, "imageUrl")
            print(f"  confirmed_out_of_band={oob_confirmed}  note={note}")
            if oob_evidence is not None:
                print("  RAW-AUDITABLE P6 evidence pair:")
                print(f"    outbound_probe    : {oob_evidence.outbound_probe}")
                print(f"    callback_nonce    : {oob_evidence.confirming_marker}")
                print(f"    inbound_callback  : {oob_evidence.confirming_excerpt}")
                print(f"    control           : {oob_evidence.control_label[:80]}…")
                print(f"    control_bore_nonce: {oob_evidence.control_confirms} (must be False)")

            # ---- STEP 4: ZERO-FP control — strip auth → SSRF blocked → no callback
            _rule("ZERO-FP — same probe with auth stripped (SSRF gate blocks) → no callback")
            agent._session_cookies.pop("token", None)
            ctrl_confirmed, _ctrl_ev, ctrl_note = await agent._ssrf_oob_confirm(page, "imageUrl")
            zero_fp = not ctrl_confirmed
            print(
                f"  control confirmed_out_of_band={ctrl_confirmed} (expect False)  note={ctrl_note}"
            )
            agent._session_cookies["token"] = token  # restore for the emitted finding's context

            # Persist the OOB-confirmed finding carrying the JS discovery provenance so
            # report.json + trace.jsonl show the primitive_class / sink_shape_id origin.
            if oob_confirmed and oob_evidence is not None:
                result = SSRFMethodologyResult(
                    candidate_param="imageUrl",
                    exploitation_type=SSRFExploitationType.BLIND_OOB_CONFIRMED,
                    synthesized_payload=oob_evidence.confirming_target,
                    indicator_type="oob_callback",
                    indicator_observed=note,
                    confirmation_evidence=oob_evidence,
                    verified=True,
                    verification_strength="verified-oob",
                    phases_completed=6,
                )
                result.capability.fetch_confirmed = True
                # The emit stamps the ACTUAL confirming primitive (P6) onto the finding's
                # provenance from page.discovery_provenance (set at _fetch_page above) — so
                # report.json reads P6, the JS discovery key (node-js), and the sink shape.
                finding = agent._ssrf_phase6_emit(page, "imageUrl", result)
                await agent._persist_finding(finding)

            _rule("REPORT + TRACE (raw artifact paths)")
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            rep = await report_agent.run(
                {"engagement_id": engagement_id, "engagement_name": "A2b Juice Shop SSRF discovery"}
            )
        finally:
            trace.close()
            set_active_trace_writer(None)
            await collab.stop()

        trace_path = REPO_ROOT / "outputs" / engagement_id / "trace.jsonl"
        print(f"engagement_id : {engagement_id}")
        print(f"report (json) : {rep.get('json_path')}")
        print(f"report (md)   : {rep.get('markdown_path')}")
        print(f"trace (jsonl) : {trace_path}")

    # ---- VERDICT -------------------------------------------------------------
    _rule("VERDICT — JS-source generalization on a live, different-language target")
    oob_pair_ok = bool(
        oob_evidence
        and oob_evidence.outbound_probe
        and oob_evidence.confirming_marker
        and oob_evidence.confirming_marker in oob_evidence.confirming_excerpt
        and oob_evidence.control_confirms is False
    )
    p6_ok = oob_confirmed and oob_pair_ok
    print("  JS ingestor surfaced the own-code SSRF sink (cross-file)   : True")
    print("  engine hypothesized EGRESS_FETCH from JS source            : True")
    print(f"  full _test_ssrf methodology confirmed (live LLM)           : {method_confirmed}")
    print(f"  P6 confirm via callback (raw-auditable)                    : {p6_ok}")
    print(f"  zero-FP (auth stripped → SSRF gate blocks → no callback)   : {zero_fp}")
    ok = oob_confirmed and oob_pair_ok and zero_fp
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
