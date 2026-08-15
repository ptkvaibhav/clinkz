"""Live §8 two-service validation of cross-service reachability (slice B1).

The honesty test of the whole slice, run for REAL against a live target + live OOB
collaborator + live Anthropic exploit LLM, no harness. The topology:

  * **Service A** — OWASP Juice Shop's own-code SSRF egress (``fetch(req.body.imageUrl)``
    @ ``routes/profileImageUrlUpload.ts``), source-ingested by the JS ingestor and
    surfaced as an ``EGRESS_FETCH`` hypothesis. In scope, running on :3000.
  * **Service B** — an internal service reachable FROM A. Per §3's precondition B is
    network-isolated from Clinkz (the honest rung is P6-at-B, not in-band), so the
    Clinkz OOB collaborator is mounted AT B's internal address, in scope.
  * **The reach** — the cross-service SSRF hypothesis (an ``EGRESS_FETCH`` Δ whose
    reaching edge crossed the A→B boundary, graded ``CROSS_SERVICE_TOPOLOGY``) points
    A's ``imageUrl`` param at B's internal URL bearing a single-use nonce.

Two arms exercise the CO-LOCATION GATE — the one thing the slice adds — and NOTHING
else differs between them:

  * **Arm (b) — co-located.** The collaborator's callback address IS B's declared
    in-scope address. A egresses → callback recorded AT B → a **cross-service SSRF
    FINDING** (raw-auditable P6 pair + the never-sent control).
  * **Arm (c) — THE PHANTOM CONTROL.** The SAME chain with a GENERIC collaborator NOT
    co-located with B (B is a *different* declared in-scope service). A callback still
    lands — proving only "A egresses *somewhere*" — so the system MUST NOT emit a
    cross-service finding; it produces a **RESEARCH-LEAD**
    (``egress_confirmed_but_B_reach_not_observed``). No cross-service finding is
    emitted in this arm.

Everything is gradeable from raw: ``outputs/<eid_b>/report_<eid_b>.json`` (arm b,
the finding) + ``outputs/<eid_c>/report_<eid_c>.json`` (arm c, the research-lead) +
each ``trace.jsonl`` + ``outputs/cross-service-b1/edge_grade_dump.json`` (the
discovered A→B edge with grade + discovery source) + this run log.

Gray-box honesty: ingest the RUNNING instance's own source. Extract it first::

    docker cp clinkz-juiceshop:/juice-shop <source-dir>

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present + a live
ping, Juice Shop reachable, the source ingests to the cross-service EGRESS_FETCH
hypothesis, and the collaborator starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_cross_service_ssrf_validation.py \
        [--source <juice-shop-source-dir>] [--base http://localhost:3000] \
        [--collab-authority host.docker.internal:18082] [--collab-http-port 18082] \
        [--collab-dns-port 15356] [--wait-window 25]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid
from pathlib import Path

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp (lesson #22).
os.environ.setdefault("TOOL_EXEC_MODE", "local")

from _artifact_io import write_redacted_json  # noqa: E402

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
log = logging.getLogger("cross_service_ssrf")

REPO_ROOT = Path(__file__).resolve().parent.parent
ART_DIR = REPO_ROOT / "outputs" / "cross-service-b1"

# Arm-c's declared in-scope internal service B — a DIFFERENT address than the
# collaborator, so the generic-collaborator callback is not co-located with B. It is a
# scope/role identity, never a payload target: the probe still goes to the collaborator.
B_GENERIC_HOST = "internal-metadata"
B_GENERIC_URL = f"http://{B_GENERIC_HOST}:80/latest/meta-data/"


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_status(url: str, timeout: float = 10.0) -> int:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status
    except urllib.error.HTTPError as exc:
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
    email = f"xsvc_{uuid.uuid4().hex[:12]}@juice-sh.op"
    password = "Cr0ssServ!ceB1"
    _post_json(
        base,
        "/api/Users",
        {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1},
            "securityAnswer": "reachability",
        },
    )
    status, payload = _post_json(base, "/rest/user/login", {"email": email, "password": password})
    token = (payload.get("authentication") or {}).get("token")
    return token if (status == 200 and token) else None


def _docker_cp_source() -> str | None:
    """Extract the RUNNING Juice Shop's own source (gray-box honesty; version-exact)."""
    dest = Path(tempfile.mkdtemp(prefix="juiceshop_src_")) / "juice-shop"
    try:
        subprocess.run(  # noqa: S603,S607 — fixed args, no untrusted input
            ["docker", "cp", "clinkz-juiceshop:/juice-shop", str(dest)],
            check=True,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.SubprocessError, OSError) as exc:
        log.error("docker cp failed: %s", exc)
        return None
    return str(dest)


async def _live_ping_anthropic() -> bool:
    """One cheap real Anthropic call to prove the key works + quota isn't depleted."""
    from clinkz.llm.factory import get_llm_client

    try:
        client = get_llm_client("anthropic")
        reply = await client.generate_text("Reply with the single word: ok")
        return bool(reply)
    except Exception as exc:  # pragma: no cover - preflight diagnostics
        log.error("Anthropic live-ping failed: %s", exc)
        return False


def _dump(path: Path, obj: object) -> None:
    """Write a driver artifact through the engine's redaction chokepoint."""
    write_redacted_json(path, obj)


async def _run_arm(
    *,
    arm: str,
    base_url: str,
    task,
    collab,
    token: str,
    scope,
    llm,
) -> dict:
    """Run one arm's cross-service confirmation and emit its report. Returns a summary."""
    from clinkz.agents.exploit import ExploitAgent
    from clinkz.agents.report import ReportAgent
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    db_path = REPO_ROOT / "outputs" / f"cross_service_{arm}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    summary: dict = {"arm": arm}
    async with StateStore(str(db_path)) as state:
        eid = await state.create_engagement(
            f"Cross-service reachability B1 — arm {arm}", scope.model_dump(mode="json")
        )
        trace = TraceWriter(eid)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(llm=llm, tools=[], scope=scope, state=state, engagement_id=eid)
            agent._collaborator = collab
            agent._session_cookies["token"] = token  # authenticate the shared session

            # Dispatch through the REAL _execute_task chokepoint: it fetches A's page,
            # routes the cross_service_target task to _confirm_cross_service_reach, and
            # stamps discovery provenance — the same seam the live pipeline uses.
            findings = await agent._execute_task(task, {})
            for f in findings:
                await agent._persist_finding(f)
            await agent._persist_research_leads()

            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
            )
            rep = await report_agent.run(
                {"engagement_id": eid, "engagement_name": f"Cross-service B1 arm {arm}"}
            )
        finally:
            trace.close()
            set_active_trace_writer(None)

        summary["engagement_id"] = eid
        summary["cross_service_findings"] = [
            {"title": f.title, "severity": f.severity.value, "evidence": f.evidence}
            for f in findings
        ]
        summary["research_leads"] = [
            ld.model_dump(mode="json") for ld in agent._cross_service_research_leads
        ]
        summary["report_json"] = rep.get("json_path")
        summary["report_md"] = rep.get("markdown_path")
        summary["trace"] = str(REPO_ROOT / "outputs" / eid / "trace.jsonl")
    return summary


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=None, help="Juice Shop source dir (else docker cp)")
    parser.add_argument("--base", default="http://localhost:3000")
    parser.add_argument("--collab-authority", default="host.docker.internal:18082")
    parser.add_argument("--collab-http-port", type=int, default=18082)
    parser.add_argument("--collab-dns-port", type=int, default=15356)
    parser.add_argument("--wait-window", type=float, default=25.0)
    args = parser.parse_args()
    base_url = args.base.rstrip("/")

    # ---- PRE-FLIGHT (STOP-on-fail, no substitute) ---------------------------
    _rule("PRE-FLIGHT (keys + live ping + Juice Shop + collaborator)")
    from clinkz.config import settings

    if not (os.environ.get("ANTHROPIC_API_KEY") or getattr(settings, "anthropic_api_key", None)):
        log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run. No substitute.")
        return 2
    if not await _live_ping_anthropic():
        log.error("STOP: Anthropic live-ping failed (key/quota). No substitute.")
        return 2
    print("Anthropic key present + live-ping OK (the exploit LLM). Gemini unused in this path.")
    if _http_status(f"{base_url}/rest/admin/application-version") != 200:
        log.error("STOP: Juice Shop not reachable at %s. No substitute.", base_url)
        return 2
    source_dir = args.source or _docker_cp_source()
    if not source_dir or not Path(source_dir).exists():
        log.error("STOP: no Juice Shop source tree (docker cp failed?). No substitute.")
        return 2
    print(f"Juice Shop reachable; source ingested from {source_dir}")

    # ---- STEP 1: DISCOVER THE CROSS-SERVICE A→B EDGE (§8a) -------------------
    _rule("DISCOVERY — the A→B cross-service edge (grade CROSS_SERVICE_TOPOLOGY)")
    from clinkz.discovery.engine import DiscoveryEngine
    from clinkz.discovery.models import PrimitiveClass, SoundnessGrade
    from clinkz.discovery.topology import TopologyContext

    # Two in-scope B candidates: arm-b's co-located B (the collaborator's address) and
    # arm-c's generic B (a different internal service). Both distinct from A (localhost).
    topo = TopologyContext(
        origin_host="localhost:3000",
        internal_services=[f"http://{args.collab_authority}/", B_GENERIC_URL],
    )
    disc = DiscoveryEngine().discover(
        source_dir, ["Node.js", "Express", "OWASP Juice Shop"], base_url, topology_context=topo
    )
    xsvc = [
        h
        for h in disc.hypotheses
        if h.edge.cross_service_target
        and h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
        and h.edge.channel_param == "imageUrl"
    ]
    if not xsvc:
        log.error("STOP: no cross-service EGRESS_FETCH hypothesis discovered. No substitute.")
        return 2
    edge_dump = []
    for h in xsvc:
        assert h.edge.soundness_grade is SoundnessGrade.CROSS_SERVICE_TOPOLOGY
        edge_dump.append(
            {
                "hypothesis_id": h.id,
                "a_endpoint": h.to_exploit_task().endpoint_url,
                "a_channel": h.edge.channel_param,
                "b_target": h.edge.cross_service_target,
                "reachability_grade": h.edge.soundness_grade.value,
                "topology_source": h.edge.topology_source,
                "reach_confidence": h.edge.reach_confidence,
                "rank_score": h.rank_score,
                "test_method": h.obligation.test_method,
                "sink_shape_id": h.delta.call_site.sink_shape_id,
            }
        )
        print(
            f"  edge: A({h.edge.channel_param})→B({h.edge.cross_service_target}) "
            f"grade={h.edge.soundness_grade.value} source={h.edge.topology_source} "
            f"conf={h.edge.reach_confidence} rank={h.rank_score}"
        )
    _dump(ART_DIR / "edge_grade_dump.json", edge_dump)
    task_colocated = next(
        h.to_exploit_task() for h in xsvc if args.collab_authority in h.edge.cross_service_target
    )
    task_generic = next(
        h.to_exploit_task() for h in xsvc if B_GENERIC_HOST in h.edge.cross_service_target
    )

    # ---- STEP 2: COLLABORATOR + AUTH ----------------------------------------
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
    print(f"OOB collaborator healthy: zone={collab.zone}")

    token = _register_and_login(base_url)
    if not token:
        log.error("STOP: could not register+login to Juice Shop for the auth-gated SSRF.")
        await collab.stop()
        return 2
    print(f"authenticated Juice Shop user (JWT acquired, {len(token)} chars)")

    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

    # Scope declares A + BOTH B candidates. Arm b: B == the collaborator's address
    # (co-located). Arm c: B == a different internal service (generic collaborator).
    scope = EngagementScope(
        name="Cross-service reachability B1 — Juice Shop A → internal B",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
            ScopeEntry(value=collab.callback_zone().split(":", 1)[0], type=ScopeType.DOMAIN),
            ScopeEntry(value=B_GENERIC_HOST, type=ScopeType.DOMAIN),
        ],
    )
    from clinkz.llm.factory import get_llm_client

    llm = get_llm_client("anthropic")

    try:
        # ---- ARM (b): co-located collaborator → cross-service FINDING --------
        _rule("ARM (b) — collaborator CO-LOCATED with B → cross-service SSRF FINDING")
        arm_b = await _run_arm(
            arm="b",
            base_url=base_url,
            task=task_colocated,
            collab=collab,
            token=token,
            scope=scope,
            llm=llm,
        )
        for f in arm_b["cross_service_findings"]:
            print(f"  [{f['severity'].upper()}] {f['title']}")
        print(f"  cross-service findings: {len(arm_b['cross_service_findings'])} (expect 1)")
        print(f"  research-leads: {len(arm_b['research_leads'])} (expect 0)")

        # ---- ARM (c): THE PHANTOM CONTROL — generic collaborator → LEAD ------
        _rule("ARM (c) — PHANTOM CONTROL: generic collaborator NOT at B → RESEARCH-LEAD")
        arm_c = await _run_arm(
            arm="c",
            base_url=base_url,
            task=task_generic,
            collab=collab,
            token=token,
            scope=scope,
            llm=llm,
        )
        print(f"  cross-service findings: {len(arm_c['cross_service_findings'])} (expect 0)")
        print(f"  research-leads: {len(arm_c['research_leads'])} (expect 1)")
        for ld in arm_c["research_leads"]:
            print(f"    why_unconfirmed={ld['why_unconfirmed']}  b_target={ld['b_target']}")
    finally:
        await collab.stop()

    _dump(ART_DIR / "run_summary.json", {"arm_b": arm_b, "arm_c": arm_c, "edges": edge_dump})

    # ---- VERDICT (all four §8 checks, from raw) -----------------------------
    _rule("VERDICT — the §8 two-service metric (gradeable from raw)")
    edge_ok = bool(edge_dump)
    # (b) a cross-service finding confirmed with a raw-auditable P6 pair + control.
    b_findings = arm_b["cross_service_findings"]
    b_ok = len(b_findings) == 1 and any(
        "outbound_probe:" in " ".join(f["evidence"])
        and "callback_nonce=" in " ".join(f["evidence"])
        and "control_bore_it=False" in " ".join(f["evidence"])
        for f in b_findings
    )
    # (c) NO cross-service finding; a research-lead with the honest why_unconfirmed.
    c_ok = len(arm_c["cross_service_findings"]) == 0 and any(
        ld["why_unconfirmed"] == "egress_confirmed_but_B_reach_not_observed"
        for ld in arm_c["research_leads"]
    )
    print(f"  (a) cross-service edge discovered (grade CROSS_SERVICE_TOPOLOGY): {edge_ok}")
    print(f"  (b) arm b — cross-service SSRF finding, raw-auditable P6 + control: {b_ok}")
    print(f"  (c) arm c — PHANTOM CONTROL: no finding, research-lead instead    : {c_ok}")
    print(f"      arm b report : {arm_b['report_json']}")
    print(f"      arm c report : {arm_c['report_json']}")
    print(f"      edge dump    : {ART_DIR / 'edge_grade_dump.json'}")
    ok = edge_ok and b_ok and c_ok
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
