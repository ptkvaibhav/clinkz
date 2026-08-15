"""Live two-engagement validation of cross-service topology LEARNING (slice B2, §6/§8).

The "gets smarter" proof for the cross-service loop, run for REAL against a live
target + live OOB collaborator + live Anthropic exploit LLM, no harness. It extends
the B1 §8 experiment (the reach) with the B2 loop (learning the reach), over ONE
shared cross-engagement KB:

  * **Engagement A** — a genuine cross-service reach confirmed via B1's path (OWASP
    Juice Shop's own-code SSRF egress → an internal service B instrumented by the
    Clinkz collaborator at B's address). On confirm, the YES-only write-back persists
    the ABSTRACTED ``reaches`` edge (role-of-A → role-of-B, both a tech/role class —
    NEVER a host/IP/URL).

  * **Engagement B, cold-control** — the SAME target with its recon adjacency WITHHELD
    (``internal_services`` empty) and an EMPTY KB. Discovery produces ZERO cross-service
    hypotheses (nothing re-derives the withheld chain).

  * **Engagement B, warm** — identical withheld conditions, but the KB now holds
    engagement A's ``reaches`` edge. The SEPARATE topology recall seeds a cross-service
    hypothesis (``topology_source='catalog'``, ``reach_confidence=0.15``) that the
    UNCHANGED co-location + P6 gate then CONFIRMS. Recall changed the PATH; the live
    proof confirmed the finding.

  * **Zero-FP arm** — a warm catalog-seeded chain aimed at a B the collaborator is NOT
    co-located with → a RESEARCH-LEAD (``egress_confirmed_but_B_reach_not_observed``),
    never a finding: a learned topology is still fully proof-gated.

Everything is gradeable from raw: the ``technology_relations`` dump before/after
(the abstracted reaches edge, both ends role/class), the cold vs warm discovery trace
(0 vs 1 catalog-seeded cross-service hypothesis), and each engagement's report.json.

Gray-box honesty: ingest the RUNNING instance's own source (``docker cp``).

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present + a live
ping, Juice Shop reachable, the source ingests to the cross-service EGRESS_FETCH
hypothesis, and the collaborator starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_cross_service_topology_learning_validation.py \
        [--source <juice-shop-source-dir>] [--base http://localhost:3000] \
        [--collab-authority host.docker.internal:18084] [--collab-http-port 18084] \
        [--collab-dns-port 15358] [--wait-window 25]
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
log = logging.getLogger("xsvc_learning")

REPO_ROOT = Path(__file__).resolve().parent.parent
ART_DIR = REPO_ROOT / "outputs" / "cross-service-b2"

# The abstracted role identities the reaches edge is keyed on — role/tech classes,
# NEVER a host. A is the specific Juice Shop product; B is an internal-metadata role.
A_ROLE = "owasp-juice-shop"
B_ROLE = "internal-metadata-service"

# The zero-FP arm's declared in-scope B — a DIFFERENT address than the collaborator, so
# a catalog-seeded chain aimed at it is NOT co-located (proves the learned prior is
# still proof-gated). A scope/role identity only; the probe still goes to the collaborator.
B_GENERIC_HOST = "internal-metadata-generic"
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
    email = f"xsvc2_{uuid.uuid4().hex[:12]}@juice-sh.op"
    password = "L34rnServ!ceB2"
    _post_json(
        base,
        "/api/Users",
        {
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "securityQuestion": {"id": 1},
            "securityAnswer": "topology",
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


def _discover_xsvc(source_dir: str, base_url: str, topo, relations):
    """Run discovery and return the cross-service EGRESS_FETCH hypotheses (imageUrl)."""
    from clinkz.discovery.engine import DiscoveryEngine
    from clinkz.discovery.models import PrimitiveClass

    disc = DiscoveryEngine().discover(
        source_dir,
        ["Node.js", "Express", "OWASP Juice Shop"],
        base_url,
        technology_relations=relations,
        topology_context=topo,
    )
    return [
        h
        for h in disc.hypotheses
        if h.edge.cross_service_target
        and h.delta.call_site.primitive_class is PrimitiveClass.EGRESS_FETCH
        and h.edge.channel_param == "imageUrl"
    ]


def _edge_row(h) -> dict:
    return {
        "hypothesis_id": h.id,
        "a_endpoint": h.to_exploit_task().endpoint_url,
        "a_channel": h.edge.channel_param,
        "b_target": h.edge.cross_service_target,
        "reachability_grade": h.edge.soundness_grade.value,
        "topology_source": h.edge.topology_source,
        "reach_confidence": h.edge.reach_confidence,
        "cross_service_a_identity": h.edge.cross_service_a_identity,
        "cross_service_b_identity": h.edge.cross_service_b_identity,
        "prior_source": h.prior_source,
        "rank_score": h.rank_score,
    }


async def _run_engagement(*, name: str, task, collab, token: str, scope, llm, kb_path: str) -> dict:
    """Confirm a cross-service reach through the REAL driver + emit a report."""
    from clinkz.agents.exploit import ExploitAgent
    from clinkz.agents.report import ReportAgent
    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    db_path = REPO_ROOT / "outputs" / f"xsvc_learn_{name}.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    summary: dict = {"engagement": name}
    kb = await PersistentKnowledgeBase.create(kb_path)
    async with StateStore(str(db_path)) as state:
        eid = await state.create_engagement(
            f"Cross-service topology learning B2 — {name}", scope.model_dump(mode="json")
        )
        trace = TraceWriter(eid)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(
                llm=llm,
                tools=[],
                scope=scope,
                state=state,
                engagement_id=eid,
                persistent_kb=kb,
            )
            agent._collaborator = collab
            agent._session_cookies["token"] = token
            findings = await agent._execute_task(task, {})
            for f in findings:
                await agent._persist_finding(f)
            await agent._persist_research_leads()
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=eid
            )
            rep = await report_agent.run(
                {"engagement_id": eid, "engagement_name": f"Cross-service B2 {name}"}
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
        summary["trace"] = str(REPO_ROOT / "outputs" / eid / "trace.jsonl")
    await kb.close()
    return summary


async def _dump_relations(kb_path: str) -> list[dict]:
    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase

    kb = await PersistentKnowledgeBase.create(kb_path)
    try:
        return await kb.get_technology_relations()
    finally:
        await kb.close()


async def main() -> int:  # noqa: PLR0911, PLR0915 — a linear live driver with STOP gates
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=None, help="Juice Shop source dir (else docker cp)")
    parser.add_argument("--base", default="http://localhost:3000")
    parser.add_argument("--collab-authority", default="host.docker.internal:18084")
    parser.add_argument("--collab-http-port", type=int, default=18084)
    parser.add_argument("--collab-dns-port", type=int, default=15358)
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
    print("Anthropic key present + live-ping OK (the exploit LLM).")
    if _http_status(f"{base_url}/rest/admin/application-version") != 200:
        log.error("STOP: Juice Shop not reachable at %s. No substitute.", base_url)
        return 2
    source_dir = args.source or _docker_cp_source()
    if not source_dir or not Path(source_dir).exists():
        log.error("STOP: no Juice Shop source tree (docker cp failed?). No substitute.")
        return 2
    print(f"Juice Shop reachable; source ingested from {source_dir}")

    from clinkz.discovery.topology import TopologyContext
    from clinkz.oob import CallbackShape, OOBCollaborator

    collab_url = f"http://{args.collab_authority}/"
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

    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType

    scope = EngagementScope(
        name="Cross-service topology learning B2 — Juice Shop A → internal B",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
            ScopeEntry(value=collab.callback_zone().split(":", 1)[0], type=ScopeType.DOMAIN),
            ScopeEntry(value=B_GENERIC_HOST, type=ScopeType.DOMAIN),
        ],
    )
    llm = get_llm_client("anthropic")

    # A shared cross-engagement KB across A and warm-B (fresh temp file — no legacy edges).
    kb_path = str(Path(tempfile.mkdtemp(prefix="xsvc_kb_")) / "clinkz_knowledge.db")

    # Topology A: full adjacency, B co-located with the collaborator, both ends abstract.
    topo_a = TopologyContext(
        origin_host="localhost:3000",
        origin_identity=A_ROLE,
        internal_services=[collab_url],
        service_identities={collab_url: B_ROLE},
    )
    # Topology B: recon adjacency WITHHELD (no internal_services); B identity still known.
    topo_b_warm = TopologyContext(
        origin_host="localhost:3000",
        origin_identity=A_ROLE,
        internal_services=[],
        service_identities={collab_url: B_ROLE},
    )
    # Zero-FP topology: a catalog-seeded chain aimed at a GENERIC B (not the collaborator).
    topo_zerofp = TopologyContext(
        origin_host="localhost:3000",
        origin_identity=A_ROLE,
        internal_services=[],
        service_identities={B_GENERIC_URL: B_ROLE},
    )

    try:
        relations_before = await _dump_relations(kb_path)
        _dump(ART_DIR / "technology_relations_before.json", relations_before)

        # ---- ENGAGEMENT A: confirm the reach → write the abstracted reaches edge ----
        _rule("ENGAGEMENT A — cross-service reach CONFIRMED → reaches edge written")
        xa = _discover_xsvc(source_dir, base_url, topo_a, [])
        if not xa:
            log.error("STOP: no cross-service EGRESS_FETCH hypothesis in engagement A.")
            return 2
        _dump(ART_DIR / "engagement_a_edges.json", [_edge_row(h) for h in xa])
        task_a = next(
            h.to_exploit_task() for h in xa if args.collab_authority in h.edge.cross_service_target
        )
        arm_a = await _run_engagement(
            name="a", task=task_a, collab=collab, token=token, scope=scope, llm=llm, kb_path=kb_path
        )
        print(
            f"  engagement A cross-service findings: {len(arm_a['cross_service_findings'])} (=1?)"
        )

        relations_after = await _dump_relations(kb_path)
        _dump(ART_DIR / "technology_relations_after.json", relations_after)
        reaches = [r for r in relations_after if r["relation_type"] == "reaches"]
        for r in reaches:
            print(f"  reaches edge: {r['tech_a']} -> {r['tech_b']} (sim={r['similarity_score']})")

        # ---- ENGAGEMENT B COLD-CONTROL: withheld adjacency + EMPTY KB → 0 xsvc ----
        _rule("ENGAGEMENT B (cold-control) — withheld adjacency + EMPTY KB → 0 cross-service")
        cold = _discover_xsvc(source_dir, base_url, topo_b_warm, [])
        _dump(ART_DIR / "engagement_b_cold_edges.json", [_edge_row(h) for h in cold])
        print(f"  cold-control cross-service hypotheses: {len(cold)} (expect 0)")

        # ---- ENGAGEMENT B WARM: withheld adjacency + KB from A → catalog seed → P6 ----
        _rule("ENGAGEMENT B (warm) — topology recall seeds catalog chain → P6 confirms")
        warm = _discover_xsvc(source_dir, base_url, topo_b_warm, relations_after)
        _dump(ART_DIR / "engagement_b_warm_edges.json", [_edge_row(h) for h in warm])
        print(f"  warm cross-service hypotheses: {len(warm)} (expect 1, topology_source=catalog)")
        for h in warm:
            e = h.edge
            print(f"    edge: source={e.topology_source} conf={e.reach_confidence}")
            print(f"          b={e.cross_service_target}")
        arm_b = {"cross_service_findings": [], "research_leads": []}
        if warm:
            task_warm = next(
                h.to_exploit_task()
                for h in warm
                if args.collab_authority in h.edge.cross_service_target
            )
            arm_b = await _run_engagement(
                name="b_warm",
                task=task_warm,
                collab=collab,
                token=token,
                scope=scope,
                llm=llm,
                kb_path=kb_path,
            )
            print(
                f"  warm cross-service findings: {len(arm_b['cross_service_findings'])} (expect 1)"
            )

        # ---- ZERO-FP arm: catalog-seeded chain aimed at a non-co-located B → lead ----
        _rule("ZERO-FP — a learned chain aimed at a NON-co-located B → RESEARCH-LEAD")
        zf = _discover_xsvc(source_dir, base_url, topo_zerofp, relations_after)
        _dump(ART_DIR / "engagement_zerofp_edges.json", [_edge_row(h) for h in zf])
        arm_z = {"cross_service_findings": [], "research_leads": []}
        if zf:
            task_z = next(
                h.to_exploit_task() for h in zf if B_GENERIC_HOST in h.edge.cross_service_target
            )
            arm_z = await _run_engagement(
                name="zerofp",
                task=task_z,
                collab=collab,
                token=token,
                scope=scope,
                llm=llm,
                kb_path=kb_path,
            )
            print(f"  zero-fp cross-service findings: {len(arm_z['cross_service_findings'])} (=0?)")
            print(f"  zero-fp research-leads: {len(arm_z['research_leads'])} (expect 1)")
    finally:
        await collab.stop()

    _dump(
        ART_DIR / "run_summary.json",
        {
            "relations_before": relations_before,
            "relations_after": relations_after,
            "engagement_a": arm_a,
            "cold_control_xsvc": len(cold),
            "warm": arm_b,
            "zerofp": arm_z,
        },
    )

    # ---- VERDICT (gradeable from raw) ---------------------------------------
    _rule("VERDICT — the §6/§8 two-engagement topology-learning metric (from raw)")
    edge_ok = (
        len(reaches) == 1 and reaches[0]["tech_a"] == A_ROLE and reaches[0]["tech_b"] == B_ROLE
    )
    a_ok = len(arm_a["cross_service_findings"]) == 1
    cold_ok = len(cold) == 0
    warm_seed_ok = len(warm) == 1 and warm[0].edge.topology_source == "catalog"
    warm_confirm_ok = len(arm_b["cross_service_findings"]) == 1
    zerofp_ok = len(arm_z["cross_service_findings"]) == 0 and any(
        ld["why_unconfirmed"] == "egress_confirmed_but_B_reach_not_observed"
        for ld in arm_z["research_leads"]
    )
    print(f"  (1) abstracted reaches edge written (both ends role/class): {edge_ok}")
    print(f"  (2) engagement A cross-service reach confirmed            : {a_ok}")
    print(f"  (3) cold-control B — ZERO cross-service hypotheses        : {cold_ok}")
    print(f"  (4) warm B — catalog-seeded cross-service hypothesis      : {warm_seed_ok}")
    print(f"  (5) warm B — the seeded chain CONFIRMED by the P6 gate    : {warm_confirm_ok}")
    print(f"  (6) zero-FP — non-co-located learned chain → research-lead: {zerofp_ok}")
    print(f"      relations before/after : {ART_DIR / 'technology_relations_before.json'} / after")
    print(f"      cold/warm edge dumps   : {ART_DIR / 'engagement_b_cold_edges.json'} / warm")
    ok = edge_ok and a_ok and cold_ok and warm_seed_ok and warm_confirm_ok and zerofp_ok
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
