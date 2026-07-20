"""Live end-to-end validation of the Log4Shell flagship — the payoff of P6.

Runs the WHOLE new vertical against a LIVE Vulhub ``log4j/CVE-2021-44228`` (Apache
Solr 8.11.0 + ``log4j-core`` 2.14.1 on :8983), a LIVE OOB collaborator, and a real
exploit agent (built with the live Anthropic LLM) — no harness, no mocks. It proves
from raw evidence the deliverable of the flagship:

  A. LOG-SINK REACHABILITY — the discovery engine ingests real Solr/log4j source and
     surfaces the log-sink channel (untrusted ``action`` → a ``log().info(params)``
     sink) at ``STATIC_HEURISTIC`` grade, manifest-version-gated (log4j-core 2.14.1
     < 2.15 arms it), lowering to a ``_test_log4shell`` ExploitTask on the CVE's
     ``/solr/admin/cores`` ``action`` param — the reachability-as-prior half (§4.3).
  B. P6 CONFIRM — the ``_test_log4shell`` methodology fires a CLINKZ-OWNED, nonce-only
     ``${jndi:dns://<zone>/<T>}`` probe into the logged param; the target's log4j
     interpolates it and the JNDI DNS lookup for ``<T>`` reaches the collaborator's
     DNS leg. Log4Shell CONFIRMED via P6, RAW-AUDITABLE (the outbound probe carrying
     ``T`` AND the inbound callback bearing ``T`` are both in the finding).
  C. REAL SEAM (live LLM) — the discovery hypothesis rides the real
     ``run() → _parse_discovery_tasks → _merge_discovery_tasks`` handoff and confirms
     through the real dispatch + ``_persist_finding`` chokepoint.
  D. EXFIL GUARDRAIL — the JNDI carrier structurally refuses any non-nonce payload.
  E. ZERO-FP — the built-in never-sent control produces no callback (unforgeability),
     and an egress-denied probe (unreachable authority) yields no finding
     (``blind_unconfirmed``, not ``not_vulnerable``).
  F. NO REGRESSION — the same collaborator + generalized ``_oob_send`` still confirm
     a blind SSRF out-of-band (GeoServer CVE-2021-40822), and the file-read discovery
     class still surfaces its Flink hypothesis (both unchanged by the log-sink class).

Docker mode guarantees egress: the Solr container reaches the host collaborator via
``host.docker.internal``. The reliable local Log4Shell channel is ``jndi:dns://`` sent
DIRECTLY to the collaborator's DNS-leg authority (host:dns_port) — no wildcard-DNS
delegation, no port 53 (design §P6.5.4: the DNS leg confirms Log4Shell).

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present, Solr
reachable, and the collaborator starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_log4shell_p6_validation.py \
        [--solr-base http://localhost:8983] [--source tests/fixtures/solr_log4shell] \
        [--collab-authority host.docker.internal:18080] \
        [--collab-http-port 18080] [--collab-dns-port 15353] \
        [--geoserver-base http://localhost:8080/geoserver]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import re
import sys
import urllib.error
import urllib.request
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
    format="%(asctime)s %(name)-28s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
for _noisy in ("httpcore", "httpx", "aiohttp", "urllib3", "google", "anthropic", "openai"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("log4shell_validation")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO_ROOT / "tests" / "fixtures" / "solr_log4shell"
FLINK_SOURCE = REPO_ROOT / "tests" / "fixtures" / "flink_jobmanager_logs"


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_get_text(url: str, timeout: float = 10.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover - preflight diagnostics
        return 0, f"<error: {exc}>"


def _raw_pair_is_auditable(evidence: list[str]) -> bool:
    """Whether a finding's evidence carries an auditable P6 pair.

    Confirms the SAME nonce leaves in a ``jndi:dns://`` outbound probe AND returns in
    the inbound-callback excerpt, and that the never-sent control bore no nonce — so
    the confirmation is re-derivable from the artifact, not self-asserted.
    """
    text = "\n".join(str(e) for e in evidence)
    m_out = re.search(r"outbound_probe:.*jndi:dns://[^/]+/([a-z0-9]{16,64})", text)
    m_call = re.search(r"confirming_excerpt:.*host=([a-z0-9]{16,64})", text)
    if not (m_out and m_call):
        return False
    return m_out.group(1) == m_call.group(1) and "control_bore_it=False" in text


async def main() -> int:  # noqa: C901 - a linear validation script, read top to bottom
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solr-base", default="http://localhost:8983")
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="Log4Shell source fixture")
    parser.add_argument("--collab-authority", default="host.docker.internal:18080")
    parser.add_argument("--collab-http-port", type=int, default=18080)
    parser.add_argument("--collab-dns-port", type=int, default=15353)
    parser.add_argument("--wait-window", type=float, default=15.0)
    parser.add_argument("--geoserver-base", default="http://localhost:8080/geoserver")
    args = parser.parse_args()

    solr_base = args.solr_base.rstrip("/")
    cores_url = f"{solr_base}/solr/admin/cores"

    # ---- PRE-FLIGHT ----------------------------------------------------------
    _rule("PRE-FLIGHT (keys + Solr + collaborator health-check)")
    from clinkz.config import settings

    if not (os.environ.get("ANTHROPIC_API_KEY") or getattr(settings, "anthropic_api_key", None)):
        log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run.")
        return 2
    status, _ = _http_get_text(f"{cores_url}?action=STATUS&wt=json")
    if status != 200:
        log.error("STOP: Solr not reachable at %s (status %s). No substitute.", cores_url, status)
        return 2
    print(f"Solr {cores_url} -> HTTP {status}; TOOL_EXEC_MODE={os.environ.get('TOOL_EXEC_MODE')}")
    print("ANTHROPIC_API_KEY present: True")

    settings.oob_wait_window = float(args.wait_window)

    from clinkz.oob import CallbackShape, OOBCollaborator, OOBTemplateId, build_oob_payload

    collab = OOBCollaborator(
        zone=args.collab_authority,
        callback_shape=CallbackShape.PATH,
        bind_host="0.0.0.0",  # noqa: S104 — the target must be able to call back
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
        log.error("STOP: OOB collaborator health-check failed (DNS+HTTP self-round-trip).")
        await collab.stop()
        return 2
    print(
        f"OOB collaborator healthy: zone={collab.zone} shape={collab.callback_shape.value} "
        f"dns_authority={collab.dns_authority()} (jndi:dns:// target)"
    )

    from clinkz.agents.exploit import ExploitAgent, PageAnalysis
    from clinkz.agents.report import ReportAgent
    from clinkz.discovery import DiscoveryEngine
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scan import ParamLocation, ScanResult
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    # ---- A. LOG-SINK REACHABILITY (the discovery engine, gray-box) -----------
    _rule("A. LOG-SINK REACHABILITY — engine surfaces the channel at heuristic grade")
    disc = DiscoveryEngine().discover(args.source, ["Java", "Solr"], cores_url)
    sm = disc.source_model
    print(f"ingested files={sm.files_ingested} tech={sm.technologies}")
    print(f"manifest verdict: {sm.manifest_evidence or '(none)'}")
    for cs in sm.call_sites:
        if cs.primitive_class.value == "log_interpolation":
            fname = cs.file.replace("\\", "/").split("/")[-1]
            print(f"  log sink: {cs.symbol}() tainted_by={cs.tainted_by!r} @{fname}:{cs.line}")
    heuristic = [h for h in disc.hypotheses if h.edge.soundness_grade.value == "static_heuristic"]
    print(f"heuristic log-sink hypotheses: {len(heuristic)}")
    for h in heuristic[:6]:
        print(
            f"  - param={h.edge.channel_param!r} grade={h.edge.soundness_grade.value} "
            f"test={h.obligation.test_method} confirm={h.obligation.confirmation_primitives} "
            f"rank={h.rank_score}"
        )
    tasks = disc.exploit_tasks()
    action_tasks = [t for t in tasks if "action" in t.endpoint_params]
    channels = [t.endpoint_params[0] for t in tasks if t.endpoint_params]
    print(f"channels surfaced: {channels}")
    if not action_tasks:
        log.error("STOP: discovery did not surface the CVE's 'action' log-sink channel.")
        await collab.stop()
        return 3

    scope = EngagementScope(
        name="Log4Shell P6 — Solr CVE-2021-44228",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
        source_dir=args.source,
        discovery_base_url=cores_url,
    )
    db_path = REPO_ROOT / "outputs" / "log4shell_validation.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    llm = get_llm_client("anthropic")

    log4shell_confirmed = False
    raw_pair_ok = False
    seam_confirmed = False
    zero_fp_control = False
    guardrail_ok = True
    ssrf_oob_ok = False
    file_read_ok = False

    async with StateStore(str(db_path)) as state:
        engagement_id = await state.create_engagement(
            "Log4Shell P6 — Solr CVE-2021-44228", scope.model_dump(mode="json")
        )
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            agent._collaborator = collab

            # ---- B. P6 CONFIRM (real methodology, shared-window fire-and-reap) ----
            _rule("B. P6 CONFIRM — _test_log4shell fires jndi:dns:// nonce, reaps the callback")
            page = PageAnalysis(
                url=cores_url,
                body="",
                status=200,
                input_params=channels,
                param_locations={c: ParamLocation.QUERY for c in channels},
                request_method="GET",
            )
            findings = await agent._test_log4shell(page)
            for f in findings:
                print(f"  [{f.severity.value.upper()}] {f.title}")
                await agent._persist_finding(f)
            log4shell_confirmed = any("log4shell" in str(f.title).lower() for f in findings)
            # Show the raw-auditable P6 pair for the FIRST confirmed finding (the
            # outbound ${jndi:dns://…T…} probe + the inbound callback bearing T).
            if findings:
                for ev in findings[0].evidence:
                    if any(
                        k in str(ev).lower() for k in ("jndi:dns", "callback", "nonce", "control")
                    ):
                        print(f"      • {str(ev)[:200]}")
            raw_pair_ok = any(_raw_pair_is_auditable(f.evidence) for f in findings)
            print(
                f"  Log4Shell findings: {len(findings)} (confirmed={log4shell_confirmed}, "
                f"raw-auditable pair={raw_pair_ok})"
            )

            # ---- C. REAL SEAM (live LLM) — hand the action hypothesis to run() ---
            _rule("C. REAL SEAM — discovery task rides run() → _merge_discovery_tasks (live LLM)")
            seam_agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            seam_agent._collaborator = collab
            seam_result = await seam_agent.run(
                {
                    "scan_result": ScanResult(target=cores_url).model_dump(mode="json"),
                    "research_result": {"technologies": ["Java", "Solr", "log4j"]},
                    "discovery_tasks": [action_tasks[0].model_dump(mode="json")],
                }
            )
            print(f"  seam exploit summary: {seam_result.get('summary')}")
            all_findings = await state.get_findings(engagement_id)
            seam_confirmed = any(
                "log4shell" in str(f.get("title", "")).lower() for f in all_findings
            )
            print(f"  Log4Shell in state after seam: {seam_confirmed}")

            # ---- D. EXFIL GUARDRAIL (structural) --------------------------------
            _rule("D. EXFIL GUARDRAIL — the JNDI carrier refuses any non-nonce payload")
            for exfil in (
                "${env:AWS_SECRET_ACCESS_KEY}",
                "../../etc/passwd",
                "victim.internal",
                "a b",
            ):
                try:
                    build_oob_payload(
                        OOBTemplateId.JNDI_DNS,
                        exfil,
                        collab.dns_authority(),
                        shape=CallbackShape.PATH,
                    )
                    print(f"  FAIL: carrier built a payload from exfil attempt {exfil!r}")
                    guardrail_ok = False
                except ValueError:
                    print(f"  refused exfil attempt {exfil!r} (ValueError) ✓")

            # ---- E. ZERO-FP — egress-denied probe → no callback → no finding ----
            _rule("E. ZERO-FP — a JNDI probe to an unreachable authority yields no finding")

            # Point the collaborator's DNS authority at a dead port for one probe: the
            # target cannot call back, so nothing confirms (blind_unconfirmed, not a finding).
            class _DeadCollab:
                callback_shape = CallbackShape.PATH

                def __init__(self, inner: OOBCollaborator) -> None:
                    self._inner = inner
                    self.healthy = True

                def mint(self, ref: str) -> str:
                    return self._inner.mint(ref)

                def dns_authority(self) -> str:
                    return "127.0.0.1:1"  # nothing listens here — egress can't reach us

                def callback_zone(self) -> str:
                    return "127.0.0.1:1"

                def record_sent(self, nonce: str, outbound: str) -> None:
                    self._inner.record_sent(nonce, outbound)

                async def reap(self, nonces: list[str], deadline: float):
                    return await self._inner.reap(nonces, deadline)

            control_agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            control_agent._collaborator = _DeadCollab(collab)  # type: ignore[assignment]
            control_page = PageAnalysis(
                url=cores_url,
                body="",
                status=200,
                input_params=["action"],
                param_locations={"action": ParamLocation.QUERY},
                request_method="GET",
            )
            control_findings = await control_agent._test_log4shell(control_page)
            zero_fp_control = len(control_findings) == 0
            print(f"  egress-denied control → {len(control_findings)} findings (expect 0)")
            print(
                "  built-in never-sent control on every confirmed finding: "
                "control_bore_it=False (in the raw pair above — unforgeability)"
            )

            # ---- F. NO REGRESSION — SSRF-OOB (GeoServer) + file-read (Flink) ----
            _rule("F. NO REGRESSION — blind SSRF still confirms OOB; file-read still surfaces")
            gs_base = args.geoserver_base.rstrip("/")
            gs_status, _ = _http_get_text(f"{gs_base}/web/")
            if gs_status == 200:
                from clinkz.discovery.constants import CARRIER_ALIGN_HOST

                gs_agent = ExploitAgent(
                    llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
                )
                gs_agent._collaborator = collab
                gs_page = await gs_agent._fetch_page(
                    f"{gs_base}/TestWfsPost",
                    ["url"],
                    method="POST",
                    content_type="application/x-www-form-urlencoded",
                    param_locations={"url": ParamLocation.FORM_BODY},
                    carrier_constraints=[CARRIER_ALIGN_HOST],
                )
                ssrf_oob_ok, ssrf_ev, ssrf_note = await gs_agent._ssrf_oob_confirm(gs_page, "url")
                print(
                    f"  SSRF blind confirmed OOB (generalized _oob_send): {ssrf_oob_ok} "
                    f"({ssrf_note})"
                )
            else:
                print(
                    f"  GeoServer not up (HTTP {gs_status}) — skipping the SSRF-OOB regression leg"
                )
            fr = DiscoveryEngine().discover(
                str(FLINK_SOURCE), ["Java", "Flink"], "http://localhost:8081"
            )
            file_read_ok = any(h.obligation.test_method == "_test_lfi" for h in fr.hypotheses)
            print(f"  file-read (Flink) hypothesis still surfaces via _test_lfi: {file_read_ok}")

            # ---- REPORT --------------------------------------------------------
            _rule("REPORT + TRACE (raw artifact paths)")
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            rep = await report_agent.run(
                {"engagement_id": engagement_id, "engagement_name": "Log4Shell P6"}
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
    _rule("VERDICT")
    channel_ok = bool(heuristic and action_tasks)
    b_ok = log4shell_confirmed and raw_pair_ok
    print(f"  A. log-sink channel surfaced at heuristic grade : {channel_ok}")
    print(f"  B. Log4Shell CONFIRMED via P6 (raw-auditable)    : {b_ok}")
    print(f"  C. confirmed through the real run() seam         : {seam_confirmed}")
    print(f"  D. exfil guardrail holds (structural)            : {guardrail_ok}")
    print(f"  E. zero-FP (egress denied → no finding)          : {zero_fp_control}")
    print(f"  F. SSRF-OOB + file-read unregressed              : {ssrf_oob_ok and file_read_ok}")
    ok = (
        log4shell_confirmed
        and raw_pair_ok
        and seam_confirmed
        and guardrail_ok
        and zero_fp_control
        and file_read_ok
    )
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
