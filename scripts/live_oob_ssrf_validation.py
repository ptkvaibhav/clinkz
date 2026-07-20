"""Live isolation-validation of the P6 out-of-band confirmation primitive.

Isolates the ONE new variable — OOB confirmation — on a KNOWN-real SSRF we already
confirm in-band (GeoServer TestWfsPost, CVE-2021-40822), exactly as
``docs/p6-oob-design.md`` §P6.6 prescribes. It runs against a LIVE GeoServer and a
LIVE collaborator (no harness, no mocks; the exploit path is real), and proves from
raw evidence:

  A. IN-BAND unregressed — the same SSRF still confirms in-band (P3), so P6 is added
     without breaking the built primitive.
  B. P6 CONFIRM — pointing the SSRF ``url`` at the collaborator, a callback bearing
     the probe's unique nonce arrives and the SSRF confirms out-of-band, RAW-
     AUDITABLE (the outbound probe carrying the nonce AND the inbound callback
     bearing it are both in the finding).
  C. ZERO-FP — the SAME probe with the fetch guard's egress denied (carrier removed)
     produces no callback → no confirmation → no finding.
  D. EXFIL GUARDRAIL — the carrier structurally refuses to build an exfil payload.

Docker mode guarantees egress: the GeoServer container reaches the host collaborator
via ``host.docker.internal``. The nonce rides in the callback path (PATH shape), so
no wildcard-DNS delegation is needed for the HTTP leg (the DNS leg is exercised by
the collaborator's own health-check).

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present, GeoServer
reachable, and the collaborator starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_oob_ssrf_validation.py \
        [--base http://localhost:8080/geoserver] \
        [--collab-authority host.docker.internal:18080] [--collab-http-port 18080]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
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
    format="%(asctime)s %(name)-26s %(levelname)-5s %(message)s",
    datefmt="%H:%M:%S",
)
for _noisy in ("httpcore", "httpx", "aiohttp", "urllib3", "google", "anthropic", "openai"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
log = logging.getLogger("oob_ssrf_validation")

REPO_ROOT = Path(__file__).resolve().parent.parent


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_get_text(url: str, timeout: float = 10.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status, resp.read().decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover - preflight diagnostics
        return 0, f"<error: {exc}>"


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="http://localhost:8080/geoserver", help="GeoServer base")
    parser.add_argument(
        "--collab-authority",
        default="host.docker.internal:18080",
        help="callback authority the target connects back to (PATH shape)",
    )
    parser.add_argument("--collab-http-port", type=int, default=18080)
    parser.add_argument("--collab-dns-port", type=int, default=15353)
    parser.add_argument("--wait-window", type=float, default=25.0)
    args = parser.parse_args()

    base_url = args.base.rstrip("/")
    twp_url = f"{base_url}/TestWfsPost"

    # ---- PRE-FLIGHT ----------------------------------------------------------
    _rule("PRE-FLIGHT (keys + GeoServer + collaborator health-check)")
    from clinkz.config import settings

    if not (os.environ.get("ANTHROPIC_API_KEY") or getattr(settings, "anthropic_api_key", None)):
        log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run.")
        return 2
    status, _ = _http_get_text(f"{base_url}/web/")
    if status != 200:
        log.error(
            "STOP: GeoServer not reachable at %s/web/ (status %s). No substitute.", base_url, status
        )
        return 2
    twp_status, _ = _http_get_text(twp_url)
    print(f"GeoServer /web/ -> HTTP {status}; GET {twp_url} -> HTTP {twp_status}")
    print(f"ANTHROPIC_API_KEY present: True; TOOL_EXEC_MODE={os.environ.get('TOOL_EXEC_MODE')}")

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
        log.error(
            "STOP: OOB collaborator health-check failed (DNS+HTTP self-round-trip). No substitute."
        )
        await collab.stop()
        return 2
    print(
        f"OOB collaborator healthy: zone={collab.zone} shape={collab.callback_shape.value} "
        f"http_port={args.collab_http_port} dns_port={args.collab_dns_port}"
    )

    # ---- D. EXFIL GUARDRAIL (structural — no live target needed) --------------
    _rule("D. EXFIL GUARDRAIL — the carrier refuses to build an exfil payload")
    from clinkz.oob.templates import mint_nonce

    guardrail_ok = True
    for exfil in ("${env:AWS_SECRET_ACCESS_KEY}", "../../etc/passwd", "victim.internal", "a b"):
        try:
            build_oob_payload(
                OOBTemplateId.BLIND_SSRF_URL, exfil, collab.zone, shape=CallbackShape.PATH
            )
            print(f"  FAIL: carrier built a payload from exfil attempt {exfil!r}")
            guardrail_ok = False
        except ValueError:
            print(f"  refused exfil attempt {exfil!r} (ValueError) ✓")
    _good = mint_nonce()
    _url = build_oob_payload(
        OOBTemplateId.BLIND_SSRF_URL, _good, collab.zone, shape=CallbackShape.PATH
    )
    print(f"  carrier output for a real nonce: {_url}  (host is fixed collaborator authority)")

    # ---- Build the real proof engine + the GeoServer page --------------------
    from clinkz.agents.exploit import ExploitAgent
    from clinkz.agents.report import ReportAgent
    from clinkz.discovery.constants import CARRIER_ALIGN_HOST
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scan import ParamLocation
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    scope = EngagementScope(
        name="P6 OOB isolation — GeoServer SSRF",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
    )
    db_path = REPO_ROOT / "outputs" / "oob_ssrf_validation.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    llm = get_llm_client("anthropic")

    inband_confirmed = False
    oob_confirmed = False
    oob_evidence = None
    zero_fp = False
    async with StateStore(str(db_path)) as state:
        engagement_id = await state.create_engagement(
            "P6 OOB isolation — GeoServer SSRF", scope.model_dump(mode="json")
        )
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            agent._collaborator = collab

            # The TestWfsPost page carries the Host-alignment carrier so the fetch
            # guard is satisfied (CVE-2021-40822). ``url`` rides FORM_BODY.
            page = await agent._fetch_page(
                twp_url,
                ["url"],
                method="POST",
                content_type="application/x-www-form-urlencoded",
                param_locations={"url": ParamLocation.FORM_BODY},
                carrier_constraints=[CARRIER_ALIGN_HOST],
            )

            # ---- A. IN-BAND unregressed --------------------------------------
            _rule("A. IN-BAND SSRF unregressed (P3, the built primitive)")
            inband_findings = await agent._test_ssrf(page)
            inband_confirmed = any("ssrf" in str(f.title).lower() for f in inband_findings)
            for f in inband_findings:
                print(f"  [{f.severity.value.upper()}] {f.title}")
                for ev in f.evidence[:5]:
                    print(f"      • {str(ev)[:150]}")
                await agent._persist_finding(f)
            print(f"  in-band SSRF findings: {len(inband_findings)} (confirmed={inband_confirmed})")

            # ---- B. P6 CONFIRM via the OOB callback --------------------------
            _rule("B. P6 CONFIRM — point SSRF url at the collaborator, reap the callback")
            oob_confirmed, oob_evidence, note = await agent._ssrf_oob_confirm(page, "url")
            print(f"  confirmed_out_of_band={oob_confirmed}  note={note}")
            if oob_evidence is not None:
                print("  RAW-AUDITABLE P6 evidence pair:")
                print(f"    primitive         : {oob_evidence.primitive}")
                print(f"    outbound_probe    : {oob_evidence.outbound_probe}")
                print(f"    callback_nonce    : {oob_evidence.confirming_marker}")
                print(f"    inbound_callback  : {oob_evidence.confirming_excerpt}")
                print(f"    control           : {oob_evidence.control_label}")
                print(f"    control_bore_nonce: {oob_evidence.control_confirms} (must be False)")

            # ---- C. ZERO-FP — deny egress (drop the carrier) → no callback ----
            _rule("C. ZERO-FP — same probe, fetch-guard egress denied (no carrier) → no callback")
            bare_page = await agent._fetch_page(
                twp_url,
                ["url"],
                method="POST",
                content_type="application/x-www-form-urlencoded",
                param_locations={"url": ParamLocation.FORM_BODY},
            )
            ctrl_confirmed, _ctrl_ev, ctrl_note = await agent._ssrf_oob_confirm(bare_page, "url")
            zero_fp = not ctrl_confirmed
            print(
                f"  control confirmed_out_of_band={ctrl_confirmed} (expect False)  note={ctrl_note}"
            )

            # Persist the OOB-confirmed finding so report.json + trace.jsonl carry
            # the raw P6 pair. GeoServer reflects in-band (so the normal blind
            # branch never fires here); this emits the BLIND_OOB_CONFIRMED finding
            # from the section-B evidence via the real phase-6 emitter/trace.
            if oob_confirmed and oob_evidence is not None:
                from clinkz.models.methodology import (
                    SSRFExploitationType,
                    SSRFMethodologyResult,
                )

                oob_result = SSRFMethodologyResult(
                    candidate_param="url",
                    exploitation_type=SSRFExploitationType.BLIND_OOB_CONFIRMED,
                    synthesized_payload=oob_evidence.confirming_target,
                    indicator_type="oob_callback",
                    indicator_observed=note,
                    confirmation_evidence=oob_evidence,
                    verified=True,
                    verification_strength="verified-oob",
                    phases_completed=6,
                )
                oob_result.capability.fetch_confirmed = True
                oob_finding = agent._ssrf_phase6_emit(twp_url, "url", oob_result)
                await agent._persist_finding(oob_finding)

            # ---- REPORT ------------------------------------------------------
            _rule("REPORT + TRACE (raw artifact paths)")
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            rep = await report_agent.run(
                {"engagement_id": engagement_id, "engagement_name": "P6 OOB isolation"}
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
    oob_pair_ok = bool(
        oob_evidence
        and oob_evidence.outbound_probe
        and oob_evidence.confirming_marker
        and oob_evidence.confirming_marker in oob_evidence.confirming_excerpt
        and oob_evidence.control_confirms is False
    )
    print(f"  A. in-band SSRF unregressed (P3)             : {inband_confirmed}")
    print(f"  B. P6 confirm via callback (raw-auditable)   : {oob_confirmed and oob_pair_ok}")
    print(f"  C. zero-FP (egress denied → no callback)     : {zero_fp}")
    print(f"  D. exfil guardrail holds (structural)        : {guardrail_ok}")
    ok = inband_confirmed and oob_confirmed and oob_pair_ok and zero_fp and guardrail_ok
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
