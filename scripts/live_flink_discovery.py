"""Live-integration validation of the discovery engine's SECOND capability class.

The thesis test made live: against a LIVE Apache Flink 1.11.2 (Vulhub
``flink/CVE-2020-17519`` on :8081), the discovery engine finds and confirms the
``/jobmanager/logs/:filename`` path-traversal arbitrary file read end-to-end through
the REAL proof engine with a LIVE Anthropic exploit LLM — using a NEW ``FILE_READ``
catalog entry that reduces to the SAME P3 file-content oracle the black-box
``_test_lfi`` methodology already uses (zero new proof code), driven through the
SAME DiscoveryEngine → Orchestrator wiring → Exploit plan-union seam as the SSRF
class (GeoServer / Solr).

This is the multi-class metric made live: the file-read class needed a catalog
entry, a file-read source idiom (typed path param → ``new File`` sink, no
basename-strip guard), and one piece of oracle-sensitivity work — the path-segment
traversal carrier (Flink routes a literal ``/`` to a different handler, so the whole
``%252f``-encoded payload must ride the path segment verbatim as ONE opaque segment).

Sections (each prints raw evidence):

  1. SOURCE INGESTION + DISCOVERY (via the wired Orchestrator step) — ingest Flink's
     real ``JobManagerCustomLogHandler`` / ``JobManagerCustomLogHeaders`` /
     ``LogFileNamePathParameter`` → surface the ``filename`` path channel, the
     source-derived route ``/jobmanager/logs/:filename``, and the unguarded
     ``new File(logDir, filename)`` sink; show the ``_test_lfi`` ExploitTask the
     engine lowers to (PATH location, ``carry_path_segment_traversal_raw`` carrier).
  2. PROOF via the real seam — hand the hypothesis to the Exploit agent through the
     REAL message-content handoff (``discovery_tasks`` → ``run()`` →
     ``_parse_discovery_tasks`` → ``_merge_discovery_tasks``), run the real pipeline;
     the file read confirms IN-BAND via P3 (Flink returns /etc/passwd content), with
     the raw-auditable ConfirmationEvidence pair (leaked bytes + benign control).
  3. ZERO-FP — a reflection-in-error control endpoint (``/taskmanagers/:id``, which
     reflects the traversal string in a 500 stack trace but reads no file) yields no
     finding: reflection is not a file read.

Pre-flight: requires ANTHROPIC_API_KEY and a reachable Flink; if either is missing
it STOPS and reports (no substitute run). Flink's file read has NO stateful
precondition (unlike Solr's RemoteStreaming), so the driver only checks
reachability. ``TOOL_EXEC_MODE=local`` is set before importing clinkz so the
in-process aiohttp path is used (docker mode would curl inside the unrelated
clinkz-tools container).

Usage::

    python scripts/live_flink_discovery.py [--source <path>] [--host <host:port>]
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp.
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
log = logging.getLogger("flink_discovery")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO_ROOT / "tests" / "fixtures" / "flink_jobmanager_logs"


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_status(url: str, timeout: float = 10.0) -> int:
    """Small stdlib GET returning just the status (preflight reachability)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:  # pragma: no cover - preflight diagnostics
        return 0


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="Flink source fixture path")
    parser.add_argument("--host", default="http://localhost:8081", help="Flink host:port base")
    args = parser.parse_args()

    base_host = args.host.rstrip("/")

    # ---- Pre-flight: keys + reachability (STOP, no substitute, if either fails) --
    _rule("PRE-FLIGHT")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        from clinkz.config import settings  # triggers .env load

        if not getattr(settings, "anthropic_api_key", None):
            log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run.")
            return 2
    status = _http_status(f"{base_host}/")
    if status != 200:
        log.error("STOP: Flink not reachable at %s/ (status %s). No substitute.", base_host, status)
        return 2
    print(f"Flink / -> HTTP {status}; ANTHROPIC_API_KEY present: True")
    print(f"TOOL_EXEC_MODE={os.environ.get('TOOL_EXEC_MODE')}")

    # ---- 1. SOURCE INGESTION + DISCOVERY via the WIRED orchestrator step --------
    _rule("1. SOURCE INGESTION + DISCOVERY (wired Orchestrator step → ExploitTask)")
    from clinkz.discovery import DiscoveryEngine
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    scope = EngagementScope(
        name="Flink jobmanager/logs path-traversal file read (2nd capability class)",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
        source_dir=args.source,
        discovery_base_url=base_host,
    )

    disc = DiscoveryEngine().discover(args.source, ["Java", "Flink"], base_host)
    sm = disc.source_model
    print(
        f"ingested files={sm.files_ingested} coverage={sm.coverage_grade.value} "
        f"tech={sm.technologies}"
    )
    for ep in sm.entrypoints:
        print(
            f"  entrypoint: {ep.http_methods} route={ep.route!r} "
            f"handler={ep.handler_symbol} params={ep.params} path_params={ep.path_params}"
        )
    for cs in sm.call_sites:
        fname = cs.file.replace("\\", "/").split("/")[-1]
        print(
            f"  call-site : {cs.primitive_class.value} {cs.symbol}() "
            f"tainted_by={cs.tainted_by!r} guard={cs.guard_symbol!r} @{fname}:{cs.line}"
        )
    for d in disc.deltas:
        print(f"  Δ: {d.delta_grade.value} conf={d.delta_confidence} :: {d.intent_evidence}")
    for e in disc.edges:
        print(
            f"  reach: {e.soundness_grade.value} loc={e.channel_location.value} "
            f":: {e.path_evidence}"
        )

    # Black-box gap: the traversal injection point is a framework path parameter —
    # the log listing exposes only benign filenames, never the ../ traversal shape.
    print(
        "\nblack-box: the ':filename' traversal is a framework path param, not a "
        "crawlable link/form → gray-box source is what surfaces it as an injection point"
    )

    orch = OrchestratorAgent.__new__(OrchestratorAgent)
    orch._logger = logging.getLogger("orchestrator")
    orch._scope = scope
    tasks = orch._build_discovery_tasks(["Java", "Flink"], "localhost")
    for t in tasks:
        locs = {k: v.value for k, v in t.param_locations.items()}
        print(
            f"  → ExploitTask: {t.test_method} {t.endpoint_method} {t.endpoint_url}\n"
            f"      params={t.endpoint_params} locations={locs} carrier={t.carrier_constraints}"
        )
    if not tasks:
        log.error("STOP: discovery produced no exploit tasks.")
        return 3

    # ---- 2. PROOF via the real seam (message-content handoff) -------------------
    _rule("2. PROOF — hand tasks to Exploit via the real run() handoff, run the pipeline")
    from clinkz.agents.exploit import ExploitAgent, PageAnalysis
    from clinkz.agents.report import ReportAgent
    from clinkz.discovery.constants import CARRIER_PATH_TRAVERSAL
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scan import ParamLocation, ScanResult
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    db_path = REPO_ROOT / "outputs" / "flink_discovery.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    llm = get_llm_client("anthropic")

    async with StateStore(str(db_path)) as state:
        engagement_id = await state.create_engagement(
            "Flink jobmanager/logs file read (2nd capability class)", scope.model_dump(mode="json")
        )
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            # THE WIRED HANDOFF: discovery tasks ride in the message content exactly
            # as the Orchestrator passes them; run() parses + unions them. The
            # black-box scan is EMPTY, so discovery is the ONLY reason the traversal
            # is tested. This exercises _parse_discovery_tasks + _merge_discovery_tasks.
            result = await agent.run(
                {
                    "scan_result": ScanResult(target=base_host).model_dump(mode="json"),
                    "research_result": {"technologies": ["Java", "Flink"]},
                    "discovery_tasks": [t.model_dump(mode="json") for t in tasks],
                }
            )
            print(f"exploit summary: {result['summary']}")

            findings = await state.get_findings(engagement_id)
            lfi = [f for f in findings if "file inclusion" in str(f.get("title", "")).lower()]
            print(f"\nfindings in state: {len(findings)}  (file-read: {len(lfi)})")
            for f in findings:
                sev = str(f.get("severity", "?")).upper()
                print(f"  [{sev}] {f.get('title')}  status={f.get('status')}")
                for ev in (f.get("evidence") or [])[:12]:
                    print(f"      • {str(ev)[:190]}")

            # ---- 3. ZERO-FP control ------------------------------------------
            _rule("3. ZERO-FP — reflection-in-error control (/taskmanagers/:id)")
            # /taskmanagers/<traversal> reflects the ../ string in a 500 stack trace
            # but reads NO file — so a reflected payload must NOT confirm a file read.
            control_page = PageAnalysis(
                url=f"{base_host}/taskmanagers/:taskmanagerid",
                body="",
                status=200,
                input_params=["taskmanagerid"],
                param_locations={"taskmanagerid": ParamLocation.PATH},
                carrier_constraints=[CARRIER_PATH_TRAVERSAL],
            )
            control_findings = await agent._test_lfi(control_page)
            print(
                f"  reflection-in-error control /taskmanagers/:id → "
                f"{len(control_findings)} file-read findings (expect 0)"
            )

            # ---- Report --------------------------------------------------------
            _rule("REPORT + TRACE (raw artifact paths)")
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            rep = await report_agent.run(
                {"engagement_id": engagement_id, "engagement_name": "Flink file read"}
            )
        finally:
            trace.close()
            set_active_trace_writer(None)

        trace_path = REPO_ROOT / "outputs" / engagement_id / "trace.jsonl"
        print(f"engagement_id : {engagement_id}")
        print(f"report (json) : {rep.get('json_path')}")
        print(f"report (md)   : {rep.get('markdown_path')}")
        print(f"trace (jsonl) : {trace_path}")

        # ---- Verdict ---------------------------------------------------------
        _rule("VERDICT")
        confirmed = any(
            "file inclusion" in str(f.get("title", "")).lower()
            and str(f.get("status")) in ("confirmed", "new")
            for f in findings
        )
        has_evidence_pair = any(
            "confirming_excerpt" in str(ev).lower()
            for f in findings
            for ev in (f.get("evidence") or [])
        )
        zero_fp = len(control_findings) == 0
        print(f"  FILE READ CONFIRMED in-band (P3, genuine)    : {confirmed}")
        print(f"  raw-auditable ConfirmationEvidence in finding: {has_evidence_pair}")
        print(f"  zero false positives (reflection control)    : {zero_fp}")
        ok_all = confirmed and has_evidence_pair and zero_fp
        print(f"\n  RESULT: {'PASS' if ok_all else 'INCOMPLETE'}")
        return 0 if ok_all else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
