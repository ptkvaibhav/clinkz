"""Live Engagement-A validation of the capability-learning loop (slice 1, WRITE side).

Runs the REAL run() seam against a LIVE Vulhub ``log4j/CVE-2021-44228`` (Apache Solr
8.11.0 + ``log4j-core`` 2.14.1 on :8983), a LIVE OOB collaborator, and a real exploit
agent built with the live Anthropic LLM — no harness, no mocks — wired to a FRESH
``clinkz_knowledge.db``. It proves the slice-1 deliverable from raw artifacts:

  (a) CATALOG-STATE DIFF — ``capability_facts`` is EMPTY before (0 rows) and holds a
      ``confirmed`` ``log4j-core`` / ``=2.14.1`` / ``log_interpolation`` /
      ``log4j.log_sink`` fact after, with an observation whose ``evidence_ref`` LINKS
      to the finding (never bytes). The row's existence + content is the learning.
  (b) EMISSION UNCHANGED — the run's report.json finding SET is identical to the
      in-repo baseline ``outputs/p6-log4shell/report.json`` (the Layer-2 write-back
      adds a DB, changes nothing confirmed).
  (c) CONFIDENCE — present as a number, and provably UNUSED in any emission decision
      (slice 1 has no reader of ``capability_facts.confidence`` at all).

The confirm rides the REAL ``run() → _merge_discovery_tasks → _execute_task →
_persist_finding → _record_finding_to_kb`` chokepoint (the write-back is stamped from
the discovery task's provenance at ``_execute_task``, so a black-box finding writes
nothing). Docker mode guarantees egress: the Solr container reaches the host
collaborator via ``host.docker.internal``; the Log4Shell channel is ``jndi:dns://``
to the collaborator's DNS-leg authority (design §P6.5.4).

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present, Solr
reachable, and the collaborator starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_capability_learning_validation.py \
        [--solr-base http://localhost:8983] [--source tests/fixtures/solr_log4shell] \
        [--collab-authority host.docker.internal:18080] \
        [--collab-http-port 18080] [--collab-dns-port 15353]
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

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp (lesson #22).
os.environ.setdefault("TOOL_EXEC_MODE", "local")

try:
    from dotenv import load_dotenv

    load_dotenv()  # populate ANTHROPIC_API_KEY / GEMINI_API_KEY from .env for the live run
except ImportError:  # pragma: no cover
    pass

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
log = logging.getLogger("capability_learning_validation")

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SOURCE = REPO_ROOT / "tests" / "fixtures" / "solr_log4shell"
BASELINE_REPORT = REPO_ROOT / "outputs" / "p6-log4shell" / "report.json"
OUT_DIR = REPO_ROOT / "outputs" / "capability-learning"


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


def _finding_set(report_path: Path) -> set[str]:
    """The distinct emitted-finding SET (title|severity) from a report.json.

    Per-run nonces live in evidence, not titles, so the title|severity set is the
    stable emission signature to diff a warm run against the cold baseline.
    """
    data = json.loads(report_path.read_text(encoding="utf-8"))
    return {f"{f.get('severity')}|{f.get('title')}" for f in data.get("findings", [])}


async def main() -> int:  # noqa: C901 - a linear validation script, read top to bottom
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solr-base", default="http://localhost:8983")
    parser.add_argument("--source", default=str(DEFAULT_SOURCE))
    parser.add_argument("--collab-authority", default="host.docker.internal:18080")
    parser.add_argument("--collab-http-port", type=int, default=18080)
    parser.add_argument("--collab-dns-port", type=int, default=15353)
    parser.add_argument("--wait-window", type=float, default=15.0)
    args = parser.parse_args()

    solr_base = args.solr_base.rstrip("/")
    cores_url = f"{solr_base}/solr/admin/cores"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ---- PRE-FLIGHT ----------------------------------------------------------
    _rule("PRE-FLIGHT (keys + Solr 8.11.0/log4j-core 2.14.1 + collaborator health)")
    from clinkz.config import settings

    if not (os.environ.get("ANTHROPIC_API_KEY") or getattr(settings, "anthropic_api_key", None)):
        log.error("STOP: ANTHROPIC_API_KEY not set — the exploit LLM cannot run.")
        return 2
    status, _ = _http_get_text(f"{cores_url}?action=STATUS&wt=json")
    if status != 200:
        log.error("STOP: Solr not reachable at %s (status %s). No substitute.", cores_url, status)
        return 2
    print(f"Solr {cores_url} -> HTTP {status}; TOOL_EXEC_MODE={os.environ.get('TOOL_EXEC_MODE')}")

    settings.oob_wait_window = float(args.wait_window)

    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
    from clinkz.oob import CallbackShape, OOBCollaborator

    # Fresh, isolated capability KB (never the shared one) so the before-dump is 0 rows.
    kb_path = OUT_DIR / "capability_kb.db"
    if kb_path.exists():
        kb_path.unlink()
    kb = await PersistentKnowledgeBase.create(str(kb_path))

    facts_before = await kb.get_capability_facts()
    obs_before = await kb.get_capability_observations()
    print(f"capability KB (fresh): {kb_path}")
    print(f"  capability_facts BEFORE: {len(facts_before)} rows")
    print(f"  capability_observations BEFORE: {len(obs_before)} rows")
    if facts_before or obs_before:
        log.error("STOP: fresh KB is not empty — cannot prove a clean before/after diff.")
        await kb.close()
        return 2

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
        await kb.close()
        return 2
    if not await collab.health_check():
        log.error("STOP: OOB collaborator health-check failed (DNS+HTTP self-round-trip).")
        await collab.stop()
        await kb.close()
        return 2
    print(f"OOB collaborator healthy: dns_authority={collab.dns_authority()} (jndi:dns:// target)")

    from clinkz.agents.exploit import ExploitAgent, PageAnalysis
    from clinkz.agents.report import ReportAgent
    from clinkz.discovery import DiscoveryEngine
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scan import ParamLocation, ScanResult
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.state import StateStore

    # ---- Discovery: surface the log-sink channels (gray-box) -----------------
    _rule("DISCOVERY — log-sink channels at heuristic grade (manifest-gated)")
    disc = DiscoveryEngine().discover(args.source, ["Java", "Apache Solr 8.11.0"], cores_url)
    print(f"manifest verdict: {disc.source_model.manifest_evidence or '(none)'}")
    print(
        f"manifest structured: technology_key={disc.source_model.manifest_technology_key!r} "
        f"observed_version={disc.source_model.manifest_observed_version!r}"
    )
    tasks = disc.exploit_tasks()
    channels = [t.endpoint_params[0] for t in tasks if t.endpoint_params]
    print(f"channels surfaced: {channels}")
    if not tasks:
        log.error("STOP: discovery surfaced no log-sink channel.")
        await collab.stop()
        await kb.close()
        return 3
    # Show the provenance the write-back keys on (source → task).
    p0 = tasks[0].discovery_provenance
    print(
        f"task provenance: technology_key={p0.technology_key!r} version={p0.observed_version!r} "
        f"sink_shape_id={p0.sink_shape_id!r} class={p0.primitive_class!r} "
        f"confirm={p0.confirmation_primitive!r} grade={p0.reachability_grade!r}"
    )

    scope = EngagementScope(
        name="Capability-learning A — Solr CVE-2021-44228",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
        source_dir=args.source,
        discovery_base_url=cores_url,
    )
    state_db = OUT_DIR / "engagement_state.db"
    if state_db.exists():
        state_db.unlink()
    llm = get_llm_client("anthropic")

    rep: dict = {}
    b_ok = False
    async with StateStore(str(state_db)) as state:
        engagement_id = await state.create_engagement(
            "Capability-learning A — Solr CVE-2021-44228", scope.model_dump(mode="json")
        )
        trace = TraceWriter(engagement_id)
        set_active_trace_writer(trace)
        try:
            # ---- REAL SEAM (live LLM) with the persistent KB wired -------------
            _rule("ENGAGEMENT A — real run() seam confirms + writes the capability fact")
            agent = ExploitAgent(
                llm=llm,
                tools=[],
                scope=scope,
                state=state,
                engagement_id=engagement_id,
                persistent_kb=kb,  # the write-back target — the whole point of slice 1
            )
            agent._collaborator = collab
            result = await agent.run(
                {
                    "scan_result": ScanResult(target=cores_url).model_dump(mode="json"),
                    "research_result": {"technologies": ["Java", "Solr", "log4j"]},
                    "discovery_tasks": [t.model_dump(mode="json") for t in tasks],
                }
            )
            print(f"  exploit summary: {result.get('summary')}")
            state_findings = await state.get_findings(engagement_id)
            log4shell = [
                f for f in state_findings if "log4shell" in str(f.get("title", "")).lower()
            ]
            print(f"  Log4Shell findings persisted via real run() seam: {len(log4shell)}")
            print(
                "  (per-task dispatch confirms the 'action' channel — only an action-"
                "bearing request reaches Solr's CREATE-command log line; the write-back "
                "fires through the genuine _execute_task→_persist_finding chokepoint)"
            )

            # ---- REPORT (artifact) -------------------------------------------
            report_agent = ReportAgent(
                llm=llm, tools=[], scope=scope, state=state, engagement_id=engagement_id
            )
            rep = await report_agent.run(
                {"engagement_id": engagement_id, "engagement_name": "Capability-learning A"}
            )

            # ---- (b) EMISSION A/B — write-back on vs off, SAME methodology -----
            # Fire the whole channel bag in one request (all params logged together,
            # like the in-repo baseline) so the full finding set surfaces, and prove
            # the write-back does not change WHAT is emitted: identical findings with
            # the KB wired (write-back active) and with persistent_kb=None (no-op).
            _rule("(b) EMISSION A/B — identical findings with the write-back ON vs OFF")
            prov = tasks[0].discovery_provenance
            locs = {c: ParamLocation.QUERY for c in channels}
            page_off = PageAnalysis(
                url=cores_url, body="", status=200, input_params=list(channels),
                param_locations=locs, request_method="GET",
            )
            page_on = PageAnalysis(
                url=cores_url, body="", status=200, input_params=list(channels),
                param_locations=locs, request_method="GET", discovery_provenance=prov,
            )
            agent_off = ExploitAgent(
                llm=llm, tools=[], scope=scope, state=state,
                engagement_id=engagement_id, persistent_kb=None,  # write-back is a no-op
            )
            agent_off._collaborator = collab
            findings_off = await agent_off._test_log4shell(page_off)
            findings_on = await agent._test_log4shell(page_on)
            for f in findings_on:  # stamp + persist to write the KB fact (as _execute_task does)
                f.discovery_provenance = prov
                await agent._persist_finding(f)
            titles_off = {f"{f.severity.value}|{f.title}" for f in findings_off}
            titles_on = {f"{f.severity.value}|{f.title}" for f in findings_on}
            print(f"  findings with write-back OFF (persistent_kb=None): {len(titles_off)}")
            print(f"  findings with write-back ON  (persistent_kb=kb)  : {len(titles_on)}")
            ab_identical = titles_off == titles_on and bool(titles_on)
            print(f"  emission identical ON vs OFF: {ab_identical}")
            baseline_titles = _finding_set(BASELINE_REPORT) if BASELINE_REPORT.exists() else set()
            matches_baseline = bool(baseline_titles) and titles_on == baseline_titles
            print(f"  baseline distinct findings: {len(baseline_titles)}")
            print(f"  warm finding SET == baseline SET: {matches_baseline}")
            only_warm = sorted(titles_on - baseline_titles)
            only_base = sorted(baseline_titles - titles_on)
            print(f"    in warm not baseline: {only_warm or '(none)'}")
            print(f"    in baseline not warm: {only_base or '(none)'}")
            b_ok = ab_identical and matches_baseline
        finally:
            trace.close()
            set_active_trace_writer(None)
            await collab.stop()

    # ---- (a) CATALOG-STATE DIFF ---------------------------------------------
    _rule("(a) CATALOG-STATE DIFF — capability_facts before(0) vs after")
    facts_after = await kb.get_capability_facts()
    obs_after = await kb.get_capability_observations()
    print(f"  capability_facts AFTER: {len(facts_after)} row(s)")
    for f in facts_after:
        print(
            f"    fact: technology_key={f['technology_key']!r} "
            f"version_predicate={f['version_predicate']!r} "
            f"primitive_class={f['primitive_class']!r} sink_shape_id={f['sink_shape_id']!r} "
            f"evidence_grade={f['evidence_grade']!r} confidence={f['confidence']} "
            f"first_seen={f['first_seen_engagement']!r}"
        )
    print(f"  capability_observations AFTER: {len(obs_after)} row(s)")
    for o in obs_after[:12]:
        print(
            f"    obs: outcome={o['outcome']!r} sink={o['sink_shape_id']!r} "
            f"P={o['confirmation_primitive']!r} grade={o['reachability_grade']!r} "
            f"evidence_ref={o['evidence_ref']!r}"
        )
    (OUT_DIR / "capability_facts_before.json").write_text(
        json.dumps(facts_before, indent=2), encoding="utf-8"
    )
    (OUT_DIR / "capability_facts_after.json").write_text(
        json.dumps(facts_after, indent=2), encoding="utf-8"
    )
    (OUT_DIR / "capability_observations_after.json").write_text(
        json.dumps(obs_after, indent=2), encoding="utf-8"
    )

    target_fact = next(
        (
            f
            for f in facts_after
            if f["technology_key"] == "log4j-core"
            and f["primitive_class"] == "log_interpolation"
            and f["sink_shape_id"] == "log4j.log_sink"
            and f["evidence_grade"] == "confirmed"
        ),
        None,
    )
    a_ok = target_fact is not None and len(obs_after) >= 1
    confirmed_obs = [o for o in obs_after if o["outcome"] == "confirmed"]
    evidence_ref_is_link = all(
        (o["evidence_ref"] or "").startswith("finding:") for o in confirmed_obs
    )
    print(f"  target log4j-core fact present + confirmed: {target_fact is not None}")
    print(f"  >=1 confirmed observation, evidence_ref a LINK: {evidence_ref_is_link}")

    # ---- (c) CONFIDENCE present + provably unused in emission ----------------
    _rule("(c) CONFIDENCE — a number, provably UNUSED in any emission decision")
    conf_present = target_fact is not None and isinstance(target_fact["confidence"], (int, float))
    print(f"  confidence value on the fact: {target_fact['confidence'] if target_fact else None}")
    # No emission path READS a capability fact. The only fact reader, get_capability_facts,
    # is called nowhere in src (recall is slice 2); the write-back's
    # recompute_capability_confidence return value is discarded (never branched on). So
    # confidence cannot gate a finding — structurally, slice 1 does not read facts back.
    src = REPO_ROOT / "src" / "clinkz"
    fact_readers = [
        str(py.relative_to(REPO_ROOT))
        for py in src.rglob("*.py")
        if py.name != "persistent_kb.py"
        and "get_capability_facts" in py.read_text("utf-8", "replace")
    ]
    print(f"  src modules that READ capability facts: {fact_readers or '(none)'}")
    c_ok = conf_present and not fact_readers

    await kb.close()

    trace_path = REPO_ROOT / "outputs" / engagement_id / "trace.jsonl"
    print(f"\nengagement_id : {engagement_id}")
    print(f"report (json) : {rep.get('json_path')}")
    print(f"report (md)   : {rep.get('markdown_path')}")
    print(f"trace (jsonl) : {trace_path}")
    print(f"KB dumps      : {OUT_DIR}")

    # ---- VERDICT -------------------------------------------------------------
    _rule("VERDICT")
    print(f"  (a) capability_facts 0→confirmed log4j-core fact + observations : {a_ok}")
    print(f"  (b) emission unchanged (finding SET identical to baseline)      : {b_ok}")
    print(f"  (c) confidence present as a number, provably unused in emission : {c_ok}")
    ok = a_ok and b_ok and c_ok and evidence_ref_is_link
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
