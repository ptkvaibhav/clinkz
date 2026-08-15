"""Live two-engagement validation of the capability-learning READ side (slice 2).

The §6 "gets smarter" experiment, run for REAL against a LIVE Vulhub
``log4j/CVE-2021-44228`` (Apache Solr 8.11.0 + ``log4j-core`` 2.14.1 on :8983), a
LIVE OOB collaborator, and a real exploit agent built with the live Anthropic LLM —
no harness, no mocks. It proves, from RAW artifacts (non-self-graded):

  (1) CATALOG-STATE DIFF — ``capability_facts`` + ``technology_relations`` before A
      (0 rows each) vs after A: a ``confirmed`` ``log4j-core`` / ``=2.14.1`` fact AND a
      manifest-derived ``apache-solr@8.11.0 → log4j-core@2.14.1`` bundles edge — the
      dormant table's first production row.
  (2) TRACE DIFF (warm B vs cold-control B, SAME partial source) — the withheld
      log-sink source means the recognizer finds NO log sink, so the COLD control
      produces ZERO LOG_INTERPOLATION hypotheses; the WARM run (capability_kb from A)
      recalls the log4j fact via the bundles edge and produces ONE recall-seeded
      hypothesis (``prior_source=capability_recall``). Hypothesis-present-vs-absent
      under identical partial source is the unambiguous "recall substituted for
      derivation" signal, readable from the two trace.jsonl files.
  (3) The warm-B finding is confirmed by the LIVE P1–P6 proof (the P6 JNDI/DNS
      callback), NOT by recall — recall changed the PATH to the finding, never the
      finding (§5 invariant).

Pre-flight (STOP + report, never a substitute): ANTHROPIC_API_KEY present, Solr
reachable, and the collaborator starts + passes its self-round-trip health-check.

Usage::

    python scripts/live_capability_recall_validation.py \
        [--solr-base http://localhost:8983] \
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
from typing import Any

# Must be set BEFORE importing clinkz so the HTTP client uses host aiohttp (lesson #22).
os.environ.setdefault("TOOL_EXEC_MODE", "local")

from _artifact_io import write_redacted_json  # noqa: E402

try:
    from dotenv import load_dotenv

    load_dotenv()
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
log = logging.getLogger("capability_recall_validation")

REPO_ROOT = Path(__file__).resolve().parent.parent
FULL_SOURCE = REPO_ROOT / "tests" / "fixtures" / "solr_log4shell"
PARTIAL_SOURCE = REPO_ROOT / "tests" / "fixtures" / "solr_log4shell_partial"
OUT_DIR = REPO_ROOT / "outputs" / "capability-recall"
FINGERPRINT = ["Java", "Apache Solr 8.11.0"]


def _rule(title: str) -> None:
    print("\n" + "=" * 78 + f"\n{title}\n" + "=" * 78)


def _http_get_text(url: str, timeout: float = 10.0) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (in-scope)
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")
    except Exception as exc:  # pragma: no cover - preflight diagnostics
        return 0, f"<error: {exc}>"


def _discovery_hypothesis_events(trace_path: Path) -> list[dict[str, Any]]:
    """Every ``discovery_hypotheses`` payload from a trace.jsonl (the §6.2 metric line)."""
    events: list[dict[str, Any]] = []
    if not trace_path.exists():
        return events
    for line in trace_path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        payload = record.get("payload", {})
        if payload.get("message_type") == "discovery_hypotheses":
            events.append(payload)
    return events


def _log_hypotheses(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten the LOG_INTERPOLATION hypotheses across the trace's discovery events."""
    rows: list[dict[str, Any]] = []
    for event in events:
        for h in event.get("discovery_hypotheses", []):
            if h.get("primitive_class") == "log_interpolation":
                rows.append(h)
    return rows


async def main() -> int:  # noqa: C901 - a linear validation script, read top to bottom
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--solr-base", default="http://localhost:8983")
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

    from clinkz.agents.exploit import ExploitAgent, PageAnalysis
    from clinkz.agents.report import ReportAgent
    from clinkz.discovery import DiscoveryEngine, derive_bundles_edges
    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
    from clinkz.llm.factory import get_llm_client
    from clinkz.models.scan import ParamLocation
    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.observability.trace import TraceWriter, set_active_trace_writer
    from clinkz.oob import CallbackShape, OOBCollaborator
    from clinkz.state import StateStore

    # Fresh, isolated capability KB (never the shared one) so the before-dump is 0 rows.
    kb_path = OUT_DIR / "capability_kb.db"
    if kb_path.exists():
        kb_path.unlink()
    kb = await PersistentKnowledgeBase.create(str(kb_path))
    facts_before = await kb.get_capability_facts()
    relations_before = await kb.get_technology_relations()
    print(f"capability KB (fresh): {kb_path}")
    print(f"  capability_facts BEFORE: {len(facts_before)} rows")
    print(f"  technology_relations BEFORE: {len(relations_before)} rows")
    if facts_before or relations_before:
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

    llm = get_llm_client("anthropic")
    scope = EngagementScope(
        name="Capability-recall — Solr CVE-2021-44228",
        targets=[
            ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
            ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ],
        source_dir=str(FULL_SOURCE),
        discovery_base_url=cores_url,
    )
    state_db = OUT_DIR / "engagement_state.db"
    if state_db.exists():
        state_db.unlink()

    a_engagement = ""
    warm_engagement = ""
    cold_engagement = ""
    warm_confirmed = 0
    rep: dict[str, Any] = {}

    async with StateStore(str(state_db)) as state:
        # ================= ENGAGEMENT A (cold, FULL source) ==================
        _rule("ENGAGEMENT A (cold) — cold-derive, LIVE P6 confirm, write fact + bundles edge")
        a_engagement = await state.create_engagement(
            "Capability-recall A", scope.model_dump(mode="json")
        )
        trace_a = TraceWriter(a_engagement)
        set_active_trace_writer(trace_a)
        try:
            disc_a = DiscoveryEngine().discover(
                str(FULL_SOURCE),
                FINGERPRINT,
                cores_url,
                capability_facts=[],
                technology_relations=[],
            )
            print(f"A manifest: {disc_a.source_model.manifest_evidence or '(none)'}")
            log_hyps_a = [
                h
                for h in disc_a.hypotheses
                if h.delta.call_site.primitive_class.value == "log_interpolation"
            ]
            print(
                f"A cold LOG_INTERPOLATION hypotheses: {len(log_hyps_a)} "
                f"(prior_source={ {h.prior_source for h in log_hyps_a} })"
            )

            # Mirror the orchestrator seam: write the manifest-derived bundles edge.
            for edge in derive_bundles_edges(
                disc_a.source_model.manifest_technology_key,
                disc_a.source_model.manifest_observed_version,
                FINGERPRINT,
            ):
                await kb.add_technology_relation(
                    edge.tech_a, edge.tech_b, edge.relation_type, edge.similarity
                )

            # LIVE P6 confirm through the exploit agent + write-back (mirrors slice 1).
            agent_a = ExploitAgent(
                llm=llm,
                tools=[],
                scope=scope,
                state=state,
                engagement_id=a_engagement,
                persistent_kb=kb,
            )
            agent_a._collaborator = collab
            a_tasks = disc_a.exploit_tasks()
            a_channels = [t.endpoint_params[0] for t in a_tasks if t.endpoint_params]
            prov_a = next(t.discovery_provenance for t in a_tasks if "action" in t.endpoint_params)
            page_a = PageAnalysis(
                url=cores_url,
                body="",
                status=200,
                input_params=list(a_channels),
                param_locations={c: ParamLocation.QUERY for c in a_channels},
                request_method="GET",
                discovery_provenance=prov_a,
            )
            findings_a = await agent_a._test_log4shell(page_a)
            for f in findings_a:
                f.discovery_provenance = prov_a
                await agent_a._persist_finding(f)
            print(f"A LIVE Log4Shell confirmations: {len(findings_a)}")
        finally:
            trace_a.close()
            set_active_trace_writer(None)

        facts_after = await kb.get_capability_facts()
        relations_after = await kb.get_technology_relations()
        # Through the engine's redaction chokepoint, like every writer inside it.
        write_redacted_json(OUT_DIR / "capability_facts_before.json", facts_before)
        write_redacted_json(OUT_DIR / "capability_facts_after.json", facts_after)
        write_redacted_json(OUT_DIR / "technology_relations_before.json", relations_before)
        write_redacted_json(OUT_DIR / "technology_relations_after.json", relations_after)
        target_fact = next(
            (
                f
                for f in facts_after
                if f["technology_key"] == "log4j-core"
                and f["primitive_class"] == "log_interpolation"
                and f["evidence_grade"] == "confirmed"
            ),
            None,
        )
        bundles_edge = next(
            (
                r
                for r in relations_after
                if r["relation_type"] == "bundles"
                and r["tech_a"] == "apache-solr@8.11.0"
                and r["tech_b"] == "log4j-core@2.14.1"
            ),
            None,
        )
        print(
            f"  capability_facts AFTER A: {len(facts_after)} row(s); "
            f"confirmed log4j fact: {target_fact is not None}"
        )
        print(
            f"  technology_relations AFTER A: {len(relations_after)} row(s); "
            f"bundles edge: {bundles_edge is not None}"
        )

        facts_dump = await kb.get_capability_facts()
        relations_dump = await kb.get_technology_relations()

        # ============ ENGAGEMENT B — COLD-CONTROL (empty KB, PARTIAL) ============
        _rule("ENGAGEMENT B — COLD-CONTROL (empty store, PARTIAL source) → 0 hypotheses")
        cold_engagement = await state.create_engagement(
            "Capability-recall B cold", scope.model_dump(mode="json")
        )
        trace_cold = TraceWriter(cold_engagement)
        set_active_trace_writer(trace_cold)
        try:
            disc_cold = DiscoveryEngine().discover(
                str(PARTIAL_SOURCE),
                FINGERPRINT,
                cores_url,
                capability_facts=[],
                technology_relations=[],
            )
        finally:
            trace_cold.close()
            set_active_trace_writer(None)
        cold_log = [
            h
            for h in disc_cold.hypotheses
            if h.delta.call_site.primitive_class.value == "log_interpolation"
        ]
        print(
            f"  cold-control recalls: {len(disc_cold.recalls)}; "
            f"LOG_INTERPOLATION hypotheses: {len(cold_log)}"
        )

        # =============== ENGAGEMENT B — WARM (KB from A, PARTIAL) ================
        _rule(
            "ENGAGEMENT B — WARM (capability_kb from A, SAME partial source) → "
            "recall-seeded + LIVE confirm"
        )
        warm_engagement = await state.create_engagement(
            "Capability-recall B warm", scope.model_dump(mode="json")
        )
        trace_warm = TraceWriter(warm_engagement)
        set_active_trace_writer(trace_warm)
        try:
            disc_warm = DiscoveryEngine().discover(
                str(PARTIAL_SOURCE),
                FINGERPRINT,
                cores_url,
                capability_facts=facts_dump,
                technology_relations=relations_dump,
            )
            warm_log = [
                h
                for h in disc_warm.hypotheses
                if h.delta.call_site.primitive_class.value == "log_interpolation"
            ]
            print(
                f"  warm recalls: {len(disc_warm.recalls)} "
                f"(match_kind={[r.match_kind for r in disc_warm.recalls]})"
            )
            print(
                f"  warm recall-seeded LOG_INTERPOLATION hypotheses: {len(warm_log)} "
                f"(prior_source={ {h.prior_source for h in warm_log} }, "
                f"grade={ {h.edge.soundness_grade.value for h in warm_log} })"
            )

            # LIVE P6 proof on the recall-SEEDED task — recall changed the PATH, the
            # proof confirms the finding (§5). Fire the seeded channel bag in one page.
            warm_tasks = disc_warm.exploit_tasks()
            warm_channels = [t.endpoint_params[0] for t in warm_tasks if t.endpoint_params]
            prov_warm = next(
                (t.discovery_provenance for t in warm_tasks if "action" in t.endpoint_params), None
            )
            if warm_channels and prov_warm is not None:
                agent_warm = ExploitAgent(
                    llm=llm,
                    tools=[],
                    scope=scope,
                    state=state,
                    engagement_id=warm_engagement,
                    persistent_kb=kb,
                )
                agent_warm._collaborator = collab
                page_warm = PageAnalysis(
                    url=cores_url,
                    body="",
                    status=200,
                    input_params=list(warm_channels),
                    param_locations={c: ParamLocation.QUERY for c in warm_channels},
                    request_method="GET",
                    discovery_provenance=prov_warm,
                )
                findings_warm = await agent_warm._test_log4shell(page_warm)
                warm_confirmed = len(findings_warm)
                for f in findings_warm:
                    f.discovery_provenance = prov_warm
                    await agent_warm._persist_finding(f)
                print(
                    "  warm-B LIVE P6 confirmations (recall changed the PATH, proof "
                    f"confirms): {warm_confirmed}"
                )
                report_agent = ReportAgent(
                    llm=llm, tools=[], scope=scope, state=state, engagement_id=warm_engagement
                )
                rep = await report_agent.run(
                    {
                        "engagement_id": warm_engagement,
                        "engagement_name": "Capability-recall B warm",
                    }
                )
        finally:
            trace_warm.close()
            set_active_trace_writer(None)

    await kb.close()

    # ---- RAW METRIC (non-self-graded) ----------------------------------------
    _rule("RAW METRIC — trace diff (warm B vs cold-control B, SAME partial source)")
    cold_trace = REPO_ROOT / "outputs" / cold_engagement / "trace.jsonl"
    warm_trace = REPO_ROOT / "outputs" / warm_engagement / "trace.jsonl"
    cold_events = _discovery_hypothesis_events(cold_trace)
    warm_events = _discovery_hypothesis_events(warm_trace)
    cold_log_hyps = _log_hypotheses(cold_events)
    warm_log_hyps = _log_hypotheses(warm_events)
    warm_recall_hyps = [h for h in warm_log_hyps if h.get("prior_source") == "capability_recall"]
    print(f"  cold-control trace LOG_INTERPOLATION hypotheses : {len(cold_log_hyps)}")
    print(
        f"  warm trace LOG_INTERPOLATION hypotheses         : {len(warm_log_hyps)} "
        f"({len(warm_recall_hyps)} prior_source=capability_recall)"
    )
    for h in warm_recall_hyps[:4]:
        print(
            f"    warm hyp: id={h.get('hypothesis_id')} prior={h.get('prior_source')} "
            f"rank={h.get('rank_score')} channel={h.get('channel_param')} "
            f"grade={h.get('reachability_grade')} tech={h.get('technology_key')}"
        )

    print(f"\nengagement A (cold)      : {a_engagement}")
    print(f"engagement B cold-control: {cold_engagement}")
    print(f"engagement B warm        : {warm_engagement}")
    print(f"report (warm json)       : {rep.get('json_path')}")
    print(f"trace (cold-control)     : {cold_trace}")
    print(f"trace (warm)             : {warm_trace}")
    print(f"KB dumps                 : {OUT_DIR}")

    # ---- VERDICT -------------------------------------------------------------
    _rule("VERDICT")
    a_ok = target_fact is not None and bundles_edge is not None
    trace_ok = len(cold_log_hyps) == 0 and len(warm_recall_hyps) >= 1
    proof_ok = warm_confirmed >= 1
    print(f"  (1) catalog-state diff: confirmed log4j fact + real bundles edge  : {a_ok}")
    print(f"  (2) trace diff: cold-control 0 hyps, warm >=1 recall-seeded hyp   : {trace_ok}")
    print(f"  (3) warm-B confirmed by the LIVE P1-P6 proof (recall changed path): {proof_ok}")
    ok = a_ok and trace_ok and proof_ok
    print(f"\n  RESULT: {'PASS' if ok else 'INCOMPLETE'}")
    return 0 if ok else 4


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
