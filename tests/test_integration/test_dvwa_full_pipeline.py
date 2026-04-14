"""Live integration test: full v2 pipeline against DVWA.

Prerequisites:
- DVWA running on http://localhost:8080 — typically via Docker:
    docker run --rm -d -p 8080:80 vulnerables/web-dvwa
- Network tools available (nmap, katana/ffuf, sqlmap, etc.)
- LLM API key configured (OPENAI_API_KEY or equivalent)

Marked with @pytest.mark.integration so it is skipped in normal pytest runs.
Run explicitly with:
    pytest -m integration tests/test_integration/test_dvwa_full_pipeline.py -v -s

Phase 3 target: 12+/14 DVWA vulnerability categories found.
"""

from __future__ import annotations

import logging
import os
import socket
from pathlib import Path

import pytest

from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.models.finding import Finding
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.orchestrator.orchestrator import OrchestratorAgent

logger = logging.getLogger(__name__)

DVWA_HOST = "localhost"
DVWA_PORT = 8080
DVWA_URL = f"http://{DVWA_HOST}:{DVWA_PORT}"

SCOPE = EngagementScope(
    name="dvwa-full-pipeline-v2",
    targets=[ScopeEntry(value=DVWA_URL, type=ScopeType.URL)],
)

# ---------------------------------------------------------------------------
# DVWA vulnerability categories (14 total)
# ---------------------------------------------------------------------------

DVWA_CATEGORIES: set[str] = {
    "sql_injection",
    "xss_reflected",
    "xss_stored",
    "command_injection",
    "file_inclusion",
    "file_upload",
    "csrf",
    "brute_force",
    "weak_session_ids",
    "dom_xss",
    "javascript_attacks",
    "authorization_bypass",
    "open_redirect",
    "csp_bypass",
}

# Mapping from finding vuln_class / category strings to DVWA categories
_FINDING_TO_DVWA: dict[str, str] = {
    "sqli": "sql_injection",
    "sql_injection": "sql_injection",
    "sql-injection": "sql_injection",
    "xss_reflected": "xss_reflected",
    "xss": "xss_reflected",
    "reflected_xss": "xss_reflected",
    "xss_stored": "xss_stored",
    "stored_xss": "xss_stored",
    "command_injection": "command_injection",
    "cmdi": "command_injection",
    "os_command_injection": "command_injection",
    "lfi": "file_inclusion",
    "rfi": "file_inclusion",
    "file_inclusion": "file_inclusion",
    "path_traversal": "file_inclusion",
    "file_upload": "file_upload",
    "unrestricted_file_upload": "file_upload",
    "csrf": "csrf",
    "cross-site_request_forgery": "csrf",
    "brute_force": "brute_force",
    "default_credentials": "brute_force",
    "weak_credentials": "brute_force",
    "weak_session": "weak_session_ids",
    "weak_session_ids": "weak_session_ids",
    "session_fixation": "weak_session_ids",
    "dom_xss": "dom_xss",
    "dom_based_xss": "dom_xss",
    "javascript": "javascript_attacks",
    "javascript_attacks": "javascript_attacks",
    "js_attacks": "javascript_attacks",
    "authorization_bypass": "authorization_bypass",
    "idor": "authorization_bypass",
    "insecure_direct_object_reference": "authorization_bypass",
    "access_control": "authorization_bypass",
    "open_redirect": "open_redirect",
    "redirect": "open_redirect",
    "csp_bypass": "csp_bypass",
    "security_headers": "csp_bypass",
    "content_security_policy": "csp_bypass",
    "missing_security_headers": "csp_bypass",
}


def _dvwa_reachable() -> bool:
    """Check whether DVWA is listening on the expected address."""
    try:
        with socket.create_connection((DVWA_HOST, DVWA_PORT), timeout=3):
            return True
    except OSError:
        return False


def _has_llm_key() -> bool:
    """Check whether at least one LLM API key is configured."""
    return bool(
        os.environ.get("OPENAI_API_KEY")
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("GEMINI_API_KEY")
    )


def _map_finding_to_dvwa_category(finding: Finding) -> str | None:
    """Map a Finding's vulnerability class to a DVWA category name."""
    vuln_class = getattr(finding, "vuln_class", "") or ""
    if not vuln_class:
        # Try extracting from title or description heuristically
        title_lower = finding.title.lower()
        for key, cat in _FINDING_TO_DVWA.items():
            if key.replace("_", " ") in title_lower:
                return cat
        return None
    return _FINDING_TO_DVWA.get(vuln_class.lower().strip())


# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not _dvwa_reachable(), reason=f"DVWA not reachable at {DVWA_HOST}:{DVWA_PORT}")
@pytest.mark.skipif(not _has_llm_key(), reason="No LLM API key available")
async def test_dvwa_full_pipeline(tmp_path: Path) -> None:
    """Run complete v2 pipeline against DVWA.

    Target: 12+/14 vulnerability categories found.

    This test uses:
    - Real PersistentKnowledgeBase (temp file, seeded with Tier 1)
    - Real StateStore (temp file)
    - Real tool execution (nmap, katana, ffuf, sqlmap, etc.)
    - Real LLM calls
    """
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

    db_path = str(tmp_path / "dvwa_full_pipeline.db")

    orchestrator = OrchestratorAgent(db_path=db_path)

    result = await orchestrator.run(SCOPE)

    # --- Print summary for manual review ---
    print("\n" + "=" * 70)
    print("DVWA FULL PIPELINE RESULT")
    print("=" * 70)
    print(f"Status: {result.get('status')}")

    phases = result.get("phases", {})
    for phase_name, phase_data in phases.items():
        status = phase_data.get("status", "unknown") if isinstance(phase_data, dict) else "present"
        print(f"  {phase_name}: {status}")

    # --- Verify recon ---
    recon_phase = phases.get("recon", {})
    recon_result = recon_phase.get("result", recon_phase)
    if isinstance(recon_result, dict):
        ports_data = recon_result.get("ports", {})
        open_ports = ports_data.get("open_ports", [])
        assert 80 in open_ports or 8080 in open_ports, (
            f"Expected port 80 or 8080 in open_ports: {open_ports}"
        )

        tech_stack = recon_result.get("tech_stack", {})
        technologies = tech_stack.get("technologies", [])
        tech_names = [t.get("name", "").lower() for t in technologies]
        assert any("apache" in t for t in tech_names), (
            f"Expected 'apache' in tech_stack, got: {tech_names}"
        )
        assert any("php" in t for t in tech_names), (
            f"Expected 'php' in tech_stack, got: {tech_names}"
        )

    # --- Verify findings coverage ---
    exploit_phase = phases.get("exploit", {})
    findings_raw = exploit_phase.get("findings", [])

    # Convert raw dicts to Finding objects if needed
    findings: list[Finding] = []
    for f in findings_raw:
        if isinstance(f, Finding):
            findings.append(f)
        elif isinstance(f, dict):
            try:
                findings.append(Finding(**f))
            except Exception:
                logger.warning("Could not parse finding: %s", f)

    found_categories: set[str] = set()
    for finding in findings:
        category = _map_finding_to_dvwa_category(finding)
        if category:
            found_categories.add(category)

    coverage = len(found_categories)
    missing = sorted(DVWA_CATEGORIES - found_categories)

    print(f"\nDVWA Coverage: {coverage}/{len(DVWA_CATEGORIES)}")
    print(f"Found: {sorted(found_categories)}")
    print(f"Missing: {missing}")
    print(f"Total findings: {len(findings)}")
    print("=" * 70 + "\n")

    # Phase 3 target: 12+/14
    assert coverage >= 12, (
        f"Only {coverage}/14 categories found: {sorted(found_categories)}. Missing: {missing}"
    )

    # --- Verify KB recording ---
    kb_path = db_path.replace(".db", "_knowledge.db")
    if Path(kb_path).exists():
        persistent_kb = await PersistentKnowledgeBase.create(kb_path)
        try:
            engagements = await persistent_kb.get_past_results_for_technology("Apache")
            assert len(engagements) > 0, "No results recorded to KB for Apache"
            print(f"KB: {len(engagements)} technique results for Apache")
        finally:
            await persistent_kb.close()
    else:
        logger.warning("KB file not found at %s — skipping KB verification", kb_path)


@pytest.mark.integration
@pytest.mark.asyncio
@pytest.mark.skipif(not _dvwa_reachable(), reason=f"DVWA not reachable at {DVWA_HOST}:{DVWA_PORT}")
@pytest.mark.skipif(not _has_llm_key(), reason="No LLM API key available")
async def test_dvwa_recon_only(tmp_path: Path) -> None:
    """Smoke test: run only recon against DVWA to verify basic connectivity.

    Lighter-weight than the full pipeline test — useful for quick validation.
    """
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

    from clinkz.agents.recon import ReconAgent
    from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
    from clinkz.knowledge.seed_playbook import seed_tier1_tests
    from clinkz.llm.factory import get_llm_client
    from clinkz.state import StateStore
    from clinkz.tools.resolver import ToolResolver

    db_path = tmp_path / "dvwa_recon.db"
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("dvwa-recon-smoke", SCOPE.model_dump())

    llm = get_llm_client()
    resolver = ToolResolver()

    kb_path = str(tmp_path / "test_knowledge.db")
    persistent_kb = await PersistentKnowledgeBase.create(kb_path)
    await seed_tier1_tests(persistent_kb)

    try:
        agent = ReconAgent(
            llm=llm,
            tools=[],
            scope=SCOPE,
            state=state,
            engagement_id=eid,
            resolver=resolver,
        )

        result = await agent.run({"target": DVWA_HOST})

        assert result["status"] == "complete", f"Recon failed: {result}"
        recon = result["result"]
        open_ports = recon["ports"]["open_ports"]
        assert 80 in open_ports or 8080 in open_ports, (
            f"Expected port 80 or 8080 in open_ports: {open_ports}"
        )

        print(f"\nRecon smoke test passed — {len(open_ports)} open ports found")
    finally:
        await persistent_kb.close()
        await state.close()
