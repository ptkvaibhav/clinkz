"""Live integration test: ReconAgent v2 against DVWA.

Prerequisites:
- DVWA running on http://localhost (port 80) — typically via Docker:
    docker run --rm -d -p 80:80 vulnerables/web-dvwa
- Network tools available (nmap at minimum)

Marked with @pytest.mark.integration so it is skipped in normal pytest runs.
Run explicitly with: pytest -m integration tests/test_integration/test_dvwa_recon_v2.py -v -s
"""

from __future__ import annotations

import logging
import socket
from pathlib import Path

import pytest

from clinkz.agents.recon import ReconAgent
from clinkz.knowledge.persistent_kb import PersistentKnowledgeBase
from clinkz.knowledge.seed_playbook import seed_tier1_tests
from clinkz.llm.factory import get_llm_client
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

logger = logging.getLogger(__name__)

DVWA_HOST = "127.0.0.1"
DVWA_PORT = 80
SCOPE = EngagementScope(
    name="dvwa-recon-v2-test",
    targets=[ScopeEntry(value=DVWA_HOST, type=ScopeType.IP)],
)


def _dvwa_reachable() -> bool:
    """Check whether DVWA is listening on the expected address."""
    try:
        with socket.create_connection((DVWA_HOST, DVWA_PORT), timeout=3):
            return True
    except OSError:
        return False


@pytest.mark.integration
@pytest.mark.skipif(not _dvwa_reachable(), reason=f"DVWA not reachable at {DVWA_HOST}:{DVWA_PORT}")
async def test_recon_v2_against_dvwa(tmp_path: Path) -> None:
    """Run the deterministic ReconAgent v2 against a live DVWA instance.

    Asserts:
    1. Port 80 is found
    2. HTTP service detected
    3. tech_stack contains Apache and PHP
    4. ReconResult.web_info is not None
    5. ReconResult.llm_summary is non-empty
    6. Persistent KB playbook entries match Apache (Tier 1 returned)
    """
    logging.basicConfig(level=logging.INFO, format="%(name)s %(levelname)s %(message)s")

    # --- Set up dependencies ---
    db_path = tmp_path / "dvwa_test.db"
    state = StateStore(db_path)
    await state.connect()
    eid = await state.create_engagement("dvwa-recon-v2", SCOPE.model_dump())

    llm = get_llm_client()
    resolver = ToolResolver()

    # --- Set up persistent KB ---
    kb_path = str(tmp_path / "test_knowledge.db")
    persistent_kb = await PersistentKnowledgeBase.create(kb_path)
    await seed_tier1_tests(persistent_kb)

    try:
        # --- Run the ReconAgent v2 ---
        agent = ReconAgent(
            llm=llm,
            tools=[],
            scope=SCOPE,
            state=state,
            engagement_id=eid,
            resolver=resolver,
        )

        result = await agent.run({"target": DVWA_HOST})

        # --- Print full result for manual review ---
        import json

        print("\n" + "=" * 70)
        print("FULL RECON RESULT (v2):")
        print("=" * 70)
        print(json.dumps(result, indent=2, default=str))
        print("=" * 70 + "\n")

        # --- Assertions ---
        assert result["status"] == "complete", f"Expected status=complete, got {result['status']}"

        recon = result["result"]

        # 1. Port 80 is found
        assert 80 in recon["ports"]["open_ports"], (
            f"Port 80 not found in open_ports: {recon['ports']['open_ports']}"
        )

        # 2. HTTP service detected
        services = recon["services"]["services"]
        http_services = [
            s for s in services
            if s.get("is_http") or s.get("service_name", "").lower() in ("http", "https")
        ]
        assert http_services, f"No HTTP service found in services: {services}"

        # 3. tech_stack contains Apache and PHP (DVWA's stack)
        tech_names = [
            t["name"].lower() for t in recon["tech_stack"]["technologies"]
        ]
        assert any("apache" in t for t in tech_names), (
            f"Expected 'apache' in tech_stack, got: {tech_names}"
        )
        assert any("php" in t for t in tech_names), (
            f"Expected 'php' in tech_stack, got: {tech_names}"
        )

        # 4. web_info is not None
        assert recon["web_info"] is not None, "Expected web_info to be populated for DVWA"

        # 5. llm_summary is non-empty
        assert recon["llm_summary"], "Expected non-empty llm_summary"
        assert len(recon["llm_summary"]) > 20, (
            f"llm_summary too short: {recon['llm_summary'][:100]}"
        )

        # 6. Query persistent KB for playbook entries matching "Apache"
        apache_entries = await persistent_kb.get_playbook_for_technology("Apache")
        tier1_entries = [e for e in apache_entries if e.get("tier") == 1]
        assert tier1_entries, (
            "Expected Tier 1 playbook entries for Apache, got none"
        )
        print(f"\nPlaybook: {len(tier1_entries)} Tier 1 entries match 'Apache':")
        for entry in tier1_entries[:5]:
            print(f"  - {entry['technique_name']}: {entry.get('technique_description', '')}")

    finally:
        await persistent_kb.close()
        await state.close()
