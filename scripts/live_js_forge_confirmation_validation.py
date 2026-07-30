"""Live smoke gate for the WSTG-CLNT-11 forge-and-accept confirmation (G16).

Drives the real ``_test_javascript_attacks`` against the RUNNING DVWA at each
security level and prints, per level, whether a finding was emitted and what the
four-arm differential measured. The point of the gate is the pair of outcomes:

* a level whose client-side chain is replayable AND whose server validates the
  token → a CONFIRMED finding whose evidence names the forged value, the two
  equal-shaped controls, and the page divergence;
* every other level → NO finding and an ``UnprovenExploitLead`` naming the
  missing effect.

Usage::

    python scripts/live_js_forge_confirmation_validation.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from pathlib import Path

# The in-process HTTP path — set before importing clinkz so config picks it up.
os.environ.setdefault("TOOL_EXEC_MODE", "local")

logging.basicConfig(level=logging.WARNING, format="%(levelname)-5s %(name)s %(message)s")

DVWA_BASE = "http://localhost:8080"
DB_PATH = Path("outputs/js_forge_smoke.db")
LEVELS = ("low", "medium", "high")

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType  # noqa: E402

SCOPE = EngagementScope(
    name="js-forge-confirmation-smoke",
    targets=[
        ScopeEntry(value="127.0.0.1", type=ScopeType.IP),
        ScopeEntry(value="localhost", type=ScopeType.DOMAIN),
    ],
)


async def _authenticate() -> dict[str, str]:
    from clinkz.tools.auth import WebAuthenticator

    result = await WebAuthenticator(scope=SCOPE).authenticate(
        f"{DVWA_BASE}/login.php", "admin", "password"
    )
    if not result.success:
        print(f"FATAL: DVWA authentication failed: {result.error}")
        sys.exit(1)
    return result.session_cookies


async def _set_level(cookies: dict[str, str], level: str) -> dict[str, str]:
    import aiohttp

    url = f"{DVWA_BASE}/security.php"
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, cookies=cookies, ssl=False) as resp:
            body = await resp.text(errors="replace")
        match = re.search(r"name=['\"]user_token['\"].*?value=['\"]([^'\"]+)", body)
        data = {"security": level, "seclev_submit": "Submit"}
        if match:
            data["user_token"] = match.group(1)
        async with session.post(url, data=data, cookies=cookies, ssl=False) as resp:
            await resp.text(errors="replace")
    cookies["security"] = level
    return cookies


async def main() -> int:
    from clinkz.agents.exploit import ExploitAgent
    from clinkz.llm.factory import get_llm_client
    from clinkz.state import StateStore

    cookies = await _authenticate()
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    failures: list[str] = []

    async with StateStore(str(DB_PATH)) as state:
        engagement_id = await state.create_engagement(
            "js-forge-confirmation-smoke", SCOPE.model_dump(mode="json")
        )
        for level in LEVELS:
            cookies = await _set_level(cookies, level)
            agent = ExploitAgent(
                llm=get_llm_client("gemini"),
                tools=[],
                scope=SCOPE,
                state=state,
                engagement_id=engagement_id,
            )
            agent._session_cookies = dict(cookies)
            page = await agent._fetch_page(f"{DVWA_BASE}/vulnerabilities/javascript/", {})
            findings = await agent._test_javascript_attacks(page)
            leads = list(agent._unproven_exploit_leads)

            print("=" * 78)
            print(f"LEVEL {level}  page_status={page.status}  forms={len(page.forms)}")
            print(f"  findings={len(findings)}  leads={len(leads)}")
            for finding in findings:
                print(f"  FINDING  [{finding.severity.value}] {finding.title}")
                for line in finding.evidence:
                    print(f"      {line[:400]}")
            for lead in leads:
                print(f"  LEAD     why={lead.why_unconfirmed}")
                print(f"      raw:     {lead.raw_observation[:300]}")
                print(f"      missing: {lead.missing_observation[:300]}")

            # Gate: a finding may only exist with a confirmed forgery in evidence.
            for finding in findings:
                joined = " ".join(finding.evidence)
                if "forge_confirmed=True" not in joined:
                    failures.append(f"{level}: finding emitted without forge_confirmed=True")
                if "Response: " not in joined:
                    failures.append(f"{level}: finding has no Response observation")
            if level == "low" and len(findings) != 1:
                failures.append(f"low: expected exactly 1 confirmed finding, got {len(findings)}")
            if level != "low" and findings:
                failures.append(f"{level}: emitted {len(findings)} finding(s); chain is external JS")

    print("=" * 78)
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}")
        return 1
    print("SMOKE GATE PASS")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
