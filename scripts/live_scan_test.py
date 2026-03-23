"""Live integration test: Scan Agent + real Gemini LLM + real tools vs Juice Shop.

Runs the full ReAct loop with a real GeminiClient and scan-category tools
(katana, ffuf, httpx) executing inside the clinkz-tools Docker container
against 172.20.0.2 (Juice Shop).

Usage:
    python scripts/live_scan_test.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from pathlib import Path

# Ensure project root is on sys.path for local dev
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Force docker execution mode before importing anything that reads settings
os.environ.setdefault("TOOL_EXEC_MODE", "docker")
os.environ.setdefault("DOCKER_CONTAINER", "clinkz-tools")
os.environ.setdefault("LLM_PROVIDER", "gemini")

from clinkz.agents.scan import ScanAgent  # noqa: E402
from clinkz.llm.gemini_client import GeminiClient  # noqa: E402
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType  # noqa: E402
from clinkz.state import StateStore  # noqa: E402
from clinkz.tools.ffuf import FfufTool  # noqa: E402
from clinkz.tools.httpx_tool import HttpxTool  # noqa: E402
from clinkz.tools.katana import KatanaTool  # noqa: E402
from clinkz.tools.resolver import ToolResolver  # noqa: E402

# ---------------------------------------------------------------------------
# Logging — show everything so we can watch the agent think
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
# Quiet down noisy libraries
for noisy in ("httpcore", "httpx", "urllib3", "google", "grpc"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger = logging.getLogger("live_scan_test")

# ---------------------------------------------------------------------------
# Scope: only Juice Shop
# ---------------------------------------------------------------------------
SCOPE = EngagementScope(
    name="Juice Shop Live Scan Test",
    targets=[
        ScopeEntry(value="172.20.0.2", type=ScopeType.IP),
    ],
)

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------
TOOL_TIMEOUT = 180  # seconds per tool execution


async def main() -> None:
    logger.info("=" * 70)
    logger.info("LIVE SCAN TEST — Gemini + Katana/Ffuf/Httpx vs Juice Shop (172.20.0.2)")
    logger.info("=" * 70)

    # 1. Create a real Gemini client
    logger.info("Creating GeminiClient...")
    llm = GeminiClient()
    logger.info("GeminiClient ready (model: %s)", llm._model_name)

    # 2. Build a ToolResolver restricted to scan-category tools
    resolver = ToolResolver()
    allowed_tools = {KatanaTool, FfufTool, HttpxTool}

    # Keep only katana/ffuf/httpx in the capability map
    filtered_caps = {
        cap: [cls for cls in classes if cls in allowed_tools]
        for cap, classes in resolver._capability_map.items()
    }
    resolver._capability_map = {k: v for k, v in filtered_caps.items() if v}
    resolver._name_map = {
        name: cls for name, cls in resolver._name_map.items() if cls in allowed_tools
    }

    logger.info(
        "ToolResolver restricted to: capabilities=%s, tools=%s",
        list(resolver._capability_map.keys()),
        list(resolver._name_map.keys()),
    )

    # 3. Set up the state store (temp file)
    db_path = Path("live_scan_test.db")
    async with StateStore(db_path) as state:
        engagement_id = await state.create_engagement(
            "Juice Shop Live Scan Test", SCOPE.model_dump()
        )
        logger.info("Engagement created: %s", engagement_id)

        # 4. Create ScanAgent with the real LLM and restricted resolver
        katana = KatanaTool(scope=SCOPE, timeout=TOOL_TIMEOUT)
        ffuf = FfufTool(scope=SCOPE, timeout=TOOL_TIMEOUT)
        httpx = HttpxTool(scope=SCOPE, timeout=TOOL_TIMEOUT)

        agent = ScanAgent(
            llm=llm,
            tools=[katana, ffuf, httpx],
            scope=SCOPE,
            state=state,
            engagement_id=engagement_id,
            resolver=resolver,
        )

        # 5. Run the agent with recon context and a focused task
        logger.info("Starting ScanAgent...")
        logger.info("-" * 70)

        result = await agent.run({
            "urls": ["http://172.20.0.2:80"],
            "task": (
                "Crawl and map the attack surface of http://172.20.0.2:80. "
                "Context from recon: Target 172.20.0.2 has port 80 open running "
                "Apache 2.4.25 with DVWA v1.10 at http://172.20.0.2:80. "
                "Start with web_crawling to discover endpoints, then try "
                "directory_fuzzing to find hidden paths. Use http_probing to "
                "fingerprint interesting endpoints. "
                "After mapping the attack surface, provide your final_answer "
                "with a structured summary of all discovered endpoints and paths."
            ),
        })

        # 6. Print results
        logger.info("=" * 70)
        logger.info("SCAN AGENT COMPLETE")
        logger.info("=" * 70)

        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(result.get("summary", "(no summary)"))

        print("\n" + "=" * 70)
        print("DISCOVERED ENDPOINTS")
        print("=" * 70)
        for ep in result.get("endpoints", []):
            print(f"  {ep}")

        print("\n" + "=" * 70)
        print("TOKEN USAGE")
        print("=" * 70)
        print(f"  Input tokens:  {llm.total_input_tokens}")
        print(f"  Output tokens: {llm.total_output_tokens}")
        print(f"  Total tokens:  {llm.total_tokens}")

    # Clean up temp db
    if db_path.exists():
        db_path.unlink()
        logger.info("Cleaned up %s", db_path)


if __name__ == "__main__":
    asyncio.run(main())
