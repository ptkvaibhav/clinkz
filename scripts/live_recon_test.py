"""Live integration test: Recon Agent + real Gemini LLM + real Nmap vs Juice Shop.

Runs the full ReAct loop with a real GeminiClient and NmapTool executing
inside the clinkz-tools Docker container against 172.20.0.2 (Juice Shop).

Usage:
    python scripts/live_recon_test.py
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

from clinkz.agents.recon import ReconAgent  # noqa: E402
from clinkz.llm.gemini_client import GeminiClient  # noqa: E402
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType  # noqa: E402
from clinkz.state import StateStore  # noqa: E402
from clinkz.tools.nmap import NmapTool  # noqa: E402
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

logger = logging.getLogger("live_recon_test")

# ---------------------------------------------------------------------------
# Scope: only Juice Shop
# ---------------------------------------------------------------------------
SCOPE = EngagementScope(
    name="Juice Shop Live Test",
    targets=[
        ScopeEntry(value="172.20.0.2", type=ScopeType.IP),
    ],
)

# ---------------------------------------------------------------------------
# Timeouts
# ---------------------------------------------------------------------------
LLM_TIMEOUT = 15  # seconds per LLM call (not used directly — Gemini client has its own)
NMAP_TIMEOUT = 120  # seconds for nmap execution


async def main() -> None:
    logger.info("=" * 70)
    logger.info("LIVE RECON TEST — Gemini + Nmap vs Juice Shop (172.20.0.2)")
    logger.info("=" * 70)

    # 1. Create a real Gemini client
    logger.info("Creating GeminiClient...")
    llm = GeminiClient()
    logger.info("GeminiClient ready (model: %s)", llm._model_name)

    # 2. Build a ToolResolver with ONLY Nmap registered
    #    We do this by creating a resolver and clearing everything except nmap.
    resolver = ToolResolver()
    # Keep only nmap in the capability map
    nmap_caps = {
        cap: [cls for cls in classes if cls is NmapTool]
        for cap, classes in resolver._capability_map.items()
    }
    resolver._capability_map = {k: v for k, v in nmap_caps.items() if v}
    resolver._name_map = {
        name: cls for name, cls in resolver._name_map.items() if cls is NmapTool
    }

    logger.info(
        "ToolResolver restricted to: capabilities=%s, tools=%s",
        list(resolver._capability_map.keys()),
        list(resolver._name_map.keys()),
    )

    # 3. Set up the state store (in-memory via temp file)
    db_path = Path("live_recon_test.db")
    async with StateStore(db_path) as state:
        engagement_id = await state.create_engagement(
            "Juice Shop Live Test", SCOPE.model_dump()
        )
        logger.info("Engagement created: %s", engagement_id)

        # 4. Create ReconAgent with the real LLM and restricted resolver
        nmap_tool = NmapTool(scope=SCOPE, timeout=NMAP_TIMEOUT)
        agent = ReconAgent(
            llm=llm,
            tools=[nmap_tool],
            scope=SCOPE,
            state=state,
            engagement_id=engagement_id,
            resolver=resolver,
        )

        # 5. Run the agent with a focused task
        logger.info("Starting ReconAgent...")
        logger.info("-" * 70)

        result = await agent.run({
            "targets": ["172.20.0.2"],
            "task": "Perform port scanning on 172.20.0.2. "
            "Focus on finding open ports and identifying services. "
            "Only use port_scanning capability. "
            "Scan common web ports (80, 443, 3000, 8080, 8443). "
            "After scanning, provide your final_answer with the results.",
        })

        # 6. Print results
        logger.info("=" * 70)
        logger.info("RECON AGENT COMPLETE")
        logger.info("=" * 70)

        print("\n" + "=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(result.get("summary", "(no summary)"))

        print("\n" + "=" * 70)
        print("DISCOVERED HOSTS")
        print("=" * 70)
        for host in result.get("hosts", []):
            print(f"  Host: {host}")

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
