"""Live full recon: ReconAgent + real Gemini LLM + ALL recon tools vs Juice Shop.

Runs the full ReAct loop with a real GeminiClient and every recon-category
tool (nmap, subfinder, httpx, whatweb, wafw00f) executing inside the
clinkz-tools Docker container against 172.20.0.2 (Juice Shop).

Features:
- 15-second delay between LLM calls (free-tier safe)
- 180-second timeout per tool execution
- Verbose printing of every LLM decision and tool result
- Continues on tool failure

Usage:
    python scripts/live_full_recon.py
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

# Ensure project root is on sys.path for local dev
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Force docker execution mode before importing anything that reads settings
os.environ.setdefault("TOOL_EXEC_MODE", "docker")
os.environ.setdefault("DOCKER_CONTAINER", "clinkz-tools")
os.environ.setdefault("LLM_PROVIDER", "gemini")

from clinkz.agents.recon import ReconAgent  # noqa: E402
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall  # noqa: E402
from clinkz.llm.gemini_client import GeminiClient  # noqa: E402
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType  # noqa: E402
from clinkz.state import StateStore  # noqa: E402
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

logger = logging.getLogger("live_full_recon")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TARGET = "172.20.0.2"
LLM_DELAY = 15  # seconds between LLM calls (free tier)
TOOL_TIMEOUT = 180  # seconds per tool execution

SCOPE = EngagementScope(
    name="Juice Shop Full Recon",
    targets=[
        ScopeEntry(value=TARGET, type=ScopeType.IP),
    ],
)


# ---------------------------------------------------------------------------
# Instrumented LLM wrapper — adds delay + verbose printing
# ---------------------------------------------------------------------------


class InstrumentedGeminiClient(LLMClient):
    """Wraps GeminiClient with a delay between calls and verbose output."""

    def __init__(self, inner: GeminiClient, delay: float = LLM_DELAY) -> None:
        self._inner = inner
        self._delay = delay
        self._call_count = 0

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._call_count += 1
        call_num = self._call_count

        # Delay between LLM calls (skip first call)
        if call_num > 1:
            print(f"\n{'='*70}")
            print(f"  Waiting {self._delay}s before LLM call #{call_num} (free tier)")
            print(f"{'='*70}")
            await asyncio.sleep(self._delay)

        print(f"\n{'#'*70}")
        print(f"  LLM CALL #{call_num}")
        print(f"{'#'*70}")

        start = time.monotonic()
        action = await self._inner.reason(messages, tools)
        elapsed = time.monotonic() - start

        print(f"  Response time: {elapsed:.1f}s")
        print(f"  Tokens so far: in={self._inner.total_input_tokens} "
              f"out={self._inner.total_output_tokens}")

        if action.thought:
            print(f"\n  THOUGHT:")
            for line in action.thought.strip().split("\n"):
                print(f"    {line}")

        if action.tool_call:
            print(f"\n  ACTION: call tool '{action.tool_call.name}'")
            print(f"  ARGUMENTS: {action.tool_call.arguments}")

        if action.final_answer is not None:
            print(f"\n  FINAL ANSWER (first 500 chars):")
            for line in action.final_answer[:500].split("\n"):
                print(f"    {line}")
            if len(action.final_answer) > 500:
                print(f"    ... ({len(action.final_answer)} chars total)")

        return action

    async def research(self, query: str) -> str:
        return await self._inner.research(query)

    async def generate_text(self, prompt: str) -> str:
        return await self._inner.generate_text(prompt)

    @property
    def total_input_tokens(self) -> int:
        return self._inner.total_input_tokens

    @property
    def total_output_tokens(self) -> int:
        return self._inner.total_output_tokens

    @property
    def total_tokens(self) -> int:
        return self._inner.total_tokens


# ---------------------------------------------------------------------------
# Instrumented ReconAgent — prints tool results
# ---------------------------------------------------------------------------


class VerboseReconAgent(ReconAgent):
    """ReconAgent that prints every tool result and uses custom tool timeout."""

    def __init__(self, *a: Any, tool_timeout: int = TOOL_TIMEOUT, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self._tool_timeout = tool_timeout

    async def _resolve_and_execute(self, args: dict[str, Any]) -> str:
        """Resolve capability, execute with custom timeout, print everything."""
        capability: str = args.get("capability", "").strip()
        tool_args: dict[str, Any] = args.get("arguments") or {}

        print(f"\n{'~'*70}")
        print(f"  TOOL EXECUTION")
        print(f"  Capability: {capability}")
        print(f"  Arguments:  {tool_args}")
        print(f"{'~'*70}")

        if not capability:
            return "Error: 'capability' is required."

        match = self._resolver.find_tool(capability)
        if match is None:
            msg = f"No tool registered for capability '{capability}'."
            print(f"  {msg}")
            return msg
        if not match.available:
            msg = (
                f"Tool '{match.name}' for '{capability}' is not installed. "
                "Try a different capability."
            )
            print(f"  {msg}")
            return msg
        if match.tool_class is None:
            msg = f"Tool '{match.name}' has no local class (MCP-only)."
            print(f"  {msg}")
            return msg

        print(f"  Resolved: {capability} -> {match.name}")

        # Create tool with custom timeout
        tool = match.tool_class(scope=self.scope, timeout=self._tool_timeout)

        action_id = await self.state.log_action(
            engagement_id=self.engagement_id,
            phase=self.name,
            agent=self.__class__.__name__,
            tool=match.name,
            input_data=tool_args,
        )

        start = time.monotonic()
        try:
            validated = tool.validate_input(tool_args)
            raw_output = await tool.execute(validated)
            parsed = tool.parse_output(raw_output)

            await self.state.complete_action(action_id, output_data=parsed.model_dump())
            await self._persist_tool_output(parsed)

            result = parsed.model_dump_json(indent=2)
            elapsed = time.monotonic() - start

            # Print result summary
            print(f"\n  TOOL RESULT ({elapsed:.1f}s, {len(result)} chars):")
            for line in result[:1500].split("\n"):
                print(f"    {line}")
            if len(result) > 1500:
                print(f"    ... ({len(result)} chars total)")

            return result

        except Exception as exc:
            elapsed = time.monotonic() - start
            print(f"\n  TOOL FAILED after {elapsed:.1f}s: {exc}")
            await self.state.complete_action(
                action_id,
                output_data={"error": str(exc)},
                status="failed",
            )
            return f"Tool '{match.name}' failed: {exc}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=" * 70)
    print("  LIVE FULL RECON — Gemini + ALL Tools vs Juice Shop (172.20.0.2)")
    print("=" * 70)

    # 1. Verify docker container is running
    print("\nChecking Docker container...")
    proc = await asyncio.create_subprocess_exec(
        "docker", "exec", "clinkz-tools", "echo", "ok",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        print(f"ERROR: clinkz-tools container not running: {stderr.decode()}")
        print("Start it with: docker compose -f docker/docker-compose.yml up -d")
        sys.exit(1)
    print("  clinkz-tools container: OK")

    # 2. Create instrumented Gemini client
    print("\nCreating GeminiClient...")
    # Try multiple models — free tier has separate quotas per model
    model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")
    raw_llm = GeminiClient(model=model)
    llm = InstrumentedGeminiClient(raw_llm, delay=LLM_DELAY)
    print(f"  Model: {raw_llm._model_name}")

    # 3. Build ToolResolver with ALL recon tools
    resolver = ToolResolver()

    # Show what's available
    recon_tools = resolver.get_tools_by_category("recon")
    print(f"\nRecon tools registered: {recon_tools}")

    all_caps = resolver.get_all_capabilities()
    print(f"All capabilities: {all_caps}")

    # Check which tools are actually available in Docker
    print("\nTool availability (inside Docker):")
    for tool_name in recon_tools:
        available = resolver.is_available(tool_name)
        status = "AVAILABLE" if available else "MISSING"
        print(f"  {tool_name}: {status}")

    # 4. Set up state store
    db_path = Path("live_full_recon.db")
    async with StateStore(db_path) as state:
        engagement_id = await state.create_engagement(
            "Juice Shop Full Recon", SCOPE.model_dump()
        )
        print(f"\nEngagement: {engagement_id}")

        # 5. Create VerboseReconAgent with all tools and full resolver
        agent = VerboseReconAgent(
            llm=llm,
            tools=[],  # Tools are resolved dynamically via the resolver
            scope=SCOPE,
            state=state,
            engagement_id=engagement_id,
            resolver=resolver,
        )

        # 6. Run the agent
        print(f"\n{'='*70}")
        print("  STARTING RECON AGENT")
        print(f"  Target: {TARGET}")
        print(f"  LLM delay: {LLM_DELAY}s between calls")
        print(f"  Tool timeout: {TOOL_TIMEOUT}s per tool")
        print(f"{'='*70}\n")

        overall_start = time.monotonic()

        result = await agent.run({
            "targets": [TARGET],
            "task": (
                f"Perform complete reconnaissance on {TARGET}. "
                "This is a local Juice Shop instance running in Docker. "
                "It is an IP address, not a domain, so skip subdomain_enumeration. "
                "Run the following capabilities in order:\n"
                "1. port_scanning — scan all common ports to find open services\n"
                "2. http_probing — probe discovered HTTP ports for status, titles, tech\n"
                "3. web_fingerprinting — identify the full technology stack\n"
                "4. waf_detection — check for WAF presence\n"
                "After running all tools, provide your final_answer with a complete "
                "summary of all findings."
            ),
        })

        overall_elapsed = time.monotonic() - overall_start

        # 7. Print final results
        print(f"\n{'='*70}")
        print("  RECON AGENT COMPLETE")
        print(f"  Total time: {overall_elapsed:.0f}s")
        print(f"{'='*70}")

        print(f"\n{'='*70}")
        print("  FULL SUMMARY")
        print(f"{'='*70}")
        print(result.get("summary", "(no summary)"))

        print(f"\n{'='*70}")
        print("  DISCOVERED HOSTS")
        print(f"{'='*70}")
        hosts = result.get("hosts", [])
        if hosts:
            for host in hosts:
                print(f"  {host}")
        else:
            print("  (none persisted to state store)")

        print(f"\n{'='*70}")
        print("  ACTIONS LOG")
        print(f"{'='*70}")
        actions = await state.get_actions(engagement_id)
        for action in actions:
            tool = action.get("tool", "?")
            status = action.get("status", "?")
            print(f"  [{status}] {tool}")

        print(f"\n{'='*70}")
        print("  TOKEN USAGE")
        print(f"{'='*70}")
        print(f"  Input tokens:  {llm.total_input_tokens}")
        print(f"  Output tokens: {llm.total_output_tokens}")
        print(f"  Total tokens:  {llm.total_tokens}")
        print(f"  LLM calls:     {llm._call_count}")

    # Clean up temp db
    if db_path.exists():
        db_path.unlink()
        logger.info("Cleaned up %s", db_path)


if __name__ == "__main__":
    asyncio.run(main())
