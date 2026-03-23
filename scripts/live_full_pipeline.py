"""Live full pipeline: Complete Orchestrator-driven pentest against DVWA.

Runs the ENTIRE multi-agent pentest pipeline against DVWA (172.20.0.2)
using the real OrchestratorAgent, real GeminiClient, and real tools
via Docker exec.

Pipeline:
  1. Orchestrator spins up Recon Agent -> discovers hosts/services
  2. Reviews recon, spins up Scan Agent -> maps attack surface
  3. Reviews scan, spins up Exploit Agent -> exploits vulnerabilities
  4. Reviews exploit, spins up Critic Agent -> validates findings
  5. Spins up Report Agent -> generates final pentest report

Features:
- Real GeminiClient for ALL agents (shared LLM instance)
- Real tools (nmap, httpx, ffuf, nuclei, sqlmap, etc.) via Docker exec
- 10-second delay between LLM calls (free-tier safe)
- Max 5 iterations per phase agent (token conservation)
- 30-minute total engagement timeout
- Verbose output: every Orchestrator decision, agent lifecycle event,
  tool execution, and finding
- Final report saved to outputs/dvwa_pentest_report.json

Usage:
    python scripts/live_full_pipeline.py
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Path setup — ensure project root is importable
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Force docker execution mode before importing anything that reads settings
os.environ.setdefault("TOOL_EXEC_MODE", "docker")
os.environ.setdefault("DOCKER_CONTAINER", "clinkz-tools")
os.environ.setdefault("LLM_PROVIDER", "gemini")

# ---------------------------------------------------------------------------
# Monkey-patch MAX_ITERATIONS BEFORE importing agents
# ---------------------------------------------------------------------------
import clinkz.agents.base  # noqa: E402

clinkz.agents.base.MAX_ITERATIONS = 5  # conserve tokens: 5 iterations per agent

from clinkz.llm.base import AgentAction, LLMClient, LLMMessage, ToolCall  # noqa: E402
from clinkz.llm.gemini_client import GeminiClient  # noqa: E402
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType  # noqa: E402
from clinkz.orchestrator.orchestrator import OrchestratorAgent  # noqa: E402
from clinkz.state import StateStore  # noqa: E402

# ---------------------------------------------------------------------------
# Logging — show everything
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
# Quiet noisy libraries
for noisy in ("httpcore", "httpx", "urllib3", "google", "grpc", "aiosqlite"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

logger = logging.getLogger("live_full_pipeline")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
def _get_container_ip(container_name: str) -> str:
    """Get the IP address of a running Docker container."""
    import subprocess

    result = subprocess.run(
        [
            "docker", "inspect", container_name,
            "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Cannot get IP for container '{container_name}': {result.stderr.strip()}"
        )
    ip = result.stdout.strip()
    if not ip:
        raise RuntimeError(f"Container '{container_name}' has no IP — is it running?")
    return ip


TARGET = _get_container_ip("clinkz-dvwa")
LLM_DELAY = 10  # seconds between LLM calls
TOTAL_TIMEOUT = 1800  # 30 minutes
DB_PATH = Path("outputs/dvwa_pipeline.db")
REPORT_PATH = Path("outputs/dvwa_pentest_report.json")

SCOPE = EngagementScope(
    name="DVWA Full Pipeline Test",
    targets=[ScopeEntry(value=TARGET, type=ScopeType.IP)],
)


# ---------------------------------------------------------------------------
# Instrumented LLM wrapper — delay + verbose printing for every call type
# ---------------------------------------------------------------------------


class InstrumentedGeminiClient(LLMClient):
    """Wraps GeminiClient with a delay between calls and verbose output.

    Instruments all three LLM methods: reason(), research(), generate_text().
    """

    def __init__(self, inner: GeminiClient, delay: float = LLM_DELAY) -> None:
        self._inner = inner
        self._delay = delay
        self._call_count = 0

    async def _wait(self, call_num: int, label: str) -> None:
        """Wait between LLM calls (skip the very first call)."""
        if call_num > 1:
            print(f"\n{'='*70}")
            print(f"  Waiting {self._delay}s before {label} #{call_num} (free tier)")
            print(f"{'='*70}")
            await asyncio.sleep(self._delay)

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        self._call_count += 1
        n = self._call_count
        await self._wait(n, "REASON")

        print(f"\n{'#'*70}")
        print(f"  LLM REASON #{n}")
        print(f"{'#'*70}")

        start = time.monotonic()
        action = await self._inner.reason(messages, tools)
        elapsed = time.monotonic() - start

        print(f"  Response time: {elapsed:.1f}s")
        print(f"  Tokens: in={self._inner.total_input_tokens} "
              f"out={self._inner.total_output_tokens}")

        if action.thought:
            lines = action.thought.strip()[:400]
            print(f"\n  THOUGHT:")
            for line in lines.split("\n"):
                print(f"    {line}")

        if action.tool_call:
            args_str = json.dumps(action.tool_call.arguments)[:300]
            print(f"\n  ACTION: {action.tool_call.name}")
            print(f"  ARGS: {args_str}")

        if action.final_answer is not None:
            print(f"\n  FINAL ANSWER ({len(action.final_answer)} chars):")
            for line in action.final_answer[:400].split("\n"):
                print(f"    {line}")
            if len(action.final_answer) > 400:
                print(f"    ... ({len(action.final_answer)} chars total)")

        return action

    async def research(self, query: str) -> str:
        self._call_count += 1
        n = self._call_count
        await self._wait(n, "RESEARCH")

        print(f"\n{'*'*70}")
        print(f"  RESEARCH #{n}")
        print(f"  Query: {query[:120]}")
        print(f"{'*'*70}")

        start = time.monotonic()
        result = await self._inner.research(query)
        elapsed = time.monotonic() - start

        print(f"  Research time: {elapsed:.1f}s")
        print(f"  Tokens: in={self._inner.total_input_tokens} "
              f"out={self._inner.total_output_tokens}")
        print(f"\n  RESULT ({len(result)} chars):")
        for line in result[:500].split("\n"):
            print(f"    {line}")
        if len(result) > 500:
            print(f"    ... ({len(result)} chars total)")

        return result

    async def generate_text(self, prompt: str) -> str:
        self._call_count += 1
        n = self._call_count
        await self._wait(n, "GENERATE")

        # Show a short label from the prompt
        first_line = prompt.split("\n")[0][:80]
        print(f"\n{'+'*70}")
        print(f"  GENERATE TEXT #{n}")
        print(f"  Prompt: {first_line}...")
        print(f"{'+'*70}")

        start = time.monotonic()
        result = await self._inner.generate_text(prompt)
        elapsed = time.monotonic() - start

        print(f"  Generate time: {elapsed:.1f}s")
        print(f"  Tokens: in={self._inner.total_input_tokens} "
              f"out={self._inner.total_output_tokens}")
        print(f"\n  RESULT ({len(result)} chars):")
        for line in result[:400].split("\n"):
            print(f"    {line}")
        if len(result) > 400:
            print(f"    ... ({len(result)} chars total)")

        return result

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
# Verbose Orchestrator — prints every decision
# ---------------------------------------------------------------------------


class VerboseOrchestratorAgent(OrchestratorAgent):
    """OrchestratorAgent with verbose action printing and graceful shutdown."""

    async def _execute_action(
        self, tool_call: ToolCall
    ) -> tuple[str, bool]:
        """Print every orchestrator decision before executing it."""
        name = tool_call.name
        args = tool_call.arguments

        print(f"\n{'>'*70}")
        print(f"  ORCHESTRATOR DECISION: {name}")
        for k, v in args.items():
            val_str = str(v)[:250]
            print(f"    {k}: {val_str}")
        print(f"{'>'*70}")

        result_text, is_complete = await super()._execute_action(tool_call)

        print(f"  RESULT: {result_text[:250]}")
        if is_complete:
            print(f"\n  {'*'*50}")
            print(f"  *** ENGAGEMENT COMPLETE ***")
            print(f"  {'*'*50}")

        return result_text, is_complete

    async def run(self, scope: EngagementScope) -> dict[str, Any]:
        """Run engagement with graceful agent shutdown on completion."""
        result = await super().run(scope)

        # Shut down any still-running agent tasks
        if self._lifecycle is not None:
            running = self._lifecycle.get_running_agents()
            if running:
                print(f"\n  Shutting down remaining agents: {running}")
                for agent_name in running:
                    try:
                        await self._lifecycle.shut_down(agent_name)
                        print(f"    Stopped: {agent_name}")
                    except Exception as exc:
                        print(f"    Failed to stop {agent_name}: {exc}")

        return result


# ---------------------------------------------------------------------------
# Post-engagement summary — reads from the DB
# ---------------------------------------------------------------------------


async def print_engagement_summary(
    db_path: Path,
    raw_llm: GeminiClient,
    llm: InstrumentedGeminiClient,
    result: dict[str, Any],
    elapsed: float,
) -> None:
    """Read the engagement DB and print a full summary."""
    print(f"\n{'='*70}")
    print("ENGAGEMENT SUMMARY")
    print(f"{'='*70}")
    print(f"  Status:   {result.get('status', 'unknown')}")
    print(f"  Summary:  {result.get('summary', 'N/A')[:300]}")
    print(f"  Duration: {elapsed:.0f}s ({elapsed / 60:.1f} min)")

    if not db_path.exists():
        print("  (No database file found — cannot extract details)")
        return

    async with StateStore(db_path) as state:
        # Find the engagement
        async with state._conn.execute(
            "SELECT id FROM engagements LIMIT 1"
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            print("  (No engagement found in database)")
            return

        eid = row["id"]
        findings = await state.get_findings(eid)
        targets = await state.get_targets(eid)
        actions = await state.get_actions(eid)
        messages = await state.get_messages(eid)

        # --- Targets ---
        print(f"\n{'-'*70}")
        print(f"DISCOVERED TARGETS ({len(targets)})")
        print(f"{'-'*70}")
        for t in targets[:30]:
            ip = t.get("ip", "unknown")
            tags = t.get("tags", [])
            services = t.get("services", [])
            svc_str = ""
            if services:
                svc_str = " | ports: " + ", ".join(
                    f"{s.get('port', '?')}/{s.get('name', '?')}"
                    for s in services[:5]
                )
            print(f"  {ip}{svc_str} {tags}")
        if len(targets) > 30:
            print(f"  ... and {len(targets) - 30} more")

        # --- Findings ---
        print(f"\n{'-'*70}")
        print(f"FINDINGS ({len(findings)})")
        print(f"{'-'*70}")
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "info").upper()
            title = f.get("title", "Untitled")
            target = f.get("target", "?")
            status = f.get("status", "new")
            confirmed = "CONFIRMED" if status == "confirmed" else "UNCONFIRMED"
            print(f"  [{i}] [{sev}] {title}")
            print(f"       Target: {target} | Status: {confirmed}")
            if f.get("cvss_score"):
                print(f"       CVSS: {f['cvss_score']}")
            if f.get("cve_ids"):
                print(f"       CVEs: {f['cve_ids']}")
            if f.get("evidence"):
                for ev in f["evidence"][:2]:
                    print(f"       Evidence: {str(ev)[:150]}")
            if f.get("remediation"):
                print(f"       Fix: {f['remediation'][:150]}")

        # --- Tool executions ---
        print(f"\n{'-'*70}")
        print(f"TOOL EXECUTIONS ({len(actions)})")
        print(f"{'-'*70}")
        for a in actions:
            tool = a.get("tool", "N/A")
            phase = a.get("phase", "?")
            status = a.get("status", "?")
            created = a.get("created_at", "")[:19]
            print(f"  [{phase:8s}] {tool:20s} -> {status:10s} ({created})")

        # --- Message flow ---
        print(f"\n{'-'*70}")
        print(f"AGENT MESSAGE FLOW ({len(messages)})")
        print(f"{'-'*70}")
        for m in messages:
            from_a = m.get("from_agent", "?")
            to_a = m.get("to_agent", "?")
            mtype = m.get("message_type", "?")
            ts = m.get("timestamp", "")[:19]
            # Show content preview for result/status messages
            content_raw = m.get("content_json", "{}")
            try:
                content = json.loads(content_raw) if isinstance(content_raw, str) else content_raw
            except (json.JSONDecodeError, TypeError):
                content = {}
            preview = ""
            if mtype in ("result", "status"):
                if isinstance(content, dict):
                    status_val = content.get("status", "")
                    summary_val = content.get("summary", "")[:80]
                    if status_val:
                        preview = f" | status={status_val}"
                    if summary_val:
                        preview += f" | {summary_val}"
            print(f"  {ts} {from_a:12s} -> {to_a:12s} [{mtype:8s}]{preview}")

        # --- Save report JSON ---
        report_data = {
            "engagement": {
                "id": eid,
                "name": "DVWA Full Pipeline Test",
                "target": TARGET,
                "status": result.get("status"),
                "summary": result.get("summary"),
                "duration_seconds": round(elapsed, 1),
            },
            "targets": targets,
            "findings": findings,
            "actions": [
                {k: v for k, v in a.items() if k != "output_json"}
                for a in actions
            ],
            "messages": messages,
            "token_usage": {
                "input_tokens": raw_llm.total_input_tokens,
                "output_tokens": raw_llm.total_output_tokens,
                "total_tokens": raw_llm.total_tokens,
                "llm_calls": llm._call_count,
            },
        }

        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        REPORT_PATH.write_text(
            json.dumps(report_data, indent=2, default=str), encoding="utf-8"
        )
        print(f"\nReport saved to: {REPORT_PATH}")

    # --- Token usage ---
    print(f"\n{'-'*70}")
    print("TOKEN USAGE")
    print(f"{'-'*70}")
    print(f"  Input tokens:  {raw_llm.total_input_tokens:,}")
    print(f"  Output tokens: {raw_llm.total_output_tokens:,}")
    print(f"  Total tokens:  {raw_llm.total_tokens:,}")
    print(f"  LLM calls:     {llm._call_count}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def main() -> None:
    print("=" * 70)
    print("CLINKZ FULL PIPELINE — Orchestrator-driven pentest vs DVWA")
    print("=" * 70)
    print(f"  Target:          {TARGET}")
    print(f"  LLM delay:       {LLM_DELAY}s between calls")
    print(f"  Max iterations:  5 per phase agent")
    print(f"  Total timeout:   {TOTAL_TIMEOUT}s ({TOTAL_TIMEOUT // 60} min)")
    print(f"  DB path:         {DB_PATH}")
    print(f"  Report path:     {REPORT_PATH}")
    print("=" * 70)

    # 1. Create the real Gemini client + instrumented wrapper
    logger.info("Creating GeminiClient...")
    raw_llm = GeminiClient()
    llm = InstrumentedGeminiClient(raw_llm, delay=LLM_DELAY)
    logger.info("GeminiClient ready (model: %s)", raw_llm._model_name)

    # 2. Ensure output directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Clean up any leftover DB from a previous run
    if DB_PATH.exists():
        DB_PATH.unlink()

    # 3. Create the verbose orchestrator
    orchestrator = VerboseOrchestratorAgent(llm=llm, db_path=DB_PATH)

    # 4. Run the full engagement with a 30-minute timeout
    print(f"\n{'='*70}")
    print("STARTING ENGAGEMENT")
    print(f"{'='*70}\n")

    start_time = time.monotonic()
    try:
        result = await asyncio.wait_for(
            orchestrator.run(SCOPE),
            timeout=TOTAL_TIMEOUT,
        )
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start_time
        print(f"\n{'!'*70}")
        print(f"  ENGAGEMENT TIMED OUT after {elapsed:.0f}s ({elapsed / 60:.1f} min)")
        print(f"{'!'*70}")
        result = {
            "status": "timeout",
            "summary": f"Engagement timed out after {elapsed / 60:.1f} minutes.",
        }
    except KeyboardInterrupt:
        elapsed = time.monotonic() - start_time
        print(f"\n{'!'*70}")
        print(f"  ENGAGEMENT INTERRUPTED after {elapsed:.0f}s")
        print(f"{'!'*70}")
        result = {
            "status": "interrupted",
            "summary": f"Engagement interrupted after {elapsed / 60:.1f} minutes.",
        }
    except Exception as exc:
        elapsed = time.monotonic() - start_time
        logger.error("Engagement crashed: %s", exc, exc_info=True)
        result = {
            "status": "failed",
            "summary": f"Engagement failed: {exc}",
            "error": str(exc),
        }
    else:
        elapsed = time.monotonic() - start_time

    # 5. Print full engagement summary and save report
    await print_engagement_summary(DB_PATH, raw_llm, llm, result, elapsed)

    # 6. Clean up temp DB (report already saved as JSON)
    if DB_PATH.exists():
        DB_PATH.unlink()
        logger.info("Cleaned up %s", DB_PATH)

    print(f"\n{'='*70}")
    print("DONE")
    print(f"{'='*70}")


if __name__ == "__main__":
    asyncio.run(main())
