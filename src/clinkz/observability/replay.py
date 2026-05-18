"""Agent step replay harness — re-run one recorded step in isolation.

The :class:`StepReplayer` reads a recorded step input file under
``outputs/<engagement_id>/step_inputs/<step_id>.json`` and re-runs the
exact step method on a fresh agent instance — without spinning up the
whole pipeline.

When something breaks mid-engagement, the cost of "rerun the whole
pipeline to reproduce" is minutes plus container restarts. Replaying a
single step is seconds.

Replay loop:

1. Load the recorded step inputs (full payload, agent class, method name,
   engagement scope, llm provider).
2. Re-create the engagement scope from the recorded data.
3. Construct a fresh in-memory ``StateStore`` and a default ``ToolResolver``.
4. Build the LLM client via the same factory the orchestrator uses, so
   the replayed step talks to the same provider (subject to env-var
   overrides — the replayer is deliberately opinionated about *fresh*
   LLM calls; replay is for re-exercising tools and deterministic logic).
5. Instantiate the agent and call the recorded method with the recorded
   args.
6. Capture the new output, compare it against the recorded summary if
   one exists in the trace, return a :class:`ReplayResult`.

Re-instantiating the *whole* agent on every replay is intentional. A step
on its own has very little context — the agent's ``__init__`` is the
contract for what the step needs to run.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from clinkz.models.scope import EngagementScope
from clinkz.observability.invocations import StepInputRecorder

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class ReplayDiff:
    """The diff between an original step output and its replay.

    For now this is a coarse "same / different" verdict plus the raw
    JSON-rendered comparison. A future revision can switch to a structured
    diff (per-field) if callers need that granularity.
    """

    identical: bool
    original_summary: str
    replayed_summary: str
    notes: list[str] = field(default_factory=list)


@dataclass
class ReplayResult:
    """The outcome of one StepReplayer.replay() call."""

    step_id: str
    agent: str
    step_name: str
    method_name: str
    succeeded: bool
    error: str | None = None
    original_output: Any = None
    replayed_output: Any = None
    diff: ReplayDiff | None = None


# ---------------------------------------------------------------------------
# Agent class resolution
# ---------------------------------------------------------------------------


#: Maps the recorded ``agent_class`` field back to ``(module, class)``.
#: Kept narrow on purpose — replay should only target deterministic v2
#: agents. If you add a new agent that wraps steps via ``_record_step``,
#: add it here too.
_AGENT_CLASS_MAP: dict[str, tuple[str, str]] = {
    "ReconAgent": ("clinkz.agents.recon", "ReconAgent"),
    "ScanAgent": ("clinkz.agents.scan", "ScanAgent"),
    "ExploitAgent": ("clinkz.agents.exploit", "ExploitAgent"),
    "ResearchAgent": ("clinkz.agents.research", "ResearchAgent"),
    "ReportAgent": ("clinkz.agents.report", "ReportAgent"),
    "CriticAgent": ("clinkz.agents.critic", "CriticAgent"),
}


def _load_agent_class(class_name: str) -> type[Any]:
    """Resolve an agent class name recorded in the step inputs.

    Raises:
        KeyError: If the class name isn't in the known map.
        ImportError: If the module cannot be loaded.
    """
    if class_name not in _AGENT_CLASS_MAP:
        raise KeyError(f"Unknown agent class '{class_name}'. Known: {sorted(_AGENT_CLASS_MAP)}")
    module_name, klass_name = _AGENT_CLASS_MAP[class_name]
    module = importlib.import_module(module_name)
    return getattr(module, klass_name)


# ---------------------------------------------------------------------------
# StepReplayer
# ---------------------------------------------------------------------------


class StepReplayer:
    """Re-run one captured agent step against a fresh agent instance.

    Args:
        engagement_id: Engagement whose ``step_inputs/`` directory to read.
        step_id: UUID of the step to replay (filename: ``<step_id>.json``).
        outputs_root: Root directory containing engagement subdirs. Defaults
            to ``outputs``.
        llm_provider: Optional provider override (defaults to whatever the
            agent's role configures via env vars).
    """

    def __init__(
        self,
        engagement_id: str,
        step_id: str,
        *,
        outputs_root: Path | str = Path("outputs"),
        llm_provider: str | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        self.step_id = step_id
        self.outputs_root = Path(outputs_root)
        self.llm_provider = llm_provider
        self._step_inputs = StepInputRecorder(
            engagement_id=engagement_id,
            outputs_root=self.outputs_root,
        )
        self._logger = logging.getLogger(f"{__name__}.StepReplayer")

    async def replay(self) -> ReplayResult:
        """Run the step in isolation and return the result."""
        try:
            payload = self._step_inputs.load(self.step_id)
        except FileNotFoundError:
            return ReplayResult(
                step_id=self.step_id,
                agent="",
                step_name="",
                method_name="",
                succeeded=False,
                error=f"No step_inputs file for step_id {self.step_id}",
            )

        agent_name = payload.get("agent", "")
        step_name = payload.get("step_name", "")
        replay_info = payload.get("replay", {}) or {}
        method_name = replay_info.get("method_name", "")
        agent_class_name = replay_info.get("agent_class", "")
        recorded_inputs = payload.get("inputs", {}) or {}

        if not method_name or not agent_class_name:
            return ReplayResult(
                step_id=self.step_id,
                agent=agent_name,
                step_name=step_name,
                method_name=method_name,
                succeeded=False,
                error=(
                    "Step input is missing replay.method_name or replay.agent_class. "
                    "Recorded steps must call BaseAgent._record_step with a method_name."
                ),
            )

        try:
            agent_cls = _load_agent_class(agent_class_name)
        except (KeyError, ImportError) as exc:
            return ReplayResult(
                step_id=self.step_id,
                agent=agent_name,
                step_name=step_name,
                method_name=method_name,
                succeeded=False,
                error=f"Could not load agent class '{agent_class_name}': {exc}",
            )

        self._logger.info(
            "Replaying step %s — %s.%s",
            self.step_id,
            agent_class_name,
            method_name,
        )

        try:
            agent_instance = await self._instantiate_agent(agent_cls)
        except Exception as exc:  # noqa: BLE001 — surface clearly in result
            return ReplayResult(
                step_id=self.step_id,
                agent=agent_name,
                step_name=step_name,
                method_name=method_name,
                succeeded=False,
                error=f"Could not instantiate agent: {exc}",
            )

        method = getattr(agent_instance, method_name, None)
        if method is None or not callable(method):
            return ReplayResult(
                step_id=self.step_id,
                agent=agent_name,
                step_name=step_name,
                method_name=method_name,
                succeeded=False,
                error=f"Agent has no callable method '{method_name}'",
            )

        try:
            outputs = await method(**recorded_inputs)
        except TypeError:
            # Fall back to positional dispatch when the step method was
            # written before keyword-only support (e.g., ``_step_port_scan(self, target)``).
            try:
                outputs = await method(*recorded_inputs.values())
            except Exception as exc:  # noqa: BLE001 — surface clearly in result
                return ReplayResult(
                    step_id=self.step_id,
                    agent=agent_name,
                    step_name=step_name,
                    method_name=method_name,
                    succeeded=False,
                    error=f"Method call failed (positional fallback): {exc}",
                )
        except Exception as exc:  # noqa: BLE001 — surface clearly in result
            return ReplayResult(
                step_id=self.step_id,
                agent=agent_name,
                step_name=step_name,
                method_name=method_name,
                succeeded=False,
                error=f"Method call failed: {exc}",
            )

        original_summary = self._lookup_original_output_summary()
        replayed_summary = _stringify(outputs)
        diff = ReplayDiff(
            identical=(original_summary.strip() == replayed_summary.strip()),
            original_summary=original_summary,
            replayed_summary=replayed_summary,
        )

        return ReplayResult(
            step_id=self.step_id,
            agent=agent_name,
            step_name=step_name,
            method_name=method_name,
            succeeded=True,
            original_output=original_summary,
            replayed_output=replayed_summary,
            diff=diff,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _instantiate_agent(self, agent_cls: type[Any]) -> Any:
        """Build a fresh agent instance suitable for one-shot step replay.

        Uses an in-memory SQLite state store and the default LLM factory.
        The scope is read from the engagement row if available; falls back
        to a permissive single-target scope when the database is missing.
        """
        from clinkz.llm.fallback import ResilientLLMClient
        from clinkz.state import StateStore

        scope = await self._load_scope()
        state = StateStore(":memory:")
        await state.connect()
        await state.create_engagement(scope.name, scope.model_dump())

        agent_role = agent_cls.__name__.lower().replace("agent", "")
        if self.llm_provider is not None:
            from clinkz.llm.factory import get_llm_client

            llm = get_llm_client(self.llm_provider)
        else:
            try:
                llm = ResilientLLMClient(agent_role=agent_role)
            except Exception:
                # Fall back to a stub LLM that raises if used. Steps that
                # don't call self.llm (port scan, service scan, web recon)
                # will still complete.
                from clinkz.llm.base import (
                    AgentAction,
                    LLMClient,
                    LLMMessage,
                )

                class _UnavailableLLM(LLMClient):
                    async def reason(
                        self,
                        messages: list[LLMMessage],
                        tools: list[dict[str, Any]] | None = None,
                    ) -> AgentAction:
                        raise RuntimeError("Replay: no LLM provider configured")

                    async def research(self, query: str) -> str:
                        raise RuntimeError("Replay: no LLM provider configured")

                    async def generate_text(self, prompt: str) -> str:
                        raise RuntimeError("Replay: no LLM provider configured")

                llm = _UnavailableLLM()

        return agent_cls(
            llm=llm,
            tools=[],
            scope=scope,
            state=state,
            engagement_id=self.engagement_id,
        )

    async def _load_scope(self) -> EngagementScope:
        """Reconstruct the engagement scope from disk or fall back to a stub.

        Looks at the recorded step inputs first (in case the agent stored
        the scope there), then at the engagement row in the per-engagement
        state DB if one exists alongside ``outputs/``. As a last resort,
        builds a permissive scope covering ``0.0.0.0/0`` so the agent's
        scope check doesn't immediately reject every target.
        """
        from clinkz.models.scope import ScopeEntry, ScopeType

        payload = self._step_inputs.load(self.step_id)
        recorded_scope = payload.get("inputs", {}).get("scope")
        if isinstance(recorded_scope, dict) and "targets" in recorded_scope:
            try:
                return EngagementScope.model_validate(recorded_scope)
            except Exception:
                pass

        target = payload.get("inputs", {}).get("target") or "127.0.0.1"
        # Derive a hostname/IP from a URL if needed
        if isinstance(target, str) and target.startswith(("http://", "https://")):
            from urllib.parse import urlparse

            host = urlparse(target).hostname or target
        else:
            host = str(target)

        scope_type = ScopeType.DOMAIN
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", str(host)):
            scope_type = ScopeType.IP

        return EngagementScope(
            name=f"replay-{self.engagement_id}",
            targets=[ScopeEntry(value=str(host), type=scope_type)],
        )

    def _lookup_original_output_summary(self) -> str:
        """Pull the original output_summary from trace.jsonl, if available.

        Used purely for diffing. Returns the empty string if the trace
        file is missing or the matching agent_step event can't be found.
        """
        trace_path = self.outputs_root / self.engagement_id / "trace.jsonl"
        if not trace_path.exists():
            return ""
        try:
            with trace_path.open(encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    payload = rec.get("payload") or {}
                    if (
                        rec.get("category") == "agent_step"
                        and payload.get("step_id") == self.step_id
                    ):
                        return payload.get("output_summary") or ""
        except Exception:  # noqa: BLE001
            return ""
        return ""


def _stringify(value: Any) -> str:
    """Render any replay output to a string for diffing."""
    if value is None:
        return ""
    if hasattr(value, "model_dump_json"):
        try:
            return value.model_dump_json(indent=2)
        except Exception:  # noqa: BLE001
            return str(value)
    try:
        return json.dumps(value, default=str, indent=2)
    except (TypeError, ValueError):
        return str(value)


# ---------------------------------------------------------------------------
# Sync helper for CLI
# ---------------------------------------------------------------------------


def replay_step_sync(
    engagement_id: str,
    step_id: str,
    *,
    outputs_root: Path | str = Path("outputs"),
    llm_provider: str | None = None,
) -> ReplayResult:
    """Synchronous wrapper around :meth:`StepReplayer.replay` for the CLI."""
    replayer = StepReplayer(
        engagement_id=engagement_id,
        step_id=step_id,
        outputs_root=outputs_root,
        llm_provider=llm_provider,
    )
    return asyncio.run(replayer.replay())
