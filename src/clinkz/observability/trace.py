"""Execution trace writer — streams JSONL events to per-engagement trace files.

Every Clinkz engagement produces ``outputs/<engagement_id>/trace.jsonl`` with
four event categories that together capture WHAT the system did and WHY:

  - ``tool_call``     — every subprocess invocation (cmd, exit, duration)
  - ``llm_call``      — every LLM round-trip (provider, model, tokens, duration)
  - ``agent_step``    — start/end of each deterministic step inside an agent
  - ``data_handoff``  — every Orchestrator-mediated message between agents

The writer is process-local: a single TraceWriter instance is set as the
"active" writer for the engagement via :func:`set_active_trace_writer`, and
every wired call site (ToolBase, ResilientLLMClient, BaseAgent, Orchestrator)
fetches it via :func:`get_active_trace_writer` and emits events.

Why JSONL: append-only, each line is a complete event, trivial to grep/jq.
Why "active writer" instead of dependency injection: the call sites we need
to instrument (ToolBase, LLM clients) are constructed in too many places
to plumb a writer through every constructor — a contextvar-style global is
the lower-friction option, with the caveat that nested engagements would
collide. We don't run nested engagements today; if that changes, swap to
``contextvars.ContextVar``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, TextIO

logger = logging.getLogger(__name__)


class TraceCategory(StrEnum):
    """Trace event categories.

    Keep this list in sync with the ``--category`` filter values in the
    ``clinkz trace inspect`` CLI.
    """

    TOOL_CALL = "tool_call"
    LLM_CALL = "llm_call"
    AGENT_STEP = "agent_step"
    DATA_HANDOFF = "data_handoff"
    METHODOLOGY_PHASE = "methodology_phase"


_DEFAULT_OUTPUTS_ROOT = Path("outputs")


def _summarise(value: Any, max_chars: int = 500) -> str:
    """Render any payload to a single string capped at *max_chars*.

    Used to keep trace lines bounded — if you need the full raw output,
    inspect the underlying state store instead. The trace is for *flow*,
    not exhaustive evidence.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, default=str)
        except (TypeError, ValueError):
            text = str(value)
    if len(text) > max_chars:
        return text[:max_chars] + f"...[truncated {len(text) - max_chars} chars]"
    return text


class TraceWriter:
    """Append-only JSONL trace writer for one engagement.

    Thread-safe: write() acquires a lock so concurrent agent tasks don't
    interleave half-lines. The file is opened on construction and closed
    by :meth:`close`.

    Args:
        engagement_id: Engagement UUID — used to name the output directory.
        outputs_root: Root directory for trace files. Defaults to ``outputs``.
        path_override: Explicit trace file path (overrides the directory layout).
            Mainly used by tests.
    """

    def __init__(
        self,
        engagement_id: str,
        outputs_root: Path | str = _DEFAULT_OUTPUTS_ROOT,
        *,
        path_override: Path | str | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        if path_override is not None:
            self.path = Path(path_override)
        else:
            self.path = Path(outputs_root) / engagement_id / "trace.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh: TextIO | None = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._closed = False

    def write(
        self,
        *,
        stage: str,
        category: TraceCategory | str,
        payload: dict[str, Any],
    ) -> None:
        """Append one trace event.

        Args:
            stage: Human-readable phase label (``"recon"``, ``"scan"``, etc.).
            category: One of the TraceCategory values.
            payload: Category-specific fields. Keys differ per category — see
                module docstring for the canonical schema per category.
        """
        if self._closed or self._fh is None:
            return
        cat_value = category.value if isinstance(category, TraceCategory) else str(category)
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "stage": stage,
            "category": cat_value,
            "payload": payload,
        }
        line = json.dumps(record, default=str)
        with self._lock:
            try:
                self._fh.write(line + "\n")
                self._fh.flush()
            except Exception as exc:  # noqa: BLE001 — tracing must never raise
                logger.warning("TraceWriter write failed: %s", exc)

    # Convenience wrappers per category — keep call sites short and force
    # consistent payload keys across the codebase.

    def tool_call(
        self,
        *,
        stage: str,
        cmd: list[str] | str,
        stdout_summary: str = "",
        stderr_summary: str = "",
        exit_code: int | None = None,
        duration_ms: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record a subprocess invocation."""
        payload: dict[str, Any] = {
            "cmd": cmd if isinstance(cmd, str) else " ".join(cmd),
            "stdout_summary": _summarise(stdout_summary),
            "stderr_summary": _summarise(stderr_summary),
            "exit_code": exit_code,
            "duration_ms": duration_ms,
        }
        if extra:
            payload.update(extra)
        self.write(stage=stage, category=TraceCategory.TOOL_CALL, payload=payload)

    def llm_call(
        self,
        *,
        stage: str,
        provider: str,
        model: str,
        prompt_summary: str,
        response_summary: str,
        tokens: dict[str, int] | int | None = None,
        duration_ms: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record an LLM round-trip."""
        payload: dict[str, Any] = {
            "provider": provider,
            "model": model,
            "prompt_summary": _summarise(prompt_summary),
            "response_summary": _summarise(response_summary),
            "tokens": tokens,
            "duration_ms": duration_ms,
        }
        if extra:
            payload.update(extra)
        self.write(stage=stage, category=TraceCategory.LLM_CALL, payload=payload)

    def agent_step(
        self,
        *,
        agent: str,
        step_name: str,
        input_summary: str = "",
        output_summary: str = "",
        duration_ms: float | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record an agent step boundary (entry on start, full record on end)."""
        payload: dict[str, Any] = {
            "agent": agent,
            "step_name": step_name,
            "input_summary": _summarise(input_summary),
            "output_summary": _summarise(output_summary),
            "duration_ms": duration_ms,
        }
        if extra:
            payload.update(extra)
        self.write(stage=agent, category=TraceCategory.AGENT_STEP, payload=payload)

    def methodology_phase(
        self,
        *,
        stage: str,
        skill: str,
        phase_number: int,
        phase_name: str,
        payload_summary: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record one phase of an adaptive methodology skill.

        Adaptive ``_test_*`` methods (XSS-reflected, SQLi, etc.) emit one
        event per phase so the trace shows the full chain of decisions the
        skill made — reflection mapping, char fingerprinting, payload
        synthesis, bypass attempts, verification, finding emission.
        ``payload_summary`` is the short human-readable form; ``extra``
        carries the structured per-phase result (CharacterMap dump,
        SynthesizedPayload, etc.).
        """
        payload: dict[str, Any] = {
            "skill": skill,
            "phase_number": phase_number,
            "phase_name": phase_name,
            "payload_summary": _summarise(payload_summary),
        }
        if extra:
            payload.update(extra)
        self.write(stage=stage, category=TraceCategory.METHODOLOGY_PHASE, payload=payload)

    def data_handoff(
        self,
        *,
        from_agent: str,
        to_agent: str,
        data_summary: str,
        size_bytes: int | None = None,
        message_type: str = "",
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record an inter-agent message routed by the Orchestrator."""
        payload: dict[str, Any] = {
            "from_agent": from_agent,
            "to_agent": to_agent,
            "data_summary": _summarise(data_summary),
            "size_bytes": size_bytes,
            "message_type": message_type,
        }
        if extra:
            payload.update(extra)
        self.write(
            stage=f"{from_agent}->{to_agent}",
            category=TraceCategory.DATA_HANDOFF,
            payload=payload,
        )

    def close(self) -> None:
        """Close the underlying file handle. Idempotent."""
        if self._closed:
            return
        self._closed = True
        if self._fh is not None:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:  # noqa: BLE001 — best-effort
                pass
            self._fh = None

    def __enter__(self) -> TraceWriter:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


# ---------------------------------------------------------------------------
# Active writer (process-global)
# ---------------------------------------------------------------------------


_active_writer: TraceWriter | None = None
_active_lock = threading.Lock()


def set_active_trace_writer(writer: TraceWriter | None) -> None:
    """Set the writer that wired call sites should emit to.

    Called by the Orchestrator at engagement start, and reset to ``None``
    at the end so leftover module-state from a prior run can't contaminate
    a later one.
    """
    global _active_writer
    with _active_lock:
        _active_writer = writer


def get_active_trace_writer() -> TraceWriter | None:
    """Return the active writer, or None if no engagement is tracing."""
    return _active_writer


# ---------------------------------------------------------------------------
# Stopwatch helper — keep duration math out of every call site
# ---------------------------------------------------------------------------


class Stopwatch:
    """Tiny perf_counter-based stopwatch returning milliseconds."""

    __slots__ = ("_start",)

    def __init__(self) -> None:
        self._start = time.perf_counter()

    @property
    def elapsed_ms(self) -> float:
        return (time.perf_counter() - self._start) * 1000.0
