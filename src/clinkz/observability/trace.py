"""Execution trace writer — streams JSONL events to per-engagement trace files.

Every Clinkz engagement produces ``outputs/<engagement_id>/trace.jsonl`` with
four event categories that together capture WHAT the system did and WHY:

  - ``tool_call``     — every subprocess invocation (cmd, exit, duration)
  - ``llm_call``      — every LLM round-trip (provider, model, tokens, duration)
  - ``agent_step``    — start/end of each deterministic step inside an agent
  - ``data_handoff``  — every Orchestrator-mediated message between agents

Each ``tool_call`` summary line carries an ``invocation_file`` field that
points to ``outputs/<engagement_id>/tool_invocations/<seq>_<tool>.json`` —
the full-fidelity record (entire stdout/stderr, parsed Pydantic output, the
exact argv). Each ``agent_step`` carries a ``step_id`` linking to
``outputs/<engagement_id>/step_inputs/<step_id>.json`` with the full input
payload for replay.

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
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, TextIO

from clinkz.engagement.secrets import redact_structure
from clinkz.observability.invocations import (
    InvocationRecord,
    StepContext,
    StepInputRecorder,
    ToolInvocationRecorder,
)

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

    Owns two sibling recorders:

      - ``invocations`` — ``tool_invocations/<seq>_<tool>.json`` per call
      - ``step_inputs`` — ``step_inputs/<step_id>.json`` per agent step

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
        self.outputs_root = Path(outputs_root)
        if path_override is not None:
            self.path = Path(path_override)
        else:
            self.path = self.outputs_root / engagement_id / "trace.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh: TextIO | None = self.path.open("a", encoding="utf-8")
        self._lock = threading.Lock()
        self._closed = False
        self.invocations = ToolInvocationRecorder(
            engagement_id=engagement_id,
            outputs_root=self.outputs_root,
        )
        self.step_inputs = StepInputRecorder(
            engagement_id=engagement_id,
            outputs_root=self.outputs_root,
        )
        # The currently-active step. Updated by :meth:`step` so that tool
        # invocations record their owning agent/step automatically.
        self._current_step: StepContext | None = None
        self._current_step_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Current step context (used by ToolBase to attribute invocations)
    # ------------------------------------------------------------------

    @property
    def current_step(self) -> StepContext | None:
        """The agent step currently in flight, or ``None`` if outside any step."""
        return self._current_step

    def _set_current_step(self, ctx: StepContext | None) -> None:
        with self._current_step_lock:
            self._current_step = ctx

    @contextmanager
    def step(
        self,
        *,
        agent: str,
        step_name: str,
        inputs: dict[str, Any] | None = None,
        replay_info: dict[str, Any] | None = None,
    ) -> Iterator[str]:
        """Begin an agent step. Returns the step_id.

        On entry: generates a fresh step_id, writes the full inputs file to
        ``step_inputs/<step_id>.json``, and sets the active step context so
        tool invocations inside the step are attributed correctly.

        On exit: emits one ``agent_step`` trace event with the step_id, the
        elapsed duration, and any ``inputs``/``outputs`` summaries.

        Args:
            agent: Canonical agent name (``"recon"``, ``"scan"``, ...).
            step_name: Step identifier within the agent (e.g. ``"port_scan"``).
            inputs: Full input payload — written verbatim to the inputs file.
            replay_info: Extra fields the replayer needs (agent_class,
                method_name, llm_provider, ...).

        Yields:
            The freshly-generated step_id (a UUID string).
        """
        step_id = str(uuid.uuid4())
        payload: dict[str, Any] = {
            "step_id": step_id,
            "engagement_id": self.engagement_id,
            "agent": agent,
            "step_name": step_name,
            "ts": datetime.now(UTC).isoformat(),
            "inputs": inputs if inputs is not None else {},
        }
        if replay_info:
            payload["replay"] = replay_info
        self.step_inputs.record(step_id, payload)

        previous = self._current_step
        self._set_current_step(StepContext(step_id=step_id, agent=agent, step_name=step_name))
        sw = Stopwatch()
        outcome = "ok"
        try:
            yield step_id
        except Exception:
            outcome = "error"
            raise
        finally:
            self._set_current_step(previous)
            extra = {"step_id": step_id, "outcome": outcome}
            if replay_info:
                extra["replay"] = replay_info
            self.agent_step(
                agent=agent,
                step_name=step_name,
                input_summary=_summarise(inputs) if inputs is not None else "",
                duration_ms=sw.elapsed_ms,
                extra=extra,
            )

    # ------------------------------------------------------------------
    # Tool invocation recording — full-fidelity sidecar file
    # ------------------------------------------------------------------

    def attach_parsed_output(
        self,
        seq: int,
        *,
        parsed_output_type: str,
        parsed_output: dict[str, Any] | None,
        parse_succeeded: bool,
    ) -> None:
        """Re-write an invocation file with parsed-output details filled in.

        Called by ``BaseAgent._execute_tool`` (and any tool wrapper that
        parses its own output before returning) after ``parse_output``
        succeeds. The seq number was returned by
        :meth:`record_tool_invocation` at subprocess time.

        Tracing must never raise — failures here are logged and swallowed.
        """
        if seq < 0:
            return
        # The filename uses zero-padded seq + sanitized tool name. Glob to
        # find it back; cheaper than maintaining a seq→path map in memory
        # and equally correct because seq is unique per engagement.
        try:
            matches = list(self.invocations.dir.glob(f"{seq:05d}_*.json"))
            if not matches:
                return
            path = matches[0]
            data = json.loads(path.read_text(encoding="utf-8"))
            data["parsed_output_type"] = parsed_output_type
            # A tool's PARSED output can echo the credential it submitted (an
            # auth tool's own result), so this write is redacted like every
            # other artifact writer.
            data["parsed_output"] = redact_structure(parsed_output)
            data["parse_succeeded"] = parse_succeeded
            path.write_text(
                json.dumps(data, default=str, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001 — tracing must never raise
            logger.warning("attach_parsed_output failed for seq=%d: %s", seq, exc)

    def record_tool_invocation(
        self,
        *,
        tool_name: str,
        exec_mode: str,
        cwd: str,
        command: list[str],
        env_overrides: dict[str, str] | None = None,
        stdin: str | None = None,
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0,
        duration_ms: float | None = None,
        parsed_output_type: str = "",
        parsed_output: dict[str, Any] | None = None,
        parse_succeeded: bool = False,
        agent: str | None = None,
        step: str | None = None,
        step_id: str | None = None,
    ) -> tuple[int, Path]:
        """Persist a full-fidelity invocation record and return (seq, path).

        If ``agent`` / ``step`` / ``step_id`` are not provided, the active
        step context (if any) is used. The path returned points to
        ``tool_invocations/<seq>_<tool>.json`` and is suitable for embedding
        in the matching ``trace.jsonl`` summary line via ``invocation_file``.
        """
        seq = self.invocations.next_seq()
        ctx = self._current_step
        record = InvocationRecord(
            seq=seq,
            ts=self.invocations.make_timestamp(),
            tool_name=tool_name,
            exec_mode=exec_mode,
            cwd=cwd,
            command=list(command),
            env_overrides=dict(env_overrides or {}),
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            exit_code=exit_code,
            duration_ms=duration_ms,
            agent=agent if agent is not None else (ctx.agent if ctx else ""),
            step=step if step is not None else (ctx.step_name if ctx else ""),
            step_id=step_id if step_id is not None else (ctx.step_id if ctx else ""),
            parsed_output_type=parsed_output_type,
            parsed_output=parsed_output,
            parse_succeeded=parse_succeeded,
        )
        path = self.invocations.record(record)
        return seq, path

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
        # Every trace line passes through redaction. This is the second layer
        # under SecretStr: the primary guarantee is that no writer is handed a
        # plaintext credential, but a tool's own argv carries whatever the
        # methodology built -- a login curl's `-d email=..&password=..` is the
        # engagement's own credential, verbatim, in an artifact an operator
        # shares. A live run found exactly that.
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "stage": stage,
            "category": cat_value,
            "payload": redact_structure(payload),
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
