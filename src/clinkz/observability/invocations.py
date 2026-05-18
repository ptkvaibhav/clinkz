"""Full-fidelity tool invocation records — one JSON file per subprocess call.

The summary lines in ``trace.jsonl`` keep the timeline readable, but the
real evidence (full stdout, full stderr, parsed Pydantic output, the exact
argv that was run) is too large to inline. Each invocation is written to
``outputs/<engagement_id>/tool_invocations/<seq>_<tool_name>.json`` and the
matching ``trace.jsonl`` summary points to it via ``invocation_file``.

Why a separate file per call:

- ``cat`` / ``jq`` on a single file is fast; loading the whole ``trace.jsonl``
  every time a developer wants one stdout dump is not.
- The CLI ``clinkz tool-invoke <id> <seq>`` becomes a trivial file open.
- ``clinkz tool-invoke <id> <seq> --replay`` can read back the exact argv,
  env, and cwd to re-run the same call deterministically.

Why a sibling module (not part of ``TraceWriter``):

- The recorder owns the invocation sequence counter and per-engagement
  directory layout; ``TraceWriter`` owns the JSONL stream. Keeping them
  separate means tests can use either one alone.
- A single recorder instance is held by the active ``TraceWriter`` so all
  call sites (every ``ToolBase`` subclass) reach it the same way.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class StepContext:
    """In-flight agent step — used to attribute tool invocations to a step.

    Set by :meth:`TraceWriter.step` and read by the invocation recorder so
    every ``tool_invocations/<seq>_<tool>.json`` carries the owning agent
    and step id. ``None`` outside any step.
    """

    step_id: str
    agent: str
    step_name: str


@dataclass
class InvocationRecord:
    """The structured payload written per tool invocation.

    Mirrors the schema documented in ``docs/observability.md`` — keep them
    in sync if you add or rename fields.
    """

    seq: int
    ts: str
    tool_name: str
    exec_mode: str
    cwd: str
    command: list[str]
    env_overrides: dict[str, str] = field(default_factory=dict)
    stdin: str | None = None
    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0
    duration_ms: float | None = None
    agent: str = ""
    step: str = ""
    step_id: str = ""
    parsed_output_type: str = ""
    parsed_output: dict[str, Any] | None = None
    parse_succeeded: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a plain dict suitable for ``json.dumps``."""
        return {
            "seq": self.seq,
            "ts": self.ts,
            "tool_name": self.tool_name,
            "exec_mode": self.exec_mode,
            "cwd": self.cwd,
            "command": self.command,
            "env_overrides": self.env_overrides,
            "stdin": self.stdin,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "agent": self.agent,
            "step": self.step,
            "step_id": self.step_id,
            "parsed_output_type": self.parsed_output_type,
            "parsed_output": self.parsed_output,
            "parse_succeeded": self.parse_succeeded,
        }


class ToolInvocationRecorder:
    """Append-only per-engagement recorder for tool invocations.

    Args:
        engagement_id: Engagement UUID — used to name the output directory.
        outputs_root: Root directory for invocation files. Defaults to ``outputs``.
        dir_override: Explicit invocation directory (overrides the default layout).
            Mainly used by tests.
    """

    def __init__(
        self,
        engagement_id: str,
        outputs_root: Path | str = Path("outputs"),
        *,
        dir_override: Path | str | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        if dir_override is not None:
            self.dir = Path(dir_override)
        else:
            self.dir = Path(outputs_root) / engagement_id / "tool_invocations"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._lock = threading.Lock()

    def next_seq(self) -> int:
        """Reserve the next invocation sequence number.

        Atomic — concurrent agent tasks won't collide on a seq number.
        """
        with self._lock:
            seq = self._seq
            self._seq += 1
            return seq

    def record(self, invocation: InvocationRecord) -> Path:
        """Write one invocation record to disk and return the file path.

        Tracing must never bubble an exception back to the caller — a tool
        invocation is recorded even if disk I/O fails, the failure just
        gets logged and the path is still returned (the file may be empty
        or partial).
        """
        safe_tool = _safe_filename(invocation.tool_name)
        filename = f"{invocation.seq:05d}_{safe_tool}.json"
        path = self.dir / filename
        try:
            path.write_text(
                json.dumps(invocation.to_dict(), default=str, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001 — tracing must never raise
            logger.warning("InvocationRecorder write failed for seq=%d: %s", invocation.seq, exc)
        return path

    @staticmethod
    def make_timestamp() -> str:
        """Return an ISO-8601 timestamp in UTC, used by invocation records."""
        return datetime.now(UTC).isoformat()


class StepInputRecorder:
    """Per-engagement recorder for full agent-step input payloads.

    Mirrors ``ToolInvocationRecorder`` but for steps. Each step gets a UUID
    and writes ``step_inputs/<step_id>.json`` containing the full inputs,
    the agent name, the step name, and any replay metadata.
    """

    def __init__(
        self,
        engagement_id: str,
        outputs_root: Path | str = Path("outputs"),
        *,
        dir_override: Path | str | None = None,
    ) -> None:
        self.engagement_id = engagement_id
        if dir_override is not None:
            self.dir = Path(dir_override)
        else:
            self.dir = Path(outputs_root) / engagement_id / "step_inputs"
        self.dir.mkdir(parents=True, exist_ok=True)

    def record(self, step_id: str, payload: dict[str, Any]) -> Path:
        """Write the step input payload and return the file path.

        Args:
            step_id: UUID for the step (also referenced in the trace event).
            payload: Full input payload — must be JSON-serialisable when
                rendered with ``default=str``.
        """
        path = self.dir / f"{step_id}.json"
        try:
            path.write_text(
                json.dumps(payload, default=str, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:  # noqa: BLE001 — tracing must never raise
            logger.warning("StepInputRecorder write failed for step_id=%s: %s", step_id, exc)
        return path

    def load(self, step_id: str) -> dict[str, Any]:
        """Load a recorded step input payload back from disk."""
        path = self.dir / f"{step_id}.json"
        return json.loads(path.read_text(encoding="utf-8"))


def _safe_filename(name: str) -> str:
    """Sanitise a tool name for use in a filename.

    Replaces every non-alphanumeric character with ``_``. Names like
    ``http_request`` and ``nmap`` round-trip unchanged; ``foo/bar`` becomes
    ``foo_bar``.
    """
    return "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in name) or "tool"
