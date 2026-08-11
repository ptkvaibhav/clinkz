"""A trace that exists and is empty is a broken evidence chain, not an idle run.

Four engagements on disk carry a zero-byte ``trace.jsonl``. Two of them
(``18cc9af6``, ``908b7130``, both 2026-08-07) shipped a *report* beside it — a
full run whose entire execution record is missing. The cause is not a race or a
flush: ``scripts/live_p7_client_execution_validation.py`` constructed a
``TraceWriter`` and dropped the reference, so the directory and the file were
created and ``set_active_trace_writer`` was never called. Every event the run
produced went to the active writer, which was ``None``.

Constructing a writer is therefore a trap: it has a visible filesystem side
effect that makes the bundle *look* traced. Two things close it —
:meth:`TraceWriter.activate` does both halves in one call, and :meth:`close`
says so loudly when a writer received nothing.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.observability.trace import (
    TraceCategory,
    TraceWriter,
    get_active_trace_writer,
    set_active_trace_writer,
)


@pytest.fixture(autouse=True)
def _no_leaked_active_writer():
    """Never let one case's writer become another's ambient state."""
    yield
    set_active_trace_writer(None)


class TestActivateDoesBothHalves:
    def test_the_writer_is_active_inside_the_block(self, tmp_path: Path) -> None:
        with TraceWriter.activate("eng-a", outputs_root=tmp_path) as writer:
            assert get_active_trace_writer() is writer

    def test_events_emitted_inside_the_block_reach_the_file(self, tmp_path: Path) -> None:
        with TraceWriter.activate("eng-a", outputs_root=tmp_path):
            active = get_active_trace_writer()
            assert active is not None
            active.write(stage="scan", category=TraceCategory.TOOL_CALL, payload={"cmd": "x"})

        lines = (tmp_path / "eng-a" / "trace.jsonl").read_text(encoding="utf-8").splitlines()
        assert len(lines) == 1
        assert json.loads(lines[0])["stage"] == "scan"

    def test_the_writer_is_closed_and_unset_afterwards(self, tmp_path: Path) -> None:
        with TraceWriter.activate("eng-a", outputs_root=tmp_path) as writer:
            writer.write(stage="s", category=TraceCategory.TOOL_CALL, payload={})
        assert get_active_trace_writer() is None
        assert writer._closed is True

    def test_an_exception_still_closes_and_unsets(self, tmp_path: Path) -> None:
        with pytest.raises(RuntimeError):  # noqa: PT012 — the raise is the subject
            with TraceWriter.activate("eng-a", outputs_root=tmp_path) as writer:
                writer.write(stage="s", category=TraceCategory.TOOL_CALL, payload={})
                raise RuntimeError("phase blew up")
        assert get_active_trace_writer() is None

    def test_a_nested_activation_restores_the_outer_writer(self, tmp_path: Path) -> None:
        """Restoring to ``None`` would silently disable an enclosing trace."""
        with TraceWriter.activate("outer", outputs_root=tmp_path) as outer:
            with TraceWriter.activate("inner", outputs_root=tmp_path) as inner:
                assert get_active_trace_writer() is inner
            assert get_active_trace_writer() is outer


class TestAnEmptyTraceIsReportedLoudly:
    def test_construct_and_discard_is_caught_at_close(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """The exact shape of the driver defect: built, never registered."""
        writer = TraceWriter("eng-silent", outputs_root=tmp_path)
        assert (tmp_path / "eng-silent" / "trace.jsonl").exists()  # the trap
        with caplog.at_level("ERROR", logger="clinkz.observability.trace"):
            writer.close()
        assert "NO events" in caplog.text
        assert "eng-silent" in caplog.text

    def test_a_writer_that_recorded_something_is_silent(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("ERROR", logger="clinkz.observability.trace"):
            with TraceWriter.activate("eng-ok", outputs_root=tmp_path) as writer:
                writer.write(stage="s", category=TraceCategory.TOOL_CALL, payload={})
        assert "NO events" not in caplog.text

    def test_events_written_counts_what_landed(self, tmp_path: Path) -> None:
        with TraceWriter.activate("eng-count", outputs_root=tmp_path) as writer:
            for _ in range(3):
                writer.write(stage="s", category=TraceCategory.TOOL_CALL, payload={})
            assert writer.events_written == 3


class TestOutputsRootIsAnchored:
    def test_the_root_is_absolute_from_construction(self, tmp_path: Path) -> None:
        """A relative root would follow a mid-run CWD change and split the bundle."""
        writer = TraceWriter("eng-abs", outputs_root="outputs")
        try:
            assert writer.outputs_root.is_absolute()
            assert writer.path.is_absolute()
        finally:
            writer.close()
            # Constructed outside tmp_path on purpose (the CWD default is the
            # subject); remove exactly what it made.
            writer.path.unlink(missing_ok=True)
            for sub in ("tool_invocations", "step_inputs"):
                d = writer.path.parent / sub
                if d.is_dir():
                    d.rmdir()
            if writer.path.parent.is_dir():
                writer.path.parent.rmdir()
        assert tmp_path is not None  # fixture kept for symmetry with the suite


class TestEveryProductionConstructionRegisters:
    """The guard that would have caught the driver defect at commit time."""

    def test_no_source_file_builds_a_writer_without_registering_it(self) -> None:
        import re

        roots = [Path("src/clinkz"), Path("scripts")]
        offenders: list[str] = []
        for root in roots:
            for path in root.rglob("*.py"):
                text = path.read_text(encoding="utf-8", errors="replace")
                if "TraceWriter(" not in text:
                    continue
                if "TraceWriter.activate" in text or "set_active_trace_writer" in text:
                    continue
                # The definition itself, and the classmethod that does register.
                if path.name == "trace.py":
                    continue
                for match in re.finditer(r"TraceWriter\(", text):
                    line = text.count("\n", 0, match.start()) + 1
                    offenders.append(f"{path.as_posix()}:{line}")
        assert not offenders, (
            "TraceWriter built without being registered as active — the bundle will "
            f"carry an empty trace.jsonl: {offenders}"
        )
