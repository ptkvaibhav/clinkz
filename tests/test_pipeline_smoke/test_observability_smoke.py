"""In-process smoke for the observability sidecars.

Runs without a live container target and asserts that the full-fidelity
recording layer wires up correctly: every subprocess call must drop a
``tool_invocations/<seq>_<tool>.json`` file and the matching ``trace.jsonl``
summary line must point to it.

This test catches regressions in the recording layer itself (the layer
the other smoke tests rely on) without paying the cost of a live target.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.observability.trace import (
    TraceWriter,
    set_active_trace_writer,
)
from clinkz.tools.base import ToolBase, ToolOutput

pytestmark = pytest.mark.pipeline_smoke


@pytest.fixture
def echo_tool_cls() -> type[ToolBase]:
    """Return a throwaway ``ToolBase`` subclass scoped to this test.

    ``ToolResolver`` discovers tools by walking ``ToolBase.__subclasses__()``.
    Defining this subclass at *module* scope would leak it into that global list
    for the rest of the pytest session, so ``test_resolver.py``'s
    ``test_all_tools_discovered`` (an exact-set assertion) would see a phantom
    ``echo_smoke`` tool under full-suite runs (it passes 48/48 in isolation).
    Keeping it function-local means it becomes collectable once this test is torn
    down; the ``resolver`` fixture in ``test_resolver.py`` forces a GC pass before
    reading the registry, which reaps the dead class — so the leak never escapes
    this test.
    """

    class _EchoOutput(ToolOutput):
        """Trivial parsed output — proves attach_parsed_output wiring."""

        text: str = ""

    class _EchoTool(ToolBase):
        """Minimal ToolBase subclass that calls _run_subprocess with host python.

        Reusing the host interpreter is portable across Linux/Windows/macOS
        and doesn't require a tool container — exactly what we need for a
        smoke test of the recording layer.
        """

        capabilities = ["echo"]
        category = "utility"

        @property
        def name(self) -> str:
            return "echo_smoke"

        @property
        def description(self) -> str:
            return "Smoke-test echo tool."

        def get_schema(self) -> dict[str, Any]:
            return {
                "name": self.name,
                "description": self.description,
                "parameters": {"type": "object", "properties": {}, "required": []},
            }

        def validate_input(self, args: dict[str, Any]) -> dict[str, Any]:
            return dict(args)

        async def execute(self, args: dict[str, Any]) -> str:
            text = args.get("text", "smoke")
            cmd = [sys.executable, "-c", f"print({text!r})"]
            stdout, _stderr, _rc = await self._run_subprocess(cmd)
            return stdout

        def parse_output(self, raw_output: str) -> _EchoOutput:
            return _EchoOutput(
                tool_name=self.name, success=True, raw_output=raw_output, text=raw_output
            )

    return _EchoTool


def test_tool_invocation_records_sidecar_files(
    tmp_path: Path, monkeypatch, echo_tool_cls: type[ToolBase]
) -> None:
    """ToolBase._run_subprocess must drop a full invocation record and link it."""
    # Pin cwd so the TraceWriter writes under tmp_path/outputs/
    monkeypatch.chdir(tmp_path)

    scope = EngagementScope(
        name="smoke",
        targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
    )
    engagement_id = "smoke-obs"
    writer = TraceWriter(engagement_id=engagement_id)
    set_active_trace_writer(writer)
    try:
        tool = echo_tool_cls(scope=scope)

        async def _go() -> str:
            return await tool.execute({"text": "smoke"})

        raw = asyncio.run(_go())
        assert "smoke" in raw
    finally:
        writer.close()
        set_active_trace_writer(None)

    # Invocation sidecar present
    inv_dir = tmp_path / "outputs" / engagement_id / "tool_invocations"
    assert inv_dir.exists(), f"No tool_invocations/ under {inv_dir.parent}"
    files = sorted(inv_dir.glob("*.json"))
    assert len(files) == 1, f"Expected exactly 1 invocation file, found {len(files)}"

    record = json.loads(files[0].read_text(encoding="utf-8"))
    assert record["tool_name"] == "echo_smoke"
    assert record["exit_code"] == 0
    assert "smoke" in record["stdout"]
    assert record["command"][0] == sys.executable

    # Trace summary points at the sidecar
    trace_path = tmp_path / "outputs" / engagement_id / "trace.jsonl"
    lines = [json.loads(ln) for ln in trace_path.read_text(encoding="utf-8").splitlines() if ln]
    tool_call_lines = [ln for ln in lines if ln.get("category") == "tool_call"]
    assert tool_call_lines, "No tool_call entries in trace.jsonl"
    summary = tool_call_lines[0]["payload"]
    assert "invocation_file" in summary, f"Missing invocation_file in {summary}"
    assert summary["invocation_seq"] == 0


def test_step_inputs_recorded_for_wrapped_step(tmp_path: Path, monkeypatch) -> None:
    """BaseAgent._record_step must write a step_inputs/<step_id>.json file."""
    from clinkz.agents.recon import ReconAgent
    from clinkz.llm.base import AgentAction, LLMClient, LLMMessage
    from clinkz.state import StateStore

    monkeypatch.chdir(tmp_path)

    scope = EngagementScope(
        name="smoke",
        targets=[ScopeEntry(value="127.0.0.1", type=ScopeType.IP)],
    )
    engagement_id = "smoke-step"
    writer = TraceWriter(engagement_id=engagement_id)
    set_active_trace_writer(writer)

    class _StubLLM(LLMClient):
        async def reason(
            self,
            messages: list[LLMMessage],
            tools: list[dict[str, Any]] | None = None,
        ) -> AgentAction:
            raise NotImplementedError

        async def research(self, query: str) -> str:
            return ""

        async def generate_text(self, prompt: str) -> str:
            return "[]"

    async def _go() -> None:
        state = StateStore(":memory:")
        await state.connect()
        await state.create_engagement(scope.name, scope.model_dump())
        agent = ReconAgent(
            llm=_StubLLM(),
            tools=[],
            scope=scope,
            state=state,
            engagement_id=engagement_id,
        )
        # Exercise the wrapped port_scan step directly. The resolver may not
        # find any port scanning tools on the test host — that's fine, the
        # step still writes its inputs file before bailing out.
        with agent._record_step(
            "port_scan",
            inputs={"target": "127.0.0.1"},
            replay_info={"method_name": "_step_port_scan"},
        ):
            pass

    try:
        asyncio.run(_go())
    finally:
        writer.close()
        set_active_trace_writer(None)

    step_inputs_dir = tmp_path / "outputs" / engagement_id / "step_inputs"
    assert step_inputs_dir.exists(), f"No step_inputs/ under {step_inputs_dir.parent}"
    files = list(step_inputs_dir.glob("*.json"))
    assert len(files) == 1
    payload = json.loads(files[0].read_text(encoding="utf-8"))
    assert payload["step_name"] == "port_scan"
    assert payload["agent"] == "recon"
    assert payload["inputs"] == {"target": "127.0.0.1"}
    assert payload["replay"]["agent_class"] == "ReconAgent"
    assert payload["replay"]["method_name"] == "_step_port_scan"
