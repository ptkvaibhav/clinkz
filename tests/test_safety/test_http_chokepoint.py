"""The rails must actually sit on the request, not merely exist.

A governor that is never consulted is a governor that stops nothing. These tests
exercise the real :class:`~clinkz.tools.http_client.HTTPClientTool` entry point
and assert the four things that must be true there:

  1. With no governor installed, the path is untouched (the benchmark suites).
  2. A destructive request never reaches the transport.
  3. A halted engagement sends nothing further.
  4. The response is fed back for blocking detection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clinkz.models.engagement import SafetyPolicy
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.safety.governor import (
    HALT_KILL_SWITCH,
    EngagementGovernor,
    set_active_governor,
)
from clinkz.tools.base import ToolBase
from clinkz.tools.http_client import HTTPClientTool

pytestmark = pytest.mark.asyncio

_SCOPE = EngagementScope(
    name="chokepoint",
    targets=[ScopeEntry(value="app.test", type=ScopeType.DOMAIN)],
)


@pytest.fixture(autouse=True)
def _uninstall_governor():
    """The registry is module-level; a leak between tests is a real bug."""
    set_active_governor(None)
    yield
    set_active_governor(None)


@pytest.fixture
def sent(monkeypatch) -> list[dict]:
    """Capture what would have gone out, instead of sending it."""
    calls: list[dict] = []

    async def _fake_dispatch(self: HTTPClientTool, args: dict) -> str:
        calls.append(args)
        return json.dumps(
            {
                "status_code": 200,
                "response_headers": {"Content-Type": "text/html"},
                "response_body": "<html>ok</html>",
                "redirect_chain": [],
                "response_time_ms": 1.0,
            }
        )

    monkeypatch.setattr(HTTPClientTool, "_dispatch", _fake_dispatch)
    return calls


def _tool() -> HTTPClientTool:
    return HTTPClientTool(scope=_SCOPE, engagement_id="eng-chokepoint", stage="exploit")


async def test_without_a_governor_the_path_is_untouched(sent: list[dict]) -> None:
    tool = _tool()
    raw = await tool.execute(tool.validate_input({"url": "http://app.test/x", "method": "GET"}))
    assert json.loads(raw)["status_code"] == 200
    assert len(sent) == 1


async def test_a_destructive_request_never_reaches_the_transport(
    sent: list[dict], tmp_path: Path
) -> None:
    governor = EngagementGovernor(
        "eng-chokepoint", SafetyPolicy(max_requests_per_second=1000.0), outputs_root=tmp_path
    )
    set_active_governor(governor)

    tool = _tool()
    raw = await tool.execute(
        tool.validate_input(
            {
                "url": "http://app.test/account/change-password",
                "method": "POST",
                "body": "password_new=x&password_conf=x",
            }
        )
    )
    parsed = json.loads(raw)

    assert sent == [], "a refused request was still sent to the target"
    assert parsed["status_code"] == 0
    assert parsed["safety_refusal"] == "credential_change"
    assert "refused by safety policy" in parsed["error"]
    assert governor.action_log.refused_count == 1


async def test_a_refusal_is_shaped_like_an_error_not_an_exception(
    sent: list[dict], tmp_path: Path
) -> None:
    """Every caller already handles status 0 + error; none handles a new exception.

    Raising here would be swallowed by one of the methodologies' ``except``
    blocks and turn "refused by policy" into "that probe failed".
    """
    set_active_governor(EngagementGovernor("eng-chokepoint", SafetyPolicy(), outputs_root=tmp_path))
    tool = _tool()
    parsed = tool.parse_output(
        await tool.execute(tool.validate_input({"url": "http://app.test/x", "method": "DELETE"}))
    )
    assert parsed.success is False
    assert parsed.status_code == 0
    assert parsed.error


async def test_a_halted_engagement_sends_nothing(sent: list[dict], tmp_path: Path) -> None:
    governor = EngagementGovernor(
        "eng-chokepoint", SafetyPolicy(max_requests_per_second=1000.0), outputs_root=tmp_path
    )
    set_active_governor(governor)
    governor.halt(HALT_KILL_SWITCH, "operator pulled the switch")

    tool = _tool()
    raw = await tool.execute(tool.validate_input({"url": "http://app.test/x", "method": "GET"}))

    assert sent == []
    assert "Engagement halted" in json.loads(raw)["error"]


async def test_the_response_is_fed_back_for_blocking_detection(monkeypatch, tmp_path: Path) -> None:
    async def _blocked(self: HTTPClientTool, args: dict) -> str:
        return json.dumps(
            {
                "status_code": 429,
                "response_headers": {},
                "response_body": "slow down",
                "redirect_chain": [],
                "response_time_ms": 1.0,
            }
        )

    monkeypatch.setattr(HTTPClientTool, "_dispatch", _blocked)
    governor = EngagementGovernor(
        "eng-chokepoint",
        SafetyPolicy(max_requests_per_second=1000.0, blocking_threshold=2),
        outputs_root=tmp_path,
    )
    set_active_governor(governor)

    tool = _tool()
    for _ in range(2):
        await tool.execute(tool.validate_input({"url": "http://app.test/x", "method": "GET"}))

    assert governor.halted, "throttling responses did not reach the governor"


async def test_the_concurrency_slot_is_released_even_when_the_request_raises(
    monkeypatch, tmp_path: Path
) -> None:
    """A leaked slot deadlocks the engagement after max_concurrent failures."""

    async def _boom(self: HTTPClientTool, args: dict) -> str:
        raise RuntimeError("transport exploded")

    monkeypatch.setattr(HTTPClientTool, "_dispatch", _boom)
    governor = EngagementGovernor(
        "eng-chokepoint",
        SafetyPolicy(max_requests_per_second=1000.0, max_concurrent_requests=1),
        outputs_root=tmp_path,
    )
    set_active_governor(governor)

    tool = _tool()
    with pytest.raises(RuntimeError):
        await tool.execute(tool.validate_input({"url": "http://app.test/x", "method": "GET"}))

    # The slot must be free again.
    assert (await governor.authorize("GET", "http://app.test/y")).allowed
    governor.release()


async def test_no_session_omits_the_shared_cookie_jar(monkeypatch) -> None:
    """What makes an anonymous control genuinely anonymous.

    Reading the jar would send the engagement's own session on the "anonymous"
    leg; writing it would let an unauthenticated Set-Cookie overwrite the
    session every later request depends on.
    """
    captured: list[list[str]] = []

    async def _capture(self: ToolBase, cmd: list[str]) -> tuple[str, str, int]:
        captured.append(cmd)
        return "HTTP/1.1 200 OK\r\n\r\nbody", "", 0

    monkeypatch.setattr("clinkz.config.settings.tool_exec_mode", "docker")
    monkeypatch.setattr(ToolBase, "_run_subprocess", _capture)

    tool = _tool()
    await tool.execute(
        tool.validate_input({"url": "http://app.test/x", "method": "GET", "no_session": True})
    )
    assert captured, "no request was built"
    cmd = captured[0]
    assert "-b" not in cmd, "the anonymous control read the shared cookie jar"
    assert "-c" not in cmd, "the anonymous control wrote to the shared cookie jar"

    captured.clear()
    await tool.execute(tool.validate_input({"url": "http://app.test/x", "method": "GET"}))
    assert "-b" in captured[0], "an ordinary request must still carry the session"


async def test_the_halt_reaches_subprocess_tools(tmp_path: Path) -> None:
    """A halted engagement that keeps shelling out to ffuf has not stopped."""
    governor = EngagementGovernor("eng-chokepoint", SafetyPolicy(), outputs_root=tmp_path)
    set_active_governor(governor)
    governor.halt(HALT_KILL_SWITCH, "operator pulled the switch")

    stdout, stderr, code = await _tool()._run_subprocess(["curl", "http://app.test/"])
    assert code != 0
    assert "engagement halted" in stderr
    assert stdout == ""
