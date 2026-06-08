"""Tests for the SqlmapTool wrapper — focused on auth-header passthrough.

The bearer header support lets SQLi confirmation work on token-authenticated
targets (e.g. Juice Shop), parallel to the existing ``--cookie`` handling.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.tools.sqlmap import SqlmapTool

SCOPE = EngagementScope(
    name="sqlmap-test",
    targets=[ScopeEntry(type=ScopeType.DOMAIN, value="example.com")],
)


@pytest.fixture()
def tool() -> SqlmapTool:
    return SqlmapTool(scope=SCOPE)


def test_validate_input_header_string(tool: SqlmapTool) -> None:
    args = tool.validate_input(
        {"url": "http://example.com/?id=1", "header": "Authorization: Bearer JWT"}
    )
    assert args["header"] == "Authorization: Bearer JWT"


def test_validate_input_header_dict_coerced(tool: SqlmapTool) -> None:
    args = tool.validate_input(
        {
            "url": "http://example.com/?id=1",
            "header": {"Authorization": "Bearer JWT", "X-Test": "1"},
        }
    )
    assert args["header"] == "Authorization: Bearer JWT\nX-Test: 1"


def test_validate_input_header_default_empty(tool: SqlmapTool) -> None:
    args = tool.validate_input({"url": "http://example.com/?id=1"})
    assert args["header"] == ""


@pytest.mark.asyncio
async def test_execute_passes_single_header_flag(
    tool: SqlmapTool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A single header → ``--header``; the value is passed as one argv element."""
    captured: dict[str, list[str]] = {}

    async def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> tuple[str, str, int]:
        captured["cmd"] = cmd
        return ("", "", 0)

    monkeypatch.setattr(tool, "_run_subprocess", fake_run)

    await tool.execute(
        tool.validate_input(
            {"url": "http://example.com/?id=1", "header": "Authorization: Bearer JWT"}
        )
    )

    cmd = captured["cmd"]
    assert "--header" in cmd
    assert cmd[cmd.index("--header") + 1] == "Authorization: Bearer JWT"
    assert "--headers" not in cmd


@pytest.mark.asyncio
async def test_execute_passes_multi_header_flag(
    tool: SqlmapTool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Multiple (newline-separated) headers → ``--headers``."""
    captured: dict[str, list[str]] = {}

    async def fake_run(cmd: list[str], *args: Any, **kwargs: Any) -> tuple[str, str, int]:
        captured["cmd"] = cmd
        return ("", "", 0)

    monkeypatch.setattr(tool, "_run_subprocess", fake_run)

    await tool.execute(
        tool.validate_input(
            {
                "url": "http://example.com/?id=1",
                "header": {"Authorization": "Bearer JWT", "X-Test": "1"},
            }
        )
    )

    cmd = captured["cmd"]
    assert "--headers" in cmd
    assert "--header" not in cmd
