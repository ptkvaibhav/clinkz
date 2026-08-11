"""The tool-consumption seam — where 100% of ffuf's output went for its whole life.

``_run_fuzz_tool`` read ``parsed.paths`` and ``parsed.directories``. ``FfufOutput``
has neither. Both ``hasattr`` checks were False, the seam returned ``[]``, and
content discovery never functioned — while nothing failed, because an empty list
from a fuzzer is exactly what a target with no hidden content looks like.

These tests pin the fix at three levels: the producer declares a contract, the
consumer reads the declaration rather than guessing, and a producer that declares
nothing is reported as a dead seam instead of being absorbed as an empty result.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.scan import ScanAgent
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.observability.ledger import (
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.ffuf import FfufOutput, FfufTool
from clinkz.tools.httpx_tool import HttpxOutput
from clinkz.tools.katana import KatanaOutput

_FIXTURE = Path(__file__).parent.parent / "fixtures" / "real_ffuf.json"


@pytest.fixture
def scope() -> EngagementScope:
    return EngagementScope(
        name="seam-test",
        targets=[ScopeEntry(type=ScopeType.IP, value="172.20.0.2")],
    )


# ---------------------------------------------------------------------------
# The producer side — the contract exists and is populated
# ---------------------------------------------------------------------------


def test_ffuf_output_declares_and_populates_the_discovery_contract(
    scope: EngagementScope,
) -> None:
    """Parsed real ffuf output must yield its hits through the declared method."""
    raw = _FIXTURE.read_text(encoding="utf-8")
    parsed = FfufTool(scope=scope).parse_output(raw)

    assert parsed.success
    assert type(parsed).declares_discovery()
    urls = parsed.discovered_urls()
    assert len(urls) == len(parsed.results) > 0
    assert "http://172.20.0.2/admin" in urls


def test_the_old_duck_typed_field_names_never_existed(scope: EngagementScope) -> None:
    """The regression this whole change exists for.

    Asserting the ABSENCE of ``paths``/``directories`` is the point: the defect
    was not a wrong value, it was two attribute names that were never on the
    model, so both guards silently fell through to an empty list.
    """
    parsed = FfufTool(scope=scope).parse_output(_FIXTURE.read_text(encoding="utf-8"))
    assert not hasattr(parsed, "paths")
    assert not hasattr(parsed, "directories")
    # ...while the fixture demonstrably carries six hits the seam was discarding.
    assert len(parsed.results) == len(json.loads(_FIXTURE.read_text(encoding="utf-8"))["results"])


@pytest.mark.parametrize(
    ("model", "kwargs", "expected"),
    [
        (KatanaOutput, {"urls": ["http://h/a", "http://h/b"]}, ["http://h/a", "http://h/b"]),
        (
            HttpxOutput,
            {"results": [{"url": "http://h/x", "status_code": 200}]},
            ["http://h/x"],
        ),
        (
            FfufOutput,
            {
                "results": [
                    {"url": "http://h/y", "status": 200, "length": 1, "words": 1, "lines": 1}
                ]
            },
            ["http://h/y"],
        ),
    ],
)
def test_every_discovery_output_declares_the_contract(
    model: type[ToolOutput], kwargs: dict[str, Any], expected: list[str]
) -> None:
    out = model(tool_name="t", success=True, **kwargs)
    assert type(out).declares_discovery()
    assert out.discovered_urls() == expected


def test_a_non_discovery_output_is_honest_about_declaring_nothing() -> None:
    """The base implementation is not a discovery contract, and says so.

    This is the distinction that makes the dead-seam alarm possible: without it,
    "returned no URLs" and "cannot return URLs" are the same empty list.
    """

    class Verdict(ToolOutput):
        detected: bool = False

    out = Verdict(tool_name="wafw00f", success=True)
    assert not type(out).declares_discovery()
    assert out.discovered_urls() == []


# ---------------------------------------------------------------------------
# The consumer side — the seam reads the declaration
# ---------------------------------------------------------------------------


class _FakeMatch:
    def __init__(self, tool_class: type[ToolBase] | None, available: bool = True) -> None:
        self.tool_class = tool_class
        self.available = available
        self.name = "fake"


class _FakeResolver:
    def __init__(self, tool_class: type[ToolBase] | None) -> None:
        self._cls = tool_class

    def find_tool(self, capability: str) -> _FakeMatch:
        return _FakeMatch(self._cls)

    def find_tool_by_name(self, tool_name: str) -> _FakeMatch | None:
        return _FakeMatch(self._cls)


class _StubFfuf(FfufTool):
    """FfufTool with the subprocess replaced by the recorded fixture."""

    async def execute(self, args: dict[str, Any]) -> str:
        return _FIXTURE.read_text(encoding="utf-8")


class _SilentDeadSeamTool(FfufTool):
    """A wrapper whose output type forgot to declare the contract."""

    class _Undeclared(ToolOutput):
        results: list[dict[str, Any]] = []

    async def execute(self, args: dict[str, Any]) -> str:
        return "{}"

    def parse_output(self, raw_output: str) -> ToolOutput:
        return self._Undeclared(
            tool_name="ffuf", success=True, results=[{"url": "http://172.20.0.2/admin"}]
        )


def _agent(scope: EngagementScope, tool_class: type[ToolBase]) -> ScanAgent:
    agent = ScanAgent.__new__(ScanAgent)
    agent.scope = scope
    agent._resolver = _FakeResolver(tool_class)
    agent._session_cookies = {}
    import logging

    agent._logger = logging.getLogger("test.seam")
    return agent


@pytest.mark.asyncio
async def test_fuzz_seam_delivers_the_hits_it_used_to_discard(scope: EngagementScope) -> None:
    """The end-to-end proof: six recorded hits reach the caller."""
    agent = _agent(scope, _StubFfuf)
    urls = await agent._run_fuzz_tool("ffuf", "http://172.20.0.2")

    assert len(urls) == 6
    assert "http://172.20.0.2/admin" in urls


@pytest.mark.asyncio
async def test_fuzz_seam_records_its_contribution_on_the_ledger(
    scope: EngagementScope,
) -> None:
    ledger = ContributionLedger(engagement_id="seam")
    set_active_ledger(ledger)
    try:
        urls = await _agent(scope, _StubFfuf)._run_fuzz_tool("ffuf", "http://172.20.0.2")
    finally:
        set_active_ledger(None)

    rec = next(r for r in ledger.records() if r.name == "ffuf")
    assert rec.items_contributed == len(urls) == 6
    assert rec.alarms == [], "a tool that contributed six URLs must not alarm"


@pytest.mark.asyncio
async def test_an_undeclared_output_is_a_dead_seam_not_an_empty_result(
    scope: EngagementScope, caplog: pytest.LogCaptureFixture
) -> None:
    """The defect's own shape, caught.

    A consumer reading a producer that cannot answer it must be reported as
    structurally inert — not absorbed as "the fuzzer found nothing", which is
    what let this run undetected for the seam's entire existence.
    """
    import logging

    ledger = ContributionLedger(engagement_id="seam")
    set_active_ledger(ledger)
    try:
        with caplog.at_level(logging.WARNING, logger="test.seam"):
            urls = await _agent(scope, _SilentDeadSeamTool)._run_fuzz_tool(
                "ffuf", "http://172.20.0.2"
            )
    finally:
        set_active_ledger(None)

    assert urls == []
    rec = next(r for r in ledger.records() if r.name == "ffuf")
    assert rec.dead_seam
    assert LedgerAlarm.DEAD_SEAM in rec.alarms
    assert any("DEAD SEAM" in r.getMessage() for r in caplog.records)
