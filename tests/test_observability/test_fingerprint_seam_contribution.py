"""The newly-wired fingerprint seam has to CONTRIBUTE, and the ledger has to say so.

The companion to ``test_ledger_starvation`` for the other seam that was reading a
producer by guesswork. ``ReconAgent._step_web_recon`` extracted technologies with
``hasattr(r, "technologies")`` then ``hasattr(r, "tech")`` — two field names
because two wrappers spell it differently — and read only the NAMES, so the
versions whatweb had already parsed were consumed by nothing and no engagement
could test a dependency against a known CVE.

Green tests are not the evidence here. The evidence is a non-zero
``items_contributed`` on the ledger for a real wrapper parsing real recorded
output, and a loud ``DEAD_SEAM`` for a wrapper that declares nothing. A seam that
contributes zero and a seam that cannot contribute look identical from the
consumer's side, which is exactly how the ffuf defect survived.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.recon import ReconAgent
from clinkz.models.recon import ReconService, ServiceScanResult
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.observability.ledger import (
    ContributionLedger,
    LedgerAlarm,
    set_active_ledger,
)
from clinkz.tools.base import ToolBase, ToolOutput
from clinkz.tools.httpx_tool import HttpxTool
from clinkz.tools.resolver import ToolMatch
from clinkz.tools.wafw00f import Wafw00fOutput, Wafw00fTool
from clinkz.tools.whatweb import WhatWebTool

_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"

pytestmark = pytest.mark.asyncio


@pytest.fixture
def scope() -> EngagementScope:
    return EngagementScope(
        name="fingerprint-seam",
        targets=[ScopeEntry(type=ScopeType.IP, value="10.0.0.1")],
    )


class _RecordedWhatWeb(WhatWebTool):
    """The real wrapper, with the subprocess replaced by recorded output."""

    async def execute(self, args: dict[str, Any]) -> str:
        return (_FIXTURES / "whatweb_output.json").read_text(encoding="utf-8")


class _RecordedHttpx(HttpxTool):
    async def execute(self, args: dict[str, Any]) -> str:
        return (_FIXTURES / "httpx_output.jsonl").read_text(encoding="utf-8")


class _UndeclaringFingerprinter(WhatWebTool):
    """A fingerprinter whose output type forgot the contract."""

    class _Undeclared(ToolOutput):
        results: list[dict[str, Any]] = []

    async def execute(self, args: dict[str, Any]) -> str:
        return "{}"

    def parse_output(self, raw_output: str) -> ToolOutput:
        # It identified three technologies. None can reach the inventory.
        return self._Undeclared(
            tool_name="whatweb",
            success=True,
            results=[{"technologies": ["nginx", "PHP", "jQuery"]}],
        )


class _NoHTTP:
    """No http_request tool — this suite is about the fingerprint seam only."""

    def __init__(self, fingerprinter: type[ToolBase]) -> None:
        self._fingerprinter = fingerprinter

    def find_tool(self, capability: str) -> ToolMatch | None:
        if capability == "web_fingerprinting":
            return ToolMatch(
                name=self._fingerprinter(scope=_SCOPE).name,
                source="local",
                available=True,
                tool_class=self._fingerprinter,
            )
        if capability == "waf_detection":
            return ToolMatch(
                name="wafw00f", source="local", available=True, tool_class=_QuietWafw00f
            )
        return None


class _QuietWafw00f(Wafw00fTool):
    async def execute(self, args: dict[str, Any]) -> str:
        return "[]"

    def parse_output(self, raw_output: str) -> Wafw00fOutput:
        return Wafw00fOutput(tool_name="wafw00f", success=True, results=[])


_SCOPE = EngagementScope(
    name="fingerprint-seam",
    targets=[ScopeEntry(type=ScopeType.IP, value="10.0.0.1")],
)


def _agent(fingerprinter: type[ToolBase]) -> ReconAgent:
    agent = ReconAgent.__new__(ReconAgent)
    agent.scope = _SCOPE
    agent._resolver = _NoHTTP(fingerprinter)
    agent._logger = logging.getLogger("test.fingerprint")
    return agent


async def _run(fingerprinter: type[ToolBase]) -> tuple[Any, ContributionLedger]:
    ledger = ContributionLedger(engagement_id="fp")
    set_active_ledger(ledger)
    try:
        result = await _agent(fingerprinter)._step_web_recon(
            "10.0.0.1",
            ServiceScanResult(services=[ReconService(port=80, service_name="http")]),
        )
    finally:
        set_active_ledger(None)
    return result, ledger


async def test_whatweb_contributes_components_with_versions(scope: EngagementScope) -> None:
    """The seam delivers what the wrapper parsed — names AND versions.

    The version half is the point: ``WhatWebScanResult.versions`` has been parsed
    since the wrapper was written and was read by nothing, which is precisely why
    the dependency→CVE path could not exist.
    """
    result, ledger = await _run(_RecordedWhatWeb)

    assert result.components, "the fingerprint seam contributed nothing"
    rec = next(r for r in ledger.records() if r.name == "whatweb")
    assert rec.items_contributed == len(result.components) > 0
    assert rec.alarms == [], "a tool that contributed components must not alarm"


async def test_httpx_contributes_through_the_same_declared_contract() -> None:
    """The chain's fallback contributes by the SAME method, not a second spelling.

    This is what the duck-typed seam could not do: ``httpx`` names its field
    ``tech`` and whatweb names it ``technologies``, and the consumer used to have
    to know both. It now knows neither.
    """
    result, ledger = await _run(_RecordedHttpx)

    assert result.components
    rec = next(r for r in ledger.records() if r.name == "httpx")
    assert rec.alarms == []
    # The ledger counts what the TOOL contributed; the inventory holds what
    # survived dedup. They differ whenever one tool names a product twice — httpx
    # reports ``nginx`` from both ``-tech-detect`` and the ``webserver`` banner,
    # and ``dedupe_components`` keeps the one that carried a version. Asserting
    # equality would make the ledger's number a function of the deduper, which is
    # the wrong question: "did this tool contribute anything" is about the tool.
    assert rec.items_contributed >= len(result.components) > 0


async def test_httpx_splits_the_version_out_of_its_own_format() -> None:
    """httpx reports ``nginx:1.24.0``; the split belongs to the wrapper."""
    parsed = _RecordedHttpx(scope=_SCOPE).parse_output(
        (_FIXTURES / "httpx_output.jsonl").read_text(encoding="utf-8")
    )
    components = parsed.detected_components()
    assert components, "the fixture should yield at least one technology"
    assert all(" " not in c.version for c in components), (
        "a version carrying a space is a name that was not split"
    )


async def test_an_undeclaring_fingerprinter_is_a_dead_seam_not_an_empty_result(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Three technologies identified, none able to reach the inventory.

    The distinction the whole contract exists for: without it, "found nothing"
    and "cannot report anything" are the same empty list, and the second one
    survives for years.
    """
    with caplog.at_level(logging.WARNING, logger="test.fingerprint"):
        result, ledger = await _run(_UndeclaringFingerprinter)

    assert result.components == []
    rec = next(r for r in ledger.records() if r.name == "whatweb")
    assert rec.dead_seam
    assert LedgerAlarm.DEAD_SEAM in rec.alarms
    assert any("DEAD" in r.getMessage() for r in caplog.records)
