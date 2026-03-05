"""Tests for CriticAgent — finding validation and state store marking.

Coverage:
- Valid finding (evidence + CVSS + description + remediation) → validated
- Missing evidence on high-severity finding → rejected
- Missing CVSS on critical finding → rejected
- Empty description → rejected
- Missing remediation on medium finding → rejected
- Info severity finding without evidence → validated (info is exempt)
- LLM returns INVALID verdict → finding rejected
- LLM returns unexpected format → defaults to valid
- mark_finding_validated() called for each validated finding
- Findings pulled from state store when not provided in input_data
- run() returns {"validated": [...], "rejected": [...], "status": "complete"}
- reason() and research() are never called
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from clinkz.agents.critic import CriticAgent
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage
from clinkz.models.finding import Finding, FindingStatus, Severity
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore

# ---------------------------------------------------------------------------
# Shared test scope
# ---------------------------------------------------------------------------

SCOPE = EngagementScope(
    name="critic-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)

# ---------------------------------------------------------------------------
# Mock LLM — controllable VALID / INVALID verdict
# ---------------------------------------------------------------------------


class MockCriticLLM(LLMClient):
    """Mock LLM for CriticAgent tests.

    Returns a configurable verdict from generate_text().  Raises
    AssertionError if reason() or research() are called.

    Args:
        verdict: "VALID" or "INVALID" prefix for generate_text() response.
        reason_text: Optional reason appended after the verdict prefix.
    """

    def __init__(self, verdict: str = "VALID", reason_text: str = "") -> None:
        self._verdict = verdict
        self._reason_text = reason_text or (
            "Evidence is conclusive and CVSS score is accurate."
            if verdict == "VALID"
            else "Evidence is insufficient to confirm exploitation."
        )
        self.generate_text_calls: list[str] = []

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        raise AssertionError("CriticAgent must not call reason()")

    async def research(self, query: str) -> str:
        raise AssertionError("CriticAgent must not call research()")

    async def generate_text(self, prompt: str) -> str:
        self.generate_text_calls.append(prompt)
        return f"{self._verdict}: {self._reason_text}"


class UnexpectedFormatLLM(LLMClient):
    """Mock LLM that returns an unrecognised response format."""

    async def reason(
        self,
        messages: list[LLMMessage],
        tools: list[dict[str, Any]] | None = None,
    ) -> AgentAction:
        raise AssertionError("CriticAgent must not call reason()")

    async def research(self, query: str) -> str:
        raise AssertionError("CriticAgent must not call research()")

    async def generate_text(self, prompt: str) -> str:
        return "MAYBE: This might be valid, unsure."


# ---------------------------------------------------------------------------
# Helper — build finding dicts
# ---------------------------------------------------------------------------


def _make_finding(
    title: str = "Test Finding",
    severity: str = "high",
    evidence: list[str] | None = None,
    cvss_score: float | None = 7.5,
    description: str = "Detailed technical description of the vulnerability.",
    remediation: str = "Apply the vendor patch immediately.",
    status: str = "confirmed",
) -> dict[str, Any]:
    """Build a minimal valid finding dict for test parameterization."""
    f = Finding(
        title=title,
        description=description,
        severity=Severity(severity),
        status=FindingStatus(status),
        target="http://example.com",
        evidence=evidence if evidence is not None else ["Evidence string"],
        cvss_score=cvss_score,
        remediation=remediation,
    )
    return f.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Tests — structural validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_valid_finding_validated(tmp_path: Path) -> None:
    """A complete, well-formed finding is validated and marked in state store."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding()
        fid = await state.add_finding(eid, finding)

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [{**finding, "id": fid}]})

    assert result["status"] == "complete"
    assert len(result["validated"]) == 1
    assert len(result["rejected"]) == 0
    assert result["validated"][0]["status"] == FindingStatus.CONFIRMED
    assert "validation_reason" in result["validated"][0]


@pytest.mark.asyncio
async def test_mark_finding_validated_called(tmp_path: Path) -> None:
    """mark_finding_validated() is called in the state store for valid findings."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding()
        fid = await state.add_finding(eid, finding)

        # Verify not validated yet
        pre = await state.get_findings(eid, validated_only=True)
        assert len(pre) == 0

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        await agent.run({"findings": [{**finding, "id": fid}]})

        # Now should be validated
        post = await state.get_findings(eid, validated_only=True)
    assert len(post) == 1


@pytest.mark.asyncio
async def test_missing_evidence_rejected(tmp_path: Path) -> None:
    """High-severity finding with no evidence is rejected (structural check)."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(severity="high", evidence=[])

        llm = MockCriticLLM("VALID")  # LLM would pass but structural check blocks it
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["validated"]) == 0
    assert len(result["rejected"]) == 1
    assert "evidence" in result["rejected"][0]["reason"].lower()
    # Structural check short-circuits before LLM — no generate_text() calls
    assert len(llm.generate_text_calls) == 0


@pytest.mark.asyncio
async def test_missing_cvss_on_critical_rejected(tmp_path: Path) -> None:
    """Critical finding without a CVSS score is rejected (structural check)."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(severity="critical", cvss_score=None)

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["rejected"]) == 1
    assert "cvss" in result["rejected"][0]["reason"].lower()
    assert len(llm.generate_text_calls) == 0


@pytest.mark.asyncio
async def test_missing_cvss_on_high_rejected(tmp_path: Path) -> None:
    """High finding without a CVSS score is also rejected."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(severity="high", cvss_score=None)

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["rejected"]) == 1
    assert len(llm.generate_text_calls) == 0


@pytest.mark.asyncio
async def test_empty_description_rejected(tmp_path: Path) -> None:
    """Finding with an empty description is rejected."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(description="")

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["rejected"]) == 1
    assert "description" in result["rejected"][0]["reason"].lower()


@pytest.mark.asyncio
async def test_missing_remediation_on_medium_rejected(tmp_path: Path) -> None:
    """Medium finding without remediation is rejected."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(severity="medium", remediation="")

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["rejected"]) == 1
    assert "remediation" in result["rejected"][0]["reason"].lower()


@pytest.mark.asyncio
async def test_info_finding_no_evidence_required(tmp_path: Path) -> None:
    """Informational findings are exempt from evidence and remediation checks."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(
            severity="info",
            evidence=[],
            cvss_score=None,
            remediation="",
        )
        fid = await state.add_finding(eid, finding)

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [{**finding, "id": fid}]})

    assert len(result["validated"]) == 1
    assert len(result["rejected"]) == 0


@pytest.mark.asyncio
async def test_llm_invalid_verdict_rejects_finding(tmp_path: Path) -> None:
    """LLM INVALID response causes structural-clean finding to be rejected."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding()  # passes all structural checks

        llm = MockCriticLLM(
            "INVALID",
            "CVSS score of 7.5 is overstated for the described vulnerability.",
        )
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["validated"]) == 0
    assert len(result["rejected"]) == 1
    assert "CVSS" in result["rejected"][0]["reason"] or "overstated" in result["rejected"][0]["reason"]
    assert len(llm.generate_text_calls) == 1  # LLM was consulted


@pytest.mark.asyncio
async def test_llm_unexpected_format_defaults_to_valid(tmp_path: Path) -> None:
    """Unrecognised LLM response format defaults to VALID to avoid false rejections."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding()
        fid = await state.add_finding(eid, finding)

        llm = UnexpectedFormatLLM()
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [{**finding, "id": fid}]})

    # Defaults to valid
    assert len(result["validated"]) == 1
    assert len(result["rejected"]) == 0


@pytest.mark.asyncio
async def test_multiple_findings_mixed_results(tmp_path: Path) -> None:
    """Batch of valid and invalid findings is split into validated/rejected correctly."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())

        valid_finding = _make_finding(title="Valid High SQLi", severity="high")
        missing_evidence = _make_finding(
            title="No Evidence Finding", severity="high", evidence=[]
        )
        info_finding = _make_finding(
            title="Info Finding", severity="info", evidence=[], cvss_score=None, remediation=""
        )
        fid_valid = await state.add_finding(eid, valid_finding)

        findings = [
            {**valid_finding, "id": fid_valid},
            missing_evidence,
            {**info_finding},
        ]
        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": findings})

    assert len(result["validated"]) == 2  # valid high + info
    assert len(result["rejected"]) == 1   # no evidence
    assert result["rejected"][0]["finding"]["title"] == "No Evidence Finding"
    assert result["status"] == "complete"


@pytest.mark.asyncio
async def test_findings_pulled_from_state_when_not_provided(tmp_path: Path) -> None:
    """When 'findings' is not in input_data, agent pulls from state store."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding()
        fid = await state.add_finding(eid, finding)

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        # Do NOT pass findings in input_data — should be fetched from state
        result = await agent.run({"engagement_id": eid})

    assert result["status"] == "complete"
    # The finding from state store should be processed
    assert len(result["validated"]) + len(result["rejected"]) == 1


@pytest.mark.asyncio
async def test_result_structure(tmp_path: Path) -> None:
    """run() returns a dict with 'validated', 'rejected', and 'status' keys."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": []})

    assert "validated" in result
    assert "rejected" in result
    assert "status" in result
    assert result["status"] == "complete"
    assert isinstance(result["validated"], list)
    assert isinstance(result["rejected"], list)


@pytest.mark.asyncio
async def test_rejected_finding_has_finding_and_reason_keys(tmp_path: Path) -> None:
    """Each entry in 'rejected' has 'finding' and 'reason' keys."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        finding = _make_finding(severity="critical", evidence=[])  # will be rejected

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        result = await agent.run({"findings": [finding]})

    assert len(result["rejected"]) == 1
    rejection = result["rejected"][0]
    assert "finding" in rejection
    assert "reason" in rejection
    assert isinstance(rejection["reason"], str)
    assert len(rejection["reason"]) > 0


@pytest.mark.asyncio
async def test_generate_text_called_once_per_valid_finding(tmp_path: Path) -> None:
    """generate_text() is called exactly once per finding that passes structural checks."""
    async with StateStore(tmp_path / "test.db") as state:
        eid = await state.create_engagement("Test", SCOPE.model_dump())
        findings = [_make_finding(title=f"Finding {i}") for i in range(3)]

        llm = MockCriticLLM("VALID")
        agent = CriticAgent(llm=llm, tools=[], scope=SCOPE, state=state, engagement_id=eid)
        await agent.run({"findings": findings})

    # 3 findings × 1 LLM review call each
    assert len(llm.generate_text_calls) == 3
