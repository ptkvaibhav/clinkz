"""``--resume``: rebuild an interrupted engagement's deliverable, send nothing.

The property that matters most is not that a report appears — it is that the
report says what it is. A regenerated deliverable that looks like a completed
engagement is worse than no deliverable, because a reader has no way to tell
that coverage stopped early.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from clinkz.cli import EXIT_BAD_INPUT, EXIT_OK, app
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from tests.authorization_fixtures import TEST_AUTHORIZATION

runner = CliRunner()


async def _seed(db: Path, *, with_finding: bool = True) -> str:
    """Create an engagement carrying one persisted finding, as a killed run would."""
    scope = EngagementScope(
        name="resume-test",
        targets=[ScopeEntry(value="http://app.test", type=ScopeType.URL)],
        authorization=TEST_AUTHORIZATION,
    )
    async with StateStore(db) as state:
        engagement_id = await state.create_engagement(scope.name, scope.model_dump(mode="json"))
        if with_finding:
            await state.add_finding(
                engagement_id,
                {
                    "id": "finding-1",
                    "target": "http://app.test",
                    "title": "SQL injection in the search parameter",
                    "description": "A UNION row was returned in a successful response.",
                    "severity": "high",
                    "affected_url": "http://app.test/search",
                    "evidence": ["payload=' UNION SELECT 1--", "row returned: 200"],
                },
            )
    return engagement_id


@pytest.fixture
def seeded(tmp_path: Path) -> tuple[Path, str]:
    import asyncio

    db = tmp_path / "clinkz.db"
    engagement_id = asyncio.run(_seed(db))
    return db, engagement_id


def test_resume_rebuilds_the_report_from_persisted_findings(
    seeded: tuple[Path, str], tmp_path: Path
) -> None:
    db, engagement_id = seeded
    out = tmp_path / "artifacts"
    result = runner.invoke(
        app,
        ["scan", "-t", "unused", "--resume", engagement_id, "--db", str(db), "--out", str(out)],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "1 persisted finding" in result.output
    assert "Nothing was sent to the target" in result.output

    report = out / engagement_id / f"report_{engagement_id}.json"
    assert report.is_file(), f"no report at {report}"
    data = json.loads(report.read_text(encoding="utf-8"))
    assert len(data["findings"]) == 1
    assert data["findings"][0]["title"].startswith("SQL injection")


def test_a_resumed_report_declares_that_it_is_resumed(
    seeded: tuple[Path, str], tmp_path: Path
) -> None:
    """A deliverable that looks complete but is not is the failure this prevents."""
    db, engagement_id = seeded
    out = tmp_path / "artifacts"
    runner.invoke(
        app,
        ["scan", "-t", "unused", "--resume", engagement_id, "--db", str(db), "--out", str(out)],
    )
    markdown = (out / engagement_id / f"report_{engagement_id}.md").read_text(encoding="utf-8")
    assert "regenerated from the persisted state" in markdown
    assert "No request was sent to the target" in markdown

    data = json.loads(
        (out / engagement_id / f"report_{engagement_id}.json").read_text(encoding="utf-8")
    )
    resumed = [i for i in data["not_tested"] if "regenerated" in i["reason"]]
    assert resumed, "the resumed origin is not in the machine-readable report"


def test_resuming_an_unknown_engagement_is_a_setup_error(tmp_path: Path) -> None:
    db = tmp_path / "clinkz.db"
    import asyncio

    asyncio.run(_seed(db))
    result = runner.invoke(
        app, ["scan", "-t", "unused", "--resume", "not-an-engagement", "--db", str(db)]
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "No engagement" in result.output


def test_resume_never_constructs_an_orchestrator(
    seeded: tuple[Path, str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It sends nothing, so it must not go anywhere near the engine that could."""
    db, engagement_id = seeded
    reached: list[str] = []
    monkeypatch.setattr(
        "clinkz.orchestrator.orchestrator.OrchestratorAgent.__init__",
        lambda *a, **k: reached.append("orchestrator"),
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "unused",
            "--resume",
            engagement_id,
            "--db",
            str(db),
            "--out",
            str(tmp_path / "artifacts"),
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert not reached
