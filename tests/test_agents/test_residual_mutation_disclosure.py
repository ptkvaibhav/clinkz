"""A change TESTING made that the target cannot undo goes in what the client reads.

Every other honest-limits section in a Clinkz deliverable is about what the
engine could not prove. This one is about what it *did*: a key written onto a
running process's prototype chain, which no request removes and which the
operator has to clear by restarting the process.

Three properties, and each of them is the difference between a disclosure and a
formality:

* it renders in **both** client-facing documents, and **ahead of the findings**,
  because a reader who takes the severity counts and stops must not miss the one
  section that asks something of them;
* it renders **only when populated** — a section reporting "nothing was left
  behind" on every clean run is one an operator learns to skip, which is exactly
  the state they must not be in on the run where it is populated; and
* a **wildcard authorization does not silently cover** the class that produces
  it, and the report says which key would.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents._report_pdf import render_report_pdf
from clinkz.agents.exploit import TERMINAL_DISPATCH_CLASSES
from clinkz.agents.report import ReportAgent, _parse_residual_mutations
from clinkz.models.engagement import AuthorizationRecord
from clinkz.models.finding import ResidualMutation
from clinkz.models.report import ExecutiveSummary, NotTestedCategory, PentestReport
from clinkz.models.vuln_classes import VULN_CLASSES

KEY = "x-clinkz-pp-40412"
SECTION = "Changes this test left on your systems"


def _mutation() -> ResidualMutation:
    return ResidualMutation(
        endpoint="http://target.example/api/v2/profile",
        key=KEY,
        mechanism=(
            f"a recursive merge of a JSON request body wrote {KEY!r} onto the target "
            "process's Object.prototype, where every object the process creates "
            "inherits it"
        ),
        test_method="_test_prototype_pollution",
        witnessed=True,
        remediation=(
            f"This test wrote the key {KEY!r} onto the running process's Object.prototype "
            "and it is still there. Restart the affected process (every worker, if the "
            "service runs more than one) to clear it."
        ),
    )


def _report(mutations: list[ResidualMutation]) -> PentestReport:
    now = datetime.now(UTC)
    return PentestReport(
        engagement_name="residual-mutation-disclosure",
        target_scope=["http://target.example"],
        test_start=now,
        test_end=now,
        executive_summary=ExecutiveSummary(
            overview="disclosure test", risk_rating="High", run_completed=True
        ),
        residual_mutations=mutations,
    )


class TestItReachesTheClientFacingDocuments:
    def test_markdown_names_the_key_and_the_restart(self) -> None:
        markdown = ReportAgent._render_markdown(_report([_mutation()]), [])
        assert SECTION in markdown
        assert KEY in markdown
        assert "restart" in markdown.lower()

    def test_markdown_puts_it_ahead_of_the_findings(self) -> None:
        """A reader who takes the counts and stops must have hit this first."""
        markdown = ReportAgent._render_markdown(_report([_mutation()]), [])
        assert markdown.index(SECTION) < markdown.index("## Findings")

    def test_the_pdf_carries_it_too(self, tmp_path: Path) -> None:
        """All three documents render from the same structure, so the PDF is not
        allowed to be the one that drops it."""
        pypdf = pytest.importorskip("pypdf")
        destination = tmp_path / "residual.pdf"
        render_report_pdf(_report([_mutation()]), destination)
        pages = pypdf.PdfReader(str(destination)).pages
        text = "\n".join(page.extract_text() or "" for page in pages)
        assert SECTION in text
        assert KEY in text


class TestItIsSilentWhenThereIsNothingToSay:
    def test_a_clean_run_renders_no_section(self) -> None:
        markdown = ReportAgent._render_markdown(_report([]), [])
        assert SECTION not in markdown

    def test_a_clean_run_renders_no_pdf_section(self, tmp_path: Path) -> None:
        pypdf = pytest.importorskip("pypdf")
        destination = tmp_path / "clean.pdf"
        render_report_pdf(_report([]), destination)
        pages = pypdf.PdfReader(str(destination)).pages
        text = "\n".join(page.extract_text() or "" for page in pages)
        assert SECTION not in text


class TestTheHandoffSurvivesTheOrchestrator:
    """The mutation crosses a dict boundary; a drop there is a silent loss."""

    def test_a_round_trip_through_the_handoff_keeps_the_key(self) -> None:
        parsed = _parse_residual_mutations([_mutation().model_dump(mode="json")])
        assert len(parsed) == 1
        assert parsed[0].key == KEY

    def test_a_malformed_row_does_not_take_the_rest_with_it(self) -> None:
        parsed = _parse_residual_mutations(
            ["not a dict", {"nonsense": True}, _mutation().model_dump(mode="json")]
        )
        assert [m.key for m in parsed] == [KEY]

    def test_nothing_handed_over_is_an_empty_list(self) -> None:
        assert _parse_residual_mutations(None) == []


class TestAWildcardDoesNotCoverATerminalClass:
    """ "Test everything" is not "leave my process altered until I restart it"."""

    @staticmethod
    def _not_tested(authorization: AuthorizationRecord) -> list[Any]:
        agent = ReportAgent.__new__(ReportAgent)
        return ReportAgent._build_not_tested(
            agent,
            engagement_id="00000000-0000-0000-0000-000000000000",
            authorization=authorization,
            scope_out=[],
            safety={},
            authentication={},
            finding_count=0,
        )

    def test_a_wildcard_run_states_the_terminal_class_was_withheld(self) -> None:
        record = AuthorizationRecord.model_construct(
            permitted_techniques=["all"], authorization_reference="REF-1"
        )
        withheld = [
            item
            for item in self._not_tested(record)
            if item.category == NotTestedCategory.NOT_PERMITTED
        ]
        labels = {item.item for item in withheld}
        terminal_labels = {
            v.label for v in VULN_CLASSES if v.test_method in TERMINAL_DISPATCH_CLASSES
        }
        assert terminal_labels, "no terminal class has a client label to withhold"
        assert terminal_labels <= labels, (labels, terminal_labels)

    def test_the_reason_names_the_key_that_would_authorize_it(self) -> None:
        """A withheld class the client cannot re-enable is a dead end, not a
        disclosure."""
        record = AuthorizationRecord.model_construct(
            permitted_techniques=["all"], authorization_reference="REF-1"
        )
        keys = {v.key for v in VULN_CLASSES if v.test_method in TERMINAL_DISPATCH_CLASSES}
        reasons = " ".join(
            item.reason
            for item in self._not_tested(record)
            if item.category == NotTestedCategory.NOT_PERMITTED
        )
        for key in keys:
            assert f"'{key}'" in reasons, (key, reasons)
