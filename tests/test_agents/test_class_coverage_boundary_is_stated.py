"""A coverage boundary pinned in a test and stated nowhere a client reads is hidden.

The anchored IDOR oracle reads attribution off an OWNING FIELD in the crossing
response — a field the application itself uses to name a record's owner. That
retires the public-catalogue false positive, and it costs recall on an endpoint
whose per-user records name no owner: the crossing succeeds, every control arm
refuses, and the class still abstains, because "differs from mine, from a
never-issued reference, and from what an anonymous caller is served" is three
negatives that a shared record behind a login satisfies exactly as well.

That loss was pinned as a test named after it and appeared in no deliverable. An
access-control flaw on such an endpoint produces exactly the artifact a sound
endpoint produces — nothing — so leaving it out of *What was NOT tested* lets an
absence of findings read as an absence of flaws, which is the silence every other
rule in that section exists to break. The boundary is now DECLARED by the
producer, tied to a registered abstain reason, and rendered on a clean run.
"""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from clinkz.agents.report import ReportAgent
from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED
from clinkz.models.report import NotTestedCategory
from clinkz.models.vuln_classes import VULN_CLASSES, CoverageBoundary


def _not_tested() -> list[Any]:
    """A clean, fully-capable run: nothing excluded, both roles, an oracle that ran."""
    agent = ReportAgent.__new__(ReportAgent)
    return ReportAgent._build_not_tested(
        agent,
        engagement_id="00000000-0000-0000-0000-000000000000",
        authorization=None,
        scope_out=[],
        safety={},
        authentication={"authenticated": True, "multi_role": True},
        finding_count=12,
        client_oracle={"resolved": True, "runs": 40, "reported": 40, "executions_witnessed": 3},
    )


class TestTheBoundaryIsDeclaredNotDescribed:
    def test_every_declared_boundary_names_a_registered_abstain_reason(self) -> None:
        """The prose is tied to a reason the engine actually produces.

        Without it the sentence is free text and can drift into describing an
        abstain that never happens — a disclaimer, which is what
        ``MultiPrincipalRequirement`` exists because of.
        """
        declared = [c for c in VULN_CLASSES if c.coverage_boundary.declared]
        assert declared, "at least _test_idor declares one"
        for vuln_class in declared:
            assert vuln_class.coverage_boundary.why_unconfirmed in UNPROVEN_WHY_UNCONFIRMED, (
                f"{vuln_class.test_method} declares a boundary whose reason is not in the "
                "closed vocabulary, so the lead it describes lands under a different reason"
            )

    def test_idor_declares_the_owning_field_boundary(self) -> None:
        (idor,) = [c for c in VULN_CLASSES if c.test_method == "_test_idor"]
        boundary = idor.coverage_boundary
        assert boundary.why_unconfirmed == "crossing_response_names_no_owning_principal"
        assert "abstains rather than infers" in boundary.limitation
        assert "three negatives" in boundary.limitation

    def test_half_a_boundary_is_refused_at_construction(self) -> None:
        """A sentence with no reason discloses a rule nothing enforces; a reason
        with no sentence discloses nothing at all."""
        with pytest.raises(ValidationError):
            CoverageBoundary(why_unconfirmed="not_instrumentable")
        with pytest.raises(ValidationError):
            CoverageBoundary(limitation="we abstain on some things")

    def test_no_boundary_is_the_default(self) -> None:
        assert CoverageBoundary().declared is False
        undeclared = [c for c in VULN_CLASSES if not c.coverage_boundary.declared]
        assert undeclared, "the field is a declaration, not a partition"


class TestTheBoundaryReachesTheDeliverable:
    def test_it_renders_on_a_clean_run(self) -> None:
        """A bound that decided coverage renders whether or not it bit this run.

        It is a property of the CLASS, not of what this target happened to have,
        and a client cannot ask about a limitation that only appears when it
        already cost them something.
        """
        items = _not_tested()
        abstains = [i for i in items if i.category is NotTestedCategory.CLASS_ABSTAINS]
        assert abstains, "a clean, fully-capable run still states the class's own boundary"
        (row,) = [i for i in abstains if "Insecure Direct Object Reference" in i.item]
        assert "cannot attribute" in row.item
        assert "abstains rather than infers" in row.reason

    def test_the_reason_is_the_producer_declaration_verbatim(self) -> None:
        """Nothing between the registry and the page rewrites it."""
        (idor,) = [c for c in VULN_CLASSES if c.test_method == "_test_idor"]
        items = _not_tested()
        (row,) = [
            i
            for i in items
            if i.category is NotTestedCategory.CLASS_ABSTAINS
            and "Insecure Direct Object Reference" in i.item
        ]
        assert row.reason == idor.coverage_boundary.limitation

    def test_it_is_not_filed_as_a_missing_session_or_a_missing_oracle(self) -> None:
        """Three different limitations with three different remedies.

        UNAUTHENTICATED is what the ENGAGEMENT lacked and a second credential
        fixes it; NO_CLIENT_SIDE_ORACLE is a capability that was absent and a
        browser fixes it. This one is a boundary of the METHOD and neither fixes
        it — filing it with either would tell a client to do something that
        cannot work.
        """
        items = _not_tested()
        row = next(i for i in items if i.category is NotTestedCategory.CLASS_ABSTAINS)
        assert row.category is not NotTestedCategory.UNAUTHENTICATED
        assert row.category is not NotTestedCategory.NO_CLIENT_SIDE_ORACLE

    @pytest.mark.parametrize("renderer", ["markdown", "pdf"])
    def test_both_renderers_have_a_heading_for_it(self, renderer: str) -> None:
        """An unmapped category still renders under its raw enum name, which is
        the fallback working — but ``class_abstains`` as a heading is not a
        sentence a client can read."""
        import inspect

        from clinkz.agents import _report_pdf

        source = (
            inspect.getsource(ReportAgent._render_not_tested)
            if renderer == "markdown"
            else inspect.getsource(_report_pdf)
        )
        assert "NotTestedCategory.CLASS_ABSTAINS" in source
        assert "the class abstains" in source
