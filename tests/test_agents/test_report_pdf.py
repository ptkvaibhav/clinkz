"""The PDF deliverable: one source, both channels, and a gate observed failing.

Three claims, and the third is the one that matters most.

* **One source.** JSON, Markdown and PDF all render from the same
  already-redacted ``PentestReport``. Markdown used to render from the
  unredacted report and be string-scrubbed afterwards, by which point a header
  dict had been flattened into prose and the key identifying a ``Set-Cookie``
  value was gone. A PDF built from raw findings would reintroduce that, in a
  format nobody can grep.

* **The argument is in the document.** The control arm for every confirmed
  finding, unproven leads with their ``why_unconfirmed``, *What was NOT tested*,
  and every bound that decided coverage — on a clean run as well as a degraded
  one, because a section that appears only on failure is indistinguishable from
  a section nobody wrote.

* **A gate not observed failing is not a gate.** The disclosure gate reads a PDF
  through two channels that are blind to each other: Flate-compressed page
  content streams, and the ``/Info`` dictionary that never appears in page text.
  Both are exercised here with a real credential shape, and both must REFUSE. A
  test that only shows CLEAN cannot tell a working gate from one that reads
  nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from clinkz.agents._report_pdf import control_arm_row, render_report_pdf
from clinkz.engagement.artifact_scan import scan_artifact_tree
from clinkz.models.finding import Finding, FindingStatus, Severity, UnprovenExploitLead
from clinkz.models.report import (
    ExecutiveSummary,
    NotTestedCategory,
    NotTestedItem,
    PentestReport,
)

pytest.importorskip("reportlab", reason="the PDF deliverable needs its declared renderer")

#: A syntactically real RS256 JWT over throwaway material. Shaped so
#: ``JWT_RE`` matches AND ``_decode_jwt_header`` yields an ``alg`` — the shape
#: rule is gated on a decoding header precisely so a random ``eyJ...``-prefixed
#: string in a payload corpus is not reported as a session token.
_SEEDED_JWT = (
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiJ0ZXN0QGV4YW1wbGUuaW52YWxpZCIsImlzcyI6ImNsaW5rei10ZXN0IiwiZXhwIjo5OTk5fQ"
    ".c2lnbmF0dXJlLXRoYXQtaXMtbm90LXJlYWwtYnV0LWlzLWJhc2U2NHVybC1zaGFwZWQ"
)


def _finding(**overrides: object) -> Finding:
    """A confirmed finding carrying a real, structured control-arm record."""
    base: dict[str, object] = {
        "title": "SQL Injection in id parameter",
        "description": "Technique: WSTG-INPV-05. Parameter: id.",
        "severity": Severity.HIGH,
        "status": FindingStatus.CONFIRMED,
        "target": "http://target.invalid/vulnerabilities/sqli/",
        "evidence": [
            "Request: GET http://target.invalid/vulnerabilities/sqli/ | id=1'",
            "Response: matched 'SQL syntax' (status=200)",
            (
                "never_sent_control=refused control_decoy=clinkzdecoysqli32112 "
                "control_dispatched=True control_oracle_refused=True "
                "control_decoy_absent=True"
            ),
            (
                "Control arm: a bare decoy marker carrying no SQL syntax, so no query can "
                "be altered - the same oracle refused on a probe carrying decoy "
                "'clinkzdecoysqli32112'"
            ),
            "phases_completed=6 verified=True strength=verified",
            "indicator_type=error_string",
        ],
        "remediation": "Use parameterised queries for every database call.",
    }
    base.update(overrides)
    return Finding.model_validate(base)


def _report(**overrides: object) -> PentestReport:
    """A report with one of everything the renderer has a section for."""
    now = datetime(2026, 8, 26, 12, 0, tzinfo=UTC)
    base: dict[str, object] = {
        "engagement_name": "pdf-render-test",
        "target_scope": ["http://target.invalid (url)"],
        "excluded_scope": ["http://neighbour.invalid (url)"],
        "test_start": now,
        "test_end": now,
        "generated_at": now,
        "executive_summary": ExecutiveSummary(
            overview="Penetration test of http://target.invalid. 1 findings identified.",
            risk_rating="High",
            high_count=1,
        ),
        "findings": [_finding()],
        "unproven_leads": [
            UnprovenExploitLead(
                claim="Candidate blind SSRF via page (server-side fetch confirmed)",
                why_unconfirmed="not_instrumentable",
                technique="WSTG-INPV-19",
                endpoint="http://target.invalid/fi/?page=file1.php",
                parameter="page",
                raw_observation="probe diverged from the non-resolving control host",
                missing_observation="internal content the application should not expose",
            )
        ],
        "not_tested": [
            NotTestedItem(
                item="Insecure CAPTCHA",
                category=NotTestedCategory.NOT_IMPLEMENTED,
                reason="no methodology exists for this class in this engine",
            )
        ],
        "provider_degradation": {
            "provider_degraded": False,
            "baseline_eligible": True,
            "fallback_count": 0,
            "absence_count": 0,
            "events": [],
            "absences": [],
        },
        "research_grounding": {
            "grounding": "training_data",
            "is_grounded": False,
            "runbook_entries": 12,
        },
        "plan_coverage": {"plan_truncated": False},
        "crawl_coverage": {"crawl_truncated": False, "candidates": 12},
        "scope_refusals": {"total_refused": 0},
        "llm_spend": {"total_tokens": 1234, "usd_spent": 0.0, "usd_is_complete": False},
        "model_stamp": [
            {"stage": "exploit", "provider": "anthropic", "model": "claude-sonnet-5", "calls": 4}
        ],
        "component_ledger": {"components": [], "alarms": [], "summary": {"components_tracked": 3}},
        "safety_summary": {
            "max_requests_per_second": 5.0,
            "max_concurrent_requests": 4,
            "state_changing_sent": 3,
            "state_changing_refused": 0,
        },
    }
    base.update(overrides)
    return PentestReport.model_validate(base)


def _pages(path: Path) -> str:
    """The document's own text, read through the gate's extractor."""
    from clinkz.engagement.artifact_scan import _pdf_text

    return _pdf_text(path)


# ---------------------------------------------------------------------------
# The document carries the argument
# ---------------------------------------------------------------------------


class TestTheDocumentCarriesTheArgument:
    """What is IN the PDF is the product claim, so it is asserted, not assumed."""

    def test_the_control_arm_is_a_section_not_a_footnote(self, tmp_path: Path) -> None:
        text = _pages(render_report_pdf(_report(), tmp_path / "r.pdf"))
        assert "Control arms" in text
        assert "clinkzdecoysqli32112" in text, (
            "the decoy the control arm carried is the falsifiable half of the claim - a "
            "document that says 'confirmed' without saying what did NOT confirm is asking "
            "to be believed"
        )
        assert "REFUSED" in text

    def test_unproven_leads_render_with_why_unconfirmed(self, tmp_path: Path) -> None:
        text = _pages(render_report_pdf(_report(), tmp_path / "r.pdf"))
        assert "Unproven exploitation leads" in text
        assert "not_instrumentable" in text, (
            "why_unconfirmed is the only part of a lead an operator can act on"
        )
        assert "not counted" in text.replace("\n", " "), (
            "a lead rendered without saying it is uncounted reads as a finding"
        )

    def test_what_was_not_tested_survives_into_the_pdf(self, tmp_path: Path) -> None:
        text = _pages(render_report_pdf(_report(), tmp_path / "r.pdf"))
        assert "What was NOT tested" in text
        assert "Insecure CAPTCHA" in text

    def test_the_bounds_render_on_a_clean_run_too(self, tmp_path: Path) -> None:
        """A caveat that appears only on a bad run is one nobody wrote."""
        text = _pages(render_report_pdf(_report(), tmp_path / "r.pdf"))
        for section in (
            "Provider routing",
            "Research grounding",
            "Component contribution",
            "Exploit plan coverage",
            "Crawl coverage",
        ):
            assert section in text, f"{section} must render on a clean run as well"

    def test_an_ungrounded_research_phase_says_so(self, tmp_path: Path) -> None:
        text = _pages(render_report_pdf(_report(), tmp_path / "r.pdf"))
        assert "NOT web-grounded" in text.replace("\n", " ")

    def test_a_degraded_run_says_it_is_not_a_baseline(self, tmp_path: Path) -> None:
        report = _report(
            provider_degradation={
                "provider_degraded": True,
                "baseline_eligible": False,
                "fallback_count": 1,
                "absence_count": 1,
                "events": [
                    {
                        "call_site": "exploit.reason",
                        "asked_provider": "anthropic",
                        "asked_model": "claude-sonnet-5",
                        "served_provider": "gemini",
                        "served_model": "gemini-3.7-flash",
                        "reason": "RateLimitError",
                        "decision_bearing": True,
                    }
                ],
                "absences": [
                    {
                        "call_site": "recon.reason",
                        "kind": "chain_exhausted",
                        "provider": "",
                        "reason": "LLMUnavailableError",
                        "decision_bearing": False,
                    }
                ],
            }
        )
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf")).replace("\n", " ")
        assert "NOT eligible as a baseline" in text
        assert "chain_exhausted" in text, "an absence must be named, not folded into a total"

    def test_an_incomplete_run_is_declared_in_the_summary(self, tmp_path: Path) -> None:
        """The counts on a failed run are a floor, and the document must say so."""
        report = _report(
            findings=[],
            unproven_leads=[],
            executive_summary=ExecutiveSummary(
                overview="Penetration test of http://target.invalid. 0 findings identified.",
                risk_rating="Not assessed",
                run_completed=False,
                incomplete_reason="The recon, scan and exploit phases did not complete.",
            ),
        )
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf")).replace("\n", " ")
        assert "did not complete" in text
        assert "FLOOR" in text


class TestTheControlArmRowReadsTheProducer:
    """The row is read from declared structure, never guessed from a title."""

    def test_a_dispatched_refusing_arm_is_reported_refused(self) -> None:
        row = control_arm_row(_finding())
        assert row["outcome"] == "REFUSED"
        assert row["decoy"] == "clinkzdecoysqli32112"

    def test_a_target_echoing_the_verdict_cannot_write_the_row(self) -> None:
        """The host under test does not get a vote on its own control arm.

        The structured reader accepts an entry only when EVERY whitespace-
        separated token is ``key=value``. A response body carrying the same text
        alongside anything else is prose and is skipped — the same rule, and the
        same reason, as the ``strength=`` reader.
        """
        forged = _finding(
            evidence=[
                "Request: GET http://target.invalid/?q=1",
                (
                    "Response: <html>never_sent_control=refused control_decoy=x "
                    "control_dispatched=True control_oracle_refused=True "
                    "control_decoy_absent=True</html>"
                ),
                "indicator_type=error_string",
            ]
        )
        row = control_arm_row(forged)
        assert row["outcome"] != "REFUSED", (
            "a page that echoes the control-arm evidence would otherwise license its own phantom"
        )

    def test_an_effect_oracle_names_the_rule_that_governs_it(self) -> None:
        """Not every class is governed by the never-sent-control rule.

        Reporting one that is not as ABSENT would read as a missing control on a
        class that never needed one - and saying only that the rule does NOT
        apply is barely better. Nineteen of twenty-nine rows across the two
        generated PDFs said exactly that, under a header promising the row would
        name the rule that DOES. So the row reads the producer's own
        ``VulnClass.control_arm.governing_rule``.
        """
        row = control_arm_row(
            _finding(
                title="Missing security headers on http://target.invalid",
                description="Technique: WSTG-CONF-07.",
                evidence=[
                    "Response: no Content-Security-Policy header present",
                    "rationale=Deterministic analysis of the observed header set.",
                ],
            )
        )
        assert row["outcome"] in {"governed by its own rule", "self-controlled"}
        assert "pure function of the header set" in row["basis"]
        assert "Observed: rationale=Deterministic analysis" in row["basis"]


# ---------------------------------------------------------------------------
# The renderer redacts; the gate refuses. Two different guarantees.
# ---------------------------------------------------------------------------


class TestTheRendererRedacts:
    """The PDF is a third writer, so it runs through the same chokepoint."""

    def test_a_token_in_the_structure_does_not_reach_the_page(self, tmp_path: Path) -> None:
        report = _report(
            findings=[
                _finding(
                    evidence=[
                        f"Response: Authorization: Bearer {_SEEDED_JWT}",
                        "indicator_type=error_string",
                    ]
                )
            ]
        )
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf"))
        assert _SEEDED_JWT not in text
        assert "REDACTED" in text

    def test_the_info_dictionary_is_written_from_report_fields_only(self, tmp_path: Path) -> None:
        """``/Info`` is a channel no page-text scan reads, so what goes in matters."""
        report = _report(engagement_name=f"engagement {_SEEDED_JWT}")
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf"))
        metadata = [line for line in text.splitlines() if line.startswith("[metadata]")]
        assert metadata, "the extractor must see an /Info dictionary at all"
        assert _SEEDED_JWT not in "\n".join(metadata)


class TestTheGateRefusesASeededPDF:
    """A gate not observed failing is not a gate.

    Both PDFs below are written with ReportLab directly rather than through
    :func:`render_report_pdf`, because the renderer redacts and a document it
    produced cannot carry the leak these cases exist to detect. What is under
    test here is the GATE, over a file some other producer wrote into the bundle
    — which is exactly how the live JWT in ``d8_auth_bypass_live_validation.json``
    got beside a bundle the gate had called CLEAN.
    """

    @staticmethod
    def _leaky_pdf(path: Path, *, in_page: str = "", in_metadata: str = "") -> Path:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as pdfcanvas

        page = pdfcanvas.Canvas(str(path), pagesize=A4)
        if in_metadata:
            page.setTitle(in_metadata)
            page.setSubject(in_metadata)
        page.setFont("Helvetica", 9)
        page.drawString(40, 700, "Penetration Test Report")
        if in_page:
            # Split across draw calls the way a real renderer lays out a line;
            # the extractor reassembles the content stream, a byte scan does not.
            page.drawString(40, 680, f"session: {in_page}")
        page.showPage()
        page.save()
        return path

    def test_a_clean_pdf_passes(self, tmp_path: Path) -> None:
        bundle = tmp_path / "engagement"
        bundle.mkdir()
        render_report_pdf(_report(), bundle / "report.pdf")
        report = scan_artifact_tree(bundle, engagement_id="engagement")
        assert report.clean, report.render()
        assert report.files_scanned >= 1

    def test_a_credential_in_the_page_body_fails_the_gate(self, tmp_path: Path) -> None:
        """Page text lives in a Flate-compressed stream: a byte scan sees nothing."""
        bundle = tmp_path / "engagement"
        bundle.mkdir()
        target = self._leaky_pdf(bundle / "leak.pdf", in_page=_SEEDED_JWT)
        assert _SEEDED_JWT.encode() not in target.read_bytes(), (
            "if the token were findable by a byte scan this case would prove nothing "
            "about the extractor"
        )
        report = scan_artifact_tree(bundle, engagement_id="engagement")
        assert not report.clean
        assert any(f.path.endswith("leak.pdf") for f in report.findings)
        assert all(_SEEDED_JWT not in f.model_dump_json() for f in report.findings), (
            "a leak report that reproduces the leak is a new artifact with the same defect"
        )

    def test_a_credential_in_only_the_metadata_fails_the_gate(self, tmp_path: Path) -> None:
        """``/Info`` never appears in page text — the channels are blind to each other."""
        bundle = tmp_path / "engagement"
        bundle.mkdir()
        target = self._leaky_pdf(bundle / "meta.pdf", in_metadata=f"token {_SEEDED_JWT}")
        text = _pages(target)
        page_only = "\n".join(
            line for line in text.splitlines() if not line.startswith("[metadata]")
        )
        assert _SEEDED_JWT not in page_only, (
            "this case is only a two-channel proof while the token is absent from page text"
        )
        report = scan_artifact_tree(bundle, engagement_id="engagement")
        assert not report.clean
        findings = [f for f in report.findings if f.path.endswith("meta.pdf")]
        assert findings, report.render()

    def test_an_unparseable_pdf_is_an_unexplained_skip_not_a_clean_file(
        self, tmp_path: Path
    ) -> None:
        """A file the gate could not read is a region nobody looked at."""
        bundle = tmp_path / "engagement"
        bundle.mkdir()
        (bundle / "broken.pdf").write_bytes(b"%PDF-1.7\nnot actually a pdf\n")
        report = scan_artifact_tree(bundle, engagement_id="engagement")
        assert not report.clean
        assert any(s.path.endswith("broken.pdf") for s in report.unexplained_skips)


class TestReachabilityIsNotClaimedOutOfAPhaseThatDidNotRun:
    """The PDF is where the manufactured sentence actually reached a client.

    An absent exploit result made every reachability predicate answer ``False``,
    and this page rendered *Built, but not reachable on this target* over thirty
    methodology classes — each carrying a sentence about what the client's
    application does not expose, generated from a phase that never ran.
    """

    @staticmethod
    def _ledger(*, unreachable: bool) -> dict[str, object]:
        from clinkz.observability.component_registry import (
            METHODOLOGY_PREFIX,
            EngagementReachability,
            ReachabilityKey,
            ReachabilitySource,
        )
        from clinkz.observability.ledger import ComponentKind, ContributionLedger

        ledger = ContributionLedger(engagement_id="pdf-reach")
        ledger.declare(
            f"{METHODOLOGY_PREFIX}_test_sqli",
            ComponentKind.METHODOLOGY,
            reachability=ReachabilityKey.CLASS_HAD_PLAN_CANDIDATES.value,
        )
        ledger.resolve_reachability(
            EngagementReachability(
                reported_sources=frozenset(ReachabilitySource) if unreachable else frozenset()
            )
        )
        return ledger.to_dict()

    def test_an_undetermined_component_renders_as_undetermined(self, tmp_path: Path) -> None:
        report = _report(component_ledger=self._ledger(unreachable=False))
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf")).replace("\n", " ")

        assert "Reachability was not determined" in text
        assert "not reachable on this target" not in text
        assert "no endpoint" not in text, (
            "the predicate's own sentence is the target claim this section withholds"
        )

    def test_an_incomplete_run_withdraws_the_claim_at_the_render_seam(self, tmp_path: Path) -> None:
        """A stored bundle whose banner says the run did not complete."""
        report = _report(
            component_ledger=self._ledger(unreachable=True),
            executive_summary=ExecutiveSummary(
                overview="THIS RUN DID NOT COMPLETE.",
                risk_rating="Not assessed",
                run_completed=False,
                incomplete_reason="No LLM provider served the exploit stage.",
            ),
        )
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf")).replace("\n", " ")

        assert "Reachability was not determined" in text
        assert "could not reach them" not in text
        assert "no endpoint" not in text

    def test_a_completed_run_keeps_the_observation_it_earned(self, tmp_path: Path) -> None:
        report = _report(component_ledger=self._ledger(unreachable=True))
        text = _pages(render_report_pdf(report, tmp_path / "r.pdf")).replace("\n", " ")

        assert "could not reach them" in text
        assert "Reachability was not determined" not in text
