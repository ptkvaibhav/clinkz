"""The PDF deliverable — the document that actually reaches a client.

Third renderer of the SAME structure. JSON, Markdown and PDF all read one
already-redacted :class:`~clinkz.models.report.PentestReport`; none of them
reads the live findings, and none re-derives a fact another one computed. That
rule is not stylistic. Markdown used to render from the unredacted report and be
string-scrubbed afterwards, by which point a header dict had been flattened into
prose and the key that identified a ``Set-Cookie`` value was gone — so the one
document a client reads was the weakest of the three. A PDF built from raw
findings would reintroduce exactly that, with the additional property that
nobody can grep the result.

ReportLab rather than WeasyPrint
--------------------------------

WeasyPrint needs GTK/Pango at import time and does not import on Windows, which
is the platform this engine is developed and run on. A renderer that cannot be
executed on the machine that produces the bundle cannot be verified there
either, and an unverifiable client deliverable is worse than none. ReportLab is
pure Python with the base-14 Type1 fonts built in, so the document carries no
external asset and the generated file is self-contained.

What this document argues
-------------------------

The severity table is what every scanner ships. Two sections are not:

* **Control arms.** Every confirmed finding is rendered beside the control that
  REFUSED — the confirming request with the exploitation primitive removed and
  the marker re-minted, graded by the same oracle. "Confirmed, and here is what
  did not confirm" is the whole claim; a report that shows only the positive arm
  is asking to be believed. It is a top-level section rather than an appendix
  for that reason.
* **Unproven leads.** A lead is what this engine says INSTEAD of a false
  positive, so it is a section with its own heading and every lead's
  ``why_unconfirmed``, not a footnote. Leads are never counted in the totals —
  they are a different type in a different field, and rendering keeps them that
  way.

Everything that bounded the run appears here too, on a clean run as well as a
degraded one: provider routing, research grounding, plan and crawl truncation,
component-ledger alarms. A section that appears only on failure cannot be told
apart from a section nobody wrote.

Redaction
---------

The structure handed in is already redacted (:func:`redact_structure`, applied
before ``PentestReport.model_validate``). :meth:`_PDFReport._text` applies
:func:`redact` again at the one seam every string passes through on its way into
the document — the same second pass the Markdown writer makes, for the same
reason: the structural pass cannot see a value the RENDERER composes out of two
fields. The ``/Info`` dictionary is written from the report's own fields and
from nothing else, because it is a channel no page-text scan reads.
"""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from clinkz.agents._control_arm import (
    ControlVerdict,
    control_required,
    control_verdict_from_evidence,
    declared_observation,
    indicator_is_self_controlled,
    structured_evidence_field,
)
from clinkz.agents._report_integrity import (
    AuthenticationState,
    assert_testing_window_renderable,
    authentication_state,
    document_title,
    reconciled_not_tested_reason,
    spend_cost_line,
)
from clinkz.engagement.secrets import redact
from clinkz.llm.degradation import reconcile_with_model_stamp
from clinkz.models.finding import Finding, Severity
from clinkz.models.report import NotTestedCategory, NotTestedItem, PentestReport
from clinkz.models.vuln_classes import for_finding

if TYPE_CHECKING:  # pragma: no cover — typing only
    from reportlab.platypus import Flowable

__all__ = [
    "PDF_UNAVAILABLE_HINT",
    "ControlArmRuleMissingError",
    "control_arm_row",
    "render_report_pdf",
]


class ControlArmRuleMissingError(RuntimeError):
    """A control-arm row that can only say which rule does NOT govern it.

    The section header promises "the row says which rule applies instead". A
    row that names no rule breaks that promise in the one place a client
    checks whether the evidence was controlled, so the render fails rather
    than shipping the nineteenth verbatim repetition of an absence.
    """


PDF_UNAVAILABLE_HINT = (
    "reportlab is not installed - the PDF deliverable was not written. "
    "Install it with `pip install -e .` (it is a declared dependency)."
)

#: Wrap width for the monospace evidence blocks, in characters. Chosen against
#: 7pt Courier in the body column: a raw request line is not re-flowed prose and
#: a mid-token break has to land somewhere predictable rather than wherever the
#: layout engine runs out of room.
_MONO_WRAP: int = 108

#: How many evidence entries render per finding before the block is cut, and the
#: per-entry character ceiling. Both cuts are STATED in the document, never
#: silent: a truncated PoC that does not say it was truncated is the report
#: claiming the evidence is complete.
_MAX_EVIDENCE_ENTRIES: int = 24
_MAX_EVIDENCE_CHARS: int = 4000

#: Ceiling on the observation quoted into a control-arm row. The row is a table
#: cell summarising WHY the class may confirm; the finding's own evidence block
#: carries the entry in full a few pages later, and the cut says so rather than
#: implying the observation ended there.
_MAX_OBSERVATION_CHARS: int = 190

_SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)

#: Severity swatches, dark enough to stay legible in greyscale - a client prints
#: this.
_SEVERITY_RGB: dict[Severity, tuple[float, float, float]] = {
    Severity.CRITICAL: (0.60, 0.09, 0.11),
    Severity.HIGH: (0.83, 0.33, 0.09),
    Severity.MEDIUM: (0.71, 0.55, 0.05),
    Severity.LOW: (0.16, 0.41, 0.60),
    Severity.INFO: (0.40, 0.40, 0.44),
}

_NOT_TESTED_HEADINGS: dict[NotTestedCategory, str] = {
    NotTestedCategory.SOURCE_NOT_INGESTED: "Gray-box source supplied but not analysed",
    NotTestedCategory.OUT_OF_SCOPE: "Excluded by the client",
    NotTestedCategory.NOT_PERMITTED: "Techniques not authorized",
    NotTestedCategory.NO_CLIENT_SIDE_ORACLE: "Not confirmable - no client-side oracle",
    NotTestedCategory.CLIENT_ORACLE_FOUND_NOTHING: (
        "Examined in a real browser - no execution witnessed"
    ),
    NotTestedCategory.NOT_IMPLEMENTED: "Not confirmable - no methodology",
    NotTestedCategory.DESTRUCTIVE_REFUSED: "Refused by the production safety rails",
    NotTestedCategory.ENGAGEMENT_HALTED: "Cut short when the engagement halted",
    NotTestedCategory.UNAUTHENTICATED: "Limited by the sessions available",
}


# ---------------------------------------------------------------------------
# Control arms — read from the producer, never re-derived
# ---------------------------------------------------------------------------


def control_arm_row(finding: Finding) -> dict[str, str]:
    """What the control arm says about one confirmed finding.

    Reads the DECLARED structure only — :func:`control_verdict_from_evidence`
    and :func:`structured_evidence_field` accept an evidence entry solely when
    every whitespace-separated token is ``key=value``. A finding's evidence
    carries raw response bytes, so a prefix scan would let the host under test
    write its own verdict into this table.

    Four outcomes, and they are different facts:

    * **REFUSED** — the arm was dispatched and the same oracle declined it. The
      claim this document makes.
    * **self-controlled** — the class DECLARES this channel dispatches its own
      control (``_test_sqli``'s three-arm ``auth_bypass`` differential), read
      from :attr:`~clinkz.models.vuln_classes.VulnClass.control_arm` rather than
      guessed from the channel name, because ``_test_nosqli`` has a channel of
      the same NAME with no shape-matched contradiction at all.
    * **not marker-bound** — the class confirms on an effect rather than on a
      string in a body, so the never-sent-control rule does not govern it.
    * **ABSENT** — no arm recorded. ``_persist_finding`` refuses this for a
      marker-bound class, so it can only reach a document from a bundle written
      before that gate. Rendered rather than hidden.

    Args:
        finding: A confirmed finding, already redacted.

    Returns:
        ``{title, target, test_method, channel, decoy, outcome, basis, detail}``
        — every value a plain string, ready for a table cell.
    """
    vuln_class = for_finding(finding.title, finding.description)
    test_method = vuln_class.test_method if vuln_class else ""
    verdict: ControlVerdict | None = control_verdict_from_evidence(finding.evidence)
    channel = structured_evidence_field(finding.evidence, "indicator_type")
    detail = next((e for e in finding.evidence if e.startswith("Control arm: ")), "")
    row = {
        "title": finding.title,
        "target": finding.target,
        "test_method": test_method or "(unresolved)",
        "channel": channel or "-",
        "decoy": "",
        "detail": detail.removeprefix("Control arm: "),
    }
    if verdict is not None:
        row["outcome"] = "REFUSED" if verdict.status == "refused" else verdict.status
        row["decoy"] = verdict.decoy or "-"
        row["basis"] = (
            f"dispatched={verdict.dispatched}; the same oracle refused the control="
            f"{verdict.oracle_refused}; the decoy is absent from the confirming response="
            f"{verdict.decoy_absent_from_confirming}"
        )
        return row
    self_controlled = indicator_is_self_controlled(test_method, channel)
    if self_controlled:
        row["outcome"] = "self-controlled"
        row["basis"] = self_controlled
        return row
    if test_method and not control_required(test_method):
        rule = vuln_class.control_arm.governing_rule.strip() if vuln_class else ""
        if not rule:
            raise ControlArmRuleMissingError(
                f"{test_method} is not bound by the never-sent-control rule and declares no "
                "governing_rule, so its row can only say which rule does NOT apply. Nineteen "
                "of twenty-nine rows across the two generated PDFs said exactly that, under a "
                "header promising the row would name the rule that does"
            )
        key = vuln_class.control_arm.evidence_key  # type: ignore[union-attr]
        observed = declared_observation(finding.evidence, key)
        # Rendered as ``key=value`` rather than the bare value: half these
        # observations are a bare ``True`` on their own, which says nothing, and
        # naming the field is what lets a reviewer find it in the evidence block
        # below and check it.
        row["outcome"] = "governed by its own rule"
        if len(observed) > _MAX_OBSERVATION_CHARS:
            observed = observed[:_MAX_OBSERVATION_CHARS] + "… (full entry in the evidence block)"
        row["basis"] = rule + (f". Observed: {key}={observed}" if observed else "")
        return row
    row["outcome"] = "ABSENT"
    row["basis"] = (
        "no control arm is recorded in this finding's evidence - the emission gate refuses "
        "this for a marker-bound class, so it indicates a bundle written before that gate"
    )
    return row


# ---------------------------------------------------------------------------
# The renderer
# ---------------------------------------------------------------------------


def render_report_pdf(report: PentestReport, path: Path | str) -> Path:
    """Render *report* to a PDF at *path*.

    Args:
        report: The **already-redacted** report — the structure produced by
            ``PentestReport.model_validate(redact_structure(...))``. Never the
            live report and never a raw finding list: this renderer applies no
            key-aware redaction of its own and cannot, because by the time a
            value reaches it the key that identified it is gone.
        path: Destination file. Parent directories are created.

    Returns:
        The path written.

    Raises:
        ImportError: ReportLab is not installed. Raised rather than absorbed —
            the caller decides whether a missing PDF fails the run, and a
            renderer that silently produces nothing is precisely the failure
            mode this codebase spends its guards hunting.
    """
    return _PDFReport(report).build(Path(path))


class _PDFReport:
    """One report, one document. Styles are attributes; sections are methods."""

    def __init__(self, report: PentestReport) -> None:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet

        self.report = report
        self.story: list[Flowable] = []
        self.colors = colors
        # Reconciled ONCE, at construction, so the cover and the engagement-window
        # section cannot disagree about the same fact. The guard raises here rather
        # than after a page has been laid out: a half-written document that states a
        # false testing window is exactly what this refuses to produce.
        self.window = assert_testing_window_renderable(report)

        base = getSampleStyleSheet()
        self.body = ParagraphStyle(
            "ClinkzBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=12.4,
            spaceAfter=4,
            alignment=TA_LEFT,
        )
        self.h1 = ParagraphStyle(
            "ClinkzH1",
            parent=base["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            spaceAfter=9,
        )
        self.h2 = ParagraphStyle(
            "ClinkzH2",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            spaceBefore=11,
            spaceAfter=5,
            textColor=colors.Color(0.12, 0.14, 0.22),
        )
        self.h3 = ParagraphStyle(
            "ClinkzH3",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            spaceBefore=7,
            spaceAfter=3,
        )
        self.mono = ParagraphStyle(
            "ClinkzMono",
            parent=self.body,
            fontName="Courier",
            fontSize=6.6,
            leading=8.2,
            spaceAfter=2,
        )
        self.note = ParagraphStyle(
            "ClinkzNote",
            parent=self.body,
            fontSize=8.2,
            leading=10.8,
            leftIndent=8,
            textColor=colors.Color(0.28, 0.28, 0.32),
        )
        self.cell = ParagraphStyle(
            "ClinkzCell", parent=self.body, fontSize=7.6, leading=9.4, spaceAfter=0
        )
        self.cell_head = ParagraphStyle(
            "ClinkzCellHead", parent=self.cell, fontName="Helvetica-Bold"
        )

    # -- text handling ----------------------------------------------------

    @staticmethod
    def _text(value: Any) -> str:
        """One string on its way into the document: redacted, then escaped.

        Both passes at one seam. ``redact`` is the second, string-level pass the
        Markdown writer also makes — the structural pass upstream cannot see a
        value this renderer composes out of two fields. The escaping is
        ReportLab's: ``Paragraph`` parses a mini-markup, so an unescaped ``<``
        in a response body is dropped or raises, and a response body is exactly
        what a PoC quotes.
        """
        raw = redact("" if value is None else str(value))
        return raw.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    @classmethod
    def _mono_text(cls, value: Any, width: int = _MONO_WRAP) -> str:
        """A monospace block: redacted, hard-wrapped, escaped, ``<br/>``-joined.

        Wrapped here rather than by the layout engine because these are raw
        request and response bytes. ``break_long_words`` is on: a 400-character
        payload is a single token and must break somewhere, and off-column is
        better than off-page.
        """
        raw = redact("" if value is None else str(value))
        out: list[str] = []
        for line in raw.splitlines() or [""]:
            wrapped = textwrap.wrap(
                line,
                width=width,
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            out.extend(wrapped or [""])
        return "<br/>".join(
            piece.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;") for piece in out
        )

    @staticmethod
    def _stamp(value: datetime | None) -> str:
        """An ISO timestamp, or a dash."""
        return value.isoformat() if value is not None else "-"

    # -- flowable helpers -------------------------------------------------

    def _para(self, markup: str, style: Any = None) -> None:
        from reportlab.platypus import Paragraph

        self.story.append(Paragraph(markup, style or self.body))

    def _heading(self, text: str, style: Any = None) -> None:
        from reportlab.platypus import Paragraph

        self.story.append(Paragraph(self._text(text), style or self.h2))

    def _bullets(self, items: list[str], style: Any = None) -> None:
        for item in items:
            self._para(f"&bull;&nbsp;{item}", style)

    def _rule(self) -> None:
        from reportlab.platypus import HRFlowable, Spacer

        self.story.append(Spacer(1, 3))
        self.story.append(
            HRFlowable(width="100%", thickness=0.5, color=self.colors.Color(0.8, 0.8, 0.84))
        )
        self.story.append(Spacer(1, 4))

    def _page_break(self) -> None:
        from reportlab.platypus import PageBreak

        self.story.append(PageBreak())

    def _grid(self, rows: list[list[str]], widths: list[float]) -> None:
        """A table whose cells are Paragraphs, so every column wraps."""
        from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

        data = [
            [Paragraph(value, self.cell_head if index == 0 else self.cell) for value in row]
            for index, row in enumerate(rows)
        ]
        table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.35, self.colors.Color(0.78, 0.78, 0.82)),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (-1, 0), self.colors.Color(0.93, 0.93, 0.95)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        self.story.append(table)
        self.story.append(Spacer(1, 5))

    # -- document ---------------------------------------------------------

    def build(self, destination: Path) -> Path:
        """Assemble every section and write the file."""
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate

        destination.parent.mkdir(parents=True, exist_ok=True)

        self._cover()
        self._header_block()
        self._executive_summary()
        self._control_arms()
        self._page_break()
        self._findings()
        self._chains()
        self._unproven_leads()
        self._research_leads()
        self._chain_leads()
        self._page_break()
        self._not_tested()
        self._run_integrity()

        report = self.report

        def decorate(canvas: Any, document: Any) -> None:
            """Footer on every page: the classification, and where you are."""
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColorRGB(0.4, 0.4, 0.44)
            canvas.drawString(
                18 * mm, 11 * mm, redact(f"CONFIDENTIAL - {document_title(report)}")[:110]
            )
            canvas.drawRightString(A4[0] - 18 * mm, 11 * mm, f"page {document.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(
            str(destination),
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=16 * mm,
            bottomMargin=18 * mm,
            # The /Info dictionary is one of the two channels the disclosure
            # gate reads, and it never appears in page text. Populated from the
            # report's own already-redacted fields and from nothing else — a
            # producer that stuffs an operator name or a session id in here
            # writes it somewhere no page-text scan would ever look.
            title=redact(f"Penetration Test Report - {document_title(report)}")[:200],
            author="Clinkz",
            subject=redact(f"Authorized penetration test of {', '.join(report.target_scope)}")[
                :400
            ],
            creator="Clinkz",
        )
        doc.build(self.story, onFirstPage=decorate, onLaterPages=decorate)
        return destination

    # -- sections ---------------------------------------------------------

    def _cover(self) -> None:
        report = self.report
        self._heading("Penetration Test Report", self.h1)
        self._para(f"<b>{self._text(document_title(report))}</b>")
        self._para(
            f"Testing performed {self._text(self.window.describe())}. "
            f"Report generated {self._text(self._stamp(report.generated_at))}."
        )
        self._para(
            "Every finding in this document was confirmed by an oracle that observed the "
            "vulnerability's defining security effect. Anything short of that is reported "
            "as an unconfirmed lead in its own section and is never counted as a finding.",
            self.note,
        )
        self._rule()

    def _header_block(self) -> None:
        """Authorization, window, scope, authentication, conduct.

        The block that separates a report from a scanner dump: a client-facing
        document has to state on its first page who authorized the test, under
        what reference, over what window, and what was deliberately left alone.
        """
        report = self.report
        self._heading("Authorization")
        record = report.authorization
        if record is None:
            self._para(
                "<b>No authorization record was attached to this engagement.</b> This "
                "report should not be treated as the output of an authorized test."
            )
        else:
            self._bullets(
                [
                    f"<b>Authorized by:</b> {self._text(record.authorizing_party)} "
                    f"({self._text(record.authorizing_role)})",
                    f"<b>Contact:</b> {self._text(record.authorizing_contact)}",
                    f"<b>Authorization reference:</b> {self._text(record.authorization_reference)}",
                    f"<b>Emergency contact:</b> {self._text(record.emergency_contact)}",
                    "<b>Permitted techniques:</b> "
                    + (
                        "all techniques"
                        if record.permits_all
                        else self._text(", ".join(record.permitted_techniques))
                    ),
                ]
            )
            if record.notes:
                self._bullets([f"<b>Notes:</b> {self._text(record.notes)}"])
            if record.benchmark_profile is not None:
                header_lines = record.benchmark_profile.header_lines()
                self._heading(header_lines[0], self.h3)
                self._bullets([self._text(line) for line in header_lines[1:]], self.note)
                self._para(
                    "Every request this permitted is in the action log, tagged with the "
                    "category that would otherwise have refused it "
                    "(<font face='Courier'>clinkz actions &lt;engagement-id&gt;</font>).",
                    self.note,
                )

        self._heading("Engagement window")
        window = report.engagement_window
        self._bullets(
            [
                "<b>Authorized window:</b> "
                + (
                    f"{self._text(self._stamp(window.start))} &rarr; "
                    f"{self._text(self._stamp(window.end))}"
                    if window is not None
                    else "none agreed"
                ),
                f"<b>Testing performed:</b> {self._text(self.window.describe())}",
            ]
        )

        self._heading("Scope")
        self._heading("In scope (tested)", self.h3)
        self._bullets([self._text(entry) for entry in report.target_scope] or ["(none)"])
        self._heading("Out of scope (never contacted)", self.h3)
        self._bullets([self._text(entry) for entry in report.excluded_scope] or ["(none declared)"])
        if report.rules_of_engagement:
            self._heading("Rules of engagement", self.h3)
            self._bullets([self._text(rule) for rule in report.rules_of_engagement])

        auth = report.authentication
        if auth:
            self._heading("Authentication")
            if auth.get("authenticated"):
                assertion = auth.get("assertion") or {}
                self._bullets(
                    [
                        f"<b>Mechanism:</b> {self._text(auth.get('mechanism', 'unknown'))}",
                        f"<b>Roles authenticated:</b> "
                        f"{self._text(', '.join(auth.get('roles') or []) or '(none)')}",
                        "<b>Authenticated state:</b> PROVEN &mdash; <font face='Courier'>"
                        f"{self._text(assertion.get('discriminator', '?'))}</font> at "
                        f"{self._text(assertion.get('url', '?'))} (authenticated HTTP "
                        f"{self._text(assertion.get('authenticated_status'))}, anonymous "
                        f"control HTTP {self._text(assertion.get('anonymous_status'))})",
                    ]
                )
                self._bullets(
                    [self._text(line) for line in (assertion.get("evidence") or [])], self.note
                )
            else:
                verdict = authentication_state(report)
                self._bullets(
                    [
                        f"<b>Mechanism:</b> {self._text(auth.get('mechanism', 'unknown'))}",
                        f"<b>Authenticated state:</b> {self._text(verdict.headline)}",
                    ]
                )
                if verdict.state is AuthenticationState.INCONSISTENT:
                    self._para(
                        "The record and the run disagree, so this document states both "
                        "rather than picking the one field that happens to be rendered "
                        "here:",
                        self.note,
                    )
                    self._bullets([self._text(line) for line in verdict.contradictions], self.note)

        safety = report.safety_summary
        if safety:
            self._heading("Testing conduct")
            self._grid(
                [
                    ["Measure", "Value"],
                    [
                        "Rate limit",
                        f"{self._text(safety.get('max_requests_per_second'))} requests/second, "
                        f"{self._text(safety.get('max_concurrent_requests'))} concurrent",
                    ],
                    ["Requests authorized", self._text(safety.get("requests_authorized", 0))],
                    [
                        "State-changing requests sent",
                        self._text(safety.get("state_changing_sent", 0)),
                    ],
                    [
                        "Requests refused by the safety rails",
                        self._text(safety.get("state_changing_refused", 0)),
                    ],
                    ["Browser navigations", self._text(safety.get("browser_navigations", 0))],
                ],
                [170, 310],
            )
            if safety.get("halted"):
                self._para(
                    f"<b>ENGAGEMENT HALTED</b> ({self._text(safety.get('halt_reason'))}): "
                    f"{self._text(safety.get('halt_detail'))}"
                )

    def _executive_summary(self) -> None:
        """Overview, risk rating, and the severity distribution."""
        from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

        report = self.report
        self._heading("Executive summary")
        summary = report.executive_summary
        if summary is None:
            self._para("No executive summary was produced for this engagement.")
            return

        self._para(self._text(summary.overview))
        if not summary.run_completed:
            self._para(
                "<b>This run did not complete.</b> "
                + self._text(summary.incomplete_reason or "one or more phases failed.")
                + " The counts below are a FLOOR over the part of the engagement that ran, "
                "not a measurement of the target: the absence of a finding here is not "
                "evidence that the target is sound.",
                self.note,
            )
        self._para(f"<b>Overall risk rating:</b> {self._text(summary.risk_rating)}")

        counts = {
            Severity.CRITICAL: summary.critical_count,
            Severity.HIGH: summary.high_count,
            Severity.MEDIUM: summary.medium_count,
            Severity.LOW: summary.low_count,
            Severity.INFO: summary.info_count,
        }
        total = sum(counts.values()) or 1
        # A bar per severity, drawn as a nested one-cell table rather than an
        # image: the document must stay self-contained and byte-stable, and a
        # rasterised chart is neither.
        rows: list[list[Any]] = [
            [
                Paragraph("<b>Severity</b>", self.cell),
                Paragraph("<b>Count</b>", self.cell),
                Paragraph("<b>Share of findings</b>", self.cell),
            ]
        ]
        style: list[tuple[Any, ...]] = [
            ("GRID", (0, 0), (-1, -1), 0.35, self.colors.Color(0.78, 0.78, 0.82)),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("BACKGROUND", (0, 0), (-1, 0), self.colors.Color(0.93, 0.93, 0.95)),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for index, severity in enumerate(_SEVERITY_ORDER, start=1):
            count = counts[severity]
            red, green, blue = _SEVERITY_RGB[severity]
            bar = Table(
                [[""]],
                colWidths=[max(int(round(220 * count / total)), 1)],
                rowHeights=[7],
                hAlign="LEFT",
            )
            bar.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (-1, -1),
                            self.colors.Color(red, green, blue)
                            if count
                            else self.colors.Color(0.9, 0.9, 0.92),
                        )
                    ]
                )
            )
            rows.append(
                [
                    Paragraph(severity.value.upper(), self.cell),
                    Paragraph(str(count), self.cell),
                    bar,
                ]
            )
            style.append(("TEXTCOLOR", (0, index), (0, index), self.colors.Color(red, green, blue)))
        table = Table(rows, colWidths=[80, 50, 240], hAlign="LEFT")
        table.setStyle(TableStyle(style))
        self.story.append(table)
        self.story.append(Spacer(1, 6))

        unconfirmed = (
            len(report.unproven_leads) + len(report.research_leads) + len(report.chain_leads)
        )
        self._grid(
            [
                ["Count", "Value", "What it means"],
                [
                    "Confirmed findings",
                    str(len(report.findings)),
                    "Each confirmed by an oracle that observed the defining security effect "
                    "and, where the class is marker-bound, beside a control arm that refused.",
                ],
                [
                    "Confirmed attack chains",
                    str(len(report.confirmed_chains)),
                    "Each is also one of the findings above. Counted once, never twice.",
                ],
                [
                    "Unconfirmed leads",
                    str(unconfirmed),
                    "Reachability observed, defining effect NOT witnessed. Not findings and "
                    "not counted above. This is what this engine reports instead of a false "
                    "positive.",
                ],
            ],
            [110, 45, 325],
        )

    def _control_arms(self) -> None:
        """The control arm for every confirmed finding.

        Deliberately a top-level section immediately after the executive
        summary, not an appendix. A marker oracle confirms by finding a string
        in a response body, which is proof only while that string has ONE route
        in; the first non-benchmark run shipped 14 phantoms from two second
        routes. The control is the confirming request with the exploitation
        primitive removed and the marker re-minted, graded by the SAME oracle —
        so "it confirmed" and "the control refused" are one claim, and splitting
        them across a document is presenting half of it.
        """
        report = self.report
        self._heading("Control arms - what did NOT confirm")
        if not report.findings:
            self._para("No confirmed findings, so there is no control arm to report.")
            return
        self._para(
            "Every finding in this report was re-sent with its exploitation primitive "
            "removed and its marker re-minted, then graded by the same oracle. A finding is "
            "reported only when that control REFUSED. Where a class confirms on an effect "
            "rather than on a marker in a response body, the never-sent-control rule does "
            "not govern it, and the row names the rule that does &mdash; read from the "
            "class's own declaration, with the observation it turned on.",
            self.note,
        )
        rows: list[list[str]] = [["Finding", "Class / channel", "Control outcome", "Basis"]]
        for index, finding in enumerate(report.findings, 1):
            row = control_arm_row(finding)
            rows.append(
                [
                    f"<b>{index}.</b> {self._text(row['title'])}<br/>"
                    f"<font size='6.4'>{self._text(row['target'])}</font>",
                    f"<font face='Courier' size='6.8'>{self._text(row['test_method'])}</font>"
                    f"<br/><font size='6.4'>channel: {self._text(row['channel'])}</font>",
                    f"<b>{self._text(row['outcome'])}</b>"
                    + (
                        f"<br/><font size='6.4'>decoy: {self._text(row['decoy'])}</font>"
                        if row.get("decoy")
                        else ""
                    ),
                    self._text(row["detail"] or row["basis"]),
                ]
            )
        self._grid(rows, [138, 90, 78, 174])

    def _findings(self) -> None:
        """Per-finding detail: severity, CVSS, endpoint, PoC, control arm, fix."""
        report = self.report
        self._heading("Findings")
        if not report.findings:
            self._para(
                "No confirmed findings. Read <i>What was NOT tested</i> below before "
                "treating this as a clean result - it states exactly which parts of the "
                "application this engagement was able to examine and which it was not."
            )
            return

        for index, finding in enumerate(report.findings, 1):
            self._heading(f"{index}. {finding.title}", self.h3)
            cvss = f"{finding.cvss_score:.1f}" if finding.cvss_score is not None else "N/A"
            self._grid(
                [
                    ["Severity", "CVSS", "Endpoint"],
                    [
                        f"<b>{self._text(finding.severity.value.upper())}</b>",
                        self._text(cvss),
                        f"<font face='Courier'>{self._text(finding.target)}</font>",
                    ],
                ],
                [66, 42, 372],
            )
            if finding.description:
                self._para(self._text(finding.description))
            if finding.cve_ids:
                self._para(
                    f"<b>Referenced CVEs:</b> {self._text(', '.join(finding.cve_ids))} "
                    "&mdash; context on a finding this engine proved with its own oracle, "
                    "never the proof itself.",
                    self.note,
                )
            self._evidence(finding)

            row = control_arm_row(finding)
            self._heading("Control arm", self.h3)
            self._para(
                f"<b>{self._text(row['outcome'])}</b> &mdash; "
                f"{self._text(row['detail'] or row['basis'])}"
            )
            if row.get("decoy"):
                self._para(
                    f"decoy marker: <font face='Courier'>{self._text(row['decoy'])}</font>",
                    self.note,
                )
            if row.get("detail") and row.get("basis"):
                self._para(self._text(row["basis"]), self.note)

            self._heading("Remediation", self.h3)
            self._para(self._text(finding.remediation or "N/A"))
            self._rule()

    def _evidence(self, finding: Finding) -> None:
        """The raw request/response block, with every cut stated."""
        if not finding.evidence:
            return
        self._heading("Proof of concept - request and response", self.h3)
        for entry in finding.evidence[:_MAX_EVIDENCE_ENTRIES]:
            self._para(self._mono_text(entry[:_MAX_EVIDENCE_CHARS]), self.mono)
            if len(entry) > _MAX_EVIDENCE_CHARS:
                self._para(
                    f"[entry truncated at {_MAX_EVIDENCE_CHARS} characters - the full value "
                    f"is in report.json]",
                    self.note,
                )
        if len(finding.evidence) > _MAX_EVIDENCE_ENTRIES:
            self._para(
                f"[{len(finding.evidence) - _MAX_EVIDENCE_ENTRIES} further evidence entries "
                f"not shown here - all of them are in report.json]",
                self.note,
            )

    def _chains(self) -> None:
        """The link-by-link view of every CONFIRMED chain. Adds no count."""
        report = self.report
        if not report.confirmed_chains:
            return
        self._heading("Confirmed attack chains")
        self._para(
            "Each chain below is already one of the findings above - emitted through the "
            "same chokepoint - so this section adds no count and no claim. What it adds is "
            "the composition: which step produced what, and which oracle confirmed each "
            "link. A chain is graded by its WEAKEST link and is reported only when EVERY "
            "link was independently confirmed.",
            self.note,
        )
        for index, chain in enumerate(report.confirmed_chains, 1):
            label = chain.get("title") or chain.get("name") or "chain"
            self._heading(f"C{index}. {label}", self.h3)
            steps = chain.get("steps") or chain.get("links") or []
            if isinstance(steps, list):
                self._bullets([self._text(_describe_chain_step(step)) for step in steps])
            for key in ("impact", "soundness", "why", "why_confirmed"):
                value = chain.get(key)
                if value:
                    self._para(f"<b>{self._text(key)}:</b> {self._text(value)}", self.note)

    def _unproven_leads(self) -> None:
        """Unproven exploitation leads — a first-class section, with the reason.

        A lead is what this engine says INSTEAD of a false positive, so it gets a
        heading rather than a footnote. Each states what WAS observed, what was
        NOT, and the machine-readable ``why_unconfirmed`` an operator can act on.
        """
        report = self.report
        if not report.unproven_leads:
            return
        self._heading("Unproven exploitation leads (candidates - UNCONFIRMED)")
        self._para(
            "These are <b>reachability observations whose defining security effect was "
            "never witnessed</b>. They are <b>NOT findings</b>, are <b>not counted</b> in "
            "the totals above, and no exploitation is claimed. They appear here because "
            "reporting them as confirmed would be a false positive and dropping them would "
            "be a silent loss of coverage: each names the confirming observation that is "
            "missing, so a manual tester knows exactly where the evidence stops.",
            self.note,
        )
        for index, lead in enumerate(report.unproven_leads, 1):
            self._heading(f"U{index}. {lead.claim}", self.h3)
            self._bullets(
                [
                    "<b>Why unconfirmed:</b> <font face='Courier'>"
                    f"{self._text(lead.why_unconfirmed)}</font>",
                    f"<b>Endpoint:</b> <font face='Courier'>{self._text(lead.endpoint)}</font>"
                    + (f" (parameter: {self._text(lead.parameter)})" if lead.parameter else ""),
                    f"<b>Technique:</b> {self._text(lead.technique)}",
                ]
            )
            self._para(f"observed: {self._mono_text(lead.raw_observation)}", self.mono)
            self._para(f"missing:  {self._mono_text(lead.missing_observation)}", self.mono)

    def _research_leads(self) -> None:
        """Cross-service research leads — plausible-but-unproven A→B chains."""
        report = self.report
        if not report.research_leads:
            return
        self._heading("Cross-service research leads (candidate chains - UNCONFIRMED)")
        self._para(
            "Plausible-but-unproven A&rarr;B cross-service chains. <b>NOT findings</b>, not "
            "counted in the totals, and not confirmed by an oracle co-located with service "
            "B. Each is an operator worklist item.",
            self.note,
        )
        for index, lead in enumerate(report.research_leads, 1):
            self._heading(f"L{index}. {lead.candidate_chain}", self.h3)
            self._bullets(
                [
                    f"<b>Why unconfirmed:</b> {self._text(lead.why_unconfirmed)}",
                    f"<b>A endpoint:</b> {self._text(lead.a_endpoint)} "
                    f"(channel: {self._text(lead.a_channel)})",
                    f"<b>B target:</b> {self._text(lead.b_target)}",
                    f"<b>Topology source:</b> {self._text(lead.topology_source)} "
                    f"(grade: {self._text(lead.reachability_grade)}, "
                    f"confidence: {self._text(lead.reach_confidence)})",
                ]
            )
            self._para(f"probe:       {self._mono_text(lead.raw_probe)}", self.mono)
            self._para(f"observation: {self._mono_text(lead.raw_null_observation)}", self.mono)

    def _chain_leads(self) -> None:
        """Compositions the decoy control did not discriminate."""
        report = self.report
        if not report.chain_leads:
            return
        self._heading("Unproven attack chains (UNCONFIRMED)")
        self._para(
            "A carriage is proven against a control: the real artifact ACCEPTED and an "
            "equivalently-shaped decoy the target never issued REFUSED. Where the decoy was "
            "accepted too, the endpoint accepts the SHAPE and not the VALUE - which proves "
            "nothing about the chain. Reported here rather than as a finding with a caveat.",
            self.note,
        )
        for index, lead in enumerate(report.chain_leads, 1):
            dumped = lead.model_dump(mode="json")
            self._heading(f"K{index}. {dumped.get('candidate_chain') or 'chain'}", self.h3)
            self._bullets(
                [
                    f"<b>{self._text(field)}:</b> {self._text(value)}"
                    for field, value in dumped.items()
                    if value not in (None, "", [], {}) and field != "candidate_chain"
                ]
            )

    def _not_tested_reason(self, item: NotTestedItem) -> str:
        """The reason to render, reconciled against the run's own output.

        A stored bundle carries the sentence its original run wrote. 3c47a0de's
        says "Anything behind authentication was not examined" — three pages
        after a header block that now says the record and the run disagree, above
        22 findings behind DVWA's login. The header being right does not make the
        document right.
        """
        if item.category is not NotTestedCategory.UNAUTHENTICATED:
            return item.reason
        return reconciled_not_tested_reason(item.reason, authentication_state(self.report))

    def _not_tested(self) -> None:
        """What was NOT tested, grouped by whose limitation it is."""
        report = self.report
        self._heading("What was NOT tested")
        self._para(
            "Absence of a finding is only meaningful where testing actually reached. "
            "Everything this engagement did <b>not</b> examine is listed here, with the "
            "reason. Items under <i>no client-side oracle</i> and <i>no methodology</i> are "
            "limitations of this tool and are candidates for manual review. <i>Examined in "
            "a real browser</i> is not one of them: there the oracle ran and witnessed "
            "nothing, which is an answer rather than a gap.",
            self.note,
        )
        if not report.not_tested:
            self._para("Nothing was excluded from testing.")
            return
        rendered: set[str] = set()
        for category, label in _NOT_TESTED_HEADINGS.items():
            group = [item for item in report.not_tested if item.category == category]
            if not group:
                continue
            rendered.add(str(category))
            self._heading(label, self.h3)
            self._bullets(
                [
                    f"<b>{self._text(item.item)}</b> &mdash; "
                    f"{self._text(self._not_tested_reason(item))}"
                    for item in group
                ]
            )
        # A category with no heading renders anyway, under its raw name.
        # Dropping an entry because this renderer was not updated alongside the
        # enum would delete a limitation from a client deliverable — the one
        # failure this section cannot have.
        orphans = [item for item in report.not_tested if str(item.category) not in rendered]
        if orphans:
            self._heading("Other limitations", self.h3)
            self._bullets(
                [
                    f"<b>{self._text(item.item)}</b> [{self._text(item.category)}] &mdash; "
                    f"{self._text(item.reason)}"
                    for item in orphans
                ]
            )

    def _run_integrity(self) -> None:
        """Everything that bounded this run, rendered on a clean run too.

        A section that appears only on failure cannot be told apart from a
        section nobody wrote — which is how six exploit plans and six
        false-positive cross-checks written by a cheaper model reached six
        reports that looked like reports it had not happened to.
        """
        self._heading("Run integrity and coverage bounds")
        self._para(
            "These sections render whether or not anything went wrong. A caveat that "
            "appears only on a bad run is indistinguishable from a caveat nobody wrote.",
            self.note,
        )
        self._provider_routing()
        self._research_grounding()
        self._component_contribution()
        self._plan_coverage()
        self._crawl_coverage()
        self._scope_refusals()
        self._spend()

    def _provider_routing(self) -> None:
        report = self.report
        stamp = report.provider_degradation or {}
        if stamp:
            # Reconciled at RENDER time, exactly as the Markdown renderer does
            # and through the same function. `clinkz report-pdf` runs over a
            # STORED report, which may have been written before the
            # reconciliation existed and still carry the register's half of the
            # disagreement — a clean routing claim its own model stamp
            # contradicts. Third call site of one rule, never a third copy.
            stamp = reconcile_with_model_stamp(stamp, list(report.model_stamp))
        self._heading("Provider routing", self.h3)
        if not stamp:
            self._para("No provider-routing record was captured for this run.")
        elif not stamp.get("provider_degraded"):
            self._para(
                "Every LLM call was served by the provider this run asked for. No fallback "
                "activated, no provider was excluded mid-run, and no chain was exhausted - "
                "so the run is eligible for use as a baseline."
            )
        else:
            self._para(
                f"<b>This run is NOT eligible as a baseline.</b> "
                f"{self._text(stamp.get('fallback_count', 0))} call(s) were served by a "
                f"provider other than the one asked for, and "
                f"{self._text(stamp.get('absence_count', 0))} call(s) got no answer at all. "
                f"A number produced partly by one model and partly by another - or produced "
                f"with a reasoning step missing - is not a measurement of the target, so "
                f"nothing here should be compared against another run's figures."
            )
            starved = list(stamp.get("exhausted_stages") or [])
            if starved:
                self._para(
                    "The run's own model stamp records <b>no provider at all</b> for: "
                    + ", ".join(
                        f"<font face='Courier'>{self._text(stage)}</font>" for stage in starved
                    )
                    + ". Whatever those reasoning steps would have decided was decided by a "
                    "default instead, and the phase produced its artifacts anyway.",
                    self.note,
                )
            events = [e for e in (stamp.get("events") or []) if isinstance(e, dict)]
            if events:
                rows = [["Call site", "Asked for", "Served by", "Why", "Decision-bearing"]]
                rows.extend(
                    [
                        self._text(event.get("call_site", "")),
                        self._text(
                            f"{event.get('asked_provider', '')}/{event.get('asked_model', '')}"
                        ),
                        self._text(
                            f"{event.get('served_provider', '')}/{event.get('served_model', '')}"
                        ),
                        self._text(event.get("reason", "") or "-"),
                        "yes" if event.get("decision_bearing") else "no",
                    ]
                    for event in events
                )
                self._grid(rows, [108, 96, 96, 122, 58])
            absences = [a for a in (stamp.get("absences") or []) if isinstance(a, dict)]
            if absences:
                self._para(
                    "<b>Absences</b> - a call the chain could not serve at all. Nothing "
                    "substituted, so no fallback event was written; the phase simply did "
                    "not get an answer, and whatever it would have decided was decided by "
                    "a default instead.",
                    self.note,
                )
                rows = [["Call site", "Kind", "Provider", "Why", "Decision-bearing"]]
                rows.extend(
                    [
                        self._text(absence.get("call_site", "")),
                        self._text(absence.get("kind", "")),
                        self._text(absence.get("provider", "") or "(whole chain)"),
                        self._text(absence.get("reason", "") or "-"),
                        "yes" if absence.get("decision_bearing") else "no",
                    ]
                    for absence in absences
                )
                self._grid(rows, [108, 96, 96, 122, 58])

        if report.model_stamp:
            self._heading("Which model served each stage", self.h3)
            self._para(
                "Read from the run's own trace, never from configuration: a fallback means "
                "the provider that answered is not the one that was asked, and it is the "
                "one that answered which shaped the output.",
                self.note,
            )
            rows = [["Stage", "Provider", "Model", "Calls"]]
            rows.extend(
                [
                    self._text(entry.get("stage", "")),
                    self._text(entry.get("provider", "")),
                    self._text(entry.get("model", "") or "-"),
                    self._text(entry.get("calls", "")),
                ]
                for entry in report.model_stamp
            )
            self._grid(rows, [110, 110, 190, 60])

    def _research_grounding(self) -> None:
        grounding = self.report.research_grounding or {}
        self._heading("Research grounding", self.h3)
        if not grounding:
            self._para("The research phase produced no grounding record for this run.")
            return
        if grounding.get("is_grounded"):
            self._para(
                "The research phase was served by a provider with native live search "
                f"(<font face='Courier'>{self._text(grounding.get('grounding'))}</font>), so "
                "its runbook reflects published material at the time of the run."
            )
        else:
            self._para(
                "<b>The research phase was NOT web-grounded</b> (<font face='Courier'>"
                f"{self._text(grounding.get('grounding') or 'undeclared')}</font>). Its "
                "answers are a recollection of a training corpus: every vulnerability "
                "disclosed after that model's cutoff is invisible, with nothing in the text "
                "saying so. This does <b>not</b> reach the findings - a CVE from research "
                "is a LEAD that must still be proven by one of this engine's own oracles - "
                "but it does bound what the research phase could suggest looking for."
            )
        if grounding.get("runbook_entries") is not None:
            self._para(
                f"Runbook entries produced: {self._text(grounding.get('runbook_entries'))}",
                self.note,
            )

    def _component_contribution(self) -> None:
        ledger = self.report.component_ledger or {}
        alarms = [a for a in (ledger.get("alarms") or []) if isinstance(a, dict)]
        self._heading("Component contribution", self.h3)
        if not ledger:
            self._para("No component ledger was installed for this run.")
            return
        tracked = (ledger.get("summary") or {}).get("components_tracked", 0)
        if not alarms:
            self._para(
                f"Every one of the {self._text(tracked)} components this run tracked "
                "contributed what it was asked for. No dead seam, no silent component, no "
                "fallback activation."
            )
        else:
            self._para(
                f"<b>{len(alarms)} component(s) produced nothing while the run continued "
                f"around them.</b> A total is not evidence about its parts: findings can "
                f"still appear while a component contributes zero and something else covers."
            )
            rows = [["Component", "Alarm", "Invocations", "Contributed"]]
            rows.extend(
                [
                    self._text(alarm.get("component", "")),
                    self._text(", ".join(alarm.get("alarms") or [])),
                    self._text(alarm.get("invocations", 0)),
                    self._text(alarm.get("items_contributed", 0)),
                ]
                for alarm in alarms
            )
            self._grid(rows, [200, 130, 70, 70])
        unreachable = ledger.get("unreachable") or []
        if unreachable:
            self._para(
                f"{len(unreachable)} further component(s) were built but this engagement "
                "could not reach them; each is enumerated in report.json under "
                "<font face='Courier'>component_ledger.unreachable</font> with the "
                "predicate that decided it.",
                self.note,
            )

    def _plan_coverage(self) -> None:
        plan = self.report.plan_coverage or {}
        self._heading("Exploit plan coverage", self.h3)
        if not plan:
            self._para("No exploit plan bound was recorded for this run.")
            return
        if not plan.get("plan_truncated"):
            self._para("The exploit plan fit inside its task cap: no candidate was dropped.")
            return
        self._para(
            f"<b>The exploit plan was truncated.</b> "
            f"{self._text(plan.get('dropped_total', 0))} candidate (class, endpoint) pair(s) "
            f"were ranked and dropped across {self._text(plan.get('passes_recorded', 0))} "
            f"pass(es). {len(plan.get('classes_truncated') or [])} of "
            f"{len(plan.get('classes_with_candidates') or [])} classes carrying candidates "
            f"lost at least one. The bound that most directly decides what gets TESTED is "
            f"reported here rather than only in the run log."
        )
        if plan.get("ranking_inversion_count"):
            self._para(
                f"<b>{self._text(plan.get('ranking_inversion_count'))} ranking "
                "inversion(s)</b> - a task dropped from an endpoint carrying its own "
                "class's observed surface while lower-relevance tasks survived. A larger "
                "cap does not fix this; it is an ordering defect and is reported separately "
                "for that reason.",
                self.note,
            )

    def _crawl_coverage(self) -> None:
        crawl = self.report.crawl_coverage or {}
        self._heading("Crawl coverage", self.h3)
        if not crawl:
            self._para("No crawl bound was recorded for this run.")
            return
        if not crawl.get("crawl_truncated"):
            self._para(
                f"Every one of the {self._text(crawl.get('candidates', 0))} crawl "
                "candidate(s) was opened: nothing discovered was left un-enriched."
            )
            return
        self._para(
            f"<b>The crawl's enrichment budget was reached.</b> "
            f"{self._text(crawl.get('opened', 0))} of "
            f"{self._text(crawl.get('candidates', 0))} candidate URL(s) were opened; "
            f"{self._text(crawl.get('dropped_total', 0))} were never enqueued and so never "
            f"became endpoints the exploit plan could see. This bound sits one layer BEFORE "
            f"the plan cap - everything the plan could rank had already passed through it."
        )
        if crawl.get("first_omitted"):
            self._para(
                "first omitted: <font face='Courier'>"
                f"{self._text(crawl.get('first_omitted'))}</font>",
                self.note,
            )

    def _scope_refusals(self) -> None:
        refusals = self.report.scope_refusals or {}
        self._heading("Out-of-scope targets refused", self.h3)
        total_refused = int(refusals.get("total_refused") or 0)
        if not total_refused:
            self._para(
                "Nothing this run reached for lay outside the authorized scope. Rendered "
                "even when empty: otherwise a run that enforced scope perfectly and one "
                "that never had a link to follow produce identical artifacts."
            )
            return
        hosts = refusals.get("out_of_scope_hosts") or {}
        self._para(
            f"{total_refused} request(s) to {len(hosts)} out-of-scope host(s) were refused "
            "before leaving. A real application links out and the crawler follows links; "
            "this is the evidence that the ones leaving the authorized host were stopped."
        )
        top = sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:15]
        self._bullets(
            [f"<font face='Courier'>{self._text(host)}</font> - {count}" for host, count in top]
        )
        if len(hosts) > len(top):
            self._para(
                f"({len(hosts) - len(top)} further host(s) not listed here; every refusal is "
                "in report.json under <font face='Courier'>scope_refusals</font>.)",
                self.note,
            )
        if (self.report.crawl_coverage or {}).get("crawl_truncated"):
            self._para(
                "This tally counts requests that were REFUSED. A candidate the crawl budget "
                "never opened never became a request, so it describes the opened slice of "
                "the out-of-scope surface.",
                self.note,
            )

    def _spend(self) -> None:
        spend = self.report.llm_spend or {}
        if not spend:
            return
        self._heading("LLM consumption", self.h3)
        self._grid(
            [
                ["Measure", "Value"],
                ["Total tokens", self._text(spend.get("total_tokens", 0))],
                ["Cost", self._text(spend_cost_line(spend))],
                [
                    "Token cap",
                    self._text(spend.get("token_cap"))
                    if spend.get("token_cap") is not None
                    else "none set",
                ],
            ],
            [130, 350],
        )


def _describe_chain_step(step: Any) -> str:
    """One chain step as a line, whatever shape the composer recorded."""
    if not isinstance(step, dict):
        return str(step)
    return " ".join(f"{key}={step[key]}" for key in sorted(step) if step[key] not in (None, "", []))
