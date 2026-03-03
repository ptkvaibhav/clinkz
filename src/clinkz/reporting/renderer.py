"""Report renderer — converts PentestReport to HTML, PDF, JSON, or Markdown.

HTML/PDF rendering uses Jinja2 templates + WeasyPrint.
JSON rendering uses Pydantic's model_dump_json().
"""

from __future__ import annotations

import logging
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from clinkz.models.report import PentestReport, ReportFormat

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportRenderer:
    """Renders a PentestReport to various output formats.

    Usage::

        renderer = ReportRenderer()
        renderer.render(report, format=ReportFormat.HTML, output_path=Path("report.html"))
    """

    def __init__(self) -> None:
        self._jinja_env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def render(
        self,
        report: PentestReport,
        fmt: ReportFormat,
        output_path: Path,
    ) -> None:
        """Render the report to the specified format and write to disk.

        Args:
            report: The fully populated PentestReport.
            fmt: Output format (HTML, PDF, JSON, Markdown).
            output_path: Path to write the output file.

        Raises:
            ValueError: If the format is not supported.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt == ReportFormat.HTML:
            self._render_html(report, output_path)
        elif fmt == ReportFormat.PDF:
            self._render_pdf(report, output_path)
        elif fmt == ReportFormat.JSON:
            self._render_json(report, output_path)
        elif fmt == ReportFormat.MARKDOWN:
            self._render_markdown(report, output_path)
        else:
            raise ValueError(f"Unsupported report format: {fmt}")

        logger.info("Report written to: %s", output_path)

    def _render_html(self, report: PentestReport, output_path: Path) -> None:
        """Render to HTML using the Jinja2 template."""
        template = self._jinja_env.get_template("report.html")
        html = template.render(report=report)
        output_path.write_text(html, encoding="utf-8")

    def _render_pdf(self, report: PentestReport, output_path: Path) -> None:
        """Render to PDF via WeasyPrint (HTML → PDF)."""
        import weasyprint

        # First render to HTML string
        template = self._jinja_env.get_template("report.html")
        html = template.render(report=report)
        weasyprint.HTML(string=html, base_url=str(_TEMPLATES_DIR)).write_pdf(str(output_path))

    def _render_json(self, report: PentestReport, output_path: Path) -> None:
        """Render to pretty-printed JSON."""
        output_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    def _render_markdown(self, report: PentestReport, output_path: Path) -> None:
        """Render to Markdown (basic implementation).

        TODO: Create a proper Markdown Jinja2 template.
        """
        lines = [
            f"# {report.engagement_name} — Penetration Test Report",
            "",
            f"**Generated:** {report.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            "",
            "## Executive Summary",
            "",
            report.executive_summary.overview if report.executive_summary else "_No summary_",
            "",
            "## Findings",
            "",
        ]
        for i, finding in enumerate(report.findings, 1):
            lines += [
                f"### {i}. [{finding.severity.value.upper()}] {finding.title}",
                "",
                f"**Target:** {finding.target}",
                "",
                finding.description,
                "",
                f"**Remediation:** {finding.remediation}",
                "",
            ]
        output_path.write_text("\n".join(lines), encoding="utf-8")
