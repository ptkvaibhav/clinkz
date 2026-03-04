"""Report generation and rendering module.

Usage::

    from clinkz.reporting.generator import ReportGenerator
    from clinkz.reporting.renderer import ReportRenderer

    generator = ReportGenerator(llm)
    report = await generator.generate(engagement_id, state)

    renderer = ReportRenderer()
    renderer.render(report, format="html", output_path=Path("report.html"))
"""
