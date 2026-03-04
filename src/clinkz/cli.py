"""Typer CLI entry point for Clinkz.

Commands:
    scan    — Full pipeline (recon → crawl → exploit → report)
    recon   — Reconnaissance phase only
    crawl   — Crawling / fuzzing phase only
    exploit — Exploitation phase only
    report  — Generate report from completed engagement

Usage::

    clinkz scan --target example.com --scope scope.json
    python -m clinkz recon --target 10.10.10.1
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Annotated

import typer

app = typer.Typer(
    name="clinkz",
    help="Autonomous AI penetration testing agent.",
    add_completion=False,
)


def _setup_logging(verbose: bool = False) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)-30s %(message)s",
        datefmt="%H:%M:%S",
    )


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    target: Annotated[str, typer.Option("--target", "-t", help="Target domain or IP address")],
    scope: Annotated[
        Path | None,
        typer.Option("--scope", "-s", help="Path to scope JSON file (EngagementScope)"),
    ] = None,
    provider: Annotated[
        str,
        typer.Option("--provider", "-p", help="LLM provider: openai | anthropic | gemini | ollama"),
    ] = "openai",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Directory to write reports into"),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run a full penetration test: recon → crawl → exploit → report."""
    _setup_logging(verbose)
    log = logging.getLogger("cli.scan")
    log.info("Starting full scan — target: %s, provider: %s", target, provider)

    from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
    from clinkz.orchestrator.orchestrator import OrchestratorAgent

    # Build engagement scope
    if scope is not None:
        scope_data = json.loads(scope.read_text(encoding="utf-8"))
        scope_obj = EngagementScope.model_validate(scope_data)
    else:
        # Infer scope type from the target string
        import ipaddress

        try:
            ipaddress.ip_network(target, strict=False)
            scope_type = ScopeType.CIDR if "/" in target else ScopeType.IP
        except ValueError:
            scope_type = ScopeType.DOMAIN

        scope_obj = EngagementScope(
            name=target,
            targets=[ScopeEntry(value=target, type=scope_type)],
        )

    async def _run() -> dict:
        orchestrator = OrchestratorAgent(provider=provider)
        return await orchestrator.run(scope_obj)

    result = asyncio.run(_run())
    status = result.get("status", "unknown")
    summary = result.get("summary", "No summary.")
    typer.echo(f"Engagement {status}: {summary}")


# ---------------------------------------------------------------------------
# recon
# ---------------------------------------------------------------------------


@app.command()
def recon(
    target: Annotated[str, typer.Option("--target", "-t", help="Target domain or IP address")],
    provider: Annotated[str, typer.Option("--provider", "-p")] = "openai",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run only the reconnaissance phase (nmap, subfinder, httpx, whatweb)."""
    _setup_logging(verbose)
    logging.getLogger("cli.recon").info("Recon — target: %s", target)
    # TODO: instantiate ReconAgent and run
    typer.echo(f"[TODO] Recon not yet implemented. Target: {target}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# crawl
# ---------------------------------------------------------------------------


@app.command()
def crawl(
    target: Annotated[str, typer.Option("--target", "-t", help="Target domain or IP address")],
    provider: Annotated[str, typer.Option("--provider", "-p")] = "openai",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run only the crawling and directory fuzzing phase (katana, ffuf)."""
    _setup_logging(verbose)
    logging.getLogger("cli.crawl").info("Crawl — target: %s", target)
    # TODO: instantiate CrawlAgent and run
    typer.echo(f"[TODO] Crawl not yet implemented. Target: {target}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------


@app.command()
def exploit(
    target: Annotated[str, typer.Option("--target", "-t", help="Target domain or IP address")],
    provider: Annotated[str, typer.Option("--provider", "-p")] = "openai",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run only the exploitation phase (nuclei, sqlmap, nikto, manual PoCs)."""
    _setup_logging(verbose)
    logging.getLogger("cli.exploit").info("Exploit — target: %s", target)
    # TODO: instantiate ExploitAgent and run
    typer.echo(f"[TODO] Exploit not yet implemented. Target: {target}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# report
# ---------------------------------------------------------------------------


@app.command()
def report(
    engagement_id: Annotated[
        str, typer.Option("--engagement-id", "-e", help="Engagement UUID from state store")
    ],
    fmt: Annotated[
        str,
        typer.Option(
            "--format",
            "-f",
            help="Output format: html | pdf | json | markdown",
        ),
    ] = "html",
    output: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output file path"),
    ] = Path("report.html"),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Generate a report from a completed engagement."""
    _setup_logging(verbose)
    logging.getLogger("cli.report").info(
        "Report — engagement: %s, format: %s, output: %s", engagement_id, fmt, output
    )
    # TODO: instantiate ReportGenerator and render
    typer.echo(f"[TODO] Report generation not yet implemented. Engagement: {engagement_id}")
    raise typer.Exit(code=1)


def main() -> None:
    """Entry point for the 'clinkz' script."""
    app()


if __name__ == "__main__":
    main()
