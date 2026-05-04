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

trace_app = typer.Typer(
    name="trace",
    help="Inspect engagement execution traces.",
    add_completion=False,
)
app.add_typer(trace_app, name="trace")


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
        str | None,
        typer.Option("--provider", "-p", help="LLM provider: openai | anthropic | gemini | ollama"),
    ] = None,
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
    from clinkz.tools.docker_preflight import ClinkzDockerError

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

    try:
        result = asyncio.run(_run())
    except ClinkzDockerError as exc:
        typer.echo(f"Docker pre-flight failed:\n{exc}", err=True)
        raise typer.Exit(code=2) from None

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


# ---------------------------------------------------------------------------
# trace inspect
# ---------------------------------------------------------------------------


@trace_app.command("inspect")
def trace_inspect(
    engagement_id: Annotated[
        str,
        typer.Argument(help="Engagement UUID. Reads outputs/<id>/trace.jsonl"),
    ],
    stage: Annotated[
        str | None,
        typer.Option("--stage", help="Filter to events for a single stage (e.g. 'recon')."),
    ] = None,
    category: Annotated[
        str | None,
        typer.Option(
            "--category",
            help=(
                "Filter by category: tool_call | llm_call | agent_step | "
                "data_handoff | methodology_phase"
            ),
        ),
    ] = None,
    outputs_root: Annotated[
        Path,
        typer.Option(
            "--outputs-root",
            help="Root dir containing engagement subdirs.",
        ),
    ] = Path("outputs"),
    raw: Annotated[
        bool,
        typer.Option("--raw", help="Emit JSONL instead of the human timeline."),
    ] = False,
) -> None:
    """Render a human-readable timeline (or raw JSONL) from a trace file."""
    trace_path = outputs_root / engagement_id / "trace.jsonl"
    if not trace_path.exists():
        typer.echo(f"No trace file at {trace_path}", err=True)
        raise typer.Exit(code=1)

    valid_categories = {
        "tool_call",
        "llm_call",
        "agent_step",
        "data_handoff",
        "methodology_phase",
    }
    if category is not None and category not in valid_categories:
        typer.echo(
            f"Invalid --category '{category}'. Choose from: {sorted(valid_categories)}",
            err=True,
        )
        raise typer.Exit(code=2)

    with trace_path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if stage and record.get("stage") != stage:
                continue
            if category and record.get("category") != category:
                continue
            if raw:
                typer.echo(line)
            else:
                typer.echo(_format_trace_record(record))


def _format_trace_record(record: dict) -> str:
    """Render one JSONL trace record as a single human-readable timeline line."""
    ts = record.get("ts", "")
    stage = record.get("stage", "?")
    cat = record.get("category", "?")
    payload = record.get("payload", {}) or {}
    short_ts = ts.split("T", 1)[1].split("+", 1)[0].split(".", 1)[0] if "T" in ts else ts

    if cat == "tool_call":
        cmd = payload.get("cmd", "")
        rc = payload.get("exit_code")
        dur = payload.get("duration_ms")
        dur_str = f"{dur:.0f}ms" if isinstance(dur, (int, float)) else "-"
        return f"[{short_ts}] {stage:>8} TOOL  rc={rc} {dur_str:>7}  {cmd[:140]}"
    if cat == "llm_call":
        provider = payload.get("provider", "")
        model = payload.get("model", "")
        dur = payload.get("duration_ms")
        dur_str = f"{dur:.0f}ms" if isinstance(dur, (int, float)) else "-"
        prompt = (payload.get("prompt_summary") or "").replace("\n", " ")[:80]
        resp = (payload.get("response_summary") or "").replace("\n", " ")[:80]
        return (
            f"[{short_ts}] {stage:>8} LLM   {provider}/{model} {dur_str:>7}  "
            f"q={prompt!r} a={resp!r}"
        )
    if cat == "agent_step":
        step = payload.get("step_name", "")
        dur = payload.get("duration_ms")
        dur_str = f"{dur:.0f}ms" if isinstance(dur, (int, float)) else "-"
        out = (payload.get("output_summary") or "").replace("\n", " ")[:80]
        return f"[{short_ts}] {stage:>8} STEP  {step:<30} {dur_str:>7}  {out!r}"
    if cat == "data_handoff":
        frm = payload.get("from_agent", "?")
        to = payload.get("to_agent", "?")
        mtype = payload.get("message_type", "")
        size = payload.get("size_bytes", 0)
        summary = (payload.get("data_summary") or "").replace("\n", " ")[:80]
        return f"[{short_ts}] {stage:>8} HAND  {frm}->{to} [{mtype}] {size}B  {summary!r}"
    if cat == "methodology_phase":
        skill = payload.get("skill", "?")
        phase_num = payload.get("phase_number", "?")
        phase_name = payload.get("phase_name", "")
        summary = (payload.get("payload_summary") or "").replace("\n", " ")[:80]
        return f"[{short_ts}] {stage:>8} METH  {skill}/p{phase_num}:{phase_name:<22}  {summary!r}"
    return f"[{short_ts}] {stage:>8} {cat:<5} {json.dumps(payload, default=str)[:140]}"


def main() -> None:
    """Entry point for the 'clinkz' script."""
    app()


if __name__ == "__main__":
    main()
