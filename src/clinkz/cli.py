"""Typer CLI entry point for Clinkz.

Commands:
    scan          — Full pipeline (recon → scan/research/exploit → report)
    trace inspect — Render an engagement execution trace
    tool-invoke   — Inspect or replay one recorded tool invocation
    step-replay   — Re-run one recorded agent step in isolation

The pipeline runs end-to-end via ``scan``; there are no single-phase run
commands (the Orchestrator owns phase sequencing). ``trace inspect`` /
``tool-invoke`` / ``step-replay`` are post-run inspectors over ``outputs/<id>/``.

Usage::

    clinkz scan --target example.com --scope scope.json
    python -m clinkz trace inspect <engagement_id>
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


# ---------------------------------------------------------------------------
# tool-invoke (full-fidelity tool invocation record)
# ---------------------------------------------------------------------------


@app.command("tool-invoke")
def tool_invoke(
    engagement_id: Annotated[
        str,
        typer.Argument(help="Engagement UUID. Reads outputs/<id>/tool_invocations/."),
    ],
    seq: Annotated[
        int,
        typer.Argument(help="Invocation sequence number (matches <seq>_<tool>.json)."),
    ],
    replay: Annotated[
        bool,
        typer.Option(
            "--replay",
            help="Re-run the exact command with the recorded env/cwd and diff the output.",
        ),
    ] = False,
    outputs_root: Annotated[
        Path,
        typer.Option(
            "--outputs-root",
            help="Root dir containing engagement subdirs.",
        ),
    ] = Path("outputs"),
) -> None:
    """Inspect (or replay) one tool invocation."""
    invocations_dir = outputs_root / engagement_id / "tool_invocations"
    if not invocations_dir.exists():
        typer.echo(f"No tool_invocations directory at {invocations_dir}", err=True)
        raise typer.Exit(code=1)

    matches = sorted(invocations_dir.glob(f"{seq:05d}_*.json"))
    if not matches:
        typer.echo(f"No invocation file for seq={seq} in {invocations_dir}", err=True)
        raise typer.Exit(code=1)

    record = json.loads(matches[0].read_text(encoding="utf-8"))

    if not replay:
        # Print human-readable summary then full record JSON
        typer.echo(_format_invocation_record(record))
        typer.echo("")
        typer.echo("--- Full record ---")
        typer.echo(json.dumps(record, indent=2, default=str))
        return

    # --- Replay mode ---
    import asyncio as _asyncio
    import os as _os
    import subprocess as _subprocess
    import time as _time

    command: list[str] = record.get("command") or []
    if not command:
        typer.echo("Recorded record has no command — cannot replay.", err=True)
        raise typer.Exit(code=2)
    cwd = record.get("cwd") or None
    stdin_data: str | None = record.get("stdin")
    env_overrides = record.get("env_overrides") or {}

    typer.echo(f"Replaying: {' '.join(command)}")
    started = _time.perf_counter()

    async def _run() -> tuple[str, str, int]:
        env = {**_os.environ, **env_overrides} if env_overrides else None
        proc = await _asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=env,
            stdin=_asyncio.subprocess.PIPE if stdin_data is not None else None,
            stdout=_asyncio.subprocess.PIPE,
            stderr=_asyncio.subprocess.PIPE,
        )
        input_bytes = stdin_data.encode() if stdin_data is not None else None
        out, err = await proc.communicate(input=input_bytes)
        return out.decode(errors="replace"), err.decode(errors="replace"), proc.returncode or 0

    try:
        new_stdout, new_stderr, new_rc = _asyncio.run(_run())
    except FileNotFoundError as exc:
        typer.echo(f"Replay failed: command not found on PATH ({exc})", err=True)
        raise typer.Exit(code=2) from exc
    except _subprocess.SubprocessError as exc:
        typer.echo(f"Replay failed: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    elapsed_ms = (_time.perf_counter() - started) * 1000.0
    typer.echo("")
    typer.echo("--- Replay result ---")
    typer.echo(f"Original exit_code: {record.get('exit_code')}")
    typer.echo(f"Replay exit_code:   {new_rc}")
    typer.echo(f"Original duration:  {record.get('duration_ms')}")
    typer.echo(f"Replay duration:    {elapsed_ms:.0f}ms")
    typer.echo("")
    typer.echo("--- stdout diff ---")
    _emit_text_diff(record.get("stdout", ""), new_stdout)
    typer.echo("")
    typer.echo("--- stderr diff ---")
    _emit_text_diff(record.get("stderr", ""), new_stderr)


def _format_invocation_record(record: dict) -> str:
    """One-line + brief summary of an invocation record."""
    seq = record.get("seq")
    tool = record.get("tool_name", "?")
    rc = record.get("exit_code")
    dur = record.get("duration_ms")
    dur_str = f"{dur:.0f}ms" if isinstance(dur, (int, float)) else "-"
    cmd = " ".join(record.get("command") or [])
    agent = record.get("agent") or "?"
    step = record.get("step") or "?"
    parsed_type = record.get("parsed_output_type") or "-"
    return (
        f"seq={seq} tool={tool} agent={agent} step={step} rc={rc} dur={dur_str}\n"
        f"  cmd: {cmd[:200]}\n"
        f"  parsed: {parsed_type} (succeeded={record.get('parse_succeeded')})"
    )


def _emit_text_diff(original: str, replayed: str) -> None:
    """Render a minimal unified diff between two text blobs."""
    import difflib

    if original == replayed:
        typer.echo("(identical)")
        return
    diff = difflib.unified_diff(
        original.splitlines(keepends=False),
        replayed.splitlines(keepends=False),
        fromfile="original",
        tofile="replay",
        lineterm="",
        n=2,
    )
    for line in diff:
        typer.echo(line)


# ---------------------------------------------------------------------------
# step-replay
# ---------------------------------------------------------------------------


@app.command("step-replay")
def step_replay(
    engagement_id: Annotated[
        str,
        typer.Argument(help="Engagement UUID. Reads outputs/<id>/step_inputs/."),
    ],
    step_id: Annotated[
        str,
        typer.Argument(help="Step UUID (filename: <step_id>.json)."),
    ],
    outputs_root: Annotated[
        Path,
        typer.Option(
            "--outputs-root",
            help="Root dir containing engagement subdirs.",
        ),
    ] = Path("outputs"),
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="LLM provider override."),
    ] = None,
) -> None:
    """Re-run one recorded agent step in isolation and diff against the original."""
    from clinkz.observability.replay import replay_step_sync

    result = replay_step_sync(
        engagement_id=engagement_id,
        step_id=step_id,
        outputs_root=outputs_root,
        llm_provider=provider,
    )
    typer.echo(f"Step:    {result.step_id}")
    typer.echo(f"Agent:   {result.agent}")
    typer.echo(f"Method:  {result.method_name}")
    typer.echo(f"Status:  {'ok' if result.succeeded else 'failed'}")
    if result.error:
        typer.echo(f"Error:   {result.error}", err=True)
        raise typer.Exit(code=2)

    if result.diff is not None:
        typer.echo("")
        typer.echo(f"Identical to original: {result.diff.identical}")
        if not result.diff.identical:
            typer.echo("")
            typer.echo("--- output diff ---")
            _emit_text_diff(
                result.diff.original_summary or "",
                result.diff.replayed_summary or "",
            )


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
