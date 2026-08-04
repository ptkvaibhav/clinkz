"""Typer CLI entry point for Clinkz.

Commands:
    scan          - Full pipeline (recon -> scan/research/exploit -> report)
    abort         - Kill switch: halt a running engagement immediately
    actions       - Show what a run actually did to the target
    trace inspect - Render an engagement execution trace
    tool-invoke   - Inspect or replay one recorded tool invocation
    step-replay   - Re-run one recorded agent step in isolation

The pipeline runs end-to-end via ``scan``; there are no single-phase run
commands (the Orchestrator owns phase sequencing). ``trace inspect`` /
``tool-invoke`` / ``step-replay`` / ``actions`` are post-run inspectors over
``outputs/<id>/``.

``scan`` refuses to start without an authorization record. That is deliberate
and there is no flag to skip it - see ``clinkz.engagement.gate``.

Usage::

    clinkz scan --target example.com --scope scope.json \\
        --authorization auth.json --credentials ../creds.json
    clinkz scan --target example.com --scope scope.json --dry-run
    clinkz abort <engagement_id>
    clinkz actions <engagement_id>
    python -m clinkz trace inspect <engagement_id>
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import UTC, datetime
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
    authorization: Annotated[
        Path | None,
        typer.Option(
            "--authorization",
            "-a",
            help=(
                "Path to the authorization record JSON. REQUIRED unless the scope "
                "file already carries an 'authorization' object."
            ),
        ),
    ] = None,
    credentials: Annotated[
        Path | None,
        typer.Option(
            "--credentials",
            "-c",
            help=(
                "Path to an UNTRACKED local JSON file of role credentials. "
                "Refused outright if the file is tracked by git."
            ),
        ),
    ] = None,
    prompt_credentials: Annotated[
        str | None,
        typer.Option(
            "--prompt-credentials",
            help=(
                "Comma-separated role names to prompt for interactively "
                "(passwords are read without echo), e.g. 'admin,user'."
            ),
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Enumerate what the engagement WOULD do and exit. Sends nothing.",
        ),
    ] = False,
    rate: Annotated[
        float | None,
        typer.Option("--rate", help="Max requests per second (overrides the scope's policy)."),
    ] = None,
    max_concurrency: Annotated[
        int | None,
        typer.Option("--max-concurrency", help="Max simultaneous in-flight requests."),
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
    """Run a full penetration test: recon -> crawl -> exploit -> report.

    Refuses to start without an authorization record naming the authorizing
    party, their role and contact, the authorization reference, the permitted
    techniques, and an emergency contact.
    """
    _setup_logging(verbose)
    log = logging.getLogger("cli.scan")

    from clinkz.engagement.dryrun import build_dry_run_plan, render_dry_run
    from clinkz.engagement.gate import EngagementAbortedError
    from clinkz.engagement.secrets import (
        CredentialFileError,
        load_credential_file,
        prompt_for_credentials,
    )
    from clinkz.models.engagement import AuthorizationRecord, CredentialSet
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

    # --authorization overrides / supplies the scope's record.
    if authorization is not None:
        try:
            auth_data = json.loads(authorization.read_text(encoding="utf-8"))
            scope_obj.authorization = AuthorizationRecord.model_validate(auth_data)
        except (OSError, json.JSONDecodeError) as exc:
            typer.echo(f"Could not read the authorization file: {exc}", err=True)
            raise typer.Exit(code=2) from None
        except Exception as exc:  # noqa: BLE001 - surfaced as a setup error
            typer.echo(f"Invalid authorization record in {authorization}:\n{exc}", err=True)
            raise typer.Exit(code=2) from None

    # Rail overrides. Applied to the scope's policy so one object carries the
    # rails into the engagement and into the report.
    if rate is not None:
        scope_obj.safety.max_requests_per_second = rate
    if max_concurrency is not None:
        scope_obj.safety.max_concurrent_requests = max_concurrency

    # Credentials. Never echoed, never written to the scope (which IS persisted).
    cred_set = CredentialSet()
    try:
        if credentials is not None:
            cred_set = load_credential_file(credentials)
        elif prompt_credentials:
            roles = [r.strip() for r in prompt_credentials.split(",") if r.strip()]
            cred_set = prompt_for_credentials(roles)
    except CredentialFileError as exc:
        typer.echo(f"{exc}", err=True)
        raise typer.Exit(code=2) from None

    if dry_run:
        typer.echo(render_dry_run(build_dry_run_plan(scope_obj, cred_set)))
        return

    log.info("Starting full scan - target: %s, provider: %s", target, provider)

    async def _run() -> dict:
        orchestrator = OrchestratorAgent(provider=provider, credentials=cred_set)
        return await orchestrator.run(scope_obj)

    try:
        result = asyncio.run(_run())
    except EngagementAbortedError as exc:
        # The gate, the window, or the authenticated-state assertion refused.
        # Exit code 3 so a wrapper can tell "we refused to run" apart from
        # "the run failed".
        typer.echo(f"\n{exc}\n", err=True)
        raise typer.Exit(code=3) from None
    except ClinkzDockerError as exc:
        typer.echo(f"Docker pre-flight failed:\n{exc}", err=True)
        raise typer.Exit(code=2) from None

    status = result.get("status", "unknown")
    summary = result.get("summary", "No summary.")
    typer.echo(f"Engagement {status}: {summary}")
    if status == "halted":
        typer.echo(f"HALTED ({result.get('halt_reason')}): {result.get('halt_detail')}", err=True)
    safety = result.get("safety") or {}
    if safety:
        typer.echo(
            f"State-changing requests sent: {safety.get('state_changing_sent', 0)}; "
            f"refused by safety rails: {safety.get('state_changing_refused', 0)}"
        )
    if result.get("action_log"):
        typer.echo(f"Action log: {result['action_log']}")


# ---------------------------------------------------------------------------
# abort - the kill switch
# ---------------------------------------------------------------------------


@app.command()
def abort(
    engagement_id: Annotated[
        str,
        typer.Argument(help="Engagement UUID to halt (from the run's log output)."),
    ],
    outputs_root: Annotated[
        Path,
        typer.Option("--outputs-root", help="Root dir containing engagement subdirs."),
    ] = Path("outputs"),
) -> None:
    """Halt a running engagement immediately and cleanly.

    Writes the kill-switch sentinel the running governor polls. Within one poll
    interval the engagement stops sending requests, every phase winds down, and
    the report is still generated - a halt is a clean stop, and the operator who
    pulled the switch needs the report more than one whose run completed, not
    less.

    Safe to run against a finished engagement; it simply leaves the marker.
    """
    from clinkz.safety.governor import HALT_SENTINEL

    # A blank or path-shaped id would resolve to the outputs root itself and
    # write a sentinel no governor ever polls -- the operator would believe the
    # engagement was halted while it kept testing. Refuse instead.
    cleaned = engagement_id.strip()
    if not cleaned or "/" in cleaned or "\\" in cleaned or cleaned in (".", ".."):
        typer.echo(
            f"Invalid engagement id {engagement_id!r}. Pass the UUID printed at the "
            "start of the run (also the directory name under outputs/).",
            err=True,
        )
        raise typer.Exit(code=2)

    engagement_dir = outputs_root / cleaned
    if not engagement_dir.is_dir():
        typer.echo(
            f"No engagement directory at {engagement_dir}. "
            "Check the engagement id, or pass --outputs-root.",
            err=True,
        )
        raise typer.Exit(code=1)

    sentinel = engagement_dir / HALT_SENTINEL
    sentinel.write_text(
        f"halt requested via `clinkz abort` at {datetime.now(UTC).isoformat()}\n",
        encoding="utf-8",
    )
    typer.echo(f"Kill switch armed: {sentinel}")
    typer.echo(
        "The engagement will stop sending requests within one poll interval and "
        "will still produce its report."
    )


# ---------------------------------------------------------------------------
# actions - what did it do to my app?
# ---------------------------------------------------------------------------


@app.command()
def actions(
    engagement_id: Annotated[
        str,
        typer.Argument(help="Engagement UUID. Reads outputs/<id>/actions.jsonl"),
    ],
    outcome: Annotated[
        str | None,
        typer.Option("--outcome", help="Filter: sent | refused | failed"),
    ] = None,
    outputs_root: Annotated[
        Path,
        typer.Option("--outputs-root", help="Root dir containing engagement subdirs."),
    ] = Path("outputs"),
    raw: Annotated[
        bool,
        typer.Option("--raw", help="Emit JSONL instead of the human table."),
    ] = False,
) -> None:
    """Show every state-changing request the engagement produced.

    The precise answer to "what did it do to my app?". Read-only requests are
    deliberately absent - the trace already records those, and burying twelve
    mutations in forty thousand GETs would defeat the purpose.
    """
    from clinkz.safety.action_log import ActionLog

    records = ActionLog.read(engagement_id, outputs_root=outputs_root)
    if not records:
        typer.echo(
            f"No action log at {outputs_root / engagement_id / 'actions.jsonl'} "
            "(or the engagement sent no state-changing requests)."
        )
        return

    if outcome:
        records = [r for r in records if r.outcome == outcome]

    if raw:
        for record in records:
            typer.echo(record.model_dump_json())
        return

    sent = sum(1 for r in records if r.outcome == "sent")
    refused = sum(1 for r in records if r.outcome == "refused")
    typer.echo(f"{len(records)} state-changing action(s): {sent} sent, {refused} refused")
    typer.echo("")
    for record in records:
        marker = "SENT   " if record.outcome == "sent" else "REFUSED"
        status = f" -> {record.status_code}" if record.status_code else ""
        typer.echo(f"[{record.seq:04d}] {marker} {record.method:<7} {record.url}{status}")
        if record.outcome == "refused":
            typer.echo(f"          {record.category}: {record.reason} (signal: {record.signal})")
        elif record.body_excerpt:
            typer.echo(f"          body: {record.body_excerpt[:160]}")


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
        typer.echo("Recorded record has no command - cannot replay.", err=True)
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
