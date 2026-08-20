"""Typer CLI entry point for Clinkz.

Commands:
    scan          - Full pipeline (recon -> scan/research/exploit -> report)
    abort         - Kill switch: halt a running engagement immediately
    actions       - Show what a run actually did to the target
    artifact-scan - Re-run the disclosure gate over a finished bundle
    trace inspect - Render an engagement execution trace
    tool-invoke   - Inspect or replay one recorded tool invocation
    step-replay   - Re-run one recorded agent step in isolation
    corpus-replay - Offline: re-parse the recorded tool corpus, diff vs baseline

The pipeline runs end-to-end via ``scan``; there are no single-phase run
commands (the Orchestrator owns phase sequencing). ``trace inspect`` /
``tool-invoke`` / ``step-replay`` / ``actions`` / ``artifact-scan`` are post-run
inspectors over ``<outputs-root>/<id>/``.

``scan`` refuses to start without an authorization record. That is deliberate
and there is no flag to skip it - see ``clinkz.engagement.gate``.

**The exit-code contract is part of the interface**, and lives in one place:
:data:`EXIT_CODES`. A wrapper script has to be able to tell "we refused to run"
from "the run failed" from "the run finished and the bundle must not be shared",
and a CLI that returns 0 for all three makes every caller guess.

Usage::

    clinkz scan --target https://app.example.com --authorization auth.json
    clinkz scan --target 10.10.10.0/24 --exclude 10.10.10.1 --dry-run
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
from typing import Annotated, Any

import typer

#: The exit-code contract. Stated once, rendered into ``clinkz scan --help``, and
#: asserted by the test suite so it cannot drift from what the code returns.
EXIT_OK = 0
EXIT_RUN_FAILED = 1
EXIT_BAD_INPUT = 2
EXIT_REFUSED = 3
EXIT_HALTED = 4
EXIT_UNSHAREABLE = 5

EXIT_CODES: tuple[tuple[int, str], ...] = (
    (EXIT_OK, "the engagement completed (with findings or without) - the report was written"),
    (EXIT_RUN_FAILED, "the engagement started and then failed; any partial report is named"),
    (EXIT_BAD_INPUT, "operator input was unusable: a bad flag, a missing or invalid file"),
    (
        EXIT_REFUSED,
        "refused BEFORE testing: no authorization record, outside the engagement window, "
        "or the authenticated-state assertion failed",
    ),
    (
        EXIT_HALTED,
        "halted mid-run by the kill switch or by blocking detection; report still written",
    ),
    (
        EXIT_UNSHAREABLE,
        "the engagement completed but its artifact bundle FAILED the disclosure gate - "
        "do not share it until `clinkz artifact-scan` is clean",
    ),
)


def _exit_code_help() -> str:
    """Render the exit-code contract for a ``--help`` screen."""
    return "\n".join(f"  {code}  {meaning}" for code, meaning in EXIT_CODES)


app = typer.Typer(
    name="clinkz",
    help=(
        "Clinkz — autonomous AI penetration testing.\n\n"
        "Takes an authorized scope and produces a professional pentest report with "
        "no human in the loop. Every finding is confirmed by an oracle that observed "
        "the vulnerability's DEFINING effect; anything short of that is reported as "
        "an unconfirmed lead, never as a finding.\n\n"
        "Start with `clinkz scan --help`, then `clinkz scan ... --dry-run` to see "
        "exactly what a run would do before it sends anything."
    ),
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


def _default_outputs_root() -> Path:
    """The configured outputs root, read at call time (``--out`` may have set it)."""
    from clinkz.config import outputs_root

    return outputs_root()


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


_SCAN_HELP = f"""Run a full authorized penetration test and write a client-ready report.

One command, end to end: reconnaissance, service and version detection, content
and API discovery, live research, exploitation, chaining, and the report. The
Orchestrator owns phase sequencing - there is nothing else to run.

WHAT IT PROVES. Every confirmed finding was witnessed by a deterministic oracle
that observed the vulnerability's DEFINING effect, not a correlate of it: a
database row returned in a successful response, command output in
command-output position, a 3xx Location that leaves the origin, an
authorization boundary actually crossed, an out-of-band callback carrying an
unforgeable nonce, or script execution witnessed from inside the page's own JS
context. A reflected payload is not execution and is never reported as one.

WHAT IT WILL NOT DO. It refuses to start without an authorization record. It
refuses to send a request outside the scope you gave it. It refuses destructive
actions by default - deleting a resource, changing a password or an email
address, taking a payment, revoking a key, resetting data, logging its own
session out, or toggling a security control - and every refusal is named in the
report. An effect it did not witness is published as an unconfirmed lead, never
as a finding with a caveat.

AUTHORIZATION comes from one of four places, in this order: --authorization
<file>, the six --auth-* flags (party / role / contact / ref / technique /
emergency), --auth-prompt, or an "authorization" block in the scope file.
Whichever you use must be COMPLETE; a partial record is refused by name.

EXAMPLES

  Simplest real run - authorization in a file, everything else default:

    clinkz scan -t https://app.example.com -a auth.json

  See exactly what it would do, sending nothing:

    clinkz scan -t https://app.example.com -a auth.json --dry-run

  Be asked for the authorization record instead of writing a file:

    clinkz scan -t app.example.com --auth-prompt

  A network range with a host carved out, paced for production:

    clinkz scan -t 10.10.10.0/24 -x 10.10.10.1 -a auth.json --rate-limit 2

  Authenticated, two roles, so access-control has two principals to compare:

    clinkz scan -t https://app.example.com -a auth.json -c creds.json

  Gray-box - hand it the application's source tree as well:

    clinkz scan -t https://app.example.com -a auth.json --source ~/src/app

  Rebuild the report of a run that was interrupted (sends nothing):

    clinkz scan -t unused --resume 0be7cb63-...

EXIT CODES

{_exit_code_help()}
"""


@app.command(help=_SCAN_HELP)
def scan(
    target: Annotated[
        str,
        typer.Option(
            "--target",
            "-t",
            help=(
                "What to test: a URL (https://app.example.com/portal), a hostname "
                "(app.example.com), an IP (10.0.0.5), or a CIDR block (10.0.0.0/24)."
            ),
        ),
    ],
    scope: Annotated[
        list[str] | None,
        typer.Option(
            "--scope",
            "-s",
            help=(
                "An additional in-scope entry (URL / host / IP / CIDR), or the path "
                "to a scope JSON file. Repeatable."
            ),
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-x",
            help=(
                "Explicitly OUT of scope; takes precedence over every in-scope entry. "
                "Repeatable. Named in the report as untested."
            ),
        ),
    ] = None,
    source: Annotated[
        Path | None,
        typer.Option(
            "--source",
            help=(
                "Gray-box: the application's source tree. The language is auto-detected "
                "(Java / JavaScript-TypeScript); if no ingestor matches, the run "
                "continues black-box and the report says so."
            ),
        ),
    ] = None,
    source_base_url: Annotated[
        str | None,
        typer.Option(
            "--source-base-url",
            help=(
                "Base URL that source-derived routes join onto, when it is not the "
                "primary target (e.g. https://host/geoserver)."
            ),
        ),
    ] = None,
    authorization: Annotated[
        Path | None,
        typer.Option(
            "--authorization",
            "-a",
            help=(
                "Path to the authorization record JSON. Required unless the record is "
                "supplied by --auth-* flags, --auth-prompt, or the scope file."
            ),
        ),
    ] = None,
    auth_party: Annotated[
        str, typer.Option("--auth-party", help="Legal name of the authorizing party.")
    ] = "",
    auth_role: Annotated[
        str, typer.Option("--auth-role", help="Their role/title — the basis of their authority.")
    ] = "",
    auth_contact: Annotated[
        str, typer.Option("--auth-contact", help="A reachable contact for them.")
    ] = "",
    auth_ref: Annotated[
        str, typer.Option("--auth-ref", help="Contract / SOW / ticket reference.")
    ] = "",
    auth_technique: Annotated[
        list[str] | None,
        typer.Option(
            "--auth-technique",
            help="A permitted technique or class. Repeatable. Use '*' to permit all.",
        ),
    ] = None,
    auth_emergency: Annotated[
        str,
        typer.Option("--auth-emergency", help="Who to call the moment something goes wrong."),
    ] = "",
    auth_notes: Annotated[
        str,
        typer.Option("--auth-notes", help="Caveats agreed with the client (recorded verbatim)."),
    ] = "",
    auth_prompt: Annotated[
        bool,
        typer.Option(
            "--auth-prompt",
            help="Ask for the authorization record interactively instead of via flags.",
        ),
    ] = False,
    benchmark_profile: Annotated[
        Path | None,
        typer.Option(
            "--benchmark-profile",
            help=(
                "Path to a benchmark profile JSON declaring the target a disposable "
                "throwaway and naming each destructive category permitted. Absent by "
                "default; recorded verbatim in the report header when present."
            ),
        ),
    ] = None,
    credentials: Annotated[
        Path | None,
        typer.Option(
            "--creds",
            "--credentials",
            "-c",
            help=(
                "UNTRACKED local JSON file of role-labelled credentials "
                "(admin / user / anonymous). Refused outright if git tracks it. "
                "Never logged, never written to an artifact."
            ),
        ),
    ] = None,
    prompt_credentials: Annotated[
        str | None,
        typer.Option(
            "--creds-prompt",
            "--prompt-credentials",
            help=(
                "Comma-separated role names to prompt for interactively, e.g. "
                "'admin,user'. Passwords are read without echo."
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
        typer.Option(
            "--rate-limit",
            "--rate",
            help="Ceiling on outbound requests per second across the whole engagement.",
        ),
    ] = None,
    max_concurrency: Annotated[
        int | None,
        typer.Option("--max-concurrency", help="Max simultaneous in-flight requests."),
    ] = None,
    token_cap: Annotated[
        int | None,
        typer.Option(
            "--token-cap",
            help=(
                "Total LLM tokens this engagement may consume. Measured exactly, so "
                "it needs no rate card. The run halts cleanly at the cap and still "
                "produces its report."
            ),
        ),
    ] = None,
    spend_cap_usd: Annotated[
        float | None,
        typer.Option(
            "--spend-cap-usd",
            help=(
                "Total USD this engagement may spend. Requires a declared rate per "
                "model in CLINKZ_LLM_PRICES - clinkz ships no default rate card, "
                "because a built-in table would be right the day it was written and "
                "silently wrong afterwards."
            ),
        ),
    ] = None,
    run_mode: Annotated[
        str | None,
        typer.Option(
            "--run-mode",
            help=(
                "What a provider fallback costs. 'client' (default) completes the run, "
                "stamps the report provider_degraded and marks it ineligible as a "
                "baseline. 'baseline' makes any fallback a HARD FAILURE - a ladder "
                "served by two models is not a ladder."
            ),
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option(
            "--out",
            "--output",
            "-o",
            help=(
                "Root directory for this engagement's artifact bundle (report, trace, "
                "action log, tool invocations). Default: ./outputs"
            ),
        ),
    ] = None,
    resume: Annotated[
        str | None,
        typer.Option(
            "--resume",
            help=(
                "Rebuild the report of an earlier engagement from its persisted "
                "findings. Sends NOTHING and does not re-test — findings are "
                "persisted as they are proven, phase coverage is not."
            ),
        ),
    ] = None,
    db: Annotated[
        Path | None,
        typer.Option("--db", help="SQLite state store to use (default: ./clinkz.db)."),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="LLM provider: openai | anthropic | gemini | ollama"),
    ] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Debug-level logging.")] = False,
) -> None:
    _setup_logging(verbose)
    log = logging.getLogger("cli.scan")

    from clinkz.config import settings
    from clinkz.engagement.cli_inputs import (
        AuthorizationFlags,
        ScanInputError,
        authorization_from_flags,
        load_authorization_file,
        load_benchmark_profile,
    )
    from clinkz.engagement.dryrun import build_dry_run_plan, render_dry_run
    from clinkz.engagement.gate import EngagementAbortedError, open_engagement
    from clinkz.engagement.secrets import (
        CredentialFileError,
        load_credential_file,
        prompt_for_credentials,
    )
    from clinkz.llm.providers import (
        NoProviderKeyError,
        assert_any_provider_available,
    )
    from clinkz.llm.spend import SpendCapError, SpendLedger, load_price_table
    from clinkz.models.engagement import CredentialSet
    from clinkz.orchestrator.orchestrator import OrchestratorAgent
    from clinkz.tools.docker_preflight import ClinkzDockerError

    # --out redirects the WHOLE bundle, so it is applied to the settings before
    # anything constructs a writer. Assigned rather than threaded through every
    # constructor because the trace writer, the action log, the invocation
    # recorder and the report each resolve the root independently — and a bundle
    # split across two directories is worse than one in the wrong place.
    if output is not None:
        settings.outputs_root = Path(output).expanduser()
    if db is not None:
        settings.db_path = Path(db).expanduser()

    # --resume rebuilds a deliverable from local state. It sends nothing, so it
    # runs before scope assembly and never reaches the engagement gate.
    if resume is not None:
        _run_resume(resume, db_path=settings.db_path)
        return

    # No provider key at all is the cold-start failure, so it is answered
    # first: before scope assembly, before authorization, before docker.
    # Detection only — this reads environment variables and sends nothing, so
    # it does not disturb the invariant that the authorization gate precedes
    # every packet. Placed after the --resume branch on purpose: rebuilding a
    # report from persisted findings makes no LLM calls and must not require a
    # key to do it.
    try:
        assert_any_provider_available()
    except NoProviderKeyError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    try:
        scope_obj = _assemble_scope(
            target=target,
            scope=list(scope or []),
            exclude=list(exclude or []),
        )
    except ScanInputError as exc:
        typer.echo(f"{exc}", err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    # Authorization, in precedence order: an explicit file, then flags, then the
    # interactive prompt, then whatever the scope file already carried. Each
    # source produces a COMPLETE record or an error naming what is missing —
    # there is no path that assembles a partial one.
    flags = AuthorizationFlags(
        party=auth_party,
        role=auth_role,
        contact=auth_contact,
        reference=auth_ref,
        techniques=tuple(auth_technique or ()),
        emergency=auth_emergency,
        notes=auth_notes,
    )
    try:
        if authorization is not None:
            scope_obj.authorization = load_authorization_file(authorization)
        elif flags.any_supplied():
            scope_obj.authorization = authorization_from_flags(flags)
        elif auth_prompt:
            scope_obj.authorization = authorization_from_flags(_prompt_authorization())
        if benchmark_profile is not None:
            profile = load_benchmark_profile(benchmark_profile)
            if scope_obj.authorization is None:
                raise ScanInputError(
                    "--benchmark-profile declares destructive testing against a "
                    "throwaway target, and it attaches to the authorization record. "
                    "Supply the authorization record too."
                )
            scope_obj.authorization.benchmark_profile = profile
    except ScanInputError as exc:
        typer.echo(f"{exc}", err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    # Gray-box inputs. The engine reports for itself whether the tree ingested.
    if source is not None:
        scope_obj.source_dir = str(Path(source).expanduser())
    if source_base_url is not None:
        scope_obj.discovery_base_url = source_base_url

    # Rail overrides. Applied to the scope's policy so one object carries the
    # rails into the engagement and into the report.
    if rate is not None:
        scope_obj.safety.max_requests_per_second = rate
    if max_concurrency is not None:
        scope_obj.safety.max_concurrent_requests = max_concurrency

    # LLM budget. Assembled here so a bad cap is refused before anything is
    # dispatched, rather than discovered as an under-count at the end.
    spend_ledger = SpendLedger(
        token_cap=int(token_cap or 0),
        usd_cap=float(spend_cap_usd or 0.0),
    )
    try:
        spend_ledger.prices = load_price_table()
        # Every model that could serve a call, not just the primary: a USD cap
        # that stops counting the moment the chain rotates is not a cap.
        spend_ledger.assert_enforceable(
            [
                settings.anthropic_model,
                settings.gemini_model,
                settings.gemini_research_model,
                settings.agent_model,
            ]
        )
    except SpendCapError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    # Run mode. Set on the settings singleton rather than the scope because it
    # governs the LLM chain, not the target - the resilient client reads it at
    # dispatch time, which is after every writer has been constructed.
    if run_mode is not None:
        if run_mode not in ("client", "baseline"):
            typer.echo(
                f"--run-mode must be 'client' or 'baseline' (got {run_mode!r}).",
                err=True,
            )
            raise typer.Exit(EXIT_BAD_INPUT)
        settings.run_mode = run_mode  # type: ignore[assignment]
    # Every bound, stated before anything is dispatched. An operator asked to
    # authorise a run against their own production site needs to read the
    # limits BEFORE the first packet, not reconstruct them from the report.
    typer.echo("Bounds (as configured, before dispatch):")
    typer.echo(f"  request rate  : {scope_obj.safety.max_requests_per_second:g} req/s")
    typer.echo(f"  concurrency   : {scope_obj.safety.max_concurrent_requests} in flight")
    window = scope_obj.window
    typer.echo(
        "  wall clock    : "
        + (
            f"{window.start.isoformat()} -> {window.end.isoformat()} "
            "(hard stop, re-checked on every request)"
            if window is not None
            else "no engagement window declared - set one in the scope file to bound it"
        )
    )
    typer.echo(
        "  token cap     : "
        + (f"{spend_ledger.token_cap:,} tokens" if spend_ledger.token_cap else "none")
    )
    typer.echo(
        "  spend cap     : " + (f"${spend_ledger.usd_cap:.2f}" if spend_ledger.usd_cap else "none")
    )
    typer.echo(
        "  benchmark     : "
        + (
            "PROFILE SUPPLIED — destructive categories may be permitted"
            if benchmark_profile is not None
            else "OFF (no --benchmark-profile; unsafe_method, deletion and data_reset "
            "are refused, and there is no flag that permits them)"
        )
    )
    typer.echo(
        f"Run mode: {settings.run_mode} "
        + (
            "(a provider fallback FAILS this run)"
            if settings.run_mode == "baseline"
            else "(a provider fallback is stamped and disqualifies the run as a baseline)"
        )
    )

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
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    if dry_run:
        typer.echo(render_dry_run(build_dry_run_plan(scope_obj, cred_set)))
        _echo_dry_run_source_note(scope_obj)
        return

    # The authorization refusal runs HERE, before anything is constructed.
    # ``OrchestratorAgent.run()`` opens the same gate as its first statement and
    # remains the structural guarantee — there is no path to a tool call that
    # bypasses it. But the orchestrator's CONSTRUCTOR resolves an LLM provider,
    # so an operator with no authorization record and no API key was told
    # "GEMINI_API_KEY is not set": the wrong refusal, as a traceback, about the
    # less important of the two problems. The gate is pure validation, so
    # running it twice costs a log line and fixes the order.
    try:
        open_engagement(scope_obj)
    except EngagementAbortedError as exc:
        typer.echo(f"\n{exc}\n", err=True)
        raise typer.Exit(code=EXIT_REFUSED) from None

    log.info(
        "Starting full scan — target: %s, provider: %s, outputs: %s",
        target,
        provider,
        settings.outputs_root,
    )

    try:
        orchestrator = OrchestratorAgent(provider=provider, credentials=cred_set)
    except ValueError as exc:
        # No usable LLM provider. An operator-input problem with a fix the
        # operator can act on, not a crash to read a stack trace for.
        typer.echo(f"Cannot start: {exc}", err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    try:
        result = asyncio.run(orchestrator.run(scope_obj))
    except EngagementAbortedError as exc:
        # The window or the authenticated-state assertion refused mid-setup.
        # A distinct code so a wrapper can tell "we refused to run" apart from
        # "the run failed".
        typer.echo(f"\n{exc}\n", err=True)
        raise typer.Exit(code=EXIT_REFUSED) from None
    except ClinkzDockerError as exc:
        typer.echo(f"Docker pre-flight failed:\n{exc}", err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    raise typer.Exit(code=_report_outcome(result))


def _report_outcome(result: dict[str, Any]) -> int:
    """Print the run summary and return the exit code it maps to.

    Split out so the exit-code contract is one function the tests can drive with
    a synthetic result dict, rather than something only a live engagement
    reaches.
    """
    status = result.get("status", "unknown")
    typer.echo(f"Engagement {status}: {result.get('summary', 'No summary.')}")

    safety = result.get("safety") or {}
    if safety:
        typer.echo(
            f"State-changing requests sent: {safety.get('state_changing_sent', 0)}; "
            f"refused by safety rails: {safety.get('state_changing_refused', 0)}"
        )
    if result.get("action_log"):
        typer.echo(f"Action log: {result['action_log']}")

    report_paths = (result.get("phases") or {}).get("report") or {}
    for label, key in (("Report (JSON)", "json_path"), ("Report (Markdown)", "markdown_path")):
        if report_paths.get(key):
            typer.echo(f"{label}: {report_paths[key]}")

    # The disclosure gate outranks everything else the run produced. A bundle
    # carrying credential material must not be attached to an email, and the
    # operator finds that out from the exit code, not by reading a log line that
    # scrolled past twenty minutes ago.
    disclosure = result.get("artifact_scan") or {}
    if disclosure.get("status") == "credential_material_found":
        typer.echo(
            f"\nDO NOT SHARE {disclosure.get('root')} — the artifact disclosure gate "
            f"found credential material. See {disclosure.get('report_file')}, fix, and "
            f"re-run `clinkz artifact-scan` until it is clean.",
            err=True,
        )
        return EXIT_UNSHAREABLE

    if status == "halted":
        typer.echo(
            f"HALTED ({result.get('halt_reason')}): {result.get('halt_detail')}. "
            "The report was still produced.",
            err=True,
        )
        return EXIT_HALTED
    if status == "failed":
        typer.echo(f"The engagement failed: {result.get('error', 'no error recorded')}", err=True)
        return EXIT_RUN_FAILED
    return EXIT_OK


def _assemble_scope(*, target: str, scope: list[str], exclude: list[str]) -> Any:
    """Build the EngagementScope from --target / --scope / --exclude.

    ``--scope`` is overloaded on purpose: an operator with a prepared scope
    document passes the file, and one testing a handful of hosts passes them
    inline. The two are told apart by whether the value exists on disk, and a
    value that clearly MEANT to be a file but is missing is an error rather than
    a hostname the engagement would then go and scan.

    Args:
        target: The primary ``--target`` value.
        scope: Repeated ``--scope`` values — at most one scope file, any number
            of inline entries.
        exclude: Repeated ``--exclude`` values, always inline entries.

    Returns:
        The assembled :class:`~clinkz.models.scope.EngagementScope`.

    Raises:
        ScanInputError: A value could not be classified, a named scope file is
            unreadable or invalid, or more than one scope file was supplied.
    """
    from clinkz.engagement.cli_inputs import (
        ScanInputError,
        looks_like_scope_file,
        make_scope_entry,
        names_a_scope_document,
    )
    from clinkz.models.scope import EngagementScope

    scope_obj: EngagementScope | None = None
    inline_entries = []

    for value in scope:
        if looks_like_scope_file(value):
            if scope_obj is not None:
                raise ScanInputError(
                    f"More than one scope FILE was supplied ({value}). Pass one scope "
                    "document, and add any extra hosts as inline --scope entries."
                )
            try:
                data = json.loads(Path(value).expanduser().read_text(encoding="utf-8"))
                scope_obj = EngagementScope.model_validate(data)
            except (OSError, json.JSONDecodeError) as exc:
                raise ScanInputError(f"Could not read the scope file {value}: {exc}") from None
            except ValueError as exc:
                raise ScanInputError(f"Invalid scope file {value}:\n{exc}") from None
            continue
        if names_a_scope_document(value):
            raise ScanInputError(
                f"--scope {value!r} names a scope document, and no such file exists. "
                "Check the path. (For an inline in-scope entry pass a bare host, IP, "
                "CIDR block or URL - never a .json name, which would otherwise be "
                "read as a hostname and scanned.)"
            )
        inline_entries.append(make_scope_entry(value))

    target_entry = make_scope_entry(target)
    if scope_obj is None:
        scope_obj = EngagementScope(name=target.strip(), targets=[target_entry])
    elif not any(e.value == target_entry.value for e in scope_obj.targets):
        # A --target the scope document does not list is a conflict between two
        # things the operator supplied, and BOTH silent resolutions are wrong.
        # Ignoring it scans something other than what they named; adding it
        # quietly widens the authorization boundary, because the scope document
        # IS that boundary — a stale --target from shell history alongside a
        # client's scope file would put an unauthorised host in the run.
        #
        # So the union happens (a run that scans nothing helps nobody) and it is
        # made LOUD twice: on stderr now, and in the entry's own notes, which
        # reach the report's scope section and the dry-run listing.
        target_entry = make_scope_entry(
            target, notes="added from --target; not listed in the scope document"
        )
        scope_obj.targets.append(target_entry)
        typer.echo(
            f"WARNING: --target {target_entry.value} is not listed in the scope "
            f"document and has been ADDED to the in-scope set. The scope document "
            f"is the authorization boundary — if this host is not covered by your "
            f"authorization, stop and correct one of the two.",
            err=True,
        )

    known = {e.value for e in scope_obj.targets}
    scope_obj.targets.extend(e for e in inline_entries if e.value not in known)

    excluded_known = {e.value for e in scope_obj.excluded}
    for value in exclude:
        entry = make_scope_entry(value, notes="excluded on the command line")
        if entry.value not in excluded_known:
            scope_obj.excluded.append(entry)
            excluded_known.add(entry.value)
    return scope_obj


def _prompt_authorization():  # noqa: ANN202 — returns AuthorizationFlags
    """Collect the authorization record interactively, field by field."""
    from clinkz.engagement.cli_inputs import AuthorizationFlags

    typer.echo(
        "Authorization record — every field is required. An engagement without a "
        "named authorizing party is not an engagement.\n"
    )
    party = input("Authorizing party (legal name): ").strip()
    role = input("Their role / title: ").strip()
    contact = input("Their contact (email or phone): ").strip()
    reference = input("Authorization reference (contract / SOW / ticket): ").strip()
    raw_techniques = input("Permitted techniques (comma-separated, or * for all): ").strip()
    emergency = input("Emergency contact: ").strip()
    notes = input("Notes (optional): ").strip()
    return AuthorizationFlags(
        party=party,
        role=role,
        contact=contact,
        reference=reference,
        techniques=tuple(t.strip() for t in raw_techniques.split(",") if t.strip()),
        emergency=emergency,
        notes=notes,
    )


def _echo_dry_run_source_note(scope_obj) -> None:  # noqa: ANN001 — EngagementScope
    """Report, during a dry run, whether the --source tree would actually ingest.

    A dry run exists so an operator learns what WOULD happen before it happens.
    "Your source tree is in a language this engine cannot read, so the run would
    be black-box" is exactly that kind of fact, and finding it out afterwards
    from the report is finding it out too late.
    """
    if not scope_obj.source_dir:
        return
    from clinkz.discovery import detect_ingestor

    selection = detect_ingestor(scope_obj.source_dir)
    typer.echo("")
    typer.echo("GRAY-BOX SOURCE")
    if selection.matched:
        typer.echo(f"  {scope_obj.source_dir}")
        typer.echo(f"  detected language: {selection.language} — source analysis WOULD run")
    else:
        typer.echo(f"  {scope_obj.source_dir}")
        typer.echo(f"  ! NOT INGESTABLE: {selection.reason}")
        typer.echo("  ! The engagement would run fully black-box, and the report would say so.")


def _validated_engagement_id(engagement_id: str, *, flag: str) -> str:
    """Return the id, or refuse a blank / path-shaped one.

    An engagement id names a directory under the outputs root. A blank one
    resolves to the root itself and a path-shaped one resolves outside the
    bundle, so every command that joins an operator-supplied id to a path runs
    this first. It is not theoretical: a blank shell variable once produced
    ``outputs/HALT``, a kill switch no governor polls, while the operator
    believed the engagement had been halted.

    Args:
        engagement_id: The raw operator-supplied id.
        flag: The flag or argument it came from, for the error message.

    Returns:
        The stripped id.

    Raises:
        typer.Exit: With :data:`EXIT_BAD_INPUT` when the id is unusable.
    """
    cleaned = (engagement_id or "").strip()
    if not cleaned or "/" in cleaned or "\\" in cleaned or cleaned in (".", ".."):
        typer.echo(
            f"Invalid engagement id {engagement_id!r} for {flag}. Pass the UUID "
            "printed at the start of the run (also the directory name under the "
            "outputs root).",
            err=True,
        )
        raise typer.Exit(code=EXIT_BAD_INPUT)
    return cleaned


def _run_resume(engagement_id: str, *, db_path: Path) -> None:
    """Rebuild an interrupted engagement's report from its persisted state."""
    from clinkz.engagement.artifact_scan import SCAN_REPORT_FILENAME, run_disclosure_gate
    from clinkz.engagement.resume import ResumeError, regenerate_report

    # The same refusal `abort` and `artifact-scan` make. The id names a directory
    # the report is written into, and a path-shaped one would resolve outside the
    # engagement's own bundle.
    cleaned = _validated_engagement_id(engagement_id, flag="--resume")

    try:
        result = asyncio.run(regenerate_report(cleaned, db_path=db_path))
    except ResumeError as exc:
        typer.echo(f"{exc}", err=True)
        raise typer.Exit(code=EXIT_BAD_INPUT) from None

    typer.echo(
        f"Rebuilt the report for engagement {cleaned} "
        f"({result.get('engagement_name', '')}, original status: "
        f"{result.get('original_status', 'unknown')}) from persisted state. "
        "Nothing was sent to the target."
    )
    typer.echo(
        f"{result.get('findings_persisted', 0)} persisted finding(s), "
        f"{result.get('leads_persisted', 0)} lead(s)."
    )
    typer.echo(f"Report (JSON):     {result.get('json_path')}")
    typer.echo(f"Report (Markdown): {result.get('markdown_path')}")
    typer.echo(
        "This report covers only what that engagement had already PROVEN. Coverage "
        "it never reached was not retried, and its 'What was NOT tested' section "
        "says so."
    )

    # A resume WRITES a bundle, so it earns the same disclosure gate every other
    # bundle-producing path runs. The report is redacted on the way out, but the
    # gate is the layer that re-reads what actually landed on disk — a guarantee
    # asserted by the logic that produced it is not checked at all.
    root = _default_outputs_root() / cleaned
    report = run_disclosure_gate(root, engagement_id=cleaned)
    if not report.clean:
        typer.echo(
            f"\nDO NOT SHARE {root} — the artifact disclosure gate found "
            f"{len(report.findings)} credential shape(s). See "
            f"{root / SCAN_REPORT_FILENAME}.",
            err=True,
        )
        raise typer.Exit(code=EXIT_UNSHAREABLE)


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
        Path | None,
        typer.Option("--outputs-root", help="Root dir containing engagement subdirs."),
    ] = None,
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

    outputs_root = outputs_root or _default_outputs_root()

    cleaned = _validated_engagement_id(engagement_id, flag="abort")

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
        Path | None,
        typer.Option("--outputs-root", help="Root dir containing engagement subdirs."),
    ] = None,
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

    outputs_root = outputs_root or _default_outputs_root()
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
# artifact-scan
# ---------------------------------------------------------------------------


@app.command("artifact-scan")
def artifact_scan(
    engagement_id: Annotated[
        str,
        typer.Argument(help="Engagement UUID. Scans outputs/<id>/ in full."),
    ],
    outputs_root: Annotated[
        Path | None,
        typer.Option("--outputs-root", help="Root dir containing engagement subdirs."),
    ] = None,
    bundle_only: Annotated[
        bool,
        typer.Option(
            "--bundle-only",
            help="Scan outputs/<id>/ alone, skipping companion artifacts beside it.",
        ),
    ] = False,
    raw: Annotated[
        bool,
        typer.Option("--raw", help="Emit the scan report as JSON."),
    ] = False,
) -> None:
    """Check whether an engagement's artifacts still carry credential material.

    The same gate the orchestrator runs automatically at the end of every
    engagement, exposed so it can be re-run over an older bundle - or over one
    an operator is about to send. Exits non-zero when credential material is
    found, so it can be used as a release check.

    Covers two regions: the engagement's own directory, and the companion
    artifacts beside it - loose files and result directories under the outputs
    root that belong to no engagement. The bundle alone once reported CLEAN over
    3,123 files while a live session token sat one directory up, written there
    by a validation driver. --bundle-only restores the narrower question.

    A finding names the file, line and column, the kind of credential, and a
    salted fingerprint. It never reproduces the value: a leak report that
    contains the leak is a new artifact with the same defect.
    """
    from clinkz.engagement.artifact_scan import (
        REGION_COMPANION,
        scan_artifact_tree,
        scan_companion_artifacts,
    )

    outputs_root = outputs_root or _default_outputs_root()

    # Same refusal as `clinkz abort`: a blank or path-shaped id resolves to the
    # outputs root (or outside it) and would scan the wrong tree, then report a
    # verdict the operator would read as being about their engagement.
    cleaned = _validated_engagement_id(engagement_id, flag="artifact-scan")

    root = outputs_root / cleaned
    if not root.is_dir():
        typer.echo(f"No such engagement directory: {root}", err=True)
        raise typer.Exit(code=2)

    report = scan_artifact_tree(root, engagement_id=engagement_id)
    if not bundle_only:
        report.absorb_companion(scan_companion_artifacts(outputs_root, bundle_root=root))

    if raw:
        typer.echo(report.model_dump_json(indent=2))
    else:
        typer.echo(report.render())
        beside = len(report.region_findings(REGION_COMPANION))
        if beside:
            typer.echo(
                f"\n{beside} of these are companion artifacts, not written by "
                f"{cleaned}. They are still in the directory an operator would share."
            )
    if not report.clean:
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
        Path | None,
        typer.Option(
            "--outputs-root",
            help="Root dir containing engagement subdirs.",
        ),
    ] = None,
    raw: Annotated[
        bool,
        typer.Option("--raw", help="Emit JSONL instead of the human timeline."),
    ] = False,
) -> None:
    """Render a human-readable timeline (or raw JSONL) from a trace file."""
    outputs_root = outputs_root or _default_outputs_root()
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
        Path | None,
        typer.Option(
            "--outputs-root",
            help="Root dir containing engagement subdirs.",
        ),
    ] = None,
) -> None:
    """Inspect (or replay) one tool invocation."""
    outputs_root = outputs_root or _default_outputs_root()
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
        Path | None,
        typer.Option(
            "--outputs-root",
            help="Root dir containing engagement subdirs.",
        ),
    ] = None,
    provider: Annotated[
        str | None,
        typer.Option("--provider", "-p", help="LLM provider override."),
    ] = None,
) -> None:
    """Re-run one recorded agent step in isolation and diff against the original."""
    from clinkz.observability.replay import replay_step_sync

    outputs_root = outputs_root or _default_outputs_root()

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


# ---------------------------------------------------------------------------
# corpus-replay (offline parser regression gate)
# ---------------------------------------------------------------------------


@app.command("corpus-replay")
def corpus_replay(
    rebuild: Annotated[
        bool,
        typer.Option("--rebuild", help="Regenerate the committed baseline from the corpus."),
    ] = False,
    engagement: Annotated[
        list[str] | None,
        typer.Option("--engagement", help="Limit to these engagement ids (repeatable)."),
    ] = None,
    outputs_root: Annotated[
        Path | None, typer.Option("--outputs-root", help="Root dir containing engagement subdirs.")
    ] = None,
    baseline_path: Annotated[
        Path, typer.Option("--baseline", help="Baseline digest to compare against.")
    ] = Path("tests/fixtures/corpus_replay_baseline.json"),
    per_tool_cap: Annotated[
        int, typer.Option("--per-tool-cap", help="Max unique records per tool when rebuilding.")
    ] = 400,
) -> None:
    """Re-parse the recorded tool corpus offline and diff against the baseline.

    Sends nothing. Unlike ``tool-invoke --replay``, which re-executes the
    recorded command against the live target, this only re-runs the parsers
    over bytes already on disk — so it is safe to run against a corpus recorded
    from a client engagement, and it exits non-zero when a parse changed.

    A green run covers parser behaviour against traffic already seen. It says
    nothing about a probe shape the corpus does not contain; new methodology
    still needs live confirmation.
    """
    from clinkz.observability.corpus_replay import (
        build_baseline,
        load_baseline,
        replay_corpus,
    )

    outputs_root = outputs_root or _default_outputs_root()

    if rebuild:
        baseline = build_baseline(outputs_root, engagements=engagement, per_tool_cap=per_tool_cap)
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        baseline_path.write_text(json.dumps(baseline, indent=1, sort_keys=True), encoding="utf-8")
        typer.echo(
            f"Wrote {len(baseline['entries'])} entries to {baseline_path} "
            f"({baseline_path.stat().st_size / 1024:.1f} KB)"
        )
        return

    baseline = load_baseline(baseline_path)
    if baseline is None:
        typer.echo(f"No baseline at {baseline_path}. Run with --rebuild first.", err=True)
        raise typer.Exit(code=2)

    report = replay_corpus(baseline, outputs_root, engagements=engagement)
    typer.echo(report.summary())

    if report.checked == 0:
        typer.echo(
            "Nothing was checked — the corpus is absent or shares no records with "
            "the baseline. That is not a pass.",
            err=True,
        )
        raise typer.Exit(code=2)

    for entry in report.mismatched[:20]:
        typer.echo("")
        typer.echo(f"MISMATCH {entry['key']}  {entry['path']}")
        typer.echo(f"  expected: {json.dumps(entry['expected'], sort_keys=True)[:400]}")
        typer.echo(f"  actual:   {json.dumps(entry['actual'], sort_keys=True)[:400]}")
    for entry in report.errored[:20]:
        typer.echo("")
        typer.echo(f"ERROR {entry['key']}  {entry['path']}: {entry['error']}")

    if not report.ok:
        raise typer.Exit(code=1)
    typer.echo("OK — every recorded response still parses to the same result.")


def main() -> None:
    """Entry point for the 'clinkz' script."""
    app()


if __name__ == "__main__":
    main()
