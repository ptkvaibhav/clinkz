"""``clinkz scan`` as an operator drives it — every flag, offline.

Nothing here reaches the network: each test either stops at ``--dry-run``, at a
refusal, or at a stubbed orchestrator. The one thing being tested is the
interface contract — what a flag does, what a bad flag costs, which exit code a
wrapper script can rely on, and the guarantee that a password never appears in
anything the operator or an artifact can read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from clinkz.cli import (
    EXIT_BAD_INPUT,
    EXIT_CODES,
    EXIT_HALTED,
    EXIT_OK,
    EXIT_REFUSED,
    EXIT_RUN_FAILED,
    EXIT_UNSHAREABLE,
    _report_outcome,
    app,
)
from clinkz.models.engagement import BENCHMARK_ACKNOWLEDGEMENT
from tests.authorization_fixtures import TEST_AUTHORIZATION

runner = CliRunner()

#: A password long enough to be substring-redactable, distinctive enough that a
#: leak is unambiguous.
SECRET_PASSWORD = "correct-horse-battery-staple-9471"


@pytest.fixture
def auth_file(tmp_path: Path) -> Path:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(TEST_AUTHORIZATION.model_dump(mode="json")), encoding="utf-8")
    return path


@pytest.fixture
def creds_file(tmp_path: Path) -> Path:
    path = tmp_path / "creds.json"
    path.write_text(
        json.dumps(
            {
                "credentials": [
                    {
                        "role": "admin",
                        "username": "admin@example.test",
                        "password": SECRET_PASSWORD,
                    },
                    {"role": "user", "username": "user@example.test", "password": SECRET_PASSWORD},
                    {"role": "anonymous"},
                ]
            }
        ),
        encoding="utf-8",
    )
    return path


AUTH_FLAGS = [
    "--auth-party",
    "Dana Okafor",
    "--auth-role",
    "CTO",
    "--auth-contact",
    "dana@example.test",
    "--auth-ref",
    "SOW-2026-114",
    "--auth-technique",
    "*",
    "--auth-emergency",
    "+1-555-0101",
]


# ---------------------------------------------------------------------------
# Help — the thing a tester who did not build this reads first
# ---------------------------------------------------------------------------


def test_top_level_help_lists_every_real_subcommand() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in (
        "scan",
        "abort",
        "actions",
        "artifact-scan",
        "tool-invoke",
        "step-replay",
        "corpus-replay",
        "trace",
    ):
        assert command in result.output, f"{command} is missing from the top-level help"


def test_scan_help_states_what_it_proves_and_what_it_refuses() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    assert result.exit_code == 0
    out = " ".join(result.output.split())
    assert "WHAT IT PROVES" in out
    assert "WHAT IT WILL NOT DO" in out
    assert "unforgeable nonce" in out, "the P6 oracle is not described"
    assert "authorization record" in out
    assert "EXAMPLES" in out
    assert "EXIT CODES" in out


def test_scan_help_documents_every_exit_code_the_code_can_return() -> None:
    """The contract is an interface. A wrapper reads these, so they cannot drift."""
    result = runner.invoke(app, ["scan", "--help"])
    rendered = " ".join(result.output.split())
    for code, _meaning in EXIT_CODES:
        assert f" {code} " in rendered, f"exit code {code} is not documented"


def test_every_documented_flag_is_actually_accepted() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    for flag in (
        "--target",
        "--scope",
        "--exclude",
        "--source",
        "--source-base-url",
        "--creds",
        "--creds-prompt",
        "--authorization",
        "--auth-party",
        "--auth-prompt",
        "--benchmark-profile",
        "--dry-run",
        "--rate-limit",
        "--max-concurrency",
        "--out",
        "--resume",
        "--provider",
    ):
        assert flag in result.output, f"{flag} is not on the scan command"


# ---------------------------------------------------------------------------
# Targets, scope, exclusions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    ["https://app.example.test", "app.example.test", "10.10.10.5", "10.10.10.0/24"],
)
def test_every_target_shape_reaches_a_dry_run(target: str, auth_file: Path) -> None:
    result = runner.invoke(app, ["scan", "-t", target, "-a", str(auth_file), "--dry-run"])
    assert result.exit_code == EXIT_OK, result.output
    assert target in result.output


def test_exclusions_are_recorded_and_take_precedence(auth_file: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "10.10.10.0/24",
            "-x",
            "10.10.10.1",
            "-x",
            "10.10.10.2",
            "-a",
            str(auth_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "OUT : 10.10.10.1" in result.output
    assert "OUT : 10.10.10.2" in result.output


def test_inline_scope_entries_add_to_the_target(auth_file: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-s",
            "api.example.test",
            "-s",
            "10.10.10.0/24",
            "-a",
            str(auth_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "in  : app.example.test (domain)" in result.output
    assert "in  : api.example.test (domain)" in result.output
    assert "in  : 10.10.10.0/24 (cidr)" in result.output


def test_a_scope_file_and_the_target_are_unioned(tmp_path: Path, auth_file: Path) -> None:
    """A --target the scope file does not list would be refused by every tool's
    scope check, producing a run that scans nothing and explains nothing."""
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps(
            {
                "name": "ACME Q1",
                "targets": [{"value": "api.example.test", "type": "domain"}],
                "excluded": [{"value": "legacy.example.test", "type": "domain"}],
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-s",
            str(scope_file),
            "-a",
            str(auth_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "ACME Q1" in result.output
    assert "in  : api.example.test" in result.output
    assert "in  : app.example.test" in result.output
    assert "OUT : legacy.example.test" in result.output


def test_a_mistyped_scope_document_is_an_error_not_a_hostname(tmp_path: Path) -> None:
    """The dangerous failure: ``scpoe.json`` classifies fine as a hostname."""
    result = runner.invoke(
        app, ["scan", "-t", "app.example.test", "-s", str(tmp_path / "scpoe.json"), "--dry-run"]
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "names a scope document" in result.output


def test_two_scope_files_are_refused(tmp_path: Path) -> None:
    for name in ("a.json", "b.json"):
        (tmp_path / name).write_text(
            json.dumps({"name": "x", "targets": [{"value": "a.test", "type": "domain"}]}),
            encoding="utf-8",
        )
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-s",
            str(tmp_path / "a.json"),
            "-s",
            str(tmp_path / "b.json"),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "More than one scope FILE" in result.output


def test_an_unusable_target_is_a_setup_error() -> None:
    result = runner.invoke(app, ["scan", "-t", "file:///etc/passwd", "--dry-run"])
    assert result.exit_code == EXIT_BAD_INPUT
    assert "unsupported scheme" in result.output


# ---------------------------------------------------------------------------
# Authorization — the refusal that has no override
# ---------------------------------------------------------------------------


def test_a_dry_run_without_authorization_says_a_real_run_would_refuse() -> None:
    """The dry run is how an operator FINDS OUT the record is missing."""
    result = runner.invoke(app, ["scan", "-t", "app.example.test", "--dry-run"])
    assert result.exit_code == EXIT_OK, result.output
    assert "NO AUTHORIZATION RECORD" in result.output
    assert "Nothing was sent" in result.output


def test_a_real_run_without_any_authorization_refuses_before_touching_the_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exit 3, and no state store, no docker check, no packet.

    ``open_engagement`` is the first statement of ``run()`` — before the container
    pre-flight, before the state store, before a single request — so the refusal
    is asserted by proving that the step immediately after it never ran.
    """
    reached: list[str] = []

    def _tripwire(*_a: Any, **_k: Any) -> None:
        reached.append("state_store")

    monkeypatch.setattr("clinkz.orchestrator.orchestrator.StateStore.__init__", _tripwire)

    result = runner.invoke(app, ["scan", "-t", "app.example.test"])
    assert result.exit_code == EXIT_REFUSED, result.output
    assert not reached, "the engagement got past the gate without an authorization record"
    assert "authoriz" in result.output.lower()


def test_authorization_from_flags_is_accepted(auth_file: Path) -> None:
    result = runner.invoke(app, ["scan", "-t", "app.example.test", *AUTH_FLAGS, "--dry-run"])
    assert result.exit_code == EXIT_OK, result.output
    assert "Dana Okafor" in result.output
    assert "SOW-2026-114" in result.output


def test_partial_authorization_flags_refuse_and_name_what_is_missing() -> None:
    result = runner.invoke(
        app, ["scan", "-t", "app.example.test", "--auth-party", "Dana Okafor", "--dry-run"]
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "--auth-emergency" in result.output
    assert "--auth-technique" in result.output


def test_an_authorization_file_beats_flags(auth_file: Path) -> None:
    """Precedence is stated in the help; assert it holds."""
    result = runner.invoke(
        app, ["scan", "-t", "app.example.test", "-a", str(auth_file), *AUTH_FLAGS, "--dry-run"]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "Test Authorizer" in result.output
    assert "Dana Okafor" not in result.output


def test_an_invalid_authorization_file_is_a_setup_error(tmp_path: Path) -> None:
    bad = tmp_path / "auth.json"
    bad.write_text(json.dumps({"authorizing_party": "Someone"}), encoding="utf-8")
    result = runner.invoke(app, ["scan", "-t", "app.example.test", "-a", str(bad), "--dry-run"])
    assert result.exit_code == EXIT_BAD_INPUT
    assert "Invalid authorization record" in result.output


def test_auth_prompt_collects_the_record_interactively() -> None:
    answers = "\n".join(
        [
            "Dana Okafor",
            "CTO",
            "dana@example.test",
            "SOW-2026-114",
            "*",
            "+1-555-0101",
            "",
        ]
    )
    result = runner.invoke(
        app, ["scan", "-t", "app.example.test", "--auth-prompt", "--dry-run"], input=answers + "\n"
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "Dana Okafor" in result.output


def test_the_permitted_technique_list_withholds_classes(tmp_path: Path) -> None:
    """A narrow authorization must visibly withhold everything it did not name."""
    record = TEST_AUTHORIZATION.model_dump(mode="json")
    record["permitted_techniques"] = ["sql_injection"]
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(record), encoding="utf-8")

    result = runner.invoke(app, ["scan", "-t", "app.example.test", "-a", str(path), "--dry-run"])
    assert result.exit_code == EXIT_OK, result.output
    assert "not in the client's permitted-technique list" in result.output


# ---------------------------------------------------------------------------
# Benchmark profile
# ---------------------------------------------------------------------------


def _benchmark_file(tmp_path: Path) -> Path:
    path = tmp_path / "bench.json"
    path.write_text(
        json.dumps(
            {
                "target_is_throwaway": True,
                "acknowledgement": BENCHMARK_ACKNOWLEDGEMENT,
                "permitted_categories": ["deletion", "identity_change"],
                "declared_by": "Test Operator",
                "declared_reference": "LAB-1",
            }
        ),
        encoding="utf-8",
    )
    return path


def test_a_benchmark_profile_attaches_to_the_authorization_record(
    tmp_path: Path, auth_file: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "http://localhost:3000",
            "-a",
            str(auth_file),
            "--benchmark-profile",
            str(_benchmark_file(tmp_path)),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output


def test_a_benchmark_profile_without_an_authorization_record_is_refused(tmp_path: Path) -> None:
    """It declares what was AUTHORISED, so it cannot exist without the record."""
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "http://localhost:3000",
            "--benchmark-profile",
            str(_benchmark_file(tmp_path)),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "authorization record" in result.output


# ---------------------------------------------------------------------------
# Credentials — never echoed, never written
# ---------------------------------------------------------------------------


def test_credentials_load_and_the_password_never_reaches_stdout(
    creds_file: Path, auth_file: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-a",
            str(auth_file),
            "-c",
            str(creds_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "admin" in result.output, "the roles should be reported"
    assert "user" in result.output
    assert SECRET_PASSWORD not in result.output, "a password reached the terminal"


def test_the_legacy_credentials_spelling_still_works(creds_file: Path, auth_file: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-a",
            str(auth_file),
            "--credentials",
            str(creds_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert SECRET_PASSWORD not in result.output


def test_a_git_tracked_credential_file_is_refused(auth_file: Path) -> None:
    """A credential file under version control is a leaked credential file."""
    tracked = Path("tests/authorization_fixtures.py").resolve()
    result = runner.invoke(
        app,
        ["scan", "-t", "app.example.test", "-a", str(auth_file), "-c", str(tracked), "--dry-run"],
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "tracked by git" in result.output


def test_a_missing_credential_file_is_a_setup_error(tmp_path: Path, auth_file: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-a",
            str(auth_file),
            "-c",
            str(tmp_path / "nope.json"),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_BAD_INPUT
    assert "not found" in result.output


def test_one_role_warns_that_access_control_cannot_compare(tmp_path: Path, auth_file: Path) -> None:
    solo = tmp_path / "one.json"
    solo.write_text(
        json.dumps(
            {
                "credentials": [
                    {"role": "admin", "username": "a@b.test", "password": SECRET_PASSWORD}
                ]
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(
        app, ["scan", "-t", "app.example.test", "-a", str(auth_file), "-c", str(solo), "--dry-run"]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "Only one authenticating role" in result.output
    assert SECRET_PASSWORD not in result.output


# ---------------------------------------------------------------------------
# Gray-box --source
# ---------------------------------------------------------------------------


def test_a_recognised_source_tree_is_reported_as_ingestable(
    tmp_path: Path, auth_file: Path
) -> None:
    src = tmp_path / "app"
    src.mkdir()
    (src / "package.json").write_text("{}", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", "-t", "app.example.test", "-a", str(auth_file), "--source", str(src), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "detected language: javascript" in result.output
    assert "WOULD run" in result.output


def test_an_unrecognised_source_tree_says_so_before_the_run(
    tmp_path: Path, auth_file: Path
) -> None:
    """A Python checkout ingests to an EMPTY model that is byte-identical to a
    Java tree with no sinks. Without this the operator cannot tell."""
    src = tmp_path / "app"
    src.mkdir()
    (src / "main.py").write_text("print('hi')\n", encoding="utf-8")
    result = runner.invoke(
        app,
        ["scan", "-t", "app.example.test", "-a", str(auth_file), "--source", str(src), "--dry-run"],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "NOT INGESTABLE" in result.output
    assert "fully black-box" in result.output


def test_a_missing_source_path_is_reported_not_silently_ignored(
    tmp_path: Path, auth_file: Path
) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-a",
            str(auth_file),
            "--source",
            str(tmp_path / "nope"),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "does not exist" in result.output


# ---------------------------------------------------------------------------
# Rails and --out
# ---------------------------------------------------------------------------


def test_rate_and_concurrency_overrides_reach_the_rails(auth_file: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "app.example.test",
            "-a",
            str(auth_file),
            "--rate-limit",
            "2.5",
            "--max-concurrency",
            "2",
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "max_requests_per_second: 2.5" in result.output
    assert "max_concurrent_requests: 2" in result.output


def test_the_legacy_rate_spelling_still_works(auth_file: Path) -> None:
    result = runner.invoke(
        app, ["scan", "-t", "app.example.test", "-a", str(auth_file), "--rate", "3", "--dry-run"]
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "max_requests_per_second: 3.0" in result.output


def test_out_redirects_the_whole_artifact_bundle(tmp_path: Path, auth_file: Path) -> None:
    """--out was accepted and ignored for the whole life of the CLI. Every writer
    resolves the root independently, so this asserts them together."""
    from clinkz.config import settings

    original = settings.outputs_root
    destination = tmp_path / "engagement-artifacts"
    try:
        result = runner.invoke(
            app,
            [
                "scan",
                "-t",
                "app.example.test",
                "-a",
                str(auth_file),
                "--out",
                str(destination),
                "--dry-run",
            ],
        )
        assert result.exit_code == EXIT_OK, result.output
        assert settings.outputs_root == destination

        from clinkz.observability.trace import TraceWriter
        from clinkz.safety.action_log import ActionLog
        from clinkz.safety.governor import EngagementGovernor

        writer = TraceWriter("eng-out-test")
        try:
            assert writer.path == (destination / "eng-out-test" / "trace.jsonl").resolve()
            assert writer.invocations.dir.parent == (destination / "eng-out-test").resolve()
        finally:
            writer.close()
        assert ActionLog("eng-out-test").path.parent == destination / "eng-out-test"
        assert EngagementGovernor("eng-out-test").outputs_root == destination
    finally:
        settings.outputs_root = original


# ---------------------------------------------------------------------------
# The exit-code contract
# ---------------------------------------------------------------------------


def test_a_completed_run_exits_zero() -> None:
    assert _report_outcome({"status": "completed", "summary": "done"}) == EXIT_OK


def test_a_failed_run_does_not_exit_zero() -> None:
    """It used to. A wrapper could not tell a failed engagement from a clean one."""
    assert _report_outcome({"status": "failed", "error": "boom"}) == EXIT_RUN_FAILED


def test_a_halted_run_has_its_own_code() -> None:
    outcome = _report_outcome(
        {"status": "halted", "halt_reason": "kill_switch", "halt_detail": "operator"}
    )
    assert outcome == EXIT_HALTED


def test_a_bundle_that_fails_the_disclosure_gate_outranks_everything() -> None:
    """Completed, findings written — and it must not be shared. That is the fact
    the operator most needs to leave with."""
    outcome = _report_outcome(
        {
            "status": "completed",
            "summary": "done",
            "artifact_scan": {
                "status": "credential_material_found",
                "root": "outputs/abc",
                "report_file": "outputs/abc/artifact_scan.json",
            },
        }
    )
    assert outcome == EXIT_UNSHAREABLE


def test_a_clean_disclosure_gate_does_not_change_the_outcome() -> None:
    outcome = _report_outcome(
        {"status": "completed", "summary": "done", "artifact_scan": {"status": "clean"}}
    )
    assert outcome == EXIT_OK


def test_the_documented_codes_are_the_codes_the_module_defines() -> None:
    documented = {code for code, _ in EXIT_CODES}
    assert documented == {
        EXIT_OK,
        EXIT_RUN_FAILED,
        EXIT_BAD_INPUT,
        EXIT_REFUSED,
        EXIT_HALTED,
        EXIT_UNSHAREABLE,
    }


# ---------------------------------------------------------------------------
# Security-review fixes
# ---------------------------------------------------------------------------


def test_a_target_outside_the_scope_document_is_added_loudly(
    tmp_path: Path, auth_file: Path
) -> None:
    """The scope document IS the authorization boundary.

    Both silent resolutions are wrong: ignoring --target scans something other
    than what the operator named, and adding it quietly widens what they are
    authorized to touch. So it is unioned and said out loud, twice.
    """
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({"name": "ACME", "targets": [{"value": "api.example.test", "type": "domain"}]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "stale.example.test",
            "-s",
            str(scope_file),
            "-a",
            str(auth_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "not listed in the scope document" in result.output
    assert "authorization boundary" in result.output
    # And it reaches the scope listing an operator reads, not just a log line.
    assert "added from --target" in result.output


def test_a_target_already_in_the_scope_document_warns_about_nothing(
    tmp_path: Path, auth_file: Path
) -> None:
    scope_file = tmp_path / "scope.json"
    scope_file.write_text(
        json.dumps({"name": "ACME", "targets": [{"value": "api.example.test", "type": "domain"}]}),
        encoding="utf-8",
    )
    result = runner.invoke(
        app,
        [
            "scan",
            "-t",
            "api.example.test",
            "-s",
            str(scope_file),
            "-a",
            str(auth_file),
            "--dry-run",
        ],
    )
    assert result.exit_code == EXIT_OK, result.output
    assert "authorization boundary" not in result.output


@pytest.mark.parametrize("bad_id", ["", "   ", "../other", "a/b", "..", "."])
def test_resume_refuses_a_blank_or_path_shaped_id(bad_id: str, tmp_path: Path) -> None:
    """The id names a directory the report is written into. `abort` and
    `artifact-scan` have always refused these; --resume must too."""
    result = runner.invoke(
        app, ["scan", "-t", "unused", "--resume", bad_id, "--out", str(tmp_path / "art")]
    )
    assert result.exit_code == EXIT_BAD_INPUT, f"{bad_id!r} was accepted"
    assert "Invalid engagement id" in result.output


def test_an_aborted_engagement_is_a_refusal_not_a_failure() -> None:
    """The documented contract says exit 3 when the authenticated-state
    assertion fails; the code returned 1.

    `AuthStateError` was a plain `Exception`, so the orchestrator's phase-level
    handler converted a deliberate, loud refusal into `status="failed"` and the
    CLI reported "the engagement failed". A live Juice Shop run hit exactly this
    and exited 1 while `--help` promised 3.
    """
    from clinkz.engagement.auth_state import AuthStateError
    from clinkz.engagement.gate import EngagementAbortedError

    assert issubclass(AuthStateError, EngagementAbortedError), (
        "an abort must propagate as a refusal, or the CLI reports it as a crash"
    )


def test_every_refusal_the_contract_names_is_an_abort() -> None:
    """Exit 3's documented meaning, checked against the exception hierarchy.

    Each condition the contract lists must actually reach the CLI as an
    `EngagementAbortedError`; anything that does not gets reported as a failure
    instead, and the operator cannot tell "we refused" from "we broke".
    """
    from clinkz.engagement.auth_state import AuthStateError
    from clinkz.engagement.gate import (
        AuthorizationRequiredError,
        EngagementAbortedError,
        EngagementWindowClosedError,
    )

    for refusal in (AuthorizationRequiredError, EngagementWindowClosedError, AuthStateError):
        assert issubclass(refusal, EngagementAbortedError), f"{refusal.__name__} is not an abort"
