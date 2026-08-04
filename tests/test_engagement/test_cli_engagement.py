"""CLI surface: the gate refuses, the dry run sends nothing, abort is precise."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from clinkz.cli import app
from clinkz.safety.governor import HALT_SENTINEL
from tests.authorization_fixtures import TEST_AUTHORIZATION

runner = CliRunner()


def _scope_file(tmp_path: Path, *, authorized: bool) -> Path:
    scope = {
        "name": "cli-test",
        "targets": [{"value": "http://app.test", "type": "url"}],
    }
    if authorized:
        scope["authorization"] = TEST_AUTHORIZATION.model_dump(mode="json")
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(scope), encoding="utf-8")
    return path


def test_dry_run_needs_no_authorization_and_sends_nothing(tmp_path: Path) -> None:
    """A dry run is how an operator FINDS OUT they are missing the record."""
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "app.test",
            "--scope",
            str(_scope_file(tmp_path, authorized=False)),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Nothing was sent" in result.output
    assert "NO AUTHORIZATION RECORD" in result.output


def test_dry_run_reports_the_rails_and_the_classes(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "app.test",
            "--scope",
            str(_scope_file(tmp_path, authorized=True)),
            "--dry-run",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Test Authorizer" in result.output
    assert "WILL BE REFUSED" in result.output
    assert "CLASSES THAT WOULD BE ATTEMPTED" in result.output
    assert "CLASSES THAT WOULD NOT BE ATTEMPTED" in result.output


def test_an_invalid_authorization_file_is_a_setup_error(tmp_path: Path) -> None:
    bad = tmp_path / "auth.json"
    bad.write_text(json.dumps({"authorizing_party": "Someone"}), encoding="utf-8")
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "app.test",
            "--scope",
            str(_scope_file(tmp_path, authorized=False)),
            "--authorization",
            str(bad),
            "--dry-run",
        ],
    )
    assert result.exit_code == 2
    assert "Invalid authorization record" in result.output


def test_abort_writes_the_sentinel(tmp_path: Path) -> None:
    engagement = tmp_path / "eng-123"
    engagement.mkdir()
    result = runner.invoke(app, ["abort", "eng-123", "--outputs-root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert (engagement / HALT_SENTINEL).is_file()
    assert "Kill switch armed" in result.output


def test_abort_refuses_a_blank_or_path_shaped_id(tmp_path: Path) -> None:
    """A blank id would arm a sentinel no governor polls.

    The operator would believe the engagement was halted while it kept testing —
    the worst possible outcome for a kill switch. Found on a live run, where an
    empty shell variable produced `outputs/HALT`.
    """
    for bad_id in ("", "   ", "../eng", "a/b"):
        result = runner.invoke(app, ["abort", bad_id, "--outputs-root", str(tmp_path)])
        assert result.exit_code == 2, f"{bad_id!r} was accepted"
        assert not (tmp_path / HALT_SENTINEL).exists(), f"{bad_id!r} armed the outputs root"


def test_abort_on_an_unknown_engagement_is_an_error(tmp_path: Path) -> None:
    result = runner.invoke(app, ["abort", "no-such-engagement", "--outputs-root", str(tmp_path)])
    assert result.exit_code == 1
    assert "No engagement directory" in result.output


def test_actions_reads_the_log_back(tmp_path: Path) -> None:
    from clinkz.safety.action_log import ActionLog

    log = ActionLog("eng-actions", outputs_root=tmp_path)
    log.record_sent(method="POST", url="http://app.test/comments", body="text=hi")
    log.record_refused(
        method="POST",
        url="http://app.test/account/delete",
        category="deletion",
        reason="Request semantics indicate deletion of a resource.",
        signal="delete",
    )
    result = runner.invoke(app, ["actions", "eng-actions", "--outputs-root", str(tmp_path)])
    assert result.exit_code == 0, result.output
    assert "1 sent, 1 refused" in result.output
    assert "REFUSED" in result.output
    assert "deletion" in result.output

    only_refused = runner.invoke(
        app, ["actions", "eng-actions", "--outputs-root", str(tmp_path), "--outcome", "refused"]
    )
    assert "comments" not in only_refused.output
