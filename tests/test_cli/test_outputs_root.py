"""Every artifact writer resolves the outputs root the same way, at call time.

``--out`` was accepted and silently ignored for the whole life of the CLI: the
writers each carried ``outputs_root: Path = Path("outputs")`` as a DEFAULT
ARGUMENT, bound once at import, so an operator's redirect was parsed, logged and
then overridden by a value frozen before the flag existed.

The replacement default is ``None``-resolved-at-call-time, which has its own
failure mode: widen the signature, forget the body, and the writer raises
``TypeError: ... not 'NoneType'`` the first time nobody passes the argument.
That is exactly what happened to ``ActionLog.read``, and it surfaced only
because a resume test happened to reach it. This module makes that class of
mistake fail here instead.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from clinkz.config import settings

#: Every writer/reader whose outputs root is now resolved rather than defaulted.
#: A call with NO outputs_root argument must produce a path under the configured
#: root — that call is the one an unresolved signature crashes on.
pytestmark = pytest.mark.usefixtures("redirected_outputs_root")


@pytest.fixture
def redirected_outputs_root(tmp_path: Path):
    original = settings.outputs_root
    settings.outputs_root = tmp_path / "redirected"
    try:
        yield settings.outputs_root
    finally:
        settings.outputs_root = original


def test_trace_writer_and_its_two_recorders_follow_the_root(
    redirected_outputs_root: Path,
) -> None:
    from clinkz.observability.trace import TraceWriter

    writer = TraceWriter("eng-1")
    try:
        root = redirected_outputs_root.resolve()
        assert writer.path == root / "eng-1" / "trace.jsonl"
        assert writer.invocations.dir == root / "eng-1" / "tool_invocations"
        assert writer.step_inputs.dir == root / "eng-1" / "step_inputs"
    finally:
        writer.close()


def test_action_log_write_and_read_agree_on_the_root(redirected_outputs_root: Path) -> None:
    """The write path and the read path resolved the root in two places, and only
    one of them was updated. They must agree or a run's own report cannot read
    the log the run just wrote."""
    from clinkz.safety.action_log import ActionLog

    log = ActionLog("eng-2")
    assert log.path == redirected_outputs_root / "eng-2" / "actions.jsonl"
    log.record_sent(method="POST", url="http://app.test/x", body="a=1")

    records = ActionLog.read("eng-2")
    assert len(records) == 1
    assert records[0].url == "http://app.test/x"


def test_governor_follows_the_root(redirected_outputs_root: Path) -> None:
    from clinkz.safety.governor import EngagementGovernor

    governor = EngagementGovernor("eng-3")
    assert governor.outputs_root == redirected_outputs_root
    assert governor.halt_path.parent == redirected_outputs_root / "eng-3"


def test_report_writer_follows_the_root(redirected_outputs_root: Path) -> None:
    from clinkz.config import outputs_root

    assert outputs_root() == redirected_outputs_root


def test_step_replayer_follows_the_root(redirected_outputs_root: Path) -> None:
    from clinkz.observability.replay import StepReplayer

    replayer = StepReplayer(engagement_id="eng-4", step_id="s1")
    assert replayer.outputs_root == redirected_outputs_root


def test_corpus_loader_follows_the_root(redirected_outputs_root: Path) -> None:
    from clinkz.observability.corpus_replay import load_corpus

    # The root does not exist, so the loader yields nothing — the assertion is
    # that it RESOLVED rather than raising on a None path.
    assert list(load_corpus()) == []


@pytest.mark.parametrize(
    ("module", "qualname"),
    [
        ("clinkz.observability.trace", "TraceWriter.__init__"),
        ("clinkz.observability.invocations", "ToolInvocationRecorder.__init__"),
        ("clinkz.observability.invocations", "StepInputRecorder.__init__"),
        ("clinkz.safety.action_log", "ActionLog.__init__"),
        ("clinkz.safety.action_log", "ActionLog.read"),
        ("clinkz.safety.governor", "EngagementGovernor.__init__"),
        ("clinkz.observability.replay", "StepReplayer.__init__"),
        ("clinkz.observability.corpus_replay", "load_corpus"),
    ],
)
def test_no_writer_carries_a_frozen_outputs_root_default(module: str, qualname: str) -> None:
    """A ``Path("outputs")`` default is the original bug, in one line.

    Bound at import, it makes ``--out`` a no-op for that writer while every other
    writer honours it — which splits one engagement's bundle across two trees and
    leaves each looking complete.
    """
    import importlib

    obj = importlib.import_module(module)
    for part in qualname.split("."):
        obj = getattr(obj, part)
    parameter = inspect.signature(obj).parameters.get("outputs_root")
    assert parameter is not None, f"{module}.{qualname} lost its outputs_root parameter"
    assert parameter.default is None, (
        f"{module}.{qualname} carries a frozen default ({parameter.default!r}); "
        "resolve the root at call time instead"
    )
