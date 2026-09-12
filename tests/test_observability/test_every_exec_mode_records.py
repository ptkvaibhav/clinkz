"""Every execution mode leaves an invocation record — over a COMPUTED domain.

The hole this closes
--------------------

``ToolBase._emit_trace_records`` was reached only from ``_run_subprocess`` and
``_run_subprocess_stdin``. Under ``TOOL_EXEC_MODE=local`` the HTTP tool serves
every request in-process through aiohttp and spawns no subprocess, so it reached
neither, so no record was written for any request a local-mode run made.
Engagement ``e4814440`` — cal.diy, 46 endpoints, a proven authenticated session,
a full set of methodology dispatches — holds **0 files** in
``tool_invocations/`` and **0 ``tool_call`` rows** in ``trace.jsonl``. Nothing
failed. The directory was created and stayed empty, and an empty invocation
directory is byte-identical to a run that made no calls at all.

Why the domain is computed
--------------------------

The guard-domain law (``.claude/skills/clinkz-dev/SKILL.md`` §4): a guard's
domain comes from the same source of truth as the thing it guards, and only the
CLASSIFICATION is hand-maintained. A test that asserted "local mode records" by
name would have been written against the mode someone remembered, which is
exactly the failure — ``local`` was not a mode anyone had enumerated, it was the
ELSE of ``== "docker"`` in eleven places.

So the domain is :data:`~clinkz.config.TOOL_EXEC_MODES`, and it is held to the
code in both directions:

* every mode the code BRANCHES on must be in the declared set, so a twelfth
  ``== "podman"`` cannot appear without being declared;
* every DECLARED mode must be shown to write a record, so a mode that emits
  nothing is a red build rather than a run that is quietly unauditable.

The third assertion is the one that would have caught it: with the in-process
emitter removed, ``local`` writes no record and this file goes red. That was
observed before the emitter was added, not assumed.
"""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from clinkz.config import TOOL_EXEC_MODES, settings
from clinkz.models.scope import EngagementScope, ScopeEntry
from clinkz.observability.audit import (
    AUDITABLE,
    INDETERMINATE,
    NOTHING_DISPATCHED,
    AuditRegister,
    reconcile_run_audit,
    set_active_audit_register,
)
from clinkz.observability.invocations import (
    TRANSPORT_IN_PROCESS,
    TRANSPORT_SUBPROCESS,
    TRANSPORTS,
)
from clinkz.observability.trace import TraceWriter, set_active_trace_writer
from clinkz.tools.http_client import HTTPClientTool

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"


# ---------------------------------------------------------------------------
# The domain, computed from what the code actually branches on
# ---------------------------------------------------------------------------


def _exec_mode_literals() -> dict[str, set[str]]:
    """Every string literal compared against ``tool_exec_mode``, by file.

    Reads ``settings.tool_exec_mode == "x"`` / ``!= "x"`` comparisons out of the
    AST. This is the code's own idea of the vocabulary, independent of the
    declaration, which is what makes the two-way assertion below meaningful.
    """
    found: dict[str, set[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover — a broken tree fails elsewhere
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            if not _is_exec_mode(node.left):
                continue
            for comparator in node.comparators:
                if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                    found.setdefault(str(path.relative_to(SRC)), set()).add(comparator.value)
    return found


def _is_exec_mode(node: ast.expr) -> bool:
    """Whether *node* reads the execution mode, however the reader spelled it."""
    if isinstance(node, ast.Attribute) and node.attr == "tool_exec_mode":
        return True
    # A local that was assigned from it — ``exec_mode = settings.tool_exec_mode``
    # then ``if exec_mode == "docker"`` — which is how ``tools/base.py`` reads it.
    return isinstance(node, ast.Name) and node.id in {"exec_mode", "mode"}


def test_every_branched_mode_is_declared() -> None:
    """No code branches on an execution mode the vocabulary does not name."""
    by_file = _exec_mode_literals()
    assert by_file, "found no tool_exec_mode comparison at all — the reader is broken"
    undeclared: dict[str, set[str]] = {}
    for file, literals in by_file.items():
        # ``mode``/``exec_mode`` are also used for the session mode and the
        # collaborator mode, so only literals that look like an exec mode are
        # held against the vocabulary; a literal from another vocabulary is not
        # evidence about this one.
        extra = {lit for lit in literals if lit in {"docker", "local", "host", "podman", "native"}}
        stray = extra - TOOL_EXEC_MODES
        if stray:
            undeclared[file] = stray
    assert not undeclared, (
        "these files branch on an execution mode that config.TOOL_EXEC_MODES does not "
        f"declare: {undeclared}. Declare it, and add it to the emission test below — a "
        "mode nothing can enumerate is a mode nothing can assert records."
    )


def test_docker_mode_is_branched_on_somewhere() -> None:
    """The vocabulary is not larger than the code — a declared-and-unread mode is rot."""
    read = set().union(*_exec_mode_literals().values())
    for mode in TOOL_EXEC_MODES:
        assert mode in read or mode == "local", (
            f"config declares exec mode {mode!r} and no code compares against it. "
            "Either the code stopped reading it or the declaration outlived the branch."
        )


# ---------------------------------------------------------------------------
# Every declared mode emits — the assertion the audit hole failed
# ---------------------------------------------------------------------------


class _FakeResponse:
    """Minimal aiohttp response stand-in.

    Mirrors the real contract — ``headers.getall``, ``version.major/minor``,
    ``await text()`` — rather than the consumer's assumption about it, because a
    mock that returns a shape the real client never produces is counted as
    coverage and proves nothing (invariants 66, 82).
    """

    class _Version:
        major = 1
        minor = 1

    class _Headers(dict):
        def getall(self, key: str, default: Any = None) -> Any:
            value = self.get(key)
            if value is None:
                return [] if default is None else default
            return [value]

    def __init__(self) -> None:
        self.status = 200
        self.reason = "OK"
        self.version = self._Version()
        self.headers = self._Headers({"Content-Type": "text/html"})
        self.history: list[Any] = []
        self.url = "http://target.test/probe"

    async def text(self, errors: str = "strict") -> str:
        return "<html>probe</html>"

    async def __aenter__(self) -> _FakeResponse:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


class _FakeSession:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def request(self, *args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse()

    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


#: What a curl invocation really writes to stdout, so the docker case replays
#: through ``_parse_curl_output`` exactly as the live path does.
_CURL_STDOUT = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>probe</html>\n"


class _FakeProc:
    """A completed process. Mirrors the contract ``_run_subprocess`` reads."""

    returncode = 0

    async def communicate(self, input: bytes | None = None) -> tuple[bytes, bytes]:
        return _CURL_STDOUT.encode(), b""


async def _fake_exec(*cmd: str, **kwargs: Any) -> _FakeProc:
    return _FakeProc()


def _scope() -> EngagementScope:
    return EngagementScope(
        name="exec-mode-guard",
        targets=[ScopeEntry(value="target.test", type="domain")],
    )


@pytest.fixture
def recording(tmp_path: Path) -> Any:
    """A trace writer and an audit register, installed and torn down."""
    writer = TraceWriter(
        engagement_id="exec-mode-guard",
        outputs_root=tmp_path,
    )
    register = AuditRegister()
    set_active_trace_writer(writer)
    set_active_audit_register(register)
    try:
        yield writer, register, tmp_path / "exec-mode-guard" / "tool_invocations"
    finally:
        set_active_audit_register(None)
        set_active_trace_writer(None)
        writer.close()


@pytest.mark.parametrize("exec_mode", sorted(TOOL_EXEC_MODES))
@pytest.mark.asyncio
async def test_every_exec_mode_writes_an_invocation_record(
    exec_mode: str,
    recording: tuple[TraceWriter, AuditRegister, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One HTTP request in each declared mode leaves one full-fidelity record.

    Parametrised over the DECLARED vocabulary, so adding a third mode adds a
    case that fails until that mode emits. That is the "a mode that emits
    nothing must be refused, not silently unaudited" half: the refusal is a red
    build.
    """
    import aiohttp

    _writer, register, invocations_dir = recording
    monkeypatch.setattr(settings, "tool_exec_mode", exec_mode)

    tool = HTTPClientTool(scope=_scope())
    args = {"method": "GET", "url": "http://target.test/probe"}

    if exec_mode == "docker":
        # Stubbed at the PROCESS boundary, not at ``_run_subprocess``: the real
        # ``_run_subprocess`` — including its emit call — is what has to run, or
        # the test asserts against its own stand-in. The stdout handed back is a
        # curl dump, which is what this transport really writes.
        monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
        await tool._execute_curl(args)
        expected_transport = TRANSPORT_SUBPROCESS
    else:
        monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)
        await tool._execute_aiohttp(args)
        expected_transport = TRANSPORT_IN_PROCESS

    files = sorted(invocations_dir.glob("*.json"))
    assert len(files) == 1, (
        f"exec mode {exec_mode!r} wrote {len(files)} invocation record(s) for one request. "
        "A mode that records nothing makes every claim from that run unverifiable, and an "
        "empty tool_invocations/ is indistinguishable from a run that made no calls."
    )
    record = json.loads(files[0].read_text(encoding="utf-8"))
    assert record["transport"] == expected_transport
    assert record["transport"] in TRANSPORTS
    assert record["exec_mode"] == exec_mode
    assert record["tool_name"] == "http_client"

    assert register.executions == 1
    assert register.invocations_recorded == 1
    assert register.verdict == AUDITABLE


@pytest.mark.asyncio
async def test_the_in_process_record_carries_the_request_and_the_envelope(
    recording: tuple[TraceWriter, AuditRegister, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The in-process record answers the same question the docker argv answers.

    On the subprocess transport the argv IS the request. In-process there is no
    argv, so the record carries ``request`` — and ``stdout`` is the tool's own
    envelope, which is what ``parse_output`` consumes live. A record whose stdout
    were the raw HTTP text instead would replay through a parser the live path
    never uses.
    """
    import aiohttp

    _writer, _register, invocations_dir = recording
    monkeypatch.setattr(settings, "tool_exec_mode", "local")
    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)

    tool = HTTPClientTool(scope=_scope())
    await tool._execute_aiohttp(
        {"method": "POST", "url": "http://target.test/probe", "body": "a=1"}
    )

    record = json.loads(sorted(invocations_dir.glob("*.json"))[0].read_text(encoding="utf-8"))
    assert record["request"]["method"] == "POST"
    assert record["request"]["url"] == "http://target.test/probe"
    assert record["request"]["body"] == "a=1"
    # The descriptor is readable and is NOT an argv — nothing may exec it.
    assert record["command"] == ["POST", "http://target.test/probe"]
    # stdout parses through the LIVE consumer, one stage, no curl parse.
    parsed = tool.parse_output(record["stdout"])
    assert parsed.status_code == 200
    assert parsed.response_body == "<html>probe</html>"


@pytest.mark.asyncio
async def test_a_transport_failure_is_recorded_too(
    recording: tuple[TraceWriter, AuditRegister, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A request that failed at the transport still leaves a record.

    "The request was never sent" and "the request was sent and the transport
    died" are the two readings of a missing record, and only one of them is a
    statement about the target.
    """
    import aiohttp

    class _Exploding(_FakeSession):
        def request(self, *args: Any, **kwargs: Any) -> Any:
            raise OSError("connection refused")

    _writer, register, invocations_dir = recording
    monkeypatch.setattr(settings, "tool_exec_mode", "local")
    monkeypatch.setattr(aiohttp, "ClientSession", _Exploding)

    tool = HTTPClientTool(scope=_scope())
    await tool._execute_aiohttp({"method": "GET", "url": "http://target.test/probe"})

    files = sorted(invocations_dir.glob("*.json"))
    assert len(files) == 1
    record = json.loads(files[0].read_text(encoding="utf-8"))
    assert record["exit_code"] == 1
    assert "connection refused" in record["stderr"]
    assert register.verdict == AUDITABLE


# ---------------------------------------------------------------------------
# The run-level verdict
# ---------------------------------------------------------------------------


def test_three_verdicts_not_two() -> None:
    """Nothing dispatched, all recorded, and some unrecorded are three states.

    A single boolean collapses the first two, and "unauditable" then fires on
    every reconnaissance-only run — a permanent false alarm in the section where
    a real one has to be read.
    """
    empty = AuditRegister()
    assert empty.verdict == NOTHING_DISPATCHED
    assert empty.summary()["auditable"] is False

    clean = AuditRegister()
    clean.record_execution(tool="nmap", exec_mode="docker", transport="subprocess", recorded=True)
    assert clean.verdict == AUDITABLE

    holed = AuditRegister()
    holed.record_execution(
        tool="http_client", exec_mode="local", transport="in_process", recorded=True
    )
    holed.record_execution(
        tool="http_client", exec_mode="local", transport="in_process", recorded=False
    )
    assert holed.verdict == INDETERMINATE
    summary = holed.summary()
    assert summary["tool_executions"] == 2
    assert summary["invocations_recorded"] == 1
    assert summary["unrecorded_executions"] == 1
    assert summary["unrecorded_by_tool"] == {"http_client": 1}


def test_an_unauditable_run_is_not_baseline_eligible() -> None:
    """The reconciliation only ever tightens, and it names its own reason."""
    clean_routing = {"provider_degraded": False, "baseline_eligible": True}

    holed = AuditRegister()
    holed.record_execution(
        tool="http_client", exec_mode="local", transport="in_process", recorded=False
    )
    tightened = reconcile_run_audit(clean_routing, holed.summary())
    assert tightened["baseline_eligible"] is False
    assert tightened["run_audit_verdict"] == INDETERMINATE
    assert "cannot be re-derived" in str(tightened["baseline_ineligible_reason"])
    # The input is not mutated — the caller's dict is still the register's half.
    assert clean_routing["baseline_eligible"] is True

    # One-way. A clean audit cannot grant eligibility back to a degraded run.
    degraded = {"provider_degraded": True, "baseline_eligible": False}
    ok = AuditRegister()
    ok.record_execution(tool="nmap", exec_mode="docker", transport="subprocess", recorded=True)
    assert reconcile_run_audit(degraded, ok.summary())["baseline_eligible"] is False

    # A stored bundle written before the measurement existed carries no summary,
    # and gets no invented verdict.
    assert reconcile_run_audit(clean_routing, None) == clean_routing
    assert reconcile_run_audit(clean_routing, {}) == clean_routing


def test_a_record_refuses_an_undeclared_transport(tmp_path: Path) -> None:
    """The vocabulary is closed at the point of construction."""
    from clinkz.observability.invocations import InvocationRecord

    with pytest.raises(ValueError, match="transport must be one of"):
        InvocationRecord(
            seq=0,
            ts="now",
            tool_name="http_client",
            exec_mode="local",
            cwd=str(tmp_path),
            command=["GET", "http://target.test/"],
            transport="podman-exec",
        )


@pytest.mark.asyncio
async def test_the_session_cookie_does_not_survive_into_the_record(
    recording: tuple[TraceWriter, AuditRegister, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new write site is a new disclosure surface, and this one nearly leaked.

    ``redact_structure`` is key-aware, and the keys it acts on are HEADER names.
    A ``{"cookies": {"next-auth.session-token": "…"}}`` dict matches none of them:
    the outer key is not a header name, the inner key is whatever the target named
    its cookie, and a session cookie the target named has no intrinsic shape for
    the string rules to find either. Recorded that way the live session value
    reached ``tool_invocations/*.json`` verbatim — and the disclosure gate looks
    for shapes too, so it could not have caught it.

    Recorded as the ``cookie`` header the wire actually carried, it meets
    ``redact_header_value``: the NAMES survive, because a cookie name is evidence
    about the session, and the VALUES do not.
    """
    import aiohttp

    from clinkz.engagement.secrets import clear_secrets

    clear_secrets()  # nothing registered: the shape rules alone must hold
    _writer, _register, invocations_dir = recording
    monkeypatch.setattr(settings, "tool_exec_mode", "local")
    monkeypatch.setattr(aiohttp, "ClientSession", _FakeSession)

    secret = "s%3AaZ9qLmN2pQ7vX1.8KdE3fGhJkLmNpQrS"
    tool = HTTPClientTool(scope=_scope())
    await tool._execute_aiohttp(
        {
            "method": "GET",
            "url": "http://target.test/probe",
            "cookies": {"next-auth.session-token": secret},
            "headers": {"Authorization": f"Bearer {secret}"},
        }
    )

    written = sorted(invocations_dir.glob("*.json"))[0].read_text(encoding="utf-8")
    assert secret not in written, (
        "the live session value reached the invocation record verbatim. Session "
        "material must be recorded under a header-named key the redaction walker "
        "acts on, not under a dict whose keys the target chose."
    )
    # The cookie NAME survives, because it is evidence about the session.
    assert "next-auth.session-token" in written
    assert "Authorization" in written
