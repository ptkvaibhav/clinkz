"""Regression test: the orchestrator's default-cred path actually fires WebAuthenticator.

The existing ``test_scan_to_exploit_flow.py`` exercises the
``cookies → katana → endpoints`` half of the pipeline by feeding pre-fetched
cookies straight into ``ScanAgent.run()``. That bypass hid a real defect for a
full quarter: ``WebAuthenticator`` was gating its docker-mode curl path on
``_is_docker_internal(url)`` — a hostname classifier that only recognized
literal IP addresses. Once ``target_resolver`` rewrote ``localhost:8080`` to
the container alias ``clinkz-dvwa:80`` the gate evaluated false, so every auth
attempt silently fell back to host-side aiohttp, which couldn't resolve
``clinkz-dvwa`` and threw — caught and swallowed inside ``authenticate()``.

This test routes through ``OrchestratorAgent._try_default_credentials`` —
the full orchestrator code path — and asserts:

1. ``WebAuthenticator`` issues a real HTTP request (a successful login).
2. The credential store ends up with at least one valid DVWA credential.
3. A session row is written with non-empty cookies.

If any of these fail, the regression is back.

Run::

    pytest -m integration tests/test_integration/test_orchestrator_auth_wire.py -v -s
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any

import pytest

from clinkz.config import settings
from clinkz.credentials.store import CredentialStore
from clinkz.llm.base import AgentAction, LLMClient, LLMMessage
from clinkz.models.recon import (
    PortScanResult,
    ReconResult,
    ReconService,
    ServiceScanResult,
    Technology,
    TechStack,
    WebReconResult,
)
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.observability.trace import TraceWriter, set_active_trace_writer
from clinkz.orchestrator.orchestrator import OrchestratorAgent
from clinkz.state import StateStore

DVWA_HOST = "localhost"
DVWA_PORT = 8080
DVWA_URL = f"http://{DVWA_HOST}:{DVWA_PORT}"


# ---------------------------------------------------------------------------
# Prereq probes
# ---------------------------------------------------------------------------


def _dvwa_reachable() -> bool:
    try:
        with socket.create_connection((DVWA_HOST, DVWA_PORT), timeout=3):
            return True
    except OSError:
        return False


def _tools_container_running() -> bool:
    """Check whether clinkz-tools is up and can reach the sibling DVWA alias."""
    if shutil.which("docker") is None:
        return False
    try:
        ping = subprocess.run(
            ["docker", "exec", settings.docker_container, "true"],
            capture_output=True,
            timeout=5,
        )
        if ping.returncode != 0:
            return False
        probe = subprocess.run(
            [
                "docker",
                "exec",
                settings.docker_container,
                "curl",
                "-s",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "http://clinkz-dvwa/login.php",
            ],
            capture_output=True,
            timeout=10,
        )
        return probe.returncode == 0 and probe.stdout.decode().strip() == "200"
    except (subprocess.SubprocessError, OSError):
        return False


class _NullLLM(LLMClient):
    """LLM stub for the orchestrator — never called by ``_try_default_credentials``."""

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> AgentAction:
        return AgentAction(thought="(stub)", final_answer="(stub)")

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str, **_kw: object) -> str:
        return ""


def _make_dvwa_recon(target: str) -> dict[str, object]:
    """Synthetic recon result that names DVWA — what the real recon agent emits."""
    return ReconResult(
        target=target,
        ports=PortScanResult(open_ports=[80], tool_used="synthetic"),
        services=ServiceScanResult(
            services=[ReconService(port=80, protocol="tcp", service_name="http")],
            tool_used="synthetic",
        ),
        web_info=WebReconResult(),
        tech_stack=TechStack(
            technologies=[
                Technology(name="apache", version="2.4.25", category="web_server"),
                Technology(name="php", category="language"),
                Technology(name="dvwa", version="1.10", category="application"),
            ]
        ),
        llm_summary="DVWA on Apache+PHP — synthetic recon for auth-wire test.",
    ).model_dump(mode="json")


# ---------------------------------------------------------------------------
# The regression
# ---------------------------------------------------------------------------


@pytest.mark.integration
@pytest.mark.asyncio
async def test_orchestrator_default_creds_actually_authenticate_dvwa(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_try_default_credentials`` must produce a valid DVWA session.

    Drives the exact orchestrator code path that handles default
    credential testing — the same path ``orchestrator.run()`` takes
    between Recon and the concurrent phase. Skips when DVWA isn't
    reachable or when running outside the tools-container environment.
    """
    if not _dvwa_reachable():
        pytest.skip(f"DVWA not reachable at {DVWA_URL}")

    # Prefer docker mode (matches /run-dvwa). Fall back to local mode if the
    # tools container isn't up — local mode still hits the same orchestrator
    # code path, just with aiohttp instead of curl-in-container.
    if _tools_container_running():
        monkeypatch.setenv("TOOL_EXEC_MODE", "docker")
        monkeypatch.setattr(settings, "tool_exec_mode", "docker")
        target_url = "http://clinkz-dvwa:80"
    else:
        monkeypatch.setenv("TOOL_EXEC_MODE", "local")
        monkeypatch.setattr(settings, "tool_exec_mode", "local")
        target_url = DVWA_URL

    trace_writer = TraceWriter(
        engagement_id="orch-auth-wire-test",
        outputs_root=tmp_path / "outputs",
    )
    set_active_trace_writer(trace_writer)

    try:
        db_path = tmp_path / "auth_wire.db"
        async with StateStore(db_path) as state:
            engagement_id = await state.create_engagement(
                "orch-auth-wire-test", {"name": "auth-wire"}
            )
            cred_store = CredentialStore(state)
            await cred_store.initialize()

            scope = EngagementScope(
                name="orch-auth-wire-test",
                targets=[ScopeEntry(value=target_url, type=ScopeType.URL)],
            )

            orchestrator = OrchestratorAgent(llm=_NullLLM(), db_path=db_path)
            # Wire in the bits ``run()`` would normally set up before the
            # _try_default_credentials call site. We only need state/scope/
            # cred_store/engagement_id — no bus, no LLM, no lifecycle.
            orchestrator._state = state
            orchestrator._scope = scope
            orchestrator._engagement_id = engagement_id
            orchestrator._cred_store = cred_store

            recon_result = {"result": _make_dvwa_recon(target_url)}
            await orchestrator._try_default_credentials(recon_result)

            valid = await cred_store.get_all_valid(engagement_id)
            sessions = await state.get_sessions(engagement_id)
    finally:
        set_active_trace_writer(None)
        trace_writer.close()

    # ----- Assertions: the auth wire must be alive -----
    assert valid, (
        "No valid credentials after _try_default_credentials. "
        "WebAuthenticator never produced a successful login — the "
        "default-cred wire is broken. "
        f"Trace at {trace_writer.path}"
    )
    assert any(c.username == "admin" and c.password == "password" for c in valid), (
        f"Expected admin:password to validate against DVWA, got {[c.username for c in valid]}"
    )
    assert sessions, "No session row written despite valid credentials"
    assert any(s.get("cookies") for s in sessions), (
        f"Session row exists but cookies are empty: {sessions}"
    )
    # Specifically the DVWA session cookie — proves we talked to the real
    # app, not just a 200-returning placeholder.
    any_phpsessid = any("PHPSESSID" in (s.get("cookies") or {}) for s in sessions)
    assert any_phpsessid, (
        f"Expected PHPSESSID in at least one session, got: "
        f"{[list((s.get('cookies') or {}).keys()) for s in sessions]}"
    )
