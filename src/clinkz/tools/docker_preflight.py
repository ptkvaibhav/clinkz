"""Docker pre-flight checks for container-first tool execution.

Clinkz defaults to running all security tools inside the ``clinkz-tools``
Docker container so that the resolver never picks up unrelated host binaries
that happen to share a name (the canonical footgun: the Python ``httpx``
library CLI being mistaken for ProjectDiscovery's ``httpx``).

Before any engagement starts, :func:`ensure_container_ready` verifies that:

1. Docker is installed and the daemon is reachable.
2. The target container exists (attempting to build/start it via
   ``docker compose`` when it does not).
3. The container is running (starting it if stopped).
4. A canary tool (``nmap``) is reachable inside the container.

Any failure raises :class:`ClinkzDockerError` with an actionable message.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ClinkzDockerError(RuntimeError):
    """Docker infrastructure is not ready for Clinkz execution."""


# Short timeout for every docker CLI invocation — these are metadata checks,
# not long-running operations.
_DOCKER_CMD_TIMEOUT = 15.0

# Longer timeout for ``docker compose up`` which may need to build images.
_COMPOSE_TIMEOUT = 600.0

_CANARY_TOOL = "nmap"
_CANARY_RETRIES = 10
_CANARY_BACKOFF = 0.5


async def _run(
    cmd: list[str],
    *,
    timeout: float = _DOCKER_CMD_TIMEOUT,
) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr).

    Uses asyncio to stay compatible with the orchestrator's event loop.
    Output is decoded as UTF-8 with ``errors="replace"`` so odd bytes on
    Windows consoles don't crash the pre-flight.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        # ``docker`` itself isn't on PATH.
        return 127, "", str(exc)

    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return 124, "", f"timed out after {timeout:.0f}s"

    return (
        proc.returncode or 0,
        stdout.decode("utf-8", errors="replace"),
        stderr.decode("utf-8", errors="replace"),
    )


def _repo_root() -> Path:
    """Return the repository root (the parent of ``src/clinkz/tools``)."""
    return Path(__file__).resolve().parents[3]


def _compose_file() -> Path:
    """Path to the docker-compose file that defines the tools container."""
    return _repo_root() / "docker" / "docker-compose.yml"


async def _docker_info() -> tuple[int, str, str]:
    return await _run(["docker", "info"])


async def _container_exists(name: str) -> tuple[bool, str]:
    code, _out, err = await _run(["docker", "inspect", name])
    return code == 0, err


async def _container_running(name: str) -> tuple[bool, str]:
    code, out, err = await _run(["docker", "inspect", "-f", "{{.State.Running}}", name])
    if code != 0:
        return False, err or out
    return out.strip().lower() == "true", ""


async def _start_container(name: str) -> tuple[int, str, str]:
    return await _run(["docker", "start", name])


async def _compose_up_tools() -> tuple[int, str, str]:
    compose_file = _compose_file()
    if not compose_file.exists():
        return 1, "", f"docker-compose file not found at {compose_file}"
    return await _run(
        [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "-d",
            "tools",
        ],
        timeout=_COMPOSE_TIMEOUT,
    )


async def _canary_reachable(name: str) -> tuple[bool, str]:
    """Check a canary tool is resolvable inside the container."""
    last_err = ""
    for attempt in range(1, _CANARY_RETRIES + 1):
        code, _out, err = await _run(["docker", "exec", name, "which", _CANARY_TOOL])
        if code == 0:
            return True, ""
        last_err = err or f"exit code {code}"
        logger.debug(
            "Preflight: canary '%s' not yet reachable in %s (attempt %d/%d): %s",
            _CANARY_TOOL,
            name,
            attempt,
            _CANARY_RETRIES,
            last_err.strip(),
        )
        if attempt < _CANARY_RETRIES:
            await asyncio.sleep(_CANARY_BACKOFF)
    return False, last_err


async def ensure_container_ready(container_name: str = "clinkz-tools") -> None:
    """Ensure the Clinkz tools container is running and its tools are reachable.

    Raises:
        ClinkzDockerError: When Docker is missing, the container cannot be
            started, or the canary tool cannot be resolved inside it.
    """
    # --- 1. Docker itself ---
    code, _out, err = await _docker_info()
    if code != 0:
        raise ClinkzDockerError(
            "Docker not installed or daemon not running. Install Docker "
            "Desktop and start it before running Clinkz.\n"
            f"  docker info exit code: {code}\n"
            f"  stderr: {err.strip() or '(empty)'}"
        )
    logger.info("Preflight: docker daemon reachable")

    # --- 2. Container exists? ---
    exists, inspect_err = await _container_exists(container_name)
    if not exists:
        logger.info(
            "Preflight: container '%s' not found — attempting docker compose up",
            container_name,
        )
        code, out, err = await _compose_up_tools()
        if code != 0:
            raise ClinkzDockerError(
                f"Docker container '{container_name}' does not exist and "
                "docker compose failed to create it.\n"
                f"  compose exit code: {code}\n"
                f"  stderr: {err.strip() or out.strip() or '(empty)'}\n"
                "  Try running manually: docker compose -f "
                f"{_compose_file()} up -d tools"
            )
        # Re-check existence after compose
        exists, inspect_err = await _container_exists(container_name)
        if not exists:
            raise ClinkzDockerError(
                f"docker compose reported success but container "
                f"'{container_name}' still does not exist.\n"
                f"  stderr: {inspect_err.strip() or '(empty)'}"
            )
        logger.info("Preflight: container '%s' created", container_name)
    else:
        logger.info("Preflight: container '%s' exists", container_name)

    # --- 3. Container running? ---
    running, run_err = await _container_running(container_name)
    if not running:
        logger.info("Preflight: container '%s' is stopped — starting", container_name)
        code, _out, err = await _start_container(container_name)
        if code != 0:
            raise ClinkzDockerError(
                f"Failed to start container '{container_name}'.\n"
                f"  docker start exit code: {code}\n"
                f"  stderr: {err.strip() or run_err.strip() or '(empty)'}"
            )
        logger.info("Preflight: container '%s' started", container_name)
    else:
        logger.info("Preflight: container '%s' is already running", container_name)

    # --- 4. Canary tool reachable? ---
    ok, err = await _canary_reachable(container_name)
    if not ok:
        raise ClinkzDockerError(
            f"Container '{container_name}' is running but tools aren't "
            "reachable — the image may be corrupt. Rebuild with "
            "`docker compose -f docker/docker-compose.yml build tools`.\n"
            f"  last error: {err.strip() or '(empty)'}"
        )
    logger.info(
        "Preflight: canary tool '%s' reachable inside '%s'",
        _CANARY_TOOL,
        container_name,
    )
