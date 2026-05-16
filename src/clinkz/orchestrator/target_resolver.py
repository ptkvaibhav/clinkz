"""Resolve localhost targets to container-network addresses in docker mode.

When the user runs ``python -m clinkz scan --target http://localhost:8080``
with ``TOOL_EXEC_MODE=docker``, every tool is executed via ``docker exec
clinkz-tools <tool>``. From inside the ``clinkz-tools`` container the
loopback address points at the container itself, not the host port mapping —
so curl, nmap, katana, etc. all fail to reach the actual target (DVWA,
Juice Shop, …) running in a sibling container.

This module bridges that gap. At engagement start the orchestrator calls
:func:`resolve_target_for_docker_mode` with the parsed
:class:`EngagementScope`. The resolver:

1. No-ops in local exec mode.
2. No-ops when no scope target points at localhost/127.0.0.1/0.0.0.0.
3. For each localhost target, runs ``docker ps`` + ``docker inspect`` to
   find a sibling container publishing that host port and rewrites the URL
   to ``<container_name>:<internal_port>``. The container alias is
   resolvable from inside ``clinkz-tools`` over the shared docker network.
4. Records the original→resolved mapping on the trace so reports can keep
   referring to the user-facing address.
5. Raises :class:`TargetResolutionError` when a localhost port has no
   matching container — silent fall-through would just lead to curl
   timeouts deep in the engagement.

Example::

    scope = EngagementScope(
        name="DVWA",
        targets=[ScopeEntry(value="http://localhost:8080", type=ScopeType.DOMAIN)],
    )
    resolved = await resolve_target_for_docker_mode(scope)
    # resolved.targets[0].value == "http://clinkz-dvwa:80"
"""

from __future__ import annotations

import asyncio
import json
import logging
from urllib.parse import urlparse, urlunparse

from clinkz.models.scope import EngagementScope, ScopeEntry
from clinkz.observability.trace import get_active_trace_writer

logger = logging.getLogger(__name__)

# Hostnames that always refer back to the executing container (and never to
# a sibling target). When we see one of these in a scope target we attempt
# docker resolution.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})

# Short timeout for docker CLI metadata queries.
_DOCKER_TIMEOUT = 10.0


class TargetResolutionError(RuntimeError):
    """A localhost target could not be mapped to a sibling container."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


async def resolve_target_for_docker_mode(
    scope: EngagementScope,
    *,
    self_container: str = "clinkz-tools",
) -> EngagementScope:
    """Rewrite localhost scope targets to container-network addresses.

    Returns the scope unchanged when:
    - ``TOOL_EXEC_MODE`` is not ``docker``, or
    - No scope target uses a loopback hostname.

    Otherwise, for each loopback target, looks up a sibling container
    publishing the requested host port and replaces the URL.

    Args:
        scope: Engagement scope as constructed by the CLI / caller.
        self_container: Name of the container clinkz-tools runs in. The
            resolver will refuse to map a port back to this container,
            since that would re-introduce the very loop we're fixing.

    Returns:
        A new ``EngagementScope`` with rewritten targets (or the input
        unchanged when no rewrite is needed).

    Raises:
        TargetResolutionError: If a loopback target has a port that no
            sibling container publishes.
    """
    from clinkz.config import settings

    if settings.tool_exec_mode != "docker":
        return scope

    loopback_entries = [
        (idx, entry) for idx, entry in enumerate(scope.targets) if _is_loopback_target(entry.value)
    ]
    if not loopback_entries:
        return scope

    # Build the port → container map once per engagement.
    port_map = await _build_host_port_map(exclude_container=self_container)

    new_targets: list[ScopeEntry] = list(scope.targets)
    trace_writer = get_active_trace_writer()

    for idx, entry in loopback_entries:
        host_port = _extract_host_port(entry.value)
        if host_port is None:
            raise TargetResolutionError(
                f"Loopback target '{entry.value}' has no port; cannot resolve "
                "to a container. Specify the host port (e.g. http://localhost:8080)."
            )

        mapping = port_map.get(host_port)
        if mapping is None:
            published = sorted(port_map.keys())
            raise TargetResolutionError(
                f"No running container publishes host port {host_port}. "
                f"Currently published host ports: {published or 'none'}. "
                f"Start the target container (e.g. `docker compose -f "
                f"docker/docker-compose.yml up -d`) before running the scan."
            )

        resolved_url = _rewrite_url(entry.value, mapping.container_name, mapping.container_port)
        logger.info(
            "Target resolver: '%s' -> '%s' (container=%s, container_port=%d)",
            entry.value,
            resolved_url,
            mapping.container_name,
            mapping.container_port,
        )

        notes = entry.notes
        original_marker = f"original_target={entry.value}"
        if original_marker not in notes:
            notes = f"{notes} | {original_marker}".strip(" |") if notes else original_marker

        new_targets[idx] = entry.model_copy(update={"value": resolved_url, "notes": notes})

        if trace_writer is not None:
            trace_writer.write(
                stage="orchestrator",
                category="agent_step",
                payload={
                    "step_name": "target_resolution",
                    "original_target": entry.value,
                    "resolved_target": resolved_url,
                    "container": mapping.container_name,
                    "host_port": host_port,
                    "container_port": mapping.container_port,
                },
            )

    return scope.model_copy(update={"targets": new_targets})


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


class _PortMapping:
    """Single host-port → (container, container-port) mapping."""

    __slots__ = ("container_name", "container_port")

    def __init__(self, container_name: str, container_port: int) -> None:
        self.container_name = container_name
        self.container_port = container_port


def _is_loopback_target(value: str) -> bool:
    """Return True if the scope target points at the executing container's loopback."""
    host = _extract_host(value)
    return host.lower() in _LOOPBACK_HOSTS


def _extract_host(value: str) -> str:
    """Pull the hostname out of a URL or ``host:port`` string."""
    if "://" in value:
        parsed = urlparse(value)
        return parsed.hostname or ""
    if ":" in value:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            return host
    return value


def _extract_host_port(value: str) -> int | None:
    """Pull the port out of a URL or ``host:port`` string."""
    if "://" in value:
        parsed = urlparse(value)
        if parsed.port is not None:
            return parsed.port
        if parsed.scheme == "https":
            return 443
        if parsed.scheme == "http":
            return 80
        return None
    if ":" in value:
        _, _, port = value.rpartition(":")
        if port.isdigit():
            return int(port)
    return None


def _rewrite_url(original: str, container_name: str, container_port: int) -> str:
    """Replace the host:port portion of *original* with the container address."""
    if "://" in original:
        parsed = urlparse(original)
        new_netloc = f"{container_name}:{container_port}"
        return urlunparse(parsed._replace(netloc=new_netloc))
    return f"{container_name}:{container_port}"


async def _build_host_port_map(
    *,
    exclude_container: str,
) -> dict[int, _PortMapping]:
    """Inspect every running docker container and return host-port → container mapping.

    Args:
        exclude_container: Container name to skip (the clinkz-tools container
            itself; mapping back to it would defeat the purpose).

    Returns:
        Dict mapping ``host_port`` (int) to a ``_PortMapping``. Containers
        that publish multiple ports contribute multiple entries. When two
        containers race for the same host port (shouldn't happen with
        docker — only one can bind a port at a time) the first one wins.
    """
    names = await _list_running_containers()
    if not names:
        return {}

    port_map: dict[int, _PortMapping] = {}
    for name in names:
        if name == exclude_container:
            continue
        ports = await _inspect_container_ports(name)
        for host_port, container_port in ports:
            if host_port in port_map:
                logger.warning(
                    "Port collision: host port %d already mapped to %s; ignoring %s",
                    host_port,
                    port_map[host_port].container_name,
                    name,
                )
                continue
            port_map[host_port] = _PortMapping(container_name=name, container_port=container_port)

    logger.debug("Target resolver port map: %s", {p: m.container_name for p, m in port_map.items()})
    return port_map


async def _list_running_containers() -> list[str]:
    """Return container names from ``docker ps``."""
    code, stdout, stderr = await _run_docker(
        ["docker", "ps", "--format", "{{.Names}}"],
    )
    if code != 0:
        logger.warning("docker ps failed (exit %d): %s", code, stderr.strip())
        return []
    return [line.strip() for line in stdout.splitlines() if line.strip()]


async def _inspect_container_ports(container_name: str) -> list[tuple[int, int]]:
    """Return ``(host_port, container_port)`` tuples for *container_name*.

    Reads ``.NetworkSettings.Ports`` from ``docker inspect``. Skips any port
    binding that has no host port (i.e. ``EXPOSE``-only ports).
    """
    code, stdout, stderr = await _run_docker(
        [
            "docker",
            "inspect",
            container_name,
            "--format",
            "{{json .NetworkSettings.Ports}}",
        ],
    )
    if code != 0:
        logger.warning(
            "docker inspect %s failed (exit %d): %s",
            container_name,
            code,
            stderr.strip(),
        )
        return []

    try:
        raw = json.loads(stdout.strip() or "null")
    except json.JSONDecodeError as exc:
        logger.warning("docker inspect %s returned non-JSON: %s", container_name, exc)
        return []

    if not isinstance(raw, dict):
        return []

    pairs: list[tuple[int, int]] = []
    for container_port_spec, host_bindings in raw.items():
        if not host_bindings:
            continue
        # container_port_spec looks like "80/tcp" or "443/udp"; we only care
        # about the numeric port. Mixed protocols on the same numeric port
        # are fine — both ultimately go through the same container alias.
        proto_port = container_port_spec.split("/", 1)[0]
        if not proto_port.isdigit():
            continue
        container_port = int(proto_port)
        for binding in host_bindings:
            if not isinstance(binding, dict):
                continue
            host_port_str = binding.get("HostPort", "")
            if not host_port_str or not host_port_str.isdigit():
                continue
            pairs.append((int(host_port_str), container_port))
    return pairs


async def _run_docker(cmd: list[str]) -> tuple[int, str, str]:
    """Run a docker CLI subprocess with a short timeout.

    Returns ``(exit_code, stdout, stderr)``. Exit code 127 indicates the
    docker binary is missing from PATH.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        return 127, "", str(exc)

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=_DOCKER_TIMEOUT
        )
    except TimeoutError:
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass
        return 124, "", f"timed out after {_DOCKER_TIMEOUT:.0f}s"

    return (
        proc.returncode or 0,
        stdout_bytes.decode("utf-8", errors="replace"),
        stderr_bytes.decode("utf-8", errors="replace"),
    )
