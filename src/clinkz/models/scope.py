"""Scope and engagement configuration models.

The EngagementScope defines exactly what is permitted to test.
Every tool wrapper calls scope.contains(target) before running.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess  # noqa: S404 — used with list-form, no shell=True
from enum import StrEnum
from urllib.parse import urlparse

from pydantic import BaseModel, Field, PrivateAttr, field_validator

logger = logging.getLogger(__name__)


# Hostnames that always refer to the local container's loopback. Used by the
# docker-mode equivalence path to look up which sibling container publishes
# the matching host port.
_LOOPBACK_HOSTS: frozenset[str] = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})

# Sanity gate on values fed to subprocess (docker exec, getent). The hostnames
# we resolve come from already-parsed URLs, but keep an explicit allowlist so a
# regression in upstream parsing cannot smuggle metacharacters into a command.
_HOSTNAME_SAFE = re.compile(r"^[A-Za-z0-9_\-.:]+$")

# Bounded timeout for the synchronous docker/getent lookups. Cached after the
# first call per hostname/port on each EngagementScope, so the cost is paid
# once per engagement.
_RESOLVE_TIMEOUT = 5.0


class ScopeType(StrEnum):
    """Classification of a scope entry."""

    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"


class ScopeEntry(BaseModel):
    """A single in-scope (or out-of-scope) target."""

    value: str = Field(description="IP, CIDR block, domain, or URL")
    type: ScopeType
    notes: str = Field(default="", description="Optional context for this entry")

    @field_validator("value")
    @classmethod
    def strip_whitespace(cls, v: str) -> str:
        return v.strip()


class EngagementScope(BaseModel):
    """Full scope definition for a pentest engagement.

    Loaded from a JSON file passed via --scope on the CLI,
    or constructed programmatically for testing.

    Example scope.json::

        {
            "name": "ACME Corp Q1 2025",
            "targets": [
                {"value": "10.10.10.0/24", "type": "cidr"},
                {"value": "app.acme.com",  "type": "domain"}
            ],
            "excluded": [
                {"value": "10.10.10.1", "type": "ip", "notes": "Production gateway — no touch"}
            ]
        }
    """

    name: str = Field(description="Human-readable engagement name")
    description: str = Field(default="")
    targets: list[ScopeEntry] = Field(description="In-scope targets")
    excluded: list[ScopeEntry] = Field(
        default_factory=list,
        description="Explicitly excluded targets (takes precedence over targets)",
    )
    max_rate: int = Field(default=100, description="Max requests per second across all tools")
    allowed_ports: list[int] = Field(
        default_factory=list,
        description="Whitelist of ports to test. Empty list means all ports allowed.",
    )

    # Engagement-scoped DNS caches. Resolution happens once per hostname / port,
    # then every subsequent contains() call is dict lookups. PrivateAttrs are
    # excluded from serialization and recreated fresh on model_copy() — both
    # are intentional (a copied scope gets a fresh cache).
    _addr_cache: dict[str, frozenset[str]] = PrivateAttr(default_factory=dict)
    _port_container_cache: dict[int, str | None] = PrivateAttr(default_factory=dict)

    def contains(self, target: str) -> bool:
        """Check if a target IP, domain, or URL is within scope.

        If *target* looks like a URL (has a ``://`` scheme), the hostname
        is extracted and checked instead.  Port numbers are stripped so
        that ``http://172.20.0.2:3000`` correctly matches a scope entry
        of ``172.20.0.2``.

        When the literal hostname does not match a scope entry, the
        check falls through to address equivalence: two targets are
        equivalent when their hostnames resolve to overlapping IPs (or,
        in docker mode, when a loopback host:port maps to the same
        sibling container as a scope entry's hostname).

        Checks exclusions first (exclusions take precedence).

        Args:
            target: IP address, hostname, or URL to check.

        Returns:
            True if target is in scope and not excluded.
        """
        host, port = self._extract_host_port(target)
        if self._matches_any(host, port, self.excluded):
            return False
        return self._matches_any(host, port, self.targets)

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract the bare hostname/IP from a target string.

        Handles URLs (``http://1.2.3.4:8080/path``) and ``host:port``
        notation.  Returns the input unchanged if it is already a bare
        hostname or IP.
        """
        host, _ = EngagementScope._extract_host_port(target)
        return host

    @staticmethod
    def _extract_host_port(target: str) -> tuple[str, int | None]:
        """Return ``(host, port)`` extracted from a URL or ``host:port`` string.

        ``port`` is the explicit port if any. URL schemes contribute their
        default port (``http`` → 80, ``https`` → 443) so the equivalence
        check can compare against a published container port. Bare
        hostnames return ``(host, None)``.
        """
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port
            if port is None:
                if parsed.scheme == "http":
                    port = 80
                elif parsed.scheme == "https":
                    port = 443
            return host, port
        if ":" in target:
            host, _, port_str = target.rpartition(":")
            if port_str.isdigit():
                return host, int(port_str)
        return target, None

    def _matches_any(
        self,
        target: str,
        target_port: int | None,
        entries: list[ScopeEntry],
    ) -> bool:
        """Return True if target matches any entry in the list."""
        for entry in entries:
            if self._matches_entry(target, target_port, entry):
                return True
        return False

    def _matches_entry(
        self,
        target: str,
        target_port: int | None,
        entry: ScopeEntry,
    ) -> bool:
        """Check if target matches a single scope entry.

        Tries literal matching first (the cheap, common case) and falls
        through to address equivalence when the literal check fails.
        Equivalence is gated by entry type — it only applies to entries
        that name an addressable host (IP, DOMAIN, URL); CIDR blocks
        keep their original semantics.
        """
        if entry.type == ScopeType.IP:
            if target == entry.value:
                return True
            return self._addresses_equivalent(target, target_port, entry)

        if entry.type == ScopeType.CIDR:
            try:
                network = ipaddress.ip_network(entry.value, strict=False)
                addr = ipaddress.ip_address(target)
                return addr in network
            except ValueError:
                return False

        if entry.type in (ScopeType.DOMAIN, ScopeType.URL):
            # Normalize the entry value the same way we normalize the target
            entry_host = self._extract_host(entry.value)
            # Simple suffix match — handles subdomains
            if target == entry_host or target.endswith(f".{entry_host}"):
                return True
            return self._addresses_equivalent(target, target_port, entry)

        return False

    # ------------------------------------------------------------------
    # Address equivalence (the load-bearing addition)
    # ------------------------------------------------------------------

    def _addresses_equivalent(
        self,
        target_host: str,
        target_port: int | None,
        entry: ScopeEntry,
    ) -> bool:
        """Decide whether two host strings refer to the same address.

        Resolves the target hostname and the entry hostname to IP sets
        (via system DNS, with a docker-network fallback when
        ``TOOL_EXEC_MODE=docker``) and returns True if the sets overlap.
        In docker mode, a loopback target with an explicit port is
        additionally enriched with the address of the sibling container
        that publishes that host port — that's how
        ``localhost:8080`` matches a scope entry of ``clinkz-dvwa:80``.

        Resolution failures (DNS NXDOMAIN, docker not installed) leave
        the candidate IP set empty and the comparison returns False, so
        unreachable addresses simply stay out of scope.
        """
        entry_host = self._extract_host(entry.value)
        if not target_host or not entry_host:
            return False

        target_addrs = self._resolved_addresses(target_host, target_port)
        entry_addrs = self._resolved_addresses(entry_host, None)

        if not target_addrs or not entry_addrs:
            return False
        return bool(target_addrs & entry_addrs)

    def _resolved_addresses(self, host: str, port: int | None) -> frozenset[str]:
        """Return the set of IPv4 addresses *host* may resolve to.

        Combines system DNS, the docker-network DNS (in docker mode),
        and — when *host* is a loopback name with a known *port* in
        docker mode — the address of the sibling container that
        publishes that host port.
        """
        addrs: set[str] = set(self._addresses_for(host))
        if port is not None and host.lower() in _LOOPBACK_HOSTS:
            from clinkz.config import settings as _settings

            if _settings.tool_exec_mode == "docker":
                container = self._container_for_port(port)
                if container:
                    addrs.update(self._addresses_for(container))
        return frozenset(addrs)

    def _addresses_for(self, host: str) -> frozenset[str]:
        """Cached resolution of *host* to its IPv4 address set."""
        if host in self._addr_cache:
            return self._addr_cache[host]
        result = _resolve_host_addresses(host)
        self._addr_cache[host] = result
        return result

    def _container_for_port(self, port: int) -> str | None:
        """Cached docker lookup: which sibling container publishes *port*?"""
        if port in self._port_container_cache:
            return self._port_container_cache[port]
        result = _resolve_docker_port_container(port)
        self._port_container_cache[port] = result
        return result


# ---------------------------------------------------------------------------
# Module-level resolution helpers — pure functions, no scope state.
# Tests monkeypatch these to avoid hitting the network or docker.
# ---------------------------------------------------------------------------


def _resolve_host_addresses(host: str) -> frozenset[str]:
    """Resolve *host* to a set of IPv4 addresses.

    Tries (in order):
      1. If *host* is already an IP literal, return ``{host}``.
      2. System DNS via ``socket.gethostbyname_ex``.
      3. Docker-network DNS (``docker exec clinkz-tools getent hosts``)
         when ``TOOL_EXEC_MODE=docker`` — this is how single-label
         container aliases like ``clinkz-dvwa`` resolve.

    Returns an empty set when every resolver fails. Never raises.
    """
    if not host or not _HOSTNAME_SAFE.match(host):
        return frozenset()

    try:
        ipaddress.ip_address(host)
        return frozenset({host})
    except ValueError:
        pass

    addrs: set[str] = set()

    try:
        _, _, system_addrs = socket.gethostbyname_ex(host)
        addrs.update(system_addrs)
    except (OSError, UnicodeError):
        # gethostbyname raises herror/gaierror (both subclass OSError) on
        # NXDOMAIN; UnicodeError covers non-IDN names that fail encoding.
        pass

    from clinkz.config import settings as _settings

    if _settings.tool_exec_mode == "docker":
        addrs.update(_resolve_via_docker(host, container=_settings.docker_container))

    return frozenset(addrs)


def _resolve_via_docker(host: str, *, container: str) -> set[str]:
    """Resolve *host* via ``getent hosts`` inside *container*.

    Sync ``subprocess.run`` with a tight timeout. Returns an empty set on
    any failure (docker missing, container down, NXDOMAIN, timeout) —
    callers fall back to whatever the system resolver returned.
    """
    if not _HOSTNAME_SAFE.match(host) or not _HOSTNAME_SAFE.match(container):
        return set()

    try:
        result = subprocess.run(  # noqa: S603 — list-form, validated args
            ["docker", "exec", container, "getent", "hosts", host],
            capture_output=True,
            text=True,
            timeout=_RESOLVE_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return set()

    if result.returncode != 0:
        return set()

    out: set[str] = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if not parts:
            continue
        try:
            ipaddress.ip_address(parts[0])
        except ValueError:
            continue
        out.add(parts[0])
    return out


def _resolve_docker_port_container(host_port: int) -> str | None:
    """Find which running container publishes *host_port*.

    Returns the container name (suitable for feeding back into
    ``_resolve_host_addresses``) or None when no container publishes the
    port. Sync, bounded by ``_RESOLVE_TIMEOUT``.
    """
    if host_port < 1 or host_port > 65535:
        return None
    try:
        ps = subprocess.run(  # noqa: S603 — list-form, no shell
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=_RESOLVE_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    if ps.returncode != 0:
        return None

    from clinkz.config import settings as _settings

    self_container = _settings.docker_container

    for raw_name in ps.stdout.splitlines():
        name = raw_name.strip()
        if not name or name == self_container or not _HOSTNAME_SAFE.match(name):
            continue
        try:
            inspect = subprocess.run(  # noqa: S603
                [
                    "docker",
                    "inspect",
                    name,
                    "--format",
                    "{{json .NetworkSettings.Ports}}",
                ],
                capture_output=True,
                text=True,
                timeout=_RESOLVE_TIMEOUT,
                check=False,
            )
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            continue
        if inspect.returncode != 0:
            continue
        if _container_publishes_port(inspect.stdout, host_port):
            return name
    return None


def _container_publishes_port(inspect_json: str, host_port: int) -> bool:
    """Return True when *inspect_json* contains a binding for *host_port*."""
    import json

    try:
        raw = json.loads(inspect_json.strip() or "null")
    except json.JSONDecodeError:
        return False
    if not isinstance(raw, dict):
        return False
    for bindings in raw.values():
        if not bindings:
            continue
        for binding in bindings:
            if not isinstance(binding, dict):
                continue
            hp = binding.get("HostPort", "")
            if hp.isdigit() and int(hp) == host_port:
                return True
    return False
