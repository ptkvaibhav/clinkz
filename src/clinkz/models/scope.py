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

from clinkz.models.engagement import AuthorizationRecord, EngagementWindow, SafetyPolicy

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


class _AddressMatch(StrEnum):
    """How a target's address was matched to a scope entry.

    The distinction exists because the port gate is only meaningful within one
    port namespace. A docker published-port match crosses a namespace boundary
    by construction — the host port is 8080 and the container port is 80 — and
    comparing those two numbers is comparing two different things.
    """

    #: No overlap; the target is not this entry.
    NONE = "none"
    #: The two hosts resolve to overlapping addresses. Same namespace.
    RESOLVED = "resolved"
    #: A loopback host:port matched the sibling container publishing that port.
    #: The target's PORT is what identified the container, so it is already
    #: bound and there is nothing left for a number comparison to add.
    PUBLISHED_PORT = "published_port"


class PortGateRule(StrEnum):
    """Whether an entry's declared port is comparable with a dispatch's, and why.

    The port gate has two rules and only one of them is arithmetic, so the
    second one gets a name. It used to be an ``if`` with a two-line comment
    inside :meth:`EngagementScope._equivalent_and_bound`, which is where a rule
    goes to be rediscovered: the next reader sees a branch that skips a check
    and has to reconstruct from scratch why skipping it is not a hole.

    * :attr:`COMPARE` — the two addresses live in one port namespace, so the
      numbers mean the same thing and :meth:`EngagementScope._port_binds`
      decides.
    * :attr:`ALREADY_BOUND_BY_THE_PORT` — the match was made THROUGH a port. A
      loopback dispatch to ``localhost:8080`` matched the scope entry
      ``clinkz-dvwa:80`` because 8080 is the host port that container publishes,
      so the dispatch's port is what identified the container in the first
      place. Comparing 8080 against 80 afterwards compares a host-namespace
      number with a container-namespace one and refuses every docker-mode
      engagement this project runs.

    The distinction is not a docker convenience. It is the general form: a port
    that participated in ESTABLISHING an identity cannot also be evidence
    against it, and the only reason there is one instance of it today is that
    docker publishing is the only namespace crossing this engine resolves.
    """

    #: One namespace. The declared port binds, or refuses.
    COMPARE = "compare"
    #: The target's port already named the entry. Nothing left to compare.
    ALREADY_BOUND_BY_THE_PORT = "already_bound_by_the_port"

    @property
    def reason(self) -> str:
        """Why this rule applies, for a refusal message or an audit."""
        if self is PortGateRule.COMPARE:
            return (
                "the target and the scope entry resolve within one port namespace, so a "
                "port each of them names is a port comparable with the other's"
            )
        return (
            "the dispatch's port is what matched this entry — it named the container "
            "publishing that host port — so the entry's container-side port and the "
            "dispatch's host-side port are numbers from two different namespaces and "
            "comparing them would refuse every docker-published target"
        )


def port_gate_rule(match: _AddressMatch) -> PortGateRule:
    """Which port rule an address match puts a dispatch under.

    Pure, total over :class:`_AddressMatch`, and separate from the code that
    applies it so the decision is testable without constructing a scope, a
    docker network and a resolver.

    Args:
        match: How the target's address matched the entry.

    Returns:
        The rule. :attr:`_AddressMatch.NONE` never reaches here — an entry that
        did not match has no port question — and is mapped to
        :attr:`PortGateRule.COMPARE`, the strict answer, so a future caller that
        reaches it is refused rather than exempted.
    """
    if match is _AddressMatch.PUBLISHED_PORT:
        return PortGateRule.ALREADY_BOUND_BY_THE_PORT
    return PortGateRule.COMPARE


def declared_port(value: str) -> int | None:
    """The port a scope entry EXPLICITLY names, or ``None``.

    "Explicitly" is the whole content of this function. A scheme's default port
    is something *we* infer: ``https://cal.diy`` says nothing about 443, and
    treating it as a declaration would silently bind the record to one port the
    operator never wrote — refusing dispatches an authorization the operator
    believes is host-wide should permit. Only a port present in the string
    counts.

    Args:
        value: A scope entry's ``value`` — a URL, ``host:port``, bare host,
            IP or CIDR.

    Returns:
        The port written in *value*, or ``None`` when it names none.
    """
    text = (value or "").strip()
    if "://" in text:
        try:
            netloc = urlparse(text).netloc
        except ValueError:
            return None
        # rpartition, not split: an IPv6 literal is full of colons and only the
        # one after the closing bracket can be a port.
        host, sep, port = netloc.rpartition(":")
        return int(port) if sep and host and port.isdigit() else None
    if "/" in text:
        # A CIDR block names hosts, never a port.
        return None
    host, sep, port = text.rpartition(":")
    return int(port) if sep and host and port.isdigit() else None


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

    # ---- Engagement setup (productization P1) --------------------------------
    # Optional on the MODEL so every existing programmatic construction (tests,
    # smoke harnesses, the discovery engine's fixtures) keeps working, and
    # REQUIRED at the engagement gate: OrchestratorAgent.run() refuses to start
    # without an authorization record (clinkz.engagement.gate.require_authorization).
    # Making it model-optional-but-run-required is deliberate — the refusal
    # belongs where an engagement actually begins, not where a unit test builds a
    # scope object to check a CIDR match.
    authorization: AuthorizationRecord | None = Field(
        default=None,
        description="Who authorized this engagement. Required to start a run.",
    )
    window: EngagementWindow | None = Field(
        default=None,
        description="Agreed testing window. Outside it the engagement hard-stops.",
    )
    safety: SafetyPolicy = Field(
        default_factory=SafetyPolicy,
        description="Production safety rails (rate, concurrency, blocking response).",
    )
    # Human-readable rules of engagement echoed into the report header — e.g.
    # "no testing during business hours", "do not touch the payment provider".
    # Recorded, never interpreted.
    rules_of_engagement: list[str] = Field(default_factory=list)

    # Gray-box discovery inputs (optional; absent ⇒ black-box, engine inert).
    # ``source_dir`` is the ingestable target source tree the discovery engine
    # reads (§2.2 — a source tree is an engagement input alongside the scope).
    # ``discovery_base_url`` is the app base URL that source-derived routes join
    # onto (e.g. ``http://host:8080/geoserver``); a shared request parser with no
    # source-derived route (Solr) supplies the reflecting handler URL here. When
    # unset the discovery step falls back to the primary target URL.
    source_dir: str | None = Field(
        default=None, description="Gray-box: path to the target source tree to ingest"
    )
    discovery_base_url: str | None = Field(
        default=None, description="Gray-box: app base URL that discovered routes join onto"
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
        and port are extracted and both are checked.

        **A port an entry names BINDS.** ``http://172.20.0.2:3000`` matches a
        scope entry of ``172.20.0.2`` — that entry named no port, so it
        authorizes the host — but it does NOT match an entry of
        ``http://172.20.0.2:8080``. The port used to be stripped and discarded,
        so one entry authorised every one of the 65,535 services on a host, and
        on a lab machine carrying five containers at once that is five targets
        under one record. See :func:`declared_port` for what counts as "named".

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
        if not self._port_allowed(port):
            return False
        return self._matches_any(host, port, self.targets)

    def _port_allowed(self, port: int | None) -> bool:
        """Whether ``allowed_ports`` permits a dispatch to *port*.

        The field documented itself as "Whitelist of ports to test. Empty list
        means all ports allowed." and was read by nothing in the engine — a
        control an operator could write into a scope document, believe, and
        never have applied. An empty list keeps its documented meaning; a
        non-empty one now binds.

        A dispatch naming no port is not bounded here, for the same reason a
        ported entry does not refuse one: a bare host is not a dispatch to a
        port, and refusing it would refuse the port scan whose whole job is to
        find out which ports exist.
        """
        if not self.allowed_ports or port is None:
            return True
        return port in self.allowed_ports

    def refusal_reason(self, target: str) -> str:
        """Why *target* is out of scope, or ``""`` when it is in scope.

        A boolean refusal is unattributable: "outside the engagement scope"
        reads the same for a host nobody authorised and for an authorised host
        reached on a port the record did not name, and those have different
        fixes. The gate that raises quotes this, so the distinction reaches the
        action log rather than dying at the ``if``.

        Args:
            target: IP address, hostname, ``host:port`` or URL.

        Returns:
            A sentence naming what refused it, or ``""``.
        """
        host, port = self._extract_host_port(target)
        if self._matches_any(host, port, self.excluded):
            return f"{host} is on the engagement's excluded list"
        if not self._port_allowed(port):
            return (
                f"port {port} is not among the ports this scope permits "
                f"({sorted(self.allowed_ports)})"
            )
        if self._matches_any(host, port, self.targets):
            return ""
        # The host IS named; it was the port that refused. Say so — this is the
        # case an operator reads as "my scope is wrong" when it is right.
        if port is not None and self._matches_any(host, None, self.targets):
            named = sorted(
                {
                    declared
                    for entry in self.targets
                    if (declared := declared_port(entry.value)) is not None
                    and self._matches_entry(host, None, entry)
                }
            )
            return (
                f"{host} is in scope but this scope names it at port(s) {named}, "
                f"and this dispatch went to port {port}"
            )
        return f"{host} is named by no entry in the engagement scope"

    def addresses_equivalent(self, host_a: str, host_b: str) -> bool:
        """Whether two host/URL strings refer to the same network address.

        The cross-service **co-location oracle** (cross-service design §3/§4): a
        cross-service SSRF finding is emitted only when the confirming callback's
        destination is co-located with service B — i.e. the collaborator's callback
        host and B's in-scope endpoint resolve to the same address. A generic
        collaborator NOT at B fails this check, so its callback proves only "A
        egresses somewhere" (plain SSRF) and the outcome is a research-lead, never a
        cross-service finding. A literal host match short-circuits; otherwise the two
        hosts are resolved (system DNS + docker-network fallback) and compared for
        IP-set overlap. Resolution failure ⇒ ``False`` (not co-located — the honest
        default, never a phantom co-location).

        Args:
            host_a: A host or URL string.
            host_b: A host or URL string.

        Returns:
            ``True`` iff both resolve to (or literally are) the same address.
        """
        a_host, a_port = self._extract_host_port(host_a)
        b_host, b_port = self._extract_host_port(host_b)
        if not a_host or not b_host:
            return False
        if a_host.lower() == b_host.lower():
            return True
        a_addrs = self._resolved_addresses(a_host, a_port)
        b_addrs = self._resolved_addresses(b_host, b_port)
        return bool(a_addrs and b_addrs and (a_addrs & b_addrs))

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
        """Check if target matches a single scope entry — host AND port.

        Tries literal matching first (the cheap, common case) and falls
        through to address equivalence when the literal check fails.
        Equivalence is gated by entry type — it only applies to entries
        that name an addressable host (IP, DOMAIN, URL); CIDR blocks
        keep their original semantics.

        **The port gate applies only where the two are in the same port
        namespace.** That is the literal-match path and the DNS-overlap
        equivalence path. It is deliberately NOT applied when the match came
        from the docker published-port lookup: that lookup *consumed* the
        target's port to identify which sibling container publishes it, so
        ``localhost:8080`` matching an entry of ``clinkz-dvwa:80`` is a port
        already bound — more tightly than a number comparison could bind it,
        and across a namespace boundary where the numbers are not comparable.
        """
        if entry.type == ScopeType.IP:
            # Against the entry's HOST, not its raw value: an IP entry may
            # carry a port (``10.0.0.5:8080``), and comparing the bare target
            # host against the whole string never matches such an entry at all.
            if target == self._extract_host(entry.value):
                return self._port_binds(entry, target_port)
            return self._equivalent_and_bound(target, target_port, entry)

        if entry.type == ScopeType.CIDR:
            # A CIDR names no port and cannot: it authorizes a block of hosts.
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
                return self._port_binds(entry, target_port)
            return self._equivalent_and_bound(target, target_port, entry)

        return False

    @staticmethod
    def _port_binds(entry: ScopeEntry, target_port: int | None) -> bool:
        """Whether *entry*'s declared port permits a dispatch to *target_port*.

        Three cases, and only one of them refuses:

        * **The entry names no port.** It authorizes the host, so every port on
          it is in scope. This is what a bare ``app.acme.com`` or an
          ``https://cal.diy`` means — 443 there is a default *we* inferred, not
          a port the operator typed, and inferring a bound the record does not
          state is the same defect in the other direction.
        * **The entry names a port and the dispatch names none.** A bare
          hostname is not a dispatch *to a port* — it is nmap's ``-p 1-65535``
          against the host, which is how every recon phase starts. The entry's
          port cannot refute it, so the host rule decides.
        * **Both name a port.** They must be equal. This is the refusal:
          an entry of ``http://host:3000`` and a dispatch to ``host:8080``.

        Args:
            entry: The scope entry being matched against.
            target_port: The dispatch's port, or ``None`` for a bare host.

        Returns:
            ``False`` only when both name a port and the two differ.
        """
        entry_port = declared_port(entry.value)
        if entry_port is None or target_port is None:
            return True
        return entry_port == target_port

    def _equivalent_and_bound(
        self,
        target_host: str,
        target_port: int | None,
        entry: ScopeEntry,
    ) -> bool:
        """Address equivalence, with the port gate applied where it is meaningful."""
        match = self._address_match(target_host, target_port, entry)
        if match is _AddressMatch.NONE:
            return False
        if port_gate_rule(match) is PortGateRule.ALREADY_BOUND_BY_THE_PORT:
            return True
        return self._port_binds(entry, target_port)

    # ------------------------------------------------------------------
    # Address equivalence (the load-bearing addition)
    # ------------------------------------------------------------------

    def _address_match(
        self,
        target_host: str,
        target_port: int | None,
        entry: ScopeEntry,
    ) -> _AddressMatch:
        """Decide whether two host strings refer to the same address, and HOW.

        Resolves the target hostname and the entry hostname to IP sets
        (via system DNS, with a docker-network fallback when
        ``TOOL_EXEC_MODE=docker``) and returns True if the sets overlap.
        In docker mode, a loopback target with an explicit port is
        additionally enriched with the address of the sibling container
        that publishes that host port — that's how
        ``localhost:8080`` matches a scope entry of ``clinkz-dvwa:80``.

        Resolution failures (DNS NXDOMAIN, docker not installed) leave
        the candidate IP set empty and the comparison returns
        :attr:`_AddressMatch.NONE`, so unreachable addresses simply stay out of
        scope.

        Returns:
            Which of the two equivalences held, so the caller can decide whether
            the entry's declared port is comparable with the target's. See
            :class:`_AddressMatch`.
        """
        entry_host = self._extract_host(entry.value)
        if not target_host or not entry_host:
            return _AddressMatch.NONE

        # Resolve WITHOUT the docker published-port enrichment first, so the two
        # equivalences stay distinguishable. Folding them together is what would
        # make a namespace-crossing match indistinguishable from a same-namespace
        # one, and the port gate reads exactly that difference.
        plain_target = self._addresses_for(target_host)
        entry_addrs = self._resolved_addresses(entry_host, None)
        if entry_addrs and plain_target and (plain_target & entry_addrs):
            return _AddressMatch.RESOLVED

        target_addrs = self._resolved_addresses(target_host, target_port)
        if entry_addrs and target_addrs and (target_addrs & entry_addrs):
            return _AddressMatch.PUBLISHED_PORT
        return _AddressMatch.NONE

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
