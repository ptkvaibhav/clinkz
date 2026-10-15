"""No test in this package waits on a name resolver (register R5).

The login-discovery tests drive ``OrchestratorAgent._find_login_url`` against a
scope of ``http://app:3000``, and the readers it calls — ``_linked_urls`` and
``_script_path_literals`` — send a real GET through ``HTTPClientTool`` with a
ten-second timeout. ``app`` is a single-label name. On a resolver that fails it
fast (this container, CI) the read fails in milliseconds; on one that walks a
search suffix, asks LLMNR/NetBIOS, or answers NXDOMAIN with an address and
lets the connect hang, every read waits out its timeout. The suite took 5.5
minutes on Linux and 17-22 on Windows for that reason, and a gate that slow is
a gate that gets skipped.

So resolution is stubbed here to the outcome the fast resolver already gives:
an immediate ``gaierror``. Behaviour is unchanged — every one of those reads
already failed — only the wait is gone. IP literals and ``localhost`` still
resolve, so a test that stands up a loopback server is unaffected.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterator
from typing import Any

import pytest

from clinkz.models import scope as scope_module

#: Names a test may legitimately resolve: the loopback server a test owns.
_LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain"})


def _is_local(host: object) -> bool:
    if host is None:
        return True
    text = host.decode() if isinstance(host, bytes) else str(host)
    if text.lower() in _LOCAL_NAMES:
        return True
    try:
        ipaddress.ip_address(text.strip("[]"))
    except ValueError:
        return False
    return True


@pytest.fixture(autouse=True)
def _no_name_resolution(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail every non-local name lookup at once, the way a fast resolver does."""
    real_getaddrinfo = socket.getaddrinfo
    real_gethostbyname = socket.gethostbyname
    real_gethostbyname_ex = socket.gethostbyname_ex

    def unresolvable(host: object) -> socket.gaierror:
        return socket.gaierror(socket.EAI_NONAME, f"name resolution stubbed in tests: {host!r}")

    def getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        if _is_local(host):
            return real_getaddrinfo(host, *args, **kwargs)
        raise unresolvable(host)

    def gethostbyname(host: str) -> str:
        if _is_local(host):
            return real_gethostbyname(host)
        raise unresolvable(host)

    def gethostbyname_ex(host: str) -> tuple[str, list[str], list[str]]:
        if _is_local(host):
            return real_gethostbyname_ex(host)
        raise unresolvable(host)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", gethostbyname_ex)
    # The docker-network fallback is a ``docker exec … getent`` subprocess with
    # a five-second timeout — the same wait by a different road.
    monkeypatch.setattr(scope_module, "_resolve_via_docker", lambda host, *, container: set())
    monkeypatch.setattr(scope_module, "_resolve_docker_port_container", lambda port: None)
    yield
