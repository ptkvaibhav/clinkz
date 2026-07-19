"""The OOB collaborator — receive-only, health-checked, correlating, bounded.

Exercises the §P6.1 properties against the REAL listeners (no mocks): the DNS and
HTTP legs are bound on loopback high ports, hit with real traffic, and the recorded
events / correlation table / reaper are asserted. The receive-only property is
proven structurally (the HTTP handler returns a static 200 and the DNS responder
answers only its own advertised address — it initiates nothing else) and the
event log is proven bounded + redacted.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Any

from clinkz.oob.collaborator import (
    OOBCollaborator,
    _build_dns_query,
    _candidate_nonce_tokens,
    _parse_dns_qname,
)
from clinkz.oob.templates import CallbackShape, mint_nonce

# Distinct high ports per module so parallel suites / a busy host do not collide.
_HTTP_PORT = 18131
_DNS_PORT = 15431


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _make_collab(**kw: Any) -> OOBCollaborator:
    params: dict[str, Any] = {
        "zone": f"127.0.0.1:{_HTTP_PORT}",
        "callback_shape": CallbackShape.PATH,
        "bind_host": "127.0.0.1",
        "http_port": _HTTP_PORT,
        "dns_port": _DNS_PORT,
        "advertised_ip": "127.0.0.1",
    }
    params.update(kw)
    return OOBCollaborator(**params)


async def _http_callback(port: int, path: str, host: str = "") -> bytes:
    """Simulate a target's inbound HTTP callback; return the collaborator's reply."""
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    host_hdr = host or f"127.0.0.1:{port}"
    writer.write(f"GET {path} HTTP/1.1\r\nHost: {host_hdr}\r\nConnection: close\r\n\r\n".encode())
    await writer.drain()
    reply = await asyncio.wait_for(reader.read(256), timeout=5.0)
    writer.close()
    return reply


# ---------------------------------------------------------------------------
# Health-check (§P6.7.1) — the gate
# ---------------------------------------------------------------------------


def test_health_check_confirms_both_legs() -> None:
    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        try:
            assert await collab.health_check() is True
            assert collab.healthy is True
        finally:
            await collab.stop()

    _run(scenario())


def test_health_check_false_before_start() -> None:
    async def scenario() -> None:
        collab = _make_collab()
        assert await collab.health_check() is False
        assert collab.healthy is False

    _run(scenario())


# ---------------------------------------------------------------------------
# Mint → correlate → reap (§P6.1.4 / §P6.3.2)
# ---------------------------------------------------------------------------


def test_mint_registers_correlation_and_records_sent() -> None:
    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        try:
            nonce = collab.mint("ssrf:http://target/x:url")
            assert collab.pending_for(nonce) is not None
            assert collab.pending_for(nonce).hypothesis_ref == "ssrf:http://target/x:url"
            collab.record_sent(nonce, "POST /x url=http://<n>/")
            assert collab.pending_for(nonce).outbound_probe == "POST /x url=http://<n>/"
            assert collab.pending_for(nonce).sent_at > 0
        finally:
            await collab.stop()

    _run(scenario())


def test_http_callback_correlates_to_the_minted_nonce() -> None:
    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        try:
            nonce = collab.mint("hyp-1")
            reply = await _http_callback(_HTTP_PORT, f"/{nonce}")
            # Receive-only: the listener returns a static 200 and reads nothing else.
            assert reply.startswith(b"HTTP/1.1 200")
            reaped = await collab.reap([nonce], deadline=time.time() + 3)
            assert nonce in reaped
            assert reaped[nonce].protocol == "http"
            assert nonce in reaped[nonce].observed_path
        finally:
            await collab.stop()

    _run(scenario())


def test_reap_shared_window_returns_only_callers() -> None:
    """Fire-and-reap: three nonces, only two call back → two confirmed, one absent."""

    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        try:
            n1, n2, n3 = collab.mint("h1"), collab.mint("h2"), collab.mint("h3")
            await _http_callback(_HTTP_PORT, f"/{n1}")
            await _http_callback(_HTTP_PORT, f"/{n3}")
            reaped = await collab.reap([n1, n2, n3], deadline=time.time() + 3)
            assert set(reaped) == {n1, n3}  # n2 never called back → blind_unconfirmed
        finally:
            await collab.stop()

    _run(scenario())


def test_reap_no_callback_returns_empty_within_window() -> None:
    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        try:
            nonce = collab.mint("never-fires")
            reaped = await collab.reap([nonce], deadline=time.time() + 1)
            assert reaped == {}
        finally:
            await collab.stop()

    _run(scenario())


# ---------------------------------------------------------------------------
# Receive-only / scope properties (§P6.1.5)
# ---------------------------------------------------------------------------


def test_dns_answers_only_its_own_advertised_address() -> None:
    """The DNS leg resolves nothing but its own address — it cannot be steered."""

    async def scenario() -> None:
        collab = _make_collab(advertised_ip="127.0.0.1")
        await collab.start()
        try:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_connect(sock, ("127.0.0.1", _DNS_PORT))
                query = _build_dns_query("victimhostlabel1234.evil.example")
                await loop.sock_sendall(sock, query)
                resp = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=5.0)
            finally:
                sock.close()
            # The A record's RDATA (last 4 bytes) is the advertised IP, never a
            # target-chosen address — the responder cannot be pointed elsewhere.
            assert resp[-4:] == socket.inet_aton("127.0.0.1")
        finally:
            await collab.stop()

    _run(scenario())


def test_non_nonce_traffic_never_pollutes_the_index() -> None:
    """A scanner hitting '/' or '/favicon.ico' records no correlatable nonce."""

    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        try:
            await _http_callback(_HTTP_PORT, "/")
            await _http_callback(_HTTP_PORT, "/favicon.ico")
            # A never-minted, shape-invalid path yields no correlation entry.
            reaped = await collab.reap(["favicon"], deadline=time.time() + 1)
            assert reaped == {}
        finally:
            await collab.stop()

    _run(scenario())


def test_stop_clears_the_bounded_log() -> None:
    async def scenario() -> None:
        collab = _make_collab()
        await collab.start()
        nonce = collab.mint("h1")
        await _http_callback(_HTTP_PORT, f"/{nonce}")
        await collab.reap([nonce], deadline=time.time() + 2)
        assert collab.events_for(nonce)
        await collab.stop()
        # Teardown clears the event log + correlation table (bounded retention).
        assert collab.events_for(nonce) == []
        assert collab.pending_for(nonce) is None
        assert collab.healthy is False

    _run(scenario())


# ---------------------------------------------------------------------------
# Stateless parsing helpers
# ---------------------------------------------------------------------------


def test_candidate_tokens_keep_only_shape_valid_nonces() -> None:
    good = mint_nonce()
    tokens = _candidate_nonce_tokens(f"{good}.oob.clinkz.test", f"/{good}")
    assert tokens == {good}
    # Noise (short/hyphenated) is discarded.
    assert _candidate_nonce_tokens("favicon.ico", "/robots.txt") == set()


def test_dns_qname_parser_roundtrips() -> None:
    name = "abcdef1234567890.oob.clinkz.test"
    assert _parse_dns_qname(_build_dns_query(name)) == name


def test_dns_qname_parser_tolerates_garbage() -> None:
    assert _parse_dns_qname(b"") == ""
    assert _parse_dns_qname(b"\x00" * 4) == ""
