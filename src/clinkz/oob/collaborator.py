"""The OOB collaborator — a receive-only DNS + HTTP callback listener (§P6.1).

The collaborator is attacker-controlled infrastructure Clinkz *runs*, never a host
Clinkz *connects to* (§P6.1.5 guardrail 4). Its whole job is to answer one
question: *"has an inbound event bearing nonce T arrived?"* — the P6 confirmation
oracle. Its security posture is deliberately minimal:

* **Receive-only.** The HTTP listener reads a bounded request and returns a static
  200; it never makes an outbound request. The DNS listener answers only queries
  under its own zone, with its own advertised address — it can never be steered
  into an SSRF relay or a fetch-and-forward hop (guardrail 3).
* **Bounded + redacted.** The event log is capped and stores only callback
  metadata (nonce, protocol, source IP, bounded host/path) — never a body,
  never a secret (guardrail 6). It is cleared on teardown.
* **Per-engagement.** Provisioned in preflight, health-checked before it is
  trusted, torn down at the end. A minted nonce maps to exactly one hypothesis via
  the correlation table, so concurrent blind probes stay disambiguable (§P6.1.4).

Provisioning modes (§P6.1.2) select only the *transport* / reachable address; the
listener code here is shared. The default engagement floor is ``disabled`` (no
collaborator), so nothing here runs unless P6 is explicitly opted in.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import logging
import socket
import struct
import time
from collections import deque
from collections.abc import Callable
from typing import Literal

from pydantic import BaseModel

from clinkz.oob.templates import CallbackShape, is_valid_nonce, mint_nonce

logger = logging.getLogger(__name__)

# Bounded retention: the event log never grows past this many callbacks per
# engagement (guardrail 6 — bounded retention). Oldest events are evicted.
_MAX_EVENTS = 512

# Bounded metadata: observed host / path excerpts are capped so a hostile callback
# cannot bloat the log. The nonce is short; anything beyond this is noise.
_MAX_FIELD = 256

# Bounded request read on the HTTP leg: we only need the request line + Host header,
# never a body. Cap the read so a slow-loris / huge request cannot exhaust memory.
_HTTP_READ_CAP = 8192
_HTTP_READ_TIMEOUT = 5.0

# Poll cadence while reaping — small enough to be responsive, large enough not to spin.
_REAP_POLL_INTERVAL = 0.25


class OOBEvent(BaseModel):
    """A single inbound callback the collaborator recorded (bounded, redacted).

    Attributes:
        nonce: The nonce token carried by the event (leftmost DNS/Host label or a
            path segment) that matched a shape-valid nonce.
        protocol: ``"dns"`` or ``"http"`` — which leg received the callback.
        source_ip: The source address of the callback. A **soft corroborator**
            only (§P6.2.2): DNS callbacks arrive from the target's *resolver*, not
            the target, so the nonce — not the source IP — is the hard proof.
        observed_host: Bounded excerpt of the queried name / HTTP ``Host`` header.
        observed_path: Bounded excerpt of the HTTP request path (empty for DNS).
        received_at: Wall-clock epoch seconds the callback was recorded.
    """

    nonce: str
    protocol: Literal["dns", "http"]
    source_ip: str = ""
    observed_host: str = ""
    observed_path: str = ""
    received_at: float = 0.0


class PendingProbe(BaseModel):
    """A minted nonce's correlation record — the nonce→hypothesis mapping (§P6.1.4).

    Attributes:
        nonce: The single-use nonce minted for this probe.
        hypothesis_ref: An opaque handle identifying the exact hypothesis / probe
            this nonce was minted for (e.g. ``ssrf:<url>:<param>``).
        outbound_probe: The RAW outbound probe string that carried the nonce to the
            target — one half of the raw-auditable P6 evidence pair (§P6.2.4). Set
            once the probe is actually sent.
        sent_at: Wall-clock epoch seconds the probe was dispatched (0 until sent).
    """

    nonce: str
    hypothesis_ref: str = ""
    outbound_probe: str = ""
    sent_at: float = 0.0


class _DNSProtocol(asyncio.DatagramProtocol):
    """Minimal receive-only authoritative responder for the collaborator's zone.

    Records the queried name (leftmost label as the candidate nonce) and answers
    with a single A record pointing at the collaborator's own advertised address —
    so a target that resolves ``<nonce>.<zone>`` reaches the collaborator, and the
    DNS leg alone confirms a DNS-only egress (§P6.5.4). It never resolves anything
    but its own address: it cannot be steered.
    """

    def __init__(self, record: Callable[..., None], advertised_ip: str) -> None:
        self._record = record
        self._advertised_ip = advertised_ip
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        qname = _parse_dns_qname(data)
        if qname:
            self._record("dns", src_ip=addr[0], host=qname, path="")
        response = _build_dns_response(data, self._advertised_ip)
        if response and self.transport is not None:
            with contextlib.suppress(OSError):
                self.transport.sendto(response, addr)


class OOBCollaborator:
    """A receive-only DNS + HTTP callback listener with a P6 correlation table.

    Lifecycle mirrors the container preflight discipline: :meth:`start` binds the
    listeners, :meth:`health_check` proves the loop end-to-end before it is trusted
    (§P6.7.1), :meth:`stop` tears everything down. Between, a methodology
    :meth:`mint`\\s a nonce, sends the probe, :meth:`record_sent` captures the
    outbound half of the evidence, and :meth:`reap` waits one shared window for
    inbound callbacks (fire-and-reap, §P6.3.2).
    """

    def __init__(
        self,
        *,
        zone: str,
        callback_shape: CallbackShape,
        bind_host: str = "0.0.0.0",  # noqa: S104 — a receive-only listener must accept target callbacks
        http_port: int = 18080,
        dns_port: int = 15353,
        advertised_ip: str = "127.0.0.1",
        max_events: int = _MAX_EVENTS,
    ) -> None:
        """Configure (but do not start) the collaborator.

        Args:
            zone: The callback authority handed to the carrier. For ``SUBDOMAIN``
                shape this is a wildcard-resolvable base (``oob.clinkz.test``); for
                ``PATH`` shape it is a fixed reachable ``host:port`` the target can
                connect to directly.
            callback_shape: Where the nonce rides in the callback host.
            bind_host: Listener bind address (``0.0.0.0`` so the target can reach it).
            http_port: TCP port for the HTTP leg.
            dns_port: UDP port for the DNS leg.
            advertised_ip: The IPv4 the DNS leg answers with (the address a target
                should connect to). Defaults to loopback for the self-round-trip
                health-check; set to the bridge/host address for a real target.
            max_events: Bounded event-log capacity.
        """
        self.zone = zone
        self.callback_shape = callback_shape
        self._bind_host = bind_host
        self._http_port = http_port
        self._dns_port = dns_port
        self._advertised_ip = advertised_ip
        self._events: deque[OOBEvent] = deque(maxlen=max_events)
        self._by_nonce: dict[str, list[OOBEvent]] = {}
        self._pending: dict[str, PendingProbe] = {}
        self._http_server: asyncio.AbstractServer | None = None
        self._dns_transport: asyncio.DatagramTransport | None = None
        self._started = False
        self._healthy = False

    # ------------------------------------------------------------------
    # Provisioning lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Bind the DNS + HTTP listeners. Raises on bind failure (caller degrades)."""
        loop = asyncio.get_running_loop()
        self._http_server = await asyncio.start_server(
            self._handle_http, host=self._bind_host, port=self._http_port
        )
        self._dns_transport, _protocol = await loop.create_datagram_endpoint(
            lambda: _DNSProtocol(self._record, self._advertised_ip),
            local_addr=(self._bind_host, self._dns_port),
        )
        self._started = True
        logger.info(
            "OOB collaborator started: zone=%s shape=%s http=%s:%d dns=%s:%d",
            self.zone,
            self.callback_shape.value,
            self._bind_host,
            self._http_port,
            self._bind_host,
            self._dns_port,
        )

    async def stop(self) -> None:
        """Tear down listeners and clear the bounded log + correlation table."""
        if self._http_server is not None:
            self._http_server.close()
            with contextlib.suppress(Exception):
                await self._http_server.wait_closed()
            self._http_server = None
        if self._dns_transport is not None:
            self._dns_transport.close()
            self._dns_transport = None
        self._events.clear()
        self._by_nonce.clear()
        self._pending.clear()
        self._started = False
        self._healthy = False
        logger.info("OOB collaborator stopped and event log cleared")

    @property
    def healthy(self) -> bool:
        """Whether the preflight health-check confirmed the loop (§P6.7.1 gate)."""
        return self._healthy

    async def health_check(self) -> bool:
        """Self-hit both legs with a fresh token; confirm the round-trip (§P6.7.1).

        Mints a token, hits the collaborator's *own* HTTP and DNS listeners over
        loopback, and confirms it recorded a callback bearing the token on **both**
        legs. Only a collaborator that passes this gate may turn a P6
        non-confirmation into an operator research-lead — a dead collaborator must
        surface as "collaborator unavailable", never as ``blind_unconfirmed`` (a
        clean-looking target). Sets :pyattr:`healthy`.

        Returns:
            ``True`` iff both the HTTP and DNS self-round-trips were recorded.
        """
        if not self._started:
            self._healthy = False
            return False
        token = mint_nonce()
        http_ok = await self._self_http(token)
        dns_ok = await self._self_dns(token)
        # Confirm the listeners actually recorded the token on both legs.
        protocols = {e.protocol for e in self.events_for(token)}
        recorded_both = {"http", "dns"} <= protocols
        self._healthy = bool(http_ok and dns_ok and recorded_both)
        logger.info(
            "OOB collaborator health-check: http=%s dns=%s recorded=%s → healthy=%s",
            http_ok,
            dns_ok,
            sorted(protocols),
            self._healthy,
        )
        return self._healthy

    # ------------------------------------------------------------------
    # Minting + correlation (§P6.1.4)
    # ------------------------------------------------------------------

    def mint(self, hypothesis_ref: str) -> str:
        """Mint a single-use nonce and register its hypothesis mapping.

        Args:
            hypothesis_ref: An opaque handle for the exact hypothesis/probe.

        Returns:
            The minted nonce (to hand to :func:`~clinkz.oob.templates.build_oob_payload`).
        """
        nonce = mint_nonce()
        self._pending[nonce] = PendingProbe(nonce=nonce, hypothesis_ref=hypothesis_ref)
        return nonce

    def record_sent(self, nonce: str, outbound_probe: str) -> None:
        """Record that the probe carrying *nonce* was dispatched (evidence half A)."""
        pending = self._pending.get(nonce)
        if pending is not None:
            pending.outbound_probe = outbound_probe[:_MAX_FIELD]
            pending.sent_at = time.time()

    def pending_for(self, nonce: str) -> PendingProbe | None:
        """The correlation record for *nonce*, if minted here."""
        return self._pending.get(nonce)

    def events_for(self, nonce: str) -> list[OOBEvent]:
        """All recorded callbacks bearing *nonce* (idempotent, may be empty)."""
        return list(self._by_nonce.get(nonce, ()))

    async def reap(self, nonces: list[str], deadline: float) -> dict[str, OOBEvent]:
        """Fire-and-reap: wait until *deadline* for any of *nonces* to call back.

        The scheduler has already sent every probe; this waits **one shared
        window** for callbacks to arrive concurrently (§P6.3.2), so a batch of K
        blind probes costs one window, not K windows. Returns the first callback
        seen per nonce; a nonce with no callback by the deadline is simply absent
        (its hypothesis becomes ``blind_unconfirmed``).

        Args:
            nonces: The minted nonces to watch for.
            deadline: Absolute wall-clock epoch second to stop waiting.

        Returns:
            ``{nonce: earliest OOBEvent}`` for every nonce that called back.
        """
        outstanding = set(nonces)
        confirmed: dict[str, OOBEvent] = {}
        while outstanding and time.time() < deadline:
            for nonce in list(outstanding):
                events = self._by_nonce.get(nonce)
                if events:
                    confirmed[nonce] = events[0]
                    outstanding.discard(nonce)
            if not outstanding:
                break
            await asyncio.sleep(_REAP_POLL_INTERVAL)
        # Final sweep in case a callback landed between the last poll and the deadline.
        for nonce in list(outstanding):
            events = self._by_nonce.get(nonce)
            if events:
                confirmed[nonce] = events[0]
        return confirmed

    # ------------------------------------------------------------------
    # Recording (bounded, redacted) — the receive-only core
    # ------------------------------------------------------------------

    def _record(self, protocol: str, *, src_ip: str, host: str, path: str) -> None:
        """Record an inbound callback, indexing it by every nonce token it carries.

        Bounded and redaction-safe: only callback metadata is stored, capped to
        :data:`_MAX_FIELD`. A token is indexed only if it is a shape-valid nonce
        (so arbitrary path/host noise never inflates the index).
        """
        host = (host or "")[:_MAX_FIELD]
        path = (path or "")[:_MAX_FIELD]
        tokens = _candidate_nonce_tokens(host, path)
        if not tokens:
            return
        event = OOBEvent(
            nonce=next(iter(tokens)),
            protocol="dns" if protocol == "dns" else "http",
            source_ip=(src_ip or "")[:_MAX_FIELD],
            observed_host=host,
            observed_path=path,
            received_at=time.time(),
        )
        self._events.append(event)
        for token in tokens:
            self._by_nonce.setdefault(token, []).append(event)

    async def _handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Receive-only HTTP handler: read a bounded request, record, static 200.

        Never makes an outbound request. Extracts the request path (first segment
        as the candidate nonce for the PATH shape) and the ``Host`` header
        (leftmost label as the candidate nonce for the SUBDOMAIN shape).
        """
        try:
            try:
                raw = await asyncio.wait_for(
                    reader.read(_HTTP_READ_CAP), timeout=_HTTP_READ_TIMEOUT
                )
            except (TimeoutError, OSError):
                raw = b""
            path, host = _parse_http_request(raw)
            peer = writer.get_extra_info("peername") or ("", 0)
            src_ip = peer[0] if isinstance(peer, tuple) else ""
            if path or host:
                self._record("http", src_ip=src_ip, host=host, path=path)
            body = b"ok"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + body
            )
            with contextlib.suppress(OSError):
                await writer.drain()
        finally:
            with contextlib.suppress(OSError):
                writer.close()

    # ------------------------------------------------------------------
    # Health-check self-hits (loopback)
    # ------------------------------------------------------------------

    async def _self_http(self, token: str) -> bool:
        """Loopback GET carrying *token* in path + Host; confirm a 200 comes back."""
        host_label = f"{token}.{_host_only(self.zone)}"
        request = (
            f"GET /{token} HTTP/1.1\r\nHost: {host_label}\r\n"
            f"User-Agent: clinkz-oob-health\r\nConnection: close\r\n\r\n"
        ).encode()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", self._http_port), timeout=5.0
            )
        except (OSError, TimeoutError):
            return False
        try:
            writer.write(request)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(64), timeout=5.0)
            return resp.startswith(b"HTTP/1.1 200")
        except (OSError, TimeoutError):
            return False
        finally:
            with contextlib.suppress(OSError):
                writer.close()
                await writer.wait_closed()

    async def _self_dns(self, token: str) -> bool:
        """Loopback DNS query for ``<token>.<zone>``; confirm an answer comes back."""
        query = _build_dns_query(f"{token}.{_host_only(self.zone)}")
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setblocking(False)
            await loop.sock_connect(sock, ("127.0.0.1", self._dns_port))
            await loop.sock_sendall(sock, query)
            resp = await asyncio.wait_for(loop.sock_recv(sock, 512), timeout=5.0)
            return len(resp) > 0
        except (OSError, TimeoutError):
            return False
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # Carrier authority
    # ------------------------------------------------------------------

    def callback_zone(self) -> str:
        """The zone/authority the carrier interpolates the nonce into."""
        return self.zone

    def dns_authority(self) -> str:
        """The DNS-leg authority a ``jndi:dns://`` lookup targets directly.

        For the ``PATH`` shape the JNDI DNS provider queries the nonce as a domain
        straight at the collaborator's DNS leg (no wildcard delegation, no port 53),
        so the authority is the zone host with the **DNS** port — the reliable
        docker-mode Log4Shell channel (§P6.5.4). For the ``SUBDOMAIN`` shape the nonce
        rides as a subdomain resolved by the target's own resolver, so the delegated
        zone is used as-is.
        """
        if self.callback_shape is CallbackShape.SUBDOMAIN:
            return self.zone
        return f"{_host_only(self.zone)}:{self._dns_port}"


# ---------------------------------------------------------------------------
# Stateless helpers — parsing & nonce extraction
# ---------------------------------------------------------------------------


def _host_only(zone: str) -> str:
    """Strip a ``:port`` suffix from *zone* so it is a valid DNS name."""
    return zone.split(":", 1)[0]


def _candidate_nonce_tokens(host: str, path: str) -> set[str]:
    """Every shape-valid nonce token carried by an event's host/path.

    Extracts the leftmost host label and each path segment, keeping only those
    that are shape-valid nonces — so arbitrary noise (a scanner hitting ``/`` or
    ``/favicon.ico``) never pollutes the correlation index.
    """
    tokens: set[str] = set()
    host_label = _host_only(host).split(".", 1)[0].strip().lower()
    if is_valid_nonce(host_label):
        tokens.add(host_label)
    for segment in (path or "").split("/"):
        seg = segment.strip().lower()
        if is_valid_nonce(seg):
            tokens.add(seg)
    return tokens


def _parse_http_request(raw: bytes) -> tuple[str, str]:
    """Extract (path, host) from a raw HTTP request head. Bounded, tolerant."""
    if not raw:
        return "", ""
    text = raw.decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    request_line = lines[0] if lines else ""
    parts = request_line.split(" ")
    path = parts[1] if len(parts) >= 2 else ""
    host = ""
    for line in lines[1:]:
        if ":" in line and line.split(":", 1)[0].strip().lower() == "host":
            host = line.split(":", 1)[1].strip()
            break
    return path, host


def _parse_dns_qname(data: bytes) -> str:
    """Parse the QNAME from a DNS query packet, or ``""`` on malformed input."""
    if len(data) < 12:
        return ""
    offset = 12
    labels: list[str] = []
    try:
        while offset < len(data):
            length = data[offset]
            if length == 0:
                break
            offset += 1
            if length & 0xC0:  # compression pointer — not expected in a query
                return ""
            label = data[offset : offset + length]
            if len(label) != length:
                return ""
            labels.append(label.decode("latin-1", errors="replace"))
            offset += length
    except IndexError:
        return ""
    return ".".join(labels)


def _build_dns_response(query: bytes, ip: str) -> bytes:
    """Build a minimal A-record response echoing *query*'s question, pointing at *ip*.

    Answers with the collaborator's own advertised address only — it resolves
    nothing else, so it cannot be steered (guardrail 3). Returns ``b""`` if the
    query is malformed or *ip* is not a valid IPv4.
    """
    if len(query) < 12:
        return b""
    try:
        packed_ip = ipaddress.IPv4Address(ip).packed
    except (ipaddress.AddressValueError, ValueError):
        return b""
    # Find the end of the question section (QNAME + QTYPE + QCLASS).
    offset = 12
    while offset < len(query):
        length = query[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0:
            return b""
        offset += 1 + length
    q_end = offset + 4  # QTYPE(2) + QCLASS(2)
    if q_end > len(query):
        return b""
    question = query[12:q_end]
    txn_id = query[0:2]
    # Flags: QR=1, Opcode=0, AA=1, TC=0, RD (echo), RA=1, RCODE=0.
    rd = query[2] & 0x01
    flags = struct.pack(">H", 0x8580 | (rd << 8))
    header = txn_id + flags + struct.pack(">HHHH", 1, 1, 0, 0)
    # Answer: NAME pointer to 0x0C, TYPE A, CLASS IN, TTL 30, RDLENGTH 4, RDATA ip.
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 30, 4) + packed_ip
    return header + question + answer


def _build_dns_query(name: str) -> bytes:
    """Build a minimal DNS A query for *name* (used by the health-check self-hit)."""
    qname = (
        b"".join(
            bytes([len(label)]) + label.encode("latin-1", errors="replace")
            for label in name.split(".")
            if label
        )
        + b"\x00"
    )
    header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", 1, 1)
