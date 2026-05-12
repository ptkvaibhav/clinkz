"""Shared helpers for adaptive ``_test_*`` methodologies.

Both the command-injection and the local-file-inclusion methodologies open
their phase-1 (injection-point mapping) loop with the same probe shape:
send a parameter value, time the response, hash the body, record status /
length / fingerprint. Centralising that probe here keeps the two
methodologies in lockstep and gives the unit tests one helper to mock.

The helper is intentionally narrow — it returns a structured baseline
result; comparison logic lives inside each methodology so it can apply
its own divergence threshold.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import TYPE_CHECKING, Any, Protocol

from pydantic import BaseModel

if TYPE_CHECKING:
    from clinkz.agents.exploit import PageAnalysis, _HTTPResponse


class _ProbeSender(Protocol):
    """Structural type for an agent that can send a probe to a parameter.

    The exploit agent's ``_send_probe`` method satisfies this protocol.
    Declared as a Protocol so the helper has no import-cycle on
    ``ExploitAgent``.
    """

    async def _send_probe(
        self,
        page: PageAnalysis,
        param: str,
        value: str,
    ) -> _HTTPResponse: ...


class BaselineProbe(BaseModel):
    """Per-probe response fingerprint shared by CMDI and LFI phase 1.

    Attributes:
        variant: Human-readable label for the probe (``"original"``,
            ``"semicolon"``, ``"traversal_dotdot"``, ...). Used by trace
            events and by phase-2 fingerprinting code to pick out probes.
        value: The parameter value sent.
        status: HTTP status of the response.
        length: Length of the response body (bytes / chars after decoding).
        body_hash: 16-char SHA1 hex digest of a normalised body — strips
            decimal numbers and whitespace runs so transient values
            (timestamps, request IDs) don't perturb the fingerprint.
        time_ms: Round-trip time in milliseconds.
        body: Full response body. Kept for downstream phases that need to
            scan for content (errors, file signatures, canaries). The
            field is excluded from short fingerprint comparisons.
    """

    variant: str
    value: str
    status: int
    length: int
    body_hash: str
    time_ms: float
    body: str = ""


def _normalise_body(body: str) -> str:
    """Stable normalisation used by ``body_hash``.

    Strips runs of whitespace and decimal numbers so the fingerprint
    compares structure rather than transient values (timestamps, request
    IDs, etc). Equal fingerprint = same shape of page; different
    fingerprint = the probe caused a real divergence.
    """
    normalized = re.sub(r"\d+", "0", body)
    normalized = re.sub(r"\s+", " ", normalized).strip().lower()
    return normalized


def _hash_body(body: str) -> str:
    """16-char SHA1 hex digest of a normalised body.

    SHA1 here is a non-cryptographic shape fingerprint — collisions are
    tolerable, security is not the property.
    """
    return hashlib.sha1(  # noqa: S324
        _normalise_body(body).encode("utf-8", errors="replace"),
        usedforsecurity=False,
    ).hexdigest()[:16]


async def baseline_probe(
    agent: _ProbeSender,
    page: PageAnalysis,
    param: str,
    *,
    variant: str,
    value: str,
) -> BaselineProbe:
    """Send one probe and return a populated :class:`BaselineProbe`.

    Times the round-trip with :func:`time.monotonic`, hashes the body via
    :func:`_hash_body`, and packages everything into a
    :class:`BaselineProbe`. Both the CMDI and LFI methodologies open
    phase-1 by calling this helper across their probe matrix, then look
    for divergence between the original probe and the variants.

    Args:
        agent: Object exposing ``_send_probe``. The exploit agent
            satisfies this. We accept it as an argument rather than
            owning the dispatch so the helper has no dependency on
            ``ExploitAgent``.
        page: Page being probed.
        param: Parameter name.
        variant: Short label distinguishing the probe in trace events.
        value: Parameter value to send.

    Returns:
        Fully populated :class:`BaselineProbe`.
    """
    t0 = time.monotonic()
    resp = await agent._send_probe(page, param, value)
    elapsed_ms = (time.monotonic() - t0) * 1000.0
    body: str = resp.body or ""
    return BaselineProbe(
        variant=variant,
        value=value,
        status=resp.status,
        length=len(body),
        body_hash=_hash_body(body),
        time_ms=elapsed_ms,
        body=body,
    )


def baseline_diverged(
    probe: BaselineProbe,
    original: BaselineProbe,
    *,
    length_min: int = 1,
) -> bool:
    """Whether ``probe`` meaningfully differs from ``original``.

    Divergence: any of status mismatch, body-hash mismatch, or length
    delta of at least ``length_min`` bytes. Phase-1 of both methodologies
    uses ``length_min=1`` (very lax — a single-byte echo of an injected
    separator counts); phase-2 fingerprinting tightens the threshold by
    raising ``length_min``.
    """
    return (
        probe.status != original.status
        or probe.body_hash != original.body_hash
        or abs(probe.length - original.length) >= length_min
    )


def probe_to_dict(probe: BaselineProbe) -> dict[str, Any]:
    """Convert a :class:`BaselineProbe` to a trace-friendly dict.

    Drops the full body but keeps the human-relevant fingerprint fields.
    Used by the trace event payloads in both methodologies.
    """
    return {
        "variant": probe.variant,
        "value": probe.value,
        "status": probe.status,
        "length": probe.length,
        "body_hash": probe.body_hash,
        "time_ms": round(probe.time_ms, 2),
    }


__all__ = [
    "BaselineProbe",
    "baseline_diverged",
    "baseline_probe",
    "probe_to_dict",
]
