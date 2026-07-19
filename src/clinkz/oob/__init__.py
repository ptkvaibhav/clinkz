"""Out-of-band (P6) confirmation infrastructure.

The sixth confirmation primitive (``docs/p6-oob-design.md``): a blind capability
is confirmed when an inbound callback bearing a Clinkz-minted, single-use nonce
reaches a Clinkz-owned collaborator within a wait window. Two pieces live here:

* :mod:`clinkz.oob.templates` — the CLINKZ-OWNED payload templates and the
  callback-URL **carrier**. The structural exfil guardrail (§P6.7.4): a
  methodology *selects* a template; it never authors the payload string, and the
  only variable a template carries is a validated ``[a-z0-9]`` nonce. Target /
  LLM / source data is **structurally incapable** of reaching the callback host.
* :mod:`clinkz.oob.collaborator` — :class:`~clinkz.oob.collaborator.OOBCollaborator`,
  a **receive-only** DNS + HTTP listener with a bounded, redacted, per-engagement
  event log, per-probe nonce minting, a nonce→hypothesis correlation table, a
  preflight self-round-trip health-check, and a fire-and-reap shared-window reaper.

Disabled by default (``OOB_COLLABORATOR_MODE=disabled``): with no collaborator
wired, blind hypotheses defer exactly as before (``blind_suspected``), so the
black-box floor is unchanged.
"""

from __future__ import annotations

from clinkz.oob.collaborator import OOBCollaborator, OOBEvent, PendingProbe
from clinkz.oob.templates import (
    CallbackShape,
    OOBTemplateId,
    build_oob_payload,
    mint_nonce,
)

__all__ = [
    "CallbackShape",
    "OOBCollaborator",
    "OOBEvent",
    "OOBTemplateId",
    "PendingProbe",
    "build_oob_payload",
    "mint_nonce",
]
