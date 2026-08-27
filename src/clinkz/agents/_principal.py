"""A named authenticated principal, and the handoff that carries one.

The Orchestrator logs in every supplied role, asserts each resulting session
against an anonymous control, and stores all of them in ``_role_sessions``. It
then logged a line saying the access-control classes could compare principals —
and the sessions never left the orchestrator. Exploit was handed the PRIMARY
role's cookies and headers and nothing else, so "compare principals" described a
capability that stopped one layer short of the code that needed it.

This module is that layer. It is deliberately small and pure: a principal is a
role name, a username, and the session material to send as them. Building the
list is a parse of the handoff dict, so it is testable with no orchestrator, no
network and no target — which is what makes it possible to assert the tier rule
(:mod:`clinkz.agents._idor_oracle`) offline.

**What is NOT here:** the decision of what a principal may be used for. A second
principal makes positive attribution possible; whether a given oracle is allowed
to confirm on it is declared by the vulnerability-class registry
(:class:`~clinkz.models.vuln_classes.MultiPrincipalRequirement`) and enforced at
the emission chokepoint. Keeping the two apart is why the tier rule cannot be
satisfied by a class remembering to check.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ANONYMOUS",
    "Principal",
    "parse_role_sessions",
]


@dataclass(frozen=True)
class Principal:
    """One authenticated identity the engagement holds a proven session for.

    Attributes:
        role: The operator-supplied role name (``"admin"``, ``"user_b"``). The
            address a methodology asks for a principal by.
        username: The identity that session belongs to. Never a credential — the
            :class:`~clinkz.models.engagement.CredentialSet` is structurally kept
            off the Exploit Agent — but it is what a finding names when it says
            whose object was read.
        cookies: Session cookies to send as this principal.
        headers: Auth headers (a bearer token) to send as this principal.
        primary: Whether this is the engagement's own session — the one the
            ambient cookie jar holds and the session sentinel guards.
    """

    role: str
    username: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    primary: bool = False

    @property
    def carries_session(self) -> bool:
        """Whether there is any session material to send as this principal.

        A principal with neither cookies nor headers is not a second identity,
        it is an anonymous request wearing a role name — and an oracle that
        treated it as a principal would compare A against nobody and call the
        difference an authorization boundary.
        """
        return bool(self.cookies or self.headers)

    def label(self) -> str:
        """Short human name for evidence and traces: ``role`` or ``role (user)``."""
        if self.username and self.username != self.role:
            return f"{self.role} ({self.username})"
        return self.role or "(unnamed principal)"


#: The absence of a principal, spelled explicitly.
#:
#: The anonymous arm is not "a principal with no cookies" — it is the deliberate
#: absence of one, sent under :data:`~clinkz.tools.http_client.SESSION_NONE` so
#: the shared jar is neither read nor written. Passing ``None`` to the carrier
#: selects it; this constant exists so a caller can NAME it in a trace or a table
#: without inventing an empty :class:`Principal` that ``carries_session`` would
#: then have to reject.
ANONYMOUS = "anonymous"


def parse_role_sessions(raw: Any) -> tuple[Principal, ...]:
    """Build the principal list from the Orchestrator's ``role_sessions`` handoff.

    Only ESTABLISHED sessions become principals. A role whose login failed is
    recorded by the orchestrator with ``established=False`` so the abort message
    can name it, and carrying that forward as a usable identity would let an
    oracle "compare" against a session that was never proven — the failure mode
    :mod:`clinkz.engagement.auth_state` exists to prevent, one layer along.

    A role with no session material is dropped for the same reason
    (:attr:`Principal.carries_session`), and so is a duplicate role name: the
    role is the address, and two entries under one address make which one a
    finding names a matter of dict ordering.

    Args:
        raw: Whatever arrived on the message. Anything that is not a list of
            dicts yields no principals — a malformed handoff degrades to
            single-role, which is the tier that cannot confirm.

    Returns:
        The principals, primary first, then in handoff order.
    """
    if not isinstance(raw, list):
        return ()

    parsed: list[Principal] = []
    seen: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        if not entry.get("established", False):
            continue
        role = str(entry.get("role") or "").strip()
        if not role or role in seen:
            continue
        cookies = entry.get("cookies")
        headers = entry.get("headers")
        principal = Principal(
            role=role,
            username=str(entry.get("username") or "").strip(),
            cookies=dict(cookies) if isinstance(cookies, dict) else {},
            headers=dict(headers) if isinstance(headers, dict) else {},
            primary=bool(entry.get("primary", False)),
        )
        if not principal.carries_session:
            continue
        seen.add(role)
        parsed.append(principal)

    parsed.sort(key=lambda p: not p.primary)
    return tuple(parsed)
