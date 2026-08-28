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

**What IS here, beyond the identity: which DIRECTION a crossing runs in.** Two
principals make a crossing dispatchable; they do not make it meaningful on their
own. "As A, read B's object" is evidence of a broken boundary only while no role
A holds authorizes that read — so an arm dispatched from the more privileged
identity grades an administrator's legitimate reach as an IDOR, on precisely the
engagement shape that is commonest in the field. :class:`PrivilegeOrder` is the
rank the arms are chosen from, and it is DECLARED by the operator rather than
read out of a role label, because a label is free text and a hierarchy is not
something a response can be asked about.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "ANONYMOUS",
    "PRIVILEGE_ORDER_UNDECLARED",
    "Principal",
    "PrivilegeOrder",
    "parse_role_sessions",
    "privilege_order",
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
        privilege: The operator's DECLARED rank for this role in the
            application's own hierarchy, lower being less privileged, or ``None``
            when they did not say. Only the relative order is ever read.
    """

    role: str
    username: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    primary: bool = False
    privilege: int | None = None

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
        rank = entry.get("privilege")
        principal = Principal(
            role=role,
            username=str(entry.get("username") or "").strip(),
            cookies=dict(cookies) if isinstance(cookies, dict) else {},
            headers=dict(headers) if isinstance(headers, dict) else {},
            primary=bool(entry.get("primary", False)),
            # A rank that did not arrive as an int is UNDECLARED, not zero.
            # ``bool`` is an ``int`` in Python and ``privilege: true`` is a
            # plausible thing for an operator to write, so it is excluded
            # explicitly — silently reading it as rank 1 would order the
            # principals off a typo.
            privilege=rank if isinstance(rank, int) and not isinstance(rank, bool) else None,
        )
        if not principal.carries_session:
            continue
        seen.add(role)
        parsed.append(principal)

    parsed.sort(key=lambda p: not p.primary)
    return tuple(parsed)


#: The lead reason a crossing dispatched without a knowable privilege order gets.
#:
#: Registered in :data:`~clinkz.models.finding.UNPROVEN_WHY_UNCONFIRMED`, because
#: an unregistered reason is normalised to ``not_instrumentable`` — "we lack the
#: access" — and the access is exactly what this run HAD. What it lacked was the
#: operator's statement of which of the two identities outranks the other.
PRIVILEGE_ORDER_UNDECLARED = "privilege_order_undeclared_crossing_may_be_authorized"


@dataclass(frozen=True)
class PrivilegeOrder:
    """The run's principals ranked least-privileged first, and whether that rank
    is something the operator actually stated.

    **Why the direction of a crossing decides whether it is one.** An IDOR arm is
    "as A, ask for B's object". If A is the more privileged identity, being served
    that object may be the application working: an administrator reading a
    customer's basket is a feature in most applications, and grading it as a
    boundary crossing produces a false positive on the single commonest client
    shape there is — an engagement handed one admin or service account. Dispatched
    the other way, from the least-privileged identity available, there is no role
    that authorizes the read and the observation is unambiguous.

    Equal rank is fine, and is in fact the cleanest crossing of all: two ordinary
    customers are peers, so neither can be reading the other's record by
    entitlement. The rule is therefore *A must not outrank B*, not *A must be
    strictly below B*.

    **Why it is declared and not inferred.** A role label is free text the
    operator picked for their own application; reading a hierarchy out of it is
    guessing at an answer the producer never gave, which is the failure this
    codebase has now paid for in a component's field names, a tool's output
    model and a version's provenance. So an undeclared order is reported as
    undeclared. It costs a confirmation — the crossing still dispatches and is
    still recorded, it is just a lead — and a lead naming the missing declaration
    is something an operator can act on in one line of their credential file.

    Attributes:
        known: Whether every principal that could take part in a crossing carries
            a declared rank. Vacuously ``True`` with fewer than two principals:
            there is no pair, so there is no order to get wrong — and the
            single-role tier already refuses to confirm for its own reason.
        ordered: The principals, least-privileged first. When ``known`` is False
            this is the handoff order unchanged, so the arms are still dispatched
            and still recorded; only the verdict is bounded.
        why_unknown: Which roles declared nothing, ready to render into the lead.
            Empty when ``known``.
    """

    known: bool
    ordered: tuple[Principal, ...]
    why_unknown: str = ""

    @property
    def least_privileged(self) -> Principal | None:
        """The identity every ``as A`` arm should be carried as."""
        return self.ordered[0] if self.ordered else None

    def crossing_candidates(self) -> tuple[Principal, ...]:
        """The identities whose objects A may ask for — everyone A does not outrank.

        With a known order that is every principal ranked at or above A. Without
        one it is simply everyone else, because refusing to dispatch would throw
        away an observation that is still worth recording; what an unknown order
        costs is the confirmation, not the arm.
        """
        a = self.least_privileged
        if a is None:
            return ()
        if not self.known:
            return tuple(p for p in self.ordered if p.role != a.role)
        floor = a.privilege
        if floor is None:
            return ()
        return tuple(
            p
            for p in self.ordered
            if p.role != a.role and p.privilege is not None and p.privilege >= floor
        )


def privilege_order(principals: tuple[Principal, ...]) -> PrivilegeOrder:
    """Rank *principals* least-privileged first, reporting whether the rank is real.

    Ties break on role name so the order is a function of the principal SET and
    not of handoff order — the same reason the exploit plan refuses to break a
    tie on the crawler's emission sequence. An engagement whose arms depend on
    dict ordering cannot be compared against its own baseline.

    Args:
        principals: The run's proven principals, in handoff order.

    Returns:
        The order. ``known`` is False whenever two or more principals could form
        a crossing and any of them declared no rank.
    """
    if len(principals) < 2:
        return PrivilegeOrder(known=True, ordered=tuple(principals))

    undeclared = [p.role for p in principals if p.privilege is None]
    if undeclared:
        return PrivilegeOrder(
            known=False,
            ordered=tuple(principals),
            why_unknown=(
                "no privilege rank was declared for "
                + ", ".join(f"role {role!r}" for role in sorted(undeclared))
                + " — without it the engine cannot tell whether the crossing was "
                "dispatched from the less privileged identity or the more privileged "
                "one, and an administrator reading a customer's record is the "
                "application working"
            ),
        )

    return PrivilegeOrder(
        known=True,
        ordered=tuple(sorted(principals, key=lambda p: (p.privilege or 0, p.role))),
    )
