"""What counts as a secret SERVED to someone who never authenticated.

The defining effect of this class is narrow and it is not "a string that looks
sensitive appeared somewhere". It is one of exactly two observations:

  * **Credential material in a response served to an anonymous requester.** The
    shape vocabulary is :mod:`clinkz.engagement.credential_shapes` — the same one
    the artifact-disclosure gate uses, so a shape the redactor removes from our
    own bundles is a shape we look for in the target's. Reusing it matters
    beyond convenience: that vocabulary is *definite* (a JWT gated on a decoding
    header, a PEM block, a vendor key with its own prefix), and its entropy
    heuristic is deliberately left behind. An entropy rule would flag a minified
    bundle's hashes, a sourcemap, and every build id.

  * **An operational endpoint answering an anonymous request with privileged
    data.** Privileged means naming internal infrastructure the public surface
    does not: environment-variable assignments, connection strings, internal
    hostnames and RFC1918 addresses in a config document.

Both need the **anonymous control** to mean anything, and it is a control in the
strict sense: the request carried no session material at all (``no_session``),
because the shared engagement cookie jar would otherwise make our "anonymous"
probe carry our own session — the same trap
:mod:`clinkz.engagement.auth_state` exists to avoid on the other side.

**The self-echo guard is the anti-phantom rule here.** A response that contains
the Authorization header we just sent it, or the session cookie we hold, is the
target quoting us back. Confirming on that would report our own credentials as
the target's leak — in every engagement, on every echoing endpoint. So a shape
whose fingerprint matches session material we supplied is discarded, and because
the fingerprint is a salted hash the comparison never handles the secret itself.

A baseline is required for the second effect: content that also appears on the
site root is page chrome, not a disclosure by this endpoint.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from clinkz.engagement.credential_shapes import ShapeHit, find_shapes, fingerprint

#: Shape kinds that are credential material by construction. ``cookie`` is
#: excluded on purpose: a ``Set-Cookie`` in a response is the application issuing
#: a session, which is the feature working, not a disclosure.
_DEFINITE_SECRET_KINDS: frozenset[str] = frozenset(
    {"jwt", "private_key", "api_key", "authorization"}
)

#: Assignments that name infrastructure rather than content. Anchored on the
#: ``KEY=value`` / ``"key": "value"`` shapes a config document uses, so prose
#: mentioning the word "password" is not a match.
_CONFIG_ASSIGNMENT_RE = re.compile(
    r"""(?xi)
    (?:^|[\s,{"'])
    (
        [A-Z][A-Z0-9_]{2,}_(?:PASSWORD|SECRET|TOKEN|KEY|DSN|URI|URL|HOST|DB)
      | (?:DATABASE|REDIS|MONGO|POSTGRES|MYSQL|AMQP|SMTP)_[A-Z0-9_]+
      | (?:aws|azure|gcp)_[a-z0-9_]*(?:key|secret|token)
    )
    ["']?\s*[:=]\s*["']?
    ([^\s"',}]{4,})
    """,
)

#: A driver connection string with credentials in the authority.
_CONNECTION_STRING_RE = re.compile(
    r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/\"']+:[^\s@/\"']+@[^\s\"'/]+"
)

#: RFC1918 / link-local / loopback addresses, and ``.internal``/``.local`` hosts.
_INTERNAL_HOST_RE = re.compile(
    r"(?i)\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}"
    r"|[a-z0-9-]+\.(?:internal|local|svc\.cluster\.local))\b"
)

#: Minimum distinct internal markers before a document counts as operational.
#: One internal hostname in a large bundle is a build artifact; several
#: assignments naming infrastructure is a configuration document.
_MIN_OPERATIONAL_MARKERS = 2


class ServedSecret(BaseModel):
    """One credential shape served to an anonymous requester.

    Attributes:
        kind: Shape identifier from the credential vocabulary.
        detail: Non-secret description (``alg=HS256 claims=[...]``, vendor).
        fingerprint: Salted hash prefix — correlates within this bundle and
            replays nowhere. The evidence NEVER carries the value itself; a
            report that reproduces the credential it is warning about has
            leaked it a second time.
        excerpt_context: Up to 60 characters of the surrounding text with the
            value itself removed, so a reader can locate it in the response.
    """

    kind: str
    detail: str
    fingerprint: str
    excerpt_context: str = ""


class OperationalDisclosure(BaseModel):
    """Privileged infrastructure content an anonymous request received.

    Attributes:
        markers: What was matched, described without reproducing values
            (``"DATABASE_URL assignment"``, ``"internal host 10.x"``).
        marker_count: How many distinct markers were found.
    """

    markers: tuple[str, ...] = ()
    marker_count: int = 0


def _context_around(text: str, hit: ShapeHit) -> str:
    """Up to 60 chars around *hit*, with the matched value blanked out."""
    start = max(0, hit.start - 30)
    end = min(len(text), hit.start + hit.length + 30)
    before = text[start : hit.start]
    after = text[hit.start + hit.length : end]
    return f"{before}<REDACTED:{hit.kind}>{after}".replace("\n", " ").strip()


def served_secrets(
    body: str,
    *,
    supplied_material: list[str] | None = None,
) -> list[ServedSecret]:
    """Credential shapes in *body* that we did not put there ourselves.

    Args:
        body: The response body an ANONYMOUS request received.
        supplied_material: Every secret value this engagement supplied to the
            target — session cookie values, bearer tokens. Any shape whose
            fingerprint matches one of these is the target quoting us back, and
            is discarded. Compared as fingerprints, so this function never
            handles the secret in the clear.

    Returns:
        Definite credential shapes, in document order. Empty when the body holds
        none, or holds only material we supplied.
    """
    if not body:
        return []
    ours = {fingerprint(value) for value in (supplied_material or []) if value}
    found: list[ServedSecret] = []
    for hit in find_shapes(body):
        if hit.kind not in _DEFINITE_SECRET_KINDS:
            continue
        if hit.fingerprint in ours:
            continue  # our own credential, echoed — never the target's leak
        found.append(
            ServedSecret(
                kind=hit.kind,
                detail=hit.detail,
                fingerprint=hit.fingerprint,
                excerpt_context=_context_around(body, hit),
            )
        )
    return found


def operational_disclosure(body: str, *, baseline_body: str = "") -> OperationalDisclosure:
    """Whether *body* is a configuration/operational document, not page content.

    Args:
        body: The response an anonymous request received.
        baseline_body: The site root's body. Markers that also appear there are
            page chrome (a footer naming an internal host, a bundled config
            constant) and are subtracted — a disclosure has to be a property of
            THIS endpoint, or every page on the site would confirm.

    Returns:
        The disclosure, with ``marker_count`` below
        :data:`_MIN_OPERATIONAL_MARKERS` meaning "not established". One internal
        hostname inside a large bundle is a build artifact; several assignments
        naming infrastructure is a configuration document.
    """
    if not body:
        return OperationalDisclosure()

    markers: list[str] = []
    seen: set[str] = set()

    def _add(label: str, evidence: str) -> None:
        if evidence and evidence in baseline_body:
            return  # also on the root — page chrome, not this endpoint's disclosure
        if label in seen:
            return
        seen.add(label)
        markers.append(label)

    for match in _CONFIG_ASSIGNMENT_RE.finditer(body):
        _add(f"{match.group(1)} assignment", match.group(0))
    for match in _CONNECTION_STRING_RE.finditer(body):
        scheme = match.group(0).split("://", 1)[0]
        _add(f"{scheme} connection string with embedded credentials", match.group(0))
    for match in _INTERNAL_HOST_RE.finditer(body):
        _add(f"internal host {match.group(0)}", match.group(0))

    return OperationalDisclosure(markers=tuple(markers), marker_count=len(markers))


def disclosure_is_established(disclosure: OperationalDisclosure) -> bool:
    """Whether an operational disclosure clears the evidence bar."""
    return disclosure.marker_count >= _MIN_OPERATIONAL_MARKERS


__all__ = [
    "OperationalDisclosure",
    "ServedSecret",
    "disclosure_is_established",
    "operational_disclosure",
    "served_secrets",
]
