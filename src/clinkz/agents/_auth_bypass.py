"""Authentication bypass — the one vocabulary for "did this response log us in?".

The gap this closes (D8). Forty SQL-injection payloads landed in a login form's
email field, the target graded the challenge solved, and ``_test_sqli`` emitted
nothing — **correctly**, because its oracle looks for a DB-error signature, a
boolean row-set delta, or a UNION row, and an authentication bypass produces
none of those. It produces ``200`` and a JWT. The methodology was not wrong; it
had no indicator for the effect that actually occurred.

The defining effect
-------------------
**Authenticated as a principal whose credential we never supplied.** Not "the
request succeeded", not "a cookie came back" — an application that issues an
anonymous session cookie on every response would confirm on that, forever, on
every endpoint.

So confirmation needs a differential, built the way every other oracle here is
built — the real artifact ACCEPTED and an equivalently-shaped decoy REFUSED:

* **probe** — the tautology (``' OR '1'='1' -- ``). Must return an auth artifact.
* **control** — the SAME payload shape with a non-injecting value: the
  *contradiction* (``' OR '1'='2' -- ``). One character apart, identical
  furniture, identical length class. Must NOT return one. This is what
  attributes the difference to SQL boolean evaluation rather than to the shape
  of the string — a WAF returning a canned 200, or a handler that errors into a
  token, answers both arms the same way.
* **benign** — an ordinary wrong-credential request. Must NOT return one. This
  is what rules out an endpoint that hands an artifact to everybody.

And where the artifact NAMES a principal, that principal must differ from every
identity we supplied. The probe rides the engagement's own session; an endpoint
echoing our existing identity back is not a bypass, it is us being logged in
already.

Everything here is pure: three observations in, a verdict out, no I/O. The
carrier lives in the Exploit agent; the decision lives here, where it is
testable without a target and reusable by any methodology whose payload can
reach a login handler.

**The artifact never carries the token value.** A bypass finding is made of
exactly the material a report must not reproduce, so an artifact holds a salted
fingerprint and the principal — the two things that make the finding legible —
and the credential itself stays out of every downstream writer by construction
rather than by the redactor catching it later.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import StrEnum

from clinkz.engagement.credential_shapes import (
    JWT_RE,
    fingerprint,
    jwt_identity_claim,
    jwt_payload_claim_names,
)

#: Response bytes scanned for an auth artifact. The body is chosen by the host
#: under test, so the read is bounded like every other parse of target output.
_MAX_BODY_SCAN = 200_000

#: Cookie NAMES that carry a session. A cookie outside this vocabulary (a CSRF
#: token, a locale, a consent flag) is not an authentication artifact — "a
#: cookie came back" is precisely the observation this class must never confirm
#: on. Matched on a word-ish containment so ``connect.sid``, ``PHPSESSID`` and
#: ``__Host-session`` all resolve, without ``sidebar_state`` doing so.
_SESSION_COOKIE_TOKENS: tuple[str, ...] = (
    "sessid",
    "session",
    "sess",
    "sid",
    "token",
    "auth",
    "jwt",
    "bearer",
    "remember",
    "identity",
    "login",
)

#: JSON keys whose value is a credential the server just issued.
_TOKEN_BODY_KEYS: tuple[str, ...] = (
    "token",
    "access_token",
    "accesstoken",
    "id_token",
    "idtoken",
    "jwt",
    "bearer",
    "session",
    "sessionid",
    "session_id",
    "authorization",
    "apikey",
    "api_key",
)

#: JSON/JWT keys naming WHO the credential belongs to. Ordered: a registered JWT
#: claim first, then the application spellings.
_PRINCIPAL_KEYS: tuple[str, ...] = (
    "sub",
    "email",
    "username",
    "user_name",
    "userName",
    "login",
    "name",
    "user",
    "userid",
    "user_id",
    "id",
)

#: How deep a JSON body is walked looking for a token or a principal. Bounded:
#: the structure is the target's choice.
_MAX_JSON_DEPTH = 6

#: Shortest string under a credential-shaped key that counts as issued material.
#: Present only to reject a placeholder (``"token": "n/a"``); it is NOT the
#: guard that makes this class honest. That is the differential — an
#: application answering every request with the same short token produces the
#: artifact in all three arms and confirms nothing.
_MIN_TOKEN_LENGTH = 8


class AuthArtifactKind(StrEnum):
    """What kind of authenticated state the response handed back."""

    #: ``Set-Cookie`` naming a session.
    SESSION_COOKIE = "session_cookie"
    #: A token in the response body (JWT or otherwise).
    BODY_TOKEN = "body_token"
    #: A redirect AWAY from the login surface — the form-login equivalent of a
    #: token, and the only artifact a classic PHP app produces at the boundary.
    AUTHENTICATED_REDIRECT = "authenticated_redirect"


@dataclass(frozen=True)
class AuthArtifact:
    """Proof that a response conferred authenticated state.

    Attributes:
        kind: Which artifact was seen.
        where: The exact location it was read from, for the evidence line.
        principal: The identity the artifact NAMES, or ``""`` when the artifact
            is opaque (a random session id names nobody). An empty principal is
            not a failure — it just means requirement (c) cannot apply and the
            differential has to carry the confirmation alone.
        fingerprint: Salted, non-replayable digest of the credential. The value
            itself is deliberately absent from this structure.
        claim_names: For a JWT, the NAMES of its claims — enough for a reader to
            see what the token asserts without the artifact carrying any of it.
    """

    kind: AuthArtifactKind
    where: str
    principal: str = ""
    fingerprint: str = ""
    claim_names: list[str] = field(default_factory=list)

    def describe(self) -> str:
        """One evidence-safe line naming the artifact, never its value."""
        parts = [f"{self.kind.value} at {self.where}"]
        if self.principal:
            parts.append(f"principal={self.principal}")
        if self.fingerprint:
            parts.append(f"sha256={self.fingerprint}")
        if self.claim_names:
            parts.append(f"claims=[{','.join(self.claim_names)}]")
        return " ".join(parts)


@dataclass(frozen=True)
class AuthObservation:
    """One arm of the differential: what came back for one request."""

    label: str
    status: int
    artifact: AuthArtifact | None = None

    @property
    def authenticated(self) -> bool:
        return self.artifact is not None

    def describe(self) -> str:
        detail = self.artifact.describe() if self.artifact else "no auth artifact"
        return f"{self.label}: status={self.status} {detail}"


@dataclass(frozen=True)
class AuthBypassVerdict:
    """The decision, with each requirement recorded separately.

    Every boolean is stated rather than collapsed into the verdict, so a
    non-confirmation says WHICH arm refused to cooperate — the difference
    between "the payload did not work" and "this endpoint authenticates
    everybody" is the whole diagnostic value.
    """

    confirmed: bool
    reason: str
    probe_authenticated: bool = False
    control_refused: bool = False
    benign_refused: bool = False
    principal_is_foreign: bool = False
    observed: str = ""


def _iter_json_nodes(value: object, depth: int = 0):
    """Yield every ``(key, value)`` pair in a nested JSON structure, bounded."""
    if depth > _MAX_JSON_DEPTH:
        return
    if isinstance(value, dict):
        for key, inner in value.items():
            yield str(key), inner
            yield from _iter_json_nodes(inner, depth + 1)
    elif isinstance(value, list):
        for inner in value[:50]:
            yield from _iter_json_nodes(inner, depth + 1)


def _parse_json(body: str) -> object | None:
    try:
        return json.loads(body[:_MAX_BODY_SCAN])
    except (ValueError, TypeError):
        return None


def jwt_principal(token: str) -> str:
    """The identity a JWT names, or ``""``.

    Reads ONLY an identity claim, through the credential-shape module that owns
    JWT decoding. A JWT payload routinely carries material a report must never
    reproduce — Juice Shop's carries the account's password hash — so the
    payload is never fetched here, dumped, or attached.
    """
    return jwt_identity_claim(token, _PRINCIPAL_KEYS)


def _looks_like_session_cookie(name: str) -> bool:
    """Whether a cookie NAME is session-bearing rather than incidental."""
    low = name.strip().lower()
    return any(token in low for token in _SESSION_COOKIE_TOKENS)


def _set_cookie_pairs(raw: str) -> list[tuple[str, str]]:
    """``(name, value)`` for each cookie in one or more joined Set-Cookie headers."""
    pairs: list[tuple[str, str]] = []
    for chunk in re.split(r",(?=[^;=]+=)", raw):
        first = chunk.split(";", 1)[0].strip()
        if "=" not in first:
            continue
        name, _, value = first.partition("=")
        name = name.strip()
        if name:
            pairs.append((name, value.strip()))
    return pairs


def _header(headers: dict[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name:
            return value
    return ""


def read_auth_artifact(
    status: int,
    headers: dict[str, str],
    body: str,
) -> AuthArtifact | None:
    """Read the authenticated artifact a response conferred, if any.

    The single vocabulary for "does this response carry authenticated state",
    shared by every methodology that can reach a login handler. Richest signal
    first: a body token names a principal, a session cookie usually does not,
    and a redirect names nothing but is the only artifact a form login gives.

    Args:
        status: HTTP status.
        headers: Response headers (any casing).
        body: Response body.

    Returns:
        The artifact, or ``None``. ``None`` is the answer for a plain ``200``
        with no credential material — "the request succeeded" is not
        authentication.
    """
    text = (body or "")[:_MAX_BODY_SCAN]

    # 1. A JWT anywhere in the body is unambiguous: it decodes as a token.
    jwt_match = JWT_RE.search(text)
    if jwt_match:
        token = jwt_match.group(0)
        return AuthArtifact(
            kind=AuthArtifactKind.BODY_TOKEN,
            where="response body (JWT)",
            principal=jwt_principal(token),
            fingerprint=fingerprint(token),
            claim_names=jwt_payload_claim_names(token),
        )

    # 2. A non-JWT token under a credential-shaped key.
    parsed = _parse_json(text)
    if parsed is not None:
        principal = ""
        for key, value in _iter_json_nodes(parsed):
            if principal or key.lower() not in {p.lower() for p in _PRINCIPAL_KEYS}:
                continue
            if isinstance(value, (str, int)) and str(value).strip():
                principal = str(value).strip()[:120]
        for key, value in _iter_json_nodes(parsed):
            if key.lower() not in _TOKEN_BODY_KEYS:
                continue
            if isinstance(value, str) and len(value.strip()) >= _MIN_TOKEN_LENGTH:
                return AuthArtifact(
                    kind=AuthArtifactKind.BODY_TOKEN,
                    where=f"response body key {key!r}",
                    principal=principal,
                    fingerprint=fingerprint(value.strip()),
                )

    # 3. A session cookie the response SET.
    set_cookie = _header(headers, "set-cookie")
    if set_cookie:
        for name, value in _set_cookie_pairs(set_cookie):
            if not _looks_like_session_cookie(name) or not value:
                continue
            token_principal = jwt_principal(value) if JWT_RE.match(value) else ""
            return AuthArtifact(
                kind=AuthArtifactKind.SESSION_COOKIE,
                where=f"Set-Cookie: {name}",
                principal=token_principal,
                fingerprint=fingerprint(value),
            )

    # 4. A redirect AWAY from the login surface. Reuses the engagement's own
    #    login-shape vocabulary rather than growing a second one here.
    if status in (301, 302, 303, 307, 308):
        from clinkz.engagement.auth_state import ProbeResponse

        probe = ProbeResponse(status=status, headers=dict(headers), body=text)
        if probe.location and not probe.redirects_to_login:
            return AuthArtifact(
                kind=AuthArtifactKind.AUTHENTICATED_REDIRECT,
                where=f"Location: {probe.location[:120]}",
            )
    return None


def body_carries_auth_artifact(body: str) -> bool:
    """Whether a response BODY alone carries authenticated state.

    The body-only half of :func:`read_auth_artifact`, for callers that have no
    headers to hand. Exists so there is one answer to "does this look like a
    successful authentication" rather than a per-methodology guess.
    """
    return read_auth_artifact(200, {}, body) is not None


#: Shortest supplied value that may be matched as a SUBSTRING of a principal.
#: An exact match always counts, however short. Containment does not: the
#: benign parameter value defaults to ``"1"``, and a two-way substring test
#: against it would judge ``admin1@corp.example`` to be an identity we
#: supplied and refuse a genuine bypass. This guard runs in the
#: suppress-a-real-finding direction, so its own false positives are the
#: expensive kind.
_MIN_SUBSTRING_IDENTITY = 4


def _principal_matches_supplied(principal: str, supplied: list[str]) -> bool:
    """Whether the artifact names an identity WE provided.

    Compared both ways for values long enough to be distinctive: an application
    echoes ``clinkz-probe@example.com`` back verbatim, but it may also name the
    local part alone, or wrap it. Either direction of containment means the
    principal is ours, and a principal that is ours cannot demonstrate
    authenticating as someone else.
    """
    subject = principal.strip().lower()
    if not subject:
        return False
    for value in supplied:
        candidate = (value or "").strip().lower()
        if not candidate:
            continue
        if subject == candidate:
            return True
        if len(candidate) < _MIN_SUBSTRING_IDENTITY or len(subject) < _MIN_SUBSTRING_IDENTITY:
            continue
        if subject in candidate or candidate in subject:
            return True
    return False


def decide_auth_bypass(
    *,
    probe: AuthObservation,
    control: AuthObservation,
    benign: AuthObservation,
    supplied_identities: list[str],
) -> AuthBypassVerdict:
    """Decide whether an authentication bypass was DEMONSTRATED.

    Every requirement must hold. Each is a separate reason for refusing, and
    the refusal names which one failed.

    Args:
        probe: The injecting payload's arm — the tautology.
        control: The same payload SHAPE with a non-injecting value — the
            contradiction. Its job is to fail.
        benign: An ordinary credential attempt. Its job is to fail too.
        supplied_identities: Every identity this engagement provided — the
            authenticated-as identity and the benign values the carrier sent.

    Returns:
        The verdict, with each requirement recorded.
    """
    observed = " | ".join(o.describe() for o in (probe, control, benign))

    if not probe.authenticated:
        return AuthBypassVerdict(
            confirmed=False,
            reason="no_auth_artifact_returned",
            observed=observed,
        )
    if control.authenticated:
        # The endpoint answered a NON-injecting value of the same shape with an
        # artifact too. Whatever produced it, it was not the injected boolean —
        # this is the accept-everything case, and it is exactly the observation
        # a naive "200 + a cookie" oracle would have called a finding.
        return AuthBypassVerdict(
            confirmed=False,
            reason="shape_matched_control_also_authenticated",
            probe_authenticated=True,
            observed=observed,
        )
    if benign.authenticated:
        return AuthBypassVerdict(
            confirmed=False,
            reason="benign_credentials_also_authenticated",
            probe_authenticated=True,
            control_refused=True,
            observed=observed,
        )

    principal = probe.artifact.principal if probe.artifact else ""
    if principal and _principal_matches_supplied(principal, supplied_identities):
        # The token names US. Consistent with the engagement's own session being
        # reflected back, which demonstrates nothing about crossing a boundary.
        return AuthBypassVerdict(
            confirmed=False,
            reason="principal_is_an_identity_we_supplied",
            probe_authenticated=True,
            control_refused=True,
            benign_refused=True,
            observed=observed,
        )

    return AuthBypassVerdict(
        confirmed=True,
        reason=(
            "authenticated as a principal whose credential was never supplied: "
            f"{principal or 'opaque artifact'}"
        ),
        probe_authenticated=True,
        control_refused=True,
        benign_refused=True,
        principal_is_foreign=bool(principal),
        observed=observed,
    )
