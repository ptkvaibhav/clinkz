"""The composition oracle — a chain fails when the artifact is swapped for a decoy.

This is the module that stops chaining from manufacturing findings.

Two confirmed findings do not imply the chain between them, and a *successful
second request* does not either. An endpoint that accepts everything accepts our
carried credential too; a login form that 200s on every POST "accepts" a password
we never recovered. So a carriage is proven the way every other oracle here is —
against a control. The control is an **equivalently-shaped decoy**: same length,
same alphabet, same structure, a value the target never issued. The chain
confirms only when

    the real artifact is ACCEPTED   and   the decoy is REFUSED

which is exactly the observation an accept-everything endpoint cannot produce,
and exactly the observation a *guess* cannot produce either. If the decoy is also
accepted we have learned nothing about the artifact, and the honest outcome is a
lead naming that link — never a finding with a caveat attached.

The decoy is derived deterministically from the real value's shape, so two runs
build the same control and the composition is reproducible. It is derived by a
one-way digest, so the decoy can never accidentally BE the real value, and the
real value never enters the evidence: see :class:`~clinkz.chaining.models.ChainArtifact`.
"""

from __future__ import annotations

import hashlib
import re
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel

from clinkz.chaining.models import ChainArtifact, ChainLink, CompositionEvidence
from clinkz.chaining.vocabulary import ArtifactKind
from clinkz.discovery.models import SoundnessGrade, compose_soundness

#: Confirmation primitives a link may cite. A link whose primitive is not one of
#: these is not independently proven, whatever its ``confirmed`` flag says — the
#: chain gate re-checks both, because "every link is confirmed by a P1–P7 oracle"
#: is the emission rule and a boolean nobody cross-checks is a convention.
CONFIRMATION_PRIMITIVES: frozenset[str] = frozenset({"P1", "P2", "P3", "P4", "P5", "P6", "P7"})

#: Bounded excerpt width for the evidence, matching the ConfirmationEvidence
#: discipline: enough context to re-derive the verdict, never a full HTTP log.
_EXCERPT_WIDTH = 400

#: The decoy host suffix. ``.invalid`` is reserved by RFC 2606 and resolves
#: nowhere, so a decoy URL cannot accidentally reach a real service — the control
#: has to fail for the reason we intend, not because we picked somebody's domain.
_DECOY_HOST_SUFFIX = ".clinkz-decoy.invalid"

_LOWER = "abcdefghijklmnopqrstuvwxyz"
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DIGIT = "0123456789"


def _digest_stream(seed: str, length: int) -> bytes:
    """A deterministic byte stream of *length* bytes derived from *seed*."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hashlib.sha256(f"{seed}\x00{counter}".encode()).digest())
        counter += 1
    return bytes(out[:length])


def _remap_preserving_class(value: str, seed: str) -> str:
    """Rebuild *value* character by character, preserving each character's CLASS.

    A lowercase letter becomes a different lowercase letter, a digit a different
    digit, and everything else — dots, dashes, slashes, ``@`` — is preserved
    verbatim. That single rule keeps a JWT's three dot-separated segments and
    their lengths, a hex token's alphabet, and a password's mix of cases and
    punctuation, which is what makes the result a *control* rather than merely a
    different string.
    """
    stream = _digest_stream(seed, max(1, len(value)))
    out: list[str] = []
    for index, char in enumerate(value):
        byte = stream[index]
        if char in _LOWER:
            out.append(_LOWER[byte % 26])
        elif char in _UPPER:
            out.append(_UPPER[byte % 26])
        elif char in _DIGIT:
            out.append(_DIGIT[byte % 10])
        else:
            out.append(char)
    return "".join(out)


def _decoy_path(value: str, seed: str) -> tuple[str, str]:
    """A decoy filesystem path: same depth, same extension, different basename."""
    segments = value.split("/")
    rebuilt: list[str] = []
    for index, segment in enumerate(segments):
        if not segment or segment in (".", ".."):
            rebuilt.append(segment)
            continue
        stem, dot, ext = segment.rpartition(".")
        if dot:
            rebuilt.append(f"{_remap_preserving_class(stem, f'{seed}:{index}')}.{ext}")
        else:
            rebuilt.append(_remap_preserving_class(segment, f"{seed}:{index}"))
    return "/".join(rebuilt), (
        f"same path depth ({len(segments)} segments) and same file extension, "
        "with every name segment rebuilt character-class for character-class"
    )


def _decoy_url(value: str, seed: str) -> tuple[str, str]:
    """A decoy URL: same scheme, port and path shape, a host that resolves nowhere.

    The host is the only part replaced, because the host is what the chain
    claims: "the server fetched THIS internal address". A decoy that changed the
    path would test whether the path exists, which is a different question.
    """
    try:
        parts = urlsplit(value)
    except ValueError:
        remapped = _remap_preserving_class(value, seed)
        return remapped, "character-class-preserving rebuild of an unparseable URL"
    if not parts.netloc:
        return _decoy_path(value, seed)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    decoy_host = f"{_remap_preserving_class(host.replace('.', '-'), seed)}{_DECOY_HOST_SUFFIX}"
    decoy_path, _ = _decoy_path(parts.path, seed) if parts.path else ("", "")
    rebuilt = urlunsplit((parts.scheme, f"{decoy_host}{port}", decoy_path, parts.query, ""))
    return rebuilt, (
        f"same scheme ({parts.scheme or 'none'}), same port ({parts.port or 'default'}) and "
        "same path depth, with the host replaced by a reserved .invalid name that "
        "resolves nowhere"
    )


def decoy_for(artifact: ChainArtifact) -> tuple[str, str]:
    """Build the equivalently-shaped decoy for *artifact*.

    Args:
        artifact: The artifact the chain intends to carry.

    Returns:
        ``(decoy_value, shape_description)``. The description is what goes into
        the evidence: a reviewer has to be able to see WHY the decoy is a control
        for this artifact and not just another request.

    Raises:
        ValueError: When the artifact carries no value — there is nothing to
            build a control against, and a chain with no artifact is not a chain.
    """
    value = artifact.value
    if not value:
        raise ValueError("cannot build a decoy for an empty artifact")
    seed = f"clinkz-chain-decoy\x00{artifact.kind.value}\x00{value}"

    if artifact.kind is ArtifactKind.INTERNAL_ENDPOINT:
        decoy, shape = _decoy_url(value, seed)
    elif artifact.kind is ArtifactKind.FILE_PATH:
        decoy, shape = _decoy_path(value, seed)
    else:
        decoy = _remap_preserving_class(value, seed)
        shape = (
            f"same length ({len(value)} characters), same character classes in the "
            "same positions, and every separator preserved"
        )

    if decoy == value:
        # Degenerate input (all-punctuation, or a one-character alphabet). Force a
        # difference rather than return a "control" identical to the probe, which
        # would silently make the composition unfalsifiable.
        decoy = f"{decoy}0" if not decoy.endswith("0") else f"{decoy}1"
        shape = f"{shape} (one character appended: the shape-preserving rebuild collided)"
    return decoy, shape


class CompositionVerdict(BaseModel):
    """Whether the carriage itself is proven.

    Attributes:
        confirmed: The real artifact was accepted AND the decoy was refused. The
            only state that may emit.
        why_unconfirmed: The reason, from
            :data:`~clinkz.models.finding.CHAIN_WHY_UNCONFIRMED`. Empty when
            confirmed.
        detail: One sentence for the evidence.
        evidence: The raw, re-derivable both-sides record.
    """

    confirmed: bool = False
    why_unconfirmed: str = ""
    detail: str = ""
    evidence: CompositionEvidence


def evaluate_composition(
    *,
    artifact: ChainArtifact,
    decoy_value: str,
    decoy_shape: str,
    acceptance_signal: str,
    real_accepted: bool,
    real_status: int | None,
    real_body: str,
    decoy_accepted: bool,
    decoy_status: int | None,
    decoy_body: str,
    salt: str = "",
) -> CompositionVerdict:
    """Decide whether step N's output was actually accepted at step N+1.

    Args:
        artifact: What was carried.
        decoy_value: The equivalently-shaped control, from :func:`decoy_for`.
        decoy_shape: How the decoy matched the artifact's shape.
        acceptance_signal: What "accepted" means for this chain kind — decided by
            the planner BEFORE the requests go out, so the verdict cannot be
            graded on its own result.
        real_accepted: Whether the acceptance signal fired for the real artifact.
        real_status: HTTP status of the real carriage.
        real_body: Response body of the real carriage.
        decoy_accepted: Whether the acceptance signal ALSO fired for the decoy.
        decoy_status: HTTP status of the decoy carriage.
        decoy_body: Response body of the decoy carriage.
        salt: Engagement-local fingerprint salt.

    Returns:
        A verdict that is ``confirmed`` only when the real artifact was accepted
        and the decoy was refused.
    """
    decoy_artifact = artifact.model_copy(update={"value": decoy_value})
    evidence = CompositionEvidence(
        carried_kind=artifact.kind,
        carried_fingerprint=artifact.fingerprint(salt),
        decoy_fingerprint=decoy_artifact.fingerprint(salt),
        decoy_shape=decoy_shape,
        acceptance_signal=acceptance_signal,
        real_accepted=real_accepted,
        real_status=real_status,
        real_excerpt=(real_body or "")[:_EXCERPT_WIDTH],
        decoy_accepted=decoy_accepted,
        decoy_status=decoy_status,
        decoy_excerpt=(decoy_body or "")[:_EXCERPT_WIDTH],
    )

    if not real_accepted:
        return CompositionVerdict(
            why_unconfirmed="carried_artifact_not_accepted",
            detail=(
                f"the {artifact.kind.value} recovered at the previous step was presented "
                f"and NOT accepted (status {real_status}; the acceptance signal "
                f"{acceptance_signal!r} did not fire), so the two findings do not compose"
            ),
            evidence=evidence,
        )
    if decoy_accepted:
        return CompositionVerdict(
            why_unconfirmed="decoy_also_accepted_composition_not_discriminating",
            detail=(
                f"the carried {artifact.kind.value} was accepted (status {real_status}) but "
                f"so was an equivalently-shaped decoy the target never issued (status "
                f"{decoy_status}; {decoy_shape}). This endpoint accepts the SHAPE, not the "
                "value, so its acceptance says nothing about what we recovered"
            ),
            evidence=evidence,
        )
    return CompositionVerdict(
        confirmed=True,
        detail=(
            f"the {artifact.kind.value} recovered at the previous step was ACCEPTED "
            f"(status {real_status}, acceptance signal {acceptance_signal!r}) while an "
            f"equivalently-shaped decoy — {decoy_shape} — was REFUSED (status "
            f"{decoy_status}). The composition is therefore a property of the value we "
            "recovered, not of the request shape"
        ),
        evidence=evidence,
    )


def links_independently_confirmed(links: list[ChainLink]) -> str | None:
    """The first link that is NOT independently confirmed, or ``None``.

    "Every link is confirmed by a P1–P7 oracle" is the emission rule, so it is
    checked here rather than trusted: a link must carry ``confirmed`` AND cite a
    primitive from :data:`CONFIRMATION_PRIMITIVES`. A ``confirmed=True`` with no
    primitive is a boolean nobody derived from an observation.

    Args:
        links: The chain's links, in order.

    Returns:
        A sentence naming the unconfirmed link and why, or ``None`` when every
        link is proven.
    """
    if not links:
        return "the chain has no links at all"
    for link in links:
        if not link.confirmed:
            reason = link.why_unconfirmed or "no confirming observation was recorded"
            return (
                f"link {link.ordinal} ({link.test_method or link.kind.value} on "
                f"{link.endpoint or 'the target'}) is not confirmed: {reason}"
            )
        cited = {part.strip().upper() for part in (link.confirmation_primitive or "").split("/")}
        if not cited & CONFIRMATION_PRIMITIVES:
            return (
                f"link {link.ordinal} ({link.test_method or link.kind.value}) claims "
                f"confirmation but cites no P1–P7 oracle (got {link.confirmation_primitive!r})"
            )
    return None


def grade_chain(links: list[ChainLink]) -> SoundnessGrade:
    """Grade a chain by its WEAKEST link.

    Delegates to :func:`~clinkz.discovery.models.compose_soundness`, which is the
    single source of truth for min-over-composition — the same function the
    cross-service A→B path is graded by. Reusing it is what keeps an in-application
    chain from being graded by a rule that drifted from the service-to-service one.

    Args:
        links: The chain's links.

    Returns:
        The weakest link's grade.

    Raises:
        ValueError: When *links* is empty.
    """
    return compose_soundness([link.soundness for link in links])


# ---------------------------------------------------------------------------
# Parsing an artifact out of recovered content
# ---------------------------------------------------------------------------

#: Field names whose value is authentication material. General vocabulary — the
#: words a configuration file, an environment dump or a database column uses for
#: a secret, not any application's own.
_SECRET_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "passphrase",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "token",
        "auth_token",
        "private_key",
        "db_password",
        "database_password",
    }
)

#: Field names that identify WHO the secret belongs to.
_IDENTITY_KEYS: frozenset[str] = frozenset(
    {"user", "username", "login", "email", "account", "db_user", "database_user", "uid"}
)

_KV_RE = re.compile(
    r"""["']?(?P<key>[A-Za-z_][A-Za-z0-9_.-]{0,40})["']?\s*[:=]\s*["']?(?P<value>[^\s"',;}\]]{1,200})""",
)

#: A ``user:secret`` line, the shape a password database or an htpasswd file uses.
_COLON_PAIR_RE = re.compile(r"^(?P<user>[A-Za-z0-9_.\-@]{1,64}):(?P<secret>[^\s:]{4,200})", re.M)

#: ``scheme://user:password@host`` — a connection string carries both halves.
_USERINFO_RE = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*://(?P<user>[^:/@\s]{1,64}):(?P<secret>[^@/\s]{1,200})@"
)

#: Never propose more than this many credentials out of one recovered document.
#: A chain is a targeted composition; a hundred carriage attempts against a login
#: endpoint is a brute-force run wearing a chain's name, and the rails would
#: (correctly) start refusing us halfway through.
MAX_CREDENTIALS_PER_DOCUMENT = 3


class ParsedCredential(BaseModel):
    """A credential pair parsed out of recovered content.

    Attributes:
        identity: The username/email, when the content named one.
        secret: The secret itself. Rendered nowhere — it becomes a
            :class:`~clinkz.chaining.models.ChainArtifact` value.
        how: Where in the content it was found, for the evidence. Names the KEY
            and the shape, never the value.
    """

    identity: str = ""
    secret: str
    how: str = ""


def credentials_in(content: str) -> list[ParsedCredential]:
    """Parse credential material out of content recovered by an earlier link.

    This is what turns "we read /etc/passwd-shaped bytes" into a chain: the
    FILE_CONTENT artifact has to become a CREDENTIAL artifact before anything can
    carry it. Deliberately conservative — three general shapes, all of which name
    the credential explicitly:

      * ``key=value`` / ``key: value`` where the key is a secret-word
      * a ``user:secret`` line
      * a ``scheme://user:secret@host`` connection string

    Nothing is inferred from entropy: a high-entropy string is not a password
    just because it looks like one, and a carriage attempt built on a wrong guess
    is a login attempt against the client's application for nothing.

    Args:
        content: Bytes recovered by a file-read, XXE or SQLi link.

    Returns:
        Up to :data:`MAX_CREDENTIALS_PER_DOCUMENT` parsed credentials, in
        deterministic order (source shape, then identity, then secret) so two
        runs carry the same artifact.
    """
    if not content:
        return []
    found: dict[tuple[str, str], ParsedCredential] = {}

    for match in _USERINFO_RE.finditer(content):
        cred = ParsedCredential(
            identity=match.group("user"),
            secret=match.group("secret"),
            how="a scheme://user:secret@host connection string in the recovered content",
        )
        found.setdefault((cred.identity, cred.secret), cred)

    pending_identity = ""
    for match in _KV_RE.finditer(content):
        key = match.group("key").lower().replace("-", "_")
        value = match.group("value")
        if key in _IDENTITY_KEYS:
            pending_identity = value
            continue
        if key not in _SECRET_KEYS or len(value) < 3:
            continue
        cred = ParsedCredential(
            identity=pending_identity,
            secret=value,
            how=f"a {match.group('key')!r} field in the recovered content",
        )
        found.setdefault((cred.identity, cred.secret), cred)

    for match in _COLON_PAIR_RE.finditer(content):
        cred = ParsedCredential(
            identity=match.group("user"),
            secret=match.group("secret"),
            how="a user:secret line in the recovered content",
        )
        found.setdefault((cred.identity, cred.secret), cred)

    ordered = sorted(found.values(), key=lambda c: (c.how, c.identity, c.secret))
    return ordered[:MAX_CREDENTIALS_PER_DOCUMENT]


__all__ = [
    "CONFIRMATION_PRIMITIVES",
    "MAX_CREDENTIALS_PER_DOCUMENT",
    "CompositionVerdict",
    "ParsedCredential",
    "credentials_in",
    "decoy_for",
    "evaluate_composition",
    "grade_chain",
    "links_independently_confirmed",
]
