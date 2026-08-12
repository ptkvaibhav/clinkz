"""Turning a confirmed finding into the artifact it actually put in our hands.

State carriage needs a source. This module is that source, and it is deliberately
ONE seam rather than a registration call sprinkled through twenty-four
methodologies: the class declares what it yields
(:data:`~clinkz.chaining.vocabulary.CLASS_YIELDS`) and the harvester looks for
*that kind* in *that finding's* evidence. A methodology cannot forget to
register, and the harvester cannot invent a kind the class never claimed.

This is the same rule the discovery contract states for tool wrappers — the
PRODUCER declares what it contributes, and the consumer reads the declaration
rather than guessing field names. A harvester that scanned every finding for
every shape would find credential-looking bytes in an XSS payload we sent
ourselves and carry our own probe into a login form.

**Nothing harvested here is ever rendered.** The values become
:class:`~clinkz.chaining.models.ChainArtifact` payloads, whose ``value`` field is
excluded from serialisation; the evidence quotes shapes and fingerprints.
"""

from __future__ import annotations

import re
from ipaddress import ip_address
from urllib.parse import urlsplit

from clinkz.chaining.composition import credentials_in
from clinkz.chaining.models import ChainArtifact
from clinkz.chaining.vocabulary import ArtifactKind, yields_of

#: How much of a recovered body is kept as a content artifact. Bounded because a
#: content artifact exists to be re-parsed (for credentials, for an internal
#: address), not to be stored: an unbounded copy of a target's file would put
#: recovered data into memory and then into a trace for no proof value.
MAX_CONTENT_CHARS = 8_000

#: Never harvest more than this many artifacts from one finding. A single
#: recovered document can name dozens of hosts; each becomes a carriage attempt
#: against the client's application, and a chain is a targeted composition rather
#: than a sweep.
MAX_ARTIFACTS_PER_FINDING = 4

_RESPONSE_PREFIX = "Response: "
_REQUEST_PREFIX = "Request: "

#: A URL-shaped token, for internal-endpoint harvesting.
_URL_RE = re.compile(
    r"\b(?:https?://)[A-Za-z0-9._~:\[\]%-]+(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
)

#: An opaque token: a long run of token-safe characters, optionally dot-segmented
#: (a JWT). Used only for classes that DECLARE a SESSION_TOKEN yield, so a long
#: hex string in an unrelated body is never mistaken for one.
_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_-]{16,512}(?:\.[A-Za-z0-9_-]{8,512}){0,2}\b")

#: PEM blocks and vendor-prefixed keys — the definite key-material shapes. The
#: same "definite shape, never entropy" line the artifact-disclosure gate draws.
_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
    r"|\bAKIA[0-9A-Z]{16}\b"
    r"|\bsk-[A-Za-z0-9]{20,}\b",
    re.DOTALL,
)


def _evidence_text(evidence: list[str], prefix: str) -> str:
    """Concatenate the evidence entries carrying *prefix*."""
    return "\n".join(entry[len(prefix) :] for entry in evidence if entry.startswith(prefix))


def is_internal_address(url: str) -> bool:
    """Whether *url* names a loopback, link-local or private address.

    An internal endpoint is the artifact that makes an SSRF chain worth carrying,
    and "internal" here is an address-space fact rather than a name we recognise
    — so a hostname that is not an IP literal is not claimed to be internal. A
    wrong claim would point a confirmed fetch primitive at a host the client
    never authorised, which is the one mistake the scope fence exists to prevent.
    """
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    if not host:
        return False
    try:
        addr = ip_address(host.strip("[]"))
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)


def harvest_artifacts(
    *,
    test_method: str,
    finding_id: str,
    finding_title: str,
    evidence: list[str],
    target: str = "",
) -> list[ChainArtifact]:
    """Harvest the artifacts a confirmed *test_method* finding put in our hands.

    Args:
        test_method: The class that produced the finding. Its declared yields
            decide which shapes are looked for; a class that declares nothing
            harvests nothing, however suggestive its evidence.
        finding_id: The confirmed finding's id.
        finding_title: Its title, for the artifact label.
        evidence: The finding's evidence entries (``Request: ``/``Response: ``).
        target: The finding's endpoint.

    Returns:
        Up to :data:`MAX_ARTIFACTS_PER_FINDING` artifacts, in
        :class:`~clinkz.chaining.vocabulary.ArtifactKind` declaration order so
        two runs harvest the same set in the same order.
    """
    declared = yields_of(test_method)
    if not declared:
        return []

    response = _evidence_text(evidence, _RESPONSE_PREFIX)
    request = _evidence_text(evidence, _REQUEST_PREFIX)
    if not response:
        return []

    harvested: list[ChainArtifact] = []

    def add(kind: ArtifactKind, value: str, label: str, how: str, principal: str = "") -> None:
        if not value or any(a.kind is kind and a.value == value for a in harvested):
            return
        harvested.append(
            ChainArtifact(
                kind=kind,
                value=value,
                label=label,
                principal=principal,
                source_finding_id=finding_id,
                source_test_method=test_method,
                obtained_by=how,
            )
        )

    for kind in ArtifactKind:
        if kind not in declared:
            continue

        if kind is ArtifactKind.CREDENTIAL:
            for cred in credentials_in(response):
                add(
                    kind,
                    cred.secret,
                    f"credential for {cred.identity or 'an unnamed principal'} "
                    f"from {finding_title}",
                    cred.how,
                    principal=cred.identity,
                )
        elif kind is ArtifactKind.SIGNING_KEY:
            for match in _KEY_RE.finditer(response):
                add(
                    kind,
                    match.group(0),
                    f"key material served by {target or 'the endpoint'}",
                    "a definite key-material shape (PEM block or vendor-prefixed key)",
                )
        elif kind is ArtifactKind.SESSION_TOKEN:
            for match in _TOKEN_RE.finditer(response):
                # Skip a token we ourselves sent: our own probe value returning is
                # the reflection phantom, one rung up.
                if match.group(0) in request:
                    continue
                add(
                    kind,
                    match.group(0),
                    f"session token issued at {target or 'the endpoint'}",
                    f"an opaque token in the response {finding_title} was confirmed on",
                )
        elif kind is ArtifactKind.INTERNAL_ENDPOINT:
            for match in _URL_RE.finditer(response):
                if is_internal_address(match.group(0)):
                    add(
                        kind,
                        match.group(0),
                        "an internal address named in the recovered content",
                        "a URL in a private, loopback or link-local address space",
                    )
        elif kind in (
            ArtifactKind.FILE_CONTENT,
            ArtifactKind.DB_RECORD,
            ArtifactKind.INTERNAL_RESPONSE,
            ArtifactKind.COMMAND_OUTPUT,
        ):
            add(
                kind,
                response[:MAX_CONTENT_CHARS],
                f"content recovered by {finding_title}",
                f"the response {test_method.removeprefix('_test_')} confirmed on",
            )
        elif kind in (ArtifactKind.IDENTITY, ArtifactKind.STORED_ARTIFACT):
            add(
                kind,
                target or finding_title,
                f"{kind.value} established by {finding_title}",
                f"the confirmed effect of {test_method.removeprefix('_test_')}",
            )
        # ADMIN_CAPABILITY yields no carriable value: the privilege is a property
        # of the account the application now holds, not something we take away
        # with us. Declared as a yield for planning visibility; harvested as
        # nothing, deliberately, so no chain can claim to carry it.

    return harvested[:MAX_ARTIFACTS_PER_FINDING]


__all__ = [
    "MAX_ARTIFACTS_PER_FINDING",
    "MAX_CONTENT_CHARS",
    "harvest_artifacts",
    "is_internal_address",
]
