"""Turning operator command-line input into validated engagement models.

Everything ``clinkz scan`` must decide *before* an engagement exists: what the
target string names, which entries are in and out of scope, and whether the
operator supplied a complete authorization record. Kept out of :mod:`clinkz.cli`
so it is pure and directly testable — a Typer callback is awkward to exercise,
and these are exactly the decisions that must not be exercised only by hand.

Three rules run through all of it:

  * **Classification is explicit, never inferred from what parses first.** A
    target is a URL, a CIDR block, an IP, or a hostname, and the answer is
    derived once here rather than re-derived at each call site.
  * **A refusal names every missing field at once.** An operator assembling an
    authorization record from six flags should be told all six that are absent,
    not made to rediscover them one run at a time. This mirrors
    :class:`~clinkz.models.engagement.AuthorizationRecord`, which has no
    partially-populated shape.
  * **Nothing here reads a secret.** Credential intake is
    :mod:`clinkz.engagement.secrets`, which registers what it reads for
    redaction. A password must not have a second entry point that does not.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from clinkz.models.engagement import (
    BENCHMARK_ACKNOWLEDGEMENT,
    AuthorizationRecord,
    BenchmarkProfile,
)
from clinkz.models.scope import ScopeEntry, ScopeType

#: Schemes a target string may carry. Anything else (``file://``, ``ftp://``)
#: is refused rather than silently treated as a hostname — the engine speaks
#: HTTP, and an operator who typed a scheme meant it.
_SUPPORTED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


class ScanInputError(ValueError):
    """An operator-supplied value could not be turned into an engagement input.

    Carries a message written for the person at the terminal: what was wrong,
    and what to pass instead.
    """


# ---------------------------------------------------------------------------
# Targets and scope entries
# ---------------------------------------------------------------------------


def classify_target(value: str) -> ScopeType:
    """Classify a target string as a URL, CIDR block, IP address, or hostname.

    Order matters and is deliberate. A scheme wins outright — ``http://10.0.0.1``
    is a URL, not an IP, because the port and path are part of what the operator
    named. A ``/`` with no scheme means a CIDR block. Everything else is offered
    to the IP parser and falls through to hostname.

    Args:
        value: The raw ``--target`` / ``--scope`` / ``--exclude`` value.

    Returns:
        The matching :class:`~clinkz.models.scope.ScopeType`.

    Raises:
        ScanInputError: The value is blank, carries an unsupported scheme, or is
            a ``/``-bearing string that is not a valid network.
    """
    cleaned = (value or "").strip()
    if not cleaned:
        raise ScanInputError("a target cannot be blank")

    if "://" in cleaned:
        parsed = urlparse(cleaned)
        if parsed.scheme not in _SUPPORTED_SCHEMES:
            raise ScanInputError(
                f"unsupported scheme '{parsed.scheme}://' in {cleaned!r}. "
                f"Clinkz tests HTTP services: use http:// or https://, or pass a "
                f"bare hostname / IP."
            )
        if not parsed.hostname:
            raise ScanInputError(f"{cleaned!r} has no host — expected e.g. https://app.example.com")
        return ScopeType.URL

    if "/" in cleaned:
        try:
            ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise ScanInputError(
                f"{cleaned!r} contains '/' so it was read as a CIDR block, and it is "
                f"not a valid one ({exc}). For a URL include the scheme "
                f"(https://{cleaned})."
            ) from None
        return ScopeType.CIDR

    try:
        ipaddress.ip_address(cleaned)
    except ValueError:
        return ScopeType.DOMAIN
    return ScopeType.IP


def make_scope_entry(value: str, *, notes: str = "") -> ScopeEntry:
    """Build a classified :class:`ScopeEntry` from a raw operator string.

    Args:
        value: Raw target string.
        notes: Optional free-text note recorded against the entry (rendered in
            the report's scope section).

    Returns:
        The classified entry.

    Raises:
        ScanInputError: The value could not be classified.
    """
    return ScopeEntry(value=value.strip(), type=classify_target(value), notes=notes)


def looks_like_scope_file(value: str) -> bool:
    """Whether *value* names an existing file rather than a scope entry.

    ``--scope`` accepts both a JSON scope document and a literal in-scope entry,
    so the two have to be told apart. Existence on disk is the test, not the
    suffix: a hostname is never a file that exists, and a scope file the operator
    mistyped should fail as a missing file rather than be quietly scanned as a
    hostname called ``scope.jsno``.

    Args:
        value: The raw ``--scope`` value.

    Returns:
        ``True`` when the value resolves to an existing file.
    """
    text = (value or "").strip()
    if not text or "://" in text:
        return False
    try:
        return Path(text).expanduser().is_file()
    except OSError:
        # A string long enough or malformed enough to upset the OS path layer is
        # not a file; treat it as an entry and let classification reject it.
        return False


def names_a_scope_document(value: str) -> bool:
    """Whether *value* was clearly MEANT as a scope file, whether or not it exists.

    The test is a ``.json`` suffix and nothing else. ``.json`` is not a TLD, so no
    legitimate host is spelled that way, and an operator who typed it meant a
    file. A missing one must be an error naming the file — a mistyped
    ``--scope scpoe.json`` would otherwise classify cleanly as a *hostname* and
    the engagement would go and scan it.

    Deliberately NOT "contains a path separator": ``10.10.10.0/24`` is a CIDR
    block, and a slash heuristic here refuses the single most ordinary way to
    name a network range.

    Args:
        value: The raw ``--scope`` value.

    Returns:
        ``True`` when the value names a JSON document.
    """
    text = (value or "").strip()
    if not text or "://" in text:
        return False
    return text.lower().endswith(".json")


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationFlags:
    """The authorization record as six command-line flags.

    Mirrors :class:`~clinkz.models.engagement.AuthorizationRecord` field for
    field. Held as a dataclass rather than passed as six positional arguments so
    :meth:`any_supplied` can answer "did the operator start filling this in?" —
    the question that separates "no flags, look elsewhere for the record" from
    "half the flags, refuse and say which half".
    """

    party: str = ""
    role: str = ""
    contact: str = ""
    reference: str = ""
    techniques: tuple[str, ...] = ()
    emergency: str = ""
    notes: str = ""

    def any_supplied(self) -> bool:
        """Whether the operator supplied any authorization flag at all."""
        return bool(
            self.party.strip()
            or self.role.strip()
            or self.contact.strip()
            or self.reference.strip()
            or [t for t in self.techniques if t.strip()]
            or self.emergency.strip()
        )


#: Flag name ↔ human label for each required authorization field, in the order
#: an operator would be asked for them.
_AUTH_FIELDS: tuple[tuple[str, str, str], ...] = (
    ("party", "--auth-party", "legal name of the person authorizing this test"),
    ("role", "--auth-role", "their role or title (the basis of their authority)"),
    ("contact", "--auth-contact", "a reachable contact for them"),
    ("reference", "--auth-ref", "the contract / SOW / ticket reference"),
    ("techniques", "--auth-technique", "a permitted technique (repeatable; '*' for all)"),
    ("emergency", "--auth-emergency", "who to call the moment something goes wrong"),
)


def authorization_from_flags(flags: AuthorizationFlags) -> AuthorizationRecord:
    """Assemble an :class:`AuthorizationRecord` from command-line flags.

    Args:
        flags: The supplied flag values.

    Returns:
        The validated record.

    Raises:
        ScanInputError: One or more required fields are missing. The message
            names **every** missing flag, because discovering them one run at a
            time is the same refusal delivered six times.
    """
    missing = [
        (flag, description)
        for attr, flag, description in _AUTH_FIELDS
        if not (
            [t for t in flags.techniques if t.strip()]
            if attr == "techniques"
            else str(getattr(flags, attr)).strip()
        )
    ]
    if missing:
        lines = [f"  {flag:<20} {description}" for flag, description in missing]
        raise ScanInputError(
            "Incomplete authorization record — these flags are required and were "
            "not supplied:\n"
            + "\n".join(lines)
            + "\n\nAn engagement without a named authorizing party is not an "
            "engagement. Supply the missing flags, pass a complete record with "
            "--authorization <file.json>, or run --auth-prompt to be asked for "
            "them interactively."
        )

    try:
        return AuthorizationRecord(
            authorizing_party=flags.party.strip(),
            authorizing_role=flags.role.strip(),
            authorizing_contact=flags.contact.strip(),
            authorization_reference=flags.reference.strip(),
            permitted_techniques=[t.strip() for t in flags.techniques if t.strip()],
            emergency_contact=flags.emergency.strip(),
            notes=flags.notes.strip(),
        )
    except ValueError as exc:
        raise ScanInputError(f"Invalid authorization record: {exc}") from None


def load_authorization_file(path: Path) -> AuthorizationRecord:
    """Load and validate an authorization record from a JSON file.

    Args:
        path: Path to the record.

    Returns:
        The validated record.

    Raises:
        ScanInputError: The file is missing, unreadable, or does not carry a
            complete record.
    """
    try:
        raw = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScanInputError(f"Authorization file not found: {path}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanInputError(f"Could not read the authorization file {path}: {exc}") from None
    try:
        return AuthorizationRecord.model_validate(raw)
    except ValueError as exc:
        raise ScanInputError(f"Invalid authorization record in {path}:\n{exc}") from None


def load_benchmark_profile(path: Path) -> BenchmarkProfile:
    """Load and validate a benchmark profile from a JSON file.

    A file rather than flags on purpose. The profile requires
    :data:`~clinkz.models.engagement.BENCHMARK_ACKNOWLEDGEMENT` reproduced
    verbatim, and a sentence that long typed at a shell prompt would be
    copy-pasted from documentation without being read — which is the one thing
    the attestation exists to prevent. Written into a file the operator authored,
    it is a deliberate act with a record.

    Args:
        path: Path to the profile.

    Returns:
        The validated profile.

    Raises:
        ScanInputError: The file is missing, unreadable, or the profile is not
            fully explicit.
    """
    try:
        raw = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ScanInputError(f"Benchmark profile not found: {path}") from None
    except (OSError, json.JSONDecodeError) as exc:
        raise ScanInputError(f"Could not read the benchmark profile {path}: {exc}") from None
    try:
        return BenchmarkProfile.model_validate(raw)
    except ValueError as exc:
        raise ScanInputError(
            f"Invalid benchmark profile in {path}:\n{exc}\n\n"
            "A benchmark profile has no partial shape. It must set "
            "'target_is_throwaway': true, reproduce the attestation verbatim:\n"
            f"  {BENCHMARK_ACKNOWLEDGEMENT}\n"
            "and name each permitted destructive category, a declaring party, and "
            "a reference."
        ) from None


__all__ = [
    "AuthorizationFlags",
    "ScanInputError",
    "authorization_from_flags",
    "classify_target",
    "load_authorization_file",
    "load_benchmark_profile",
    "looks_like_scope_file",
    "names_a_scope_document",
    "make_scope_entry",
]
