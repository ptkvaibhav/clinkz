"""Credential intake and the process-wide redaction registry.

Two responsibilities, one file, because they are the same guarantee seen from
both ends:

  * **Intake** — :func:`load_credential_file` / :func:`prompt_for_credentials`
    are the only two ways an operator's password enters the process, and both
    register it as a secret on the way in.
  * **Redaction** — :func:`redact` / :func:`redact_structure` are applied at
    every writer that produces a durable artifact (trace, action log, report,
    state store), so a secret that reaches one of them by an unforeseen route is
    masked rather than written.

The PRIMARY guarantee is structural: passwords live in
:class:`~pydantic.SecretStr` on :class:`~clinkz.models.engagement.RoleCredential`,
the credential set is never attached to the persisted
:class:`~clinkz.models.scope.EngagementScope`, and no code path passes a
plaintext password to a writer. The registry here is the second layer — it
catches the route nobody thought of.

**Two definitions of "secret", not one.** Redaction removes a string because of
what it IS (a registered value) *and* because of what it LOOKS LIKE (a
credential shape — see :mod:`clinkz.engagement.credential_shapes`). Value-only
redaction is structurally incapable of removing the credential material an
engagement CAPTURES rather than supplies: a live run wrote five session JWTs
into ``trace.jsonl``, one of whose payload carried the account's password hash,
and every writer was already redacting correctly. Nothing was registered, so
nothing was removed. Shape redaction is always on, registry or not — an
artifact must be clean whether or not an engagement installed anything.

Order is deliberate: shapes run first, so a registered password that arrives
inside a session token disappears with the whole token rather than leaving a
partially-masked one behind.

**Honest limitation.** Value redaction is a substring replacement, so it can
only be applied to values long enough to be distinctive. A secret shorter than
:data:`_MIN_REDACTABLE_LEN` characters is accepted (we do not get to dictate the
client's password policy) but is NOT substring-redacted, because replacing every
occurrence of a two-character string would corrupt every artifact it appears in.
:func:`register_secret` returns ``False`` in that case and the loader warns, so
the gap is visible rather than silent.
"""

from __future__ import annotations

import json
import logging
import subprocess  # noqa: S404 — list-form, no shell=True; used for git hygiene checks
from pathlib import Path
from typing import Any

from clinkz.engagement.credential_shapes import (
    CREDENTIAL_HEADER_KEYS,
    redact_header_value,
    redact_shapes,
)
from clinkz.models.engagement import CredentialSet, RoleCredential

logger = logging.getLogger(__name__)

#: What a redacted secret is replaced with in any artifact.
REDACTION_PLACEHOLDER = "[REDACTED]"

#: Shortest secret we are willing to substring-redact. Below this, replacement
#: would destroy the surrounding artifact (see the module docstring).
_MIN_REDACTABLE_LEN = 4

#: Bounded timeout for the git hygiene checks.
_GIT_TIMEOUT = 5.0

#: Process-wide set of registered secrets. Ordered longest-first at redaction
#: time so a secret that contains another is masked before its substring is.
_SECRETS: set[str] = set()


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def register_secret(value: str) -> bool:
    """Register *value* for redaction in every artifact writer.

    Args:
        value: The plaintext secret.

    Returns:
        ``True`` when the value is long enough to be substring-redacted safely,
        ``False`` when it was accepted but is too short to redact (the caller
        should warn — see the module docstring).
    """
    if not value:
        return False
    if len(value) < _MIN_REDACTABLE_LEN:
        return False
    _SECRETS.add(value)
    return True


def registered_secret_count() -> int:
    """How many secrets are currently registered (never the values)."""
    return len(_SECRETS)


def clear_secrets() -> None:
    """Forget every registered secret.

    Called at engagement teardown and between tests so a secret cannot outlive
    the engagement that supplied it.
    """
    _SECRETS.clear()


def redact(text: str) -> str:
    """Replace credential shapes and every registered secret in *text*.

    Shapes first (see the module docstring), then registered values.

    Args:
        text: Arbitrary text about to be written to a durable artifact.

    Returns:
        *text* with credential material removed. Shape redaction applies
        whether or not anything is registered.
    """
    if not text:
        return text
    out = redact_shapes(text)
    if not _SECRETS:
        return out
    # Longest first: a secret that contains another must be masked before the
    # shorter one turns it into "[REDACTED]xyz".
    for secret in sorted(_SECRETS, key=len, reverse=True):
        if secret in out:
            out = out.replace(secret, REDACTION_PLACEHOLDER)
    return out


def redact_structure(obj: Any) -> Any:
    """Recursively redact every string inside *obj*.

    Handles the shapes an artifact writer actually serializes: ``dict``,
    ``list``, ``tuple``, ``set``, ``str``. Any other type is returned as-is
    (numbers, ``None``, Pydantic models — a model is dumped by its own writer
    before it reaches here).

    **Key-aware.** A value whose key is in
    :data:`~clinkz.engagement.credential_shapes.CREDENTIAL_HEADER_KEYS` is
    redacted on the strength of the key alone. This is the only way a
    ``Set-Cookie`` value can be caught: the target chose it, so it has no
    intrinsic shape, and the sole thing identifying it as the session is the
    header it arrived under. A header dict flattened to a string loses that,
    which is why the walker — not the string rule — makes this call.

    **The key rule reaches a LIST under that key, not only a bare string.**
    ``Set-Cookie`` is the one header a response legitimately sends more than
    once, so the producers that keep all of them keep them as a list
    (``HTTPClientOutput.set_cookie``, ``HopResponse.set_cookies``). Testing
    ``isinstance(value, str)`` alone would step straight past those into the
    generic walk, where each element meets only the SHAPE rules — and a session
    cookie the target named has no shape. The key is the whole of the evidence,
    so it has to survive the container.

    Args:
        obj: A JSON-ish structure.

    Returns:
        The same shape with strings redacted.
    """
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            new_key = redact_structure(key)
            if isinstance(key, str) and key.strip().lower() in CREDENTIAL_HEADER_KEYS:
                if isinstance(value, str):
                    out[new_key] = redact(redact_header_value(key, value))
                    continue
                if isinstance(value, (list, tuple)) and all(
                    isinstance(item, str) for item in value
                ):
                    redacted = [redact(redact_header_value(key, item)) for item in value]
                    out[new_key] = redacted if isinstance(value, list) else tuple(redacted)
                    continue
            out[new_key] = redact_structure(value)
        return out
    if isinstance(obj, list):
        return [redact_structure(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(redact_structure(v) for v in obj)
    if isinstance(obj, set):
        return {redact_structure(v) for v in obj}
    return obj


# ---------------------------------------------------------------------------
# Intake
# ---------------------------------------------------------------------------


class CredentialFileError(Exception):
    """Raised when a credential file is unusable or unsafe to read."""


def describe_credential_validation_error(exc: Exception) -> str:
    """Render a credential-file validation failure WITHOUT echoing the file.

    Pydantic's ``ValidationError`` stringifies each error with an
    ``input_value=`` fragment showing the data that failed. On every other
    model that is exactly what an operator needs. On this one it is a
    **plaintext password on stderr**::

        invalid credential set - 1 validation error for CredentialSet
          Value error, login_url belongs on each entry inside 'credentials' ...
          [type=value_error, input_value={'login_url': 'https://ap...S3cr3t-Real-Password'}]}]

    ``SecretStr`` cannot help here: the value is still a raw ``str`` in the
    input dict, because validation is what would have turned it into a
    ``SecretStr`` and validation is what failed. Neither can
    :func:`redact` — :func:`_register_all` runs only after a *successful*
    parse, so at this moment the chokepoint has never seen the password.

    The window is small and it is the only one there is, so it is closed by
    construction: this reads the ValidationError's STRUCTURED errors and quotes
    only ``loc``, ``msg`` and ``type``. The input is never touched, so no
    formatting choice downstream can put it back.

    Args:
        exc: The exception raised by ``CredentialSet.model_validate``.

    Returns:
        A message naming what is wrong and where, and nothing from the file.
    """
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        # Not a ValidationError. Its own message is ours, and no model
        # validator in this module puts a value into one.
        return str(exc)
    lines: list[str] = []
    try:
        for error in errors():
            where = ".".join(str(part) for part in error.get("loc", ())) or "(root)"
            lines.append(f"  {where}: {error.get('msg', '')} [{error.get('type', '')}]")
    except Exception:  # noqa: BLE001 — a redaction helper must never raise
        return "the credential file did not validate (details withheld: they would quote the file)"
    return "\n".join(lines) or str(type(exc).__name__)


def load_credential_file(path: Path | str) -> CredentialSet:
    """Load a credential set from an untracked local JSON file.

    Expected shape::

        {
          "credentials": [
            {"role": "admin", "username": "admin@example.com", "password": "..."},
            {"role": "user",  "username": "user@example.com",  "password": "..."},
            {"role": "anonymous"}
          ]
        }

    Refuses outright when the file is tracked by git: a credential file under
    version control is a leaked credential file, and the refusal must be a hard
    error rather than a warning that scrolls past. Warns (does not refuse) when
    the file is inside the repository but merely untracked — that is recoverable,
    an accidental ``git add`` away from not being.

    Every password read is registered for redaction.

    Args:
        path: Path to the JSON credential file.

    Returns:
        The parsed :class:`~clinkz.models.engagement.CredentialSet`.

    Raises:
        CredentialFileError: File missing, unreadable, malformed, or git-tracked.
    """
    cred_path = Path(path).expanduser()
    if not cred_path.is_file():
        raise CredentialFileError(f"Credential file not found: {cred_path}")

    if _is_git_tracked(cred_path):
        raise CredentialFileError(
            f"Refusing to read {cred_path}: the file is tracked by git. "
            "A credential file under version control is a leaked credential file. "
            "Move it outside the repository (or add it to .gitignore and "
            "`git rm --cached` it) and re-run."
        )
    if _is_inside_repo(cred_path) and not _is_git_ignored(cred_path):
        logger.warning(
            "Credential file %s is inside the repository and is NOT gitignored — "
            "one `git add .` away from being committed. Prefer a path outside the repo.",
            cred_path,
        )

    try:
        raw = json.loads(cred_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CredentialFileError(f"Could not read credential file {cred_path}: {exc}") from exc

    if not isinstance(raw, dict) or not isinstance(raw.get("credentials"), list):
        raise CredentialFileError(f"{cred_path}: expected a JSON object with a 'credentials' list")

    try:
        cred_set = CredentialSet.model_validate(raw)
    except Exception as exc:  # noqa: BLE001 — surfaced as a setup error, not swallowed
        # NOT f"{exc}". Pydantic's stringified ValidationError carries an
        # ``input_value=`` echo of the data that failed, and the data that
        # failed is a credential file — so the plaintext password lands on
        # stderr, which `clinkz scan` prints verbatim. See
        # describe_credential_validation_error for why neither SecretStr nor
        # redact() can help at this point.
        detail = describe_credential_validation_error(exc)
        raise CredentialFileError(
            f"{cred_path}: invalid credential set —{chr(10)}{detail}"
        ) from None

    _register_all(cred_set)
    logger.info(
        "Loaded %d credential set(s) from %s — roles: %s",
        len(cred_set.credentials),
        cred_path,
        ", ".join(cred_set.roles) or "(none)",
    )
    return cred_set


def prompt_for_credentials(roles: list[str]) -> CredentialSet:
    """Collect credentials interactively, reading passwords without echo.

    Args:
        roles: Role labels to prompt for, in order.

    Returns:
        The assembled credential set. A role left with a blank username is
        recorded as the anonymous baseline rather than dropped.
    """
    import getpass

    entries: list[RoleCredential] = []
    for role in roles:
        label = role.strip() or "user"
        username = input(f"[{label}] username (blank = anonymous): ").strip()
        if not username:
            entries.append(RoleCredential(role=label))
            continue
        password = getpass.getpass(f"[{label}] password: ")
        entries.append(RoleCredential(role=label, username=username, password=password))

    cred_set = CredentialSet(credentials=entries)
    _register_all(cred_set)
    return cred_set


def _register_all(cred_set: CredentialSet) -> None:
    """Register every secret in *cred_set*, warning about unredactable ones."""
    for cred in cred_set.credentials:
        secret = cred.secret()
        if not secret:
            continue
        if not register_secret(secret):
            logger.warning(
                "Credential for role '%s' is shorter than %d characters — it is "
                "accepted but CANNOT be substring-redacted from artifacts. "
                "Artifacts are still not written with credentials by design; this "
                "only disables the second layer.",
                cred.role,
                _MIN_REDACTABLE_LEN,
            )


# ---------------------------------------------------------------------------
# git hygiene helpers — bounded, list-form, never raise
# ---------------------------------------------------------------------------


def _git(args: list[str], cwd: Path) -> int | None:
    """Run a git command and return its exit code, or ``None`` if git is absent."""
    try:
        result = subprocess.run(  # noqa: S603 — list-form, no shell
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    return result.returncode


def _is_git_tracked(path: Path) -> bool:
    """Whether *path* is tracked by the git repo containing it."""
    code = _git(["ls-files", "--error-unmatch", "--", path.name], path.parent)
    return code == 0


def _is_git_ignored(path: Path) -> bool:
    """Whether *path* is matched by a gitignore rule."""
    code = _git(["check-ignore", "-q", "--", path.name], path.parent)
    return code == 0


def _is_inside_repo(path: Path) -> bool:
    """Whether *path* lives inside a git working tree."""
    return _git(["rev-parse", "--is-inside-work-tree"], path.parent) == 0


__all__ = [
    "REDACTION_PLACEHOLDER",
    "CredentialFileError",
    "clear_secrets",
    "describe_credential_validation_error",
    "load_credential_file",
    "prompt_for_credentials",
    "redact",
    "redact_structure",
    "register_secret",
    "registered_secret_count",
]
