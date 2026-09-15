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

**A registration is scoped to where the secret can appear, and a colliding one
is refused before it is taken.** Replacement is unconditional and process-wide,
so a registration's blast radius is every artifact written while it is armed.
Two rules keep that radius honest, and they address the two sources separately
because the sources are different:

* **Lifetime** (:func:`provisional_secret`) — a default-credential guess is
  public until it works, so it is armed for the attempt and released on failure.
  Registering one for the whole run substring-replaced an ordinary English word
  out of 711,918 sites on one cal.diy engagement, including the URL
  ``/auth/forgot-password`` and an LFI oracle's own ``root:x:0:0:`` marker.
* **Spelling** (:func:`register_credential_set`) — an operator credential that
  is a word the engine's own models declare is REFUSED at intake, naming the
  colliding key. Such a value would rewrite the engine's schema out of its own
  dumps, and a dump a model rejects is no report at all. The vocabulary is
  computed in :mod:`clinkz.engagement.schema_vocabulary`, never hand-listed.

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
import re
import subprocess  # noqa: S404 — list-form, no shell=True; used for git hygiene checks
from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from clinkz.engagement.credential_shapes import (
    CREDENTIAL_HEADER_KEYS,
    redact_header_value,
    redact_shapes,
)
from clinkz.engagement.schema_vocabulary import (
    SchemaCollision,
    collisions,
    declared_enum_values,
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

#: Process-wide registry of secrets, ``value -> live registration count``.
#: Ordered longest-first at redaction time so a secret that contains another is
#: masked before its substring is.
#:
#: **Counted, not a set.** Two sources register independently — the operator's
#: credential file and the default-credential sweep's catalogue — and they can
#: register the same string. A plain set makes the sweep's release on a failed
#: guess remove the operator's registration, which is the redaction layer going
#: silently off for the rest of the run. A count releases only the registration
#: its own caller took.
_SECRETS: dict[str, int] = {}


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
        should warn — see the module docstring). A ``False`` return takes no
        registration, so it must not be released.
    """
    if not value:
        return False
    if len(value) < _MIN_REDACTABLE_LEN:
        return False
    _SECRETS[value] = _SECRETS.get(value, 0) + 1
    return True


def release_secret(value: str) -> bool:
    """Drop ONE registration of *value*, leaving any other source's intact.

    The counterpart to :func:`register_secret`, and the mechanism behind
    :func:`provisional_secret`. Releasing a value nobody registered is a no-op
    rather than an error: a caller that got ``False`` from
    :func:`register_secret` (too short) and released anyway is not a bug.

    Args:
        value: The plaintext secret to release.

    Returns:
        ``True`` when this call removed the last registration and the value is
        no longer redacted, ``False`` otherwise.
    """
    count = _SECRETS.get(value)
    if count is None:
        return False
    if count > 1:
        _SECRETS[value] = count - 1
        return False
    del _SECRETS[value]
    return True


def is_registered(value: str) -> bool:
    """Whether *value* is currently redacted from artifacts."""
    return value in _SECRETS


def registered_secret_count() -> int:
    """How many distinct secrets are currently registered (never the values)."""
    return len(_SECRETS)


def clear_secrets() -> None:
    """Forget every registered secret.

    Called at engagement teardown and between tests so a secret cannot outlive
    the engagement that supplied it.
    """
    _SECRETS.clear()


class ProvisionalSecret:
    """The handle :func:`provisional_secret` yields.

    Call :meth:`keep` to convert the provisional registration into a permanent
    one. Anything else — falling off the end of the block, an early ``return``,
    an exception — releases it.
    """

    __slots__ = ("_value", "_registered", "_kept")

    def __init__(self, value: str) -> None:
        self._value = value
        self._registered = False
        self._kept = False

    @property
    def registered(self) -> bool:
        """Whether the value was long enough to be registered at all."""
        return self._registered

    def keep(self) -> None:
        """Promote this registration to a permanent one."""
        self._kept = True

    def _arm(self) -> None:
        self._registered = register_secret(self._value)

    def _disarm(self) -> None:
        if self._registered and not self._kept:
            release_secret(self._value)


@contextmanager
def provisional_secret(value: str) -> Iterator[ProvisionalSecret]:
    """Register *value* for the duration of the block, and only that long.

    **A registered secret is scoped to where it can appear, not matched
    globally.** Substring replacement is unconditional and process-wide, so a
    registration's blast radius is every artifact written while it is armed —
    and for a value that is a word rather than a password, that is the whole
    run. Measured on engagement ``92c89d0d`` (cal.diy): the default-credential
    sweep registered its catalogue, and **711,918** replacements landed inside a
    longer string, overwhelmingly in the target's own i18n bundle, where
    ``admin`` appears in ordinary English prose. It also rewrote 6,227 copies of
    the URL ``/auth/forgot-password``, an LFI oracle's ``root:x:0:0:`` marker,
    and a command-injection payload — none of which was written anywhere near a
    credential POST.

    The registration itself is right; its LIFETIME was wrong. A catalogue
    password is public until it WORKS, so the window in which it can leak is the
    attempt: the credential POST and the artifacts that attempt writes. Arm it
    before the POST, release it after, and on the attempt that succeeds call
    :meth:`ProvisionalSecret.keep` — at that moment it stops being a public
    default and becomes a live credential for the client's system, which is
    exactly what the disclosure gate exists to keep out of an artifact.

    Args:
        value: The plaintext secret, armed for the block.

    Yields:
        A :class:`ProvisionalSecret` handle.
    """
    handle = ProvisionalSecret(value)
    handle._arm()
    try:
        yield handle
    finally:
        handle._disarm()


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


#: A redaction marker as it appears in already-redacted text — ``[REDACTED]`` and
#: the labelled forms. Used to ask whether a redaction consumed the WHOLE of a
#: string or only part of it.
#:
#: One level of nesting is allowed, because the labelled forms carry a bracketed
#: field of their own: a JWT redacts to
#: ``[REDACTED:JWT sha256=… alg=HS256 claims=[sub]]``. A pattern that stopped at
#: the first ``]`` would leave the outer bracket as residue and read a key that
#: was nothing but a token as schema.
_REDACTION_SPAN_RE: Final = re.compile(r"\[REDACTED(?:[^\[\]]|\[[^\]]*\])*\]")


def _redact_key(key: Any) -> Any:
    """Redact a dict KEY only when the key is credential material END TO END.

    **A key is schema; a value is data.** This is the same rule the IDOR oracle
    states about attribution — the field NAME survives because it is schema — and
    it was missing here, where it does the most damage.

    The default-credential sweep registers each password it is about to try, so
    that one which WORKS is not left in an artifact in plaintext. The catalogue
    contains ``test``, ``root``, ``admin`` and ``password``. Registered secrets
    are replaced as SUBSTRINGS, and the walker was passing keys through the same
    replacement, so on every run where that sweep fired:

    * ``test_start`` became ``[REDACTED]_start`` and ``test_end`` became
      ``[REDACTED]_end``, so ``PentestReport.model_validate`` rejected the
      redacted structure for two missing required fields and **no report.json,
      no Markdown and no PDF were written at all**;
    * ``test_method`` became ``[REDACTED]_method`` and every ``_test_sqli`` key
      became ``_[REDACTED]_sqli``, so the class identity that
      ``regrade_stored_bundles.py``, ``corpus-replay`` and the plan-coverage
      account all key on was destroyed in the trace.

    A guard that damages the artifact it protects protects nothing. The fix is
    not to stop redacting keys — a dict genuinely keyed BY a token should still
    be redacted — but to require that the whole key was credential material.
    ``test_start`` merely CONTAINS a registered word and is schema with an
    unlucky substring; a key that is nothing but a JWT is not schema.

    Values are untouched by this: they are data and keep substring redaction.

    **One REGISTRY span, not "no residue".** The first version of this rule asked
    only whether anything survived the markers, and that is satisfied by a key two
    separate registrations happen to TILE. Found by the positive control over
    the report model's own key vocabulary: with ``test``, ``_end``, ``find``
    and ``ings`` registered, ``test_end`` and ``findings`` both render
    ``[REDACTED][REDACTED]`` — so they are not merely lost, they COLLIDE into
    one key and one of the two values is silently discarded. A key that is
    credential material is credential material *once*.

    Only the value registry can tile by coincidence; a SHAPE span cannot, because
    it is an intrinsic-structure claim and no schema vocabulary here is spelled
    like a JWT or a PEM block. So the count is over registry spans alone, which
    are separable by inspection: every shape replacement carries the labelled
    ``[REDACTED:`` marker and the registry always writes the bare
    ``[REDACTED]``.

    **The residual hazard, stated.** A key that genuinely is two concatenated
    REGISTERED VALUES now survives verbatim — no producer in this tree builds
    one, and shape-bearing keys are unaffected. That direction is chosen
    deliberately: over 4,173 stored reports and 600 traces, a key wholly consumed
    by redaction occurs **zero** times, while the over-redaction direction cost
    every deliverable on every sweeping run. Keeping a key is recoverable; a
    report that was never written is not.

    Args:
        key: The dict key, of any type.

    Returns:
        The key, or the redacted form when the redaction consumed the key in its
        entirety without more than one registry span doing it.
    """
    if not isinstance(key, str):
        return key
    redacted = redact(key)
    if redacted == key:
        return key
    # Did the redaction consume the whole key, or just a piece of it? What is
    # left after every marker is removed is the part that was NOT credential
    # material. Anything left means the key is schema.
    residue = _REDACTION_SPAN_RE.sub("", redacted).strip()
    if residue:
        return key
    # Nothing survived the markers — but by HOW MANY redactions? Two or more
    # REGISTRY spans mean the key was TILED by separate registrations, which is a
    # coincidence of spellings rather than a key that is credential material. It
    # is not merely lossy either, it COLLIDES: with ``test``, ``_end``, ``find``
    # and ``ings`` registered, ``test_end`` and ``findings`` both render
    # ``[REDACTED][REDACTED]``, so two fields merge into one and one of the two
    # values is silently discarded.
    #
    # Only registry spans can tile by coincidence. A SHAPE span is an intrinsic-
    # structure claim — a JWT, a PEM block, an `Authorization` value — and no
    # schema vocabulary in this tree is spelled like one, so any number of them
    # consuming the whole key still means the key is data. Every shape
    # replacement carries the labelled marker ``[REDACTED:`` and the value
    # registry always writes the bare ``[REDACTED]``, so the two are separable by
    # inspection rather than by provenance tracking.
    registry_spans = sum(
        1 for span in _REDACTION_SPAN_RE.findall(redacted) if span == REDACTION_PLACEHOLDER
    )
    return key if registry_spans > 1 else redacted


@lru_cache(maxsize=1)
def _engine_vocabulary() -> frozenset[str]:
    """Closed-vocabulary words the ENGINE writes, long enough to be registerable.

    Computed from the models, same source as the intake refusal. Values shorter
    than :data:`_MIN_REDACTABLE_LEN` are excluded because no registration can
    match inside one, so protecting them would be protection against nothing.
    """
    return frozenset(value for value in declared_enum_values() if len(value) >= _MIN_REDACTABLE_LEN)


def _redact_leaf(value: str) -> Any:
    """Redact a string LEAF of a structure — the value side of the key rule.

    **A closed vocabulary the engine declares is schema wherever it sits, in a
    key or in a value.** :func:`_redact_key` says a key is schema; this says the
    same about the one kind of value that is also schema. An enum-constrained
    field does not carry data the target chose — it carries a word from a list
    this codebase wrote — and rewriting one makes the model reject the document
    it belongs to.

    That is not hypothetical and it is not the key failure wearing a new coat.
    ``PentestReport`` declares ``medium_count``, so a control registering the
    first four characters of every declared field name registers ``medi``;
    ``medi`` is a substring of the VALUE ``"medium"`` that ``Finding.severity``
    carries; substring redaction makes it ``"[REDACTED]um"``; and the enum
    refuses it. No report.json, no Markdown, no PDF — the same total outage the
    key fix closed, reached by a route the key fix cannot see, because nothing
    here is a key.

    **The match is EXACT, never containment.** A leaf that merely contains an
    enum word is ordinary data — a response body, a log line, an operator's
    note — and keeps substring redaction in full. Only a leaf that is nothing
    but one of the engine's own words is exempt, and such a leaf has no room to
    be carrying anything else.

    **The residual hazard, stated.** A value the engine registered as a secret
    and which is EXACTLY one of the 152 registerable enum words now survives in
    an artifact. An operator credential cannot reach that state — a credential
    that spells one of these is refused at intake by
    :func:`register_credential_set`, which is the other half of this rule and
    why the two landed together. What remains is a secret DISCOVERED mid-run
    (``exploit.py`` registers a found artifact's value) whose whole value is a
    word like ``bash`` or ``HS256``. That is a four-to-six character "secret",
    which the module docstring already declares as the honest gap in value
    redaction, and it is weighed against an outage that has been observed.

    Args:
        value: One string leaf of a structure being redacted.

    Returns:
        The leaf, redacted, or unchanged when it is the engine's own vocabulary.
    """
    if value in _engine_vocabulary():
        return value
    return redact(value)


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
        return _redact_leaf(obj)
    if isinstance(obj, dict):
        out: dict[Any, Any] = {}
        for key, value in obj.items():
            # A key is SCHEMA — see :func:`_redact_key`. It used to go through the
            # same substring replacement as a value, which is how the word
            # ``test``, registered by the default-credential sweep, turned
            # ``test_start`` into ``[REDACTED]_start`` and took the whole report
            # down with it.
            new_key = _redact_key(key)
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


class CredentialCollisionError(CredentialFileError):
    """Raised when a credential is a word the engine's own schema declares.

    A subclass of :class:`CredentialFileError` so every existing intake caller
    already surfaces it as a setup error with exit code 2 — this is bad input,
    caught before the engagement opens, and there is nothing to retry.
    """


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
    :func:`redact` — :func:`register_credential_set` runs only after a *successful*
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

    register_credential_set(cred_set)
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
    register_credential_set(cred_set)
    return cred_set


def _collision_refusal(role: str, found: tuple[SchemaCollision, ...]) -> str:
    """The refusal message, naming the colliding key and the change that fixes it."""
    lines = [
        f"Refusing the engagement: the credential for role '{role}' is a word the "
        "engine's own schema declares.",
        "",
        "  It collides with:",
    ]
    lines += [f"    - {collision.describe()}" for collision in found]
    lines += [
        "",
        "  Why this is a refusal and not a warning: every registered secret is "
        "replaced as a SUBSTRING in every artifact the engine writes, and the "
        "engine's artifacts are dumps of its own models. A redaction that lands on "
        "schema rather than on data removes part of the structure, and the line "
        "above says which - a rejected dump means the run ends with no deliverable "
        "at all, a deleted key means an artifact that writes with a field missing. "
        "Neither has a symptom before the end of the run, which is why this is "
        "caught here and not at render time.",
        "",
        "  The change that resolves it: give this account a password that is not "
        "one of the words above. Any value that is not exactly a field name the "
        "engine declares, and not a substring of one of its enum values, is "
        "accepted - which is every password that is not an English word this "
        "codebase happens to spell.",
        "",
        "  There is deliberately no flag to skip this. The alternative to changing "
        "the password is registering it anyway, and that is the run that produces "
        "no report.",
    ]
    return "\n".join(lines)


def register_credential_set(cred_set: CredentialSet) -> None:
    """Register every secret in *cred_set* with the redaction chokepoint.

    Public because it has a second caller: a validation driver that constructs a
    :class:`~clinkz.models.engagement.CredentialSet` in code rather than loading
    one from a file gets no registration, and every artifact the run writes then
    carries the plaintext. Measured — ``scripts/live_adaptive_auth_validation.py``
    left ``"password": "pro"`` in 28 lines of its own ``actions.jsonl``, because
    the action log's body excerpt is redacted by VALUE and no value had been
    registered.

    ``load_credentials`` calls it; so must anything else that assembles a
    credential set and then makes requests with it. It is the same rule the
    ``scripts/_artifact_io.py`` split encodes one layer out: the engine's
    redaction reaches only where the engine was told what to redact.

    **This is also where a colliding credential is refused, and the refusal is at
    INTAKE rather than at render time.** A credential that is a word the engine's
    own schema declares will, once registered, rewrite that schema out of the
    structures the engine dumps — and the two ways it does that both end in
    ``model_validate`` rejecting the document, which writes no report.json, no
    Markdown and no PDF. Discovering that at render time means discovering it
    after a full engagement has run; discovering it here costs the operator one
    password change before a single packet leaves. The vocabulary is COMPUTED
    from the models themselves
    (:mod:`clinkz.engagement.schema_vocabulary`), so it is not a list to keep
    current.

    Nothing is registered unless every credential passes: a refusal must leave
    the registry exactly as it found it, or a caller that catches the error is
    running with half a credential set armed.

    Raises:
        CredentialCollisionError: A credential collides with the engine's own
            declared field names or enum vocabularies.
    """
    for cred in cred_set.credentials:
        secret = cred.secret()
        if not secret or len(secret) < _MIN_REDACTABLE_LEN:
            # Too short to be registered at all, so too short to corrupt
            # anything. The warning for that case is below, on the same branch
            # that declines to register it.
            continue
        found = collisions(secret)
        if found:
            raise CredentialCollisionError(_collision_refusal(cred.role, found))

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
    "CredentialCollisionError",
    "CredentialFileError",
    "ProvisionalSecret",
    "clear_secrets",
    "describe_credential_validation_error",
    "is_registered",
    "load_credential_file",
    "prompt_for_credentials",
    "provisional_secret",
    "redact",
    "redact_structure",
    "register_credential_set",
    "register_secret",
    "registered_secret_count",
    "release_secret",
]
