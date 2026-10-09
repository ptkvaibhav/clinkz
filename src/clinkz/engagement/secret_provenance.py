"""Is THIS occurrence of a registered secret the secret? Decided by provenance.

Register R30. The value registry used to replace every registered string as a
SUBSTRING of every string the engine wrote. For a password that is an ordinary
word that is a different operation from redaction: engagement ``e7bd146a`` (DVWA,
``admin``/``password``) completed with the disclosure gate CLEAN and the bundle
damaged — ``password_new`` became ``[REDACTED]_new`` in the client-facing CSRF
evidence, 218 captured pages lost ``type="password"`` (so ``corpus-replay`` read
DVWA's login page as having no login form), and the brute-force class's own
probe ``wrongpassword0`` was recorded as ``wrong[REDACTED]0``. The record of
what was sent was no longer what was sent.

The question a substring match answers — "does this text contain these
characters?" — is not the question redaction exists to answer, which is "did
the secret get here?". This module answers the second one, per occurrence, from
where the occurrence sits and where the text came from:

1. **Inside a longer identifier, it is not the value.** ``password_new`` is a
   different string from ``password``; an occurrence glued to identifier
   characters (``[A-Za-z0-9_]``, or a hyphen joining two of them) is a substring
   of some other token. Escape sequences (``\\n``, ``\\u0022``, ``%22``) are
   separators, not identifier characters — an echo after an encoded quote is
   still an echo.
2. **In a NAME position it is schema.** ``password=…`` and ``"password": …``
   name a field; the engine's request and the target's form both spell their
   field names, and invariant 13 says names survive.
3. **As the VALUE of a credential-named field it is redacted, unconditionally.**
   ``password=password`` in a request body the engine constructed is exactly the
   placement redaction exists for, whatever any control says.
4. **Anywhere else, it is kept only on positive evidence that the TARGET or the
   ENGINE authored it**: the same unit appeared in a response the target served
   *without the credential* (the login page's anonymous GET, or any
   ``session_mode='none'`` request — see :func:`control_units`); it is an HTML
   ``type=`` keyword (the HTML specification's closed vocabulary, not data); or
   it sits inside a string literal of the engine's own source. Absent all three
   it is redacted — the default is the secret, so a rule that fails to fire
   fails CLOSED.

**The control is per UNIT, not per page, and that is the honest granularity.**
A writer seam (trace, action log, invocation record, report) receives a string
with no page attached, so "the same page fetched anonymously" cannot be asked
there. What can be asked is whether the target ever served this exact unit —
``type="password"``, ``name="password"``, or a bare word together with its two
neighbouring tokens — to a request that did not carry the secret. A reflected
echo is a unit the anonymous target never produced: ``value="password"``,
``<td>password</td>``, ``"pw":"password"``. Those stay redacted, and the
positive control in ``tests/test_engagement/test_secret_provenance.py`` is red
with the control rule removed.

**Residual, stated.** (a) A secret the target glues to identifier characters is
not redacted (rule 1) — a server concatenating a password into a longer token
is the case, and none is known. (b) A secret the target served ANONYMOUSLY in
the same unit is kept (rule 4) — a public page publishing the credential in
prose is a finding about the target, and its value is already public there.
Neither weakens shape redaction, which runs first and is unaffected.

Pure: no registry, no I/O except reading the engine's own source once.
"""

from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path
from typing import Final

#: Characters that continue an identifier. A registered value with one of these
#: on either side (where its own edge character is one too) is part of a longer
#: token, not an occurrence of the value.
_IDENT: Final = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")

#: Characters that end a unit. Whitespace, markup brackets, and the delimiters
#: of query strings, JSON and argument lists. ``=`` and ``:`` are NOT here: they
#: join a name to its value inside one unit, and rule 2/3 read that join.
_UNIT_SEPARATORS: Final = frozenset(" \t\r\n<>&,;(){}[]|?")

#: An escape sequence immediately before an occurrence. The last character of
#: one is an identifier character (``n``, ``2``…) but it encodes a separator, so
#: an occurrence after it is NOT glued to anything.
_ESCAPE_BEFORE: Final = re.compile(r"(?:\\[nrtbf\"'/]|\\u[0-9a-fA-F]{4}|%[0-9a-fA-F]{2}|&#?\w+;)$")

#: A field name whose value is a credential. Read only to decide rule 3, where
#: it makes redaction UNCONDITIONAL; a name that misses this pattern still falls
#: through to rule 4, whose default is redaction. So a gap here costs nothing
#: the fail-closed default does not already cover.
_CREDENTIAL_NAME: Final = re.compile(
    r"pass|pwd|^pw$|secret|token|cred|auth|apikey|api_key|^pin$", re.I
)

#: The HTML specification's ``<input type>`` keywords. A closed vocabulary the
#: protocol declares, the same way an engine enum is one (invariant 110): the
#: value of ``type=`` is never data the operator supplied.
HTML_INPUT_TYPES: Final = frozenset(
    {
        "button",
        "checkbox",
        "color",
        "date",
        "datetime-local",
        "email",
        "file",
        "hidden",
        "image",
        "month",
        "number",
        "password",
        "radio",
        "range",
        "reset",
        "search",
        "submit",
        "tel",
        "text",
        "time",
        "url",
        "week",
    }
)

#: How much engine-source context an occurrence must carry, on its two sides
#: together, before "this sits inside an engine string literal" is evidence. A
#: bare word is in some literal somewhere; a sentence fragment is not.
_LITERAL_CONTEXT_MIN = 12
_LITERAL_CONTEXT_SPAN = 20


def _is_glued_left(text: str, start: int, secret: str) -> bool:
    if start == 0 or secret[0] not in _IDENT:
        return False
    before = text[start - 1]
    if before == "-" and start >= 2 and text[start - 2] in _IDENT:
        return not _ESCAPE_BEFORE.search(text[max(0, start - 9) : start - 1])
    if before not in _IDENT:
        return False
    return not _ESCAPE_BEFORE.search(text[max(0, start - 8) : start])


def _is_glued_right(text: str, end: int, secret: str) -> bool:
    if end >= len(text) or secret[-1] not in _IDENT:
        return False
    after = text[end]
    if after == "-" and end + 1 < len(text) and text[end + 1] in _IDENT:
        return True
    return after in _IDENT


def is_embedded(text: str, start: int, secret: str) -> bool:
    """Rule 1: the occurrence at *start* is part of a longer identifier."""
    return _is_glued_left(text, start, secret) or _is_glued_right(text, start + len(secret), secret)


def _unit_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    """The unit containing ``text[start:end]``: expand to the nearest separators.

    A literal backslash escape (``\\n``) is a separator too — the text may be a
    JSON-encoded envelope whose newlines are two characters.
    """
    left = start
    while left > 0 and text[left - 1] not in _UNIT_SEPARATORS:
        if text[left - 1] in "nrt" and left >= 2 and text[left - 2] == "\\":
            break
        left -= 1
    right = end
    while right < len(text) and text[right] not in _UNIT_SEPARATORS:
        if text[right] == "\\" and right + 1 < len(text) and text[right + 1] in "nrt":
            break
        right += 1
    return left, right


def normalize_unit(unit: str) -> str:
    """Comparison form of a unit: escapes dropped, quotes unified.

    The same attribute arrives as ``type="password"`` in the page, as
    ``type=\\"password\\"`` inside a JSON envelope, and as ``type='password'`` on
    a page that quotes singly. They are one unit.
    """
    return unit.replace("\\", "").replace("'", '"').strip()


def _strip_quotes(value: str) -> str:
    return value.replace("\\", "").strip().strip("\"'").strip()


def _assignment(unit: str) -> int:
    """Offset of the first ``=`` or ``:`` joining a name to a value, or -1."""
    for i, ch in enumerate(unit):
        if ch in "=:":
            return i
    return -1


def _neighbour_tokens(text: str, left: int, right: int) -> tuple[str, str]:
    """The unit before and the unit after ``text[left:right]``, normalized."""
    i = left - 1
    while i >= 0 and text[i] in _UNIT_SEPARATORS:
        i -= 1
    prev_end = i + 1
    while i >= 0 and text[i] not in _UNIT_SEPARATORS:
        i -= 1
    prev = text[i + 1 : prev_end]
    j = right
    while j < len(text) and text[j] in _UNIT_SEPARATORS:
        j += 1
    next_start = j
    while j < len(text) and text[j] not in _UNIT_SEPARATORS:
        j += 1
    return normalize_unit(prev), normalize_unit(text[next_start:j])


def occurrence_signature(text: str, start: int, secret: str) -> str:
    """The comparison key of one occurrence — what a control must have served.

    An assignment unit (``name=value``, ``"name":"value"``) is self-describing,
    so its key is the unit. A bare word is not — ``password`` alone says nothing
    about whether it is a label or an echo — so its key carries the two
    neighbouring units, which is the local context a reflected value does not
    share with the page's own prose.
    """
    end = start + len(secret)
    left, right = _unit_bounds(text, start, end)
    unit = text[left:right]
    if _assignment(unit) >= 0:
        return normalize_unit(unit)
    prev, nxt = _neighbour_tokens(text, left, right)
    return f"{prev}\x00{normalize_unit(unit)}\x00{nxt}"


#: Prefix of the control entry recording that the target DECLARED the secret's
#: spelling as a field name (``name="…"``) in a response served without it.
DECLARED_FIELD: Final = "\x01field\x00"

#: Attributes whose value REFERENCES a field rather than carrying data. An echo
#: lands in ``value=``; ``id``/``for``/``name`` name a field.
_FIELD_REFERENCE_ATTRS: Final = frozenset({"name", "id", "for"})


@lru_cache(maxsize=1)
def _engine_words() -> frozenset[str]:
    """Every string literal in the engine's source, as exact values."""
    return frozenset(_all_literals())


@lru_cache(maxsize=1)
def _all_literals() -> tuple[str, ...]:
    package = Path(__file__).resolve().parent.parent
    literals: list[str] = []
    for path in sorted(package.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        literals.extend(
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        )
    return tuple(literals)


def is_schema_name(secret: str, controls: frozenset[str]) -> bool:
    """Whether *secret*'s spelling is a NAME in someone's schema, provably.

    Either the target declared it as a field name in a response served without
    the credential, or the engine's own source uses it as a literal. A strong
    password is neither, so an echo of one in a name position stays redacted.
    """
    return DECLARED_FIELD + secret in controls or secret in _engine_words()


@lru_cache(maxsize=1)
def _engine_literals() -> tuple[str, ...]:
    """Every string literal in the engine's own source, f-string parts included.

    Text the engine authored is the engine's vocabulary, the way a field name is
    the target's. A remediation sentence ("…such as changing a password, an email
    address…") is not an echo of anybody's credential, and the proof is that the
    sentence is in this package.
    """
    return tuple(lit for lit in _all_literals() if len(lit) >= _LITERAL_CONTEXT_MIN)


@lru_cache(maxsize=256)
def _literals_containing(secret: str) -> tuple[str, ...]:
    return tuple(lit for lit in _engine_literals() if secret in lit)


def in_engine_literal(text: str, start: int, secret: str) -> bool:
    """Rule 4c: the occurrence and enough of its context are engine source text."""
    candidates = _literals_containing(secret)
    if not candidates:
        return False
    end = start + len(secret)
    left_ctx = text[max(0, start - _LITERAL_CONTEXT_SPAN) : start]
    right_ctx = text[end : end + _LITERAL_CONTEXT_SPAN]
    # Clip the context at a line break: a literal is one string, and a window
    # spanning two lines of a rendered document spans two of them.
    left_ctx = left_ctx.rsplit("\n", 1)[-1]
    right_ctx = right_ctx.split("\n", 1)[0]
    if len(left_ctx) + len(right_ctx) < _LITERAL_CONTEXT_MIN:
        return False
    window = left_ctx + secret + right_ctx
    return any(window in lit for lit in candidates)


def is_secret_occurrence(text: str, start: int, secret: str, controls: frozenset[str]) -> bool:
    """Whether the occurrence of *secret* at *start* is the secret (redact it).

    Args:
        text: The string being redacted.
        start: Offset of the occurrence.
        secret: The registered value.
        controls: Signatures of this secret's occurrences in responses the
            target served without the credential (:func:`control_units`).

    Returns:
        ``True`` to redact. The default — no rule claimed the occurrence for
        the target or the engine — is ``True``.
    """
    if is_embedded(text, start, secret):
        return False
    end = start + len(secret)
    left, right = _unit_bounds(text, start, end)
    unit = text[left:right]
    op = _assignment(unit)
    if op >= 0:
        if end - left <= op:
            if is_schema_name(secret, controls):
                return False  # rule 2: a NAME someone's schema declares
        elif start - left > op:
            name = _strip_quotes(unit[:op])
            value = _strip_quotes(unit[op + 1 :])
            if _CREDENTIAL_NAME.search(name):
                return True  # rule 3: the value of a credential field
            if name.lower() == "type" and value.lower() in HTML_INPUT_TYPES:
                return False  # rule 4b: the HTML specification's vocabulary
            if (
                name.lower() in _FIELD_REFERENCE_ATTRS
                and value == secret
                and is_schema_name(secret, controls)
            ):
                return False  # rule 2, attribute form: it names a declared field
    if occurrence_signature(text, start, secret) in controls:
        return False  # rule 4a: the target served this without the credential
    return not in_engine_literal(text, start, secret)  # rule 4c, else fail closed


def iter_occurrences(text: str, secret: str) -> list[int]:
    """Offsets of every non-overlapping occurrence of *secret* in *text*."""
    found: list[int] = []
    i = text.find(secret)
    while i != -1:
        found.append(i)
        i = text.find(secret, i + len(secret))
    return found


def control_units(body: str, secret: str) -> set[str]:
    """Signatures of *secret*'s occurrences in a response served WITHOUT it.

    The caller vouches for provenance: *body* must be a response to a request
    that carried neither the secret nor a session derived from it.
    """
    units: set[str] = set()
    for i in iter_occurrences(body, secret):
        if is_embedded(body, i, secret):
            continue
        signature = occurrence_signature(body, i, secret)
        units.add(signature)
        if signature == f'name="{secret}"':
            units.add(DECLARED_FIELD + secret)
    return units
