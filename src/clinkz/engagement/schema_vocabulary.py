"""The engine's own declared vocabulary — the words a credential may not be.

Why this module exists
----------------------

Registered secrets are replaced as **substrings** in every artifact the engine
writes. That is the point of the value registry — it catches the route nobody
thought of — and it is also the route by which a credential can delete the
deliverable, because the engine's artifacts are not free text. They are dumps of
the engine's own Pydantic models, and a model rejects its own dump when a
redaction lands on a piece of its *schema* rather than on its data.

There are exactly **two** such landings, and this module computes the vocabulary
for both:

* **A declared FIELD NAME, matched exactly.**
  :func:`~clinkz.engagement.secrets._redact_key` rewrites a dict key only when a
  single registration consumed it end to end — which is to say only when the
  registered value *equals* the key. A key that merely contains a registered
  word keeps its residue and stays schema. So the key route needs equality, not
  containment, and when it fires on a **required** field the model rejects the
  structure and no report.json, no Markdown and no PDF are written at all.

* **A declared ENUM VALUE, matched as a substring.**
  An enum-constrained field carries a closed vocabulary as its *value*, and a
  value is data — it keeps substring redaction, correctly. ``PentestReport``
  declares ``medium_count``, so a four-character secret ``medi`` is a substring
  of the VALUE ``"medium"`` that ``Finding.severity`` carries; redaction makes
  it ``"[REDACTED]um"``; the enum refuses it; the same total outage arrives by a
  different route. This one needs containment, not equality.

The two predicates are different because the two mechanisms are different, and
writing one rule for both would either miss the enum case or refuse every
credential that shares four letters with any field name in the tree.

What this module is NOT
-----------------------

It is not a vocabulary of "words too common to redact" — that was weighed as
option C in R14 and rejected, because it is a list to own and to keep current
against every target's prose. This is the opposite shape: **computed** from the
models themselves, so a new field or a new enum member joins it in the commit
that declares it, and nothing is hand-maintained. The refusal it powers is
narrow by construction — it fires only where the engine can demonstrate that the
structure would no longer validate.

It also cannot help the default-credential catalogue. ``admin`` and ``root``
collide with no field name and no enum value here, and they are precisely the
words that corrupt an English-language target's prose. That half is
:func:`~clinkz.engagement.secrets.provisional_secret` — the registration's
lifetime, not its spelling.
"""

from __future__ import annotations

import enum
import importlib
import inspect
import pkgutil
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

from pydantic import BaseModel

#: How many owners a collision message names before it counts the rest.
_OWNERS_NAMED: Final = 3


@dataclass(frozen=True, slots=True)
class SchemaCollision:
    """One way a registered credential would damage the engine's own structures.

    **The credential never lands in this object, and never in the message.**
    The field-name predicate is EQUALITY, so the "colliding word" on that arm IS
    the operator's password — and quoting it puts a plaintext credential on
    stderr, which is the exact window
    :func:`~clinkz.engagement.secrets.describe_credential_validation_error`
    exists to close by construction. Nor is stderr only a terminal: two shipped
    drivers capture a child ``clinkz scan``'s stderr into
    ``outputs/_juiceshop_benchmark/`` through ``write_redacted_text``, and the
    PARENT process never registers the credential set — so ``redact`` there has
    only the shape rules, and a password has no shape. The disclosure gate would
    then certify that companion region CLEAN over a file carrying the client's
    password.

    The enum arm is the same axis and not even weaker. Its predicate is
    containment, so naming the enum value narrows the credential to that word's
    substrings — and for a four-character credential equal to a four-character
    enum value (``high``, ``info``, ``bash``) it discloses it exactly. So
    neither arm renders a word.

    What survives is the whole of the actionable content: WHICH kind of
    collision, WHERE the colliding vocabulary is declared, and WHAT registering
    the credential would destroy. The operator knows their own password; a
    reader of a captured log does not need to.

    Attributes:
        kind: ``"field_name"`` or ``"enum_value"``.
        token: The declared word, on the ``enum_value`` arm only — it is the
            engine's own vocabulary there, kept so a test can name it. Empty on
            the ``field_name`` arm, where the word would be the credential
            itself. Rendered by nothing.
        owners: Where the vocabulary is declared, dotted and sorted.
        required: Whether any declaring field is required. A required field that
            vanishes is a rejected dump; an optional one is a lost field.
    """

    kind: str
    token: str
    owners: tuple[str, ...]
    required: bool

    def describe(self) -> str:
        """One line: the collision, where the vocabulary is declared, and the cost.

        ASCII only, and — see the class docstring — **no operator input**. Both
        properties guard the same failure: this string reaches stderr through
        ``typer.echo`` on whatever console encoding the operator has, and from
        there into a captured log. A refusal that raises while being printed is
        not a refusal; one that reprints the credential is not a protection.
        """
        shown = ", ".join(self.owners[:_OWNERS_NAMED])
        rest = len(self.owners) - _OWNERS_NAMED
        if rest > 0:
            shown = f"{shown} (+{rest} more)"
        what = (
            "this credential is EXACTLY a declared field name"
            if self.kind == "field_name"
            else "this credential is a SUBSTRING of a declared enum value"
        )
        return f"{what}, declared by {shown}\n      {self.consequence()}"

    def consequence(self) -> str:
        """What registering the credential would actually do to an artifact.

        The three outcomes are different and the operator is owed the
        difference: a rejected dump is no deliverable at all, while a lost
        optional key is a field missing from artifacts that still write.
        """
        if self.kind == "enum_value":
            return (
                "substring redaction rewrites this VALUE, the enum refuses the "
                "rewritten form, and model_validate rejects the dump: no report.json, "
                "no Markdown, no PDF"
            )
        if self.required:
            return (
                "one registration consumes this KEY end to end, so the field "
                "disappears from the dump and model_validate rejects it for a missing "
                "required field: no report.json, no Markdown, no PDF"
            )
        return (
            "one registration consumes this KEY end to end, so the field name is "
            "deleted from every structure carrying it - silently, in artifacts that "
            "otherwise still write"
        )


def _model_and_enum_modules() -> list[object]:
    """Every module under ``clinkz.models``, imported.

    The domain is the package, not a list of module names: a model file added
    tomorrow is covered by the commit that adds it.
    """
    import clinkz.models as models_pkg

    modules: list[object] = [models_pkg]
    for info in pkgutil.iter_modules(models_pkg.__path__):
        modules.append(importlib.import_module(f"clinkz.models.{info.name}"))
    return modules


@lru_cache(maxsize=1)
def declared_field_names() -> dict[str, tuple[tuple[str, ...], bool]]:
    """``field name -> (owners, any_required)`` across every declared model.

    Read from ``model_fields`` rather than from a JSON schema: an alias, a
    private attribute and a computed field all serialize differently, and what
    the redactor meets is the key ``model_dump`` writes.
    """
    owners: dict[str, set[str]] = {}
    required: dict[str, bool] = {}
    for module in _model_and_enum_modules():
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, BaseModel) or obj is BaseModel:
                continue
            if not obj.__module__.startswith("clinkz.models"):
                continue
            for name, field in obj.model_fields.items():
                owners.setdefault(name, set()).add(f"{obj.__module__}.{obj.__qualname__}")
                required[name] = required.get(name, False) or field.is_required()
    return {
        name: (tuple(sorted(places)), required[name]) for name, places in sorted(owners.items())
    }


@lru_cache(maxsize=1)
def declared_enum_values() -> dict[str, tuple[str, ...]]:
    """``enum value -> owners`` for every string-valued enum member declared.

    Only ``str`` members are collected: a redaction is a string substitution and
    cannot reach an int or an auto() sentinel.
    """
    owners: dict[str, set[str]] = {}
    for module in _model_and_enum_modules():
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if not issubclass(obj, enum.Enum) or obj is enum.Enum:
                continue
            if not obj.__module__.startswith("clinkz.models"):
                continue
            for member in obj:
                if isinstance(member.value, str) and member.value:
                    owners.setdefault(member.value, set()).add(
                        f"{obj.__module__}.{obj.__qualname__}"
                    )
    return {value: tuple(sorted(places)) for value, places in sorted(owners.items())}


def collisions(value: str) -> tuple[SchemaCollision, ...]:
    """Every way registering *value* would invalidate one of the engine's dumps.

    Args:
        value: A candidate secret, as the operator supplied it.

    Returns:
        The collisions, field names first. Empty when the value is safe to
        register — which is the ordinary case for any credential that is not a
        word this codebase happens to spell.
    """
    if not value:
        return ()
    found: list[SchemaCollision] = []
    names = declared_field_names()
    if value in names:
        owners, required = names[value]
        found.append(
            # token="" deliberately: on this arm the colliding word IS the
            # credential, and nothing may carry it out of this function.
            SchemaCollision(kind="field_name", token="", owners=owners, required=required)
        )
    for token, owners in declared_enum_values().items():
        if value in token:
            found.append(
                SchemaCollision(kind="enum_value", token=token, owners=owners, required=False)
            )
    return tuple(found)


__all__ = [
    "SchemaCollision",
    "collisions",
    "declared_enum_values",
    "declared_field_names",
]
