"""The engine's own declared vocabulary: field names and enum values, computed.

Read by the redactor (:mod:`clinkz.engagement.secrets`), which never rewrites a
string LEAF that is exactly one of the engine's enum values — a closed
vocabulary this codebase wrote is schema in a value's position too, and a
rewritten one makes the model reject its own dump.

**This module used to power an intake refusal, and no longer does** (register
R30). A credential that spelled a declared field name, or sat inside a declared
enum value, was refused before the engagement opened, because substring
redaction would have rewritten that schema out of every dump. Redaction is now
decided per occurrence by provenance
(:mod:`clinkz.engagement.secret_provenance`): a key is never rewritten for a
spelling the engine's source uses, an enum leaf is exempt by exact match, and an
occurrence inside a longer identifier is not the value. With the substring
replacement gone, the refusal guarded against nothing, and an operator whose
lab account is ``admin``/``password`` is no longer turned away.

The vocabulary is **computed** from the models themselves, so a new field or a
new enum member joins it in the commit that declares it.
"""

from __future__ import annotations

import enum
import importlib
import inspect
import pkgutil
from functools import lru_cache

from pydantic import BaseModel


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


__all__ = [
    "declared_enum_values",
    "declared_field_names",
]
