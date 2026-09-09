"""Who assembles a credential set, and who tells redaction about it — computed.

``register_secret`` is the only thing that makes a password removable from an
artifact by VALUE. Shapes catch what a secret LOOKS like
(``engagement/credential_shapes.py``); a password the operator chose has no
shape, so it is protected by having been registered or it is not protected at
all. ``load_credential_file`` and ``prompt_for_credentials`` both register, which
is why every run driven from the CLI is safe.

A ``CredentialSet`` assembled in CODE is not. ``scripts/live_adaptive_auth_
validation.py`` built one from ``--username`` / ``--password`` and left
``"password": "pro"`` in 28 lines of its own ``actions.jsonl``, because the
action log's body excerpt is redacted by value and no value had been registered.
That was fixed at the site. **The site is not the deliverable** — the same rule
the guard-domain law states everywhere else in this repo: a fix for one call site
is a fix for one call site, and the next driver that assembles a credential set
gets no registration and no warning. This is redaction's guard-domain problem,
and the payload is the client's password.

So the DOMAIN is computed — every function under ``src/clinkz`` and ``scripts``
that constructs a credential-carrying container, by constructor or by a Pydantic
factory — and the CLASSIFICATION is declared, one entry per function, with the
reason. Both halves of each classification are then CHECKED against the tree, so
an entry cannot claim a registration it does not perform:

* a ``REGISTERS`` entry must actually call a registrar;
* a ``NO_SECRET`` entry must actually construct nothing carrying a secret.

There are TWO domains here, because the exposure has two shapes. Domain A is the
container: a ``CredentialSet`` or ``RoleCredential`` built somewhere that never
registers. Domain B is the driver that skips the container entirely — POSTs
``{"email": ..., "password": ...}`` itself and then serialises the exchange.
Domain A cannot see domain B, and domain B is where the measurement found two
live drivers writing an artifact with a credential they had chosen themselves and
registered nowhere.

``tests/`` is deliberately out of domain A: a test writes no client-facing
artifact, and putting ~14 fixtures in the table would bury the six sites that
matter. ``tests/test_engagement/test_driver_artifact_writes.py`` is the test that
exercises the leak directly.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SEARCH_ROOTS = (ROOT / "src" / "clinkz", ROOT / "scripts")

#: The models that carry a credential. Both, because a ``RoleCredential`` built
#: alone and appended to a set later is the same exposure as a whole set.
CONTAINERS = frozenset({"CredentialSet", "RoleCredential"})

#: Pydantic entry points that build one of those from data. ``model_validate``
#: is how ``load_credential_file`` builds its set, and the payload is a dict the
#: walker cannot look inside — so a factory always counts as carrying a secret.
FACTORIES = frozenset(
    {"model_validate", "model_validate_json", "model_construct", "parse_obj", "model_copy"}
)

#: Calls that hand a value to the redaction registry.
REGISTRARS = frozenset({"register_secret", "register_credential_set"})

#: Keywords whose value IS the secret, or a container holding one.
SECRET_KEYWORDS = frozenset({"password", "secret", "token", "credentials"})


class _Site:
    """How a credential-constructing function is classified."""

    #: Constructs a container carrying a secret and registers it for redaction.
    REGISTERS = "registers"
    #: Constructs an EMPTY container — a fallback, a default, a placeholder.
    #: Nothing secret passes through it, so there is nothing to register.
    NO_SECRET = "no_secret"


#: ``file::function -> (classification, reason)``. The half a human owns.
DECLARED: dict[str, tuple[str, str]] = {
    "src/clinkz/cli.py::scan": (
        _Site.NO_SECRET,
        "seeds an EMPTY CredentialSet so the anonymous path has one, then replaces it "
        "wholesale with load_credential_file's or prompt_for_credentials' return; both "
        "of those register, and nothing secret is ever constructed here",
    ),
    "src/clinkz/engagement/dryrun.py::build_dry_run_plan": (
        _Site.NO_SECRET,
        "`credentials or CredentialSet()` — the fallback for a dry run with no "
        "credentials supplied. The dry run sends nothing and the empty set carries "
        "nothing; a set that WAS supplied was registered by whoever loaded it",
    ),
    "src/clinkz/engagement/secrets.py::load_credential_file": (
        _Site.REGISTERS,
        "the file path into the engine: it model_validate()s the operator's JSON and "
        "calls register_credential_set on the result before returning it, which is why "
        "every run driven by `--credentials` is redacted by value",
    ),
    "src/clinkz/engagement/secrets.py::prompt_for_credentials": (
        _Site.REGISTERS,
        "the interactive path: builds one RoleCredential per role from a getpass read "
        "and registers the assembled set on the line after it is constructed",
    ),
    "src/clinkz/orchestrator/orchestrator.py::__init__": (
        _Site.NO_SECRET,
        "`credentials or CredentialSet()` — the anonymous-engagement fallback. The "
        "orchestrator never assembles a credential; it holds the one it was handed, "
        "and holding it is deliberately NOT attaching it to the scope",
    ),
    "scripts/live_adaptive_auth_validation.py::_run": (
        _Site.REGISTERS,
        "assembles a set from --username/--password and calls register_credential_set "
        "before installing the governor. This is the driver whose actions.jsonl carried "
        "the plaintext in 28 lines before that call existed",
    ),
}


def _qualname(path: Path, fn: str) -> str:
    return f"{path.relative_to(ROOT).as_posix()}::{fn}"


def _owner_and_attr(func: ast.expr) -> tuple[str | None, str | None]:
    if isinstance(func, ast.Name):
        return func.id, None
    if isinstance(func, ast.Attribute):
        base = func.value
        return (base.id if isinstance(base, ast.Name) else None), func.attr
    return None, None


def _constructions(node: ast.AST) -> list[ast.Call]:
    """Every call in *node* that builds a credential container."""
    out: list[ast.Call] = []
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        owner, attr = _owner_and_attr(sub.func)
        if owner not in CONTAINERS:
            continue
        if attr is None or attr in FACTORIES:
            out.append(sub)
    return out


def _carries_a_secret(call: ast.Call) -> bool:
    """Whether this construction could put a plaintext secret into the container.

    A Pydantic factory always counts: its argument is data the walker cannot see
    inside, and refusing to guess is the only safe reading.
    """
    _, attr = _owner_and_attr(call.func)
    if attr in FACTORIES:
        return True
    for keyword in call.keywords:
        if keyword.arg is None:  # **kwargs — unknown contents
            return True
        if keyword.arg in SECRET_KEYWORDS:
            return True
    return bool(call.args)


def _registers(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            owner, attr = _owner_and_attr(sub.func)
            if owner in REGISTRARS or attr in REGISTRARS:
                return True
    return False


def _domain() -> dict[str, tuple[bool, bool]]:
    """``qualname -> (constructs something carrying a secret, registers)``."""
    found: dict[str, tuple[bool, bool]] = {}
    for base in SEARCH_ROOTS:
        for path in sorted(base.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            scopes: list[tuple[str, ast.AST]] = [("<module>", tree)]
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    scopes.append((node.name, node))
            # Innermost scope wins: a construction inside a function belongs to
            # that function, not to the module that contains it.
            claimed: set[int] = set()
            for name, scope in reversed(scopes):
                calls = [c for c in _constructions(scope) if id(c) not in claimed]
                if not calls:
                    continue
                claimed.update(id(c) for c in calls)
                qual = _qualname(path, name)
                carries = any(_carries_a_secret(c) for c in calls)
                found[qual] = (carries, _registers(scope))
    return found


def test_every_credential_construction_site_is_classified() -> None:
    """computed - declared: a new one fails the build until somebody says which."""
    undeclared = sorted(set(_domain()) - set(DECLARED))
    assert not undeclared, (
        "these functions assemble a credential-carrying container and no entry says "
        "whether the secret in it was registered for redaction. Registering is what "
        "makes a password removable from an artifact BY VALUE; a password has no "
        f"shape for the shape rules to catch: {undeclared}"
    )


def test_no_entry_outlived_the_function_it_described() -> None:
    """declared - computed: the half that stops the table rotting into a wish."""
    stale = sorted(set(DECLARED) - set(_domain()))
    assert not stale, f"declared for functions that no longer build a credential container: {stale}"


@pytest.mark.parametrize("qualname", sorted(DECLARED))
def test_each_classification_carries_a_substantive_reason(qualname: str) -> None:
    classification, reason = DECLARED[qualname]
    assert classification in {_Site.REGISTERS, _Site.NO_SECRET}, (
        f"{qualname}: unknown classification {classification!r}"
    )
    assert len(reason.split()) >= 12, f"{qualname}: a classification needs a reason, not a label"


REGISTERING = sorted(q for q, (c, _) in DECLARED.items() if c == _Site.REGISTERS)
NO_SECRET = sorted(q for q, (c, _) in DECLARED.items() if c == _Site.NO_SECRET)


@pytest.mark.parametrize("qualname", REGISTERING)
def test_a_registers_entry_actually_registers(qualname: str) -> None:
    """The claim is checked against the tree, not taken on the table's word."""
    carries, registers = _domain()[qualname]
    assert registers, (
        f"{qualname} is declared {_Site.REGISTERS} and calls neither register_secret "
        f"nor register_credential_set. Every artifact this path writes would carry the "
        f"plaintext, because redaction by value only removes what it was told about"
    )
    assert carries, (
        f"{qualname} registers but constructs nothing carrying a secret — reclassify it "
        f"as {_Site.NO_SECRET} so the table describes what the code does"
    )


@pytest.mark.parametrize("qualname", NO_SECRET)
def test_a_no_secret_entry_really_constructs_nothing_secret(qualname: str) -> None:
    """The other half. An empty-container claim that stopped being true fails here."""
    carries, _ = _domain()[qualname]
    assert not carries, (
        f"{qualname} is declared {_Site.NO_SECRET} but now constructs a credential "
        f"container carrying one. Either register it and reclassify it "
        f"{_Site.REGISTERS}, or keep the construction empty"
    )


def test_the_domain_is_not_trivially_small() -> None:
    """A domain that collapsed is a guard that stopped guarding."""
    assert len(_domain()) >= 5, (
        f"the credential-construction domain computed to {len(_domain())} members, "
        f"which means the walk stopped resolving: {sorted(_domain())}"
    )


# ===========================================================================
# Domain B: a driver that CHOOSES a credential, and writes an artifact
# ===========================================================================
#
# The container is not where the exposure lives. A driver that never builds a
# ``RoleCredential`` at all — one that POSTs ``{"email": ..., "password": ...}``
# with urllib and then serialises the exchange — has exactly the same defect,
# and domain A cannot see it.
#
# Measured over ``scripts/`` on 2026-09-09: five modules supply a password-shaped
# string LITERAL and also write an artifact. Two of them had chosen their own
# credential (``Cr0ssServ!ceB1``, ``L34rnServ!ceB2``), registered it nowhere, and
# wrote a redacted JSON artifact — redacted by shape, which a password does not
# have, and by registered value, of which there was none.
#
# ``scripts/_artifact_io.py::register_lab_credential`` is the sanctioned route
# and existed the whole time. Existing is not the same as being reached, which
# is what a computed domain is for.

#: Calls that put an artifact on disk. The redacting writers are the sanctioned
#: ones; the raw two are here because a module that writes raw is still a module
#: whose credential can land in a file (``test_driver_artifact_writes.py`` is
#: what refuses the raw write itself).
#: What counts as "this module supplies a password". Matched on the identifier or
#: the key, never on the word appearing in prose: ``dvwa_ladder_run.py`` mentions
#: it throughout its damage check and offers no credential at all.
PASSWORD_TOKEN = re.compile(r"(?:^|_)(password|passwd|pwd)s?(?:_|$)", re.IGNORECASE)

ARTIFACT_WRITERS = frozenset(
    {"write_redacted_json", "write_redacted_text", "write_text", "write_bytes"}
)

#: Everything that hands a value to the redaction registry, from a driver.
DRIVER_REGISTRARS = REGISTRARS | {"register_lab_credential"}


class _Driver:
    """How a credential-supplying driver is classified."""

    #: Registers the credential it chose, so redaction can remove it by value.
    REGISTERS = "registers"
    #: The value is a PUBLISHED default of a disposable benchmark container and
    #: is also an ordinary English word, so registering it would rewrite the
    #: field NAME as well as the value and cost the artifact its readability.
    PUBLISHED_DEFAULT = "published_default"


#: ``scripts/<module> -> (classification, reason)``.
DECLARED_DRIVERS: dict[str, tuple[str, str]] = {
    "scripts/d1_consistency_runner.py": (
        _Driver.PUBLISHED_DEFAULT,
        "posts DVWA's own documented default admin/password to reset the level. The "
        "value is the English word 'password'; registering it would redact the field "
        "NAME out of every artifact this driver writes and protect a credential that "
        "is published in DVWA's README and in this repo's compose file",
    ),
    "scripts/live_p7_client_execution_validation.py": (
        _Driver.PUBLISHED_DEFAULT,
        "the same DVWA default, offered by the driver's own login helper, and the same "
        "reason: the value is a dictionary word, so redaction by value cannot separate "
        "the secret from the schema around it",
    ),
    "scripts/live_cross_service_ssrf_validation.py": (
        _Driver.REGISTERS,
        "chooses its own throwaway Juice Shop credential and registers it with "
        "register_lab_credential before the account is created. This driver wrote a "
        "redacted artifact with that password unregistered until 2026-09-09",
    ),
    "scripts/live_cross_service_topology_learning_validation.py": (
        _Driver.REGISTERS,
        "the topology-learning sibling of the SSRF driver, with its own distinct "
        "throwaway credential and the same registration before the account is created",
    ),
    "scripts/live_d8_auth_bypass_validation.py": (
        _Driver.REGISTERS,
        "registers ADMIN_PASSWORD at import. This is the driver whose output shipped a "
        "complete session JWT and the lab password in three request bodies, which is "
        "the incident the whole driver-write chokepoint was built for",
    ),
}


def _password_literals(tree: ast.AST) -> list[tuple[str, str]]:
    """``(where the name came from, the literal)`` for each supplied password.

    Three shapes, because a driver supplies a credential in three ways: assigned
    to a password-shaped name, written as a password-shaped key in a body dict,
    or passed as a password-shaped keyword. A name alone is deliberately NOT
    enough — ``dvwa_ladder_run.py`` mentions the word all over its damage check
    and supplies no credential at all, and a domain that swept it in would spend
    its reader's attention on a module with nothing to classify.
    """
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Name)
                    and PASSWORD_TOKEN.search(target.id)
                    and isinstance(node.value, ast.Constant)
                    and isinstance(node.value.value, str)
                ):
                    out.append((target.id, node.value.value))
        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=False):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and PASSWORD_TOKEN.search(key.value)
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    out.append((key.value, value.value))
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if (
                    keyword.arg
                    and PASSWORD_TOKEN.search(keyword.arg)
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                ):
                    out.append((keyword.arg, keyword.value.value))
    return out


def _called(tree: ast.AST, names: frozenset[str]) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            owner, attr = _owner_and_attr(node.func)
            if owner in names or attr in names:
                return True
    return False


def _driver_domain() -> dict[str, bool]:
    """``scripts/<module> -> registers``, for drivers that supply AND write."""
    found: dict[str, bool] = {}
    for path in sorted((ROOT / "scripts").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        if not _password_literals(tree):
            continue
        if not _called(tree, ARTIFACT_WRITERS):
            continue
        found[path.relative_to(ROOT).as_posix()] = _called(tree, DRIVER_REGISTRARS)
    return found


def test_every_credential_supplying_driver_is_classified() -> None:
    """computed - declared. The next driver is looked at before it lands."""
    undeclared = sorted(set(_driver_domain()) - set(DECLARED_DRIVERS))
    assert not undeclared, (
        "these drivers hardcode a password AND write an artifact, and no entry says "
        "whether the value was registered for redaction. scripts/_artifact_io.py"
        "::register_lab_credential is the route; if a value genuinely should not be "
        f"registered, say which classification applies and why: {undeclared}"
    )


def test_no_driver_entry_outlived_its_module() -> None:
    stale = sorted(set(DECLARED_DRIVERS) - set(_driver_domain()))
    assert not stale, f"declared for drivers that no longer supply a password and write: {stale}"


@pytest.mark.parametrize("module", sorted(DECLARED_DRIVERS))
def test_each_driver_classification_carries_a_substantive_reason(module: str) -> None:
    classification, reason = DECLARED_DRIVERS[module]
    assert classification in {_Driver.REGISTERS, _Driver.PUBLISHED_DEFAULT}
    assert len(reason.split()) >= 12, f"{module}: a classification needs a reason"


@pytest.mark.parametrize(
    "module", sorted(m for m, (c, _) in DECLARED_DRIVERS.items() if c == _Driver.REGISTERS)
)
def test_a_registering_driver_actually_registers(module: str) -> None:
    """Checked against the tree. The table cannot claim a call that is not there."""
    assert _driver_domain()[module], (
        f"{module} is declared {_Driver.REGISTERS} and calls no registrar. Every "
        f"artifact it writes carries the plaintext, because redaction by value removes "
        f"only what it was told about and a password has no shape"
    )


@pytest.mark.parametrize(
    "module",
    sorted(m for m, (c, _) in DECLARED_DRIVERS.items() if c == _Driver.PUBLISHED_DEFAULT),
)
def test_a_published_default_driver_supplies_only_dictionary_words(module: str) -> None:
    """The exemption's own precondition, checked rather than asserted in prose.

    ``published_default`` is licensed by the value being unregisterable without
    collateral damage. A driver that quietly starts supplying a real credential
    under that classification has to fail here rather than inherit the licence.
    """
    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    supplied = {value for _, value in _password_literals(tree)}
    offenders = sorted(v for v in supplied if not v.isalpha() or len(v) > 12)
    assert not offenders, (
        f"{module} is declared {_Driver.PUBLISHED_DEFAULT}, which is licensed by the "
        f"value being an ordinary word that cannot be redacted by value without "
        f"rewriting the schema around it. These are not that: {offenders}. Register "
        f"them with register_lab_credential and reclassify"
    )
