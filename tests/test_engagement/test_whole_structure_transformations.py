"""A transformation applied to a whole structure separates schema from content.

The generalisation
------------------

Redaction ate the deliverable because it applied one string rule to a whole
nested structure without asking which part of that structure was *vocabulary*
and which part was *content*. ``test_start`` became ``[REDACTED]_start``,
``PentestReport.model_validate`` rejected the report's own dump, and no
report.json, Markdown or PDF was written on any run where the default-credential
sweep fired.

Redaction is not the only whole-structure transformation in this tree, so the
rule is not a fact about redaction:

    **A transformation applied to a whole structure must distinguish the
    structure's own vocabulary from the content it carries. Which of the two a
    dict KEY is, is the transformation's to declare — and a transformation that
    never asked has declared "content" by default, which is the failing case.**

Why the domain is computed
--------------------------

Grepping for ``redact`` finds the one site that already failed. Grepping for
``.items()`` finds 51 modules, almost all of them single-level reads where the
question does not arise. The shape that matters is a walk that *descends* —
branches on a container type or iterates ``.items()`` — and *recurses*, directly
or through another descending function in the same module. That is computable
with nothing hand-written, and it is what :func:`_domain` does.

The hand-maintained half is the classification, one entry per member, in
:data:`DECLARED`. Both directions are asserted: a new recursive walk nobody
classified fails the build, and an entry whose walk has gone fails it too.

Known blind spots, named rather than papered over (the same ones §6 of the dev
skill names for its own call graph): a walk whose recursion crosses a module
boundary, one dispatched through ``getattr``, and one built from a callable
handed in as a value. Each is this file's own law one level up.

The second question, per member: what is the shortest secret that corrupts it
---------------------------------------------------------------------------

``register_secret`` refuses anything below ``_MIN_REDACTABLE_LEN = 4``, so 4 is
the floor for every member downstream of redaction. It is also the *answer* for
every one of them, because every schema key of four characters or more contains
a four-character substring. Measured on this tree: ``PentestReport`` declares
**125** field names across its nested models; **39** are alphabetic and at least
four characters, so a single registered secret equal to one of them consumes the
whole key — and **14 of those 39 are required somewhere**, where losing the key
is not a degraded report but no report at all.

That number is why the answer cannot be a length threshold. It is tracked as the
value half of R14 in ``docs/analysis/register.md``.

What the control found that the key fix does not reach
------------------------------------------------------

Run against the model's own vocabulary, this control fails at
``model_validate`` — and not on a key. ``PentestReport`` declares
``medium_count``, so the control registers ``medi``; ``medi`` is a substring of
the VALUE ``"medium"`` that ``Finding.severity`` carries; substring redaction
makes it ``"[REDACTED]um"``; and ``severity`` is one of **four** enum-constrained
fields reachable from ``PentestReport`` rather than free ``str``. So the
deliverable is lost again, by a different route, and the key fix cannot reach it
because nothing here is a key. Held as a STRICT xfail, so the day R14's value
half lands it XPASSes and forces the register entry closed.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from clinkz.engagement.secrets import (
    _MIN_REDACTABLE_LEN,
    clear_secrets,
    redact_structure,
    register_secret,
)
from clinkz.models.report import ExecutiveSummary, Finding, Host, PentestReport

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"

#: Container types whose appearance in an ``isinstance`` check means the function
#: is deciding how to DESCEND rather than how to validate one value.
_CONTAINERS = frozenset({"dict", "list", "tuple", "set", "Mapping", "Sequence"})


class _Keys:
    """What a whole-structure transformation does with dict KEYS."""

    #: The key is rewritten by the same rule that rewrites values. This is the
    #: failing shape, and it is permitted ONLY where the transformation makes
    #: the schema/content call explicitly.
    TRANSFORMED = "transformed"
    #: The key is inspected — compared, collected, used to choose a branch — and
    #: carried into the output unchanged. Schema is read as schema.
    READ = "read"
    #: The key is carried through untouched and never inspected.
    PASSTHROUGH = "passthrough"
    #: The walk descends through containers but the dict keys never reach the
    #: output or a decision: it collects values, or it flattens to a list.
    DISCARDED = "discarded"


#: ``file::function -> (classification, reason)``. One entry per computed member.
#: A reason shorter than six words is an unclassified site wearing a label.
DECLARED: dict[str, tuple[str, str]] = {
    "engagement/secrets.py::redact_structure": (
        _Keys.TRANSFORMED,
        "the one member that rewrites keys, and the only one that asks the question "
        "explicitly: _redact_key rewrites a key only when a SINGLE redaction consumed it "
        "end to end, so a key that merely contains a registered word stays schema",
    ),
    "agents/_api_schema.py::_object_field_names": (
        _Keys.READ,
        "collects JSON body field NAMES and tests each against is_server_managed to decide "
        "which the server assigns; the key is the payload the function exists to produce and "
        "is never rewritten",
    ),
    "agents/_api_schema.py::record_field_names": (
        _Keys.DISCARDED,
        "records the field names a response declared, descending through the body to reach "
        "them; nothing it walks is keyed by data it must preserve",
    ),
    "agents/_api_schema.py::_structured_error_fields": (
        _Keys.DISCARDED,
        "reads the field names an error body names back, descending past list and dict "
        "wrappers to reach them",
    ),
    "agents/_auth_bypass.py::_iter_json_nodes": (
        _Keys.READ,
        "yields every node of a JSON body so the auth-bypass indicator can look for a "
        "principal field; keys are compared, never written back",
    ),
    "agents/_idor_oracle.py::_json_leaves": (
        _Keys.READ,
        "walks to the leaves of an object so attribution can be read off an OWNING FIELD; "
        "invariant 13 is exactly this rule — the field NAME survives because it is schema",
    ),
    "agents/_json_body.py::walk": (
        _Keys.READ,
        "builds the dotted PATH of every leaf, which is invariant 20's body-field identity; "
        "a key here is the address of a value and rewriting one would move the write",
    ),
    "agents/_json_body.py::locate_value": (
        _Keys.READ,
        "finds the path at which a given value sits, comparing keys to assemble the same "
        "dotted address the writer uses",
    ),
    "agents/_package_identity.py::packages_from_package_lock": (
        _Keys.READ,
        "an npm lockfile is keyed BY package path, so here the key is CONTENT and the "
        "walker is right to read it out; it emits the name rather than rewriting it",
    ),
    "agents/_package_identity.py::_walk_v1": (
        _Keys.READ,
        "the v1 lockfile nests dependencies under their own names, so the same content-in-"
        "key-position reading applies one level down",
    ),
    "agents/_route_discovery.py::_endpoints_from_spec": (
        _Keys.DISCARDED,
        "descends an OpenAPI document to reach path items; the route strings it yields come "
        "from the spec's own path map rather than from an arbitrary key",
    ),
    "agents/_route_discovery.py::_spec_param_model": (
        _Keys.DISCARDED,
        "resolves a parameter object out of a spec, descending through refs and lists to reach it",
    ),
    "agents/_route_discovery.py::_spec_request_body": (
        _Keys.DISCARDED,
        "resolves a request-body schema out of a spec the same way",
    ),
    "agents/_route_discovery.py::_schema_property_names": (
        _Keys.READ,
        "reads the property names a spec declares, which is the surface the sweep will "
        "probe; the names are the output, not something to transform",
    ),
    "agents/exploit.py::_flatten_submitted": (
        _Keys.READ,
        "flattens a submitted body so a reflection search can attribute an observation to "
        "the parameter that produced it, which needs the parameter NAME intact",
    ),
    "agents/exploit.py::_auth_bypass_send_probe": (
        _Keys.PASSTHROUGH,
        "carries a caller's header and parameter dicts down to the probe sender without "
        "inspecting or rewriting either set of keys",
    ),
    "observability/corpus_replay.py::_canonical": (
        _Keys.DISCARDED,
        "canonicalises a stored structure for comparison; it reads values out of a bundle "
        "that was ALREADY redacted at write time, which is why a key corrupted then is "
        "unrecoverable here",
    ),
    "observability/corpus_replay.py::_stabilise": (
        _Keys.PASSTHROUGH,
        "replaces volatile VALUES so a replay baseline is stable across re-records, and "
        "carries every key through unchanged because the key is the baseline's identity",
    ),
}


# ---------------------------------------------------------------------------
# The computed domain
# ---------------------------------------------------------------------------


def _called_names(node: ast.AST) -> set[str]:
    """Every name called inside *node*, bare or as an attribute."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name):
                out.add(func.id)
            elif isinstance(func, ast.Attribute):
                out.add(func.attr)
    return out


def _isinstance_types(node: ast.AST) -> set[str]:
    """Every type named in an ``isinstance`` check inside *node*."""
    out: set[str] = set()
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Call)
            and isinstance(sub.func, ast.Name)
            and sub.func.id == "isinstance"
            and len(sub.args) == 2
        ):
            target = sub.args[1]
            for elt in target.elts if isinstance(target, ast.Tuple) else [target]:
                if isinstance(elt, ast.Name):
                    out.add(elt.id)
    return out


def _descends(node: ast.AST) -> bool:
    """Whether *node* decides how to walk INTO a container."""
    return bool(_CONTAINERS & _isinstance_types(node)) or "items" in _called_names(node)


def _domain() -> dict[str, int]:
    """``file::function -> line`` for every recursive whole-structure walk.

    Seeded with the directly self-recursive descenders, then closed under
    same-module mutual recursion. Cross-module recursion and dynamic dispatch
    are the declared blind spots — see the module docstring.
    """
    found: dict[str, int] = {}
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover — a broken tree fails elsewhere
            continue
        rel = path.relative_to(SRC).as_posix()

        descenders: dict[str, list[ast.AST]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _descends(node):
                descenders.setdefault(node.name, []).append(node)

        recursive = {
            name
            for name, nodes in descenders.items()
            if any(name in _called_names(node) for node in nodes)
        }
        changed = True
        while changed:
            changed = False
            for name, nodes in descenders.items():
                if name in recursive:
                    continue
                if any(_called_names(node) & recursive for node in nodes):
                    recursive.add(name)
                    changed = True

        for name in recursive:
            found[f"{rel}::{name}"] = min(node.lineno for node in descenders[name])  # type: ignore[attr-defined]
    return found


def test_the_reader_finds_something() -> None:
    """A domain reader that returns nothing proves only that it is broken."""
    domain = _domain()
    assert len(domain) >= 15, f"the AST reader found only {len(domain)} recursive walks"
    assert "engagement/secrets.py::redact_structure" in domain, (
        "the walk this whole rule came from is not in the computed domain — the reader "
        "no longer matches the shape it was written for"
    )


def test_every_whole_structure_transformation_is_classified() -> None:
    """A new recursive walk must say what it does with the structure's vocabulary."""
    missing = sorted(set(_domain()) - set(DECLARED))
    assert not missing, (
        f"these functions walk a whole nested structure and are not classified: {missing}. "
        "Say whether a dict KEY is schema or content for this walk. A walk that never "
        "asked has answered 'content', which is how a registered password turned "
        "test_start into [REDACTED]_start and cost every deliverable on every run where "
        "the default-credential sweep fired."
    )


def test_no_declaration_outlived_its_walk() -> None:
    """The table is not larger than the code it classifies."""
    stale = sorted(set(DECLARED) - set(_domain()))
    assert not stale, (
        f"these DECLARED entries match no recursive whole-structure walk: {stale}. "
        "Remove the entry, or find where the walk moved to."
    )


def test_every_classification_is_in_the_vocabulary_with_a_real_reason() -> None:
    """A label with no reason is an unclassified site."""
    vocabulary = {_Keys.TRANSFORMED, _Keys.READ, _Keys.PASSTHROUGH, _Keys.DISCARDED}
    for site, (classification, reason) in sorted(DECLARED.items()):
        assert classification in vocabulary, f"{site}: {classification!r} is not a classification"
        assert len(reason.split()) >= 6, f"{site}: the reason is too short to be one"


def test_only_redaction_rewrites_a_key() -> None:
    """The failing shape stays confined to the one site that reasons about it.

    ``TRANSFORMED`` is the classification that needs watching: it is the shape
    that failed. One member holds it, and that member is the one whose job is
    deciding what a key IS. A second one appearing is the rule spreading to a
    walk that has not thought about it.
    """
    transformed = sorted(
        site
        for site, (classification, _) in DECLARED.items()
        if classification == _Keys.TRANSFORMED
    )
    assert transformed == ["engagement/secrets.py::redact_structure"], (
        f"a second whole-structure walk now rewrites dict keys: {transformed}. A key is "
        "schema; rewriting one needs the same end-to-end reasoning _redact_key carries."
    )


# ---------------------------------------------------------------------------
# The positive control the key rule needed and did not have
# ---------------------------------------------------------------------------


def _declared_field_names() -> set[str]:
    """Every field name ``PentestReport`` declares, across its nested models.

    Read from the model's own JSON schema rather than from an instance: a field
    that a minimal report leaves empty is still a key that a populated one
    carries, and the corruption does not care which.
    """
    schema = PentestReport.model_json_schema()
    names: set[str] = set(schema.get("properties") or {})
    for definition in (schema.get("$defs") or {}).values():
        names |= set(definition.get("properties") or {})
    return names


def _populated_report() -> PentestReport:
    """A report with enough of the model populated to exercise nested keys."""
    now = datetime(2026, 9, 12, 18, 20, 11, tzinfo=UTC)
    return PentestReport(
        engagement_name="a-key-is-schema",
        target_scope=["http://target.example"],
        test_start=now,
        test_end=now,
        executive_summary=ExecutiveSummary(
            overview="the positive control", risk_rating="High", run_completed=True
        ),
        hosts=[Host(ip="198.51.100.7", hostnames=["target.example"])],
        findings=[
            Finding(
                title="Reflected parameter",
                description="the login form echoes the submitted password",
                severity="medium",
                target="http://target.example/login",
            )
        ],
    )


@pytest.fixture(autouse=True)
def _clean_registry() -> None:
    clear_secrets()
    yield
    clear_secrets()


def test_a_credential_that_is_a_substring_of_every_schema_key_still_writes_a_report() -> None:
    """The control, at its worst case: one registered secret per declared key.

    Not a spot check on ``test_start``. Every field name ``PentestReport``
    declares contributes its own leading and trailing four characters to the
    registry, so the structure is walked with a registered secret sitting inside
    essentially every key it has. Every key must still be there.

    This is the control that would have caught the outage, and it found two more
    things on its first two runs:

    * with both ends of a key registered, ``test`` + ``_end`` and ``find`` +
      ``ings`` TILED their keys, so ``test_end`` and ``findings`` both rendered
      ``[REDACTED][REDACTED]`` — not lost but COLLIDED into one key, with one of
      the two values silently discarded. Fixed: the rule is now one span and no
      residue, rather than no residue alone;
    * carried through to ``model_validate``, it still fails — on a VALUE, not a
      key. That is R14 and it is the next test, held as a strict xfail.
    """
    dumped = _populated_report().model_dump(mode="json")

    # A PROPER substring, strictly shorter than the key. A key of exactly
    # ``_MIN_REDACTABLE_LEN`` characters has none that can be registered at all,
    # so it is reachable only by registering it whole — which is the declared
    # whole-key behaviour and the residual hazard R14 tracks, not this rule.
    registered = 0
    for name in _declared_field_names():
        if len(name) > _MIN_REDACTABLE_LEN:
            registered += register_secret(name[:_MIN_REDACTABLE_LEN])
            registered += register_secret(name[-_MIN_REDACTABLE_LEN:])
    assert registered > 50, (
        f"the control registered only {registered} secrets — it is not exercising the "
        "vocabulary it claims to"
    )

    redacted = redact_structure(dumped)

    def keys_of(obj: object, out: set[str]) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(key, str):
                    out.add(key)
                keys_of(value, out)
        elif isinstance(obj, list):
            for value in obj:
                keys_of(value, out)

    before: set[str] = set()
    after: set[str] = set()
    keys_of(dumped, before)
    keys_of(redacted, after)
    assert before - after == set(), (
        f"these keys did not survive redaction: {sorted(before - after)}. A key is schema; "
        "a registered secret inside one is a coincidence of spelling."
    )


@pytest.mark.xfail(
    strict=True,
    reason=(
        "R14, the VALUE half. The same control, carried one step further to the failure "
        "that actually happened — the model rejecting its own dump — still fails, and NOT "
        "on a key. PentestReport declares `medium_count`, so the control registers `medi`, "
        "and `medi` is a substring of the VALUE 'medium' that `Finding.severity` carries. "
        "Substring redaction turns it into '[REDACTED]um' and the enum refuses it, so no "
        "report.json, no Markdown and no PDF are written — the same total outage the key "
        "fix closed, reached by a different route. Four fields reachable from PentestReport "
        "are enum-constrained rather than free `str`, which is what makes a value "
        "substitution able to invalidate the document. Strict, so the day the value half "
        "lands this XPASSes and forces R14 closed."
    ),
)
def test_a_credential_inside_a_schema_value_still_writes_a_report() -> None:
    """The half the key fix does not reach. See the xfail reason and R14."""
    dumped = _populated_report().model_dump(mode="json")
    for name in _declared_field_names():
        if len(name) > _MIN_REDACTABLE_LEN:
            register_secret(name[:_MIN_REDACTABLE_LEN])
            register_secret(name[-_MIN_REDACTABLE_LEN:])
    PentestReport.model_validate(redact_structure(dumped))


def test_a_common_word_credential_produces_a_complete_report_with_the_value_gone() -> None:
    """The real shape: a password that is an ordinary English word.

    ``password``, ``test``, ``root`` and ``admin`` are all in the default-
    credential catalogue, so this registration is what a sweeping run performs
    against any target. The value must be gone from the data and every key must
    be intact.
    """
    for candidate in ("test", "root", "admin", "password"):
        register_secret(candidate)

    report = _populated_report()
    dumped = report.model_dump(mode="json")
    dumped["appendices"] = {"Credentials tried": "admin / password on /login, root / root on /ssh"}
    redacted = redact_structure(dumped)

    revalidated = PentestReport.model_validate(redacted)
    assert revalidated.test_start == report.test_start, "the timestamps are still readable"
    assert revalidated.findings[0].title == "Reflected parameter"
    assert set(dumped) == set(redacted), "a top-level key was rewritten"

    trail = redacted["appendices"]["Credentials tried"]
    assert "password" not in trail and "admin" not in trail, (
        "a VALUE is data and keeps substring redaction — narrowing the key rule must "
        "not narrow the value rule"
    )
    assert "[REDACTED]" in trail


def test_a_one_character_credential_is_refused_rather_than_applied() -> None:
    """The shortest case, and the honest gap it leaves.

    A one-character secret cannot be substring-redacted without shredding every
    artifact it appears in, so ``register_secret`` refuses it and returns
    ``False`` for the caller to warn on. The consequence is stated rather than
    hidden: the report is complete and correct, and the value is NOT removed,
    because the second layer never accepted it. The first layer — passwords in
    ``SecretStr``, never handed to a writer — is what covers this case.
    """
    assert register_secret("a") is False
    assert register_secret("ab") is False
    assert register_secret("abc") is False
    assert register_secret("abcd") is True, "four characters is the floor, not five"

    clear_secrets()
    assert register_secret("e") is False

    dumped = _populated_report().model_dump(mode="json")
    redacted = redact_structure(dumped)
    PentestReport.model_validate(redacted)
    assert redacted["engagement_name"] == "a-key-is-schema", (
        "a refused registration must leave the artifact untouched — a one-character "
        "secret applied as a substring would remove a letter from every string"
    )


def test_a_key_tiled_by_two_registrations_is_schema_not_a_collision() -> None:
    """The regression for what the positive control found.

    Two registered secrets that happen to tile a key are two coincidences, not
    evidence that the key is credential material — and the old rule could not
    tell, because it asked only whether anything survived the markers.
    """
    for candidate in ("test", "_end", "find", "ings"):
        register_secret(candidate)

    out = redact_structure({"test_start": 1, "test_end": 2, "findings": [], "test_method": "x"})
    assert set(out) == {"test_start", "test_end", "findings", "test_method"}, (
        "two keys tiled by separate registrations collapsed into one — the loss is not "
        "just the key names, it is that one field's VALUE was overwritten by the other's"
    )
    assert out["test_end"] == 2
    assert out["findings"] == []


def test_a_key_consumed_by_one_registration_is_still_redacted() -> None:
    """The narrowing does not remove the rule.

    A dict genuinely keyed BY credential material is not schema, and one
    registration consuming the whole key is how that is recognised. This is the
    behaviour whose residual hazard is measured in the module docstring: 39 of
    ``PentestReport``'s 125 declared field names could be consumed this way, 14
    of them required. It is the value half of R14.
    """
    register_secret("admin")
    out = redact_structure({"admin": "counted", "admin_role": "kept"})
    assert "admin" not in out
    assert out["[REDACTED]"] == "counted"
    assert out["admin_role"] == "kept"


def test_a_key_made_only_of_shape_spans_is_still_data() -> None:
    """Only the value REGISTRY can tile a key by coincidence.

    A shape span is an intrinsic-structure claim — a JWT, a PEM block, an
    ``Authorization`` value — and no schema vocabulary in this tree is spelled
    like one. So the tiling refusal counts registry spans alone, and a key that
    shape redaction consumed entirely is data however many markers it took.
    """
    register_secret("admin")
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    out = redact_structure({jwt: "session", f"{jwt}admin": "also a session"})
    assert jwt not in out
    assert f"{jwt}admin" not in out, (
        "a shape span beside a registry span is still a key made of credential "
        "material; only two REGISTRY spans are a spelling coincidence"
    )
    assert all("eyJhbGci" not in key for key in out)
