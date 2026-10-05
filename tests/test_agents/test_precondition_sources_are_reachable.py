"""A precondition whose only source is downstream of its own gate.

The state
---------

*Registered, dispatched, and never able to begin* already has an artifact —
``_record_intent_abstention`` writes an ``InconclusiveMeasurement`` and the
report renders it (R11). But that artifact says something about **this
endpoint**: the application's surface evidenced no such intent here. For two of
the three business-logic classes that sentence is not the whole truth, and the
part it leaves out is about the ENGINE:

    ``_business_logic_intent`` evidences an intent facet from a representation
    (``_observed_records``) or from a rejection (``self._business_logic_rejections``).
    On an RPC action endpoint there is no collection, so the first source is
    structurally empty. The second is written by ``_remember_rejection``, whose
    only three call sites are inside the three business-logic classes at phase
    3 — **downstream of the phase-1 gate the value is needed to pass.**

That is its own state, and it is neither of the two it looks like. Not
*unexercised* — the classes were dispatched 168 times. Not *not applicable* —
the endpoint may well carry the rule. It is a precondition the engine can only
produce by first getting past the gate the precondition guards.

What is measured, and where the strict reading has to soften
------------------------------------------------------------

Across 2,989 stored traces:

* ``business_logic_ordering_constraint`` — 64 phase-1 dispatches, **0** with a
  non-empty representation, **0** assertions of any kind, **0** phase-5 verdicts;
* ``business_logic_single_use_action`` — 104 phase-1 dispatches, **1** with a
  representation (and that one evidenced ``entity_type`` and
  ``ownership_relation``, not ``single_use_action``), **0** phase-5 verdicts;
* ``business_logic_quantity_bound`` — 50 phase-1, 38 with a representation, 25
  ``quantity_bound`` assertions, **18** phase-5 verdicts. The class that works,
  and it works off the representation.
* assertions carrying ``evidence_source="rejection"``: **zero, ever.**

The cycle is not quite closed, and saying so is the point of measuring it:
``_test_constraint_violation`` passes phase 1 off a *collection's*
representation, so it can reach phase 3 and fill the shared pool for a later
class. That bootstrap exists. It has never once produced an assertion, and there
is a second, independent reason why it cannot: what ``_remember_rejection``
is handed is the response to a **malformed-value control**
(``clinkz-control-not-a-valid-value``), which is a SCHEMA refusal — while
``_SINGLE_USE_REJECTION_RE`` and ``_ORDERING_REJECTION_RE`` look for BUSINESS-RULE
refusals ("this coupon has already been used", "must be paid first"). A type
error cannot say that. So the honest statement is not "zero paths in the graph"
but "one bootstrap edge, dead for a reason of its own".

Why the domain is computed
--------------------------

Reading the three classes finds the two that were already suspected. The shape
is computable without naming them: an instance attribute that a methodology gate
READS, whose every *informative* writer sits inside a ``_test_*`` method or a
helper reachable only from one.

Two refinements are what make the sweep see anything at all, and both are the
guard-domain law in miniature:

* an assignment that can only write the EMPTY value is not a source, it is the
  declaration of an absence. ``self._business_logic_rejections: list[str] = []``
  in ``__init__`` is an upstream writer by spelling, and counting it reports
  **zero** members for the whole tree;
* the gate is frequently in a shared helper rather than in the ``_test_*`` body —
  ``_business_logic_intent`` is phase 1 for all three classes — so restricting
  reads to ``_test_*`` bodies misses the one member this file exists for.
"""

from __future__ import annotations

import ast
import collections
from pathlib import Path

EXPLOIT = Path(__file__).resolve().parents[2] / "src" / "clinkz" / "agents" / "exploit.py"

#: Methods that MUTATE a container in place. An ``append`` is a write.
_MUTATORS = frozenset({"append", "add", "update", "extend", "setdefault", "insert"})


class _Source:
    """How a downstream-written precondition behaves at the gate that reads it."""

    #: Written and read inside one function: a once-per-run latch, a dedup set, a
    #: record of what this run has already emitted. No gate depends on another
    #: function having filled it.
    LATCH = "latch"
    #: A gate elsewhere reads it, but as a CEILING — the empty value PASSES.
    #: Being downstream-written is the point: it counts what has been spent.
    CEILING = "ceiling"
    #: A gate elsewhere reads it as EVIDENCE — the empty value FAILS. This is the
    #: self-satisfying shape, and it must point at a register entry.
    EVIDENCE = "evidence_self_satisfying"


#: ``attribute -> (classification, reason)``. Domain computed, classification
#: declared — the same split every other guard in this tree uses.
DECLARED: dict[str, tuple[str, str]] = {
    "_business_logic_rejections": (
        _Source.EVIDENCE,
        "R13. _business_logic_intent reads it as one of only two intent evidence sources, and "
        "on an action endpoint it is the only one that is not structurally empty; every writer "
        "is a phase-3 call site inside the three classes it gates",
    ),
    "_p7_runs_used": (
        _Source.CEILING,
        "_p7_oracle reads it against _MAX_P7_RUNS, so zero PASSES and the counter exists "
        "precisely to record what previous dispatches spent; downstream-written is correct here",
    ),
    "_client_execution_oracle": (
        _Source.LATCH,
        "memoises the launched browser for the rest of the run, written and read inside _p7_oracle",
    ),
    "_control_arm_kills": (
        _Source.LATCH,
        "accumulates the arms that refused, written and read inside _disclose_control_arm_kill",
    ),
    "_control_arm_kill_disclosures": (
        _Source.LATCH,
        "dedups the disclosure lead so one kill is written once, inside the same function",
    ),
    "_idor_emitted": (
        _Source.LATCH,
        "dedups IDOR emissions within _idor_phase6_emit so one surface yields one finding",
    ),
    "_jwt_emitted_attacks": (
        _Source.LATCH,
        "dedups JWT attack emissions inside _jwt_phase6_emit on the same one-per-surface rule",
    ),
    "_security_headers_emitted": (
        _Source.LATCH,
        "dedups the header finding inside _security_headers_phase4_emit, one per origin",
    ),
    "_inconclusive_measurements": (
        _Source.LATCH,
        "the abstention artifact itself; _test_brute_force reads back what it appended rather "
        "than gating on another dispatch having filled it",
    ),
    "_lfi_file_server_probed": (
        _Source.LATCH,
        "a once-per-run latch so the file-server probe is not repeated, written and read in place",
    ),
    "_write_crossing_dispatched": (
        _Source.LATCH,
        "a once-per-run latch recording that the write-crossing class already dispatched",
    ),
}


def _self_attr(node: ast.AST) -> str | None:
    """``self._x`` -> ``"_x"``; anything else -> ``None``."""
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ):
        return node.attr
    return None


def _is_empty_literal(node: ast.expr | None) -> bool:
    """Whether *node* can only ever write a value carrying no information.

    ``self._business_logic_rejections: list[str] = []`` is an upstream writer by
    spelling and an absence by meaning. Counting it as a source reports zero
    members for the entire tree, which is how this shape stays invisible.
    """
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return node.value in (None, "", 0, False)
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        return not node.elts
    if isinstance(node, ast.Dict):
        return not node.keys
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        return node.func.id in {"list", "dict", "set", "frozenset", "tuple"} and not node.args
    return False


def _domain() -> dict[str, tuple[frozenset[str], frozenset[str]]]:
    """``attribute -> (writers, readers)`` for every downstream-only precondition."""
    tree = ast.parse(EXPLOIT.read_text(encoding="utf-8"))

    functions: dict[str, list[ast.AST]] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            functions.setdefault(node.name, []).append(node)

    def calls_in(node: ast.AST) -> set[str]:
        out: set[str] = set()
        for sub in ast.walk(node):
            if isinstance(sub, ast.Call):
                func = sub.func
                name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
                if name in functions:
                    out.add(name)
        return out

    callers: dict[str, set[str]] = collections.defaultdict(set)
    for name, nodes in functions.items():
        for node in nodes:
            for callee in calls_in(node):
                callers[callee].add(name)

    # Everything reachable ONLY from a methodology dispatch.
    downstream = {name for name in functions if name.startswith("_test_")}
    changed = True
    while changed:
        changed = False
        for name in functions:
            if name in downstream:
                continue
            seen = callers.get(name)
            if seen and seen <= downstream:
                downstream.add(name)
                changed = True

    writers: dict[str, set[str]] = collections.defaultdict(set)
    for name, nodes in functions.items():
        for node in nodes:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign | ast.AugAssign | ast.AnnAssign):
                    if _is_empty_literal(getattr(sub, "value", None)):
                        continue
                    targets = sub.targets if isinstance(sub, ast.Assign) else [sub.target]
                    for target in targets:
                        attr = _self_attr(target)
                        if attr:
                            writers[attr].add(name)
                elif isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    if sub.func.attr in _MUTATORS:
                        attr = _self_attr(sub.func.value)
                        if attr:
                            writers[attr].add(name)

    readers: dict[str, set[str]] = collections.defaultdict(set)
    for name in downstream:
        for node in functions[name]:
            for sub in ast.walk(node):
                attr = _self_attr(sub)
                if attr and isinstance(getattr(sub, "ctx", None), ast.Load):
                    readers[attr].add(name)

    found: dict[str, tuple[frozenset[str], frozenset[str]]] = {}
    for attr, who_reads in readers.items():
        who_writes = writers.get(attr)
        if not who_writes:
            continue  # never written informatively: a collaborator, not a precondition
        if any(name not in downstream for name in who_writes):
            continue  # something upstream of every gate can fill it
        found[attr] = (frozenset(who_writes), frozenset(who_reads))
    return found


def test_the_reader_finds_the_member_it_was_written_for() -> None:
    """A domain reader that cannot see R13 proves only that it is broken."""
    domain = _domain()
    assert "_business_logic_rejections" in domain, (
        "the sweep no longer sees the precondition it was written for. Check the two "
        "refinements in the module docstring: empty-literal initialisers, and reads that "
        "happen in a shared gate helper rather than in the _test_* body."
    )
    writers, readers = domain["_business_logic_rejections"]
    assert writers == {"_remember_rejection"}
    assert "_business_logic_intent" in readers


def test_every_downstream_written_precondition_is_classified() -> None:
    """A new gate reading state only a later phase can produce must say so."""
    missing = sorted(set(_domain()) - set(DECLARED))
    assert not missing, (
        f"these attributes are read by a methodology gate and written only downstream of "
        f"one: {missing}. Say which it is — a LATCH (read where it is written), a CEILING "
        f"(the empty value passes), or EVIDENCE (the empty value fails, which means the "
        f"gate needs what only passing the gate produces)."
    )


def test_no_declaration_outlived_its_attribute() -> None:
    """The table is not larger than the code it classifies."""
    stale = sorted(set(DECLARED) - set(_domain()))
    assert not stale, (
        f"these DECLARED entries match no downstream-written precondition: {stale}. "
        "Remove the entry, or find where the attribute moved to."
    )


def test_every_classification_is_in_the_vocabulary_with_a_real_reason() -> None:
    vocabulary = {_Source.LATCH, _Source.CEILING, _Source.EVIDENCE}
    for attr, (classification, reason) in sorted(DECLARED.items()):
        assert classification in vocabulary, f"{attr}: {classification!r} is not a classification"
        assert len(reason.split()) >= 6, f"{attr}: the reason is too short to be one"


def test_a_self_satisfying_precondition_is_registered() -> None:
    """``EVIDENCE`` is the classification that needs watching.

    A gate that needs what only passing the gate produces is not a class waiting
    for the right target — it is a capability the engine does not have, and the
    deliverable must not describe it as the former. Every member carries a
    register entry so the state is tracked rather than labelled.
    """
    register = (
        Path(__file__).resolve().parents[2] / "docs" / "analysis" / "register.md"
    ).read_text(encoding="utf-8")
    evidence = sorted(
        attr for attr, (classification, _) in DECLARED.items() if classification == _Source.EVIDENCE
    )
    assert evidence == ["_business_logic_rejections"], (
        f"a second self-satisfying precondition appeared: {evidence}. Each one is a class "
        "that cannot begin, however good the target is."
    )
    for attr in evidence:
        assert attr in register, (
            f"{attr} is classified {_Source.EVIDENCE} but docs/analysis/register.md does not "
            f"name it. A state that is not tracked is a label."
        )
