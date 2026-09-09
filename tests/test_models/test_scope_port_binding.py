"""A scope entry that names a port binds that port — and nobody decides scope elsewhere.

``EngagementScope.contains`` extracted the hostname from a target, threw the
port away, and matched on the host alone. So an authorization record naming
``http://host:3000`` returned ``True`` for a dispatch to ``host:445``, and on a
lab machine publishing five containers at once that one record authorised all
five. An authorization record is the one artifact in this system that has to
mean exactly what it says.

The rule, in three cases (:meth:`EngagementScope._port_binds`):

* the entry names **no** port — it authorizes the host, every port on it. That
  is what a bare ``app.acme.com`` means, and it is what ``https://cal.diy``
  means too: 443 there is a default *we* infer, never a port the operator
  typed, and binding to an inferred port refuses dispatches the record permits.
* the entry names a port and the **dispatch** names none — a bare host is not a
  dispatch to a port. It is ``nmap -p 1-65535`` against the host, which is how
  every recon phase starts, and the entry's port cannot refute it.
* **both** name a port — they must be equal. This is the refusal.

The second half of this module is the guard-domain law. The port rule is worth
nothing if some other function decides scope for itself, so the DOMAIN here is
computed from the call graph — every function that reaches a containment
primitive — and the CLASSIFICATION is declared, one entry per function. Both
directions are asserted.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType, declared_port
from clinkz.tools.http_client import HTTPClientTool

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"

#: The containment primitives. A function that calls one of these is deciding,
#: or reporting, whether a target is in scope. ``validate_input`` is deliberately
#: NOT a seed: the tool wrappers that DEFINE it are deciders (they call
#: ``_check_scope``) and are reached that way, while the hundred call sites that
#: merely invoke a tool are dispatchers, not deciders.
PRIMITIVES: frozenset[str] = frozenset(
    {"contains", "_matches_any", "_matches_entry", "_check_scope", "refusal_reason"}
)


class _How:
    """How a scope decider obtains the port rule."""

    #: This function IS the rule. Only ``models/scope.py`` may be this.
    PRIMITIVE = "primitive"
    #: Delegates to the primitive, so the port rule applies without restating it.
    ROUTED = "routed"


#: ``qualified name -> (classification, reason)``. The half a human owns.
DECLARED: dict[str, tuple[str, str]] = {
    # ------------------------------------------------------------- primitive
    "models/scope.py::contains": (
        _How.PRIMITIVE,
        "the containment decision itself; it extracts host AND port and hands both "
        "to the matcher, which is where the port gate lives",
    ),
    "models/scope.py::_matches_any": (
        _How.PRIMITIVE,
        "iterates the entries and delegates each one to _matches_entry, which applies "
        "the port gate per entry",
    ),
    "models/scope.py::_matches_entry": (
        _How.PRIMITIVE,
        "the one place the port gate is applied, and the one place that knows a docker "
        "published-port match crosses a namespace where the numbers are not comparable",
    ),
    "models/scope.py::refusal_reason": (
        _How.PRIMITIVE,
        "reports which half refused, reusing the same matcher rather than re-deriving "
        "the answer; a second implementation here would be a second rule",
    ),
    # ---------------------------------------------------------------- routed
    "tools/base.py::_check_scope": (
        _How.ROUTED,
        "the raising gate every tool wrapper passes through; it asks contains() and "
        "quotes refusal_reason() so a port refusal is attributable in the action log",
    ),
    "browser/oracle.py::validate_input": (
        _How.ROUTED,
        "the P7 browser scope check, run before a navigation is launched and delegated "
        "to _check_scope so a browser cannot reach a port the record did not name",
    ),
    "tools/auth.py::validate_input": (
        _How.ROUTED,
        "checks the login URL the operator or discovery supplied before any credential "
        "is encoded, through the shared gate",
    ),
    "tools/auth.py::_resolve_post_url": (
        _How.ROUTED,
        "scope-checks the form action the TARGET wrote, which is the one string in the "
        "login flow that can leave the authorised origin, through the shared gate",
    ),
    "tools/ffuf.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the target is checked through the shared gate",
    ),
    "tools/http_client.py::validate_input": (
        _How.ROUTED,
        "the HTTP chokepoint wrapper; every engine request is scope-checked here",
    ),
    "tools/httpx_tool.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the target is checked through the shared gate",
    ),
    "tools/katana.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the crawl seed is checked through the shared gate",
    ),
    "tools/nikto.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the target is checked through the shared gate",
    ),
    "tools/nmap.py::validate_input": (
        _How.ROUTED,
        "the port scanner wrapper; it is dispatched at a bare host, which the port "
        "gate deliberately does not refuse",
    ),
    "tools/nuclei.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the target is checked through the shared gate",
    ),
    "tools/sqlmap.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the injection target is checked through the shared gate",
    ),
    "tools/subfinder.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the enumeration root is checked through the shared gate",
    ),
    "tools/wafw00f.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the target is checked through the shared gate",
    ),
    "tools/whatweb.py::validate_input": (
        _How.ROUTED,
        "tool wrapper; the target is checked through the shared gate",
    ),
    "agents/exploit.py::_carriage_surface": (
        _How.ROUTED,
        "filters chain-carriage candidates through scope.contains before any of them "
        "is presented to an endpoint",
    ),
    "agents/exploit.py::_confirm_cross_service_reach": (
        _How.ROUTED,
        "asks contains() whether service B is authorised; the addresses_equivalent call "
        "beside it answers co-location, which is a different question and not a gate",
    ),
    "agents/exploit.py::_fallback_synthesis_xxe": (
        _How.ROUTED,
        "restricts an LLM-suggested external-entity host to scope before the payload is "
        "built, through contains()",
    ),
    "agents/exploit.py::_find_cookie_setter_urls": (
        _How.ROUTED,
        "keeps only in-scope setter URLs harvested out of a page body, through contains()",
    ),
    "agents/exploit.py::_harvest_session_vectors": (
        _How.ROUTED,
        "keeps only in-scope session-carrying URLs, through contains()",
    ),
    "agents/exploit.py::_jwt_fetch_public_key": (
        _How.ROUTED,
        "refuses to fetch a JWKS URL the token names unless the record authorises it, "
        "through contains()",
    ),
    "agents/exploit.py::_probe_cookie_setter": (
        _How.ROUTED,
        "scope-checks the setter URL before visiting it, through contains()",
    ),
    "agents/exploit.py::_probe_session_setter": (
        _How.ROUTED,
        "scope-checks the session setter URL before visiting it, through contains()",
    ),
    "agents/exploit.py::_xxe_payload_in_scope": (
        _How.ROUTED,
        "defence in depth on the SYSTEM entity host, which is fetched server-side and "
        "never passes the HTTP client own gate, through contains()",
    ),
    "agents/scan.py::_record_session_setters": (
        _How.ROUTED,
        "keeps only in-scope setter URLs before recording them as state, through contains()",
    ),
}


def _domain() -> dict[str, list[str]]:
    """Every function under ``src/clinkz`` that calls a containment primitive."""
    found: dict[str, list[str]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            hits = set()
            for sub in ast.walk(node):
                if not isinstance(sub, ast.Call):
                    continue
                func = sub.func
                name = (
                    func.attr
                    if isinstance(func, ast.Attribute)
                    else func.id
                    if isinstance(func, ast.Name)
                    else None
                )
                if name in PRIMITIVES:
                    hits.add(name)
            if hits:
                found[f"{rel}::{node.name}"] = sorted(hits)
            elif rel == "models/scope.py" and node.name in PRIMITIVES:
                # A primitive that calls no other primitive is still one. Leaving
                # it out would exclude _matches_entry -- the single function the
                # port gate lives in -- from the domain that guards the port gate.
                found[f"{rel}::{node.name}"] = ["<is a primitive>"]
    return found


# ---------------------------------------------------------------------------
# The rule
# ---------------------------------------------------------------------------


def _scope(*values: str) -> EngagementScope:
    return EngagementScope(
        name="t",
        targets=[ScopeEntry(value=v, type=ScopeType.URL) for v in values],
    )


@pytest.mark.parametrize(
    ("entry", "target", "expected"),
    [
        # Both name a port and they agree.
        ("http://host.test:3000", "http://host.test:3000/x", True),
        ("http://host.test:3000", "host.test:3000", True),
        # Both name a port and they differ. THE REFUSAL.
        ("http://host.test:3000", "http://host.test:8080/x", False),
        ("http://host.test:3000", "host.test:8080", False),
        ("http://host.test:3000", "host.test:445", False),
        # A ported entry against a scheme-defaulted dispatch: 80 is a port.
        ("http://host.test:3000", "http://host.test/", False),
        # The dispatch names no port: not a dispatch to a port at all.
        ("http://host.test:3000", "host.test", True),
        # The entry names no port: it authorizes the host.
        ("http://host.test", "http://host.test:8080/x", True),
        ("https://cal.diy", "https://cal.diy/x", True),
        # 443 on an https entry is inferred by us, never declared by the operator.
        ("https://cal.diy", "cal.diy:8080", True),
    ],
)
def test_the_port_a_record_names_binds(entry: str, target: str, expected: bool) -> None:
    assert _scope(entry).contains(target) is expected


def test_declared_port_reads_only_what_the_operator_typed() -> None:
    assert declared_port("http://a:3000") == 3000
    assert declared_port("a:22") == 22
    assert declared_port("https://cal.diy") is None
    assert declared_port("http://cal.diy") is None
    assert declared_port("10.0.0.0/24") is None
    assert declared_port("app.acme.com") is None


def test_a_ported_exclusion_excludes_that_port_only() -> None:
    """Exclusions take precedence, and they mean exactly what they say too."""
    scope = EngagementScope(
        name="t",
        targets=[ScopeEntry(value="app.acme.com", type=ScopeType.DOMAIN)],
        excluded=[ScopeEntry(value="app.acme.com:22", type=ScopeType.DOMAIN)],
    )
    assert scope.contains("app.acme.com:22") is False
    assert scope.contains("app.acme.com:443") is True


def test_allowed_ports_binds_when_it_is_non_empty() -> None:
    """The field documented itself as a whitelist and was read by nothing."""
    scope = EngagementScope(
        name="t",
        targets=[ScopeEntry(value="app.acme.com", type=ScopeType.DOMAIN)],
        allowed_ports=[443],
    )
    assert scope.contains("https://app.acme.com/x") is True
    assert scope.contains("http://app.acme.com/x") is False
    assert scope.contains("app.acme.com") is True  # a bare host names no port


def test_a_port_refusal_names_the_port_and_not_the_host() -> None:
    reason = _scope("http://host.test:3000").refusal_reason("http://host.test:8080/x")
    assert "3000" in reason
    assert "8080" in reason
    assert "named by no entry" not in reason


def test_an_unknown_host_still_says_so() -> None:
    reason = _scope("http://host.test:3000").refusal_reason("http://evil.tld/")
    assert "named by no entry" in reason


def test_the_guard_is_observed_refusing_and_the_refusal_is_terminal() -> None:
    """An entry naming :3000, a dispatch to :8080 — the gate RAISES.

    Terminal is the assertion. A scope check that returns ``False`` and lets the
    caller carry on is not a control; the wrapper has to be unable to proceed.

    Through a REAL wrapper, deliberately. A ``ToolBase`` subclass defined in a
    test file is discovered by ``ToolResolver`` as an engine tool — the resolver
    walks ``__subclasses__()`` — so a local stub here becomes a phantom
    capability everywhere else.
    """
    tool = HTTPClientTool(scope=_scope("http://host.test:3000"))

    tool._check_scope("http://host.test:3000/ok")  # the authorised port: no raise

    with pytest.raises(ValueError) as excinfo:
        tool._check_scope("http://host.test:8080/x")
    message = str(excinfo.value)
    assert "8080" in message
    assert "3000" in message
    assert "Refusing to run tool" in message


def test_the_refusal_is_terminal_through_validate_input_too() -> None:
    """The seam a tool actually passes through, not just the helper under it."""
    tool = HTTPClientTool(scope=_scope("http://host.test:3000"))
    tool.validate_input({"method": "GET", "url": "http://host.test:3000/ok"})
    with pytest.raises(ValueError):
        tool.validate_input({"method": "GET", "url": "http://host.test:8080/x"})


# ---------------------------------------------------------------------------
# The guard domain — computed, not listed
# ---------------------------------------------------------------------------


def test_every_scope_decider_is_classified() -> None:
    """computed - declared: a new way to decide scope fails the build until named."""
    undeclared = sorted(set(_domain()) - set(DECLARED))
    assert not undeclared, (
        "these functions decide (or report) whether a target is in scope and no entry "
        "says how they obtain the port rule. A scope decision that does not route "
        f"through EngagementScope.contains does not get it: {undeclared}"
    )


def test_no_entry_outlived_the_function_it_described() -> None:
    stale = sorted(set(DECLARED) - set(_domain()))
    assert not stale, f"declared for functions that no longer decide scope: {stale}"


@pytest.mark.parametrize("qualname", sorted(DECLARED))
def test_each_classification_carries_a_substantive_reason(qualname: str) -> None:
    how, reason = DECLARED[qualname]
    assert how in {_How.PRIMITIVE, _How.ROUTED}
    assert len(reason.split()) >= 6, f"{qualname}: a classification needs a reason, not a label"


def test_only_scope_py_may_be_the_primitive() -> None:
    """The rule has one home. Two homes is two rules, and one of them goes stale."""
    elsewhere = sorted(
        q
        for q, (how, _) in DECLARED.items()
        if how == _How.PRIMITIVE and not q.startswith("models/scope.py::")
    )
    assert not elsewhere, f"the port rule may only live in models/scope.py, not {elsewhere}"


def test_the_port_comparison_exists_exactly_once() -> None:
    """``declared_port`` is called only from inside the scope model.

    The count is the argument for every ROUTED classification above: they are
    covered *because* there is one implementation to be covered by.
    """
    callers = {
        f"{path.relative_to(SRC).as_posix()}::{node.name}"
        for path in sorted(SRC.rglob("*.py"))
        for tree in [ast.parse(path.read_text(encoding="utf-8", errors="replace"))]
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        for sub in ast.walk(node)
        if isinstance(sub, ast.Call)
        and isinstance(sub.func, ast.Name)
        and sub.func.id == "declared_port"
    }
    outside = sorted(q for q in callers if not q.startswith("models/scope.py::"))
    assert not outside, f"declared_port is called outside the scope model at {outside}"


# ---------------------------------------------------------------------------
# The namespace crossing, as a NAMED rule rather than an audit footnote
# ---------------------------------------------------------------------------


class TestThePortGateRule:
    """The exemption has a name, a reason, and a total mapping.

    ``_equivalent_and_bound`` used to carry this as ``if match is
    PUBLISHED_PORT: return True`` under a two-line comment, which is where a
    rule goes to be rediscovered: the next reader sees a branch that skips the
    port check and has to reconstruct from scratch why skipping it is not a
    hole. The general form is worth stating, because it is not about docker —
    **a port that participated in establishing an identity cannot also be
    evidence against it** — and docker publishing is merely the only namespace
    crossing this engine resolves today.
    """

    def test_a_published_port_match_is_already_bound_by_its_port(self) -> None:
        from clinkz.models.scope import PortGateRule, _AddressMatch, port_gate_rule

        assert (
            port_gate_rule(_AddressMatch.PUBLISHED_PORT) is PortGateRule.ALREADY_BOUND_BY_THE_PORT
        )

    def test_a_resolved_match_compares(self) -> None:
        from clinkz.models.scope import PortGateRule, _AddressMatch, port_gate_rule

        assert port_gate_rule(_AddressMatch.RESOLVED) is PortGateRule.COMPARE

    def test_an_unmatched_address_falls_to_the_strict_answer(self) -> None:
        """NONE never reaches the gate, and if it ever does it must not exempt.

        The safe direction for a rule nobody expected to be reached is the one
        that refuses, not the one that permits.
        """
        from clinkz.models.scope import PortGateRule, _AddressMatch, port_gate_rule

        assert port_gate_rule(_AddressMatch.NONE) is PortGateRule.COMPARE

    def test_the_mapping_is_total_over_every_address_match(self) -> None:
        """A new ``_AddressMatch`` member must not silently inherit an answer."""
        from clinkz.models.scope import PortGateRule, _AddressMatch, port_gate_rule

        for match in _AddressMatch:
            assert isinstance(port_gate_rule(match), PortGateRule)

    def test_each_rule_states_why_rather_than_labelling(self) -> None:
        from clinkz.models.scope import PortGateRule

        for rule in PortGateRule:
            assert len(rule.reason.split()) >= 15, f"{rule}: a rule needs its reason"
        crossing = PortGateRule.ALREADY_BOUND_BY_THE_PORT.reason
        assert "namespace" in crossing
        assert "matched this entry" in crossing

    def test_the_exemption_is_applied_through_the_named_rule_not_a_bare_branch(
        self,
    ) -> None:
        """The call site reads the rule. A re-inlined branch fails here.

        This is the difference between "named" and "documented": a name that
        nothing calls is a comment with a type annotation.
        """
        source = (SRC / "models" / "scope.py").read_text(encoding="utf-8")
        applied = source.split("def _equivalent_and_bound", 1)[1].split("def ", 1)[0]
        assert "port_gate_rule(match)" in applied
        assert "_AddressMatch.PUBLISHED_PORT" not in applied, (
            "the crossing is decided by the named rule, not by a second comparison "
            "beside it — two places that must agree is one place that will not"
        )
