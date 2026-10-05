"""An HTTP verb the engine could not read is UNREAD, never a GET it measured.

What was measured
-----------------

``agents/exploit.py::_applicable_methods_for_endpoint`` is the **only** producer
of the deterministic Tier-1 buckets, and seven classes enter through one line::

    if endpoint.has_form or (endpoint.method or "GET").upper() in ("POST", "PUT", "PATCH"):

So an endpoint recorded ``GET`` is not a lower-ranked candidate for those seven
— it is absent from them. Not truncated, not out-ranked, not abstaining: never
planned, and its own preconditions never consulted.

``_js_api_mining`` is the one producer that can READ a verb out of a target's
own source, and its fallback was::

    if method is None:
        method = "GET"

which makes a call site whose verb it could not read byte-identical to one it
read AS GET. The absence is spelled as a measurement, and the value it is
spelled as is precisely the one that removes the endpoint from every write
class.

Measured live against the local cal.com container, before the fix: of 12 bundles
read, the miner emitted **2** call sites (both reported ``GET``) while **7** call
sites in those same bundles carried a config argument it cannot see into — an
identifier, or a literal with a top-level spread. All seven were planned as
reads. The same measurement also found the sharper case: ``var m = "POST";
fetch(u, {method: m})`` was reported ``GET``, and that is not an absence at all
but a verb sitting one binding away that the miner declined to resolve.

The rule
--------

    **How an endpoint's METHOD came to be known is a property the producer
    declares, and a verb nobody read is its own state.** ``UNREAD`` never admits
    an endpoint to a write-family class — a terminal, mutating methodology
    against a route with no evidence it writes is invariant 88 plus a residual
    mutation in another principal's data. What it does is get the route ASKED
    (the ``OPTIONS`` sweep probes an unread route first, within its relevance
    grade) and get the gap DISCLOSED.

Why the domain is computed
--------------------------

Every ``Endpoint(...)`` construction under ``src/`` is a producer of surface,
and the field's default is the pessimistic value — so a site that forgets to
declare does not fail loudly, it quietly marks real reads as unread and inflates
the disclosure until an operator learns to skim it. The domain is therefore
every such CALL, found by AST walk, and the guard asserts each one passes
``method_evidence`` explicitly. A new producer fails the build until it says how
it knows.
"""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest

from clinkz.agents._api_schema import _select_routes
from clinkz.agents._js_api_mining import mine_api_call_sites
from clinkz.models.scan import Endpoint, MethodEvidence
from clinkz.observability.plan_alarms import (
    MethodProvenance,
    PlanAlarmRegister,
    method_provenance_summary,
    record_method_provenance,
    set_active_plan_alarms,
)

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"
_WINDOW = datetime(2026, 9, 15, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# The computed domain: every Endpoint construction declares its verb's origin
# ---------------------------------------------------------------------------


def _endpoint_constructions() -> list[tuple[str, int, bool]]:
    """``(file, line, declares_method_evidence)`` for every ``Endpoint(...)`` call."""
    out: list[tuple[str, int, bool]] = []
    for path in sorted(SRC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover — a broken tree fails elsewhere
            continue
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (
                func.id
                if isinstance(func, ast.Name)
                else func.attr
                if isinstance(func, ast.Attribute)
                else ""
            )
            if name != "Endpoint":
                continue
            declared = any(kw.arg == "method_evidence" for kw in node.keywords)
            out.append((rel, node.lineno, declared))
    return out


def test_the_reader_finds_the_producers() -> None:
    """A domain reader that returns nothing proves only that it is broken."""
    found = _endpoint_constructions()
    assert len(found) >= 10, f"the AST reader found only {len(found)} Endpoint constructions"
    files = {rel for rel, _line, _declared in found}
    for expected in ("agents/scan.py", "agents/_route_discovery.py", "agents/_api_schema.py"):
        assert expected in files, f"{expected} constructs endpoints and the reader missed it"


def test_every_endpoint_producer_declares_how_it_knows_the_verb() -> None:
    """A producer that has not said how it knows is one nobody checked.

    The field's default is ``UNREAD``, which is safe but not free: an
    undeclared real read is disclosed as an unread verb, and a disclosure that
    over-fires is one an operator stops reading (invariant 77).
    """
    undeclared = [
        f"{rel}:{line}" for rel, line, declared in _endpoint_constructions() if not declared
    ]
    assert not undeclared, (
        f"these Endpoint constructions do not declare method_evidence: {undeclared}. "
        "Say how the verb came to be known: NAMED (the source or the protocol stated "
        "it), PLATFORM_DEFAULT (none could have been named, so the idiom's default IS "
        "the verb), or UNREAD (a config we cannot see into). A site that never asked "
        "gets UNREAD by default, which inflates the disclosure rather than failing."
    )


# ---------------------------------------------------------------------------
# The miner: three states, and the one it used to collapse
# ---------------------------------------------------------------------------

#: ``idiom -> (source, expected method, expected evidence)``. The shapes a real
#: bundle serves, including the four the live cal.com measurement found.
IDIOMS: dict[str, tuple[str, str, MethodEvidence]] = {
    "bare fetch, one argument": (
        'fetch("/api/profile").then(r=>r.json())',
        "GET",
        MethodEvidence.PLATFORM_DEFAULT,
    ),
    "fetch, init read in full, no method key": (
        'fetch("/api/profile",{headers:{"x-a":"b"},credentials:"include"})',
        "GET",
        MethodEvidence.PLATFORM_DEFAULT,
    ),
    "fetch, only a NESTED spread": (
        'fetch("/api/profile",{headers:{...h}})',
        "GET",
        MethodEvidence.PLATFORM_DEFAULT,
    ),
    "angular get": ('this.http.get("/api/profile")', "GET", MethodEvidence.NAMED),
    "angular post": (
        'this.http.post("/api/feedback",{comment:e.comment})',
        "POST",
        MethodEvidence.NAMED,
    ),
    "fetch, literal method": (
        'fetch("/api/feedback",{method:"POST",body:JSON.stringify(e)})',
        "POST",
        MethodEvidence.NAMED,
    ),
    "xhr open": (
        'var x=new XMLHttpRequest();x.open("PUT","/api/profile");',
        "PUT",
        MethodEvidence.NAMED,
    ),
    "method hoisted into a local binding": (
        'var m="POST";fetch("/api/bookings",{method:m})',
        "POST",
        MethodEvidence.NAMED,
    ),
    "fetch, identifier init": ('fetch("/api/profile",n)', "GET", MethodEvidence.UNREAD),
    "fetch, TOP-LEVEL spread init": (
        'fetch("/api/profile",{...n,headers:h})',
        "GET",
        MethodEvidence.UNREAD,
    ),
    "axios config with a top-level spread": (
        'axios({url:"/api/teams",...n})',
        "GET",
        MethodEvidence.UNREAD,
    ),
    "method key with an unresolvable value": (
        'fetch("/api/bookings",{method:z.k})',
        "GET",
        MethodEvidence.UNREAD,
    ),
}


@pytest.mark.parametrize(("idiom", "case"), sorted(IDIOMS.items()))
def test_the_miner_declares_how_it_knows_each_verb(
    idiom: str, case: tuple[str, str, MethodEvidence]
) -> None:
    """Each idiom, with the verb it yields and the evidence for it."""
    source, expected_method, expected_evidence = case
    sites = mine_api_call_sites(source)
    assert sites, f"{idiom}: no call site mined"
    site = sites[0]
    assert site.method == expected_method, f"{idiom}: method"
    assert site.method_evidence is expected_evidence, f"{idiom}: evidence"


def test_the_two_reasons_a_verb_is_get_are_no_longer_the_same_value() -> None:
    """The whole point, in one assertion.

    A bare ``fetch(url)`` and a ``fetch(url, cfg)`` both produce a ``GET``
    endpoint, and they always will — the difference is not the verb, it is
    whether the verb was read. Before this rule the two were byte-identical.
    """
    read = mine_api_call_sites('fetch("/api/x")')[0]
    unread = mine_api_call_sites('fetch("/api/x",n)')[0]
    assert read.method == unread.method == "GET"
    assert read.method_evidence is not unread.method_evidence, (
        "a verb the miner read and a verb it could not read are still the same fact"
    )


def test_a_hoisted_method_is_recovered_rather_than_disclosed() -> None:
    """Reading it beats declaring it unread, where reading it is possible.

    ``var m = "POST"; fetch(u, {method: m})`` is a WRITE endpoint sitting one
    binding away, and the miner already resolves bindings for URLs. Reporting it
    as an unread GET would be honest and would still lose the endpoint; the
    third state is for verbs that cannot be read, not for ones nobody tried to.
    """
    sites = mine_api_call_sites('var m="POST";fetch("/api/bookings",{method:m,body:b})')
    assert sites[0].method == "POST"
    assert sites[0].method_evidence is MethodEvidence.NAMED


def test_two_call_sites_dedupe_to_the_weaker_evidence() -> None:
    """A route with one read verb and one unread call is still unread.

    The two directions are not symmetric. Downgrading costs an ``OPTIONS`` probe
    and a line of disclosure; keeping the stronger claim costs the write surface.
    """
    sites = mine_api_call_sites('this.http.get("/api/x");fetch("/api/x",n);')
    assert len(sites) == 1
    assert sites[0].method_evidence is MethodEvidence.UNREAD


# ---------------------------------------------------------------------------
# The consumers
# ---------------------------------------------------------------------------


def test_an_unread_verb_never_admits_an_endpoint_to_a_write_class() -> None:
    """``UNREAD`` discloses and prioritises. It never relaxes the write gate.

    A ``GET`` endpoint admitted to ``_test_write_crossing`` is a terminal,
    mutating class dispatched against a route with no evidence it writes —
    invariant 88 plus a residual mutation in another principal's data. The gate
    is right; what was missing is the input to it. This pins that the third
    state did not become a back door into the gate.
    """
    from clinkz.agents.exploit import ExploitAgent

    unread = Endpoint(
        url="http://target.example/api/bookings",
        method="GET",
        params=["id"],
        method_evidence=MethodEvidence.UNREAD,
    )
    methods = ExploitAgent._applicable_methods_for_endpoint(
        ExploitAgent.__new__(ExploitAgent), unread
    )
    for write_class in (
        "_test_write_crossing",
        "_test_mass_assignment",
        "_test_input_validation",
        "_test_xss_stored",
    ):
        assert write_class not in methods, (
            f"{write_class} was queued against an endpoint whose verb nobody read. "
            "An unread verb is not evidence that the route writes."
        )


def test_an_unread_route_is_probed_first_but_only_within_its_grade() -> None:
    """The tie-break that turns a disclosure into a capability.

    An unread route is exactly the route the ``OPTIONS`` sweep exists to ask, so
    it sorts first — but WITHIN its relevance grade. Across grades it would undo
    the 32-of-40 ordering fix, because every ``/_next/static/chunks/…`` bundle is
    unread by construction (a URL string literal carries no verb) and would take
    the budget straight back.
    """
    set_active_plan_alarms(PlanAlarmRegister())
    bundle = "http://t/_next/static/chunks/a.js"
    routes = [bundle, "http://t/api/a", "http://t/api/z", "http://t/auth/login"]

    plain = _select_routes(routes, 3, sweep="options_methods")
    assert plain[0] == "http://t/api/a", "the relevance order is the baseline"

    promoted = _select_routes(
        routes, 3, sweep="options_methods", unread=frozenset({"http://t/api/z"})
    )
    assert promoted[0] == "http://t/api/z", "an unread API route is asked first"
    assert promoted[1] == "http://t/api/a", "and the read one right behind it"

    # The half that matters: an unread BUNDLE must not displace a read
    # application route. Every bundle is unread by construction - a URL string
    # literal carries no verb - so an unread-first order ACROSS grades would
    # hand the budget straight back to the chunks, which is the 32-of-40
    # ordering failure this sweep already had once.
    bundle_first = _select_routes(routes, 2, sweep="options_methods", unread=frozenset({bundle}))
    assert bundle_first == ["http://t/api/a", "http://t/api/z"], (
        f"an unread bundle displaced a read application route: {bundle_first}"
    )


# ---------------------------------------------------------------------------
# The disclosure
# ---------------------------------------------------------------------------


def test_the_disclosure_renders_on_a_clean_run_too() -> None:
    """ "Every verb was read" is the claim that makes an all-GET surface mean something.

    A section that appears only when something went unread cannot be told apart
    from one nobody wrote.
    """
    from clinkz.agents.report import ReportAgent
    from clinkz.models.report import PentestReport

    set_active_plan_alarms(PlanAlarmRegister())
    record_method_provenance(MethodProvenance(named=9, platform_default=37, unread=0))
    report = PentestReport(
        engagement_name="clean",
        target_scope=["http://target.example"],
        test_start=_WINDOW,
        test_end=_WINDOW,
        method_provenance=method_provenance_summary(),
    )
    lines: list[str] = []
    ReportAgent._render_method_provenance(lines, report)
    body = "\n".join(lines)
    assert "HTTP method provenance" in body
    assert "46 discovered endpoint(s) carries a method the engine READ" in body


def test_the_disclosure_names_the_limit_as_ours_not_the_targets() -> None:
    """A class that cannot begin is a capability the engine lacks (invariant 109).

    A reader told only "no write endpoints were found" goes looking at their own
    application. The sentence has to say whose limit it is.
    """
    from clinkz.agents.report import ReportAgent
    from clinkz.models.report import PentestReport

    set_active_plan_alarms(PlanAlarmRegister())
    record_method_provenance(
        MethodProvenance(
            named=2,
            platform_default=37,
            unread=7,
            unread_examples=["http://target.example/api/bookings"],
        )
    )
    report = PentestReport(
        engagement_name="unread",
        target_scope=["http://target.example"],
        test_start=_WINDOW,
        test_end=_WINDOW,
        method_provenance=method_provenance_summary(),
    )
    lines: list[str] = []
    ReportAgent._render_method_provenance(lines, report)
    body = "\n".join(lines)
    assert "7 of 46 discovered endpoint(s) carry an HTTP method the engine could not read" in body
    assert "UNDISCOVERED, not absent" in body
    assert "limit of the test, not a reading of the application" in body
    assert "http://target.example/api/bookings" in body


def test_an_unmeasured_provenance_renders_nothing_rather_than_a_zero() -> None:
    """A counter nobody set is not a run in which every verb was read.

    The same distinction invariant 80 draws: a default is byte-identical to a
    producer's measured zero, so the summary carries ``measured`` and the
    renderer consults it before either branch.
    """
    from clinkz.agents.report import ReportAgent
    from clinkz.models.report import PentestReport

    set_active_plan_alarms(PlanAlarmRegister())
    summary = method_provenance_summary()
    assert summary["measured"] is False
    lines: list[str] = []
    ReportAgent._render_method_provenance(
        lines,
        PentestReport(
            engagement_name="unmeasured",
            target_scope=["http://target.example"],
            test_start=_WINDOW,
            test_end=_WINDOW,
            method_provenance=summary,
        ),
    )
    assert lines == []
