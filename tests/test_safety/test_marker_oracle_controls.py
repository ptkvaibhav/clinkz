"""Every oracle that reads a target-controlled body for a marker we chose — with what.

Invariants 27 and 30 bind every dispatched methodology: no marker oracle
confirms without a control arm that REFUSED, and the arm must round-trip like
the payload. The exploit path enforces that on every class it dispatches. The
**authentication path had no equivalent at all**: the engine held the login-page
GET and the credential POST of the same URL, identical byte length, and compared
nothing. A failure keyword in a page that carries it whatever we send read as
"the application refused this credential", and the same defect in
``classify_lockout`` — where a phrase does not merely misread one exchange but
HALTS THE ENGAGEMENT and asserts the client account is locked — was one nav-bar
link away on every DVWA page.

So the question this module answers is *where else*. The DOMAIN is computed:
every function under ``src/clinkz`` that tests a marker **we** chose (a string
literal, or an element of a literal phrase collection) against something
body-shaped. That last qualifier is what made the first pass of this domain
useless and the second pass honest — ``_login_verdict`` builds its vocabulary as
a local ``list`` on the line above the loop, so a domain that only recognised
UPPERCASE module constants excluded the single member the whole exercise is
about. The guard-domain law, one more time: the member that most needs the guard
is the one a narrow domain omits.

The CLASSIFICATION is declared, one entry per function, with the reason.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"

#: Names that ARE a response body, or a lowered / normalised copy of one.
BODY_NAME = re.compile(
    r"^(body|html|text|page_source|resp_body|response_body|post_body|miss_body|"
    r"baseline_body|control_body|corroborating_body|payload_body|body_lower|"
    r"lowered|low|lower_body|blob|haystack|page_text|rendered|stdout|snippet|"
    r"content|page|doc|source)$",
    re.IGNORECASE,
)


class _Control:
    """What licenses this oracle to read a marker out of a body."""

    #: A response the payload did not produce is compared, and the marker only
    #: counts when the control does NOT carry it.
    HAS_CONTROL = "has_control"
    #: No control, and none is needed: a false positive here can only SUPPRESS,
    #: refuse, redact or narrow. It has no path to a finding.
    SAFE_DIRECTION = "no_control_safe_direction"
    #: No control, and the marker is not read out of anything the target wrote —
    #: our own tool output, source we ingested, a config value, a URL we built.
    NOT_A_TARGET_BODY = "not_a_target_body"
    #: No control, and a false positive HALTS or BLOCKS the engagement. This is
    #: the shape ``classify_lockout`` had, and it is reported rather than hidden.
    STOPS_THE_RUN = "no_control_stops_the_run"
    #: No control, and a false positive can reach a CONFIRMED finding. The set
    #: this module exists to keep small, visible, and deliberate.
    CAN_CONFIRM = "no_control_can_confirm"


#: ``qualname -> (classification, reason)``. The half a human owns.
DECLARED: dict[str, tuple[str, str]] = {
    # ------------------------------------------------------------ has control
    "tools/auth.py::_login_verdict": (
        _Control.HAS_CONTROL,
        "takes control_body — the login page served without credentials, the same URL "
        "and the same jar — and a refusal marker present in it is discarded and named "
        "in the evidence rather than allowed to decide the verdict",
    ),
    "safety/lockout.py::classify_lockout": (
        _Control.HAS_CONTROL,
        "takes control_body and discards any phrase the control carries too; headers "
        "and status are deliberately not control-compared because a protocol artifact "
        "the server emitted cannot be page furniture",
    ),
    "agents/exploit.py::_brute_force_attempt_reached_auth": (
        _Control.HAS_CONTROL,
        "requires the auth-failure marker to be absent from the unauthenticated page "
        "baseline it already holds, and falls back to a whole-body difference against "
        "that same baseline",
    ),
    "agents/_input_validation.py::response_accepted": (
        _Control.HAS_CONTROL,
        "its only consumer, evaluate(), runs it on the probe AND on a malformed control "
        "and confirms nothing unless the control was REJECTED; acceptance alone is "
        "explicitly not evidence about the declared constraint",
    ),
    "agents/exploit.py::_session_issued": (
        _Control.HAS_CONTROL,
        "reached only through _present_artifact, which runs the identical request for "
        "the real artifact and for a decoy the target never issued; a decoy that is "
        "also accepted yields a ChainResearchLead rather than a finding",
    ),
    "agents/exploit.py::_looks_like_login_page": (
        _Control.HAS_CONTROL,
        "same seam as _session_issued: the decoy round-trips like the payload, so a "
        "login page recognised on both arms refuses the chain rather than confirming it",
    ),
    # ----------------------------------------------------------- safe direction
    "agents/exploit.py::_idor_response_indicates_not_a_resource": (
        _Control.SAFE_DIRECTION,
        "a match makes the class ABSTAIN — the reference resolved to nothing the caller "
        "can see, which is the opposite of an IDOR; a false positive drops a true "
        "positive and can never emit one",
    ),
    "agents/exploit.py::_idor_param_is_excluded": (
        _Control.SAFE_DIRECTION,
        "excludes auth and token parameters from IDOR candidacy before any probe is "
        "sent; a false positive narrows the tested set and never widens a verdict",
    ),
    "agents/exploit.py::_csrf_is_security_sensitive": (
        _Control.SAFE_DIRECTION,
        "decides whether a form is worth testing at all; candidacy is not emission, and "
        "the class still has to observe a missing or ineffective token afterwards",
    ),
    "engagement/credential_shapes.py::redact_shapes": (
        _Control.SAFE_DIRECTION,
        "a match REDACTS. Over-redaction costs readability in an artifact; the failure "
        "the other way is a live credential in a client deliverable",
    ),
    "engagement/credential_shapes.py::find_shapes": (
        _Control.SAFE_DIRECTION,
        "the disclosure gate half of the same vocabulary: a match FAILS the bundle, "
        "which is the direction that cannot cause a leak",
    ),
    "safety/destructive.py::_legacy_form_verdict": (
        _Control.SAFE_DIRECTION,
        "a match REFUSES to submit a form; a false positive costs coverage and is "
        "disclosed as a withheld technique, never a claim about the target",
    ),
    "browser/_container_runner.py::run_witness": (
        _Control.SAFE_DIRECTION,
        "keeps CSP-related console lines as target-authored evidence; P7 only ever "
        "PROMOTES, so no console line has a path to demoting or suppressing anything",
    ),
    "agents/exploit.py::_weak_session_phase2_observation": (
        _Control.SAFE_DIRECTION,
        "reads HttpOnly / Secure / SameSite off the Set-Cookie header the server wrote. "
        "An attribute absence is complete in one response, so there is nothing a second "
        "response could control for",
    ),
    "agents/exploit.py::_file_upload_phase2_fingerprint": (
        _Control.SAFE_DIRECTION,
        "records that the endpoint rejects zero-byte or oversize uploads; the observation "
        "shapes later probes and is never itself a finding",
    ),
    "agents/exploit.py::_lfi_phase2_fingerprint": (
        _Control.SAFE_DIRECTION,
        "the marker is a value THIS ENGINE sent, base64-encoded inside a data:// wrapper, "
        "so a match is attributable to the payload; it records wrapper support for phase "
        "three and emits nothing",
    ),
    "agents/exploit.py::_security_header_severity": (
        _Control.SAFE_DIRECTION,
        "reads the weakness strings this engine wrote about a CSP it already parsed, not "
        "a body the target controls; it grades a finding that is already decided",
    ),
    # --------------------------------------------------------- not a target body
    "tools/sqlmap.py::parse_output": (
        _Control.NOT_A_TARGET_BODY,
        "parses sqlmap stdout against sqlmap own conclusion vocabulary; a not-injectable "
        "marker is checked FIRST so an ambiguous run reads as negative",
    ),
    "llm/providers.py::validate_provider_key": (
        _Control.NOT_A_TARGET_BODY,
        "matches an exception string raised by a provider SDK to classify a key status; "
        "no pentest target is anywhere in that path",
    ),
    "agents/_js_api_mining.py::object_literal_fields": (
        _Control.NOT_A_TARGET_BODY,
        "brace matching while parsing a JavaScript object literal; the marker is syntax, "
        "not a security signal",
    ),
    "agents/_js_api_mining.py::_balanced_object": (
        _Control.NOT_A_TARGET_BODY,
        "brace matching in the same parser, for the same reason",
    ),
    "agents/_js_api_mining.py::_body_fields_from_expr": (
        _Control.NOT_A_TARGET_BODY,
        "brace matching in the same parser, for the same reason",
    ),
    "agents/_js_api_mining.py::mine_api_call_sites": (
        _Control.NOT_A_TARGET_BODY,
        "paren matching while locating call sites in a bundle; syntax, not a verdict",
    ),
    "discovery/js_source_ingest.py::_build_handler_registry": (
        _Control.NOT_A_TARGET_BODY,
        "brace matching over a source tree the engagement supplied, not over a response",
    ),
    "discovery/js_source_ingest.py::_resolve_handler": (
        _Control.NOT_A_TARGET_BODY,
        "paren matching over that same supplied source tree",
    ),
    "agents/_route_discovery.py::_spec_request_body": (
        _Control.NOT_A_TARGET_BODY,
        "picks a preferred media type out of an OpenAPI operation; the literals are "
        "media types, and the structure is a spec rather than a rendered page",
    ),
    "discovery/versions.py::_parse_prerelease": (
        _Control.NOT_A_TARGET_BODY,
        "splits a semver prerelease on its hyphen; the marker is version grammar",
    ),
    "engagement/artifact_scan.py::_line_and_column": (
        _Control.NOT_A_TARGET_BODY,
        "counts newlines to report where in OUR OWN artifact a match was found",
    ),
    "engagement/cli_inputs.py::looks_like_scope_file": (
        _Control.NOT_A_TARGET_BODY,
        "decides whether an operator argument is a URL or a path, before any request",
    ),
    "engagement/cli_inputs.py::names_a_scope_document": (
        _Control.NOT_A_TARGET_BODY,
        "the same question about the same operator-typed argument",
    ),
    "tools/component_names.py::split_name_version": (
        _Control.NOT_A_TARGET_BODY,
        "splits a component name from its version on a separator; the marker is naming "
        "grammar and never a response",
    ),
    "agents/_url_safety.py::_is_session_setter_basename": (
        _Control.NOT_A_TARGET_BODY,
        "reads the basename of a URL PATH, not a body; a match keeps the crawl away "
        "from a session setter, which is also the safe direction",
    ),
    "agents/exploit.py::_idor_phase1_reference_point": (
        _Control.NOT_A_TARGET_BODY,
        "the literals are matched against a PARAMETER NAME, not a response body — the "
        "local is called low, which is why the computed domain flags it — and the name "
        "signal only decides candidacy; the four dispatched arms decide the verdict",
    ),
    "agents/exploit.py::_normalise_traversal_segment": (
        _Control.NOT_A_TARGET_BODY,
        "re-encodes the slashes in a payload THIS ENGINE built, before sending it",
    ),
    "safety/governor.py::_looks_blocked": (
        _Control.HAS_CONTROL,
        "the body arm takes a control that costs no traffic: a signature this same "
        "target already served in an unblocked response (a 2xx/3xx carrying no WAF "
        "header) is its own error vocabulary and is discarded and NAMED in the "
        "governor summary. The consecutive-blocked mitigation this replaces did not "
        "bound an unconditionally-shipped marker — an SPA that ships its error "
        "strings in every shell satisfies CONSECUTIVE by construction and the "
        "counter never resets. Status still outranks keyword: 429/503 halt regardless",
    ),
    # ------------------------------------------------------ can confirm
    "agents/exploit.py::_xxe_phase5_verify": (
        _Control.CAN_CONFIRM,
        "the DoS arm confirms on a timing delta OR on a 503 OR on the phrase "
        "temporarily not available. The timing arm has a benign well-formed control "
        "beside it and the phrase arm does not, so a page carrying that phrase confirms "
        "an entity-expansion DoS on a target that never parsed the payload",
    ),
}


def _body_of(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and BODY_NAME.match(node.id):
        return node.id
    if isinstance(node, ast.Attribute) and BODY_NAME.match(node.attr):
        return node.attr
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr in ("lower", "casefold", "strip"):
            return _body_of(node.func.value)
    if isinstance(node, ast.BoolOp):
        for value in node.values:
            got = _body_of(value)
            if got:
                return got
    return None


def _literal_marker(node: ast.AST, loop_vars: set[str]) -> bool:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return True
    if isinstance(node, ast.Name) and node.id in loop_vars:
        return True
    if isinstance(node, ast.Tuple) and node.elts:
        return _literal_marker(node.elts[0], loop_vars)
    return False


def _loop_vars_over_literals(fn: ast.AST) -> set[str]:
    """Loop targets iterating a literal, a module constant, or a LOCAL literal list.

    The local half is load-bearing. ``_login_verdict`` built its failure
    vocabulary as ``failure_keywords = [...]`` immediately above the loop that
    read it, so a domain recognising only UPPERCASE constants excluded exactly
    the function this module was written for.
    """
    local_literals: set[str] = set()
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Assign) and isinstance(sub.value, ast.List | ast.Tuple | ast.Set):
            elts = sub.value.elts
            if elts and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in elts):
                for target in sub.targets:
                    if isinstance(target, ast.Name):
                        local_literals.add(target.id)

    out: set[str] = set()
    for sub in ast.walk(fn):
        generators: list[tuple[ast.AST, ast.AST]] = []
        if isinstance(sub, ast.For | ast.AsyncFor):
            generators = [(sub.target, sub.iter)]
        elif isinstance(sub, ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp):
            generators = [(gen.target, gen.iter) for gen in sub.generators]
        for target, iterable in generators:
            literal = isinstance(iterable, ast.Tuple | ast.List | ast.Set)
            constant = isinstance(iterable, ast.Name) and (
                iterable.id.isupper() or iterable.id in local_literals
            )
            attribute = isinstance(iterable, ast.Attribute) and iterable.attr.isupper()
            if not (literal or constant or attribute):
                continue
            for name in ast.walk(target):
                if isinstance(name, ast.Name):
                    out.add(name.id)
    return out


def _verdict_shaped(fn: ast.AST) -> bool:
    """Whether the function returns something a caller reads as an answer."""
    for sub in ast.walk(fn):
        if isinstance(sub, ast.Return) and sub.value is not None:
            value = sub.value
            if isinstance(value, ast.Constant) and isinstance(value.value, bool):
                return True
            if isinstance(value, ast.Compare | ast.BoolOp):
                return True
            if isinstance(value, ast.Call):
                func = value.func
                if isinstance(func, ast.Name) and func.id[:1].isupper():
                    return True
            if isinstance(value, ast.Attribute) and value.attr.isupper():
                return True
            if isinstance(value, ast.Tuple | ast.Name | ast.Subscript | ast.Attribute):
                return True
    return False


def _domain() -> dict[str, list[int]]:
    """Every function testing a marker WE chose against something body-shaped."""
    found: dict[str, list[int]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            loop_vars = _loop_vars_over_literals(node)
            hits: list[int] = []
            for sub in ast.walk(node):
                if isinstance(sub, ast.Compare):
                    for op, comparator in zip(sub.ops, sub.comparators, strict=False):
                        if not isinstance(op, ast.In | ast.NotIn):
                            continue
                        if _body_of(comparator) and _literal_marker(sub.left, loop_vars):
                            hits.append(sub.lineno)
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute):
                    if sub.func.attr not in ("find", "count", "index", "startswith", "endswith"):
                        continue
                    if (
                        _body_of(sub.func.value)
                        and sub.args
                        and _literal_marker(sub.args[0], loop_vars)
                    ):
                        hits.append(sub.lineno)
            if hits and _verdict_shaped(node):
                found[f"{rel}::{node.name}"] = sorted(hits)
    return found


def test_every_marker_oracle_declares_what_licenses_it() -> None:
    """computed - declared: a new marker oracle fails the build until classified."""
    undeclared = sorted(set(_domain()) - set(DECLARED))
    assert not undeclared, (
        "these functions decide on a marker WE chose, found inside something "
        "body-shaped, and no entry says what licenses that. Invariants 27 and 30 want "
        "a control; if one is genuinely not needed, say which of the four other "
        f"classifications applies and why: {undeclared}"
    )


def test_no_entry_outlived_the_function_it_described() -> None:
    stale = sorted(set(DECLARED) - set(_domain()))
    assert not stale, f"declared for functions that no longer read a marker: {stale}"


@pytest.mark.parametrize("qualname", sorted(DECLARED))
def test_each_classification_carries_a_substantive_reason(qualname: str) -> None:
    classification, reason = DECLARED[qualname]
    assert classification in {
        _Control.HAS_CONTROL,
        _Control.SAFE_DIRECTION,
        _Control.NOT_A_TARGET_BODY,
        _Control.STOPS_THE_RUN,
        _Control.CAN_CONFIRM,
    }
    assert len(reason.split()) >= 8, f"{qualname}: a classification needs a reason, not a label"


def test_the_uncontrolled_confirming_set_is_named_and_small() -> None:
    """The answer to "where else", pinned so it cannot grow quietly.

    Not an assertion that these are acceptable — an assertion that they are
    DECLARED. Adding a sixth uncontrolled oracle that can confirm should require
    editing this number and saying so out loud.
    """
    uncontrolled = sorted(
        q
        for q, (how, _) in DECLARED.items()
        if how in (_Control.CAN_CONFIRM, _Control.STOPS_THE_RUN)
    )
    assert uncontrolled == [
        "agents/exploit.py::_xxe_phase5_verify",
    ], f"the uncontrolled marker oracles changed: {uncontrolled}"


def test_the_two_auth_path_oracles_now_take_a_control() -> None:
    """The fix this module was written alongside, pinned as a decision."""
    for qualname in ("tools/auth.py::_login_verdict", "safety/lockout.py::classify_lockout"):
        classification, reason = DECLARED[qualname]
        assert classification == _Control.HAS_CONTROL
        assert "control" in reason


def test_the_blocking_oracle_now_takes_a_control() -> None:
    """``_looks_blocked`` left the uncontrolled set, and by which route.

    Pinned separately from the auth-path pair because the control has a
    different SOURCE: those two dispatch a control request, this one reads a
    response the engagement already holds. A future edit that reintroduces a
    dispatch here should have to change this test.
    """
    classification, reason = DECLARED["safety/governor.py::_looks_blocked"]
    assert classification == _Control.HAS_CONTROL
    assert "no traffic" in reason
