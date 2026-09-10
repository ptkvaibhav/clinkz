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


def test_the_blocking_body_arm_declares_what_it_lost() -> None:
    """A control that narrows an oracle has a cost, and the cost is written down.

    ``_looks_blocked``'s body arm discards a signature this target already served
    in an unblocked response. That is right, and it costs exactly one case: a
    target that GENUINELY blocks with a phrase it also ships unconditionally.
    An SPA whose error shell carries "access denied" on every route, and which
    then really does start refusing us with that same shell, is invisible to the
    body arm — the marker was learned as benign before the block began.

    The case is accepted rather than mitigated, and the boundary is DECLARED
    (:data:`~clinkz.safety.governor.BLOCKING_BODY_ARM_BOUNDARY`) rather than left
    in the commit message that introduced the control. The next reader who finds
    a run that kept hammering a blocking target should find the sentence saying
    this was decided, not rediscover it as a bug.

    Two things the declaration must say, because they are what make the trade
    defensible rather than merely stated: the loss is LATE detection and not
    absent detection (the status arm is untouched), and the alternative
    generates absences that read as a clean target.
    """
    from clinkz.safety.governor import BLOCKING_BODY_ARM_BOUNDARY

    boundary = BLOCKING_BODY_ARM_BOUNDARY.lower()
    assert "429" in boundary and "503" in boundary, (
        "the boundary must name the arm that still fires, or it reads as a hole "
        "rather than as a narrowing"
    )
    assert "late" in boundary, "detected LATE is not the same as never detected"
    assert "clean target" in boundary, (
        "the boundary must say what the alternative costs — a false halt generates "
        "absences that read as an application with nothing to find"
    )
    assert len(BLOCKING_BODY_ARM_BOUNDARY.split()) >= 40


def test_the_boundary_reaches_the_operator_beside_the_discards(tmp_path) -> None:
    """The sentence sits in ``stats()`` next to ``benign_block_markers``.

    A boundary only in a source comment is a boundary the operator reading "we
    ruled out 'access denied'" never sees. They are the person who has to decide
    whether the run they are looking at was blocked, so the discard and the rule
    behind it belong in one record.
    """
    from clinkz.safety.governor import BLOCKING_BODY_ARM_BOUNDARY, EngagementGovernor

    governor = EngagementGovernor("boundary-test", outputs_root=tmp_path)
    stats = governor.stats()
    assert stats["blocking_body_arm_boundary"] == BLOCKING_BODY_ARM_BOUNDARY
    assert "benign_block_markers" in stats


def test_the_chokepoints_credential_observation_takes_a_control() -> None:
    """The THIRD credential-observation site, and the one invariant 98 missed.

    ``_login_verdict`` and ``classify_lockout`` got a control arm, and the
    authenticator's two form arms pass it. The JSON arm observes somewhere else
    entirely — through ``HTTPClientTool``, whose chokepoint calls
    ``observe_credential_response`` on every credential-bearing POST — and that
    site passed nothing.

    Measured on cal.diy: its 383 KB login page ships the strings ``rate limit``
    and ``try again later`` in every response. The two form attempts correctly
    DISCARDED them against their control; this site then classified the same
    bytes as a rate-limit stop, which refuses every later credential for the
    account. A stop asserting the client's account is rate limited, produced by
    a string in a page footer — and, because the adaptive-auth layer runs after
    the deterministic pass, a stop that took the whole capability with it.

    Asserted on the SIGNATURE and the wiring rather than on behaviour, because
    the failure mode is a parameter nobody passes: a control that exists and is
    not handed over is byte-identical to no control at all.
    """
    import inspect

    from clinkz.tools.http_client import HTTPClientTool

    signature = inspect.signature(HTTPClientTool._observe_credential)
    assert "control_body" in signature.parameters, (
        "the chokepoint's lockout classifier takes no control — the same defect "
        "invariant 98 fixed for _login_verdict and classify_lockout"
    )

    source = inspect.getsource(HTTPClientTool)
    assert "control_body=self.credential_control_body" in source, (
        "the control is declared and not handed over, which is byte-identical to having none"
    )
    assert "control_body=control_body" in source, (
        "the control reaches classify_lockout, not just the method boundary"
    )


def test_every_credential_arming_site_arms_the_control_too() -> None:
    """The account and its control are armed together, or the budget is spent blind.

    A caller that names the account and supplies no control is a caller whose
    credential attempts can be stopped by the application's own vocabulary — and
    it is exactly the shape that was live until cal.diy exposed it. Computed
    over the source rather than listed, so a fourth arming site has to answer
    this question before it can send anything.

    The exemption is stated where it applies: a site with no un-credentialed
    response to compare against passes ``""``, which discards nothing and is the
    behaviour that predates the parameter — but it must do so DELIBERATELY, by
    naming the attribute, rather than by never mentioning it.
    """
    src = Path(__file__).resolve().parents[2] / "src" / "clinkz"
    arming: dict[str, set[str]] = {}
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        attrs = {
            target.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Attribute)
            and target.attr in ("credential_account", "credential_control_body")
        }
        if "credential_account" in attrs:
            arming[path.relative_to(src).as_posix()] = attrs

    assert arming, "the scanner found no arming site at all — it is measuring nothing"
    blind = sorted(
        name
        for name, attrs in arming.items()
        if "credential_control_body" not in attrs and not name.endswith("http_client.py")
    )
    assert not blind, (
        "these callers name the account for the per-account budget and never mention "
        f"the lockout control, so their attempts can be stopped by page furniture: {blind}"
    )


# ---------------------------------------------------------------------------
# The domain over the CALL — the half a domain over the ORACLE cannot see
# ---------------------------------------------------------------------------
#
# Everything above computes over ORACLE BODIES: a function is in the domain
# because of what IT reads. That domain was written to answer "where else does
# the engine decide on a marker", and it answered it — and then the adaptive
# authentication layer landed with a credential-observation site inside it that
# the domain did not contain, which is the guard-domain law failing inside the
# guard built for the guard-domain law.
#
# The reason is worth more than the site. ``HTTPClientTool._observe_credential``
# is NOT a marker oracle: it reads no marker, it parses an envelope and forwards
# ``body=`` to ``classify_lockout`` two hops away, and it returns ``None`` so it
# fails ``_verdict_shaped`` as well. It was excluded twice, correctly, on the
# domain's own terms.
#
# **The defect is the terms.** ``classify_lockout`` is classified HAS_CONTROL
# because it TAKES a ``control_body`` parameter — declared ``control_body: str =
# ""``, which means "discard nothing", which is the pre-fix behaviour. The same
# permissive default sat at every hop: ``_observe_credential`` ->
# ``observe_credential_response(control_body="")`` -> ``classify_lockout(
# control_body="")``. So:
#
#     A control that is an OPTIONAL PARAMETER WITH A PERMISSIVE DEFAULT turns a
#     guard about the callee into an unguarded property of every call site. An
#     oracle marked HAS_CONTROL is only as controlled as its least careful
#     caller, and no domain computed over oracle bodies can see a caller.
#
# It stayed invisible while the auth path had ONE consumer, because then "the
# oracle takes a control" and "every call passes a control" were the same
# sentence. The adaptive layer made them two sentences.
#
# So the domain below is computed over CALLS: every function that hands a body
# to one of these oracles, or that arms the attribute one of them reads. The
# classification is computed too — whether the call actually passes a control —
# and the declaration carries the REASON, so a site that stops supplying one
# fails against its own entry rather than silently rejoining the pre-fix
# behaviour.


#: Oracles that accept a control body. A call to one of these is a call that
#: either supplies a control or declines to.
CONTROL_TAKERS: frozenset[str] = frozenset(
    {
        "classify_lockout",
        "observe_credential_response",
        "_observe_credential",
        "_observe_credential_response",
        "_login_verdict",
    }
)

#: The attribute a caller arms so the chokepoint's own observation is
#: controlled. Assigning it is supplying a control one hop early.
CONTROL_ATTRIBUTE = "credential_control_body"


class _Supply:
    """What a call site does about the control the oracle it reaches accepts."""

    #: Hands over a control body that is not an empty literal.
    SUPPLIES = "supplies_a_control"
    #: Hands over nothing, or an empty literal. Declared, never inferred.
    NONE = "supplies_no_control"


def _is_empty_literal(node: ast.AST) -> bool:
    """Whether an argument is a hardcoded empty string."""
    return isinstance(node, ast.Constant) and node.value == ""


def _control_sites() -> dict[str, str]:
    """Every function reaching a control-taking oracle, and what it supplies.

    Two ways to reach one, and both count:

    * calling it, passing (or not passing) ``control_body`` — ``classify_lockout``
      also takes it fourth positionally, which is how the exploit path's brute-
      force observation supplies one;
    * arming :data:`CONTROL_ATTRIBUTE`, which the HTTP chokepoint reads at the
      credential POST. That is the seam the adaptive-auth dispatcher uses, and
      it is invisible to any domain that looks only at calls.

    A function supplies a control when every route it takes to an oracle carries
    one. One uncontrolled route is enough to classify the whole site
    :attr:`_Supply.NONE`: the guard is about what can reach an oracle
    uncontrolled, not about what usually does.
    """
    sites: dict[str, list[bool]] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            qualname = f"{rel}::{node.name}"
            for sub in ast.walk(node):
                if isinstance(sub, ast.Assign):
                    for target in sub.targets:
                        if isinstance(target, ast.Attribute) and target.attr == CONTROL_ATTRIBUTE:
                            sites.setdefault(qualname, []).append(not _is_empty_literal(sub.value))
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
                if name not in CONTROL_TAKERS:
                    continue
                keyword = next((k for k in sub.keywords if k.arg == "control_body"), None)
                if keyword is not None:
                    supplied = not _is_empty_literal(keyword.value)
                elif name == "classify_lockout" and len(sub.args) >= 4:
                    # Its control is the fourth positional.
                    supplied = not _is_empty_literal(sub.args[3])
                else:
                    supplied = False
                sites.setdefault(qualname, []).append(supplied)
    return {
        qualname: _Supply.SUPPLIES if all(flags) else _Supply.NONE
        for qualname, flags in sites.items()
    }


#: ``qualified name -> reason``. Every entry is a call site the computation
#: above found; its classification is COMPUTED, so this table carries only the
#: half a human owns — why the site is shaped that way.
DECLARED_CONTROL_SITES: dict[str, str] = {
    # -------------------------------------------------------- the exploit path
    "agents/exploit.py::_brute_force_phase2_observation": (
        "passes the class's own baseline body fourth-positionally to classify_lockout, so "
        "a login page that ships 'too many attempts' as furniture cannot stop the series "
        "this class exists to measure"
    ),
    # -------------------------------------------------- the deterministic path
    "safety/governor.py::observe_credential_response": (
        "forwards the caller's control straight through to classify_lockout; the governor "
        "holds no un-credentialed response of its own and must not invent one"
    ),
    "tools/auth.py::_dispatch": (
        "hands the login page the authenticator already fetched to the credential "
        "observation, which is the one body on this path the credential provably did not "
        "produce"
    ),
    "tools/auth.py::_execute_aiohttp": (
        "the host transport's credential exchange: both the login verdict and the lockout "
        "observation get the login HTML this arm fetched before the POST"
    ),
    "tools/auth.py::_execute_curl": (
        "the docker transport's credential exchange, controlled identically to the host "
        "one, because a verdict that differs by execution mode is a defect the mode hides"
    ),
    "tools/auth.py::_observe_credential_response": (
        "forwards its caller's control to the governor unchanged; it is a seam, and a seam "
        "that substituted a control would be inventing evidence"
    ),
    "tools/auth.py::_post": (
        "the form arm's POST hands the login page it just read to the credential "
        "observation, so a nav-bar phrase cannot halt the engagement"
    ),
    # ------------------------------------------------------------ the chokepoint
    "tools/http_client.py::execute": (
        "reads credential_control_body off the tool and hands it to the credential "
        "observation. This is the site the oracle-shaped domain could not see: it reads no "
        "marker and returns no verdict, and it decides whether every credential POST in "
        "the engine is controlled"
    ),
    "tools/http_client.py::_observe_credential": (
        "forwards the armed control to the governor. Its own signature still defaults to "
        "the empty string, which is why this table exists: the default makes the oracle as "
        "controlled as its least careful caller, so the callers are what is asserted"
    ),
    # ------------------------------------------------------- the adaptive path
    "engagement/auth_agent_dispatch.py::_send": (
        "arms credential_control_body from the login page's own lockout markers before "
        "every adaptive credential POST. The adaptive layer runs only after the "
        "deterministic pass has already spent from this account, so a false stop here does "
        "not cost a retry — it costs the whole episode"
    ),
    "tools/auth.py::_api_post_json": (
        "arms credential_control_body for the JSON arm's POST, which walks up to eight "
        "routes on one host offering the same password to each"
    ),
}


def test_every_call_that_reaches_a_control_taking_oracle_is_declared() -> None:
    """computed - declared: a new credential-observation site fails the build.

    The test that would have caught the adaptive layer's third site on the day
    it landed, rather than in a corpus sweep afterwards.
    """
    undeclared = sorted(set(_control_sites()) - set(DECLARED_CONTROL_SITES))
    assert not undeclared, (
        "these functions hand a body to an oracle that accepts a control, or arm the "
        "attribute one reads, and no entry says what they supply. An oracle is only as "
        f"controlled as its least careful caller: {undeclared}"
    )


def test_no_call_site_entry_outlived_its_function() -> None:
    stale = sorted(set(DECLARED_CONTROL_SITES) - set(_control_sites()))
    assert not stale, f"declared for call sites that no longer reach an oracle: {stale}"


@pytest.mark.parametrize("qualname", sorted(DECLARED_CONTROL_SITES))
def test_each_call_site_reason_is_substantive(qualname: str) -> None:
    reason = DECLARED_CONTROL_SITES[qualname]
    assert len(reason.split()) >= 8, f"{qualname}: a call site needs a reason, not a label"


def test_every_declared_call_site_actually_supplies_a_control() -> None:
    """The property itself, asserted over the COMPUTED domain.

    Not "these sites are declared" — "every site that can reach one of these
    oracles hands it something the credential did not produce". A site that
    starts passing ``""`` fails here, which is the failure mode the permissive
    default was silently reintroducing at each new consumer.
    """
    computed = _control_sites()
    uncontrolled = sorted(q for q, how in computed.items() if how is not _Supply.SUPPLIES)
    assert not uncontrolled, (
        "these sites reach an oracle that accepts a control and pass none, so a phrase the "
        f"target serves whatever it is sent counts as evidence about a credential: "
        f"{uncontrolled}"
    )


def test_the_adaptive_path_is_inside_this_domain() -> None:
    """Pinned as a decision, because it was outside it for two merged PRs.

    Measured 2026-09-09: of this module's 36-member oracle domain, ONE member
    lived on the deterministic auth path and NONE on the adaptive one, while the
    adaptive dispatcher was arming the control for every credential POST it
    sent. The property held; the guard could not see that it held.
    """
    computed = _control_sites()
    assert computed.get("engagement/auth_agent_dispatch.py::_send") == _Supply.SUPPLIES
    assert any(q.startswith("engagement/auth_agent") for q in computed), (
        "the adaptive-auth path left this domain; if its dispatcher no longer arms the "
        "control, that is the regression this test exists for"
    )
