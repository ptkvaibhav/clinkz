"""Who offers a password, and who is bounded when they do — computed, not listed.

``SafetyPolicy.max_credential_attempts_per_account`` bounds credential attempts
per ``(origin, account)``. It bounds them at ONE place — ``EngagementGovernor``
``.authorize(..., account=...)`` — and a request reaches that place with an
account named only when the caller says so. ``HTTPClientTool.execute`` reads
``self.credential_account``, which is set at exactly one line in the whole
engine (``tools/auth.py``, the JSON arm), and ``WebAuthenticator`` names the
account at its own credential POST. **Every other credential-bearing request in
the engine is invisible to the budget**, and the biggest of them is the one
component whose entire purpose is to send failed logins:
``_test_brute_force`` submits ``_BRUTE_FORCE_ATTEMPTS`` passwords for the
account ``admin`` against every login form it finds, and the governor counts
none of them.

Measured over the stored corpus by classifying every recorded POST whose body
carried a password-shaped field:

    auth JSON arm      (account NAMED)        7095  in 168 engagements
    methodology        (account NOT named)    2796  in  81 engagements
    auth form arm      (account NAMED)         762  in 186 engagements

with 200 ungoverned credential POSTs against a single login form in engagement
``0fabde50`` alone. That is not a defect to close by making the class governed —
a class that must send eight failed logins cannot share a budget the
authenticator has already spent, and a brute-force test that abstains because
the login flow used its allowance would report an absence it never measured.
It is a defect to close by making the exemption **declared**, so the next
credential sender is looked at before it lands rather than discovered in a
corpus sweep afterwards.

So: the DOMAIN here is computed — every function under ``src/clinkz`` that
mentions a password-shaped identifier, whatever it does with it — and the
CLASSIFICATION is declared, one entry per function, with the reason. Both
directions are asserted, because a table entry that outlived its function is the
same rot as a function no entry covers.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "src" / "clinkz"

#: What counts as "this function is handling a password". Deliberately matched on
#: the identifier rather than on a call: the brute-force observation loop builds
#: its body from ``{username_field: ..., password_field: ...}`` — VARIABLE keys —
#: so a domain computed from literal dict keys cannot see the single largest
#: ungoverned credential sender in the engine. That is the guard-domain law's own
#: failure mode: the member that most needs the guard is the one a narrower
#: domain omits.
PASSWORD_TOKEN = re.compile(r"(?:^|_)(password|passwd|pwd)s?(?:_|$)", re.IGNORECASE)


class _Sender:
    """How a function in the domain is classified."""

    #: Sends a credential to the target and NAMES the account to the governor.
    GOVERNED = "governed"
    #: Sends a credential to the target and does NOT name the account.
    EXEMPT = "exempt"
    #: Handles a password without offering one to the target over the network.
    NO_DISPATCH = "no_dispatch"


#: ``qualified name -> (classification, reason)``. Hand-declared, entry by entry;
#: this is the half a human owns. A reason under six words fails, on the same
#: rule as the control-arm registry: "n/a" is not a classification.
DECLARED: dict[str, tuple[str, str]] = {
    # ---------------------------------------------------------------- governed
    "tools/auth.py::_run_form_arm": (
        _Sender.GOVERNED,
        "the form arm's credential POST goes through _governed_request, which names "
        "the account to the governor for every attempt",
    ),
    "tools/auth.py::_try_api_login": (
        _Sender.GOVERNED,
        "sets HTTPClientTool.credential_account before the POST, which is the one "
        "line in the engine that arms the chokepoint's per-account counter",
    ),
    "tools/http_client.py::execute": (
        _Sender.GOVERNED,
        "the chokepoint itself: it reads credential_account and passes account= to "
        "the governor, so it is where the budget is spent rather than assumed",
    ),
    # ------------------------------------------------------------------ exempt
    "agents/exploit.py::_brute_force_phase2_observation": (
        _Sender.EXEMPT,
        "_test_brute_force must be able to send its full series to measure whether a "
        "control trips; sharing the authenticator's per-account budget would make it "
        "report an absence it never measured, since the login flow spends that budget "
        "first. The attempts are disclosed in the finding instead (attempts_by_this_class) "
        "and the account it offers them for is _BRUTE_FORCE_PROBE_USERNAME",
    ),
    "agents/exploit.py::_present_artifact": (
        _Sender.EXEMPT,
        "carries a chained artifact back to the endpoint that would consume it; the "
        "password-shaped name is the carried field's, not a credential this engine "
        "chose to offer, and there is no account for a budget to key on",
    ),
    "orchestrator/orchestrator.py::_attempt_login": (
        _Sender.EXEMPT,
        "calls authenticate(), which spends the budget itself at the POST inside it; "
        "taking a second slot here would double-count every sweep guess",
    ),
    "orchestrator/orchestrator.py::_verify_and_refresh_session": (
        _Sender.EXEMPT,
        "same reason as _attempt_login: it re-enters authenticate(), and the budget "
        "is spent at the credential POST rather than at the call that wraps it",
    ),
    "agents/scan.py::_scan_ssh_service": (
        _Sender.EXEMPT,
        "reads an SSH service banner and never offers a password over that transport; "
        "the identifier names an auth METHOD the server advertises",
    ),
    # -------------------------------------------------------------- no dispatch
    "credentials/store.py::add": (
        _Sender.NO_DISPATCH,
        "writes a credential row to the local SQLite store; the execute() it calls is "
        "the database cursor's, not an HTTP request",
    ),
    "credentials/store.py::get": (
        _Sender.NO_DISPATCH,
        "reads credential rows out of the local store; no request leaves the machine",
    ),
    "credentials/store.py::get_all_valid": (
        _Sender.NO_DISPATCH,
        "reads credential rows out of the local store; no request leaves the machine",
    ),
    "credentials/store.py::get_defaults_for_technology": (
        _Sender.NO_DISPATCH,
        "returns catalogue rows for a technology label; nothing is dispatched anywhere",
    ),
    "credentials/store.py::seed_defaults": (
        _Sender.NO_DISPATCH,
        "seeds catalogue rows into the local store ahead of the sweep that will try them",
    ),
    "engagement/auth_state.py::detect_auth_mechanism": (
        _Sender.NO_DISPATCH,
        "classifies a response that was already fetched; it sends nothing itself",
    ),
    "engagement/auth_state.py::serves_login_form": (
        _Sender.NO_DISPATCH,
        "reads an already-fetched body for an input of type password; a pure predicate",
    ),
    "engagement/credential_shapes.py::redact_shapes": (
        _Sender.NO_DISPATCH,
        "rewrites secrets out of a string on the way to an artifact; the opposite direction",
    ),
    "engagement/credential_shapes.py::userpwd_repl": (
        _Sender.NO_DISPATCH,
        "the substitution callback inside redaction; it edits text and dispatches nothing",
    ),
    "engagement/secrets.py::prompt_for_credentials": (
        _Sender.NO_DISPATCH,
        "collects credentials from the operator at the terminal before the run starts",
    ),
    "models/engagement.py::secret": (
        _Sender.NO_DISPATCH,
        "a model property returning the credential's own value to callers in-process",
    ),
    "agents/_plan_ranking.py::rank_lfi": (
        _Sender.NO_DISPATCH,
        "orders LFI payload types; the token names a target FILE, not a credential",
    ),
    "agents/exploit.py::_is_login_form": (
        _Sender.NO_DISPATCH,
        "a shape predicate over parsed form fields; it decides, it does not send",
    ),
    "agents/exploit.py::_benign_param_value": (
        _Sender.NO_DISPATCH,
        "chooses a harmless value for a sibling field so a probe is not rejected early",
    ),
    "agents/exploit.py::_infer_field_type": (
        _Sender.NO_DISPATCH,
        "labels a form field from its name and attributes; a pure classification",
    ),
    "agents/exploit.py::_sqli_auth_bypass_applicable": (
        _Sender.NO_DISPATCH,
        "decides whether an endpoint's shape admits the auth-bypass arm at all",
    ),
    "agents/exploit.py::_harvest_known_valid_credentials": (
        _Sender.NO_DISPATCH,
        "collects credentials the engagement already holds, from local state only",
    ),
    "agents/exploit.py::_identities_authenticated_by": (
        _Sender.NO_DISPATCH,
        "maps a held credential to the principals it authenticates, in memory",
    ),
    "agents/exploit.py::_lfi_phase1_injection_point": (
        _Sender.NO_DISPATCH,
        "the token names /etc/passwd, a file this class reads, not a credential it offers",
    ),
    "agents/exploit.py::_lfi_phase2_fingerprint": (
        _Sender.NO_DISPATCH,
        "same token, same reason: /etc/passwd is the read target, not a password",
    ),
    "agents/exploit.py::_csrf_is_state_changing": (
        _Sender.NO_DISPATCH,
        "reads a form's fields to decide whether submitting it would change state",
    ),
    "agents/exploit.py::_csrf_is_security_sensitive": (
        _Sender.NO_DISPATCH,
        "reads a form's fields to decide whether the action is security-relevant",
    ),
    "orchestrator/orchestrator.py::_try_default_credentials": (
        _Sender.NO_DISPATCH,
        "plans and sequences the sweep; every actual attempt goes through _attempt_login",
    ),
    "orchestrator/orchestrator.py::_login_shape_of": (
        _Sender.NO_DISPATCH,
        "reads a fetched page for the shape of its login form; a pure predicate",
    ),
    "safety/destructive.py::_credential_identity_verdict": (
        _Sender.NO_DISPATCH,
        "classifies a request as a login or a credential change before it is sent",
    ),
    "safety/destructive.py::_legacy_form_verdict": (
        _Sender.NO_DISPATCH,
        "the older field-name path of the same classifier; it refuses, it never sends",
    ),
    "tools/auth.py::__init__": (
        _Sender.NO_DISPATCH,
        "constructs the authenticator and stores its scope; nothing is dispatched",
    ),
    "tools/auth.py::read_input": (
        _Sender.NO_DISPATCH,
        "reads the tool's declared input schema fields off the argument dict",
    ),
    "tools/auth.py::login_form": (
        _Sender.NO_DISPATCH,
        "extracts the login form and its fields from a page already fetched",
    ),
    "tools/auth.py::get_schema": (
        _Sender.NO_DISPATCH,
        "declares the tool's JSON input schema; it is a description, not a request",
    ),
    "tools/auth.py::validate_input": (
        _Sender.NO_DISPATCH,
        "validates the arguments handed to the tool before anything is dispatched",
    ),
    "tools/auth.py::_governed_request": (
        _Sender.GOVERNED,
        "the seam that takes the governor slot for a credential POST and names the "
        "account; this is the function the whole budget hangs off",
    ),
    "tools/auth.py::authenticate": (
        _Sender.EXEMPT,
        "sequences the two arms; each arm's own POST is what names the account, and "
        "a slot taken here would nest inside the one the arm takes",
    ),
    "tools/auth.py::_execute_aiohttp": (
        _Sender.EXEMPT,
        "the transport under the form arm; _governed_request has already authorized "
        "and counted the attempt before this is reached",
    ),
    "tools/auth.py::_execute_curl": (
        _Sender.EXEMPT,
        "the docker transport under the form arm, governed at the same seam as the "
        "aiohttp one, for the same reason",
    ),
}


def _mentions_password(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name) and PASSWORD_TOKEN.search(sub.id):
            return True
        if isinstance(sub, ast.Attribute) and PASSWORD_TOKEN.search(sub.attr):
            return True
        if isinstance(sub, ast.arg) and PASSWORD_TOKEN.search(sub.arg):
            return True
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            if PASSWORD_TOKEN.search(sub.value):
                return True
        if isinstance(sub, ast.Call):
            for keyword in sub.keywords:
                if keyword.arg and PASSWORD_TOKEN.search(keyword.arg):
                    return True
    return False


def _domain() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """Every function under ``src/clinkz`` that handles a password-shaped name."""
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if _mentions_password(node):
                found[f"{rel}::{node.name}"] = node
    return found


def test_every_password_handling_function_is_classified() -> None:
    """computed - declared: a new credential sender fails the build until named."""
    undeclared = sorted(set(_domain()) - set(DECLARED))
    assert not undeclared, (
        "these functions handle a password-shaped value and no entry says whether they "
        "offer it to the target, and if so whether the per-account budget can see it: "
        f"{undeclared}"
    )


def test_no_entry_outlived_the_function_it_described() -> None:
    """declared - computed: the half that stops the table rotting into a wish."""
    stale = sorted(set(DECLARED) - set(_domain()))
    assert not stale, f"declared for functions that no longer handle a password: {stale}"


@pytest.mark.parametrize("qualname", sorted(DECLARED))
def test_each_classification_carries_a_substantive_reason(qualname: str) -> None:
    classification, reason = DECLARED[qualname]
    assert classification in {_Sender.GOVERNED, _Sender.EXEMPT, _Sender.NO_DISPATCH}
    assert len(reason.split()) >= 6, f"{qualname}: an exemption needs a reason, not a label"


def test_the_brute_force_class_is_exempt_and_says_so() -> None:
    """The measurement this whole module exists for, pinned as a decision.

    Not an assertion that the exemption is harmless — an assertion that it is
    DECLARED. If someone routes the observation loop through the governor with
    an account named, this test fails and they have to come and change the
    sentence that tells the client what the attempts were.
    """
    classification, reason = DECLARED["agents/exploit.py::_brute_force_phase2_observation"]
    assert classification == _Sender.EXEMPT
    assert "budget" in reason


def test_only_one_place_arms_the_chokepoints_counter() -> None:
    """``credential_account`` is assigned exactly once under ``src/clinkz``.

    The count is the whole argument for this module. Every other credential
    sender is exempt *because* of this line's uniqueness, so a second assignment
    is a change to the story and has to be looked at.
    """
    assignments = [
        f"{path.relative_to(SRC).as_posix()}:{node.lineno}"
        for path in sorted(SRC.rglob("*.py"))
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Attribute) and target.attr == "credential_account"
    ]
    assert len(assignments) == 1, (
        f"credential_account is assigned at {assignments}; the exemption table in this "
        "module is written against there being exactly one such site"
    )
