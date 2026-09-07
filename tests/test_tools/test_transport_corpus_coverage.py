"""Which auth fixtures reach a transport, and which reach only ONE — computed, then declared.

``test_auth_transport_equivalence.py`` pins its scenarios against both credential
arms. Those were **chosen**: each is a shape the two arms had already been caught
diverging on, written down after the divergence was found by reading the
implementations side by side. A corpus assembled from past failures covers past
failures. (How many there are is deliberately not written down here — a count in
a docstring is a second place for the corpus size to live, and it is the one that
goes stale. ``test_the_corpus_is_not_empty`` reads the suite itself.)

This file computes the other half. It walks ``tests/`` and works out, per test
function, which credential arm that test actually drives — ``_execute_aiohttp``,
``_execute_curl``, or (via ``authenticate`` / ``execute`` / ``_dispatch``)
whichever arm the execution mode in force selects. Then it reports the DELTA:

* every test that drives **both** arms is an equivalence pin, and needs nothing;
* every test that drives **exactly one** is a shape being asserted on one
  transport only, and must say why. That is how every divergence so far has
  hidden — not in a scenario someone forgot to write, but in a fixture that
  existed, passed, and only ever ran one arm.

The domain is computed from the tree; only the per-test reason is
hand-maintained, and both directions are asserted, so a new single-arm fixture is
a red build rather than a quiet asymmetry. An entry for a test that no longer
exists fails too — a reason that outlives its test reads as coverage.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parents[1]

#: Attribute names that name a credential arm outright.
_DIRECT_ARM = {
    "_execute_aiohttp": "aiohttp",
    "_execute_curl": "curl",
}

#: Calls that reach a credential arm through ``_dispatch``, which picks one by
#: execution mode. A test that makes one of these drives whichever arm the mode
#: in force selects.
_MODE_DISPATCHED = {"authenticate", "_dispatch", "execute", "_run_form_arm"}

#: ``TOOL_EXEC_MODE`` value -> the arm ``_dispatch`` routes to.
_MODE_ARM = {"local": "aiohttp", "docker": "curl"}


#: test qualname -> why it is asserted on ONE transport only.
#:
#: An exemption is an allow-list entry with a substantive reason, never a silent
#: skip. "It is a unit test" is not a reason: a unit test of a shape the other
#: arm also handles is exactly the fixture that hides a divergence.
_MERIDIAN = "test_engagement.test_meridian_auth"
_SCOPE = "test_tools.test_credential_redirect_scope"
_SCOPE_GET = f"{_SCOPE}:TestTheLoginPageGetIsWalkedToo"
_SCOPE_CHAIN = f"{_SCOPE}:TestRedirectChainHasOneMeaning"
_PROMOTED = "test_tools.test_promoted_session_login"

SINGLE_ARM_REASONS: dict[str, str] = {
    # ---- Meridian: an in-process origin, and every shape it asserts is in the
    # two-arm corpus by shape rather than by this file.
    f"{_MERIDIAN}:test_the_415_is_read_as_a_content_type_negotiation": (
        "The 415 negotiation itself is held to both arms by the "
        "a_415_names_the_encoding_and_the_retry_authenticates and "
        "a_415_naming_an_encoding_we_cannot_produce_is_not_retried scenarios. "
        "What this test adds is that MERIDIAN's particular 415 is read that "
        "way, which is a statement about the target, not about a transport."
    ),
    f"{_MERIDIAN}:test_wrong_credentials_do_not_authenticate": (
        "The refused-credential shape is held to both arms by the "
        "rejected_credential_redirects_back_to_the_login_page and "
        "pre_credential_cookie_and_the_login_page_served_back scenarios. This "
        "one asserts the whole verdict tuple against a live-shaped target."
    ),
    f"{_MERIDIAN}:test_the_login_page_spelling_does_not_change_the_verdict": (
        "The /portal/gateway regression. Its subject is the ASSERTION oracle "
        "and the name gate it used to carry, which sits above the credential "
        "arms entirely — assert_authenticated has one implementation and no "
        "transport of its own to diverge across."
    ),
    f"{_MERIDIAN}:test_the_redirect_boundary_is_proven_under_either_spelling": (
        "Same subject as the spelling test: the discriminator the assertion "
        "found, which is produced by assert_authenticated rather than by "
        "either credential arm. Nothing here is transport-shaped."
    ),
    f"{_MERIDIAN}:test_a_public_path_yields_no_discriminator": (
        "The negative control for the assertion, not for the login: it asserts "
        "that a path behaving identically with and without a session proves "
        "nothing. Again assert_authenticated's, and it has one implementation."
    ),
    # ---- Scope refusal: the SHAPE is now two-armed; these assert internals
    # that are per-arm by construction.
    f"{_SCOPE}:test_a_body_preserving_redirect_off_scope_sends_no_credential": (
        "The shape is held to both arms by the new "
        "a_credential_redirect_off_scope_is_refused_not_followed scenario. "
        "What is left here is the aiohttp arm's own evidence — that the "
        "session made no second request — which is read off an aiohttp mock "
        "and has no curl equivalent to compare against."
    ),
    f"{_SCOPE}:test_an_in_scope_redirect_is_still_followed": (
        "The in-scope counterpart of the same refusal, and the same split: the "
        "two-arm scenario covers the refusal, this asserts which aiohttp "
        "requests were issued when the destination was allowed."
    ),
    f"{_SCOPE}:test_the_refusal_is_terminal_and_never_a_silent_drop": (
        "Asserts that the JSON arm does not continue to its next route after a "
        "scope refusal. The JSON arm rides HTTPClientTool, which has its own "
        "docker/host routing below this seam — the behaviour under test is the "
        "loop, and the loop has no transport."
    ),
    f"{_SCOPE_CHAIN}.test_a_rejected_login_that_redirects_back_is_not_a_success": (
        "The sibling test in the same class drives BOTH arms and asserts they "
        "hand the oracle the same chain; this one asserts what that chain then "
        "produces. Splitting them is what makes a divergence readable — one "
        "test says the inputs match, the other says what the match implies."
    ),
    f"{_SCOPE_GET}.test_an_in_scope_login_page_redirect_is_followed_and_reads_the_form_there": (
        "The login-page GET walk is held to both arms by the "
        "the_login_page_sits_behind_a_redirect scenario. This asserts which "
        "aiohttp GETs were issued, which is the arm's own request record."
    ),
    f"{_SCOPE_GET}.test_an_off_scope_login_page_redirect_sends_nothing": (
        "Asserts that NOTHING was dispatched, which can only be read from the "
        "arm's own request list. The two-arm claim it supports — that neither "
        "transport follows a login page off scope — is the curl class beside "
        "it, which drives the curl arm for the same case."
    ),
    # ---- The promoted-session positive control.
    f"{_PROMOTED}:test_a_good_credential_that_sets_no_cookie_is_indeterminate_not_refused": (
        "The SHAPE is held to both arms by the "
        "the_session_is_promoted_in_place_and_the_post_sets_nothing scenario, "
        "which asserts the same INDETERMINATE verdict and the same carried "
        "cookie through aiohttp and through a real curl. This file adds the "
        "end-to-end half, which is transport-independent."
    ),
    f"{_PROMOTED}:test_the_assertion_then_proves_the_session_the_login_could_not": (
        "The deferral's whole point, and it is assert_authenticated's job: the "
        "login hands over session material and the oracle settles it against "
        "an anonymous control. That oracle has one implementation and no "
        "transport to diverge across."
    ),
    f"{_PROMOTED}:test_a_bad_credential_on_the_same_shape_is_still_refused": (
        "The negative control for the same shape, and the two-arm corpus "
        "carries it as pre_credential_cookie_and_the_login_page_served_back — "
        "same absent Set-Cookie, same 200, login form back, REFUSED on both "
        "arms."
    ),
}


def _module_qual(path: Path) -> str:
    return str(path.relative_to(TESTS)).replace("\\", "/")[: -len(".py")].replace("/", ".")


def _mode_settings(node: ast.AST) -> set[str]:
    """``TOOL_EXEC_MODE`` values a node's subtree pins.

    Read off ``monkeypatch.setattr(settings, "tool_exec_mode", <value>)`` and off
    any bare string compared or assigned to a name spelled ``tool_exec_mode`` —
    both spellings appear in these suites, and a mode a test sets by the other
    one is still a mode it sets.
    """
    modes: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            args = [a for a in sub.args if isinstance(a, ast.Constant)]
            names = {a.value for a in args if isinstance(a.value, str)}
            if "tool_exec_mode" in names:
                modes |= {v for v in names if v in _MODE_ARM}
        elif isinstance(sub, ast.Assign):
            for target in sub.targets:
                if (
                    isinstance(target, ast.Attribute)
                    and target.attr == "tool_exec_mode"
                    and isinstance(sub.value, ast.Constant)
                    and sub.value.value in _MODE_ARM
                ):
                    modes.add(sub.value.value)
    return modes


def _referenced(node: ast.AST) -> set[str]:
    """Every attribute and bare name the subtree references."""
    seen: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            seen.add(sub.attr)
        elif isinstance(sub, ast.Name):
            seen.add(sub.id)
        elif isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            # ``monkeypatch.setattr(auth, "_cookie_jar_path", ...)`` and the
            # string form of a patched attribute name.
            seen.add(sub.value)
    return seen


def _corpus() -> dict[str, frozenset[str]]:
    """test qualname -> the credential arms it drives.

    Module scope is inherited: an autouse fixture that pins the execution mode
    for the whole module pins it for every test in it, and the arm a test drives
    through ``authenticate()`` follows from that. A module that pins BOTH (a
    parametrized mode) gives its mode-dispatched tests both arms, which is the
    honest reading — the test runs under each.
    """
    corpus: dict[str, frozenset[str]] = {}
    for path in sorted(TESTS.rglob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        if "WebAuthenticator" not in source:
            continue
        tree = ast.parse(source)
        module = _module_qual(path)

        module_modes: set[str] = set()
        # Module-level helpers, by name. A test that drives a transport through
        # one of them — ``_run(scenario, transport, ...)`` is the whole point of
        # the equivalence suite — drives it just as much as one that names the
        # arm inline, and a resolver that stopped at the test's own body would
        # report the equivalence corpus itself as covering neither arm.
        helpers: dict[str, ast.AST] = {}
        for node in tree.body:
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and not node.name.startswith("test_"):
                module_modes |= _mode_settings(node)
                helpers[node.name] = node

        def collect(container: ast.AST, prefix: str, inherited: set[str]) -> None:
            local = set(inherited)
            for child in ast.iter_child_nodes(container):
                if isinstance(child, ast.ClassDef):
                    class_modes = set(local)
                    for sub in child.body:
                        if isinstance(
                            sub, (ast.FunctionDef, ast.AsyncFunctionDef)
                        ) and not sub.name.startswith("test_"):
                            class_modes |= _mode_settings(sub)
                    collect(child, f"{prefix}{child.name}.", class_modes)
                elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not child.name.startswith("test_"):
                        continue
                    names = _referenced(child)
                    modes = local | _mode_settings(child)
                    # One hop through a module-level helper the test calls. One,
                    # deliberately: the effect of stopping here is a SMALLER
                    # corpus, which is the direction that under-claims coverage
                    # rather than over-claiming it.
                    for helper_name in sorted(names & set(helpers)):
                        names |= _referenced(helpers[helper_name])
                        modes |= _mode_settings(helpers[helper_name])
                    arms = {arm for attr, arm in _DIRECT_ARM.items() if attr in names}
                    if names & _MODE_DISPATCHED:
                        arms |= {_MODE_ARM[m] for m in modes}
                    if arms:
                        corpus[f"{module}:{prefix}{child.name}"] = frozenset(arms)

        collect(tree, "", module_modes)
    return corpus


# ---------------------------------------------------------------------------
# The pin
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def corpus() -> dict[str, frozenset[str]]:
    return _corpus()


def test_the_corpus_is_not_empty(corpus: dict[str, frozenset[str]]) -> None:
    """A domain that computes to nothing passes every assertion below it.

    The failure mode this guards is the one a computed domain always has: a
    resolver that stops matching returns an empty set, every downstream
    assertion holds vacuously, and the guard reports success while checking
    nothing.
    """
    assert corpus, "no auth test resolved to a transport arm at all"
    # The canary is structural rather than a threshold: every test in the
    # equivalence suite drives BOTH arms by construction, so a resolver that has
    # stopped matching shows up there first and shows up unambiguously.
    equivalence = {
        qual: arms
        for qual, arms in corpus.items()
        if qual.startswith("test_tools.test_auth_transport_equivalence:")
    }
    assert equivalence, (
        "the equivalence suite resolved to no transport arm — the resolver has "
        "stopped matching, and every assertion below this one is now vacuous"
    )
    one_armed = {q: sorted(a) for q, a in equivalence.items() if len(a) != 2}
    assert not one_armed, (
        f"these equivalence tests resolved to fewer than both arms, which they "
        f"drive by construction: {one_armed}"
    )


def test_every_single_arm_fixture_says_why(corpus: dict[str, frozenset[str]]) -> None:
    """The delta, and it is the deliverable of this file.

    A fixture that drives one arm is asserting a shape on one transport. That is
    sometimes right — ``test_auth_curl_path`` parses the bytes a real curl
    writes, and there is no aiohttp counterpart to that by construction — and it
    is sometimes the gap a live target falls into. Which one it is has to be
    written down, per test, or the asymmetry is invisible.
    """
    single = {q: sorted(arms)[0] for q, arms in corpus.items() if len(arms) == 1}
    undeclared = sorted(set(single) - set(SINGLE_ARM_REASONS))
    assert not undeclared, (
        "these auth tests assert a shape on ONE transport only and do not say why:\n  "
        + "\n  ".join(f"{q}  [{single[q]}]" for q in undeclared)
        + "\n\nEither add the shape to test_auth_transport_equivalence.py so both "
        "arms are held to it, or add an entry to SINGLE_ARM_REASONS stating why "
        "this one cannot be."
    )
    stale = sorted(set(SINGLE_ARM_REASONS) - set(single))
    assert not stale, (
        f"reasons declared for tests that no longer drive exactly one arm: {stale}. "
        f"A reason that outlives its test reads as coverage."
    )
    for qual, reason in SINGLE_ARM_REASONS.items():
        assert len(reason.split()) >= 12, (
            f"{qual}: a one-line reason is a box tick, not a decision about coverage"
        )
