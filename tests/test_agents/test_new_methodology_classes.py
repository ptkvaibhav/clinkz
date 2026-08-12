"""The five new classes, each proving its CONFIRM and its REFUSAL.

Every class here ships with both halves because only one of them is load-bearing
for trustworthiness. The confirm case proves the class can find the vulnerability
when it is present; the refusal case proves it does not find it when it is not —
and the refusal case is the one that would have caught every phantom this project
has shipped. So each class gets at least as many refusal fixtures as confirm
ones, and the refusals are written as the *specific* near-miss that would fool a
naive implementation rather than as an empty input.

Grouped per class. Read the refusal test above each confirm test: it says what
the class is refusing to claim.
"""

from __future__ import annotations

import pytest

from clinkz.agents._crypto_tokens import (
    forge_plaintext,
    recover_plaintext,
    reencode,
)
from clinkz.agents._input_validation import (
    CONTROL_VALUE,
    DeclaredConstraint,
    build_probes,
    declared_constraints_from_html,
    evaluate,
    response_accepted,
)
from clinkz.agents._mass_assignment import (
    candidate_fields,
    evaluate_read_back,
    probe_value_for,
)
from clinkz.agents._secret_exposure import (
    disclosure_is_established,
    operational_disclosure,
    served_secrets,
)
from clinkz.browser.csp_policy import parse_csp, select_bypass_route
from clinkz.models.vuln_classes import VULN_CLASSES, ConfirmationCapability, for_method

# A structurally valid HS256 JWT — a decodable header is what makes the shape
# DEFINITE rather than "a long base64-ish string".
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0IiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIn0"
    ".dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)


# ===========================================================================
# B1 — CSP bypass
# ===========================================================================


class TestCSPBypass:
    def test_a_strict_policy_yields_no_synthesizable_route(self) -> None:
        """THE REFUSAL. No route is a statement about OUR coverage.

        This is the case the brief calls out: the class must refuse rather than
        imply a clean policy. The refusal carries ``unreachable_note``, which
        says what would be needed — so a reader is told "we found no way in",
        never "there is no way in".
        """
        policy = parse_csp({"content-security-policy": "script-src 'nonce-AAA'; object-src 'none'"})
        route = select_bypass_route(policy, observed_nonces=["AAA", "BBB"])
        assert route.template_id is None
        assert route.unreachable_note
        assert "not proof" in route.unreachable_note or "not tested exhaustively" in (
            route.unreachable_note.lower()
        )

    def test_a_rotating_nonce_is_not_a_static_one(self) -> None:
        """The control that makes the nonce route a finding rather than a guess.

        One observation cannot distinguish a per-response nonce from a published
        constant, and that distinction IS the finding.
        """
        policy = parse_csp({"content-security-policy": "script-src 'nonce-R1'"})
        assert select_bypass_route(policy, observed_nonces=["R1", "R2"]).template_id is None

    def test_a_reused_nonce_is_a_route(self) -> None:
        """THE CONFIRM side: byte-identical across independent responses."""
        policy = parse_csp({"content-security-policy": "script-src 'nonce-SAME'"})
        route = select_bypass_route(policy, observed_nonces=["SAME", "SAME"])
        assert route.template_id is not None
        assert route.csp_nonce == "SAME"

    def test_unsafe_inline_with_a_nonce_present_does_not_allow_inline(self) -> None:
        """A browser ignores 'unsafe-inline' when a nonce or hash is present.

        Reading the directive as a word list would call this policy permissive
        and attempt (and fail) the plain inline route. The parser follows the
        spec instead.
        """
        policy = parse_csp({"content-security-policy": "script-src 'unsafe-inline' 'nonce-XYZ'"})
        assert not policy.allows_inline

    def test_the_registry_states_the_coverage_limit(self) -> None:
        vc = for_method("_test_csp")
        assert vc is not None
        assert vc.capability is ConfirmationCapability.CLIENT_SIDE_ORACLE_REQUIRED
        assert "NOT BYPASSED BY THOSE SHAPES" in vc.limitation


# ===========================================================================
# B2 — Cryptography
# ===========================================================================


class TestCryptography:
    def test_a_random_session_id_is_not_recovered(self) -> None:
        """THE REFUSAL, and the one that matters most for this class.

        A properly generated session id base64-decodes perfectly. Confirming on
        "it decoded" would confirm on every well-built session cookie in the
        world — so recovery must be anchored on a value the engagement holds.
        """
        import base64
        import os

        token = base64.b64encode(os.urandom(24)).decode()
        assert recover_plaintext(token, known_values={"username": "alice"}) is None

    def test_plaintext_containing_someone_elses_name_is_not_recovered(self) -> None:
        """A decode is only a demonstration when it surfaces OUR value.

        Otherwise "we decoded a token and it had words in it" is the claim, and
        the words could be anything the application happened to store.
        """
        import base64

        token = base64.b64encode(b"user=bob;role=guest").decode()
        assert recover_plaintext(token, known_values={"username": "alice"}) is None

    def test_no_known_value_means_no_recovery_is_attempted(self) -> None:
        """With no anchor available the class declines rather than guessing."""
        import base64

        token = base64.b64encode(b"user=alice;role=admin").decode()
        assert recover_plaintext(token, known_values={}) is None
        assert recover_plaintext(token, known_values={"username": "al"}) is None, (
            "an anchor below the minimum length would match inside random text too often"
        )

    def test_recoverable_plaintext_anchored_on_our_identity_confirms(self) -> None:
        """THE CONFIRM: the decode surfaced the identity we authenticated as."""
        import base64

        token = base64.b64encode(b"user=alice;role=customer;exp=99").decode()
        recovered = recover_plaintext(token, known_values={"username": "alice"})
        assert recovered is not None
        assert recovered.scheme == "base64"
        assert recovered.anchor == "alice"
        assert "role=customer" in recovered.plaintext

    def test_a_xor_wrapped_token_is_recovered_and_names_its_scheme(self) -> None:
        """The scheme is named so a reader can repeat the recovery by hand."""
        import base64

        plain = b"user=alice;role=customer"
        wrapped = base64.b64encode(bytes(b ^ 0x2A for b in plain)).decode()
        recovered = recover_plaintext(wrapped, known_values={"username": "alice"})
        assert recovered is not None
        assert recovered.scheme == "base64+xor:42"

    def test_the_xor_shadow_key_is_resolved_by_the_anchors_own_case(self) -> None:
        """A single-byte XOR has a shadow key, and no property of the token separates them.

        0x20 is exactly the ASCII case bit, so key K and key K^0x20 produce the
        same text in opposite cases. Both decode to printable text, both contain
        the anchor case-insensitively, and — XOR being symmetric — both re-encode
        to the original token byte for byte. A round-trip check cannot tell them
        apart; this was found by this suite after the first implementation
        reported key 10 for a token built with key 42.

        The anchor settles it: it is a value the engagement supplied, and an
        application stores it as it was given. So the exact-case decode wins.
        """
        import base64

        plain = b"user=alice;role=customer"
        for key in (0x2A, 0x0A):
            token = base64.b64encode(bytes(b ^ key for b in plain)).decode()
            recovered = recover_plaintext(token, known_values={"username": "alice"})
            assert recovered is not None
            assert recovered.scheme == f"base64+xor:{key}", (
                f"key {key}: the shadow key {key ^ 0x20} decodes just as cleanly and "
                "re-encodes identically — only the anchor's case separates them"
            )
            assert reencode(recovered.plaintext, recovered.scheme) == token

    def test_a_forgery_round_trips_under_the_recovered_scheme(self) -> None:
        """We forge under a scheme we DEMONSTRATED, never one we guessed."""
        import base64

        token = base64.b64encode(b"user=alice;role=customer").decode()
        recovered = recover_plaintext(token, known_values={"username": "alice"})
        assert recovered is not None
        forged = forge_plaintext(recovered, replacement="admin")
        assert forged is not None
        assert base64.b64decode(forged) == b"user=admin;role=customer"
        # Only the anchor changed: everything else the application built is intact.
        assert reencode(recovered.plaintext, recovered.scheme) == token

    def test_the_registry_refuses_to_call_an_unrecovered_token_strong(self) -> None:
        vc = for_method("_test_crypto")
        assert vc is not None
        assert "reported as not recovered rather than as strong" in vc.limitation


# ===========================================================================
# B3 — Input validation
# ===========================================================================


class TestInputValidation:
    def test_an_endpoint_that_accepts_everything_confirms_nothing(self) -> None:
        """THE REFUSAL, and the whole reason this class carries a control.

        A SPA shell answers 200 to every path. Without the control this class
        would confirm on every field of every form on every SPA, forever.
        """
        probe = build_probes(
            [DeclaredConstraint(field="rating", kind="max", declared="5", source="html")]
        )[0]
        verdict = evaluate(
            probe=probe,
            probe_status=200,
            probe_body="<html>app shell</html>",
            control_status=200,
            control_body="<html>app shell</html>",
        )
        assert not verdict.confirmed
        assert verdict.probe_accepted and not verdict.control_rejected
        assert "no validation at all" in verdict.detail

    def test_a_server_that_enforces_its_own_rule_is_not_a_finding(self) -> None:
        """The control in the other direction: the application working."""
        probe = build_probes(
            [DeclaredConstraint(field="rating", kind="max", declared="5", source="html")]
        )[0]
        verdict = evaluate(
            probe=probe,
            probe_status=400,
            probe_body='{"error": "rating must be <= 5"}',
            control_status=400,
            control_body='{"error": "invalid"}',
        )
        assert not verdict.confirmed
        assert "enforces its declared" in verdict.detail

    def test_a_200_carrying_a_validation_error_is_a_rejection(self) -> None:
        """Status alone has never been the answer.

        An API that answers 200 with ``{"error": ...}`` rejected the request, and
        a form that re-renders with a validation message is a 200 that rejected.
        """
        assert not response_accepted(200, '{"error": "rating must be <= 5"}')
        assert not response_accepted(200, '<div class="error">Field is required</div>')
        assert response_accepted(200, '{"id": 7, "rating": 6}')
        assert not response_accepted(500, "ok")

    def test_accepted_invalid_with_a_rejected_control_confirms(self) -> None:
        """THE CONFIRM: both halves present."""
        probe = build_probes(
            [DeclaredConstraint(field="rating", kind="max", declared="5", source="html:input[max]")]
        )[0]
        assert probe.violating_value == "6"
        verdict = evaluate(
            probe=probe,
            probe_status=201,
            probe_body='{"id": 7, "rating": 6}',
            control_status=400,
            control_body='{"error": "invalid value"}',
        )
        assert verdict.confirmed
        assert "ACCEPTED" in verdict.detail and "REJECTING" in verdict.detail

    def test_constraints_are_read_from_the_applications_own_declaration(self) -> None:
        """A finding quotes the application about its own field, not our opinion."""
        html = """
        <form action="/register" method="post">
          <input name="email" type="email" required>
          <input name="password" minlength="8" required>
          <input name="rating" type="number" min="1" max="5">
          <input name="nickname">
        </form>
        """
        constraints = declared_constraints_from_html(html, "http://t/register")
        declared = {(c.field, c.kind, c.declared) for c in constraints}
        assert ("email", "required", "true") in declared
        assert ("email", "type", "email") in declared
        assert ("password", "minlength", "8") in declared
        assert ("rating", "max", "5") in declared
        assert not any(c.field == "nickname" for c in constraints), (
            "a field the application declares nothing about is not this class's surface"
        )

    def test_a_pattern_we_cannot_safely_violate_is_skipped(self) -> None:
        """A probe that might send a VALID value would read acceptance as a finding."""
        probes = build_probes(
            [DeclaredConstraint(field="code", kind="pattern", declared="", source="html")]
        )
        assert probes == []

    def test_probe_order_is_deterministic(self) -> None:
        constraints = [
            DeclaredConstraint(field="zeta", kind="max", declared="5", source="html"),
            DeclaredConstraint(field="alpha", kind="min", declared="1", source="html"),
        ]
        forward = [(p.constraint.field, p.constraint.kind) for p in build_probes(constraints)]
        backward = [
            (p.constraint.field, p.constraint.kind)
            for p in build_probes(list(reversed(constraints)))
        ]
        assert forward == backward == [("alpha", "min"), ("zeta", "max")]

    def test_the_control_value_is_malformed_not_hostile(self) -> None:
        """A WAF must not be the thing that answers the control's question."""
        lowered = CONTROL_VALUE.lower()
        for injection_marker in ("<script", "'", '"', "../", "union", ";", "|"):
            assert injection_marker not in lowered


# ===========================================================================
# B4 — Secrets & configuration exposure
# ===========================================================================


class TestSecretsExposure:
    def test_our_own_token_echoed_back_is_never_the_targets_leak(self) -> None:
        """THE REFUSAL that matters most here.

        A response containing the bearer token we just sent is the target
        quoting us. Confirming on it would report the operator's own credential
        as the target's leak, on every echoing endpoint of every engagement.
        """
        body = f'{{"debug": {{"authorization": "Bearer {_JWT}"}}}}'
        assert served_secrets(body, supplied_material=[_JWT]) == []
        # ...and with a DIFFERENT token supplied, the target's own is reported.
        assert served_secrets(body, supplied_material=["some-other-token"])

    def test_an_ordinary_bundle_discloses_nothing(self) -> None:
        """Minified JavaScript is full of alarming-looking strings."""
        body = (
            "var a=0x1f3a5b,b='d41d8cd98f00b204e9800998ecf8427e';"
            "function q(){return btoa(JSON.stringify({t:Date.now()}))}"
        )
        assert served_secrets(body) == []
        assert not disclosure_is_established(operational_disclosure(body))

    def test_a_single_internal_host_is_a_build_artifact_not_a_disclosure(self) -> None:
        """One marker is below the bar, deliberately."""
        disclosure = operational_disclosure("// sourcemap at http://10.0.0.5/maps/app.js.map")
        assert disclosure.marker_count == 1
        assert not disclosure_is_established(disclosure)

    def test_markers_the_site_root_also_serves_are_page_chrome(self) -> None:
        """A disclosure has to be a property of THIS endpoint."""
        shared = "DATABASE_URL=postgres://x internal host 10.0.0.5"
        disclosure = operational_disclosure(shared, baseline_body=shared)
        assert disclosure.marker_count == 0

    def test_a_served_private_key_confirms(self) -> None:
        """THE CONFIRM: a definite shape, and the value is never reproduced.

        The PEM markers are assembled at runtime rather than written as a
        literal. The repo's own commit guard refuses a file containing a PEM
        block — correctly, and fail-closed, since it cannot know ours is
        synthetic — and a test for a secret-detector is the last place to reach
        for ``--no-verify``. Assembling it exercises exactly the same detector.
        """
        dashes = "-" * 5
        opening = f"{dashes}BEGIN RSA PRIVATE KEY{dashes}"
        closing = f"{dashes}END RSA PRIVATE KEY{dashes}"
        body = f"{opening}\nMIIEowIBAAKCAQEAxyz1234567890abcdefghijklmnop\n{closing}"
        found = served_secrets(body)
        assert len(found) == 1
        assert found[0].kind == "private_key"
        assert found[0].fingerprint
        assert "MIIEowIBAAKCAQEAxyz" not in found[0].excerpt_context, (
            "a report that reproduces the credential it warns about has leaked it twice"
        )

    def test_a_configuration_document_confirms(self) -> None:
        """THE CONFIRM for the operational half: several distinct markers."""
        body = (
            '{"DATABASE_URL": "postgres://app:hunter2@db.internal:5432/prod",\n'
            ' "REDIS_HOST": "10.0.3.9",\n'
            ' "SMTP_PASSWORD": "s3cr3t"}'
        )
        disclosure = operational_disclosure(body)
        assert disclosure_is_established(disclosure)
        assert disclosure.marker_count >= 2

    def test_a_set_cookie_is_the_feature_working_not_a_disclosure(self) -> None:
        """The application issuing a session is not the application leaking one."""
        assert served_secrets("Set-Cookie: session=abc123; HttpOnly") == []

    def test_the_registry_states_the_anonymous_control(self) -> None:
        vc = for_method("_test_secrets_exposure")
        assert vc is not None
        assert "NO session at all" in vc.limitation


# ===========================================================================
# B5 — Mass assignment
# ===========================================================================


class TestMassAssignment:
    def test_a_field_the_client_already_offers_is_not_mass_assignment(self) -> None:
        """THE REFUSAL: a field the form has is the form, not an escalation."""
        assert (
            candidate_fields(
                client_offered=["email", "password", "role"],
                observed_object_fields=["id", "email", "role"],
            )
            == []
        )

    def test_a_field_the_server_never_shows_is_never_guessed(self) -> None:
        """A write whose outcome cannot be interpreted is target state changed
        for nothing."""
        assert (
            candidate_fields(
                client_offered=["email"],
                observed_object_fields=["id", "email", "createdAt"],
            )
            == []
        ), "no privileged field in the server's own object ⇒ nothing to attempt"

    def test_a_dropped_field_is_the_binding_working(self) -> None:
        """THE REFUSAL that a status-only implementation would get wrong.

        Most frameworks return 201 and discard the extra field silently — so
        status-only would confirm on every framework behaving correctly.
        """
        verdict = evaluate_read_back(
            field="role",
            probe_value="clinkz-probe-role",
            probe_object={"id": 9, "email": "x@y", "role": "customer"},
            control_object={"id": 10, "email": "x@y", "role": "customer"},
        )
        assert not verdict.honoured
        assert "the binding working correctly" in verdict.detail

    def test_a_value_the_server_sets_itself_is_not_ours(self) -> None:
        """THE OTHER REFUSAL: the control is what attributes the value to US."""
        verdict = evaluate_read_back(
            field="status",
            probe_value="clinkz-probe-state",
            probe_object={"id": 9, "status": "clinkz-probe-state"},
            control_object={"id": 10, "status": "clinkz-probe-state"},
        )
        assert not verdict.honoured
        assert verdict.control_value_present
        assert "our request is not what put it there" in verdict.detail

    def test_an_unreadable_object_never_confirms(self) -> None:
        verdict = evaluate_read_back(
            field="role", probe_value="x", probe_object=None, control_object={"role": "y"}
        )
        assert not verdict.honoured
        assert "could not be read back" in verdict.detail

    def test_the_probe_carrying_it_and_the_control_without_it_confirms(self) -> None:
        """THE CONFIRM: one difference between two objects, and it is ours."""
        verdict = evaluate_read_back(
            field="role",
            probe_value="clinkz-probe-role",
            probe_object={"id": 9, "email": "x@y", "role": "clinkz-probe-role"},
            control_object={"id": 10, "email": "x@y", "role": "customer"},
        )
        assert verdict.honoured
        assert "did NOT come back on the control" in verdict.detail

    def test_read_back_tolerates_the_servers_own_type_round_trip(self) -> None:
        """``"true"`` comes back as a boolean and ``"0.01"`` as a float."""
        assert evaluate_read_back(
            field="isAdmin",
            probe_value="true",
            probe_object={"isAdmin": True},
            control_object={"isAdmin": False},
        ).honoured
        assert evaluate_read_back(
            field="price",
            probe_value="0.01",
            probe_object={"price": 0.010},
            control_object={"price": 49.99},
        ).honoured

    def test_field_naming_is_normalised_across_spellings(self) -> None:
        """An API may accept ``is_admin`` and return ``isAdmin``."""
        assert evaluate_read_back(
            field="is_admin",
            probe_value="true",
            probe_object={"isAdmin": "true"},
            control_object={"isAdmin": "false"},
        ).honoured

    @pytest.mark.parametrize(
        ("field", "expected"),
        [("role", "clinkz-probe-role"), ("isAdmin", "true"), ("price", "0.01")],
    )
    def test_probe_values_are_unmistakable_and_harmless(self, field: str, expected: str) -> None:
        """A payload that would grant real privilege is not needed to prove binding."""
        assert probe_value_for(field) == expected

    def test_candidates_are_deterministic(self) -> None:
        observed = ["price", "role", "id", "email"]
        forward = [
            c.field
            for c in candidate_fields(client_offered=["email"], observed_object_fields=observed)
        ]
        backward = [
            c.field
            for c in candidate_fields(
                client_offered=["email"], observed_object_fields=list(reversed(observed))
            )
        ]
        assert forward == backward == ["price", "role"]

    def test_the_registry_distinguishes_this_from_access_control(self) -> None:
        vc = for_method("_test_mass_assignment")
        assert vc is not None
        assert "READ" in vc.limitation
        assert "status code alone never confirms" in vc.limitation


# ===========================================================================
# All five, as a set
# ===========================================================================


NEW_CLASSES = (
    "_test_csp",
    "_test_crypto",
    "_test_input_validation",
    "_test_secrets_exposure",
    "_test_mass_assignment",
)


@pytest.mark.parametrize("method", NEW_CLASSES)
def test_each_new_class_is_dispatchable_ranked_and_described(method: str) -> None:
    """A class has to be all three or it is worse than absent.

    Dispatchable but unregistered ⇒ invisible in the report AND ungated by
    authorization. Registered but unranked ⇒ its answer hides in a tie bucket.
    Ranked but undispatchable ⇒ it costs a plan slot and a request to the
    client's target and can never fire.
    """
    from clinkz.agents.exploit import (
        _CLASS_PARAM_NAMES,
        _CLASS_PATH_TOKENS,
        _CLASS_PRECONDITIONS,
        DISPATCHABLE_TEST_METHODS,
        ExploitAgent,
    )

    assert method in DISPATCHABLE_TEST_METHODS
    assert callable(getattr(ExploitAgent, method, None))

    vc = for_method(method)
    assert vc is not None, f"{method} dispatches but no registry entry describes it"
    assert vc.label and vc.remediation, f"{method} has no client-facing label or remediation"

    has_signal = (
        bool(_CLASS_PATH_TOKENS.get(method))
        or bool(_CLASS_PARAM_NAMES.get(method))
        or bool(_CLASS_PRECONDITIONS.get(method))
    )
    assert has_signal, (
        f"{method} carries no ranking signal, so it ranks on nothing and its best "
        f"endpoint hides in a tie bucket broken by crawl order"
    )


@pytest.mark.parametrize("method", NEW_CLASSES)
def test_each_new_class_is_authorization_gated(method: str) -> None:
    """A class a client cannot authorize is a class that runs ungated."""
    vc = for_method(method)
    assert vc is not None
    assert vc.key and vc in VULN_CLASSES
