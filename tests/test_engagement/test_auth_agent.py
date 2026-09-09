"""The adaptive-auth agent: what the model may decide, and what it may not.

Every test here is about a boundary rather than a behaviour. The loop's value is
that it can propose a credential destination no parser could read; its safety is
entirely in the three things it is NOT allowed to do, so those are what is
pinned:

* it cannot mark a session authenticated — only ``assert_authenticated`` can;
* it cannot author a value — it names fields, and the engine supplies them;
* it cannot send anything the deterministic gate refuses.

A test that only asserted "the loop authenticates when the fake LLM proposes the
right URL" would pass against a loop with none of those properties.
"""

from __future__ import annotations

import json

import pytest

from clinkz.engagement.auth_agent import (
    ENCODABLE_CONTENT_TYPES,
    MAX_READS,
    AuthAgentLoop,
    AuthAgentOutcome,
    AuthObservation,
    AuthProposal,
    AuthTranscript,
    DispatchResponse,
    ProposalKind,
    ProposalRefusal,
    load_system_prompt,
    observation_from_auth_result,
    parse_proposal,
    validate_proposal,
)
from clinkz.engagement.auth_state import AuthAssertion
from clinkz.tools.auth import AuthResult, LoginVerdict

# ---------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------


class FakeLLM:
    """Answers a scripted sequence of proposals and records every prompt it saw."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.prompts: list[str] = []

    async def generate_text(self, prompt, **_kwargs) -> str:  # noqa: ANN001
        self.prompts.append(str(prompt))
        if not self.answers:
            return ""
        return self.answers.pop(0)


class FakeDispatcher:
    """Returns scripted responses and records exactly what was asked of it."""

    def __init__(self, responses: dict[str, DispatchResponse]) -> None:
        self.responses = responses
        self.reads: list[tuple[str, str]] = []
        self.posts: list[tuple[str, str, dict[str, str], str]] = []

    async def read(self, url: str, method: str) -> DispatchResponse:
        self.reads.append((url, method))
        return self.responses.get(url, DispatchResponse(status=404))

    async def post_credentials(
        self, url: str, *, content_type: str, fields: dict[str, str], account: str
    ) -> DispatchResponse:
        self.posts.append((url, content_type, dict(fields), account))
        return self.responses.get(url, DispatchResponse(status=404))


def asserter(established: bool):  # noqa: ANN201
    async def _assert(cookies: dict[str, str], headers: dict[str, str]) -> AuthAssertion:
        return AuthAssertion(
            established=established,
            url="http://t.test/me",
            discriminator="status_class" if established else "",
            authenticated_status=200 if established else 0,
            anonymous_status=401 if established else 0,
            why_unproven="" if established else "no candidate URL behaved differently",
        )

    return _assert


OBSERVATION = AuthObservation(
    base_url="http://t.test",
    login_url="http://t.test/login",
    posted_to="http://t.test/login",
    post_status=200,
    form_action_declared=False,
    form_field_names=["csrfToken", "email", "password"],
    csrf_fields_without_cookie=["csrfToken"],
    framework_fingerprint="X-Powered-By: SomeFramework",
    post_changed_nothing=True,
    verdict_evidence="the POST set no cookie and returned no token",
)


def proposal_json(**kwargs) -> str:
    body = {
        "kind": "credential_post",
        "url": "http://t.test/session",
        "method": "POST",
        "content_type": "application/x-www-form-urlencoded",
        "identity_field": "email",
        "secret_field": "password",
        "carry_fields": [],
        "rationale": "the form posts nowhere and the headers name the stack",
    }
    body.update(kwargs)
    return json.dumps(body)


def loop(llm, dispatcher, established: bool, **kwargs) -> AuthAgentLoop:  # noqa: ANN001
    return AuthAgentLoop(
        llm=llm,
        dispatcher=dispatcher,
        asserter=asserter(established),
        in_scope=lambda url: url.startswith("http://t.test"),
        system_prompt="SYSTEM",
        **kwargs,
    )


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def gate(proposal: AuthProposal, **overrides):  # noqa: ANN201
    kwargs = {
        "in_scope": lambda url: url.startswith("http://t.test"),
        "known_field_names": frozenset({"csrfToken", "email", "password"}),
        "credential_budget_remaining": 4,
        "reads_remaining": 4,
        "already_refused": frozenset(),
    }
    kwargs.update(overrides)
    return validate_proposal(proposal, **kwargs)


class TestTheGate:
    def test_a_well_formed_in_scope_credential_post_is_permitted(self) -> None:
        verdict = gate(AuthProposal(url="http://t.test/session", identity_field="email"))
        assert verdict.allowed
        assert verdict.refusal is None

    def test_a_login_body_is_not_classified_a_credential_change(self) -> None:
        """The load-bearing negative: a POST carrying ``password`` must pass.

        ``safety/destructive.py`` refuses ``credential_change``, and a login body
        carries a secret field by definition. If the classifier read that as a
        credential change the entire adaptive layer would be gated shut and
        every abstention would be this rule rather than anything about the
        target — a failure that looks exactly like the honest one.
        """
        verdict = gate(
            AuthProposal(
                url="http://t.test/session",
                identity_field="email",
                secret_field="password",
                carry_fields=["csrfToken"],
            )
        )
        assert verdict.allowed, verdict.reason

    @pytest.mark.parametrize(
        ("proposal", "overrides", "expected"),
        [
            (
                AuthProposal(url="/relative", identity_field="email"),
                {},
                ProposalRefusal.NOT_A_URL,
            ),
            (
                AuthProposal(url="http://elsewhere.test/x", identity_field="email"),
                {},
                ProposalRefusal.OUT_OF_SCOPE,
            ),
            (
                AuthProposal(url="http://t.test/x", method="PUT", identity_field="email"),
                {},
                ProposalRefusal.METHOD_NOT_PERMITTED,
            ),
            (
                AuthProposal(kind=ProposalKind.READ, url="http://t.test/x", method="DELETE"),
                {},
                ProposalRefusal.METHOD_NOT_PERMITTED,
            ),
            (
                AuthProposal(
                    url="http://t.test/x", content_type="text/xml", identity_field="email"
                ),
                {},
                ProposalRefusal.CONTENT_TYPE_NOT_ENCODABLE,
            ),
            (
                AuthProposal(url="http://t.test/x", identity_field=""),
                {},
                ProposalRefusal.NO_IDENTITY_FIELD,
            ),
            (
                AuthProposal(url="http://t.test/x", identity_field="email", secret_field=""),
                {},
                ProposalRefusal.NO_IDENTITY_FIELD,
            ),
            (
                AuthProposal(
                    url="http://t.test/x", identity_field="email", carry_fields=["invented"]
                ),
                {},
                ProposalRefusal.UNKNOWN_CARRY_FIELD,
            ),
            (
                AuthProposal(url="http://t.test/x", identity_field="email"),
                {"credential_budget_remaining": 0},
                ProposalRefusal.BUDGET_SPENT,
            ),
            (
                AuthProposal(kind=ProposalKind.READ, url="http://t.test/x", method="GET"),
                {"reads_remaining": 0},
                ProposalRefusal.READ_CEILING,
            ),
            (
                AuthProposal(url="http://t.test/account/delete", identity_field="email"),
                {},
                ProposalRefusal.DESTRUCTIVE,
            ),
        ],
    )
    def test_each_refusal_fires_on_its_own_shape(
        self, proposal: AuthProposal, overrides: dict, expected: ProposalRefusal
    ) -> None:
        verdict = gate(proposal, **overrides)
        assert not verdict.allowed
        assert verdict.refusal is expected
        assert len(verdict.reason.split()) >= 8, "a refusal states its reason"

    def test_every_refusal_reason_is_named_by_the_enum(self) -> None:
        """No refusal may be returned without a member naming it.

        The reason string is for a human; the member is what the transcript
        groups on and what the corpus driver tallies. A refusal carrying only
        prose would be invisible to both.
        """
        verdict = gate(AuthProposal(url="not a url", identity_field="email"))
        assert verdict.refusal in set(ProposalRefusal)

    def test_a_repeat_of_a_refused_proposal_is_refused_without_re_evaluating(self) -> None:
        proposal = AuthProposal(url="http://t.test/session", identity_field="email")
        verdict = gate(proposal, already_refused=frozenset({proposal.signature()}))
        assert verdict.refusal is ProposalRefusal.REPEAT_OF_REFUSED

    def test_a_rationale_change_does_not_make_it_a_new_proposal(self) -> None:
        """The signature excludes the rationale, deliberately.

        A model that re-proposes the same request with a better explanation has
        proposed the same request, and the gate that refused it is answering the
        same question. Without this a loop could spend its whole budget on one
        destination.
        """
        first = AuthProposal(url="http://t.test/x", identity_field="email", rationale="a")
        second = AuthProposal(url="http://t.test/x", identity_field="email", rationale="b")
        assert first.signature() == second.signature()

    def test_an_unbounded_budget_is_none_and_never_refuses(self) -> None:
        """``None`` means no bound, and must not be flattened to a number.

        The refusal message prints the remaining count, so a policy that
        configured no bound must not be quoted as one.
        """
        verdict = gate(
            AuthProposal(url="http://t.test/x", identity_field="email"),
            credential_budget_remaining=None,
        )
        assert verdict.allowed
        assert "no per-account credential bound" in verdict.reason

    def test_the_encodable_set_matches_the_authenticators_own(self) -> None:
        """One vocabulary, checked, rather than two that agree today."""
        from clinkz.tools.auth import ENCODABLE_CONTENT_TYPES as TOOL_TYPES

        assert ENCODABLE_CONTENT_TYPES == frozenset(TOOL_TYPES)


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------


class TestParsing:
    def test_a_fenced_answer_with_prose_around_it_parses(self) -> None:
        answer = f"Here is my reasoning.\n```json\n{proposal_json()}\n```\nThanks."
        proposal = parse_proposal(answer)
        assert proposal is not None
        assert proposal.url == "http://t.test/session"

    @pytest.mark.parametrize("answer", ["", "no json here", "{not json}", "[1,2,3]"])
    def test_an_unparseable_answer_is_none_rather_than_a_default_proposal(
        self, answer: str
    ) -> None:
        """``None``, never a default. A default proposal would be a destination
        this engine chose while reporting it as one the model proposed."""
        assert parse_proposal(answer) is None

    def test_a_model_authored_body_field_is_not_absorbed(self) -> None:
        """There is no body field, so an extra key cannot become request bytes."""
        proposal = parse_proposal(
            json.dumps(
                {
                    "kind": "credential_post",
                    "url": "http://t.test/session",
                    "identity_field": "email",
                    "body": "user=admin&pass=hunter2",
                    "raw_request": "POST /x HTTP/1.1",
                }
            )
        )
        assert proposal is not None
        assert not hasattr(proposal, "body")
        assert not hasattr(proposal, "raw_request")


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestTheLoop:
    async def test_it_authenticates_only_when_the_assertion_says_so(self) -> None:
        llm = FakeLLM([proposal_json(carry_fields=["csrfToken"])])
        dispatcher = FakeDispatcher(
            {
                "http://t.test/session": DispatchResponse(
                    status=200, set_cookie_names=["sid"], cookies={"sid": "abc"}
                )
            }
        )
        transcript = await loop(llm, dispatcher, established=True).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.outcome is AuthAgentOutcome.AUTHENTICATED
        assert transcript.attempts[-1].assertion_ran
        assert transcript.attempts[-1].established

    async def test_the_same_exchange_abstains_when_the_assertion_refuses(self) -> None:
        """The ONLY difference between this test and the one above is the oracle.

        Same proposal, same dispatch, same 200-with-a-cookie. If the loop could
        conclude anything from the exchange itself, these two would not differ —
        and the assertion would be decoration.
        """
        llm = FakeLLM([proposal_json() for _ in range(3)])
        dispatcher = FakeDispatcher(
            {
                "http://t.test/session": DispatchResponse(
                    status=200, set_cookie_names=["sid"], cookies={"sid": "abc"}
                )
            }
        )
        transcript = await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.outcome is AuthAgentOutcome.ABSTAINED

    async def test_the_secret_never_reaches_the_prompt(self) -> None:
        llm = FakeLLM([proposal_json(), proposal_json(url="http://t.test/other")])
        dispatcher = FakeDispatcher({})
        await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="hunter2-do-not-leak",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert llm.prompts, "the loop must actually have prompted"
        for prompt in llm.prompts:
            assert "hunter2-do-not-leak" not in prompt

    async def test_the_engine_supplies_the_values_and_the_model_supplies_the_names(
        self,
    ) -> None:
        """A proposal names ``csrfToken``; the engine puts the observed value in.

        There is no path by which a string a model wrote becomes a field value:
        the loop looks names up in what it observed, and the gate refuses a name
        it holds nothing for.
        """
        llm = FakeLLM([proposal_json(carry_fields=["csrfToken"])])
        dispatcher = FakeDispatcher({})
        await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        (_url, _ctype, fields, account) = dispatcher.posts[0]
        assert fields["email"] == "u@t.test"
        assert fields["password"] == "s3cret"
        assert fields["csrfToken"] == "", "an unread observed field carries the empty value"
        assert account == "u@t.test", "the POST names the account, so the budget can see it"

    async def test_a_read_teaches_a_value_the_model_may_then_name(self) -> None:
        """The one way a value enters a credential body from a response.

        The read's JSON keys become referenceable names; the VALUE is stored by
        the loop and never shown to the model. This is what lets an application
        whose credential exchange needs a fetched token be reachable at all,
        without the model ever authoring the token.
        """
        llm = FakeLLM(
            [
                json.dumps({"kind": "read", "url": "http://t.test/token", "method": "GET"}),
                proposal_json(carry_fields=["issuedToken"]),
            ]
        )
        dispatcher = FakeDispatcher(
            {
                "http://t.test/token": DispatchResponse(
                    status=200, body=json.dumps({"issuedToken": "T-42"})
                ),
                "http://t.test/session": DispatchResponse(
                    status=200, set_cookie_names=["sid"], cookies={"sid": "x"}
                ),
            }
        )
        transcript = await loop(llm, dispatcher, established=True).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.outcome is AuthAgentOutcome.AUTHENTICATED
        (_url, _ctype, fields, _account) = dispatcher.posts[0]
        assert fields["issuedToken"] == "T-42"
        # And the model was told the NAME, never the value.
        assert "issuedToken" in llm.prompts[1]
        assert "T-42" not in llm.prompts[1]

    async def test_a_spent_budget_never_attempts_and_says_nothing_about_the_password(
        self,
    ) -> None:
        llm = FakeLLM([proposal_json()])
        dispatcher = FakeDispatcher({})
        transcript = await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=0,
        )
        assert transcript.outcome is AuthAgentOutcome.NOT_ATTEMPTED
        assert transcript.llm_turns == 0, "no model is consulted when nothing can be sent"
        assert not dispatcher.posts
        reason = transcript.outcome_reason.lower()
        assert "nothing here is a statement about the credentials" in reason
        assert "wrong" not in reason

    async def test_it_cannot_spend_its_way_past_the_budget(self) -> None:
        """Three turns, one attempt of budget. The second POST is refused by the
        loop's own gate rather than by the governor at dispatch."""
        llm = FakeLLM(
            [
                proposal_json(url="http://t.test/a"),
                proposal_json(url="http://t.test/b"),
                proposal_json(url="http://t.test/c"),
            ]
        )
        dispatcher = FakeDispatcher({})
        transcript = await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=1,
        )
        assert len(dispatcher.posts) == 1
        assert transcript.credential_posts_dispatched == 1
        assert any(a.gate.refusal is ProposalRefusal.BUDGET_SPENT for a in transcript.attempts)

    async def test_a_rails_refusal_stops_the_loop_and_is_not_reported_as_the_target(
        self,
    ) -> None:
        llm = FakeLLM([proposal_json(), proposal_json(url="http://t.test/second")])
        dispatcher = FakeDispatcher(
            {
                "http://t.test/session": DispatchResponse(
                    status=0,
                    refused_by_rails="refused_credential_budget",
                    error="the per-account budget is spent",
                )
            }
        )
        transcript = await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.outcome is AuthAgentOutcome.ABSTAINED
        assert "safety rails refused" in transcript.outcome_reason
        assert len(dispatcher.posts) == 1, "the loop stops rather than trying elsewhere"

    async def test_an_llm_that_answers_nothing_abstains_rather_than_raising(self) -> None:
        class Broken:
            async def generate_text(self, prompt, **_kwargs):  # noqa: ANN001, ANN202
                raise RuntimeError("provider down")

        transcript = await loop(Broken(), FakeDispatcher({}), established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.outcome is AuthAgentOutcome.NOT_ATTEMPTED
        assert "unreachable" in transcript.outcome_reason

    async def test_reads_are_bounded_independently_of_the_credential_budget(self) -> None:
        # DISTINCT URLs, because an identical read is refused as a repeat one
        # rule earlier — the read ceiling bounds how much surface the loop may
        # map, not how many times it may ask the same question.
        reads = [
            json.dumps({"kind": "read", "url": f"http://t.test/x{i}", "method": "GET"})
            for i in range(MAX_READS + 2)
        ]
        llm = FakeLLM(reads)
        dispatcher = FakeDispatcher(
            {f"http://t.test/x{i}": DispatchResponse(status=200) for i in range(MAX_READS + 2)}
        )
        transcript = await loop(llm, dispatcher, established=False, max_turns=MAX_READS + 2).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=8,
        )
        assert transcript.reads_dispatched == MAX_READS
        assert any(a.gate.refusal is ProposalRefusal.READ_CEILING for a in transcript.attempts)


# ---------------------------------------------------------------------------
# What the transcript may and may not carry
# ---------------------------------------------------------------------------


class TestTheTranscript:
    def test_no_field_lets_a_model_write_established(self) -> None:
        """``established`` is on the ATTEMPT, not the proposal.

        A model answers with an :class:`AuthProposal`. If that model tried to
        answer ``{"established": true}`` there would be nowhere for it to land.
        """
        assert "established" not in AuthProposal.model_fields
        assert "outcome" not in AuthProposal.model_fields

    def test_a_cookie_value_never_enters_the_transcript(self) -> None:
        transcript = AuthTranscript(role="admin")
        assert "cookies" not in str(transcript.model_dump())

    def test_redaction_catches_a_token_the_target_embedded_in_a_body(self) -> None:
        """The second of two controls, and the one that catches what no rule here
        could anticipate: the target chose the bytes."""
        from clinkz.engagement.auth_agent import AuthAttempt

        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxIiwibmFtZSI6IkEifQ."
            "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        )
        transcript = AuthTranscript(
            role="admin",
            attempts=[AuthAttempt(turn=1, body_excerpt=json.dumps({"token": jwt}))],
        )
        assert jwt not in json.dumps(transcript.redacted())

    def test_a_not_engaged_transcript_renders_the_deterministic_claim(self) -> None:
        transcript = AuthTranscript(role="admin", outcome=AuthAgentOutcome.NOT_ENGAGED)
        rendered = " ".join(transcript.render_lines())
        assert "not engaged" in rendered
        assert "no model was consulted" in rendered
        assert not transcript.engaged

    @pytest.mark.parametrize(
        "outcome",
        [AuthAgentOutcome.ABSTAINED, AuthAgentOutcome.NOT_ATTEMPTED],
    )
    def test_a_failure_never_asserts_the_credentials_were_wrong(
        self, outcome: AuthAgentOutcome
    ) -> None:
        """The rule invariant 91 put on the deterministic path, kept here.

        Nothing in this loop can establish that a credential is wrong. A run
        whose POSTs were answered by routes that never evaluated one has
        observed nothing about it at all.
        """
        transcript = AuthTranscript(role="admin", outcome=outcome, outcome_reason="x")
        rendered = " ".join(transcript.render_lines()).lower()
        assert "credentials are wrong" not in rendered
        assert "wrong password" not in rendered


# ---------------------------------------------------------------------------
# The observation
# ---------------------------------------------------------------------------


class TestTheObservation:
    def test_it_reads_the_producers_declared_names(self) -> None:
        """No ``getattr`` with a default over the producer's model.

        A rename in ``AuthResult`` must break this loudly rather than produce an
        agent that reasons over an empty page and never says why (invariant 82).
        """
        result = AuthResult(
            login_url="http://t.test/login",
            posted_to="http://t.test/login",
            status_code=200,
            form_action_declared=False,
            form_field_names=["csrfToken", "email", "password"],
            csrf_fields_without_cookie=["csrfToken"],
            framework_fingerprint="X-Powered-By: SomeFramework",
            post_changed_nothing=True,
            referenced_scripts=["http://t.test/a.js"],
            verdict=LoginVerdict.REFUSED,
            verdict_evidence="nothing was set",
        )
        observation = observation_from_auth_result(
            result, base_url="http://t.test", components=["next@15.0.0"]
        )
        assert observation.form_field_names == ["csrfToken", "email", "password"]
        assert observation.framework_fingerprint == "X-Powered-By: SomeFramework"
        assert observation.components == ["next@15.0.0"]

    def test_the_briefing_states_that_a_defaulted_post_is_not_a_declared_destination(
        self,
    ) -> None:
        briefing = OBSERVATION.as_briefing()
        assert "declared NO action" in briefing
        assert "default this engine applied" in briefing

    def test_the_briefing_carries_the_coverage_note_when_the_inventory_is_partial(
        self,
    ) -> None:
        """A component list measured over part of the input is indeterminate.

        Invariant 101, carried one consumer along: an agent told "these are the
        components" over 8 of 31 chunks would read the silences as evidence.
        """
        observation = OBSERVATION.model_copy(
            update={
                "components": ["next@15.0.0"],
                "referenced_scripts": ["http://t.test/a.js"],
                "script_coverage_note": "8/31 available input(s) read — 23 not fetched",
            }
        )
        briefing = observation.as_briefing()
        assert "8/31" in briefing
        assert "its silences prove nothing" in briefing

    def test_carryable_names_are_the_pages_own_and_nothing_else(self) -> None:
        assert OBSERVATION.carryable_field_names() == frozenset({"csrfToken", "email", "password"})


# ---------------------------------------------------------------------------
# The prompt
# ---------------------------------------------------------------------------


class TestThePrompt:
    #: Spellings of the answer for the target this agent was built against. A
    #: prompt naming any of them would be a benchmark-tuned list wearing a
    #: paragraph, and the capability claim would be worthless: the model would
    #: be reading the answer back rather than recognising the stack.
    FORBIDDEN = (
        "nextauth",
        "next-auth",
        "/api/auth",
        "api/auth",
        "callback/credentials",
        "signin",
        "csrftoken",
    )

    def test_the_prompt_names_no_route_and_no_library(self) -> None:
        prompt = load_system_prompt().lower()
        named = [token for token in self.FORBIDDEN if token in prompt]
        assert not named, (
            "the proposal prompt names the answer, which makes the capability "
            f"claim worthless: {named}"
        )

    def test_the_prompt_states_the_three_rules_the_code_enforces(self) -> None:
        """The prompt and the gate must describe the same system.

        A prompt that promised the model more freedom than the gate allows would
        spend every turn on refusals; one that promised less would suppress the
        proposals this layer exists for.
        """
        prompt = load_system_prompt().lower()
        assert "you propose" in prompt and "you do not conclude" in prompt
        assert "never supply values" in prompt
        assert "budget" in prompt and "scope" in prompt


# ---------------------------------------------------------------------------
# The delta, not the jar
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
class TestSessionEvidenceIsTheDelta:
    """Invariant 91's rule, which this loop violated on its first live run.

    The episode's jar is CARRIAGE — a read may legitimately have been issued a
    CSRF cookie two turns earlier, and it has to be presented on the credential
    POST. It is not EVIDENCE: a cookie the target handed us before the credential
    was sent exists whatever we send.

    Measured on cal.diy: turn 1's read of the framework's CSRF route was issued
    two cookies, turn 2's credential POST was answered ``302`` to an explicit
    rejection and set NONE, and the loop ran the authenticated-state assertion
    anyway — against the CSRF cookies. The assertion correctly found nothing, and
    the abstention then reported "1 credential POST produced session material",
    which was a statement about the jar wearing the credential's name.
    """

    async def test_a_cookie_carried_in_from_a_read_is_not_evidence(self) -> None:
        llm = FakeLLM(
            [
                json.dumps({"kind": "read", "url": "http://t.test/csrf", "method": "GET"}),
                proposal_json(),
            ]
        )
        dispatcher = FakeDispatcher(
            {
                "http://t.test/csrf": DispatchResponse(
                    status=200,
                    set_cookie_names=["csrf-token"],
                    cookies={"csrf-token": "abc"},
                    body=json.dumps({"csrfToken": "abc"}),
                ),
                # The credential POST sets NOTHING. The jar is non-empty only
                # because of the read above.
                "http://t.test/session": DispatchResponse(
                    status=302,
                    headers={"Location": "http://t.test/error?e=bad-credentials"},
                    cookies={"csrf-token": "abc"},
                ),
            }
        )
        transcript = await loop(llm, dispatcher, established=True, max_turns=2).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        post_attempt = transcript.attempts[-1]
        assert not post_attempt.assertion_ran, (
            "the assertion ran against a jar the credential did not fill — an asserter "
            "that returns established=True would then have authenticated this run on a "
            "CSRF cookie"
        )
        assert transcript.outcome is AuthAgentOutcome.ABSTAINED

    async def test_a_cookie_the_credential_post_itself_set_is_evidence(self) -> None:
        """The other direction, so the rule is not merely 'never assert'."""
        llm = FakeLLM([proposal_json()])
        dispatcher = FakeDispatcher(
            {
                "http://t.test/session": DispatchResponse(
                    status=200, set_cookie_names=["sid"], cookies={"sid": "x"}
                )
            }
        )
        transcript = await loop(llm, dispatcher, established=True).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.attempts[-1].assertion_ran
        assert transcript.outcome is AuthAgentOutcome.AUTHENTICATED

    async def test_a_token_in_the_credential_responses_own_body_is_evidence(self) -> None:
        llm = FakeLLM([proposal_json()])
        dispatcher = FakeDispatcher(
            {
                "http://t.test/session": DispatchResponse(
                    status=200, body=json.dumps({"token": "JWT-OK"}), cookies={}
                )
            }
        )
        transcript = await loop(llm, dispatcher, established=True).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.attempts[-1].assertion_ran
        assert transcript.outcome is AuthAgentOutcome.AUTHENTICATED

    async def test_a_destination_that_answered_is_reported_apart_from_one_that_did_not(
        self,
    ) -> None:
        """The finding cal.diy produced, and the sentence that may carry it.

        The deterministic route came back byte-identical to the page served
        without a credential; the proposed destination came back ``302`` to an
        application-authored error. That difference is an OBSERVATION about two
        responses this engine watched, and it is sayable — unlike "the
        credentials are wrong", which nothing in this loop is in a position to
        say and which the reason must never contain.
        """
        llm = FakeLLM([proposal_json()])
        dispatcher = FakeDispatcher(
            {
                "http://t.test/session": DispatchResponse(
                    status=302,
                    headers={"Location": "http://t.test/error?e=incorrect-password"},
                )
            }
        )
        transcript = await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        reason = transcript.outcome_reason
        assert "did ANSWER" in reason
        assert "http://t.test/session" in reason
        assert "the application's to say and not this engine's" in reason
        assert "credentials are wrong" not in reason.lower()


@pytest.mark.asyncio
class TestARequestIsNotAskedTwice:
    """A settled question is not re-asked, and a corrected one is not a repeat.

    Both halves came off one live transcript. Against a Ghost admin panel the
    loop reached the correct endpoint, was answered ``401`` because the API
    declares its identity field as ``username`` while the proposal sent
    ``email``, and re-POSTed to the same URL — and the transcript rendered two
    identical lines, so a reader could not tell a corrected retry from a wasted
    attempt. Three of the reserve's attempts went to one destination.
    """

    async def test_an_identical_credential_post_is_refused_after_it_was_dispatched(
        self,
    ) -> None:
        llm = FakeLLM([proposal_json(), proposal_json(), proposal_json()])
        dispatcher = FakeDispatcher({"http://t.test/session": DispatchResponse(status=401)})
        transcript = await loop(llm, dispatcher, established=False).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert len(dispatcher.posts) == 1, "the same request was sent more than once"
        assert any(a.gate.refusal is ProposalRefusal.REPEAT_OF_REFUSED for a in transcript.attempts)

    async def test_a_corrected_identity_field_is_a_different_request(self) -> None:
        """The half a URL-only signature gets wrong, and the one that matters most.

        ``401 — wrong field name`` is precisely the case where re-POSTing to the
        same URL is the RIGHT move, and a signature that ignored the field names
        would refuse it as a repeat.
        """
        llm = FakeLLM(
            [
                proposal_json(identity_field="email"),
                proposal_json(identity_field="username"),
            ]
        )
        dispatcher = FakeDispatcher(
            {"http://t.test/session": DispatchResponse(status=401, set_cookie_names=[], cookies={})}
        )
        await loop(llm, dispatcher, established=False, max_turns=2).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert len(dispatcher.posts) == 2
        assert "email" in dispatcher.posts[0][2]
        assert "username" in dispatcher.posts[1][2]

    async def test_the_transcript_names_the_fields_each_post_carried(self) -> None:
        """NAMES, never values — and enough of them to tell two POSTs apart."""
        llm = FakeLLM([proposal_json(carry_fields=["csrfToken"])])
        dispatcher = FakeDispatcher({"http://t.test/session": DispatchResponse(status=401)})
        transcript = await loop(llm, dispatcher, established=False, max_turns=1).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        attempt = transcript.attempts[0]
        assert attempt.sent_field_names == ["csrfToken", "email", "password"]
        rendered = " ".join(transcript.render_lines())
        assert "carrying csrfToken, email, password" in rendered
        # The content type too: three live attempts differed only in encoding
        # and rendered as three identical lines.
        assert "as application/x-www-form-urlencoded carrying" in rendered
        assert "s3cret" not in json.dumps(transcript.redacted())

    async def test_the_abstention_counts_the_posts_that_produced_material(self) -> None:
        """A count must name the population its sentence is about.

        A live transcript read "3 credential POSTs produced session material"
        above three lines, two of which said "set no cookie".
        """
        llm = FakeLLM(
            [
                proposal_json(url="http://t.test/a"),
                proposal_json(url="http://t.test/b"),
            ]
        )
        dispatcher = FakeDispatcher(
            {
                "http://t.test/a": DispatchResponse(status=401),
                "http://t.test/b": DispatchResponse(
                    status=200, set_cookie_names=["sid"], cookies={"sid": "x"}
                ),
            }
        )
        transcript = await loop(llm, dispatcher, established=False, max_turns=2).run(
            OBSERVATION,
            role="admin",
            username="u@t.test",
            secret="s3cret",
            account="u@t.test",
            credential_budget_remaining=4,
        )
        assert transcript.credential_posts_dispatched == 2
        assert "1 of 2 credential POST(s) produced session material" in (transcript.outcome_reason)
