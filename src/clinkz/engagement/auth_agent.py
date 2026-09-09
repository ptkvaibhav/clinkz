"""Adaptive authentication — the agent that proposes, and the code that decides.

The deterministic pass (:mod:`clinkz.tools.auth`,
:mod:`clinkz.engagement.auth_state`) reads a login page and offers a credential
to what the page named. On three of this project's four auth-shape targets it
works, and this module never runs. On the fourth it cannot work, and the reason
is worth stating precisely because it is what the agent is for.

The target that found it
------------------------

cal.diy is a Next.js application. Its login page declares a ``<form>`` with **no
action**, so the credential POST is *defaulted* to the login URL rather than
addressed anywhere; the GET and the POST come back byte-identical, ~383.5 KB,
for any account; a ``csrfToken`` field is served with no cookie of that shape in
the jar. The destination the application actually authenticates on is composed at
runtime, from a base in one JavaScript chunk and a provider literal in another.
**It is not a literal anywhere** — not in the HTML, not in a header, not in any
single served file. No amount of reading the target harder produces it, because
reading is not the operation that would.

What produces it is *knowing the framework*: an application whose login form
posts nowhere, whose page ships a ``csrfToken`` field, and whose headers name a
particular stack is an application using an auth library whose route convention
is a property of the library rather than of this deployment. That knowledge is
what a language model has and a parser does not. So the agent's job is to
**propose** the destination from the framework identity plus the deterministic
facts already in hand — not to find it, and not to search for it.

The three rules that make an LLM safe in the credential path
------------------------------------------------------------

1. **The model proposes; :func:`~clinkz.engagement.auth_state.assert_authenticated`
   decides.** There is no field on any type here that an LLM can set to mean
   success. :class:`AuthAgentOutcome.AUTHENTICATED` is written in exactly one
   place — after the assertion returned ``established=True`` — and the assertion
   is the same anonymous-control comparison that proves every other session in
   this engine.

2. **The model names FIELDS; the engine supplies every VALUE.** A proposal
   carries field *names* chosen from a set the engine observed — the login
   page's own hidden inputs, and the keys of a JSON body a previous read
   returned. The values are looked up from what the target served. The
   credential itself is inserted by :class:`AuthAgentLoop`, never quoted into a
   prompt and never echoed back by the model. So the worst a compromised or
   confused model can do is name the wrong field or the wrong route; it cannot
   author the bytes of a request, and it cannot move a secret.

3. **Every proposal passes a deterministic gate before anything is sent**
   (:func:`validate_proposal`): in scope, a method whose kind it declared,
   not destructively classified, inside the per-account credential budget, and
   not a repeat of a proposal already refused. The gate reads no model output
   except the proposal it is judging, and it runs identically whichever provider
   produced it — which is why the call is classified ``PLANNING`` rather than
   ``EMIT``: a degraded model can cost this run its authenticated coverage, and
   it cannot send a credential anywhere the gate refuses.

Deterministic first, and that has to be provable
-------------------------------------------------

This module is reached only when the deterministic path has already failed to
establish a session for a role. DVWA, Juice Shop and Meridian all succeed
deterministically, so on those three targets the loop is not merely *unlikely*
to engage — it is unreachable, and the transcript records
:attr:`AuthAgentOutcome.NOT_ENGAGED` with no LLM turn taken and no request sent.
An engagement whose auth worked is byte-identical to one run before this module
existed. That is the property ``test_auth_agent_never_engages_on_a_working_login``
asserts, and it is the reason the entry point takes the failed
:class:`~clinkz.tools.auth.AuthResult` rather than the credential.

An abstention is a result
-------------------------

A loop that proposes three destinations and authenticates on none of them
returns :attr:`AuthAgentOutcome.ABSTAINED` carrying **what it read, what it
proposed, what came back and what it concluded**. That is not a failure mode to
be tidied away — it is the honest answer, it is rendered in the client-facing
document, and it is strictly better than the alternative this engine already
refuses (scanning an authenticated application anonymously and reporting an
empty result as a clean bill of health). The abstention names the reason, and
the reason may never be "the credentials are wrong" unless something actually
evaluated them.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
from collections.abc import Awaitable, Callable
from enum import StrEnum
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from clinkz.engagement.auth_state import AuthAssertion
from clinkz.engagement.secrets import redact_structure
from clinkz.llm.base import LLMClient
from clinkz.llm.call_purpose import LLMCallPurpose, llm_call_purpose

logger = logging.getLogger(__name__)

#: How many proposal rounds the loop will take. A BACKSTOP, deliberately loose
#: enough that the two bounds which are actually reasoned about — the per-account
#: credential reserve and :data:`MAX_READS` — are the ones that bind.
#:
#: It was 3, and 3 made it the operative limit rather than the backstop, which is
#: the defect of a second tighter bound nobody thought about. Measured twice on
#: live targets: on cal.diy the loop spent turn 1 on a read of the framework's
#: CSRF route, turn 2 on the credential POST, and turn 3 proposing a read of the
#: provider metadata — out of turns with its credential reserve untouched. On a
#: Ghost admin panel it reached the correct endpoint on turn 2, was answered
#: ``401``, and proposed on turn 3 to read the 2.2 MB admin bundle for the
#: identity field name the API actually declares — which is the right next move
#: and had nowhere to go.
#:
#: A read costs no credential budget, so a loop that keeps proposing reads is
#: bounded by :data:`MAX_READS`; a loop that keeps proposing credential POSTs is
#: bounded by the reserve. This number exists so that neither of those being
#: misconfigured can make the loop walk a target indefinitely.
MAX_TURNS = 6

#: Reads a turn may propose before the loop stops accepting them. A read is
#: cheap and safe, which is exactly why it needs its own ceiling: it is the one
#: proposal kind the credential budget does not bound.
MAX_READS = 6

#: Methods a :attr:`ProposalKind.READ` may use. Invariant 21's list, restated
#: here rather than imported because the constraint is this module's own: a
#: proposal that maps the surface must not be able to write to it.
READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

#: Content types the engine can encode a credential body as. Deliberately the
#: authenticator's own tuple: a proposal naming a third type is refused rather
#: than silently downgraded, because "we sent form-encoded when the model said
#: JSON" is a divergence between what was proposed and what went out, and the
#: transcript would then describe a request nobody made.
ENCODABLE_CONTENT_TYPES: frozenset[str] = frozenset(
    {"application/json", "application/x-www-form-urlencoded"}
)

#: How much of a response body the transcript keeps. Short: the transcript is a
#: diagnostic record, not a capture, and every byte of it goes through
#: :func:`~clinkz.engagement.secrets.redact_structure` on the way to disk.
BODY_EXCERPT = 400

#: Body keys that name a session token. Read only as part of the credential
#: POST's own DELTA — a token in the response to the credentials is produced by
#: them, which is exactly what a cookie carried in from an earlier turn is not.
_TOKEN_KEYS: frozenset[str] = frozenset({"token", "access_token", "accesstoken", "jwt", "id_token"})

#: JSON keys whose VALUE this module will carry into a later proposal's body.
#: Empty by design — there is no such list. A value is carried because a
#: previous response supplied it under a name the model then referenced, and
#: which names those are is a property of the target's response, never of a
#: table here. Kept as a named constant so the absence is a decision a reader
#: can find, rather than a table someone adds later without noticing what it
#: would mean.
CARRYABLE_KEY_ALLOWLIST: frozenset[str] = frozenset()


class AuthAgentOutcome(StrEnum):
    """How the adaptive layer ended, in four values that mean different things."""

    #: The deterministic path established the session. The loop never ran, no
    #: LLM was called and no request was sent. Every target whose login this
    #: engine could already read reaches this value.
    NOT_ENGAGED = "not_engaged"

    #: A proposal was dispatched and ``assert_authenticated`` PROVED the session
    #: it produced. The only value that permits the engagement to continue
    #: authenticated, and it is written on the assertion's verdict alone.
    AUTHENTICATED = "authenticated"

    #: The loop ran, proposed, dispatched, and nothing established a session.
    #: The transcript carries the sequence and :attr:`AuthTranscript.outcome_reason`
    #: names what was absent. This is a result, not an error.
    ABSTAINED = "abstained"

    #: The loop could not run at all — no LLM configured, the credential budget
    #: already spent, the engagement halted, or the model returned nothing
    #: parseable. Distinct from ABSTAINED because nothing was ever proposed, and
    #: "we tried three destinations and none worked" is a different sentence from
    #: "we never got to try one".
    NOT_ATTEMPTED = "not_attempted"


class ProposalKind(StrEnum):
    """What a proposal asks the engine to do.

    Two kinds, bounded differently, and the difference is the whole of the
    safety argument for letting a model steer here at all.
    """

    #: A safe-method request that carries no credential. Bounded by
    #: :data:`MAX_READS` and by scope; costs no credential budget. This is how
    #: an application whose auth route needs a token fetched first is reachable
    #: at all.
    READ = "read"

    #: A credential POST. Bounded by the per-account budget the governor owns,
    #: by the destructive classifier, and by scope.
    CREDENTIAL_POST = "credential_post"


class ProposalRefusal(StrEnum):
    """Why the deterministic gate refused a proposal.

    Named individually because they have different fixes and because the
    transcript reports them to an operator: "out of scope" is the operator's
    scope file, "budget spent" is the engagement's own bound, and "unknown
    field" is the model naming something the target never served.
    """

    NOT_A_URL = "not_a_url"
    OUT_OF_SCOPE = "out_of_scope"
    METHOD_NOT_PERMITTED = "method_not_permitted"
    DESTRUCTIVE = "destructive"
    CONTENT_TYPE_NOT_ENCODABLE = "content_type_not_encodable"
    UNKNOWN_CARRY_FIELD = "unknown_carry_field"
    BUDGET_SPENT = "budget_spent"
    READ_CEILING = "read_ceiling"
    REPEAT_OF_REFUSED = "repeat_of_refused"
    NO_IDENTITY_FIELD = "no_identity_field"


class AuthObservation(BaseModel):
    """Every deterministic fact the failed login pass already established.

    Assembled from an :class:`~clinkz.tools.auth.AuthResult` and the recon
    result the orchestrator already holds. **Nothing here costs a request** —
    that is the point. The agent reasons over what was learned on the way to
    failing, which is a substantial amount and was previously discarded.

    Every field is an observation. There is no field for a hypothesis, an
    inference, or a name that "looks like" anything.

    Attributes:
        base_url: The engagement's primary target URL.
        login_url: Where the login page was fetched from.
        posted_to: Where the credential POST actually went. Differs from
            *login_url* whenever a form action redirected it, and is equal to it
            when the form declared no action at all — which is itself a fact,
            carried in *form_action_declared*.
        post_status: The credential POST's status code, ``0`` if none was sent.
        page_declared_a_form: Whether the page served a ``<form>`` element.
        form_action_declared: Whether that form declared an ``action``.
        form_field_names: Every input NAME the login form declared — identity,
            secret, hidden and submit. Names are schema the application chose,
            never data, which is why they travel and values do not.
        csrf_fields_without_cookie: CSRF-shaped hidden fields with no cookie of
            that shape in the jar. Half of a double-submit token.
        login_page_cookie_names: Cookie NAMES the login GET issued. Names again:
            a value is a session and is redacted, a name is schema.
        framework_fingerprint: What the login page's headers say the stack is.
            Invariant 22's deterministic protocol artifact, and the single most
            load-bearing input the agent gets.
        login_page_content_type: What the login page served itself as.
        post_changed_nothing: The credential POST came back the same size as the
            login-page GET. The application did not act on it.
        referenced_scripts: Same-origin script URLs the login page referenced.
        script_coverage_note: What fraction of those the package-identity
            producer actually read, declared by that producer. Invariant 101 —
            a zero measured over part of the input is indeterminate, and an
            agent reasoning over the inventory has to know which it is looking
            at.
        components: ``name@version`` for every component recon named.
        verdict: The credential exchange's own three-valued verdict.
        verdict_evidence: The observation behind it.
        failure_stage: Which step ended the deterministic attempt.
    """

    base_url: str = ""
    login_url: str = ""
    posted_to: str = ""
    post_status: int = 0
    page_declared_a_form: bool = True
    form_action_declared: bool = True
    form_field_names: list[str] = Field(default_factory=list)
    csrf_fields_without_cookie: list[str] = Field(default_factory=list)
    login_page_cookie_names: list[str] = Field(default_factory=list)
    framework_fingerprint: str = ""
    login_page_content_type: str = ""
    post_changed_nothing: bool = False
    referenced_scripts: list[str] = Field(default_factory=list)
    script_coverage_note: str = ""
    components: list[str] = Field(default_factory=list)
    verdict: str = ""
    verdict_evidence: str = ""
    failure_stage: str = ""

    def carryable_field_names(self) -> frozenset[str]:
        """Field names a proposal may reference, before any read has run.

        The login form's own inputs. A proposal naming anything else is refused
        by the gate — not because the name is dangerous, but because the engine
        would have no value to put in it and would have to invent one, which is
        the rule this module is built on.
        """
        return frozenset(self.form_field_names)

    def as_briefing(self) -> str:
        """The observation as the model reads it: sentences, each one a fact.

        Written as prose rather than handed over as JSON because every line is a
        statement about what was observed, and the model's job is to recognise a
        stack from a combination of them. A schema dump invites the model to
        pattern-match on field names; sentences invite it to reason about an
        application.

        Returns:
            The briefing. Never contains a credential — the loop inserts those
            after the model has answered.
        """
        lines = [
            f"Target base URL: {self.base_url}",
            f"Login page fetched from: {self.login_url}",
        ]
        if self.login_page_content_type:
            lines.append(f"The login page served itself as: {self.login_page_content_type}")
        if not self.page_declared_a_form:
            lines.append(
                "The login page served NO <form> element at all; the field names below "
                "were read from inputs outside any form."
            )
        elif not self.form_action_declared:
            lines.append(
                "The login <form> declared NO action attribute. The credential POST was "
                f"therefore DEFAULTED to {self.posted_to or self.login_url} — that is a "
                "default this engine applied, not a destination the page named. The "
                "application's real credential destination is unknown from the HTML."
            )
        else:
            lines.append(f"The form's action sent the credential POST to: {self.posted_to}")

        if self.form_field_names:
            lines.append(
                "Input names the login page declared: " + ", ".join(sorted(self.form_field_names))
            )
        if self.csrf_fields_without_cookie:
            lines.append(
                "These CSRF-shaped fields were served with NO cookie of that shape in the "
                "jar (half of a double-submit pair): "
                + ", ".join(sorted(self.csrf_fields_without_cookie))
            )
        if self.login_page_cookie_names:
            lines.append(
                "Cookie names the login page GET issued: "
                + ", ".join(sorted(self.login_page_cookie_names))
            )
        else:
            lines.append("The login page GET issued no cookies at all.")
        if self.framework_fingerprint:
            lines.append(
                f"The login page's response HEADERS identify the stack: "
                f"{self.framework_fingerprint}"
            )
        if self.post_status:
            lines.append(f"The credential POST returned HTTP {self.post_status}.")
        if self.post_changed_nothing:
            lines.append(
                "The credential POST returned a response the SAME SIZE as the login page "
                "served without credentials. Nothing about the application changed. "
                "Nothing evaluated the credential."
            )
        if self.verdict_evidence:
            lines.append(f"The credential exchange concluded: {self.verdict_evidence}")
        if self.referenced_scripts:
            lines.append(
                f"The login page references {len(self.referenced_scripts)} same-origin "
                "script bundle(s); the first few are: " + ", ".join(self.referenced_scripts[:5])
            )
        if self.script_coverage_note:
            lines.append(
                f"Only part of that bundle set was read by this engine's package reader "
                f"({self.script_coverage_note}), so the component list below is measured "
                "over part of the input and its silences prove nothing."
            )
        if self.components:
            lines.append("Components this run identified: " + ", ".join(self.components[:20]))
        return "\n".join(f"- {line}" for line in lines)


class AuthProposal(BaseModel):
    """One thing the agent proposes doing next.

    A proposal is a *request shape*, and deliberately not a request: it names a
    URL, a kind, a content type and a set of field NAMES. Every value that ends
    up on the wire is supplied by the engine — the credential from the
    engagement's credential file, the carried fields from what the target itself
    served. There is no free-text body field on this model and that is not an
    oversight.

    Attributes:
        kind: Read, or credential POST.
        url: Absolute URL. Scope-checked by the gate before anything is sent.
        method: HTTP method. Constrained by *kind* at the gate.
        content_type: How to encode a credential body. Ignored for a read.
        identity_field: The name the credential's identity goes under.
        secret_field: The name the credential's secret goes under.
        carry_fields: Names of fields the engine should carry from what it has
            already observed — the login form's hidden inputs, or the keys of a
            JSON body a previous read returned. Values come from there, never
            from the model.
        rationale: Why. Recorded verbatim in the transcript and read by an
            operator; it decides nothing.
    """

    kind: ProposalKind = ProposalKind.CREDENTIAL_POST
    url: str = ""
    method: str = "POST"
    content_type: str = "application/x-www-form-urlencoded"
    identity_field: str = ""
    secret_field: str = "password"
    carry_fields: list[str] = Field(default_factory=list)
    rationale: str = ""

    def signature(self) -> tuple[str, ...]:
        """What makes two proposals the same proposal, for the repeat check.

        Everything that changes the bytes, and nothing that does not.

        **The rationale is excluded**: a model that re-proposes the same request
        with a new explanation has proposed the same request, and the gate that
        refused it the first time is answering the same question.

        **The FIELD NAMES are included**, and that half was missing. Measured on
        a Ghost admin panel: the loop reached the correct endpoint, was answered
        ``401`` because the API declares its identity field as ``username`` and
        the proposal sent ``email``, and then re-POSTed. Whether that second POST
        was a corrected retry or a verbatim repeat is the whole question — and a
        signature of ``(kind, method, url, content_type)`` gives the same answer
        to both, so it can neither refuse the waste nor permit the fix. A
        proposal that changes the identity field is a different request to the
        same destination and must be allowed; one that changes nothing is a
        credential attempt spent on an answer already held.
        """
        return (
            self.kind.value,
            self.method.upper(),
            self.url.rstrip("/"),
            self.content_type,
            self.identity_field,
            self.secret_field,
            *sorted(self.carry_fields),
        )


class GateVerdict(BaseModel):
    """The deterministic gate's answer about one proposal.

    Attributes:
        allowed: Whether the proposal may be dispatched.
        refusal: Which rule refused it, when one did.
        reason: The refusal in a sentence, for the transcript and the operator.
    """

    allowed: bool = False
    refusal: ProposalRefusal | None = None
    reason: str = ""


class DispatchResponse(BaseModel):
    """What came back, as the loop and the transcript need to see it.

    Attributes:
        status: HTTP status, ``0`` when the request never completed.
        headers: Response headers.
        body: Response body.
        set_cookie_names: NAMES of cookies the response set, across every hop.
        cookies: The cookie jar after the exchange. Redacted before it reaches
            disk; carried in memory because it is the session material.
        error: Transport or refusal error.
        refused_by_rails: Non-empty when the safety governor refused, carrying
            the category. Distinct from *error*: a refusal is the engine
            working, and it must not be reported as the target failing.
    """

    status: int = 0
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    set_cookie_names: list[str] = Field(default_factory=list)
    cookies: dict[str, str] = Field(default_factory=dict)
    error: str = ""
    refused_by_rails: str = ""

    @property
    def credential_session_material(self) -> bool:
        """Whether THIS response produced something that could be a session.

        Invariant 91's rule, which this loop violated on its first live run:
        **session evidence is the DELTA across the credential POST, not the
        jar.** The episode's jar is carriage — a read may legitimately have been
        issued a CSRF cookie two turns earlier, and it has to be presented on
        the POST — but a cookie the target handed us before the credential was
        sent exists whatever we send, so it is not evidence about the
        credential.

        Measured on cal.diy: turn 1's read of the framework's CSRF route was
        issued two cookies, turn 2's credential POST was answered ``302`` to an
        explicit rejection and set NONE, and the loop ran the authenticated-state
        assertion anyway — against the CSRF cookies. The assertion correctly
        found nothing, and the abstention then said "1 credential POST produced
        session material", which was a statement about the jar wearing the
        credential's name.

        Two things count, and both are produced BY this exchange: a
        ``Set-Cookie`` on this response, or a token in its body.
        """
        return bool(self.set_cookie_names or self.bearer_token)

    @property
    def bearer_token(self) -> str:
        """A token this response's JSON body carries, or ``""``.

        The same shapes :meth:`json_values` exposes, filtered to the names an
        API uses for a session. Read from THIS response, so it is part of the
        delta rather than part of the jar.
        """
        for name, value in self.json_values().items():
            if name.lower() in _TOKEN_KEYS and value.strip():
                return value.strip()
        return ""

    def json_keys(self) -> list[str]:
        """Top-level keys of the body, when it is a JSON object.

        This is how a read teaches the loop a field name the model may later
        reference. The VALUE stays here; only the name is offered to the model.
        """
        try:
            parsed = json.loads(self.body)
        except (json.JSONDecodeError, TypeError, ValueError):
            return []
        if not isinstance(parsed, dict):
            return []
        return sorted(str(k) for k in parsed)

    def json_values(self) -> dict[str, str]:
        """Top-level string values of a JSON object body, keyed by name."""
        try:
            parsed = json.loads(self.body)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        if not isinstance(parsed, dict):
            return {}
        return {str(k): v for k, v in parsed.items() if isinstance(v, str)}

    @property
    def content_type(self) -> str:
        """The response's declared content type, parameters dropped."""
        for key, value in self.headers.items():
            if key.lower() == "content-type":
                return (value or "").split(";")[0].strip().lower()
        return ""

    @property
    def location(self) -> str:
        """The ``Location`` header, case-insensitively."""
        for key, value in self.headers.items():
            if key.lower() == "location":
                return value
        return ""


class AuthAttempt(BaseModel):
    """One turn: what was proposed, what the gate said, what came back.

    The four fields are kept apart because a reader needs to tell them apart. A
    proposal the gate refused and a proposal that was dispatched and answered
    404 are different events with different fixes, and a transcript that
    rendered both as "did not work" would be useless for the one thing it exists
    for.

    Attributes:
        turn: 1-based turn number.
        proposal: What the agent proposed.
        gate: The gate's verdict.
        dispatched: Whether a request actually left the engine.
        status: Its status code.
        set_cookie_names: Cookie names the response set.
        response_content_type: What the response declared itself as.
        location: Its ``Location`` header, when it redirected.
        sent_field_names: The field NAMES this credential POST carried, sorted.
            Names are schema the application published; the values are the
            credential and what the target itself served, and neither appears
            here. Empty for a read.
        body_excerpt: A short, redacted excerpt.
        taught: What this response taught, as a deterministic sentence. Composed
            by the engine from the response, never by the model.
        assertion_ran: Whether ``assert_authenticated`` was run on the result.
        established: What it said. The ONLY field in this module that can mean
            "authenticated", and it is copied from the assertion.
        assertion_discriminator: Which boundary discriminator proved it.
    """

    turn: int = 0
    proposal: AuthProposal = AuthProposal()
    gate: GateVerdict = GateVerdict()
    dispatched: bool = False
    status: int = 0
    set_cookie_names: list[str] = Field(default_factory=list)
    sent_field_names: list[str] = Field(default_factory=list)
    response_content_type: str = ""
    location: str = ""
    body_excerpt: str = ""
    taught: str = ""
    assertion_ran: bool = False
    established: bool = False
    assertion_discriminator: str = ""


class AuthTranscript(BaseModel):
    """The whole adaptive-auth episode, as the report and an operator read it.

    Written for every role the deterministic pass failed on, including roles
    where the loop never engaged — an engagement whose auth worked carries a
    transcript saying :attr:`AuthAgentOutcome.NOT_ENGAGED` with zero turns and
    zero LLM calls, which is how "deterministic first" is *shown* rather than
    asserted.

    Attributes:
        role: Which credential role this episode was for.
        outcome: How it ended.
        outcome_reason: Why, in a sentence. On an abstention this is what the
            operator acts on, so it names what was ABSENT and never asserts the
            credentials were wrong.
        observation: What was handed in.
        attempts: Every turn, in order.
        llm_turns: How many times a model was actually asked. Zero on
            NOT_ENGAGED, and asserted to be zero by the byte-identity test.
        proposals_refused: How many proposals the gate refused.
        credential_posts_dispatched: How many credential POSTs actually left.
        reads_dispatched: How many safe-method reads actually left.
    """

    role: str = ""
    outcome: AuthAgentOutcome = AuthAgentOutcome.NOT_ENGAGED
    outcome_reason: str = ""
    observation: AuthObservation = AuthObservation()
    attempts: list[AuthAttempt] = Field(default_factory=list)
    llm_turns: int = 0
    proposals_refused: int = 0
    credential_posts_dispatched: int = 0
    reads_dispatched: int = 0

    @property
    def engaged(self) -> bool:
        """Whether the adaptive layer did anything at all."""
        return self.outcome is not AuthAgentOutcome.NOT_ENGAGED

    def redacted(self) -> dict[str, Any]:
        """The transcript as it may be written to ``outputs/``.

        Through :func:`~clinkz.engagement.secrets.redact_structure`, which is
        key-aware and shape-aware: a ``Set-Cookie`` value is caught by its key
        and a JWT by its shape. This module keeps cookie NAMES and drops cookie
        VALUES before that point anyway, so the redaction is the second of two
        controls rather than the only one — but it is the one that catches a
        token the target embedded in a body excerpt, which no rule here could
        anticipate.
        """
        return redact_structure(self.model_dump(mode="json"))

    def render_lines(self) -> list[str]:
        """The client-facing rendering: what it read, proposed, got, concluded.

        Deliberately the same four things for every outcome. A reader comparing
        a successful episode against an abstention should be reading the same
        shape with different contents, not two different documents.
        """
        if self.outcome is AuthAgentOutcome.NOT_ENGAGED:
            return [
                f"- **Adaptive authentication ({self.role}):** not engaged — the "
                "deterministic login path established the session, so no model was "
                "consulted and no additional request was sent."
            ]

        headline = {
            AuthAgentOutcome.AUTHENTICATED: (
                "PROVEN by the adaptive layer — the deterministic login path could not "
                "reach this application's credential destination"
            ),
            AuthAgentOutcome.ABSTAINED: "ABSTAINED",
            AuthAgentOutcome.NOT_ATTEMPTED: "NOT ATTEMPTED",
        }[self.outcome]
        lines = [f"- **Adaptive authentication ({self.role}):** {headline}."]
        lines.append(f"  - Why: {self.outcome_reason}")
        lines.append(
            f"  - {self.llm_turns} proposal round(s); "
            f"{self.credential_posts_dispatched} credential POST(s) and "
            f"{self.reads_dispatched} safe read(s) dispatched; "
            f"{self.proposals_refused} proposal(s) refused by the deterministic gate."
        )
        for attempt in self.attempts:
            if not attempt.gate.allowed:
                lines.append(
                    f"  - Turn {attempt.turn}: proposed {attempt.proposal.method} "
                    f"{attempt.proposal.url} — REFUSED by the gate "
                    f"({attempt.gate.refusal.value if attempt.gate.refusal else '?'}): "
                    f"{attempt.gate.reason}"
                )
                continue
            carried = (
                f" carrying {', '.join(attempt.sent_field_names)}"
                if attempt.sent_field_names
                else ""
            )
            lines.append(
                f"  - Turn {attempt.turn}: proposed {attempt.proposal.method} "
                f"{attempt.proposal.url}{carried} — {attempt.taught}"
            )
        return lines


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

#: Where the proposal prompt lives. A file beside every other agent's system
#: prompt, for the reason CLAUDE.md gives: a prompt in a string literal is a
#: prompt nobody reviews. This one especially — its whole claim is that it does
#: NOT name the answer, and a claim like that is only checkable against a diff.
PROMPT_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "agents" / "prompts" / "auth_agent_system.md"
)


def load_system_prompt(path: pathlib.Path | None = None) -> str:
    """Read the proposal prompt from disk.

    Args:
        path: Override, for tests and the corpus driver.

    Returns:
        The prompt text.

    Raises:
        FileNotFoundError: The prompt is missing. Deliberately not defaulted to
            an inline string: a loop running on a fallback prompt nobody has read
            is exactly the thing the file-on-disk rule exists to prevent, and it
            would fail silently by producing worse proposals rather than none.
    """
    return (path or PROMPT_PATH).read_text(encoding="utf-8")


def observation_from_auth_result(
    result: Any,
    *,
    base_url: str,
    components: list[str] | None = None,
    script_coverage_note: str = "",
) -> AuthObservation:
    """Build the briefing from the failed deterministic attempt.

    A pure translation, and it reads the producer's declared field names rather
    than probing for them (invariant 82) — a ``getattr`` with a default here is
    what would turn a rename in :class:`~clinkz.tools.auth.AuthResult` into an
    agent that reasons over an empty page forever and never says why.

    Args:
        result: The :class:`~clinkz.tools.auth.AuthResult` that did not
            establish a session. Typed loosely to keep ``engagement`` from
            importing ``tools``, which imports back.
        base_url: The engagement's primary target URL.
        components: ``name@version`` rows recon identified.
        script_coverage_note: The package-identity producer's own declaration of
            what fraction of the referenced bundles it read. Carried because a
            component list measured over part of the input is indeterminate, not
            a finding about the target (invariant 101), and an agent reasoning
            over the list has to be told which it is holding.

    Returns:
        An :class:`AuthObservation`.
    """
    return AuthObservation(
        base_url=base_url,
        login_url=result.login_url,
        posted_to=result.posted_to,
        post_status=result.status_code,
        page_declared_a_form=result.page_declared_a_form,
        form_action_declared=result.form_action_declared,
        form_field_names=list(result.form_field_names),
        csrf_fields_without_cookie=list(result.csrf_fields_without_cookie),
        login_page_cookie_names=list(result.login_page_cookie_names),
        framework_fingerprint=result.framework_fingerprint,
        login_page_content_type=result.login_page_content_type,
        post_changed_nothing=result.post_changed_nothing,
        referenced_scripts=list(result.referenced_scripts),
        script_coverage_note=script_coverage_note,
        components=list(components or []),
        verdict=str(result.verdict),
        verdict_evidence=result.verdict_evidence,
        failure_stage=result.failure_stage,
    )


# ---------------------------------------------------------------------------
# The deterministic gate
# ---------------------------------------------------------------------------


def _is_absolute_http_url(url: str) -> bool:
    parsed = urlparse(url or "")
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def validate_proposal(
    proposal: AuthProposal,
    *,
    in_scope: Callable[[str], bool],
    known_field_names: frozenset[str],
    credential_budget_remaining: int | None,
    reads_remaining: int,
    already_refused: frozenset[tuple[str, ...]],
) -> GateVerdict:
    """Decide whether a proposal may be dispatched. Pure, and reads no model output.

    Every rule here is a rule the engine would apply to a request from any
    source; none of them is special pleading about a proposal being
    LLM-authored. That is deliberate — a gate whose rules only make sense
    because a model wrote the input is a gate nobody can reason about.

    The order is the cheap-and-total-first order the rest of this codebase uses:
    a malformed URL is refused before scope is consulted, and scope before the
    destructive classifier, because each later check assumes the earlier one
    passed.

    Args:
        proposal: What to judge.
        in_scope: The engagement's scope predicate. Called with the proposal's
            URL and nothing else.
        known_field_names: Every field name the engine can supply a value for —
            the login form's inputs plus the keys of every read so far. A
            proposal referencing anything else is refused, because the engine
            would have to invent the value.
        credential_budget_remaining: Per-account credential attempts left, or
            ``None`` when the policy configures no bound. ``None`` is carried
            rather than flattened to a large integer because the refusal message
            prints this number, and a bound nobody set must not be quoted as one.
        reads_remaining: Safe reads left this episode.
        already_refused: Signatures of proposals this episode has already
            settled — refused by this gate, or dispatched and answered. Both are
            questions whose answer is already held.

    Returns:
        A :class:`GateVerdict`.
    """
    method = (proposal.method or "").upper()

    if not _is_absolute_http_url(proposal.url):
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.NOT_A_URL,
            reason=(
                f"{proposal.url!r} is not an absolute http(s) URL. A proposal names a "
                "destination; resolving a relative one here would mean this gate chose "
                "the host"
            ),
        )

    if proposal.signature() in already_refused:
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.REPEAT_OF_REFUSED,
            reason=(
                f"{method} {proposal.url} has already been settled this episode — either "
                "refused here, or dispatched and answered — carrying the same fields. "
                "Re-proposing it asks a question whose answer is already held, and on a "
                "credential POST it would spend one of very few attempts to hold it twice"
            ),
        )

    if not in_scope(proposal.url):
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.OUT_OF_SCOPE,
            reason=(
                f"{proposal.url} is outside the engagement scope. This is the refusal "
                "that matters most here: a proposal is the one place in this engine "
                "where a destination is named by something other than the target or the "
                "operator"
            ),
        )

    if proposal.kind is ProposalKind.READ:
        if method not in READ_METHODS:
            return GateVerdict(
                allowed=False,
                refusal=ProposalRefusal.METHOD_NOT_PERMITTED,
                reason=(
                    f"a read proposal declared method {method}; surface mapping uses "
                    f"{'/'.join(sorted(READ_METHODS))} and never writes to the target"
                ),
            )
        if reads_remaining <= 0:
            return GateVerdict(
                allowed=False,
                refusal=ProposalRefusal.READ_CEILING,
                reason=(
                    f"the read ceiling of {MAX_READS} for this episode is spent. A read "
                    "costs no credential budget, which is exactly why it needs a bound "
                    "of its own"
                ),
            )
        return GateVerdict(allowed=True, reason=f"{method} {proposal.url} is a safe read in scope")

    # From here: a credential POST.
    if method != "POST":
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.METHOD_NOT_PERMITTED,
            reason=(
                f"a credential proposal declared method {method}. A credential goes in a "
                "body, and a method that puts it in a URL puts it in every log between "
                "here and the application"
            ),
        )

    if proposal.content_type not in ENCODABLE_CONTENT_TYPES:
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.CONTENT_TYPE_NOT_ENCODABLE,
            reason=(
                f"{proposal.content_type!r} is not a type this engine encodes "
                f"({', '.join(sorted(ENCODABLE_CONTENT_TYPES))}). Sending a different "
                "encoding than the one proposed would make the transcript describe a "
                "request nobody made"
            ),
        )

    if not proposal.identity_field or not proposal.secret_field:
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.NO_IDENTITY_FIELD,
            reason=(
                "a credential POST must name both the identity field and the secret "
                "field; the engine puts the credential in those names and will not "
                "choose them itself"
            ),
        )

    unknown = [name for name in proposal.carry_fields if name not in known_field_names]
    if unknown:
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.UNKNOWN_CARRY_FIELD,
            reason=(
                f"the proposal asks to carry field(s) {', '.join(sorted(unknown))}, and "
                "nothing this engagement observed supplies a value for them. The engine "
                "sends values the target served; it does not author them"
            ),
        )

    if credential_budget_remaining is not None and credential_budget_remaining <= 0:
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.BUDGET_SPENT,
            reason=(
                "the per-account credential budget is spent. The loop cannot spend its "
                "way out of a wrong hypothesis, and an account the client handed us is "
                "not the place to try"
            ),
        )

    from clinkz.safety.destructive import classify_request

    verdict = classify_request(
        "POST",
        proposal.url,
        field_names=[
            *proposal.carry_fields,
            proposal.identity_field,
            proposal.secret_field,
        ],
    )
    if verdict.refused:
        return GateVerdict(
            allowed=False,
            refusal=ProposalRefusal.DESTRUCTIVE,
            reason=(
                f"the destructive classifier refused it as {verdict.category} "
                f"(signal: {verdict.signal}). A login shape is not a licence to POST "
                f"anywhere: {verdict.reason}"
            ),
        )

    return GateVerdict(
        allowed=True,
        reason=(
            f"POST {proposal.url} is in scope, non-destructive, encodable as "
            f"{proposal.content_type}, names both credential fields, carries only "
            f"observed values, and "
            + (
                "no per-account credential bound is configured"
                if credential_budget_remaining is None
                else f"{credential_budget_remaining} credential attempt(s) remain"
            )
        ),
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


class CredentialDispatcher(Protocol):
    """The request capability the loop needs, injected rather than imported.

    The orchestrator supplies an adapter over the engagement's real HTTP path,
    so a proposal inherits the same scope enforcement, governor, per-account
    credential budget, docker/host routing and action log as every other
    request the engagement makes. Tests supply a fake, which is what makes the
    loop's logic exercisable with no network.
    """

    async def read(self, url: str, method: str) -> DispatchResponse:
        """Issue a safe-method request carrying no credential."""
        ...

    async def post_credentials(
        self,
        url: str,
        *,
        content_type: str,
        fields: dict[str, str],
        account: str,
    ) -> DispatchResponse:
        """POST a credential body, counted against the per-account budget."""
        ...


#: Runs the authenticated-state assertion over some session material. The
#: orchestrator's own ``_assert_role_session`` machinery, injected, so the
#: adaptive path is proven by exactly the oracle the deterministic path is.
SessionAsserter = Callable[[dict[str, str], dict[str, str]], Awaitable[AuthAssertion]]


class AuthAgentLoop:
    """Propose, gate, dispatch, assert — until a session is proven or the budget ends.

    The loop owns the ordering and the budgets; it owns no verdict. Its three
    collaborators are injected and each is the authority on its own question:
    the LLM on what to propose, :func:`validate_proposal` on whether it may be
    sent, and the :data:`SessionAsserter` on whether a session exists. This
    class decides only when to stop.

    **The per-account budget governs it, and it cannot spend its way out.** The
    governor's ``max_credential_attempts_per_account`` is already spent by the
    deterministic pass before this loop begins, and the remaining balance is
    handed in. A loop that proposes a fourth credential POST with none left is
    refused by its own gate, records the refusal, and abstains — which is the
    correct outcome, because the alternative is locking an account the client
    handed us on the assumption that we would be careful.
    """

    def __init__(
        self,
        *,
        llm: LLMClient,
        dispatcher: CredentialDispatcher,
        asserter: SessionAsserter,
        in_scope: Callable[[str], bool],
        system_prompt: str,
        max_turns: int = MAX_TURNS,
        max_reads: int = MAX_READS,
    ) -> None:
        self._llm = llm
        self._dispatcher = dispatcher
        self._assert_session = asserter
        self._in_scope = in_scope
        self._system_prompt = system_prompt
        self._max_turns = max_turns
        self._max_reads = max_reads
        self._logger = logging.getLogger(f"{__name__}.AuthAgentLoop")
        # Set only on the AUTHENTICATED path, and read only by the orchestrator
        # to install the session. Instance state rather than transcript fields
        # because a cookie VALUE must not live in a structure whose whole
        # purpose is to be written to disk.
        self._session_cookies: dict[str, str] = {}
        self._assertion: AuthAssertion | None = None

    async def run(
        self,
        observation: AuthObservation,
        *,
        role: str,
        username: str,
        secret: str,
        account: str,
        credential_budget_remaining: int | None,
    ) -> AuthTranscript:
        """Run the loop and return its transcript.

        Never raises: an exception here would abort an engagement over an
        adaptive layer that is by definition running because the deterministic
        one already failed. Everything that goes wrong becomes an outcome with a
        reason, which is the same contract the safety rails keep.

        Args:
            observation: What the deterministic pass learned.
            role: The credential role, for the transcript.
            username: The identity to offer. Never quoted into a prompt.
            secret: The secret to offer. Never quoted into a prompt, never
                logged, never placed in the transcript.
            account: The account identifier the governor keys its budget on.
            credential_budget_remaining: Attempts left for that account, or
                ``None`` when the policy configures no bound.

        Returns:
            An :class:`AuthTranscript`.
        """
        transcript = AuthTranscript(role=role, observation=observation)

        if credential_budget_remaining is not None and credential_budget_remaining <= 0:
            transcript.outcome = AuthAgentOutcome.NOT_ATTEMPTED
            transcript.outcome_reason = (
                "the per-account credential budget was already spent by the deterministic "
                "login attempt, so no proposal could have been dispatched. Nothing here is "
                "a statement about the credentials — nothing offered them"
            )
            return transcript

        # Field names the engine can supply a value for. Grows as reads teach it
        # new ones; a name never in here is a name the gate refuses.
        known_values: dict[str, str] = dict.fromkeys(observation.form_field_names, "")
        # Signatures this episode has SETTLED: refused by the gate, or
        # dispatched and answered. Both are questions whose answer is held, and
        # a credential POST re-asking one spends an attempt to learn nothing.
        settled: set[tuple[str, ...]] = set()
        history: list[str] = []
        reads_used = 0
        posts_used = 0

        for turn in range(1, self._max_turns + 1):
            proposal = await self._propose_destinations(observation, history, turn)
            if proposal is None:
                if transcript.attempts:
                    # The round produced nothing, and earlier rounds produced
                    # something. What the loop LEARNED outranks how it stopped:
                    # an operator needs the destinations that were tried and
                    # what came back, and "the model returned nothing parseable"
                    # is a footnote on that rather than a replacement for it.
                    transcript.outcome = AuthAgentOutcome.ABSTAINED
                    transcript.outcome_reason = (
                        f"{_abstention_reason(transcript)}. The loop then stopped early: "
                        "a proposal round returned nothing this engine could parse into a "
                        "request shape"
                    )
                else:
                    transcript.outcome = AuthAgentOutcome.NOT_ATTEMPTED
                    transcript.outcome_reason = (
                        "no proposal was obtained — the model was unreachable or returned "
                        "nothing this engine could parse into a request shape. Nothing was "
                        "sent and nothing was concluded about the credentials"
                    )
                return transcript
            transcript.llm_turns += 1

            gate = validate_proposal(
                proposal,
                in_scope=self._in_scope,
                known_field_names=frozenset(known_values),
                credential_budget_remaining=(
                    None
                    if credential_budget_remaining is None
                    else credential_budget_remaining - posts_used
                ),
                reads_remaining=self._max_reads - reads_used,
                already_refused=frozenset(settled),
            )
            attempt = AuthAttempt(turn=turn, proposal=proposal, gate=gate)

            if not gate.allowed:
                transcript.proposals_refused += 1
                settled.add(proposal.signature())
                attempt.taught = f"refused before dispatch: {gate.reason}"
                transcript.attempts.append(attempt)
                history.append(
                    f"Turn {turn}: proposed {proposal.method} {proposal.url} — REFUSED by "
                    f"the deterministic gate ({gate.refusal.value if gate.refusal else '?'}): "
                    f"{gate.reason}"
                )
                self._logger.warning(
                    "Auth proposal REFUSED [%s] %s %s: %s",
                    gate.refusal.value if gate.refusal else "?",
                    proposal.method,
                    proposal.url,
                    gate.reason,
                )
                continue

            settled.add(proposal.signature())
            if proposal.kind is ProposalKind.READ:
                reads_used += 1
                response = await self._dispatcher.read(proposal.url, proposal.method.upper())
                transcript.reads_dispatched += 1
            else:
                posts_used += 1
                fields = {name: known_values.get(name, "") for name in proposal.carry_fields}
                fields[proposal.identity_field] = username
                fields[proposal.secret_field] = secret
                response = await self._dispatcher.post_credentials(
                    proposal.url,
                    content_type=proposal.content_type,
                    fields=fields,
                    account=account,
                )
                transcript.credential_posts_dispatched += 1
                # NAMES, never values. Two credential POSTs to one destination
                # are either a corrected retry or a wasted attempt, and the
                # transcript could not tell them apart: the reader saw two
                # identical lines and no way to know whether the second one
                # learned anything.
                attempt.sent_field_names = sorted(fields)

            attempt.dispatched = True
            attempt.status = response.status
            attempt.set_cookie_names = list(response.set_cookie_names)
            attempt.response_content_type = response.content_type
            attempt.location = response.location
            attempt.body_excerpt = (response.body or "")[:BODY_EXCERPT]
            attempt.taught = _teach(proposal, response)
            history.append(f"Turn {turn}: {proposal.method} {proposal.url} — {attempt.taught}")

            # A read teaches the engine field names it can supply values for.
            # The VALUE is stored here and never shown to the model; the model
            # may reference the NAME on a later turn, and the engine puts the
            # stored value in.
            if proposal.kind is ProposalKind.READ:
                known_values.update(response.json_values())

            if response.refused_by_rails:
                transcript.attempts.append(attempt)
                transcript.outcome = AuthAgentOutcome.ABSTAINED
                transcript.outcome_reason = (
                    f"the safety rails refused the dispatch at {proposal.url} "
                    f"[{response.refused_by_rails}]: {response.error}. Nothing evaluated "
                    "the credential, so nothing here is a statement about it"
                )
                return transcript

            if (
                proposal.kind is ProposalKind.CREDENTIAL_POST
                and response.credential_session_material
            ):
                attempt.assertion_ran = True
                assertion = await self._assert_session(dict(response.cookies), {})
                attempt.established = assertion.established
                attempt.assertion_discriminator = assertion.discriminator
                transcript.attempts.append(attempt)
                if assertion.established:
                    transcript.outcome = AuthAgentOutcome.AUTHENTICATED
                    transcript.outcome_reason = (
                        f"the credential POST proposed for turn {turn} at {proposal.url} "
                        f"produced session material, and assert_authenticated PROVED it "
                        f"via {assertion.discriminator} at {assertion.url} "
                        f"(authenticated {assertion.authenticated_status}, anonymous "
                        f"control {assertion.anonymous_status})"
                    )
                    self._session_cookies = dict(response.cookies)
                    self._assertion = assertion
                    return transcript
                history.append(
                    f"Turn {turn}: that response's session material did NOT survive the "
                    f"authenticated-state assertion — {assertion.why_unproven}"
                )
                continue

            transcript.attempts.append(attempt)

        transcript.outcome = AuthAgentOutcome.ABSTAINED
        transcript.outcome_reason = _abstention_reason(transcript)
        return transcript

    @property
    def session_cookies(self) -> dict[str, str]:
        """The session the loop proved, or ``{}``."""
        return dict(self._session_cookies)

    @property
    def assertion(self) -> AuthAssertion | None:
        """The assertion that proved it, or ``None``."""
        return self._assertion

    async def _propose_destinations(
        self, observation: AuthObservation, history: list[str], turn: int
    ) -> AuthProposal | None:
        """Ask the model for the next proposal. Returns ``None`` on any failure.

        The prompt carries the briefing and the history and nothing else. It
        does not carry the credential, and it does not carry a list of routes to
        pick from — a prompt naming the answer is the same defect as a
        benchmark-tuned list, and this module's whole claim is that the model
        supplies framework knowledge the engine does not have.
        """
        prompt = _build_prompt(self._system_prompt, observation, history, turn)
        try:
            with llm_call_purpose(LLMCallPurpose.PLANNING, site="auth_agent._propose_destinations"):
                answer = await self._llm.generate_text(prompt)
        except Exception as exc:  # noqa: BLE001 — an abstention, never an abort
            self._logger.warning("Auth proposal round %d failed: %s", turn, exc)
            return None
        return parse_proposal(answer)


def _build_prompt(
    system_prompt: str, observation: AuthObservation, history: list[str], turn: int
) -> str:
    """Assemble the proposal prompt. Pure, so the corpus driver can replay it."""
    parts = [
        system_prompt,
        "",
        "## What this engagement has already observed",
        "",
        observation.as_briefing(),
    ]
    if observation.form_field_names:
        parts += [
            "",
            "## Field names you may reference in carry_fields",
            "",
            "The engine holds a value for each of these and will supply it. Naming "
            "anything else is refused, because the engine would have to invent the value.",
            "",
            ", ".join(sorted(observation.form_field_names)),
        ]
    if history:
        parts += ["", "## What has happened so far this episode", "", *history]
    parts += [
        "",
        f"## Proposal {turn}",
        "",
        "Answer with a single JSON object and nothing else.",
    ]
    return "\n".join(parts)


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def parse_proposal(answer: str) -> AuthProposal | None:
    """Read one proposal out of a model's answer, or ``None``.

    Tolerant of a fenced block or surrounding prose, because that is what models
    emit and refusing on formatting would turn a capability question into a
    parsing one. Intolerant of anything else: a body the model authored, a
    method it invented, a field it made up — those are not parsed leniently,
    they are handed to the gate, which refuses them by name.

    Returns:
        The proposal, or ``None`` when the answer holds no JSON object.
    """
    if not answer:
        return None
    match = _JSON_OBJECT.search(answer)
    if match is None:
        return None
    try:
        data = json.loads(match.group(0))
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    try:
        return AuthProposal.model_validate(data)
    except Exception:  # noqa: BLE001 — a malformed proposal is an abstention
        return None


def _teach(proposal: AuthProposal, response: DispatchResponse) -> str:
    """What this response taught, as a sentence composed from the response.

    Deterministic and engine-authored. The model never writes into the
    transcript's factual half — it writes a rationale, which is recorded as its
    rationale, and nothing else.
    """
    if response.refused_by_rails:
        return (
            f"the safety rails refused the dispatch [{response.refused_by_rails}]: {response.error}"
        )
    if not response.status:
        return f"the request did not complete ({response.error or 'no response'})"

    parts = [f"HTTP {response.status}"]
    if response.content_type:
        parts.append(f"content-type {response.content_type}")
    if response.location:
        parts.append(f"redirecting to {response.location}")
    if response.set_cookie_names:
        parts.append("set cookie(s) " + ", ".join(sorted(response.set_cookie_names)))
    else:
        parts.append("set no cookie")
    if proposal.kind is ProposalKind.READ:
        keys = response.json_keys()
        if keys:
            parts.append("JSON body carrying key(s) " + ", ".join(keys))
        else:
            parts.append(f"{len(response.body)} byte(s) of non-JSON body")
    elif not response.credential_session_material:
        parts.append(
            "this response set no cookie and returned no token, so the credential "
            "produced nothing for the assertion to run against"
        )
    return "; ".join(parts)


def _abstention_reason(transcript: AuthTranscript) -> str:
    """Why the loop ended without a session, naming what was ABSENT.

    Never "the credentials are wrong". Nothing in this loop can establish that,
    and a run whose credential POSTs were all answered by routes that do not
    evaluate credentials has observed nothing about them at all.
    """
    dispatched = [a for a in transcript.attempts if a.dispatched]
    asserted = [a for a in transcript.attempts if a.assertion_ran]
    if not dispatched:
        return (
            f"every one of the {len(transcript.attempts)} proposal(s) was refused by the "
            "deterministic gate before dispatch, so no request carrying a credential ever "
            "left this engine"
        )
    if not transcript.credential_posts_dispatched:
        return (
            f"{transcript.reads_dispatched} safe read(s) were dispatched and no credential "
            "POST was ever proposed within the gate's bounds, so no credential was offered "
            "to this application by the adaptive layer"
        )
    if not asserted:
        answered = [
            a
            for a in dispatched
            if a.proposal.kind is ProposalKind.CREDENTIAL_POST and a.status and a.status != 404
        ]
        if answered:
            last = answered[-1]
            # An OBSERVATION about two responses, never a claim about the
            # credential. The deterministic pass's POST came back the same size
            # as the page served without one; the destination proposed here came
            # back differently. That difference is the whole finding, and it is
            # sayable because the engine watched both — unlike "the credentials
            # are wrong", which nothing here is in a position to say.
            return (
                f"{transcript.credential_posts_dispatched} credential POST(s) were "
                f"dispatched and none produced session material. The proposed "
                f"destination {last.proposal.url} did ANSWER, though — {last.taught}. "
                f"That is a different response from the one the deterministic login "
                f"route gave, so a destination that acts on the credential WAS reached "
                f"even though no session came back. What that answer means about the "
                f"credential is the application's to say and not this engine's"
            )
        return (
            f"{transcript.credential_posts_dispatched} credential POST(s) were dispatched "
            "and none produced session material or a distinguishable answer, so the "
            "authenticated-state assertion had nothing to run against. Nothing evaluated "
            "the credential to a session; this is not a statement about the credential"
        )
    # The count names the population the sentence is about — the POSTs that
    # actually produced session material — not the total dispatched. Those are
    # different numbers whenever any POST set nothing, which is most runs, and a
    # live transcript read "3 credential POSTs produced session material" above
    # three lines two of which said "set no cookie".
    return (
        f"{len(asserted)} of {transcript.credential_posts_dispatched} credential POST(s) "
        "produced session material and the authenticated-state assertion could not prove "
        "any of it against an anonymous control. Either the material is not a session, or "
        "no URL compared is protected — declare assert_url on the role to settle it"
    )


__all__ = [
    "BODY_EXCERPT",
    "PROMPT_PATH",
    "CARRYABLE_KEY_ALLOWLIST",
    "ENCODABLE_CONTENT_TYPES",
    "MAX_READS",
    "MAX_TURNS",
    "READ_METHODS",
    "AuthAgentLoop",
    "AuthAgentOutcome",
    "AuthAttempt",
    "AuthObservation",
    "AuthProposal",
    "AuthTranscript",
    "CredentialDispatcher",
    "DispatchResponse",
    "GateVerdict",
    "ProposalKind",
    "ProposalRefusal",
    "SessionAsserter",
    "load_system_prompt",
    "observation_from_auth_result",
    "parse_proposal",
    "validate_proposal",
]
