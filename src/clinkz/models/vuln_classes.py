"""Canonical registry of vulnerability classes — the client-facing view.

The Exploit Agent's own tables (``_CLASS_PATH_TOKENS``, ``_CLASS_PARAM_NAMES``,
``_CLASS_PRECONDITIONS``) are how a class gets *ranked and dispatched*. This
registry is how a class gets *talked about*: the human label a report prints, the
permitted-technique name a client authorizes, and — the part that matters most —
an honest statement of what this engine can and cannot prove about it.

Two things a professional deliverable must not do: silently omit a class the
client assumes was tested, and imply a class was cleared when the engine has no
oracle for it. Both are prevented by making the limitation a **field**, so the
report's "what was NOT tested" section is generated from the same registry the
planner is checked against rather than written by hand and left to rot.

:mod:`tests.test_models.test_vuln_classes` asserts this registry stays in sync
with the Exploit Agent's dispatch table, so a class added there without a client
label fails the build rather than disappearing from reports.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, model_validator


class ConfirmationCapability(StrEnum):
    """What this engine can prove about a class.

    Attributes:
        SERVER_SIDE: The defining effect is observable in a server response, so
            a finding here is confirmable in-band.
        OUT_OF_BAND: Confirmable only via the P6 out-of-band collaborator; with
            no collaborator provisioned the class defers rather than confirms.
        CLIENT_SIDE_ORACLE_REQUIRED: The defining effect happens in a browser
            (script execution, policy enforcement). Without a client-side oracle
            this engine can report reachability but must never claim the effect.
        NOT_IMPLEMENTED: No methodology exists. Reported as untested, never as
            clean.
    """

    SERVER_SIDE = "server_side"
    OUT_OF_BAND = "out_of_band"
    CLIENT_SIDE_ORACLE_REQUIRED = "client_side_oracle_required"
    NOT_IMPLEMENTED = "not_implemented"


class ControlArm(BaseModel):
    """What this class's oracle already does to rule out confirming on noise.

    The never-sent control is declared at CLASS granularity
    (:data:`~clinkz.agents._control_arm.MARKER_ORACLE_CLASSES`), because that is
    the granularity at which "this oracle matches a string in a body" is true.
    One class breaks that: :meth:`~clinkz.agents.exploit.ExploitAgent._test_sqli`
    confirms on five different channels, four of which are marker matches and one
    of which — ``auth_bypass`` — is a three-arm differential that DISPATCHES its
    own control and requires it to refuse.

    A consumer cannot infer that from the class name, and it must not infer it
    from the indicator name either: ``_test_nosqli`` has an ``auth_bypass``
    channel too, and that one compares the probe against a benign baseline with
    no shape-matched contradiction — the same word, a different oracle. So the
    producer declares which of ITS OWN channels carry their own dispatched arm,
    and the consumers read the declaration.

    A class the never-sent rule does not bind is not a class with no control. It
    is a class whose control is a DIFFERENT rule, and the report has to name that
    rule: 19 of 29 control-arm rows across the two generated PDFs said only which
    rule does NOT govern them, under a header promising "the row says which rule
    applies instead". Nineteen verbatim repetitions of an absence invite a client
    to read the strongest evidence in the document — a browser-witnessed nonce, a
    rejected broken signature — as unverified. So the producer declares the rule
    that DOES govern, beside the exemption from the one that does not.

    Attributes:
        self_controlled_indicators: ``indicator_type`` values this class confirms
            on whose oracle dispatches its own control arm and refuses on it.
            Empty means the class-level rule applies unchanged — the safe
            direction, so a class that forgets to declare loses nothing.
        reason: Why those channels need no separate never-sent arm. Required
            whenever ``self_controlled_indicators`` is non-empty, and rendered
            into the re-grade output so the exemption is auditable rather than
            asserted.
        governing_rule: What this class's oracle DOES require before it may
            confirm, in one clause a client can read. Required for every class
            the never-sent-control rule does not bind — see
            :func:`~clinkz.agents._control_arm.control_required` — and rendered
            as the basis of that class's control-arm row.
        evidence_key: The ``key=value`` field in the finding's own structured
            evidence that carries the observation ``governing_rule`` names, so
            the row shows what was MEASURED and not only what was promised. Read
            through ``structured_evidence_field``, so a response body cannot
            supply it. Optional: a class whose rule is a pure function of an
            observation it did not have to inject has no such key.
    """

    self_controlled_indicators: tuple[str, ...] = ()
    reason: str = ""
    governing_rule: str = ""
    evidence_key: str = ""

    @model_validator(mode="after")
    def _reason_required(self) -> ControlArm:
        """An exemption with no stated reason is an exemption nobody reviewed."""
        if self.self_controlled_indicators and not self.reason.strip():
            raise ValueError(
                "ControlArm.self_controlled_indicators requires a reason — a channel "
                "excused from the never-sent control states why it needs no separate arm"
            )
        if self.evidence_key and not self.governing_rule.strip():
            raise ValueError(
                "ControlArm.evidence_key without a governing_rule names an observation "
                "and no rule to read it under"
            )
        return self


class MultiPrincipalRequirement(BaseModel):
    """How many authenticated principals this class needs before it may CONFIRM.

    The access-control classes have a limitation no other family has: their
    defining effect is about WHOSE object was returned, and "whose" is not a
    property of a response. It is a relation between a response and an identity,
    and establishing it takes a second identity — one whose own authorized read
    of the same object says "this record is mine".

    That limitation was already written down. ``_test_idor``'s ``limitation``
    field has said "Requires at least two authenticated roles to prove that an
    authorization boundary was crossed. With a single role (or none) the class
    can only report candidates" since the registry was written, and it was
    rendered verbatim into every report — while the oracle confirmed at
    ``high``/CONFIRMED on a single role for 49 recorded findings. A limitation
    that only the report knows about is a disclaimer, not a rule.

    So the requirement is a FIELD, in numbers the emission chokepoint can compare
    against the run's own principal list, with the lead reason a shortfall
    produces declared beside it. The prose stays: it is what the client reads.
    This is what the code reads.

    Attributes:
        principals_required: Authenticated principals needed to CONFIRM. ``1``
            (the default) means the ordinary rule — the engagement's own session
            is enough — and every class except the access-control family is that.
        why_unconfirmed: The :data:`~clinkz.models.finding.UNPROVEN_WHY_UNCONFIRMED`
            member a shortfall demotes to. Required whenever more than one
            principal is needed, because "it became a lead" is only actionable if
            the lead says which observation was missing.
        reason: Why one principal cannot prove this class's effect. Rendered
            beside the lead so the operator can judge whether supplying a second
            credential is worth another engagement.
    """

    principals_required: int = 1
    why_unconfirmed: str = ""
    reason: str = ""

    @model_validator(mode="after")
    def _requirement_is_complete(self) -> MultiPrincipalRequirement:
        """A requirement with no lead reason cannot be enforced, only asserted."""
        if self.principals_required < 1:
            raise ValueError("MultiPrincipalRequirement.principals_required must be at least 1")
        if self.principals_required == 1:
            return self
        if not self.why_unconfirmed.strip() or not self.reason.strip():
            raise ValueError(
                "a class needing more than one authenticated principal must declare BOTH "
                "why_unconfirmed (the lead reason a shortfall produces) and reason (why one "
                "principal cannot prove it) — otherwise the shortfall demotes to a lead "
                "nobody can act on"
            )
        from clinkz.models.finding import UNPROVEN_WHY_UNCONFIRMED

        if self.why_unconfirmed not in UNPROVEN_WHY_UNCONFIRMED:
            raise ValueError(
                f"MultiPrincipalRequirement.why_unconfirmed={self.why_unconfirmed!r} is not in "
                "UNPROVEN_WHY_UNCONFIRMED — an unregistered reason is normalised to "
                "'not_instrumentable', which is not what happened"
            )
        return self


class CoverageBoundary(BaseModel):
    """A shape this class can never confirm, and why it abstains rather than infers.

    Distinct from :class:`MultiPrincipalRequirement`, which is about what the
    ENGAGEMENT lacked: this is about what the class refuses to claim even with
    everything it needs. The IDOR oracle is the first: it reads attribution off
    an OWNING FIELD in the crossing response — a field the application itself
    uses to name a record's owner — and a per-user record that names no owner
    cannot be attributed to anybody, so the class abstains.

    That is a real coverage boundary. An endpoint serving per-user records with
    no owner field is a shape this engine will not confirm on, and it produces
    exactly the artifact a clean endpoint produces: nothing. It was pinned as a
    test named after the loss and stated nowhere a client reads, which makes it
    the same kind of silence every other honesty rule here exists to break — the
    absence of a finding standing in for the absence of a flaw.

    The boundary renders on a clean run too, like every other bound that decided
    coverage: it is a property of the class, not of what this target happened to
    have.

    Attributes:
        why_unconfirmed: The
            :data:`~clinkz.models.finding.UNPROVEN_WHY_UNCONFIRMED` member the
            abstain records. Required — it is what ties the client-facing
            sentence to a reason the engine actually produces, so the prose
            cannot drift into describing an abstain that never happens.
        limitation: The boundary as a sentence a client can act on. Rendered
            verbatim in *What was NOT tested*.
    """

    why_unconfirmed: str = ""
    limitation: str = ""

    @model_validator(mode="after")
    def _boundary_is_complete(self) -> CoverageBoundary:
        """Half a boundary is worse than none: a sentence with no registered
        reason is a disclaimer, and a reason with no sentence discloses nothing.
        """
        if bool(self.why_unconfirmed) != bool(self.limitation):
            raise ValueError(
                "CoverageBoundary needs BOTH a registered why_unconfirmed and the "
                "sentence a client reads, or neither"
            )
        return self

    @property
    def declared(self) -> bool:
        """Whether this class declares a boundary at all."""
        return bool(self.why_unconfirmed)


class VulnClass(BaseModel):
    """One vulnerability class as a client sees it.

    Attributes:
        key: Technique name a client authorizes (``sql_injection``). This is what
            :meth:`~clinkz.models.engagement.AuthorizationRecord.permits` matches.
        test_method: The Exploit Agent method that implements it, or ``""``.
        label: Human name for the report.
        capability: What the engine can prove.
        control_arm: Which of this class's own confirming channels dispatch their
            own control arm, so a consumer never has to guess it from the class
            name or the indicator name. See :class:`ControlArm`.
        limitation: Why the class is limited, when it is. Rendered verbatim in
            the report's "what was NOT tested" section — so it has to read as a
            sentence, not a code comment.
        coverage_boundary: A shape this class refuses to confirm on even when
            the engagement gave it everything it needs, and the registered
            abstain reason that shape produces. See :class:`CoverageBoundary`.
        title_tokens: Lowercase substrings that identify this class in a
            finding's title. Used by :func:`for_finding` to attach remediation
            guidance to a finding the methodology emitted without any.
        remediation: Standards-aligned remediation guidance. A client-ready
            report has to say what to DO about a finding; the methodologies emit
            proof, not advice, so the advice is attached here — once per class,
            reviewable in one place, rather than inlined at twenty emit sites.
    """

    key: str
    test_method: str
    label: str
    capability: ConfirmationCapability
    control_arm: ControlArm = ControlArm()
    multi_principal: MultiPrincipalRequirement = MultiPrincipalRequirement()
    limitation: str = ""
    coverage_boundary: CoverageBoundary = CoverageBoundary()
    title_tokens: tuple[str, ...] = ()
    remediation: str = ""


_C = ConfirmationCapability

#: Every class the engine plans, keyed by the Exploit Agent's method name.
VULN_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        key="sql_injection",
        test_method="_test_sqli",
        label="SQL Injection",
        capability=_C.SERVER_SIDE,
        title_tokens=("sql injection",),
        control_arm=ControlArm(
            self_controlled_indicators=("auth_bypass",),
            reason=(
                "the authentication-bypass channel is a three-arm differential: the "
                "tautology must return an auth artifact, a shape-matched contradiction "
                "one character apart must NOT, and an ordinary credential attempt must "
                "not either. Both refusing arms are DISPATCHED, so the property the "
                "never-sent control establishes — the same oracle says no to a probe "
                "that exploits nothing — is established by the oracle itself. The other "
                "four channels are marker matches and are bound by the rule"
            ),
        ),
        remediation=(
            "Use parameterised queries / prepared statements for every database call; never build "
            "SQL by concatenating request data. Where a dynamic identifier is genuinely required, "
            "resolve it through a server-side allowlist. Run the application's database account "
            "with least privilege so a residual injection cannot reach beyond its own tables."
        ),
    ),
    VulnClass(
        key="nosql_injection",
        test_method="_test_nosqli",
        label="NoSQL Injection",
        capability=_C.SERVER_SIDE,
        title_tokens=("nosql injection",),
        remediation=(
            "Cast and type-check every operand before it reaches the query: reject an "
            "object-valued parameter where a scalar is expected, which is what turns a lookup "
            "into an operator injection. Disable server-side JavaScript evaluation and use the "
            "driver's typed query builders rather than raw documents assembled from request data."
        ),
    ),
    VulnClass(
        key="ssti",
        test_method="_test_ssti",
        label="Server-Side Template Injection",
        capability=_C.SERVER_SIDE,
        title_tokens=(
            "template injection",
            "ssti",
        ),
        remediation=(
            "Never render user-controlled text AS a template. Pass it to the template as DATA, so "
            "the engine escapes it, and keep the template set static and server-owned. If "
            "user-authored templates are a product requirement, use a logic-less or sandboxed "
            "engine and treat the sandbox as a hardening layer, not a boundary."
        ),
    ),
    VulnClass(
        key="xxe",
        test_method="_test_xxe",
        label="XML External Entity Injection",
        capability=_C.SERVER_SIDE,
        title_tokens=(
            "xxe",
            "xml external entity",
        ),
        remediation=(
            "Disable external entity resolution and DTD processing on every XML parser instance. "
            "Prefer a parser configuration that is secure by default, and apply it in a shared "
            "factory so a new call site cannot opt out by omission."
        ),
    ),
    VulnClass(
        key="jwt",
        test_method="_test_jwt",
        control_arm=ControlArm(
            governing_rule=(
                "a three-arm status differential: the valid baseline token was ACCEPTED "
                "and a broken-signature token of the same shape was REJECTED, so the "
                "forged token's acceptance is attributable to the forgery and not to an "
                "endpoint that accepts anything"
            ),
            evidence_key="indicator_observed",
        ),
        label="JWT / Token Forgery",
        capability=_C.SERVER_SIDE,
        title_tokens=(
            "jwt",
            "json web token",
        ),
        remediation=(
            "Pin the accepted signature algorithm server-side and reject any token whose header "
            "disagrees, including 'none'. Verify the signature BEFORE reading any claim. Validate "
            "issuer, audience, and expiry, and rotate the signing key; a symmetric key must never "
            "be a value that also appears in client-reachable code."
        ),
    ),
    VulnClass(
        key="ssrf",
        test_method="_test_ssrf",
        label="Server-Side Request Forgery",
        capability=_C.OUT_OF_BAND,
        limitation=(
            "A blind SSRF — one whose response body reveals nothing — is only "
            "confirmable through an out-of-band callback. Where no collaborator "
            "was provisioned for this engagement, blind candidates are reported "
            "as unproven leads rather than findings."
        ),
        title_tokens=(
            "ssrf",
            "server-side request forgery",
        ),
        remediation=(
            "Allowlist the destinations the server may fetch, resolve the hostname and "
            "re-validate the resulting ADDRESS against that allowlist immediately before "
            "connecting (which is what defeats DNS rebinding), and deny loopback, link-local, and "
            "cloud metadata ranges. Do not follow redirects on server-initiated fetches, and "
            "route them through an egress proxy that enforces the same policy."
        ),
    ),
    VulnClass(
        key="xss_reflected",
        test_method="_test_xss_reflected",
        label="Reflected Cross-Site Scripting",
        capability=_C.SERVER_SIDE,
        title_tokens=("reflected xss",),
        remediation=(
            "Encode output for the context it lands in — HTML body, attribute, JavaScript string, "
            "URL — at the sink, rather than sanitising on input. Deploy a strict "
            "Content-Security-Policy as defence in depth, and prefer a framework that "
            "auto-escapes by default so an unescaped sink is the exception a reviewer notices."
        ),
    ),
    VulnClass(
        key="xss_stored",
        test_method="_test_xss_stored",
        label="Stored Cross-Site Scripting",
        capability=_C.SERVER_SIDE,
        title_tokens=("stored xss",),
        remediation=(
            "Treat stored content as untrusted at RENDER time and encode it for its output "
            "context; storage-time sanitisation alone fails as soon as the same record is "
            "rendered somewhere new. Where rich text is required, sanitise with a maintained "
            "allowlist-based library and serve user content from a separate origin under a strict "
            "Content-Security-Policy."
        ),
    ),
    VulnClass(
        key="xss_dom",
        test_method="_test_xss_dom",
        control_arm=ControlArm(
            governing_rule=(
                "P7 witnessed the injected nonce returned by a CALL from inside the "
                "page's own JS context, while a second nonce minted in the same call "
                "and injected NOWHERE stayed silent. Inert reflected bytes cannot call "
                "a function, so the silent control is what separates execution from "
                "reflection"
            ),
            evidence_key="control_silent",
        ),
        label="DOM-based Cross-Site Scripting",
        capability=_C.CLIENT_SIDE_ORACLE_REQUIRED,
        limitation=(
            "DOM-based XSS executes in the browser, not in a response body. With "
            "the P7 client-side execution oracle enabled, a candidate is confirmed "
            "only when an injected single-use nonce is returned from inside the "
            "page's JavaScript context, with a never-injected control nonce "
            "staying silent. Where that oracle is not available, this engine can "
            "identify a sink reachable from a controllable source but cannot "
            "witness the script running, and candidates are reported as unproven "
            "leads requiring a manual browser check."
        ),
        title_tokens=(
            "dom xss",
            "dom-based",
        ),
        remediation=(
            "Stop passing data derived from location, document.referrer, or postMessage into "
            "innerHTML, outerHTML, document.write, or eval. Use textContent and other inert "
            "sinks, and enforce Trusted Types so an unsafe assignment fails at runtime rather "
            "than silently executing."
        ),
    ),
    VulnClass(
        key="command_injection",
        test_method="_test_cmdi",
        label="OS Command Injection",
        capability=_C.SERVER_SIDE,
        title_tokens=("command injection",),
        remediation=(
            "Do not pass request data to a shell. Invoke the target program with an argument "
            "vector so no shell metacharacter is ever interpreted, and where a value must select "
            "behaviour, map it through a server-side allowlist to a fixed argument rather than "
            "interpolating it."
        ),
    ),
    VulnClass(
        key="lfi",
        test_method="_test_lfi",
        label="Local File Inclusion / Path Traversal",
        capability=_C.SERVER_SIDE,
        title_tokens=(
            "local file inclusion",
            "file read",
            "path traversal",
            "poison-null-byte",
        ),
        remediation=(
            "Never build a filesystem path from request data. Look the resource up by an opaque "
            "identifier against a server-side map; if a path is unavoidable, resolve it to its "
            "canonical absolute form and verify it is still under the intended root AFTER "
            "resolution — checking before normalisation is exactly what traversal payloads "
            "defeat."
        ),
    ),
    VulnClass(
        key="file_upload",
        test_method="_test_file_upload",
        label="Unrestricted File Upload",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Only upload branches whose effect this engine can observe may "
            "confirm; branches whose effect requires a client-side or "
            "out-of-band observation are reported as unproven leads naming both "
            "the claimed effect and the observation that would prove it."
        ),
        title_tokens=(
            "file upload",
            "unrestricted upload",
        ),
        remediation=(
            "Store uploads outside the web root, under a server-generated name and extension, and "
            "serve them through a handler that sets a non-executing Content-Type and "
            "Content-Disposition. Validate type by inspecting the content rather than trusting "
            "the declared name or MIME, and ensure no interpreter is mapped to the storage "
            "location."
        ),
    ),
    VulnClass(
        key="csrf",
        test_method="_test_csrf",
        control_arm=ControlArm(
            governing_rule=(
                "the form's own token field and the SameSite attribute of the cookie "
                "the target set. Nothing is injected; the rule is that the "
                "state-changing form carried no unpredictable token and no SameSite "
                "mitigation stood in for one"
            ),
            evidence_key="rationale",
        ),
        label="Cross-Site Request Forgery",
        capability=_C.SERVER_SIDE,
        limitation=(
            "CSRF is confirmed by token-absence and origin-acceptance analysis. "
            "Where the only proving action would be an actual state change "
            "(a password change, a funds transfer), the production safety rails "
            "refuse to perform it and the class reports reachability only."
        ),
        title_tokens=("csrf",),
        remediation=(
            "Require a per-session anti-CSRF token, bound to the authenticated user and verified "
            "on every state-changing request. Set session cookies SameSite=Lax or Strict, and "
            "re-authenticate for high-value actions such as changing a password, an email "
            "address, or payment details."
        ),
    ),
    VulnClass(
        key="idor",
        test_method="_test_idor",
        label="Insecure Direct Object Reference / Broken Access Control",
        capability=_C.SERVER_SIDE,
        multi_principal=MultiPrincipalRequirement(
            principals_required=2,
            why_unconfirmed="single_role_cannot_attribute",
            reason=(
                "the defining effect is that the caller was served an object belonging to "
                "someone else, and 'belonging' is a relation between a response and an "
                "identity rather than anything visible in the response. One principal "
                "establishes three negatives — not the caller's own object, not a "
                "never-issued reference, not what an anonymous caller is served — and a "
                "shared record behind a login satisfies all three exactly as well as "
                "another principal's record does. Positive attribution needs a second "
                "principal's OWN authorized read of the same object"
            ),
        ),
        limitation=(
            "Requires at least two authenticated roles to prove that an "
            "authorization boundary was crossed. With a single role (or none) "
            "the class can only report candidates. It also requires those roles "
            "to be RANKED, via the optional 'privilege' field on each role in "
            "the credential file (lower is less privileged): the crossing is "
            "dispatched from the least privileged identity supplied, because a "
            "more privileged one being served a subordinate's record is in most "
            "applications the feature rather than the flaw. Where no ranking was "
            "declared the crossing is reported as a candidate rather than "
            "confirmed — the engine does not infer a hierarchy from a role's "
            "name."
        ),
        coverage_boundary=CoverageBoundary(
            why_unconfirmed="crossing_response_names_no_owning_principal",
            limitation=(
                "Records that name no owner cannot be attributed, and this class "
                "abstains rather than infers. An IDOR claim rests on the OBJECT "
                "saying whom it belongs to — a field the application itself uses "
                "to name a record's owner ('UserId', 'email', 'author') carrying a "
                "value that is not the caller's. Where an endpoint serves per-user "
                "records that name no owner, this engine reports a lead rather "
                "than a finding, even when the crossing succeeded and every "
                "control arm refused: 'differs from mine, from a never-issued "
                "reference, and from what an anonymous caller is served' is three "
                "negatives, and a shared record behind a login satisfies all three "
                "exactly as well as another user's record does. That is a real "
                "coverage boundary, not a formality — an access-control flaw on "
                "such an endpoint produces the same artifact a sound one does, "
                "which is nothing. Confirming it needs either an owning field in "
                "the response or an oracle this engine does not have."
            ),
        ),
        # No ``control_arm`` exemption. The four-arm oracle DISPATCHES a
        # never-sent control (``ref(∅)``) through the shared ``_run_control_arm``
        # seam and records its verdict in the evidence, so the class is bound by
        # the rule rather than excused from it — see
        # :data:`~clinkz.agents._control_arm.DIFFERENTIAL_CONTROL_CLASSES`.
        title_tokens=(
            "idor",
            "insecure direct object",
        ),
        remediation=(
            "Authorise every object access against the CALLER's identity, server-side, on each "
            "request — not once at navigation time and not in the client. Unguessable identifiers "
            "are useful defence in depth but must never be the control itself, because an "
            "identifier that leaks anywhere then becomes an access grant."
        ),
    ),
    VulnClass(
        key="brute_force",
        test_method="_test_brute_force",
        control_arm=ControlArm(
            governing_rule=(
                "a POSITIVE control: every attempt is proven to have REACHED the "
                "authentication handler and been answered with an auth failure, so 'no "
                "lockout' is a measurement rather than a failure to arrive"
            ),
            evidence_key="positive_control",
        ),
        label="Weak Authentication / Credential Brute Force",
        capability=_C.SERVER_SIDE,
        title_tokens=(
            "brute-force",
            "brute force",
        ),
        remediation=(
            "Rate-limit authentication per account AND per source, with progressive delay and "
            "lockout, and monitor for credential-stuffing patterns across accounts. Offer "
            "multi-factor authentication, and return a generic failure message so the response "
            "cannot be used to enumerate valid usernames."
        ),
    ),
    VulnClass(
        key="open_redirect",
        test_method="_test_open_redirect",
        control_arm=ControlArm(
            governing_rule=(
                "the browser-resolved host of the 3xx Location header the target "
                "returned - an origin comparison, not a substring in a body, so there "
                "is no marker for a decoy to collide with"
            ),
            evidence_key="redirect_target_observed",
        ),
        label="Open Redirect",
        capability=_C.SERVER_SIDE,
        title_tokens=("open redirect",),
        remediation=(
            "Do not take a redirect destination from the request. Where a return-to flow is "
            "required, pass an opaque key that maps to a server-side allowlist of paths, and "
            "reject absolute URLs, protocol-relative URLs, and anything resolving to a host you "
            "do not control."
        ),
    ),
    VulnClass(
        key="security_headers",
        test_method="_test_security_headers",
        control_arm=ControlArm(
            governing_rule=(
                "a pure function of the header set captured in phase 2. Nothing is "
                "injected, so the observation and its control are the same bytes: the "
                "rule is that the named header was absent from, or weak in, a response "
                "the target served unprompted"
            ),
            evidence_key="rationale",
        ),
        label="Security Header & Transport Hygiene",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Header presence and policy content are assessed from the response "
            "itself. Whether a Content-Security-Policy is actually BYPASSABLE is a "
            "question about how a browser resolves it, and is answered only when "
            "the P7 client-side execution oracle is enabled — and then only for "
            "the bypass shapes this engine can synthesize (a policy permitting "
            "inline script, a reused/static nonce, or a same-origin endpoint that "
            "reflects a parameter into its own JavaScript response). A policy for "
            "which no shape applies is reported as not bypassed BY THOSE SHAPES, "
            "which is a limit of this engine's coverage rather than a finding that "
            "the policy is sound."
        ),
        title_tokens=("security header",),
        remediation=(
            "Set Strict-Transport-Security with a long max-age, a Content-Security-Policy naming "
            "explicit sources, X-Content-Type-Options: nosniff, a restrictive Referrer-Policy, "
            "and frame-ancestors to control framing. Apply them at a shared edge or middleware so "
            "a new route cannot ship without them."
        ),
    ),
    VulnClass(
        key="weak_session",
        test_method="_test_weak_session",
        control_arm=ControlArm(
            governing_rule=(
                "the sequence of identifiers the TARGET itself issued across repeated "
                "authentications, graded on entropy and structure. Nothing is injected "
                "- the values under test are the server's own"
            ),
            evidence_key="rationale",
        ),
        label="Weak Session Management",
        capability=_C.SERVER_SIDE,
        title_tokens=(
            "weak session",
            "predictable",
        ),
        remediation=(
            "Generate session identifiers from a cryptographically secure RNG with at least 128 "
            "bits of entropy, regenerate the identifier on login and on any privilege change, and "
            "set Secure, HttpOnly, and SameSite on the cookie. Enforce both an idle and an "
            "absolute session lifetime server-side."
        ),
    ),
    VulnClass(
        key="javascript_attacks",
        test_method="_test_javascript_attacks",
        control_arm=ControlArm(
            governing_rule=(
                "the server answered a value forged by replaying the page's own chain "
                "differently from an equal-shaped control value it never issued, with "
                "both arms interleaved and repeated and both shown stable"
            ),
            evidence_key="forge_confirmed",
        ),
        label="Client-Side Logic Flaws",
        capability=_C.CLIENT_SIDE_ORACLE_REQUIRED,
        limitation=(
            "Confirmation requires the server to accept a value rebuilt from the "
            "page's own client-side chain while rejecting an equal-shaped "
            "control. Where that server-side acceptance cannot be observed, the "
            "class reports the client-side control's existence as reachability, "
            "never as an exploited effect."
        ),
        title_tokens=(
            "client-side",
            "javascript",
        ),
        remediation=(
            "Every control implemented in client-side code must be enforced again on the server. "
            "Treat browser-side validation, token generation, and flow sequencing as user "
            "experience, never as a security boundary — the client is an input the attacker "
            "writes."
        ),
    ),
    VulnClass(
        key="csp_bypass",
        test_method="_test_csp",
        control_arm=ControlArm(
            governing_rule=(
                "P7 under the SERVED policy, with CSP bypass asserted off and recorded: "
                "the injected nonce came back by a call from inside the page, and the "
                "never-injected control nonce did not"
            ),
            evidence_key="control_nonce_silent",
        ),
        label="Content-Security-Policy Bypass",
        capability=_C.CLIENT_SIDE_ORACLE_REQUIRED,
        limitation=(
            "Whether a policy is BYPASSABLE is a question about how a browser "
            "resolves it, so it is answered only with the P7 client-side "
            "execution oracle enabled — and then only for the bypass shapes "
            "this engine can synthesize: a policy permitting inline script, a "
            "reused or static nonce, and a same-origin endpoint that reflects a "
            "parameter into its own JavaScript response. A policy for which no "
            "shape applies is reported as NOT BYPASSED BY THOSE SHAPES, which is "
            "a limit of this engine's coverage and never a statement that the "
            "policy is sound. Where the oracle is unavailable the class reports "
            "the served policy and makes no claim about it."
        ),
        title_tokens=(
            "content-security-policy bypass",
            "csp bypass",
        ),
        remediation=(
            "Remove 'unsafe-inline' and 'unsafe-eval' from script-src. Use a per-response nonce "
            "generated from a CSRF-safe random source — a nonce reused across responses is a "
            "published constant, not a secret — and prefer 'strict-dynamic' with that nonce so "
            "host allowlists cannot be turned into gadgets. Audit every same-origin endpoint that "
            "reflects request data into a JavaScript response: under script-src 'self' such an "
            "endpoint is a fully-permitted script the attacker writes."
        ),
    ),
    VulnClass(
        key="weak_cryptography",
        test_method="_test_crypto",
        control_arm=ControlArm(
            governing_rule=(
                "the forgery is graded against a random token of the SAME SHAPE the "
                "scheme never issued; a server that honours that one too was not "
                "broken, and the class says so rather than confirming"
            ),
        ),
        label="Weak Cryptography / Forgeable Token",
        capability=_C.SERVER_SIDE,
        limitation=(
            "This class reports only what it DEMONSTRATED: plaintext recovered "
            "from a token and anchored on a value the engagement holds, or a "
            "token rebuilt under the application's own scheme and accepted while "
            "a same-shaped random token was refused. It does not attempt "
            "cryptanalysis, does not report an algorithm as weak on the strength "
            "of its name or a token's length, and a token it could not recover "
            "is reported as not recovered rather than as strong."
        ),
        title_tokens=(
            "weak cryptography",
            "forgeable token",
            "recoverable plaintext",
        ),
        remediation=(
            "Do not encode identity or authorisation into a token the client can decode or "
            "rebuild. Use an opaque identifier bound server-side to session state, or a signed "
            "token whose signature is verified before any claim is read. Where a value must be "
            "carried to the client, authenticate it with a MAC over the whole payload and reject "
            "any token whose MAC does not verify; encoding is not encryption and encryption "
            "without authentication is not integrity."
        ),
    ),
    VulnClass(
        key="input_validation",
        test_method="_test_input_validation",
        control_arm=ControlArm(
            governing_rule=(
                "probe and control bodies are compared on the READ-BACK, never on the "
                "status code - an API that answers 200 and stores the "
                "constraint-satisfying value enforced the constraint"
            ),
            evidence_key="control_status",
        ),
        label="Client-Only Input Validation",
        capability=_C.SERVER_SIDE,
        limitation=(
            "A finding here requires BOTH halves: the server accepted a value "
            "the application itself declares invalid, AND a control proved the "
            "same endpoint rejects a malformed request. Where the control is "
            "also accepted the endpoint demonstrates no validation at all, so "
            "its acceptance says nothing about the specific constraint, and the "
            "result is reported as an unproven lead."
        ),
        title_tokens=(
            "input validation",
            "client-only validation",
            "unenforced constraint",
        ),
        remediation=(
            "Re-validate every declared constraint on the server, from the same schema the client "
            "renders, so the two cannot drift. Treat the client's rules as user experience and the "
            "server's as the boundary. Reject on the server with the same specificity the client "
            "shows, and enforce the constraint at the persistence layer too, so a second entry "
            "point cannot bypass the first."
        ),
    ),
    VulnClass(
        key="secrets_exposure",
        test_method="_test_secrets_exposure",
        control_arm=ControlArm(
            governing_rule=(
                "an anonymous arm IS the control: fetched with NO session material, "
                "minus everything the site root also serves, minus anything whose "
                "fingerprint matches material this engagement supplied"
            ),
            evidence_key="context",
        ),
        label="Secret & Configuration Exposure",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Confirmed only when the material was served to a request carrying "
            "NO session at all. Credential shapes matching material this "
            "engagement itself supplied are discarded as the target echoing us "
            "back. Detection uses the definite credential-shape vocabulary (a "
            "JWT gated on a decoding header, a PEM block, vendor-prefixed keys); "
            "the entropy heuristic is deliberately not applied, so a "
            "high-entropy secret in a shape this engine does not recognise is "
            "not reported."
        ),
        title_tokens=(
            "secret exposure",
            "credential exposure",
            "configuration exposure",
            "unauthenticated operational endpoint",
        ),
        remediation=(
            "Never ship credential material to the client: a secret in a bundle is public the "
            "moment it is served, and rotating it is the only remediation once it has been. Move "
            "the call that needs it behind a server-side endpoint. Put operational surfaces "
            "(metrics, health with detail, actuator, debug, admin APIs) behind authentication and "
            "network policy, and confirm the control by requesting them with no session at all."
        ),
    ),
    VulnClass(
        key="mass_assignment",
        test_method="_test_mass_assignment",
        control_arm=ControlArm(
            governing_rule=(
                "the privileged field is graded on the READ-BACK of the created object "
                "against a control body that omitted it, so a field echoed but not "
                "honoured cannot confirm"
            ),
            evidence_key="honoured",
        ),
        label="Mass Assignment / Privilege Escalation on Create",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Distinct from the access-control class, which tests whether an "
            "object may be READ. Confirmation requires the created object to be "
            "read back carrying the value we set, AND a control object created "
            "by an otherwise identical request that omitted the field to come "
            "back without it. A status code alone never confirms: most "
            "frameworks return 201 and discard the extra field silently. Fields "
            "are proposed only from the server's own representation of the "
            "object, never guessed, so a write whose outcome could not be "
            "observed is never sent."
        ),
        title_tokens=(
            "mass assignment",
            "privilege escalation on create",
        ),
        remediation=(
            "Bind requests to an explicit allowlist of writable fields — a per-action DTO or "
            "strong-parameters filter — rather than binding the request body onto the model. "
            "Authorisation, ownership, pricing and workflow state must be set server-side from the "
            "caller's identity and the application's own rules, never accepted from the request, "
            "and the same filter must apply to update as to create."
        ),
    ),
    VulnClass(
        key="state_sequence_bypass",
        test_method="_test_state_sequence",
        control_arm=ControlArm(
            governing_rule=(
                "business logic: the out-of-order step is graded on a read-back of the "
                "object it should not have reached, against a control object driven "
                "through the intended sequence"
            ),
        ),
        label="Business Logic: Workflow Sequence Bypass",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Confirmed only when the application's OWN surface evidences the "
            "ordering: a workflow field carrying both stages in the server's "
            "representation, or the application's own words refusing an "
            "out-of-order request) AND the resource is read back in the "
            "terminal state after a request that skipped the prerequisite. An "
            "acceptance status alone never confirms: many APIs answer 200 and "
            "perform no transition. Where the ordering cannot be evidenced from "
            "the application's own surface the result is an unproven lead, "
            "because an ordering this engine merely assumes is an opinion about "
            "how the business should work."
        ),
        title_tokens=(
            "workflow sequence bypass",
            "state sequence",
            "out of sequence",
        ),
        remediation=(
            "Enforce the workflow server-side as a state machine: each transition validates the "
            "object's CURRENT persisted state before it is applied, and an illegal transition is "
            "rejected rather than accepted-and-ignored. Do not infer the current step from the "
            "request, the client's flow, or a hidden field, and apply the same check at every "
            "entry point that can advance the object, including internal and administrative ones."
        ),
    ),
    VulnClass(
        key="constraint_violation",
        test_method="_test_constraint_violation",
        control_arm=ControlArm(
            governing_rule=(
                "business logic: the out-of-range value is graded on the READ-BACK "
                "against a boundary control, because an API that accepts quantity=-1 "
                "and stores 1 enforced the constraint"
            ),
        ),
        label="Business Logic: Numeric Constraint Violation",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Distinct from the client-only input-validation class, which tests a "
            "constraint the page DECLARES in an HTML attribute. This one tests a "
            "constraint the application's own DATA evidences: a quantity field "
            "whose observed records never fall below a bound. Confirmed only "
            "when the violating value is accepted AND read back on the persisted "
            "record, while the endpoint accepts the valid boundary value and "
            "refuses a malformed control. An API that accepts a negative "
            "quantity and clamps it has behaved correctly, and only the "
            "read-back can tell the two apart."
        ),
        title_tokens=(
            "constraint violation",
            "numeric constraint",
            "quantity constraint",
        ),
        remediation=(
            "Validate business ranges server-side at the point of persistence, not only at the "
            "edge: a quantity, price, or balance has a domain the application owns, and it must be "
            "checked against that domain wherever it can be written. Prefer a type that cannot "
            "hold an invalid value (an unsigned or bounded type, a database CHECK constraint) so a "
            "new code path cannot bypass the check by omission, and reject rather than silently "
            "clamping, so the caller learns the value was wrong."
        ),
    ),
    VulnClass(
        key="repeatability",
        test_method="_test_repeatability",
        control_arm=ControlArm(
            governing_rule=(
                "business logic: two identical creates are read back and compared, "
                "because an idempotent handler answers 200 to a replay and has created "
                "nothing"
            ),
            evidence_key="satisfied",
        ),
        label="Business Logic: Single-Use Action Replayed",
        capability=_C.SERVER_SIDE,
        limitation=(
            "Confirmed only when the application's own surface declares the "
            "action single-use (a consumption marker on its own object, or its "
            "own words refusing a repeat) AND the second application's EFFECT "
            "is observed to accumulate. An idempotent handler answers 200 to a "
            "replay and changes nothing, which is correct behaviour, so a status "
            "code cannot distinguish the two and this class does not try."
        ),
        title_tokens=(
            "single-use action replayed",
            "repeatability",
            "replayed action",
        ),
        remediation=(
            "Make single-use actions consume a server-side token or mark the record consumed "
            "inside the same transaction that applies the effect, so a concurrent or repeated "
            "request cannot apply it twice. Enforce it at the database with a uniqueness "
            "constraint rather than with an application-level check-then-act, which is a race "
            "under load even when it reads correctly."
        ),
    ),
)

#: Classes proven by the gray-box discovery engine rather than by a black-box
#: ``_test_*`` dispatch entry. They emit findings, so a report has to be able to
#: describe and remediate them, but they carry no entry in the Exploit Agent's
#: ranking tables and are therefore held apart from the sync assertion.
DISCOVERY_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        key="log4shell",
        test_method="_test_log4shell",
        control_arm=ControlArm(
            governing_rule=(
                "P6 out-of-band: an inbound callback bearing a single-use nonce that "
                "existed only in the one probe that carried it, with a second nonce "
                "minted alongside and sent nowhere. The channel is an inbound callback, "
                "so there is no response body for a decoy to collide with"
            ),
        ),
        label="Log4Shell: JNDI lookup in a logged value (CVE-2021-44228)",
        capability=_C.OUT_OF_BAND,
        title_tokens=("log4shell", "cve-2021-44228"),
        remediation=(
            "Upgrade Log4j to a fixed release (2.17.1 or later); the "
            "mitigations published for the earlier CVEs were each superseded. "
            "Removing JndiLookup from the jar is a valid stopgap where an "
            "upgrade cannot ship immediately. Confirm no other dependency "
            "bundles its own vulnerable copy, and restrict outbound egress "
            "from application hosts so a residual lookup cannot reach an "
            "attacker-controlled server."
        ),
    ),
)

#: Classes proven by COMPOSING confirmed steps rather than by a single ``_test_*``
#: dispatch. A confirmed chain is emitted as an ordinary finding through the
#: normal chokepoint: it is a vulnerability, and a report has to be able to
#: describe and remediate it: but it has no entry in the Exploit Agent's ranking
#: tables, because it is never *planned* against an endpoint. Held apart from the
#: dispatch-sync assertion for that reason, exactly like :data:`DISCOVERY_CLASSES`.
COMPOSITION_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        key="attack_chain",
        test_method="",
        label="Confirmed Attack Chain",
        capability=_C.SERVER_SIDE,
        limitation=(
            "A chain is emitted as confirmed only when EVERY link is "
            "independently confirmed by one of this engine's own oracles AND the "
            "composition itself survived a control: the artifact carried from one "
            "step to the next was accepted, while an equivalently-shaped decoy "
            "the target never issued was refused. Two confirmed findings do not "
            "imply the chain between them, and where the decoy was accepted too "
            "the endpoint accepts the shape rather than the value, so the "
            "composition is reported as an unproven chain lead naming the link "
            "that stopped it. The severity is escalated from what the chain "
            "DEMONSTRATED and never from what the composition could in principle "
            "lead to."
        ),
        title_tokens=("confirmed attack chain",),
        remediation=(
            "Remediate the first link: it is what makes the rest reachable: and treat the "
            "chain as evidence that the later controls are not independent of it. Where a "
            "recovered credential or token was accepted, rotate it and audit for prior use, "
            "because a value this test recovered was recoverable before the test. Then re-check "
            "each subsequent link on its own merits: a chain is a demonstration that they compose, "
            "not a statement that only the first one is wrong."
        ),
    ),
)

#: Classes with no methodology at all. Listed so a report can say "not tested"
#: about them explicitly rather than leaving a client to assume coverage.
UNIMPLEMENTED_CLASSES: tuple[VulnClass, ...] = (
    VulnClass(
        key="insecure_captcha",
        test_method="",
        label="Insecure CAPTCHA",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "No methodology. CAPTCHA-bypass testing requires solving or "
            "replaying a human-verification challenge, which this engine does "
            "not attempt. Not tested."
        ),
        remediation=(
            "Verify the CAPTCHA response server-side against the provider on every submission and "
            "bind it to that single request; never accept a client-supplied 'passed' flag or "
            "reuse a token across the steps of a multi-step flow."
        ),
    ),
    VulnClass(
        key="business_logic_domain_specific",
        test_method="",
        label="Business Logic Flaws: domain-specific abuse",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "Three business-logic classes ARE tested: workflow sequence bypass, "
            "numeric constraint violation, and single-use action replay. Each "
            "confirms only where the application's own surface evidences the "
            "rule being broken: a workflow field, a value range its own records "
            "show, a consumption marker or its own refusal wording. What remains "
            "untested is abuse that depends on domain knowledge the HTTP surface "
            "does not carry: pricing and discount interactions, fraud and "
            "abuse-of-function flows, and any rule that exists only in a "
            "contract or a policy document. Those require a human tester with "
            "domain context, and this engine deliberately makes no claim about "
            "them rather than inferring what the application ought to do."
        ),
    ),
    VulnClass(
        key="race_condition",
        test_method="",
        label="Race Conditions",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "No methodology. Proving a race requires deliberately concurrent "
            "state-changing requests, which the production safety rails refuse "
            "to send. Not tested."
        ),
    ),
    # The two dispatch-table entries that can never emit. They are named here —
    # rather than left out of the registry, which is where they were — because a
    # method the dispatcher will run is a capability claim, and the only place a
    # client learns a claim is empty is this section of the report. Both carry a
    # ``test_method`` so the dispatch-table sync assertion can see them; neither
    # is in ``_BY_METHOD``, so the authorization gate is unchanged and they are
    # not double-reported under "techniques not authorized".
    VulnClass(
        key="kb_matched_technique",
        test_method="_test_tier2_technique",
        control_arm=ControlArm(
            governing_rule=(
                "none is needed and none can exist: this applier sends no request and "
                "returns an empty list from all three of its exits, so it constructs no "
                "finding for a control to discriminate. Registered NOT_IMPLEMENTED"
            ),
        ),
        label="Technology-matched techniques (knowledge-base Tier 2)",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "Planned, not executed. The engine matches techniques recorded in its "
            "cross-engagement knowledge base against the technologies it "
            "fingerprinted and queues one task per matching technique and endpoint, "
            "but the applier those tasks dispatch to sends no request and constructs "
            "no finding. Any technique that reached this path was therefore not "
            "tested, and nothing in this report should be read as evidence the target "
            "is unaffected by it."
        ),
    ),
    VulnClass(
        key="research_runbook_technique",
        test_method="_test_tier3_technique",
        control_arm=ControlArm(
            governing_rule=(
                "none is needed and none can exist: this applier sends no request and "
                "returns an empty list from all three of its exits, so it constructs no "
                "finding for a control to discriminate. Registered NOT_IMPLEMENTED"
            ),
        ),
        label="Research-runbook techniques (Tier 3)",
        capability=_C.NOT_IMPLEMENTED,
        limitation=(
            "Planned, not executed. The Research phase produces a runbook of "
            "candidate techniques for the observed stack and the planner queues one "
            "task per technique and endpoint, but the applier those tasks dispatch "
            "to sends no request and constructs no finding. A technique named in the "
            "runbook was researched, never attempted: including any CVE the "
            "runbook cites."
        ),
    ),
)

_ALL: tuple[VulnClass, ...] = (
    *VULN_CLASSES,
    *DISCOVERY_CLASSES,
    *COMPOSITION_CLASSES,
    *UNIMPLEMENTED_CLASSES,
)

_BY_METHOD: dict[str, VulnClass] = {
    vc.test_method: vc for vc in (*VULN_CLASSES, *DISCOVERY_CLASSES) if vc.test_method
}
_BY_KEY: dict[str, VulnClass] = {vc.key: vc for vc in _ALL}


def for_method(test_method: str) -> VulnClass | None:
    """Return the class implemented by *test_method*, or ``None``."""
    return _BY_METHOD.get(test_method)


def finding_title(test_method: str, detail: str) -> str:
    """A finding title that :func:`for_finding` is GUARANTEED to resolve.

    Every class-keyed rule in the engine — the never-sent control, the chaining
    yield vocabulary, the report's remediation attachment, the offline re-grade —
    reaches its class by matching the finding's title against
    :attr:`VulnClass.title_tokens`. So a title an emit site composed freely is a
    consumer and a producer of the same name, drifting independently.

    They did drift. ``_test_secrets_exposure`` emits *"Credential material served
    to an unauthenticated requester (authorization)"*, which contains none of its
    class's four tokens, so the juice-shop bundle carried a HIGH that resolved to
    no class at all: no remediation, no yield declaration, and — because
    ``control_required("")`` is ``False`` — no never-sent-control obligation
    either. The offline re-grade reported it as SURVIVES on the strength of that
    absence.

    Composing the title from the class's own first token makes the match a
    property of the registry rather than of each author's phrasing. The fix for a
    drifted title is to route it through here, never to add the drifted phrasing
    to ``title_tokens`` — that grows the lookup table by one entry per mistake
    and leaves the next one free to happen.

    Args:
        test_method: The emitting ``_test_*`` method.
        detail: The rest of the title — the specific, per-finding half.

    Returns:
        ``"<Canonical Token> — <detail>"``, or *detail* unchanged when
        *test_method* names no registered class (which
        ``tests/test_models/test_vuln_class_registry.py`` refuses).
    """
    vuln_class = _BY_METHOD.get(test_method)
    if vuln_class is None or not vuln_class.title_tokens:
        return detail
    canonical = vuln_class.title_tokens[0]
    return f"{canonical[:1].upper()}{canonical[1:]} — {detail}"


def for_finding(title: str, description: str = "") -> VulnClass | None:
    """Resolve the class a finding belongs to, from its own text.

    Findings are emitted with a title naming the class ("Reflected XSS in q
    parameter") but no machine-readable class field, and the methodologies emit
    proof rather than advice. This is what lets the report attach the right
    remediation to a finding without every emit site having to carry a copy of
    it.

    Matching is on the LONGEST token first, so "stored xss" wins over a bare
    "xss" and "dom xss" is not swallowed by "reflected xss". A finding that
    matches nothing returns ``None`` and is rendered without guidance — a
    missing remediation is honest; a confidently wrong one is not.

    **The description is a FALLBACK, which it says here and did not do.** The
    implementation searched ``f"{title} {description}"`` as one string, so the
    longest token anywhere won — and a description is
    ``"Technique: <id>. Parameter: <name>."``, where the *parameter name* is a
    value the methodology or the target chose, not a class name.

    On the 2026-08-21 ladder that misfiled P7's flagship at all three
    exploitable levels: ``"DOM-based XSS — script execution witnessed in a
    browser"`` carries the description ``Parameter: (client-side fragment)``, and
    ``client-side`` (11 chars, ``_test_javascript_attacks``) outranks
    ``dom-based`` (9 chars, ``_test_xss_dom``). Every class-keyed consumer then
    read the wrong class: the report attached the JavaScript-attacks
    remediation, the chain layer read the wrong declared yield, and the control
    re-grade filed a browser-witnessed DOM-XSS under a class that never ran.

    A title that resolves is authoritative; the description is consulted only
    when it does not.

    Args:
        title: The finding's title. Searched first, and alone when it matches.
        description: The finding's description, searched only as a fallback.

    Returns:
        The matching :class:`VulnClass`, or ``None``.
    """
    return _longest_token_match(title) or _longest_token_match(description)


def _longest_token_match(text: str) -> VulnClass | None:
    """The class whose longest ``title_tokens`` entry occurs in *text*."""
    haystack = (text or "").lower()
    best: VulnClass | None = None
    best_len = 0
    for vc in _ALL:
        for token in vc.title_tokens:
            if token in haystack and len(token) > best_len:
                best, best_len = vc, len(token)
    return best


def for_key(key: str) -> VulnClass | None:
    """Return the class named by a permitted-technique *key*, or ``None``."""
    return _BY_KEY.get((key or "").strip().lower())


def multi_principal_requirement(test_method: str) -> MultiPrincipalRequirement:
    """How many authenticated principals *test_method* needs before it may confirm.

    The one reader every consumer goes through — the methodology deciding
    whether to confirm, the emission chokepoint enforcing it, and the report
    explaining a lead. An unknown class gets the default (one principal), which
    is the pre-existing behaviour of every class that is not in the
    access-control family.

    Args:
        test_method: The ``_test_*`` name.

    Returns:
        The declared requirement, never ``None``.
    """
    vuln_class = _BY_METHOD.get(test_method)
    return vuln_class.multi_principal if vuln_class else MultiPrincipalRequirement()


def classes_requiring_multiple_principals() -> tuple[VulnClass, ...]:
    """Every class that cannot confirm on the engagement's own session alone.

    The domain of the emission-gate rule, COMPUTED from the registry rather than
    listed beside it: a second class added to the family is covered by the guard
    the day it is declared, not the day somebody remembers to widen a tuple.
    """
    return tuple(vc for vc in _ALL if vc.multi_principal.principals_required > 1)


def classes_requiring_client_side_oracle() -> tuple[VulnClass, ...]:
    """Classes this engine cannot confirm without a browser-side oracle."""
    return tuple(vc for vc in VULN_CLASSES if vc.capability is _C.CLIENT_SIDE_ORACLE_REQUIRED)


def limited_classes() -> tuple[VulnClass, ...]:
    """Every class carrying a stated limitation, implemented or not."""
    return tuple(vc for vc in _ALL if vc.limitation)


__all__ = [
    "COMPOSITION_CLASSES",
    "DISCOVERY_CLASSES",
    "UNIMPLEMENTED_CLASSES",
    "VULN_CLASSES",
    "ConfirmationCapability",
    "MultiPrincipalRequirement",
    "VulnClass",
    "classes_requiring_client_side_oracle",
    "classes_requiring_multiple_principals",
    "finding_title",
    "for_finding",
    "for_key",
    "for_method",
    "limited_classes",
    "multi_principal_requirement",
]
