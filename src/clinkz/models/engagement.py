"""Engagement-setup models — what a real engagement needs, captured once.

Everything a supervised, non-benchmark engagement requires before a single
packet is sent:

  * :class:`AuthorizationRecord` — WHO authorized this, under what reference,
    with which techniques permitted, and who to call when it goes wrong. Every
    field is required; there is no default and no "unauthenticated engagement"
    shape of this model, because an engagement without a named authorizing party
    is not an engagement, it is an intrusion.
  * :class:`EngagementWindow` — the agreed start/end. Outside it the engagement
    hard-stops rather than degrading.
  * :class:`SafetyPolicy` — the conservative production rails (rate, concurrency,
    blocking sensitivity). Deliberately carries **no** switch to disable the
    destructive-action refusal: that one is not a policy, it is the contract.
  * :class:`RoleCredential` / :class:`CredentialSet` — one or more labelled
    credential sets. Passwords are :class:`~pydantic.SecretStr`, so a
    ``model_dump()`` of a credential set cannot carry a plaintext password into
    a report, a trace, or the state store even by accident.

**Credentials are deliberately NOT part of** :class:`~clinkz.models.scope.EngagementScope`.
The scope is ``model_dump()``-ed into the SQLite state store at engagement
creation; anything reachable from it is persisted. Keeping the credential set on
a separate, never-persisted path is a structural guarantee rather than a
discipline — see :mod:`clinkz.engagement.secrets` for the redaction layer that
backs it up.
"""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

# A permitted-technique entry that authorizes every technique. Spelled out
# rather than implied by an empty list: an EMPTY permitted list means nothing is
# permitted (and is rejected at validation), so a blanket authorization has to be
# written down on purpose.
_WILDCARD_TECHNIQUES: frozenset[str] = frozenset({"*", "all", "any"})


def _require_nonempty(value: str, field: str) -> str:
    """Strip *value* and reject it when nothing is left.

    Args:
        value: Raw field value.
        field: Field name, for the error message.

    Returns:
        The stripped value.

    Raises:
        ValueError: When the stripped value is empty.
    """
    stripped = (value or "").strip()
    if not stripped:
        raise ValueError(
            f"'{field}' is required and must not be blank — an engagement cannot "
            "start without a complete authorization record"
        )
    return stripped


#: The attestation an operator must reproduce VERBATIM to declare a benchmark
#: target. It is long and specific on purpose: a boolean flag can be set by a
#: config template somebody copied, and a sentence this exact cannot be typed by
#: accident. This is the "impossible to enable implicitly" requirement made
#: structural rather than documented.
BENCHMARK_ACKNOWLEDGEMENT: str = (
    "I confirm this target is a disposable benchmark instance holding no real "
    "data, and I accept that destructive actions will be performed against it."
)


def never_overridable_categories() -> frozenset[str]:
    """Destructive categories a benchmark profile may NEVER permit.

    The line is not "how bad is it" — every category a profile CAN permit is bad
    for the client, which is precisely what a throwaway target makes acceptable.
    The line is WHO it damages: these two damage the ENGAGEMENT rather than the
    target. Destroying the shared session or flipping the application's security
    posture mid-run makes every later observation a measurement of a different
    application, which is how a run silently produces confident nonsense. A
    disposable target does not make a corrupted engagement worth having, so no
    profile can opt into these.

    Read from :mod:`clinkz.safety.destructive` at call time rather than imported
    at module scope: this module is imported by the engagement gate, which the
    safety package imports, so a module-level import would close a cycle. Reading
    the names lazily keeps the destructive module the ONE vocabulary — the
    alternative, restating the category strings here, is a second copy that
    drifts.
    """
    from clinkz.safety.destructive import (
        CATEGORY_SECURITY_CONTROL,
        CATEGORY_SESSION_DESTRUCTION,
    )

    return frozenset({CATEGORY_SESSION_DESTRUCTION, CATEGORY_SECURITY_CONTROL})


def overridable_categories() -> frozenset[str]:
    """Every category a profile may name.

    Enumerated rather than derived as "everything else", so adding a category to
    the classifier does not silently make it permittable — a new destructive
    category is a decision about what a benchmark declaration may authorise, and
    it should be made on purpose.
    """
    from clinkz.safety.destructive import (
        CATEGORY_BULK_MESSAGING,
        CATEGORY_CANCELLATION,
        CATEGORY_CREDENTIAL_CHANGE,
        CATEGORY_DATA_RESET,
        CATEGORY_DELETION,
        CATEGORY_IDENTITY_CHANGE,
        CATEGORY_KEY_REVOCATION,
        CATEGORY_PAYMENT,
        CATEGORY_UNSAFE_METHOD,
    )

    return frozenset(
        {
            CATEGORY_DELETION,
            CATEGORY_CREDENTIAL_CHANGE,
            CATEGORY_IDENTITY_CHANGE,
            CATEGORY_PAYMENT,
            CATEGORY_CANCELLATION,
            CATEGORY_KEY_REVOCATION,
            CATEGORY_BULK_MESSAGING,
            CATEGORY_DATA_RESET,
            CATEGORY_UNSAFE_METHOD,
        }
    )


class BenchmarkProfile(BaseModel):
    """Explicit opt-in to destructive testing against a disposable target.

    The destructive refusal is the contract with the client and stays exactly as
    it is — :class:`SafetyPolicy` still carries no switch that disables it, and
    the client-safe default is untouched. What this model adds is a *separate,
    fully explicit* declaration that a specific target is a throwaway benchmark,
    naming the categories it permits one by one.

    Chaining and business logic are why it exists. Both need state-changing
    requests, and the destructive blocklist correctly refuses ``DELETE`` and
    identity change — correct against a client's production application, and the
    reason two Juice Shop challenges are unreachable. Loosening the default would
    trade a real safety property for benchmark coverage. Declaring the benchmark
    instead trades nothing.

    **It cannot be enabled implicitly.** There is no ``enabled`` flag to flip and
    no partially-populated shape: constructing this model at all requires

      * ``target_is_throwaway`` to be ``True`` — ``False`` is a validation error,
        because "a disabled profile" is spelled by not having one;
      * ``acknowledgement`` to reproduce :data:`BENCHMARK_ACKNOWLEDGEMENT`
        verbatim;
      * at least one category, each from :data:`OVERRIDABLE_CATEGORIES` and none
        from :data:`NEVER_OVERRIDABLE_CATEGORIES`;
      * a named declaring party and a reference.

    Attributes:
        target_is_throwaway: Must be ``True``.
        acknowledgement: Must equal :data:`BENCHMARK_ACKNOWLEDGEMENT`.
        permitted_categories: The destructive categories permitted, named one by
            one, from :func:`overridable_categories`. A wildcard is deliberately
            not accepted: the point is that the operator wrote down which harms
            they are authorising.
        declared_by: Who declared the target disposable.
        declared_reference: The record (ticket, lab id, README line) that backs it.
        notes: Free-text context for the report header.
    """

    target_is_throwaway: bool
    acknowledgement: str
    permitted_categories: list[str]
    declared_by: str
    declared_reference: str
    notes: str = ""

    @field_validator("declared_by", "declared_reference")
    @classmethod
    def _nonblank_declaration(cls, v: str, info: object) -> str:
        field_name = getattr(info, "field_name", "field")
        return _require_nonempty(v, str(field_name))

    @model_validator(mode="after")
    def _fully_explicit(self) -> BenchmarkProfile:
        if not self.target_is_throwaway:
            raise ValueError(
                "'target_is_throwaway' must be true. A benchmark profile with it set "
                "false is not a disabled profile — omit the profile entirely to test "
                "with the client-safe destructive refusals in force."
            )
        if self.acknowledgement.strip() != BENCHMARK_ACKNOWLEDGEMENT:
            raise ValueError(
                "'acknowledgement' must reproduce the benchmark attestation verbatim:\n"
                f"  {BENCHMARK_ACKNOWLEDGEMENT}"
            )
        cleaned = [c.strip().lower() for c in self.permitted_categories if c and c.strip()]
        if not cleaned:
            raise ValueError(
                "'permitted_categories' must name at least one destructive category. "
                "There is no wildcard: the profile records which harms were authorised."
            )
        forbidden = sorted(set(cleaned) & never_overridable_categories())
        if forbidden:
            raise ValueError(
                f"these categories can never be permitted, on any target: "
                f"{', '.join(forbidden)}. They damage the ENGAGEMENT rather than the "
                f"target — destroying the shared session or flipping the application's "
                f"security posture makes every later observation a measurement of a "
                f"different application."
            )
        allowed = overridable_categories()
        unknown = sorted(set(cleaned) - allowed)
        if unknown:
            raise ValueError(
                f"unknown destructive categor{'y' if len(unknown) == 1 else 'ies'}: "
                f"{', '.join(unknown)}. Permitted names are: {', '.join(sorted(allowed))}"
            )
        object.__setattr__(self, "permitted_categories", cleaned)
        return self

    def permits_category(self, category: str) -> bool:
        """Whether this profile permits *category*."""
        return (category or "").strip().lower() in set(self.permitted_categories)

    def header_lines(self) -> list[str]:
        """The report-header block. Rendered verbatim; never summarised away."""
        return [
            "BENCHMARK PROFILE ACTIVE — destructive testing was explicitly authorised.",
            f"Declared by: {self.declared_by} (reference: {self.declared_reference})",
            f"Attestation: {self.acknowledgement}",
            "Destructive categories permitted: " + ", ".join(sorted(self.permitted_categories)),
            "Categories that remain refused on any target: "
            + ", ".join(sorted(never_overridable_categories())),
            *([f"Notes: {self.notes}"] if self.notes else []),
        ]


class AuthorizationRecord(BaseModel):
    """Who authorized this engagement, and on what terms.

    Recorded in the report header verbatim. Every field is required: this model
    has no partially-populated shape, so "we forgot to capture the authorizing
    party" surfaces as a validation error at setup rather than as a blank line in
    a client deliverable.

    Attributes:
        authorizing_party: Legal name of the person authorizing the test.
        authorizing_role: Their role/title (the basis of their authority).
        authorizing_contact: Reachable contact for the authorizing party.
        authorization_reference: Contract / SOW / ticket reference for the
            written authorization this record attests to.
        permitted_techniques: Technique or vulnerability-class names the client
            has permitted. ``["*"]`` (or ``all``/``any``) authorizes everything;
            an empty list is rejected.
        emergency_contact: Who to call the moment something goes wrong.
        notes: Free-text caveats agreed with the client.
        benchmark_profile: An explicit declaration that this target is a
            disposable benchmark, permitting named destructive categories.
            ``None`` — the default, and the only shape a client engagement ever
            has — means the destructive refusals are fully in force. It lives on
            the authorization record rather than on
            :class:`SafetyPolicy` because it is not a tuning knob: it is part of
            what was authorised, so it is captured where authorisation is
            captured and rendered where authorisation is rendered.
    """

    authorizing_party: str
    authorizing_role: str
    authorizing_contact: str
    authorization_reference: str
    permitted_techniques: list[str]
    emergency_contact: str
    notes: str = ""
    benchmark_profile: BenchmarkProfile | None = None

    @field_validator(
        "authorizing_party",
        "authorizing_role",
        "authorizing_contact",
        "authorization_reference",
        "emergency_contact",
    )
    @classmethod
    def _nonblank(cls, v: str, info: object) -> str:
        field_name = getattr(info, "field_name", "field")
        return _require_nonempty(v, str(field_name))

    @field_validator("permitted_techniques")
    @classmethod
    def _nonempty_techniques(cls, v: list[str]) -> list[str]:
        cleaned = [t.strip() for t in v if t and t.strip()]
        if not cleaned:
            raise ValueError(
                "'permitted_techniques' must name at least one permitted technique "
                "(use ['*'] to authorize all techniques explicitly)"
            )
        return cleaned

    @property
    def permits_all(self) -> bool:
        """Whether the record blanket-authorizes every technique."""
        return any(t.lower() in _WILDCARD_TECHNIQUES for t in self.permitted_techniques)

    def permits(self, technique: str) -> bool:
        """Whether *technique* is covered by this authorization.

        Matching is case-insensitive and normalizes ``-``/space to ``_`` so a
        client writing ``"SQL Injection"`` authorizes the ``sql_injection``
        class. A permitted entry also covers any technique that starts with it
        followed by a separator, so ``xss`` authorizes ``xss_reflected`` —
        the client granted the family, not one spelling of it.

        Args:
            technique: Technique / vulnerability-class identifier.

        Returns:
            ``True`` when permitted.
        """
        if self.permits_all:
            return True
        needle = _normalize_technique(technique)
        if not needle:
            return False
        for entry in self.permitted_techniques:
            allowed = _normalize_technique(entry)
            if not allowed:
                continue
            if needle == allowed or needle.startswith(f"{allowed}_"):
                return True
        return False


def _normalize_technique(name: str) -> str:
    """Normalize a technique name for permitted-list comparison."""
    return (name or "").strip().lower().replace("-", "_").replace(" ", "_")


class EngagementWindow(BaseModel):
    """The agreed testing window, with a hard stop at each end.

    Naive datetimes are interpreted as UTC rather than rejected — an operator
    writing ``2026-08-04T09:00:00`` in a JSON file means a wall-clock time, and
    silently treating that as local time would make the hard stop depend on the
    machine the engagement happens to run on.

    Attributes:
        start: When testing may begin.
        end: When testing must stop.
    """

    start: datetime
    end: datetime

    @field_validator("start", "end")
    @classmethod
    def _tz_aware(cls, v: datetime) -> datetime:
        return v.replace(tzinfo=UTC) if v.tzinfo is None else v

    @model_validator(mode="after")
    def _ordered(self) -> EngagementWindow:
        if self.end <= self.start:
            raise ValueError(
                f"engagement window end ({self.end.isoformat()}) must be after "
                f"start ({self.start.isoformat()})"
            )
        return self

    def contains(self, at: datetime | None = None) -> bool:
        """Whether *at* (default: now) falls inside the window."""
        moment = _now(at)
        return self.start <= moment <= self.end

    def has_started(self, at: datetime | None = None) -> bool:
        """Whether the window has opened by *at* (default: now)."""
        return _now(at) >= self.start

    def has_ended(self, at: datetime | None = None) -> bool:
        """Whether the window has closed by *at* (default: now)."""
        return _now(at) > self.end

    def remaining_seconds(self, at: datetime | None = None) -> float:
        """Seconds left in the window at *at*; ``0.0`` once it has closed."""
        return max(0.0, (self.end - _now(at)).total_seconds())


def _now(at: datetime | None) -> datetime:
    """Return *at* as a tz-aware UTC datetime, defaulting to now."""
    moment = at or datetime.now(UTC)
    return moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment


class SafetyPolicy(BaseModel):
    """Production safety rails — conservative by default.

    A deliberately vulnerable benchmark tolerates flooding; a production
    application does not. These defaults are sized for "a real application that
    someone depends on", not for throughput.

    There is intentionally no field that disables the destructive-action
    refusal. That refusal is the contract with the client, not a tunable — see
    :mod:`clinkz.safety.destructive`.

    Attributes:
        max_requests_per_second: Ceiling on outbound request rate across the
            whole engagement, enforced by a shared token bucket.
        max_concurrent_requests: Ceiling on simultaneously in-flight requests.
        blocking_threshold: Consecutive blocked/throttled responses that count as
            "the target is blocking us".
        halt_on_blocking: Stop the engagement when the threshold trips, rather
            than continuing to hammer a target that is refusing us.
        max_state_changing_requests: Ceiling on state-changing requests the
            engagement may send in total. ``0`` disables the ceiling. A cheap
            backstop against a runaway loop mutating a live application.
    """

    max_requests_per_second: float = Field(default=5.0, gt=0.0)
    max_concurrent_requests: int = Field(default=4, ge=1)
    blocking_threshold: int = Field(default=5, ge=1)
    halt_on_blocking: bool = True
    max_state_changing_requests: int = Field(default=0, ge=0)


class RoleCredential(BaseModel):
    """One labelled credential set.

    The ``role`` label is what makes access-control testing possible: an
    IDOR/authz class needs two principals to compare, and ``admin`` vs ``user``
    is the comparison. ``anonymous`` is a legitimate role with empty credentials
    — it names the unauthenticated baseline the assertion compares against.

    Attributes:
        role: Operator-supplied label (``admin`` / ``user`` / ``anonymous`` /
            anything else meaningful for this application).
        username: Login identifier (username or email).
        password: Secret. ``SecretStr``, so ``model_dump()`` yields a mask and
            never the plaintext.
        login_url: Optional explicit login endpoint for this role, when the
            application's login is not discoverable or differs per role.
        assert_url: Optional URL known to behave differently authenticated vs
            anonymous. Tried FIRST by the authenticated-state assertion.

            The assertion falls back to conventional protected paths, but an
            application whose protected surface is named something unconventional
            will fail that guess — and the engagement then aborts rather than
            scanning blind, which is correct but unhelpful if the operator
            already knew the answer. This is where they say it.
        description: Free-text note (e.g. "read-only reporting account").
    """

    # An unknown key is REFUSED, not dropped. Pydantic's default is to ignore
    # extras, and this model is filled from a hand-written JSON file by an
    # operator working from documentation — the one population where a silently
    # discarded key is indistinguishable from a key that did nothing. A
    # misplaced ``login_url`` validated cleanly, changed nothing, and the run
    # then hard-aborted on an unprovable session with no connection between the
    # two. Refusing names the key.
    model_config = ConfigDict(extra="forbid")

    role: str
    username: str = ""
    password: SecretStr = SecretStr("")
    login_url: str = ""
    assert_url: str = ""
    description: str = ""

    @field_validator("role")
    @classmethod
    def _role_nonblank(cls, v: str) -> str:
        return _require_nonempty(v, "role").lower()

    @property
    def is_anonymous(self) -> bool:
        """Whether this entry names the unauthenticated baseline."""
        return self.role == "anonymous" or not self.username

    def secret(self) -> str:
        """Return the plaintext password.

        Every call site of this method is a place a secret leaves the model, so
        it is named to be greppable. Never log, persist, or render the result.
        """
        return self.password.get_secret_value()


class CredentialSet(BaseModel):
    """The engagement's credentials, one entry per role.

    Never attached to :class:`~clinkz.models.scope.EngagementScope` — the scope
    is persisted to the state store, and a credential set must not be.

    Attributes:
        credentials: One :class:`RoleCredential` per role.
    """

    model_config = ConfigDict(extra="forbid")

    credentials: list[RoleCredential] = Field(default_factory=list)

    @model_validator(mode="before")
    @classmethod
    def _name_a_misplaced_role_field(cls, data: object) -> object:
        """Refuse a per-role key written at the top level, and say where it goes.

        ``login_url`` is per ROLE — an application whose login is undiscoverable
        or differs per principal is exactly why the field exists, and a single
        engagement-wide value could not express the second case. So it lives on
        :class:`RoleCredential`, inside each entry of ``credentials``.

        Nothing said so. It appears in no example, in no ``--help`` text and in
        no document; only in this module's docstrings. An operator who needs it
        guesses, and the natural guess is the top level of the credential file
        or the scope — and until ``extra="forbid"``, both guesses parsed
        cleanly and did nothing. The engagement then aborted on an unprovable
        session, which is the correct refusal delivered as though the operator's
        input had been fine.

        ``extra="forbid"`` alone would say "Extra inputs are not permitted",
        which is true and unhelpful. This says where the key belongs.
        """
        if not isinstance(data, dict):
            return data
        misplaced = sorted(set(data) & set(RoleCredential.model_fields) - {"credentials"})
        if misplaced:
            raise ValueError(
                f"{', '.join(misplaced)} belongs on each entry inside 'credentials', "
                "not at the top level of the credential file. Per-role, because an "
                "application's login can differ per principal. For example: "
                '{"credentials": [{"role": "admin", "username": "...", '
                '"password": "...", "login_url": "https://app/rest/user/login"}]}'
            )
        return data

    @property
    def roles(self) -> list[str]:
        """Role labels in supplied order."""
        return [c.role for c in self.credentials]

    @property
    def authenticating(self) -> list[RoleCredential]:
        """Entries that actually carry credentials (anonymous excluded)."""
        return [c for c in self.credentials if not c.is_anonymous]

    def for_role(self, role: str) -> RoleCredential | None:
        """Return the entry labelled *role*, or ``None``."""
        needle = (role or "").strip().lower()
        for cred in self.credentials:
            if cred.role == needle:
                return cred
        return None

    def primary(self) -> RoleCredential | None:
        """The credential the engagement should authenticate as by default.

        Prefers an explicit ``admin`` (broadest reachable surface), then the
        first authenticating entry.
        """
        return self.for_role("admin") or (self.authenticating[0] if self.authenticating else None)

    def secrets(self) -> list[str]:
        """Every plaintext secret in the set — for redaction registration only."""
        return [c.secret() for c in self.credentials if c.secret()]


__all__ = [
    "BENCHMARK_ACKNOWLEDGEMENT",
    "AuthorizationRecord",
    "BenchmarkProfile",
    "CredentialSet",
    "EngagementWindow",
    "RoleCredential",
    "SafetyPolicy",
    "never_overridable_categories",
    "overridable_categories",
]
