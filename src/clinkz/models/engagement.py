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

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator

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
    """

    authorizing_party: str
    authorizing_role: str
    authorizing_contact: str
    authorization_reference: str
    permitted_techniques: list[str]
    emergency_contact: str
    notes: str = ""

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

    credentials: list[RoleCredential] = Field(default_factory=list)

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
    "AuthorizationRecord",
    "CredentialSet",
    "EngagementWindow",
    "RoleCredential",
    "SafetyPolicy",
]
