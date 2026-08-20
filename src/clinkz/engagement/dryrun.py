"""``--dry-run`` - enumerate what the engagement WOULD do, sending nothing.

The operator-facing answer to "before you touch my production application, tell
me what you are about to do". Everything here is derived from the engagement
inputs alone: the scope, the authorization record, the safety policy, the
credential roles, and the class registry. **No network activity of any kind.**

That constraint is what makes the output trustworthy. A dry run that quietly
crawled the target to produce a better list would be exactly the thing the
operator asked it not to do.

Because nothing is probed, the endpoint list is whatever the caller already
knows (typically empty on a first run). The classes, the scope decisions, the
rate rails, and the destructive categories that WILL be refused are all fully
determined without it - and those are the parts an operator is signing off on.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from clinkz.models.engagement import (
    BenchmarkProfile,
    CredentialSet,
    never_overridable_categories,
    overridable_categories,
)
from clinkz.models.scope import EngagementScope
from clinkz.models.vuln_classes import (
    UNIMPLEMENTED_CLASSES,
    VULN_CLASSES,
    ConfirmationCapability,
    VulnClass,
)
from clinkz.safety.destructive import (
    CATEGORY_BULK_MESSAGING,
    CATEGORY_CANCELLATION,
    CATEGORY_CREDENTIAL_CHANGE,
    CATEGORY_DATA_RESET,
    CATEGORY_DELETION,
    CATEGORY_IDENTITY_CHANGE,
    CATEGORY_KEY_REVOCATION,
    CATEGORY_PAYMENT,
    CATEGORY_SECURITY_CONTROL,
    CATEGORY_SESSION_DESTRUCTION,
    CATEGORY_UNSAFE_METHOD,
    classify_request,
)

#: The categories the rails will refuse, in the order a client cares about them.
_REFUSED_CATEGORIES: tuple[tuple[str, str], ...] = (
    (CATEGORY_DELETION, "Deleting or destroying a resource"),
    (CATEGORY_CREDENTIAL_CHANGE, "Changing a password or other authentication material"),
    (CATEGORY_IDENTITY_CHANGE, "Changing an email address, username, or other account identity"),
    (CATEGORY_PAYMENT, "Any payment, charge, refund, transfer, or withdrawal"),
    (CATEGORY_CANCELLATION, "Cancelling, terminating, deactivating, or suspending anything"),
    (CATEGORY_KEY_REVOCATION, "Revoking or rotating a key, token, or certificate"),
    (CATEGORY_BULK_MESSAGING, "Sending mail, SMS, or notifications to a broad recipient set"),
    (CATEGORY_DATA_RESET, "Resetting or reinitialising application data"),
    (CATEGORY_UNSAFE_METHOD, "Sending an inherently unsafe method (PUT / PATCH / DELETE)"),
    (CATEGORY_SESSION_DESTRUCTION, "Logging the engagement's own session out"),
    (CATEGORY_SECURITY_CONTROL, "Toggling a WAF, IDS, or security-level control"),
)

#: Every category, as the classifier and the profile validator know them. The
#: preview is checked against this rather than against its own list, because the
#: list WAS its own: ``unsafe_method`` was absent from ``_REFUSED_CATEGORIES``
#: altogether, so an operator authorising a DVWA-ladder run — where it is one of
#: the three permitted categories — never saw it named in either column.
_ALL_CATEGORIES: frozenset[str] = frozenset(
    overridable_categories() | never_overridable_categories()
)


class DryRunClass(BaseModel):
    """One vulnerability class as the dry run reports it.

    Attributes:
        key: Technique key.
        label: Human label.
        planned: Whether it will be attempted.
        reason: Why not, when it will not be.
    """

    key: str
    label: str
    planned: bool
    reason: str = ""


class DryRunPlan(BaseModel):
    """Everything the engagement would do, derived without sending anything.

    Attributes:
        engagement_name: Scope name.
        authorized: Whether an authorization record is present.
        authorization_summary: One line naming who authorized it.
        window_summary: The agreed window, or a note that none was set.
        in_scope: In-scope entries as ``value (type)``.
        out_of_scope: Excluded entries, which take precedence.
        roles: Credential roles that would be authenticated.
        multi_role_available: Whether access-control comparison is possible.
        classes: Every class, planned or not, with the reason.
        refused_categories: Action categories that will be refused outright -
            under the profile that will actually execute, not under a constant.
        permitted_categories: Action categories an attached benchmark profile
            PERMITS. Empty on every run without one, which is the default.
        benchmark_summary: One line naming the profile, or stating there is none.
        destructive_examples: Concrete ``METHOD URL`` samples the classifier
            refuses, with the category - the rails demonstrated, not asserted.
        rails: The safety policy in force.
        warnings: Anything an operator should read before approving.
    """

    engagement_name: str = ""
    authorized: bool = False
    authorization_summary: str = ""
    window_summary: str = ""
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    multi_role_available: bool = False
    classes: list[DryRunClass] = Field(default_factory=list)
    refused_categories: list[str] = Field(default_factory=list)
    permitted_categories: list[str] = Field(default_factory=list)
    benchmark_summary: str = ""
    destructive_examples: list[str] = Field(default_factory=list)
    rails: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


#: Sample requests used to DEMONSTRATE the destructive rails during a dry run.
#: Synthetic and never sent - they exist so an operator can see the classifier's
#: actual verdicts rather than take a bullet list on trust.
_DEMO_REQUESTS: tuple[tuple[str, str], ...] = (
    ("DELETE", "/api/records/1"),
    ("POST", "/account/change-password"),
    ("POST", "/settings/email"),
    ("POST", "/checkout"),
    ("POST", "/subscription/cancel"),
    ("POST", "/api/keys/1/revoke"),
    ("POST", "/newsletter"),
    ("POST", "/admin/database/reset"),
    ("GET", "/logout"),
)


def build_dry_run_plan(
    scope: EngagementScope,
    credentials: CredentialSet | None = None,
) -> DryRunPlan:
    """Assemble the dry-run plan from engagement inputs alone.

    Args:
        scope: The engagement scope.
        credentials: The credential set, when one was supplied.

    Returns:
        A :class:`DryRunPlan`. No network activity is performed.
    """
    plan = DryRunPlan(engagement_name=scope.name)

    record = scope.authorization
    plan.authorized = record is not None
    if record is not None:
        plan.authorization_summary = (
            f"{record.authorizing_party} ({record.authorizing_role}) "
            f"under reference {record.authorization_reference}"
        )
    else:
        plan.warnings.append(
            "NO AUTHORIZATION RECORD - a real run would refuse to start. "
            "Supply --authorization <file.json> or an 'authorization' block in the scope."
        )

    if scope.window is not None:
        plan.window_summary = f"{scope.window.start.isoformat()} -> {scope.window.end.isoformat()}"
        if scope.window.has_ended():
            plan.warnings.append(
                "The engagement window has already closed - a real run would stop."
            )
        elif not scope.window.has_started():
            plan.warnings.append(
                "The engagement window has not opened yet - a real run would refuse to start."
            )
    else:
        plan.window_summary = "no window agreed (no hard stop configured)"
        plan.warnings.append(
            "No engagement window was set. Consider agreeing one so the run has a hard stop."
        )

    # Notes render on BOTH sides. They were rendered only for exclusions, so a
    # note explaining why a host is IN scope - the side that decides what gets
    # touched - was the one an operator could not see.
    plan.in_scope = [
        f"{t.value} ({t.type.value})" + (f" - {t.notes}" if t.notes else "") for t in scope.targets
    ]
    plan.out_of_scope = [
        f"{e.value} ({e.type.value})" + (f" - {e.notes}" if e.notes else "") for e in scope.excluded
    ]
    if not plan.in_scope:
        plan.warnings.append("Scope contains no targets - nothing would be tested.")

    cred_set = credentials or CredentialSet()
    plan.roles = cred_set.roles
    plan.multi_role_available = len(cred_set.authenticating) >= 2
    if not cred_set.authenticating:
        plan.warnings.append(
            "No credentials supplied - the engagement would scan ANONYMOUSLY. "
            "If the application requires a login, expect an empty report that means "
            "nothing. Supply --credentials."
        )
    elif not plan.multi_role_available:
        plan.warnings.append(
            "Only one authenticating role supplied - access-control classes (IDOR / "
            "authorization) cannot compare two principals and will report candidates only."
        )

    plan.classes = _plan_classes(scope)
    profile = record.benchmark_profile if record is not None else None
    plan.refused_categories, plan.permitted_categories = _categorise_refusals(profile)
    plan.benchmark_summary = _benchmark_summary(profile)
    if profile is not None:
        plan.warnings.append(
            "A BENCHMARK PROFILE is attached. The destructive rails are relaxed for the "
            f"categories listed under PERMITTED below ({len(profile.permitted_categories)} of "
            f"{len(_REFUSED_CATEGORIES)}). Approve this run only if the target really is "
            "disposable."
        )
    plan.destructive_examples = _demonstrate_refusals(scope)

    policy = scope.safety
    plan.rails = {
        "max_requests_per_second": str(policy.max_requests_per_second),
        "max_concurrent_requests": str(policy.max_concurrent_requests),
        "blocking_threshold": (
            f"{policy.blocking_threshold} consecutive blocked responses"
            + (" -> halt" if policy.halt_on_blocking else " -> warn only")
        ),
        "max_state_changing_requests": (
            str(policy.max_state_changing_requests)
            if policy.max_state_changing_requests
            else "unlimited"
        ),
    }
    if not policy.halt_on_blocking:
        plan.warnings.append(
            "halt_on_blocking is disabled - the engagement would keep sending "
            "requests to a target that is blocking it."
        )
    return plan


def _plan_classes(scope: EngagementScope) -> list[DryRunClass]:
    """Decide, per class, whether it would be attempted and why not."""
    record = scope.authorization
    out: list[DryRunClass] = []

    for vc in VULN_CLASSES:
        if record is not None and not record.permits(vc.key):
            out.append(
                DryRunClass(
                    key=vc.key,
                    label=vc.label,
                    planned=False,
                    reason="not in the client's permitted-technique list",
                )
            )
            continue
        out.append(
            DryRunClass(
                key=vc.key,
                label=vc.label,
                planned=True,
                reason=_capability_note(vc),
            )
        )

    for vc in UNIMPLEMENTED_CLASSES:
        out.append(DryRunClass(key=vc.key, label=vc.label, planned=False, reason=vc.limitation))
    return out


def _client_oracle_present() -> bool:
    """Whether P7 is usable on the runtime THIS run would use.

    Asked rather than assumed. The note below used to state the oracle absent
    unconditionally for every client-side class, which is a claim about the
    machine made without looking at it — and on a docker-mode host with the
    tools image built it is the opposite of the truth. A pre-dispatch document
    that under-reports coverage is the same defect as one that over-reports it:
    the operator reads "reachability only" and plans around a gap that is not
    there.

    :meth:`~clinkz.browser.oracle.PlaywrightExecutionOracle.native_availability`
    is the engine's own answer for the runtime tied to ``TOOL_EXEC_MODE``, and
    it is cached, so the ``docker exec`` it costs is paid once. Any failure to
    determine it falls back to the pessimistic answer — a dry run must never be
    the optimistic one.
    """
    try:
        from clinkz.browser.oracle import PlaywrightExecutionOracle

        return bool(PlaywrightExecutionOracle.native_availability())
    except Exception:  # noqa: BLE001 — a dry run never fails over a capability probe
        return False


def _capability_note(vc: VulnClass) -> str:
    """One line about what confirmation of *vc* depends on."""
    if vc.capability is ConfirmationCapability.OUT_OF_BAND:
        return "blind cases need the out-of-band collaborator to confirm"
    if vc.capability is ConfirmationCapability.CLIENT_SIDE_ORACLE_REQUIRED:
        if _client_oracle_present():
            return "client-side execution oracle IS available - this class can confirm"
        return "reachability only - no client-side execution oracle"
    return ""


def _categorise_refusals(
    profile: BenchmarkProfile | None,
) -> tuple[list[str], list[str]]:
    """Split the destructive categories by what the ATTACHED profile does to them.

    ``plan.refused_categories`` was built from :data:`_REFUSED_CATEGORIES`
    verbatim, so ``--dry-run`` printed the full "WILL BE REFUSED" list whether or
    not a ``--benchmark-profile`` was attached, and the profile it was handed was
    never read. That is not a cosmetic gap: **the dry run is what a client
    authorises against.** A preview that under-reports the permitted categories
    obtains consent for a stricter engagement than the one that then runs, and
    the difference is exactly the set of destructive actions the operator was
    entitled to see before saying yes.

    The split is computed with :func:`~clinkz.safety.benchmark.benchmark_override`
    semantics — ``permits_category`` on the same profile object the orchestrator
    will install — rather than by re-deriving the rule here, so preview and
    execution cannot answer differently.

    Args:
        profile: The attached benchmark profile, or ``None``.

    Returns:
        ``(refused, permitted)``, each rendered as ``label [category]``.
    """
    refused: list[str] = []
    permitted: list[str] = []
    for category, label in _REFUSED_CATEGORIES:
        if profile is not None and profile.permits_category(category):
            permitted.append(f"{label} [{category}]")
        else:
            refused.append(f"{label} [{category}]")
    return refused, permitted


def _benchmark_summary(profile: BenchmarkProfile | None) -> str:
    """One line describing the profile that will execute."""
    if profile is None:
        return (
            "none - the client-safe destructive refusals are in force and there is "
            "no flag that disables them"
        )
    return (
        f"ACTIVE - declared by {profile.declared_by} under {profile.declared_reference}; "
        f"permits {len(profile.permitted_categories)} destructive "
        f"categor{'y' if len(profile.permitted_categories) == 1 else 'ies'}"
    )


def _demonstrate_refusals(scope: EngagementScope) -> list[str]:
    """Run the real classifier over synthetic requests and report its verdicts.

    The verdicts go through :func:`~clinkz.safety.benchmark.benchmark_override`
    with the scope's own profile, so a sample the profile permits is shown as
    permitted here too. Reporting the raw classifier verdict while the run would
    override it is the same under-reporting the category list used to do, one
    line further down the page.
    """
    profile = scope.authorization.benchmark_profile if scope.authorization else None
    base = ""
    for target in scope.targets:
        if target.value.startswith(("http://", "https://")):
            base = target.value.rstrip("/")
            break
        base = f"http://{target.value}".rstrip("/")
        break

    lines: list[str] = []
    for method, path in _DEMO_REQUESTS:
        verdict = classify_request(method, f"{base}{path}")
        if verdict.refused and profile is not None and profile.permits_category(verdict.category):
            status = f"PERMITTED [{verdict.category}]"
        elif verdict.refused:
            status = f"REFUSE [{verdict.category}]"
        else:
            status = "allow"
        lines.append(f"{status:<32} {method:<7} {base}{path}")
    return lines


def render_dry_run(plan: DryRunPlan) -> str:
    """Render a :class:`DryRunPlan` as operator-facing text.

    Args:
        plan: The assembled plan.

    Returns:
        A multi-line report suitable for a terminal.
    """
    lines: list[str] = [
        "=" * 78,
        f"DRY RUN - {plan.engagement_name}",
        "  Nothing was sent. This is what the engagement WOULD do.",
        "=" * 78,
        "",
        "AUTHORIZATION",
        f"  {plan.authorization_summary or 'MISSING - a real run would refuse to start'}",
        f"  Window: {plan.window_summary}",
        "",
        "SCOPE",
    ]
    lines += [f"  in  : {entry}" for entry in plan.in_scope] or ["  in  : (none)"]
    lines += [f"  OUT : {entry}" for entry in plan.out_of_scope] or [
        "  OUT : (nothing explicitly excluded)"
    ]

    lines += [
        "",
        "AUTHENTICATION",
        f"  roles: {', '.join(plan.roles) if plan.roles else '(none - anonymous scan)'}",
        f"  multi-role access-control comparison: {'yes' if plan.multi_role_available else 'no'}",
        "",
        "SAFETY RAILS",
    ]
    lines += [f"  {key}: {value}" for key, value in plan.rails.items()]

    lines += ["", "BENCHMARK PROFILE", f"  {plan.benchmark_summary}"]

    lines += ["", "WILL BE REFUSED (default-deny, every method)"]
    lines += [f"  - {entry}" for entry in plan.refused_categories] or [
        "  - (none - every destructive category is permitted by the attached profile)"
    ]

    if plan.permitted_categories:
        lines += ["", "WILL BE PERMITTED (attached benchmark profile relaxes these)"]
        lines += [f"  ! {entry}" for entry in plan.permitted_categories]

    lines += ["", "CLASSIFIER VERDICTS ON SAMPLE ACTIONS (synthetic, never sent)"]
    lines += [f"  {entry}" for entry in plan.destructive_examples]

    planned = [c for c in plan.classes if c.planned]
    skipped = [c for c in plan.classes if not c.planned]

    lines += ["", f"CLASSES THAT WOULD BE ATTEMPTED ({len(planned)})"]
    for cls in planned:
        suffix = f"  - {cls.reason}" if cls.reason else ""
        lines.append(f"  + {cls.label} [{cls.key}]{suffix}")

    lines += ["", f"CLASSES THAT WOULD NOT BE ATTEMPTED ({len(skipped)})"]
    for cls in skipped:
        lines.append(f"  - {cls.label} [{cls.key}]: {cls.reason}")

    if plan.warnings:
        lines += ["", "WARNINGS"]
        lines += [f"  ! {warning}" for warning in plan.warnings]

    lines += ["", "=" * 78]
    return "\n".join(lines)


__all__ = [
    "DryRunClass",
    "DryRunPlan",
    "build_dry_run_plan",
    "render_dry_run",
]
