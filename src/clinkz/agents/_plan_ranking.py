"""Phase-3 type ranking: the fingerprint decides the SET, the cap guards the tail.

Every six-phase methodology reaches a phase-3 checkpoint that answers one
question — *which exploitation types is this parameter worth attempting, and in
what order?* — and then attempts a bounded prefix of the answer. Two defects
lived in that seam, and both are the same defect wearing different clothes.

**The order was not a function of the observation.** Phase 3 asked a model, and
the same phase-2 fingerprint presented to the same model minutes apart came back
in a different order: over the recorded corpus, 48 of the 64 fingerprints ranked
more than once produced at least two distinct orders, and one SQLi fingerprint
ranked 210 times produced 16. An engagement whose plan is drawn from a
distribution cannot be re-run, cannot be regression-tested, and cannot be
compared against its own baseline — which is why a plan-order defect is a
measurement problem before it is a coverage problem.

**The fingerprint was not read.** Phase 2 counts the UNION columns and proves the
breakout context, and the deterministic ranking then ignored both. Replayed
against the recorded corpus, the pre-existing fallback rankings keep **770 of the
833** confirmations the engine made that a current vocabulary can even express —
41 of the 63 they miss are IDOR ``horizontal``, dropped because
``predictability == "opaque"`` was read as *there is no horizontal access* when
it means only *you cannot guess the next identifier*.

So the ranking here is a pure function of the phase-2 fingerprint, and it returns
two things rather than one:

``ranked``
    the full order, deterministic for a given observation;
``supported``
    the subset the fingerprint **empirically backs** — the types some phase-2
    probe actually observed the precondition for.

:func:`attempt_window` then bounds the attempt list by that split rather than by
a bare ``[:3]``. A supported type is *never* truncated, because dropping a type
the target's own responses argued for is what truncation should never do; the cap
applies to the unsupported tail, which is hypothesis rather than evidence.

The tail is never empty (:data:`_MIN_UNSUPPORTED_ATTEMPTS`). Phase-2 probes are
not exhaustive — the corpus holds three ``appended_url`` open-redirect
confirmations on parameters where phase 2 reported that primitive did not work —
so "the fingerprint did not back it" is not "the fingerprint refuted it", and one
probe past the evidence is what keeps an unbacked type inside the window at all.

Pure and offline-testable by construction: nothing here sends a request, reads
configuration, or consults a model. That is what lets the whole layer be replayed
against the 3,998 recorded rankings under ``outputs/`` without touching a
target (``python scripts/plan_variance_corpus.py``).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from clinkz.models.methodology import (
    CMDIExecutionType,
    FileUploadExecutionType,
    FileUploadRestrictions,
    IDORExploitationType,
    IDORPrimitives,
    InjectionPrimitives,
    InjectionType,
    LFIRetrievalType,
    LFITraversalPrimitives,
    NoSQLContext,
    NoSQLInjectionType,
    NoSQLPrimitives,
    RedirectBypassType,
    RedirectPrimitives,
    ShellPrimitives,
    ShellType,
    SQLDialect,
    SSRFCapability,
    SSRFExploitationType,
    SSTIExploitationType,
    SSTIPrimitives,
    SSTITemplateEngine,
)

__all__ = [
    "DEFAULT_ATTEMPT_CAP",
    "TypeRanking",
    "attempt_window",
    "merge_llm_ranking",
    "rank_cmdi",
    "rank_file_upload",
    "rank_idor",
    "rank_lfi",
    "rank_nosqli",
    "rank_open_redirect",
    "rank_sqli",
    "rank_ssrf",
    "rank_ssti",
]

#: How many types a phase-4/5 loop attempts when the fingerprint backs none of
#: them. Unchanged from the ``[:3]`` this layer replaces, so a fingerprint that
#: says nothing costs exactly what it used to.
DEFAULT_ATTEMPT_CAP = 3

#: Unsupported types always attempted, however many supported ones there are.
#: Phase 2 probes a hypothesis; it does not exhaust one. A primitive phase 2
#: reported as not working has confirmed three open redirects in the recorded
#: corpus, so the cheapest honest hedge is one probe past the evidence — and it
#: is also what keeps a type no fingerprint ever backs inside the window.
#:
#: The value is measured rather than chosen. Replayed over the corpus's 835
#: confirmations: 0 keeps 830 at +0.7% attempts, 1 keeps 833 at +5.6%, and 2
#: keeps 833 at +14.6% — so 1 is the only setting that buys anything and 2 is
#: strictly dominated. The two confirmations no setting recovers are
#: ``js_protocol`` and ``file_scheme``, enum members that no longer exist, and
#: no ranking can produce a type the vocabulary has retired.
_MIN_UNSUPPORTED_ATTEMPTS = 1


@dataclass(frozen=True)
class TypeRanking[T: StrEnum]:
    """A deterministic phase-3 answer: an order, and which of it is evidenced.

    Attributes:
        ranked: Every type worth attempting, most-promising first. A pure
            function of the phase-2 fingerprint — the same observation always
            produces the same tuple.
        supported: The subset of ``ranked`` some phase-2 probe empirically
            backed. Never truncated by :func:`attempt_window`.
    """

    ranked: tuple[T, ...]
    supported: frozenset[T]

    def __post_init__(self) -> None:
        stray = self.supported - set(self.ranked)
        if stray:
            raise ValueError(
                f"supported types absent from the ranking: {sorted(t.value for t in stray)}"
            )


def attempt_window[T: StrEnum](
    ranked: Sequence[T],
    supported: Iterable[T],
    *,
    cap: int = DEFAULT_ATTEMPT_CAP,
) -> list[T]:
    """The types phase 4/5 should attempt, in order.

    Every fingerprint-supported type survives, in ``ranked`` order, followed by
    unsupported ones up to *cap* — and always at least
    :data:`_MIN_UNSUPPORTED_ATTEMPTS` of them, so a class whose whole vocabulary
    goes unsupported still probes and a type no fingerprint backs is still
    reachable.

    The window is therefore never narrower than the ``[:3]`` it replaces: with no
    supported types it is exactly ``ranked[:cap]``, and each supported type only
    ever displaces a hypothesis with an observation.

    Args:
        ranked: The deterministic order, most-promising first.
        supported: Types the phase-2 fingerprint empirically backed.
        cap: Attempts to allow when nothing is supported.

    Returns:
        The ordered attempt list.
    """
    backed = set(supported)
    keep = [t for t in ranked if t in backed]
    tail = [t for t in ranked if t not in backed]
    room = max(_MIN_UNSUPPORTED_ATTEMPTS, cap - len(keep))
    return keep + tail[:room]


def merge_llm_ranking[T: StrEnum](llm_ranked: Sequence[T], ranking: TypeRanking[T]) -> list[T]:
    """Fold a model's order into the deterministic set: it orders, we scope.

    The model orders the **supported** block — those are evidenced alternatives,
    and which evidenced channel to try first is a judgement worth having a model
    for. It does not order the unsupported tail, because there it is ranking
    hypotheses against no observation at all, and this layer has a stated
    ordering for that case while the model has only a prior. The corpus holds
    the instance: a model ranked LFI ``error_based_path`` — a leaked path, which
    is reachability rather than a read, and which this layer never supports —
    ahead of ``wrapper_extraction``, and the confirmation was
    ``wrapper_extraction``.

    It may not shrink the vocabulary either: every deterministic type the model
    omitted is appended rather than dropped.

    Args:
        llm_ranked: The parsed model ranking (possibly empty).
        ranking: The deterministic ranking for the same fingerprint.

    Returns:
        The merged order. Feed it to :func:`attempt_window` with
        ``ranking.supported``.
    """
    named = list(dict.fromkeys(llm_ranked))
    backed = [t for t in named if t in ranking.supported]
    backed += [t for t in ranking.ranked if t in ranking.supported and t not in backed]
    tail = [t for t in ranking.ranked if t not in ranking.supported]
    tail += [t for t in named if t not in ranking.supported and t not in tail]
    return backed + tail


def _order[T: StrEnum](canonical: Sequence[T], supported: Iterable[T]) -> tuple[T, ...]:
    """Canonical order with the supported types pulled to the front."""
    backed = set(supported)
    return (*[t for t in canonical if t in backed], *[t for t in canonical if t not in backed])


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

#: Canonical order, applied to the supported block and to the unsupported tail
#: alike. It is ordered by how much each channel still works when *its own*
#: signal did not fire, because that is the only case the tail describes: an
#: error string is a single cheap request; a boolean differential needs nothing
#: but a quote character; a UNION whose column count is a guess dies on "different
#: number of result columns"; a timing differential is the slowest and noisiest.
#:
#: Boolean-blind sitting above union-based is the one place this departs from
#: reading the four signals as symmetric, and the corpus is unambiguous about
#: why. Three of the signals are near-necessary for their type — 49 of 49
#: ``time_blind`` confirmations carry ``time_match``, 138 of 139 ``error_based``
#: carry ``error_match``, 38 of 42 ``union_based`` carry a column count — but
#: only 28 of 79 ``boolean_blind`` confirmations carry a ``break_prefix``.
#: Phase 2 gives up on the breakout often, and the boolean channel confirms
#: anyway from the quote character alone. Its signal is sufficient, never
#: necessary, so the type cannot sit at the bottom of the tail: ranking it last
#: drops 51 of the corpus's confirmations, and every ordering that keeps it off
#: the bottom scores full parity at identical attempt cost.
_SQLI_CANONICAL: tuple[InjectionType, ...] = (
    InjectionType.ERROR_BASED,
    InjectionType.BOOLEAN_BLIND,
    InjectionType.UNION_BASED,
    InjectionType.TIME_BLIND,
)


def rank_sqli(
    dialect: SQLDialect,
    primitives: InjectionPrimitives,
    dialect_evidence: dict[str, Any],
) -> TypeRanking[InjectionType]:
    """Rank SQLi injection types on the four signals phase 2 actually produces.

    Each of the four in-band types has exactly one phase-2 observation that is
    its precondition, and phase 2 records all four:

    ============= ================================================
    type          the observation that backs it
    ============= ================================================
    error_based   ``error_match`` — a DB error surfaced in the body
    union_based   ``union_columns`` — the front query's column count
    boolean_blind ``break_prefix`` — the confirmed closing context
    time_blind    ``time_match`` — a measured delay differential
    ============= ================================================

    The previous ranking read only the first and last of those, and 12 of the
    corpus's 42 ``union_based`` confirmations sit on fingerprints where phase 2
    had **counted the columns** and the ranking put UNION fourth anyway. That is
    not a heuristic being imperfect; it is a measurement being discarded.

    ``break_prefix`` and ``union_columns`` are tested with ``is not None``, never
    for truthiness: ``break_prefix == ""`` is a *confirmed* breakout into a value
    already in statement position, and reading it as absent would throw away the
    unquoted-context proof exactly when it is cheapest to exploit.

    ``stacked`` is appended on MSSQL/Postgres and is never supported — the
    dialect permits multi-statement execution, but nothing here observed it
    surviving the driver.

    ``auth_bypass`` is deliberately absent: applicability is a protocol artifact
    on the *request*, not on the dialect, and it is added or removed afterwards
    by the agent's own credential-field gate.

    Args:
        dialect: The fingerprinted SQL dialect.
        primitives: Phase-2 primitives, including the two this ranking exists
            to stop discarding.
        dialect_evidence: The phase-2 evidence map, keyed by signal name.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    supported: set[InjectionType] = set()
    if "error_match" in dialect_evidence:
        supported.add(InjectionType.ERROR_BASED)
    if primitives.union_columns is not None:
        supported.add(InjectionType.UNION_BASED)
    if primitives.break_prefix is not None:
        supported.add(InjectionType.BOOLEAN_BLIND)
    if "time_match" in dialect_evidence:
        supported.add(InjectionType.TIME_BLIND)

    ranked = list(_order(_SQLI_CANONICAL, supported))
    if dialect in (SQLDialect.MSSQL, SQLDialect.POSTGRES):
        ranked.append(InjectionType.STACKED)
    return TypeRanking(tuple(ranked), frozenset(supported))


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

_CMDI_CANONICAL: tuple[CMDIExecutionType, ...] = (
    CMDIExecutionType.DIRECT_EXEC,
    CMDIExecutionType.BLIND_TIME,
    CMDIExecutionType.ERROR_BASED,
    CMDIExecutionType.BLIND_OOB,
)


def rank_cmdi(
    shell_type: ShellType,
    primitives: ShellPrimitives,
    shell_evidence: dict[str, Any],
) -> TypeRanking[CMDIExecutionType]:
    """Rank command-injection types on what phase 2 got the shell to do.

    ``direct_exec`` is backed by ``os_probe`` — phase 2 already saw command
    output reach the response body, so the channel is proven before phase 4
    builds anything. ``blind_time`` is backed by ``working_time_payload``, the
    delay payload phase 2 measured. ``error_based`` and ``blind_oob`` are ranked
    but never supported: neither has a phase-2 observation of its own here.

    ``shell_type`` is unused and deliberately in the signature — it is what a
    payload is *built* from, not evidence about which channel can be observed,
    and a ranking that keyed on it would be ranking on a guess about the target
    rather than on a probe of it.

    Args:
        shell_type: The fingerprinted shell (see above).
        primitives: Phase-2 shell primitives.
        shell_evidence: The phase-2 evidence map, keyed by probe name.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    del shell_type
    supported: set[CMDIExecutionType] = set()
    if "os_probe" in shell_evidence:
        supported.add(CMDIExecutionType.DIRECT_EXEC)
    if primitives.working_time_payload is not None:
        supported.add(CMDIExecutionType.BLIND_TIME)
    return TypeRanking(_order(_CMDI_CANONICAL, supported), frozenset(supported))


# ---------------------------------------------------------------------------
# Server-side request forgery
# ---------------------------------------------------------------------------

#: Impact order, and deliberately NOT reordered by evidence. All three in-band
#: types share one precondition — the fetcher's response came back in-band — so
#: the fingerprint does not discriminate between them, and the window attempts
#: every one of them either way. What the order decides is which confirms
#: FIRST, and the phase-5 loop stops there, so ranking a loopback reach ahead of
#: an instance-metadata read would report the smaller finding on a target where
#: both hold.
#:
#: The recorded corpus is not evidence against this, though it looks like it:
#: ``cloud_metadata`` led every in-band ranking ever made and confirmed zero
#: times, while all seven in-band confirmations were ``internal_service`` or
#: ``reflected_internal``. None of those targets was in a cloud. That is a fact
#: about the corpus, not about the ranking.
_SSRF_IN_BAND: tuple[SSRFExploitationType, ...] = (
    SSRFExploitationType.CLOUD_METADATA,
    SSRFExploitationType.INTERNAL_SERVICE,
    SSRFExploitationType.REFLECTED_INTERNAL,
)


def rank_ssrf(cap: SSRFCapability) -> TypeRanking[SSRFExploitationType]:
    """Rank SSRF exploitation types on the fetcher's observed capability.

    The predecessor took ``cap`` and returned a constant, which was safe only
    because its single caller had already made the one decision that matters —
    no reflected content means no in-band type can confirm — before calling it.
    A ranking that is correct only because somebody else guarded it is a ranking
    that breaks the first time it gains a second caller, so the blind branch
    lives here now.

    ``supported`` and the order answer different questions here, and only the
    first is the fingerprint's. ``reflected_internal`` is backed directly by
    ``content_reflected`` — the fetcher's body already came back in-band, which
    is that type's whole precondition; ``internal_service`` and
    ``cloud_metadata`` additionally need the fetcher to reach an address it was
    not given, so they are supported only once ``fetch_confirmed`` holds. The
    ORDER stays impact-first regardless (see :data:`_SSRF_IN_BAND`), because
    all three are attempted anyway and the loop stops at the first confirmation.

    Args:
        cap: The phase-2 capability fingerprint.

    Returns:
        The deterministic ranking. ``blind_deferred`` alone when no content is
        reflected — supported when a fetch was nonetheless confirmed, which is
        precisely the blind-SSRF case an out-of-band collaborator can settle.
    """
    if not cap.content_reflected:
        blind = SSRFExploitationType.BLIND_DEFERRED
        supported = frozenset({blind}) if cap.fetch_confirmed else frozenset()
        return TypeRanking((blind,), supported)

    supported = {SSRFExploitationType.REFLECTED_INTERNAL}
    if cap.fetch_confirmed:
        supported |= {SSRFExploitationType.INTERNAL_SERVICE, SSRFExploitationType.CLOUD_METADATA}
    return TypeRanking(_SSRF_IN_BAND, frozenset(supported))


# ---------------------------------------------------------------------------
# Insecure direct object reference
# ---------------------------------------------------------------------------

_IDOR_CANONICAL: tuple[IDORExploitationType, ...] = (
    IDORExploitationType.HORIZONTAL,
    IDORExploitationType.FUNCTION_LEVEL,
    IDORExploitationType.PARAMETER_POLLUTION,
    IDORExploitationType.VERTICAL,
)


def rank_idor(primitives: IDORPrimitives) -> TypeRanking[IDORExploitationType]:
    """Rank IDOR exploitation types — and never withhold ``horizontal``.

    The defect this replaces was one line: ``if predictability != "opaque"``
    gated ``horizontal`` out. Opacity says *you cannot guess the next
    identifier*; it says nothing about whether the object behind a known one is
    protected. 1,087 of the corpus's 1,186 gate-closed IDOR fingerprints are
    opaque, ``horizontal`` accounts for 48 of the 49 recorded IDOR
    confirmations, and replaying the old ranking drops 41 of them.

    Phase 3 is reached only after the divergence gate, which means a reference
    probe already answered differently from the captured baseline. That is the
    horizontal signal, and it has fired by the time this function is called — so
    ``horizontal`` is supported unconditionally here, and ``predictability``
    decides how phase 4 *synthesises* a reference, not whether phase 3 may rank
    the type.

    The remaining three split on the authorization check:
    ``parameter_pollution`` needs one to confuse, so it is backed by
    ``authz_check_present``; ``function_level`` is the complementary observation
    — no check present and the unauthenticated request answered with success —
    which is the fingerprint under the corpus's one ``function_level``
    confirmation. ``vertical`` has no fingerprint field of its own and stays in
    the tail.

    Args:
        primitives: The phase-2 authorization-model fingerprint.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    supported = {IDORExploitationType.HORIZONTAL}
    if primitives.authz_check_present:
        supported.add(IDORExploitationType.PARAMETER_POLLUTION)
    elif 200 <= primitives.unauth_status_observed < 300:
        supported.add(IDORExploitationType.FUNCTION_LEVEL)
    return TypeRanking(_order(_IDOR_CANONICAL, supported), frozenset(supported))


# ---------------------------------------------------------------------------
# NoSQL injection
# ---------------------------------------------------------------------------


def rank_nosqli(
    context: NoSQLContext,
    primitives: NoSQLPrimitives,
) -> TypeRanking[NoSQLInjectionType]:
    """Rank NoSQL injection types on the phase-2 context fingerprint.

    Two things were wrong and only one of them was a hole.

    The default branch returned ``[]`` for *every* unknown context, discarding
    an observed operator set and an observed error signature along with the
    genuinely empty case. It now keys on those: operators or NoSQL error
    signatures observed with no context resolved still support operator
    injection and the boolean differential. On the recorded corpus this changes
    nothing — all 1,334 unknown-context episodes carry no operators, no error
    signature and no injectable ``$where`` — and returning ``[]`` for *those* is
    correct, not a hole. Widening them would fire NoSQL payloads at 1,334
    parameters on targets that showed no sign of a document store.

    The hole that did bite is the ``$where`` branch, which ranked ``nosql_dos``
    **first**: on a client engagement the leading attempt against a confirmed
    JavaScript-evaluating handler was a denial-of-service payload. Server-side
    JS injection is the provable effect and leads now; the DoS is last and never
    supported.

    Args:
        context: The fingerprinted query context.
        primitives: The phase-2 primitives.

    Returns:
        The deterministic ranking; empty when nothing NoSQL-shaped was observed.
    """
    if context in (NoSQLContext.JSON_OPERATOR, NoSQLContext.QUERY_BRACKET):
        return TypeRanking(
            (
                NoSQLInjectionType.OPERATOR_INJECTION,
                NoSQLInjectionType.AUTH_BYPASS,
                NoSQLInjectionType.BOOLEAN_BLIND,
            ),
            frozenset({NoSQLInjectionType.OPERATOR_INJECTION, NoSQLInjectionType.BOOLEAN_BLIND}),
        )
    if context == NoSQLContext.STRING_WHERE or primitives.where_string_injectable:
        return TypeRanking(
            (
                NoSQLInjectionType.WHERE_JS_INJECTION,
                NoSQLInjectionType.BOOLEAN_BLIND,
                NoSQLInjectionType.NOSQL_DOS,
            ),
            frozenset({NoSQLInjectionType.WHERE_JS_INJECTION}),
        )
    if primitives.operators or primitives.error_signatures:
        return TypeRanking(
            (NoSQLInjectionType.OPERATOR_INJECTION, NoSQLInjectionType.BOOLEAN_BLIND),
            frozenset({NoSQLInjectionType.OPERATOR_INJECTION}),
        )
    return TypeRanking((), frozenset())


# ---------------------------------------------------------------------------
# Server-side template injection
# ---------------------------------------------------------------------------


def rank_ssti(
    engine: SSTITemplateEngine,
    primitives: SSTIPrimitives,
) -> TypeRanking[SSTIExploitationType]:
    """Rank SSTI exploitation types — including the escape that was unreachable.

    ``sandbox_escape`` appeared in no branch of the predecessor and so could
    never be attempted, which quietly meant the class had no answer for its most
    common real shape: an engine that demonstrably evaluates an expression while
    the direct RCE gadget is blocked. That is exactly when an escape is the
    hypothesis, so it now follows ``expression_eval`` whenever a syntax was
    observed evaluating.

    ``expression_eval`` is the always-available proof and is supported by an
    observed evaluating syntax. ``rce`` is supported by ``rce_gadget_supported``
    and leads when it holds — and is not ranked at all without it, because
    "reach RCE despite the missing gadget" is what the escape IS, so a bare
    ``rce`` attempt there is the same hypothesis spelled worse. The escape
    itself is ranked but never supported: nothing in phase 2 observes a sandbox
    boundary.

    Args:
        engine: The fingerprinted template engine (unused: it selects the payload
            *syntax*, and evaluation is proven by ``evaluating_syntaxes``).
        primitives: The phase-2 engine primitives.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    del engine
    supported: set[SSTIExploitationType] = set()
    if primitives.evaluating_syntaxes:
        supported.add(SSTIExploitationType.EXPRESSION_EVAL)
    if primitives.rce_gadget_supported:
        supported.add(SSTIExploitationType.RCE)
        ranked = (
            SSTIExploitationType.RCE,
            SSTIExploitationType.EXPRESSION_EVAL,
            SSTIExploitationType.SANDBOX_ESCAPE,
        )
    else:
        ranked = (
            SSTIExploitationType.EXPRESSION_EVAL,
            SSTIExploitationType.SANDBOX_ESCAPE,
        )
    return TypeRanking(ranked, frozenset(supported))


# ---------------------------------------------------------------------------
# Local file inclusion
# ---------------------------------------------------------------------------

_LFI_CANONICAL: tuple[LFIRetrievalType, ...] = (
    LFIRetrievalType.DIRECT_READ,
    LFIRetrievalType.WRAPPER_EXTRACTION,
    LFIRetrievalType.SOURCE_DISCLOSURE,
    LFIRetrievalType.ERROR_BASED_PATH,
)

#: A wrapper whose presence proves the handler is running a PHP stream layer —
#: which is what makes reading a *source file* rather than a data file possible.
_LFI_PHP_WRAPPER_PREFIX = "php://"


def rank_lfi(
    primitives: LFITraversalPrimitives,
    prim_evidence: dict[str, Any],
) -> TypeRanking[LFIRetrievalType]:
    """Rank LFI retrieval types on what phase 2 proved it could read.

    ``source_disclosure`` was reachable from exactly one branch — the one guarded
    on ``php://filter`` — so a target exposing ``php://input`` and appending an
    extension to the parameter could not be ranked for it at all. Both of the
    corpus's ``source_disclosure`` confirmations have precisely that fingerprint,
    and replaying the old ranking loses both. Its signal is the PHP stream layer
    (**any** ``php://`` wrapper) or a suffix the handler concatenates, since an
    appended ``.php`` is what makes the parameter name a source file.

    ``direct_read`` and ``wrapper_extraction`` are backed by a strict SUPERSET of
    :meth:`ExploitAgent._lfi_primitive_confirms` — every primitive that predicate
    reads, plus the phase-2 evidence keys it has no access to. The two are
    deliberately not one predicate: that one asks whether phase 2 proved a
    payload that *reads a file*, and phase 4 answers it by rebuilding that exact
    payload instead of synthesising, so widening it would have phase 4 rebuild a
    payload nobody proved. This asks only whether an observation backs
    *attempting* the type.

    ``error_based_path`` is ranked but never supported — a leaked path is
    reachability, not a read.

    Args:
        primitives: The phase-2 path-handling primitives.
        prim_evidence: The phase-2 evidence map, keyed by probe name.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    supported: set[LFIRetrievalType] = set()
    if (
        "traversal_signature_match" in prim_evidence
        or prim_evidence.get("absolute_passwd_match")
        or prim_evidence.get("nul_truncation_works")
        or primitives.prefix_required
        or primitives.traversal_sequence is not None
        or primitives.suffix_handling == "truncatable_nul"
    ):
        supported.add(LFIRetrievalType.DIRECT_READ)
    wrappers = list(primitives.wrapper_support)
    if wrappers:
        supported.add(LFIRetrievalType.WRAPPER_EXTRACTION)
    if any(w.startswith(_LFI_PHP_WRAPPER_PREFIX) for w in wrappers) or (
        primitives.suffix_handling == "appends_extension"
    ):
        supported.add(LFIRetrievalType.SOURCE_DISCLOSURE)
    return TypeRanking(_order(_LFI_CANONICAL, supported), frozenset(supported))


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------

#: ``ALLOWLIST_BYPASS`` is deliberately absent, and it is the one member of this
#: vocabulary that is. It has its own dispatch path — harvest a token the
#: validator's substring check accepts, embed it in four attacker-URL shapes,
#: verify each — with its own payload builder and its own phase-5 event. Ranking
#: it here would open a SECOND route to the same label whose phase 4 has no
#: deterministic build at all, so the model would be asked to invent a payload
#: and a confirmation could carry the ``allowlist_bypass`` label with no
#: harvested token behind it. One label, one route.
_REDIRECT_CANONICAL: tuple[RedirectBypassType, ...] = (
    RedirectBypassType.DIRECT_REDIRECT,
    RedirectBypassType.APPENDED_URL,
    RedirectBypassType.AT_SYNTAX,
    RedirectBypassType.PROTOCOL_RELATIVE,
    RedirectBypassType.UNICODE_LOOKALIKE,
)

#: The phase-2 probe label that confirms each bypass type, where one exists.
_REDIRECT_PRIMITIVE_LABEL: dict[RedirectBypassType, str] = {
    RedirectBypassType.DIRECT_REDIRECT: "direct",
    RedirectBypassType.APPENDED_URL: "appended_url",
    RedirectBypassType.AT_SYNTAX: "at_syntax",
    RedirectBypassType.PROTOCOL_RELATIVE: "protocol_relative",
    RedirectBypassType.UNICODE_LOOKALIKE: "unicode_lookalike",
}


def rank_open_redirect(primitives: RedirectPrimitives) -> TypeRanking[RedirectBypassType]:
    """Rank redirect bypass types, ranking every one of them.

    The predecessor built its list only from primitives phase 2 had already
    confirmed, so ``appended_url`` was reachable only when pre-confirmed. Phase
    2's bypass probes are a sample, not an exhaustion: three of the corpus's
    ``appended_url`` confirmations and its one ``unicode_lookalike``
    confirmation are on parameters whose phase-2 fingerprint did **not** list
    that primitive as working, and under the old ranking all four were
    unreachable.

    So every type this ranking owns is ranked, always; the confirmed ones are
    the supported set and lead. ``direct_redirect`` is additionally supported
    when the validator fingerprinted as absent, since there is then nothing to
    bypass. ``allowlist_bypass`` is not this ranking's to own — see
    :data:`_REDIRECT_CANONICAL`.

    Args:
        primitives: The phase-2 redirect-handling primitives.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    working = set(primitives.working_bypass_primitives)
    supported = {t for t, label in _REDIRECT_PRIMITIVE_LABEL.items() if label in working}
    if primitives.validator_type == "none":
        supported.add(RedirectBypassType.DIRECT_REDIRECT)
    return TypeRanking(_order(_REDIRECT_CANONICAL, supported), frozenset(supported))


# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------

_UPLOAD_SCRIPT_EXTS = frozenset({".php", ".asp", ".aspx", ".jsp", ".jspx"})
_UPLOAD_ATYPICAL_EXTS = frozenset({".phtml", ".phar", ".svg", ".html", ".py", ".rb", ".pl", ".sh"})


def rank_file_upload(
    restrictions: FileUploadRestrictions,
) -> TypeRanking[FileUploadExecutionType]:
    """Rank upload execution types on the extensions the store actually accepted.

    Unchanged in order from its predecessor — this class already had the shape
    the rest of the layer is being moved to, and its ranking loses none of the
    corpus's 158 upload confirmations. What is new is the declared ``supported``
    set, so the attempt window can stop truncating an accepted extension.

    Note that acceptance is not execution: a supported type here means the store
    took the file, and whether the server *runs* it is what phase 5 decides.

    Args:
        restrictions: The phase-2 restriction fingerprint.

    Returns:
        The deterministic ranking for this fingerprint.
    """
    exts = set(restrictions.working_extensions)
    ranked: list[FileUploadExecutionType] = []
    supported: set[FileUploadExecutionType] = set()
    if exts & _UPLOAD_ATYPICAL_EXTS:
        ranked.append(FileUploadExecutionType.INTERPRETER_MISCONFIG)
        supported.add(FileUploadExecutionType.INTERPRETER_MISCONFIG)
    if exts & _UPLOAD_SCRIPT_EXTS:
        ranked.append(FileUploadExecutionType.DIRECT_EXECUTION)
        supported.add(FileUploadExecutionType.DIRECT_EXECUTION)
    if exts:
        # An uploaded artefact plus a separate LFI primitive elsewhere — a last
        # resort once anything at all is accepted, and never evidenced here.
        ranked.append(FileUploadExecutionType.INCLUSION_CHAIN)
    if not ranked:
        ranked.append(FileUploadExecutionType.CLIENT_SIDE_ONLY)
    return TypeRanking(tuple(ranked), frozenset(supported))
