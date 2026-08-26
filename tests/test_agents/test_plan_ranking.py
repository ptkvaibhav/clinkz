"""The phase-3 ranking layer: pure, deterministic, and reaching every type.

Offline by construction — nothing here needs an agent, a target or a model,
which is the property that lets the same functions be replayed over the recorded
corpus by ``scripts/plan_variance_corpus.py``.
"""

from __future__ import annotations

from typing import Any

import pytest

from clinkz.agents._plan_ranking import (
    DEFAULT_ATTEMPT_CAP,
    TypeRanking,
    attempt_window,
    merge_llm_ranking,
    rank_cmdi,
    rank_file_upload,
    rank_idor,
    rank_lfi,
    rank_nosqli,
    rank_open_redirect,
    rank_sqli,
    rank_ssrf,
    rank_ssti,
)
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

# ===========================================================================
# attempt_window — the bound that replaced ranked[:3]
# ===========================================================================


class TestAttemptWindow:
    def test_with_nothing_supported_it_is_exactly_the_old_bound(self) -> None:
        ranked = list(InjectionType)[:5]
        assert attempt_window(ranked, []) == ranked[:DEFAULT_ATTEMPT_CAP]

    def test_a_supported_type_is_never_truncated(self) -> None:
        """The whole reason the cap moved off the ranking.

        ``[:3]`` cut by position, so a fourth type the target's own responses
        argued for was dropped in favour of a third that nothing backed.
        """
        ranked = [
            InjectionType.ERROR_BASED,
            InjectionType.BOOLEAN_BLIND,
            InjectionType.UNION_BASED,
            InjectionType.TIME_BLIND,
        ]
        window = attempt_window(ranked, ranked)
        assert window == ranked

    def test_the_unsupported_tail_is_never_empty(self) -> None:
        """ "The fingerprint did not back it" is not "the fingerprint refuted it"."""
        ranked = [
            InjectionType.ERROR_BASED,
            InjectionType.BOOLEAN_BLIND,
            InjectionType.UNION_BASED,
            InjectionType.TIME_BLIND,
        ]
        window = attempt_window(ranked, ranked[:3])
        assert window[:3] == ranked[:3]
        assert window[3] == InjectionType.TIME_BLIND

    def test_it_is_never_narrower_than_the_bound_it_replaced(self) -> None:
        ranked = list(InjectionType)
        for supported_count in range(len(ranked) + 1):
            window = attempt_window(ranked, ranked[:supported_count])
            assert len(window) >= min(DEFAULT_ATTEMPT_CAP, len(ranked))
            assert set(ranked[:supported_count]) <= set(window)

    def test_supported_order_follows_the_ranking_not_the_supported_set(self) -> None:
        ranked = [
            InjectionType.ERROR_BASED,
            InjectionType.BOOLEAN_BLIND,
            InjectionType.UNION_BASED,
        ]
        window = attempt_window(ranked, {InjectionType.UNION_BASED, InjectionType.ERROR_BASED})
        assert window[:2] == [InjectionType.ERROR_BASED, InjectionType.UNION_BASED]


class TestTypeRanking:
    def test_a_supported_type_absent_from_the_ranking_is_a_construction_error(self) -> None:
        with pytest.raises(ValueError, match="supported types absent"):
            TypeRanking((InjectionType.ERROR_BASED,), frozenset({InjectionType.UNION_BASED}))


class TestMergeLLMRanking:
    def test_the_model_orders_the_supported_block(self) -> None:
        ranking = TypeRanking(
            (LFIRetrievalType.DIRECT_READ, LFIRetrievalType.WRAPPER_EXTRACTION),
            frozenset({LFIRetrievalType.DIRECT_READ, LFIRetrievalType.WRAPPER_EXTRACTION}),
        )
        merged = merge_llm_ranking(
            [LFIRetrievalType.WRAPPER_EXTRACTION, LFIRetrievalType.DIRECT_READ], ranking
        )
        assert merged == [LFIRetrievalType.WRAPPER_EXTRACTION, LFIRetrievalType.DIRECT_READ]

    def test_it_may_not_shrink_the_vocabulary(self) -> None:
        ranking = rank_lfi(LFITraversalPrimitives(wrapper_support=["file://"]), {})
        merged = merge_llm_ranking([LFIRetrievalType.ERROR_BASED_PATH], ranking)
        assert set(ranking.ranked) <= set(merged)
        assert merged[0] == LFIRetrievalType.WRAPPER_EXTRACTION

    def test_it_does_not_order_the_unsupported_tail(self) -> None:
        """The corpus instance: a model ranked ``error_based_path`` — a leaked
        path, which is reachability rather than a read — ahead of
        ``wrapper_extraction``, and the confirmation was ``wrapper_extraction``.
        On the tail the model ranks hypotheses against no observation, and this
        layer has a stated ordering for that case."""
        ranking = rank_lfi(LFITraversalPrimitives(suffix_handling="appends_extension"), {})
        merged = merge_llm_ranking(
            [LFIRetrievalType.ERROR_BASED_PATH, LFIRetrievalType.WRAPPER_EXTRACTION], ranking
        )
        assert merged.index(LFIRetrievalType.WRAPPER_EXTRACTION) < merged.index(
            LFIRetrievalType.ERROR_BASED_PATH
        )


# ===========================================================================
# Per-class rankings
# ===========================================================================


class TestRankSQLi:
    def test_the_four_signals_map_one_to_one(self) -> None:
        assert rank_sqli(
            SQLDialect.MYSQL, InjectionPrimitives(), {"error_match": "x"}
        ).supported == frozenset({InjectionType.ERROR_BASED})
        assert rank_sqli(
            SQLDialect.MYSQL, InjectionPrimitives(), {"time_match": {}}
        ).supported == frozenset({InjectionType.TIME_BLIND})
        assert rank_sqli(
            SQLDialect.MYSQL, InjectionPrimitives(union_columns=3), {}
        ).supported == frozenset({InjectionType.UNION_BASED})
        assert rank_sqli(
            SQLDialect.MYSQL, InjectionPrimitives(break_prefix="'"), {}
        ).supported == frozenset({InjectionType.BOOLEAN_BLIND})

    def test_a_zero_column_count_is_still_a_count(self) -> None:
        """``is not None``, never truthiness — the same rule ``break_prefix``
        needs, applied to the field beside it."""
        assert (
            InjectionType.UNION_BASED
            in rank_sqli(SQLDialect.MYSQL, InjectionPrimitives(union_columns=0), {}).supported
        )

    def test_auth_bypass_is_not_the_rankers_to_add(self) -> None:
        """Its applicability is a protocol artifact on the REQUEST — an identity
        field beside a password-shaped one — which the dialect fingerprint cannot
        see. The agent's credential-field gate owns it."""
        for dialect in SQLDialect:
            ranking = rank_sqli(
                dialect, InjectionPrimitives(break_prefix="'"), {"error_match": "x"}
            )
            assert InjectionType.AUTH_BYPASS not in ranking.ranked


class TestRankIDOR:
    def test_horizontal_is_supported_whatever_the_predictability(self) -> None:
        for predictability in ("opaque", "sequential", "random"):
            ranking = rank_idor(IDORPrimitives(predictability=predictability))
            assert IDORExploitationType.HORIZONTAL in ranking.supported
            assert ranking.ranked[0] is IDORExploitationType.HORIZONTAL

    def test_the_authz_check_splits_pollution_from_function_level(self) -> None:
        with_check = rank_idor(IDORPrimitives(authz_check_present=True, unauth_status_observed=200))
        assert IDORExploitationType.PARAMETER_POLLUTION in with_check.supported
        assert IDORExploitationType.FUNCTION_LEVEL not in with_check.supported

        without = rank_idor(IDORPrimitives(authz_check_present=False, unauth_status_observed=200))
        assert IDORExploitationType.FUNCTION_LEVEL in without.supported
        assert IDORExploitationType.PARAMETER_POLLUTION not in without.supported

    def test_an_unauthenticated_refusal_supports_neither(self) -> None:
        ranking = rank_idor(IDORPrimitives(authz_check_present=False, unauth_status_observed=403))
        assert ranking.supported == frozenset({IDORExploitationType.HORIZONTAL})


class TestRankNoSQLi:
    def test_an_empty_fingerprint_ranks_nothing(self) -> None:
        """1,334 of the corpus's 1,351 NoSQL rankings, and the honest answer for
        every one of them: nothing NoSQL-shaped was observed."""
        ranking = rank_nosqli(NoSQLContext.UNKNOWN, NoSQLPrimitives())
        assert ranking.ranked == ()

    @pytest.mark.parametrize(
        "primitives",
        [
            NoSQLPrimitives(operators=["$ne"]),
            NoSQLPrimitives(error_signatures=["MongoError"]),
        ],
    )
    def test_an_observed_signal_survives_an_unresolved_context(
        self, primitives: NoSQLPrimitives
    ) -> None:
        ranking = rank_nosqli(NoSQLContext.UNKNOWN, primitives)
        assert ranking.ranked[0] is NoSQLInjectionType.OPERATOR_INJECTION

    def test_the_where_channel_never_leads_with_denial_of_service(self) -> None:
        ranking = rank_nosqli(NoSQLContext.STRING_WHERE, NoSQLPrimitives())
        assert ranking.ranked[0] is NoSQLInjectionType.WHERE_JS_INJECTION
        assert ranking.ranked[-1] is NoSQLInjectionType.NOSQL_DOS
        assert NoSQLInjectionType.NOSQL_DOS not in ranking.supported


class TestRankLFI:
    def test_source_disclosure_needs_no_php_filter(self) -> None:
        for primitives in (
            LFITraversalPrimitives(wrapper_support=["php://input"]),
            LFITraversalPrimitives(suffix_handling="appends_extension"),
        ):
            assert LFIRetrievalType.SOURCE_DISCLOSURE in rank_lfi(primitives, {}).supported

    def test_a_non_php_wrapper_alone_does_not_support_source_disclosure(self) -> None:
        ranking = rank_lfi(LFITraversalPrimitives(wrapper_support=["file://"]), {})
        assert LFIRetrievalType.WRAPPER_EXTRACTION in ranking.supported
        assert LFIRetrievalType.SOURCE_DISCLOSURE not in ranking.supported

    def test_a_leaked_path_is_never_a_read(self) -> None:
        ranking = rank_lfi(
            LFITraversalPrimitives(traversal_sequence="../", wrapper_support=["php://filter"]),
            {"absolute_passwd_match": True},
        )
        assert LFIRetrievalType.ERROR_BASED_PATH not in ranking.supported


class TestRankOpenRedirect:
    def test_every_bypass_type_it_owns_is_ranked_however_little_was_confirmed(self) -> None:
        """The reachability defect, stated as a property.

        A ranking built only out of pre-confirmed primitives contains nothing at
        all when phase 2 confirmed nothing, so the class could not probe a
        parameter its own probes had failed on — and the corpus holds four
        confirmations on exactly those parameters.

        ``allowlist_bypass`` is excluded on purpose: it is dispatched by its own
        branch, and a second route to one label is not reachability.
        """
        ranking = rank_open_redirect(RedirectPrimitives())
        assert set(ranking.ranked) == set(RedirectBypassType) - {
            RedirectBypassType.ALLOWLIST_BYPASS
        }
        assert ranking.supported == frozenset()

    def test_an_absent_validator_supports_the_direct_redirect(self) -> None:
        ranking = rank_open_redirect(RedirectPrimitives(validator_type="none"))
        assert RedirectBypassType.DIRECT_REDIRECT in ranking.supported
        assert ranking.ranked[0] is RedirectBypassType.DIRECT_REDIRECT

    def test_an_unconfirmed_primitive_stays_inside_the_window(self) -> None:
        """Three of the corpus's ``appended_url`` confirmations are on parameters
        whose phase-2 fingerprint says that primitive does not work."""
        ranking = rank_open_redirect(
            RedirectPrimitives(
                validator_type="none",
                working_bypass_primitives=["direct", "at_syntax", "protocol_relative"],
            )
        )
        assert RedirectBypassType.APPENDED_URL not in ranking.supported
        assert RedirectBypassType.APPENDED_URL in attempt_window(ranking.ranked, ranking.supported)


class TestRankSSRF:
    def test_no_reflection_defers_to_the_blind_path(self) -> None:
        """The branch that used to live only in the caller.

        A ranking that is correct only because somebody else guarded it breaks
        the first time it gains a second caller.
        """
        ranking = rank_ssrf(SSRFCapability(fetch_confirmed=True))
        assert list(ranking.ranked) == [SSRFExploitationType.BLIND_DEFERRED]
        assert ranking.supported == frozenset({SSRFExploitationType.BLIND_DEFERRED})

    def test_the_in_band_order_is_impact_first_regardless_of_the_capability(self) -> None:
        unfetched = rank_ssrf(SSRFCapability(content_reflected=True))
        fetched = rank_ssrf(SSRFCapability(content_reflected=True, fetch_confirmed=True))
        assert unfetched.ranked == fetched.ranked
        assert unfetched.ranked[0] is SSRFExploitationType.CLOUD_METADATA
        assert unfetched.supported == frozenset({SSRFExploitationType.REFLECTED_INTERNAL})
        assert len(fetched.supported) == 3


class TestRankSSTI:
    def test_a_blocked_gadget_still_reaches_the_escape(self) -> None:
        ranking = rank_ssti(
            SSTITemplateEngine.HANDLEBARS, SSTIPrimitives(evaluating_syntaxes=["{{}}"])
        )
        assert SSTIExploitationType.SANDBOX_ESCAPE in ranking.ranked
        assert SSTIExploitationType.RCE not in ranking.ranked

    def test_a_working_gadget_leads_with_rce(self) -> None:
        ranking = rank_ssti(
            SSTITemplateEngine.PUG,
            SSTIPrimitives(evaluating_syntaxes=["#{}"], rce_gadget_supported=True),
        )
        assert ranking.ranked[0] is SSTIExploitationType.RCE
        assert SSTIExploitationType.SANDBOX_ESCAPE in ranking.ranked


class TestRankFileUpload:
    def test_acceptance_is_what_the_fingerprint_backs(self) -> None:
        ranking = rank_file_upload(FileUploadRestrictions(working_extensions=[".php"]))
        assert ranking.supported == frozenset({FileUploadExecutionType.DIRECT_EXECUTION})

    def test_nothing_accepted_falls_to_the_client_side_lead(self) -> None:
        ranking = rank_file_upload(FileUploadRestrictions())
        assert list(ranking.ranked) == [FileUploadExecutionType.CLIENT_SIDE_ONLY]
        assert ranking.supported == frozenset()


# ===========================================================================
# The reachability guard
# ===========================================================================

#: A fingerprint space per class, wide enough that every type its vocabulary
#: contains should appear in some ranking. The domain the guard checks is
#: COMPUTED from the enum, so a type added to a vocabulary lands in the guard
#: without anyone remembering to add it.
_FINGERPRINT_SPACE: dict[Any, list[TypeRanking[Any]]] = {
    InjectionType: [
        rank_sqli(d, InjectionPrimitives(break_prefix=bp, union_columns=uc), ev)
        for d in SQLDialect
        for bp in (None, "'")
        for uc in (None, 2)
        for ev in ({}, {"error_match": "x"}, {"time_match": {}})
    ],
    CMDIExecutionType: [
        rank_cmdi(s, ShellPrimitives(working_time_payload=t), ev)
        for s in ShellType
        for t in (None, "x;sleep 5")
        for ev in ({}, {"os_probe": {}})
    ],
    SSRFExploitationType: [
        rank_ssrf(SSRFCapability(fetch_confirmed=f, content_reflected=r))
        for f in (False, True)
        for r in (False, True)
    ],
    IDORExploitationType: [
        rank_idor(IDORPrimitives(predictability=p, authz_check_present=a, unauth_status_observed=s))
        for p in ("opaque", "sequential")
        for a in (False, True)
        for s in (0, 200, 403)
    ],
    NoSQLInjectionType: [
        rank_nosqli(c, NoSQLPrimitives(operators=o, where_string_injectable=w))
        for c in NoSQLContext
        for o in ([], ["$ne"])
        for w in (False, True)
    ],
    SSTIExploitationType: [
        rank_ssti(e, SSTIPrimitives(evaluating_syntaxes=s, rce_gadget_supported=g))
        for e in SSTITemplateEngine
        for s in ([], ["{{}}"])
        for g in (False, True)
    ],
    LFIRetrievalType: [
        rank_lfi(LFITraversalPrimitives(wrapper_support=w, suffix_handling=s), ev)
        for w in ([], ["file://"], ["php://filter"])
        for s in ("none", "appends_extension", "truncatable_nul")
        for ev in ({}, {"absolute_passwd_match": True})
    ],
    RedirectBypassType: [
        rank_open_redirect(RedirectPrimitives(validator_type=v, working_bypass_primitives=w))
        for v in ("none", "exact", "strict_or_unknown")
        for w in ([], ["direct"], ["appended_url", "unicode_lookalike"])
    ],
    FileUploadExecutionType: [
        rank_file_upload(FileUploadRestrictions(working_extensions=e))
        for e in ([], [".php"], [".svg"], [".gif"])
    ],
}

#: Types no fingerprint can rank, each with the reason. Exemption is DECLARED:
#: "nobody classified it" and "it needs no ranking" are different facts, and a
#: type that is silently unrankable is exactly the defect this guard exists for
#: — ``allowlist_bypass`` was unreachable for the life of the class because its
#: ranking was built only out of primitives phase 2 had confirmed.
_UNRANKABLE: dict[Any, str] = {
    InjectionType.AUTH_BYPASS: (
        "added and removed by the agent's credential-field gate, on a protocol "
        "artifact in the REQUEST that no dialect fingerprint carries"
    ),
    SSRFExploitationType.BLIND_OOB_CONFIRMED: (
        "an OUTCOME the out-of-band reap records, not a hypothesis to plan "
        "against — nothing dispatches it"
    ),
    RedirectBypassType.ALLOWLIST_BYPASS: (
        "dispatched by its own branch, which harvests a token the validator's "
        "substring check accepts and builds four attacker-URL shapes around it; "
        "ranking it here would be a second route to one label whose phase 4 has "
        "no deterministic build, so a model would invent the payload"
    ),
}


@pytest.mark.parametrize("vocabulary", list(_FINGERPRINT_SPACE), ids=lambda v: v.__name__)
def test_every_type_in_a_vocabulary_is_reachable_or_declared_unrankable(
    vocabulary: Any,
) -> None:
    rankings = _FINGERPRINT_SPACE[vocabulary]
    reachable = {t for ranking in rankings for t in ranking.ranked}
    unreachable = set(vocabulary) - reachable
    undeclared = {t for t in unreachable if t not in _UNRANKABLE}
    assert not undeclared, (
        f"{sorted(t.value for t in undeclared)} can be dispatched but no fingerprint "
        "ranks them — declare the reason in _UNRANKABLE or give them a signal"
    )
    stale = {t for t in _UNRANKABLE if t in reachable and type(t) is vocabulary}
    assert not stale, (
        f"{sorted(t.value for t in stale)} are declared unrankable but a fingerprint "
        "ranks them — the exemption outlived what it described"
    )


@pytest.mark.parametrize("vocabulary", list(_FINGERPRINT_SPACE), ids=lambda v: v.__name__)
def test_every_supported_type_survives_its_own_window(vocabulary: Any) -> None:
    """The invariant the attempt window exists to hold."""
    for ranking in _FINGERPRINT_SPACE[vocabulary]:
        window = attempt_window(ranking.ranked, ranking.supported)
        assert ranking.supported <= set(window)
        if ranking.ranked:
            assert len(window) >= min(DEFAULT_ATTEMPT_CAP, len(ranking.ranked))
