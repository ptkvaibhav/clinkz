"""Unit tests for the adaptive JWT (JSON Web Token) attack methodology phases.

JWT is the first **Tier-2** primitive — cryptographic token manipulation, not
injection — but it reuses the six-phase scaffolding. Mirrors the XXE/SSTI
methodology tests: each phase is exercised in isolation with a simulated
JWT-gated server (``_jwt_send_with_token``) and a silent LLM (so the
deterministic fallbacks drive), plus end-to-end confirms (alg:none / weak-secret)
and an N/A check on a non-JWT stack — no false emission.

Confirmation is **fully in-band**: a server is modelled as accepting / rejecting
a presented token, and the methodology confirms only when a forged token is
accepted like the valid baseline while a broken-signature token is rejected.
"""

from __future__ import annotations

import asyncio
import warnings
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock

import jwt
import pytest

from clinkz.agents.exploit import (
    _JWT_WEAK_SECRETS,
    ExploitAgent,
    PageAnalysis,
    _HTTPResponse,
)
from clinkz.llm.base import LLMClient, LLMMessage
from clinkz.models.methodology import JWTAlgorithm, JWTAttackType, JWTFingerprint
from clinkz.models.scope import EngagementScope, ScopeEntry, ScopeType
from clinkz.state import StateStore
from clinkz.tools.resolver import ToolResolver

SCOPE = EngagementScope(
    name="methodology-jwt-test",
    targets=[ScopeEntry(value="example.com", type=ScopeType.DOMAIN)],
)
PAGE = PageAnalysis(url="http://example.com/rest/basket/1", body="", status=200)
WEAK_SECRET = "secret"  # in _JWT_WEAK_SECRETS
STRONG_SECRET = "Zx9!q2-NOT-in-the-weak-list-7f3a8b1c2d4e5f6071"
FUTURE = 9999999999


# ---------------------------------------------------------------------------
# Mocks / fixtures
# ---------------------------------------------------------------------------


class _SilentLLM(LLMClient):
    """LLM whose ``generate_text`` returns "" so deterministic fallbacks drive."""

    async def reason(
        self, messages: list[LLMMessage], tools: list[dict[str, Any]] | None = None
    ) -> Any:
        raise NotImplementedError

    async def research(self, query: str) -> str:
        return ""

    async def generate_text(self, prompt: str) -> str:
        return ""


def _make_state() -> AsyncMock:
    state = AsyncMock(spec=StateStore)
    state.get_findings = AsyncMock(return_value=[])
    state.add_finding = AsyncMock(return_value="finding-001")
    state.get_new_endpoints = AsyncMock(return_value=[])
    state.log_action = AsyncMock()
    return state


def _make_agent(token: str | None = None) -> ExploitAgent:
    agent = ExploitAgent(
        llm=_SilentLLM(),
        tools=[],
        scope=SCOPE,
        state=_make_state(),
        engagement_id="methodology-jwt-test",
        resolver=ToolResolver(),
        persistent_kb=None,
    )
    agent._methodology_llm = agent.llm
    if token is not None:
        agent._session_headers = {"Authorization": f"Bearer {token}"}
    return agent


def _resp(status: int, body: str = "", headers: dict[str, str] | None = None) -> _HTTPResponse:
    return _HTTPResponse(status=status, body=body, headers=headers or {})


def _sign(claims: dict[str, Any], secret: str, alg: str = "HS256") -> str:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return jwt.encode(claims, secret, algorithm=alg)


def _valid(secret: str = WEAK_SECRET, **extra: Any) -> str:
    claims = {"sub": "user1", "role": "user", "exp": FUTURE, **extra}
    return _sign(claims, secret)


def _server(
    *,
    secret: str | None = None,
    accept_alg_none: bool = False,
    accept_predicate: Callable[[str, dict[str, Any]], bool] | None = None,
) -> Callable[[str, str | None], Any]:
    """Build a fake ``_jwt_send_with_token`` modelling a JWT-gated endpoint.

    ``secret`` set ⇒ the server verifies the signature (valid token → 200,
    broken-sig → 401); ``accept_alg_none`` ⇒ it also accepts unsigned tokens;
    ``accept_predicate`` ⇒ a custom accept rule (e.g. accept-everything = ungated).
    """

    async def send(url: str, token: str | None) -> _HTTPResponse:
        if token is None:
            return _resp(401, "Unauthorized")
        try:
            header = jwt.get_unverified_header(token)
        except Exception:
            return _resp(401, "bad token")
        if accept_predicate is not None:
            return _resp(200, '{"ok":1}') if accept_predicate(token, header) else _resp(401)
        if accept_alg_none and str(header.get("alg", "")).lower() == "none":
            return _resp(200, '{"basket":"victim"}')
        if secret is not None:
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    jwt.decode(
                        token,
                        secret,
                        algorithms=[str(header.get("alg", "HS256"))],
                        options={"verify_exp": False},
                    )
                return _resp(200, '{"basket":"ok"}')
            except Exception:
                return _resp(401, "Unauthorized")
        return _resp(401, "Unauthorized")

    return send


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Phase 1 — token acquisition + endpoint mapping
# ---------------------------------------------------------------------------


def test_session_token_from_bearer_header():
    agent = _make_agent(_valid())
    acquired = agent._jwt_session_token()
    assert acquired is not None
    carrier, token = acquired
    assert carrier == "authorization_bearer"
    assert token == _valid()


def test_session_token_from_cookie():
    agent = _make_agent()
    tok = _valid()
    agent._session_cookies = {"token": tok}
    acquired = agent._jwt_session_token()
    assert acquired is not None
    assert acquired[0] == "jwt_cookie:token"
    assert acquired[1] == tok


def test_session_token_none_without_jwt():
    agent = _make_agent()
    agent._session_headers = {}
    agent._session_cookies = {"PHPSESSID": "abc123notajwt"}
    assert agent._jwt_session_token() is None


def test_looks_like_jwt():
    assert ExploitAgent._looks_like_jwt(_valid()) is True
    assert ExploitAgent._looks_like_jwt("not.a.jwt") is False
    assert ExploitAgent._looks_like_jwt("only-one-segment") is False
    assert ExploitAgent._looks_like_jwt("") is False


def test_phase1_gated_endpoint_is_candidate():
    agent = _make_agent(_valid())
    agent._jwt_send_with_token = _server(secret=WEAK_SECRET)
    candidate, evidence = _run(agent._jwt_phase1_acquire_and_map(PAGE))
    assert candidate is not None
    assert evidence["gated"] is True
    assert evidence["valid_status"] == 200
    assert evidence["broken_sig_status"] == 401


def test_phase1_ungated_endpoint_declines():
    # Server accepts ANY token incl. a broken signature ⇒ not signature-gated ⇒
    # JWT forgery can't be cleanly verified here ⇒ decline (honesty).
    agent = _make_agent(_valid())
    agent._jwt_send_with_token = _server(accept_predicate=lambda t, h: True)
    candidate, evidence = _run(agent._jwt_phase1_acquire_and_map(PAGE))
    assert candidate is None
    assert evidence["gated"] is False


def test_phase1_na_without_token():
    agent = _make_agent()  # no session JWT
    agent._session_headers = {}
    agent._http_get = AsyncMock(return_value=_resp(200, "no token here"))
    candidate, evidence = _run(agent._jwt_phase1_acquire_and_map(PAGE))
    assert candidate is None
    assert evidence["acquired"] is False


# ---------------------------------------------------------------------------
# Phase 2 — fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_hs256_with_claims():
    agent = _make_agent()
    fp = agent._jwt_phase2_fingerprint(_valid())
    assert fp.algorithm == JWTAlgorithm.HS256
    assert fp.signature_present is True
    assert "role" in fp.claim_names
    assert "role" in fp.privileged_claim_names
    assert fp.has_expiry is True
    assert fp.expired is False
    assert fp.kid_present is False


def test_fingerprint_detects_kid_and_expired():
    agent = _make_agent()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tok = jwt.encode(
            {"sub": "u", "exp": 1}, WEAK_SECRET, algorithm="HS256", headers={"kid": "k1"}
        )
    fp = agent._jwt_phase2_fingerprint(tok)
    assert fp.kid_present is True
    assert "kid" in fp.header_params
    assert fp.has_expiry is True
    assert fp.expired is True


def test_fingerprint_alg_none_token():
    agent = _make_agent()
    none_tok = agent._jwt_alg_none_tokens({"sub": "u"})[0]
    fp = agent._jwt_phase2_fingerprint(none_tok)
    assert fp.algorithm == JWTAlgorithm.NONE
    assert fp.signature_present is False


def test_classify_alg():
    assert ExploitAgent._jwt_classify_alg("HS256") == JWTAlgorithm.HS256
    assert ExploitAgent._jwt_classify_alg("none") == JWTAlgorithm.NONE
    assert ExploitAgent._jwt_classify_alg("None") == JWTAlgorithm.NONE
    assert ExploitAgent._jwt_classify_alg("RS256") == JWTAlgorithm.RS256
    assert ExploitAgent._jwt_classify_alg("weird") == JWTAlgorithm.UNKNOWN


# ---------------------------------------------------------------------------
# Phase 3 — attack-type ranking (conditioned on fingerprint + preconditions)
# ---------------------------------------------------------------------------


def test_ranking_hmac_signed_token():
    agent = _make_agent()
    fp = JWTFingerprint(
        algorithm=JWTAlgorithm.HS256,
        signature_present=True,
        privileged_claim_names=["role"],
        has_expiry=True,
    )
    ranked = _run(agent._jwt_phase3_rank_attacks(fp))
    assert JWTAttackType.ALG_NONE in ranked
    assert JWTAttackType.WEAK_SECRET in ranked
    # No asymmetric algorithm ⇒ confusion is precondition-filtered out.
    assert JWTAttackType.ALGORITHM_CONFUSION not in ranked


def test_ranking_asymmetric_token():
    agent = _make_agent()
    fp = JWTFingerprint(algorithm=JWTAlgorithm.RS256, signature_present=True)
    ranked = _run(agent._jwt_phase3_rank_attacks(fp))
    assert JWTAttackType.ALGORITHM_CONFUSION in ranked
    # HMAC weak-secret does not apply to an RS256 token.
    assert JWTAttackType.WEAK_SECRET not in ranked


def test_ranking_unsigned_token_excludes_alg_none():
    # An already-unsigned token can't be "downgraded" to alg:none as a bypass.
    agent = _make_agent()
    fp = JWTFingerprint(algorithm=JWTAlgorithm.NONE, signature_present=False)
    ranked = _run(agent._jwt_phase3_rank_attacks(fp))
    assert JWTAttackType.ALG_NONE not in ranked


def test_precondition_gates():
    fp_hmac = JWTFingerprint(algorithm=JWTAlgorithm.HS256, signature_present=True)
    assert ExploitAgent._jwt_attack_precondition(JWTAttackType.WEAK_SECRET, fp_hmac) is True
    assert ExploitAgent._jwt_attack_precondition(JWTAttackType.KID_INJECTION, fp_hmac) is False
    fp_kid = JWTFingerprint(algorithm=JWTAlgorithm.HS256, signature_present=True, kid_present=True)
    assert ExploitAgent._jwt_attack_precondition(JWTAttackType.KID_INJECTION, fp_kid) is True


# ---------------------------------------------------------------------------
# Phase 4 — synthesis (deterministic; crypto can't be LLM'd)
# ---------------------------------------------------------------------------


def test_synthesize_alg_none_strips_signature():
    agent = _make_agent()
    fp = agent._jwt_phase2_fingerprint(_valid())
    synth = _run(agent._jwt_phase4_synthesize(JWTAttackType.ALG_NONE, fp, _valid(), PAGE))
    assert synth is not None
    # Every variant is unsigned (empty signature segment) with an alg:none header.
    for variant in synth["tokens"]:
        assert variant.endswith(".")
        assert ExploitAgent._jwt_classify_alg(jwt.get_unverified_header(variant)["alg"]) == (
            JWTAlgorithm.NONE
        )
    # Case-variant bypasses are included (none/None/NONE/...).
    algs = {jwt.get_unverified_header(t)["alg"] for t in synth["tokens"]}
    assert {"none", "None", "NONE"}.issubset(algs)


def test_synthesize_weak_secret_cracks_and_resigns():
    agent = _make_agent()
    token = _valid(WEAK_SECRET)
    fp = agent._jwt_phase2_fingerprint(token)
    synth = _run(agent._jwt_phase4_synthesize(JWTAttackType.WEAK_SECRET, fp, token, PAGE))
    assert synth is not None
    # The re-signed token verifies under the cracked weak secret.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        jwt.decode(synth["token"], WEAK_SECRET, algorithms=["HS256"], options={"verify_exp": False})


def test_synthesize_weak_secret_declines_on_strong_secret():
    agent = _make_agent()
    token = _valid(STRONG_SECRET)
    fp = agent._jwt_phase2_fingerprint(token)
    synth = _run(agent._jwt_phase4_synthesize(JWTAttackType.WEAK_SECRET, fp, token, PAGE))
    assert synth is None  # bounded list, strong secret not in it


def test_synthesize_claim_tamper_requires_cracked_secret():
    agent = _make_agent()
    # Weak secret ⇒ a validly-signed elevated token can be minted.
    token = _valid(WEAK_SECRET)
    fp = agent._jwt_phase2_fingerprint(token)
    synth = _run(agent._jwt_phase4_synthesize(JWTAttackType.CLAIM_TAMPERING, fp, token, PAGE))
    assert synth is not None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        claims = jwt.decode(
            synth["token"], WEAK_SECRET, algorithms=["HS256"], options={"verify_exp": False}
        )
    assert claims["role"] == "admin"  # elevated
    # Strong secret ⇒ no valid signing key ⇒ decline (the alg:none finding covers it).
    strong_token = _valid(STRONG_SECRET)
    fp_strong = agent._jwt_phase2_fingerprint(strong_token)
    declined = _run(
        agent._jwt_phase4_synthesize(JWTAttackType.CLAIM_TAMPERING, fp_strong, strong_token, PAGE)
    )
    assert declined is None


def test_synthesize_expired_requires_cracked_secret():
    agent = _make_agent()
    token = _valid(WEAK_SECRET)
    fp = agent._jwt_phase2_fingerprint(token)
    synth = _run(agent._jwt_phase4_synthesize(JWTAttackType.EXPIRED_ACCEPTANCE, fp, token, PAGE))
    assert synth is not None
    claims = ExploitAgent._jwt_unverified_claims(synth["token"])
    assert claims["exp"] < 9_000_000_000  # back-dated to the past


def test_synthesize_confusion_declines_without_jwks():
    agent = _make_agent()
    agent._http_get = AsyncMock(return_value=_resp(404, ""))  # no JWKS served
    fp = JWTFingerprint(algorithm=JWTAlgorithm.RS256, signature_present=True)
    synth = _run(
        agent._jwt_phase4_synthesize(JWTAttackType.ALGORITHM_CONFUSION, fp, _valid(), PAGE)
    )
    assert synth is None


# ---------------------------------------------------------------------------
# Phase 5 — in-band verification
# ---------------------------------------------------------------------------


def test_token_accepted_logic():
    valid, broken = _resp(200), _resp(401)
    assert ExploitAgent._jwt_token_accepted(_resp(200), valid, broken) is True
    assert ExploitAgent._jwt_token_accepted(_resp(401), valid, broken) is False
    assert ExploitAgent._jwt_token_accepted(_resp(403), valid, broken) is False
    assert ExploitAgent._jwt_token_accepted(_resp(0), valid, broken) is False


def test_phase5_rejects_unaccepted_forgery():
    agent = _make_agent()
    agent._jwt_send_with_token = _server(secret=STRONG_SECRET)  # rejects forgeries
    synth = {"token": "x.y.z", "tokens": ["x.y.z"], "summary": "redacted"}
    baselines = (_resp(401), _resp(200), _resp(401))
    verified, observed = _run(
        agent._jwt_phase5_verify(PAGE, JWTAttackType.ALG_NONE, synth, baselines)
    )
    assert verified is False
    assert "rejected" in observed


# ---------------------------------------------------------------------------
# End-to-end — confirm / non-finding
# ---------------------------------------------------------------------------


def test_e2e_alg_none_confirms():
    token = _valid(WEAK_SECRET)
    agent = _make_agent(token)
    agent._jwt_send_with_token = _server(secret=WEAK_SECRET, accept_alg_none=True)
    findings = _run(agent._test_jwt(PAGE))
    assert len(findings) == 1
    assert "jwt" in findings[0].title.lower()
    assert findings[0].severity.value == "critical"
    assert any("attack_type=alg_none" in ev for ev in findings[0].evidence)


def test_e2e_weak_secret_confirms_when_alg_none_blocked():
    token = _valid(WEAK_SECRET)
    agent = _make_agent(token)
    # alg:none blocked, but the HMAC secret is a common default ⇒ weak-secret forge.
    agent._jwt_send_with_token = _server(secret=WEAK_SECRET, accept_alg_none=False)
    result = _run(agent._run_jwt_methodology(PAGE))
    assert result.verified is True
    assert result.attack_type == JWTAttackType.WEAK_SECRET


def test_e2e_hardened_is_verification_honest_non_finding():
    token = _valid(STRONG_SECRET)
    agent = _make_agent(token)
    agent._jwt_send_with_token = _server(secret=STRONG_SECRET, accept_alg_none=False)
    findings = _run(agent._test_jwt(PAGE))
    assert findings == []  # ran the phases, confirmed nothing


def test_e2e_na_without_jwt_no_emission():
    agent = _make_agent()  # no JWT held
    agent._session_headers = {}
    agent._http_get = AsyncMock(return_value=_resp(200, "no token"))
    findings = _run(agent._test_jwt(PAGE))
    assert findings == []


# ---------------------------------------------------------------------------
# Safety — bounded secret list, redaction, dedup
# ---------------------------------------------------------------------------


def test_weak_secret_list_is_bounded():
    # A proof-of-vuln dictionary, never an exhaustive crack.
    assert len(_JWT_WEAK_SECRETS) <= 50
    assert len(set(_JWT_WEAK_SECRETS)) == len(_JWT_WEAK_SECRETS)  # no dups


def test_finding_redacts_token_and_secret():
    token = _valid(WEAK_SECRET)
    agent = _make_agent(token)
    agent._jwt_send_with_token = _server(secret=WEAK_SECRET, accept_alg_none=True)
    findings = _run(agent._test_jwt(PAGE))
    assert findings
    evidence_blob = " ".join(findings[0].evidence) + " " + findings[0].description
    # The raw captured token must never appear verbatim.
    assert token not in evidence_blob
    # No raw weak-secret literal leaks either.
    assert "'secret'" not in evidence_blob
    # The redacted summary shows claim NAMES, not the signature.
    assert "claims=[" in evidence_blob


def test_redact_never_contains_signature():
    agent = _make_agent()
    token = _valid(WEAK_SECRET)
    redacted = agent._jwt_redact(token)
    signature = token.rsplit(".", 1)[1]
    assert signature not in redacted
    assert "<sig elided>" in redacted


def test_per_engagement_dedup():
    # Strong secret ⇒ only alg:none is viable (weak-secret/claim-tamper decline),
    # so the engagement-wide property "alg:none accepted" emits exactly once.
    token = _valid(STRONG_SECRET)
    agent = _make_agent(token)
    agent._jwt_send_with_token = _server(secret=STRONG_SECRET, accept_alg_none=True)
    first = _run(agent._test_jwt(PAGE))
    assert len(first) == 1
    assert "alg_none" in agent._jwt_emitted_attacks
    # A second JWT-gated endpoint must not re-emit the same already-confirmed class.
    second = _run(
        agent._test_jwt(PageAnalysis(url="http://example.com/api/Users/2", body="", status=200))
    )
    assert second == []


@pytest.mark.parametrize("alg_label", ["none", "None", "NONE"])
def test_alg_none_case_variants_built(alg_label):
    agent = _make_agent()
    tokens = agent._jwt_alg_none_tokens({"sub": "u"})
    algs = {jwt.get_unverified_header(t)["alg"] for t in tokens}
    assert alg_label in algs
