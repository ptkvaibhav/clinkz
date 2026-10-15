"""Write-crossing candidates rank on the OWNING FIELD the methodology reads (R29).

The endpoint set below is the write-surface slice of the #145 ride-along
(``d29c80ee``): 36 write-crossing candidates, every one at relevance grade 0,
and a per-class cap of 8. The class's parameter signal used to be mass
assignment's state-change vocabulary — ``token``, ``password_new`` — so
``/rest/2fa/setup`` outranked ``/api/Complaints``, whose ``UserId`` is the field
the engine's only confirmed cross-principal write was proven through, and the
cap kept the former. The rows are copied from the stored ``endpoints`` table:
method, URL and parameter names only, no response data.
"""

from __future__ import annotations

import logging

from clinkz.agents._idor_oracle import field_names_owner
from clinkz.agents._principal import Principal
from clinkz.agents.exploit import (
    ExploitAgent,
    ExploitPlan,
    ExploitTask,
    _endpoint_class_signals,
    _endpoint_class_sort_key,
)
from clinkz.models.scan import Endpoint, MethodEvidence, ParamLocation

_O = "http://clinkz-juiceshop:3000"
_METHOD = "_test_write_crossing"
_CAP = 8

# (verb, path, params) as recorded on d29c80ee — every row NAMED.
_JUICE_SHOP_WRITES: list[tuple[str, str, list[str]]] = [
    ("POST", "/api/Users", ["username", "email", "role", "deluxeToken", "lastLoginIp",
                            "profileImage", "isActive"]),
    ("POST", "/rest/user/login", ["email", "password"]),
    ("POST", "/api/Addresss", ["UserId", "fullName", "mobileNum", "zipCode", "streetAddress",
                               "city", "state", "country"]),
    ("POST", "/api/BasketItems", ["ProductId", "BasketId", "quantity"]),
    ("POST", "/api/Cards", ["UserId", "fullName", "cardNum", "expMonth", "expYear"]),
    ("POST", "/rest/2fa/setup", ["password", "setupToken", "initialToken"]),
    ("POST", "/rest/2fa/verify", ["tmpToken", "totpToken"]),
    ("POST", "/rest/user/data-export", []),
    ("POST", "/rest/user/erasure-request", []),
    ("POST", "/rest/user/reset-password", []),
    ("POST", "/walletExploitAddress", []),
    ("POST", "/walletNFTVerify", []),
    ("PUT", "/api/Addresss/:p3", ["p3"]),
    ("PUT", "/api/BasketItems/:p3", ["p3"]),
    ("PUT", "/rest/order-history/:p3/delivery-status", ["p3"]),
    ("PUT", "/rest/wallet/balance", []),
    ("PATCH", "/rest/products/reviews", []),
    ("POST", "/api/Complaints", ["UserId", "message", "file"]),
    ("POST", "/api/Feedbacks", ["UserId", "comment", "rating"]),
    ("POST", "/api/Recycles", ["err"]),
    ("POST", "/api/SecurityAnswers", []),
    ("POST", "/rest/2fa/disable", ["password"]),
    ("POST", "/rest/basket/:p3/checkout", ["p3", "couponData", "orderDetails"]),
    ("POST", "/rest/chat", ["messages"]),
    ("POST", "/rest/deluxe-membership", ["paymentMode", "paymentId"]),
    ("POST", "/rest/memories", ["image", "caption"]),
    ("POST", "/rest/products/reviews", ["id"]),
    ("POST", "/submitKey", []),
    ("PUT", "/api/Hints/:p3", ["p3"]),
    ("PUT", "/api/Products/:p3", ["p3"]),
    ("PUT", "/api/Quantitys/:p3", ["p3"]),
    ("PUT", "/rest/basket/:p3/coupon/:p5", ["p3", "p5"]),
    ("PUT", "/rest/continue-code-findIt/apply/:p4", ["p4"]),
    ("PUT", "/rest/continue-code-fixIt/apply/:p4", ["p4"]),
    ("PUT", "/rest/continue-code/apply/:p4", ["p4"]),
    ("PUT", "/rest/products/:p3/reviews", ["p3"]),
]  # fmt: skip


def _endpoints() -> list[Endpoint]:
    out = []
    for verb, path, params in _JUICE_SHOP_WRITES:
        out.append(
            Endpoint(
                url=f"{_O}{path}",
                method=verb,
                params=params,
                content_type="application/json" if params else None,
                param_locations={
                    p: ParamLocation.JSON_BODY for p in params if not p.startswith("p")
                },
                method_evidence=MethodEvidence.NAMED,
            )
        )
    return out


def _agent() -> ExploitAgent:
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.write_crossing.ranking")
    agent._session_headers = {}
    agent._session_cookies = {}
    agent._principals = (
        Principal(role="customer", privilege=0, primary=False, username="a"),
        Principal(role="admin", privilege=10, primary=True, username="b"),
    )
    return agent


def _bucket() -> list[str]:
    agent = _agent()
    ranked = [
        ep
        for ep in _endpoints()
        if _METHOD in ExploitAgent._applicable_methods_for_endpoint(agent, ep)
    ]
    assert len(ranked) == len(_JUICE_SHOP_WRITES), "every row is a write-crossing candidate"
    ranked.sort(key=lambda ep: _endpoint_class_sort_key(_METHOD, ep))
    return [ep.url.removeprefix(_O) for ep in ranked]


def test_every_endpoint_carrying_an_owning_field_survives_the_cap() -> None:
    """The four ``UserId`` writes are exactly the ones the methodology can attribute."""
    kept = _bucket()[:_CAP]
    for path in ("/api/Complaints", "/api/Feedbacks", "/api/Addresss", "/api/Cards"):
        assert path in kept, f"{path} carries UserId and was cut at cap {_CAP}: {kept}"


def test_a_token_vocabulary_no_owned_object_carries_no_longer_outranks_it() -> None:
    """``/rest/2fa/setup`` scored on ``setupToken``; it now ranks behind Complaints."""
    order = _bucket()
    assert order.index("/api/Complaints") < order.index("/rest/2fa/setup")
    assert "/rest/2fa/setup" not in order[:_CAP]


def test_the_param_signal_is_the_methodologys_own_owning_field_vocabulary() -> None:
    """One vocabulary for one question: the ranking reads what owning_fields reads."""
    complaints = Endpoint(url=f"{_O}/api/Complaints", method="POST", params=["UserId"])
    two_fa = Endpoint(url=f"{_O}/rest/2fa/setup", method="POST", params=["setupToken"])
    assert field_names_owner("UserId") and not field_names_owner("setupToken")
    assert _endpoint_class_signals(_METHOD, complaints)[0] is True
    assert _endpoint_class_signals(_METHOD, two_fa)[0] is False


def test_the_final_plan_and_candidate_pool_are_traced_as_sets() -> None:
    """The producer half of the regression check: members, not counts."""
    agent = _agent()
    traced: list[dict[str, object]] = []
    agent._trace_methodology_phase = lambda **kw: traced.append(kw)  # type: ignore[method-assign]
    agent._plan_candidate_keys = {(_METHOD, f"{_O}/api/Complaints"), (_METHOD, f"{_O}/api/Cards")}
    plan = ExploitPlan(
        tasks=[ExploitTask(test_method=_METHOD, endpoint_url=f"{_O}/api/Cards", tier=1)],
        tier1_count=1,
    )

    import clinkz.agents.exploit as exploit_module

    original = exploit_module.get_active_trace_writer
    exploit_module.get_active_trace_writer = lambda: object()  # type: ignore[assignment]
    try:
        agent._trace_plan_sets(plan)
    finally:
        exploit_module.get_active_trace_writer = original
    (record,) = traced
    extra = record["extra"]
    assert isinstance(extra, dict)
    assert extra["planned"] == [[_METHOD, f"{_O}/api/Cards"]]
    assert [_METHOD, f"{_O}/api/Complaints"] in extra["candidates"]
