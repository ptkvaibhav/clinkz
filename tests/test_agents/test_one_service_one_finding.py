"""A target reachable by hostname and by address emits one finding per issue.

The pin for the two halves of the same defect, at the two seams that shipped it
in the Juice Shop variance envelope:

* run 2 emitted four security-header findings for two issues, because the
  header dedup keyed on the URL string that reached the class rather than on the
  service it names;
* run 3 emitted two IDOR findings for one crossing, because the class had no
  dedup at all and two discoverers spelled one path segment ``:id`` and ``:p3``.
"""

from __future__ import annotations

import pytest

from clinkz.agents.exploit import _crossing_path
from clinkz.models.methodology import (
    HeaderWeaknessSeverity,
    IDORExploitationType,
    IDORMethodologyResult,
    SecurityHeadersMethodologyResult,
)
from clinkz.tools.http_client import HTTPClientOutput

from .test_methodology_security_headers import _make_agent


def _parsed(address: str, *, redirect_chain: list[str] | None = None) -> HTTPClientOutput:
    """The REAL output model, never a test-local stand-in for it."""
    return HTTPClientOutput(
        tool_name="http_client",
        success=True,
        status_code=200,
        resolved_address=address,
        redirect_chain=redirect_chain or [],
    )


class TestSecurityHeadersOneService:
    def _result(self, origin: str) -> SecurityHeadersMethodologyResult:
        return SecurityHeadersMethodologyResult(
            phases_completed=3,
            origin=origin,
            observed_url=f"{origin}/",
            missing_headers=["Content-Security-Policy", "Referrer-Policy"],
            severity_rollup=HeaderWeaknessSeverity.MEDIUM,
        )

    def test_hostname_and_address_emit_one_finding_per_header(self) -> None:
        agent = _make_agent()
        # Both spellings were fetched and both reported the same peer address,
        # which is the only thing that may collapse them.
        agent._observed("http://clinkz-juiceshop:3000/", _parsed("172.20.0.2"))
        agent._observed("http://172.20.0.2:3000/", _parsed("172.20.0.2"))

        first = agent._security_headers_phase4_emit(self._result("http://clinkz-juiceshop:3000"))
        second = agent._security_headers_phase4_emit(self._result("http://172.20.0.2:3000"))

        assert len(first) == 2, "two missing headers on the first spelling"
        assert second == [], "the second spelling is the same service — nothing new"

    def test_unresolved_spellings_behave_exactly_as_before(self) -> None:
        """Nothing observed ⇒ nothing merges. The change is additive."""
        agent = _make_agent()
        first = agent._security_headers_phase4_emit(self._result("http://clinkz-juiceshop:3000"))
        second = agent._security_headers_phase4_emit(self._result("http://172.20.0.2:3000"))
        assert len(first) == 2
        assert len(second) == 2, "without a resolution these are two different origins"

    def test_two_names_on_one_address_still_emit_separately(self) -> None:
        """Virtual hosting: two applications, two postures, two findings."""
        agent = _make_agent()
        agent._observed("http://shop.example.com/", _parsed("203.0.113.7"))
        agent._observed("http://blog.example.com/", _parsed("203.0.113.7"))
        first = agent._security_headers_phase4_emit(self._result("http://shop.example.com"))
        second = agent._security_headers_phase4_emit(self._result("http://blog.example.com"))
        assert len(first) == 2
        assert len(second) == 2


class TestIDOROneCrossingOneFinding:
    def _result(self) -> IDORMethodologyResult:
        return IDORMethodologyResult(
            phases_completed=6,
            verified=True,
            verification_strength="verified",
            exploitation_type=IDORExploitationType.HORIZONTAL,
            synthesized_reference="2",
            indicator_observed="crossing confirmed",
            tier="multi_role",
            attribution="identical_rendering",
            absent_reference="900043392",
        )

    def test_two_parameter_spellings_of_one_crossing_emit_once(self) -> None:
        """``/rest/basket/:id`` and ``/rest/basket/:p3`` are one route.

        Both lower to the same dispatched request with the same arms and the
        same verdict. The parameter name is whichever discoverer found the
        route first; the request is the observation.
        """
        agent = _make_agent()
        # The endpoints as the discoverers emitted them: one route, two names
        # for the path segment. Both lower to GET /rest/basket/2.
        first = agent._idor_phase6_emit(
            "http://clinkz-juiceshop:3000/rest/basket/:id", "id", self._result()
        )
        second = agent._idor_phase6_emit(
            "http://clinkz-juiceshop:3000/rest/basket/:p3", "p3", self._result()
        )
        assert first is not None
        assert second is None, "one crossing, one finding"

    def test_a_different_crossing_still_emits(self) -> None:
        agent = _make_agent()
        first = agent._idor_phase6_emit(
            "http://clinkz-juiceshop:3000/rest/basket/:id", "id", self._result()
        )
        second = agent._idor_phase6_emit(
            "http://clinkz-juiceshop:3000/api/Users/:p3", "p3", self._result()
        )
        assert first is not None
        assert second is not None, "a different endpoint is a different observation"

    def test_the_same_crossing_under_another_host_spelling_emits_once(self) -> None:
        agent = _make_agent()
        agent._observed("http://clinkz-juiceshop:3000/", _parsed("172.20.0.2"))
        first = agent._idor_phase6_emit(
            "http://clinkz-juiceshop:3000/rest/basket/:id", "id", self._result()
        )
        second = agent._idor_phase6_emit(
            "http://172.20.0.2:3000/rest/basket/:p3", "p3", self._result()
        )
        assert first is not None
        assert second is None


class TestCrossingPath:
    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("http://h:3000/rest/basket/2", "/rest/basket/2"),
            ("http://172.20.0.2:3000/rest/basket/2", "/rest/basket/2"),
            ("http://h/api/Users/2?x=1", "/api/Users/2?x=1"),
            ("/already/relative", "/already/relative"),
        ],
    )
    def test_origin_is_stripped(self, url: str, expected: str) -> None:
        """The origin is carried separately, by the identity registry."""
        assert _crossing_path(url) == expected


class TestObservedSeam:
    def test_a_response_with_no_address_records_nothing(self) -> None:
        agent = _make_agent()
        agent._observed("http://host:3000/", _parsed(""))
        assert agent._origin_identity.identity("http://host:3000") == "http://host:3000"

    def test_the_seam_returns_the_response_unchanged(self) -> None:
        agent = _make_agent()
        parsed = HTTPClientOutput(
            tool_name="http_client",
            success=True,
            status_code=404,
            response_body="nope",
            response_headers={"X": "y"},
            resolved_address="10.0.0.1",
        )
        response = agent._observed("http://host:3000/", parsed)
        assert (response.status, response.body, response.headers) == (404, "nope", {"X": "y"})

    def test_a_redirected_request_observes_nothing(self) -> None:
        """Under ``-L`` the address is the LAST hop and the url is the FIRST.

        A target that redirects off-origin would otherwise have us file its own
        origin under somebody else's address, and a wrong collapse SUPPRESSES a
        finding. The one input a target can steer is refused.
        """
        agent = _make_agent()
        agent._observed(
            "http://target.example/", _parsed("203.0.113.9", redirect_chain=["http://other/"])
        )
        assert agent._origin_identity.identity("http://target.example") == "http://target.example"
