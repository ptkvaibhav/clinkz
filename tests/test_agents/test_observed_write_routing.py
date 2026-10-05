"""Part 1 pin: write-family classes are routed on an OBSERVED write verb.

``MethodEvidence`` exists to tell a verb the engine READ apart from the
``GET`` the JS miner used to spell an unread one. This module pins the one
consequence that makes it load-bearing on the dispatch path: an endpoint whose
verb is ``UNREAD`` never reaches a write-family class, even when its ``method``
string is a write verb — because an unread verb is no evidence the route
writes, and a terminal, mutating methodology dispatched against it is invariant
88 plus a residual mutation in another principal's data.

The exclusion used to hold only because ``UNREAD`` mapped to ``GET`` and ``GET``
is not in the write set. These tests key on the EVIDENCE, so the guarantee
survives a producer that carries an unread verb as anything else.
"""

from __future__ import annotations

import logging

from clinkz.agents._principal import Principal
from clinkz.agents.exploit import (
    WRITE_VERBS,
    ExploitAgent,
    _is_observed_write_surface,
)
from clinkz.models.scan import Endpoint, MethodEvidence

# Every write-family class the applicability gate routes on the observed verb.
_WRITE_FAMILY = {
    "_test_csrf",
    "_test_file_upload",
    "_test_xss_stored",
    "_test_brute_force",
    "_test_input_validation",
    "_test_mass_assignment",
    "_test_write_crossing",
}


def _agent() -> ExploitAgent:
    """A bare agent that can answer ``_applicable_methods_for_endpoint``."""
    agent = ExploitAgent.__new__(ExploitAgent)
    agent._logger = logging.getLogger("test.observed.write")
    agent._session_headers = {}
    agent._session_cookies = {}
    # Two principals, so ``_test_write_crossing`` has the second identity its
    # methodology needs — otherwise the class could not appear whatever the
    # verb, and "UNREAD excludes write_crossing" would be vacuously true.
    agent._principals = (
        Principal(role="customer", privilege=0, primary=False, username="a"),
        Principal(role="admin", privilege=10, primary=True, username="b"),
    )
    return agent


def test_predicate_admits_an_observed_write_verb() -> None:
    for verb in sorted(WRITE_VERBS):
        named = Endpoint(url="http://t/x", method=verb, method_evidence=MethodEvidence.NAMED)
        assert _is_observed_write_surface(named), f"NAMED {verb} is an observed write"
    # A verb that was NOT named but could not have been (a bare fetch) is still a
    # reading, not a guess — it admits too. (In practice the idiom default is
    # GET; the point is that the predicate keys on evidence, not on which
    # observation produced it.)
    platform = Endpoint(
        url="http://t/x", method="POST", method_evidence=MethodEvidence.PLATFORM_DEFAULT
    )
    assert _is_observed_write_surface(platform)


def test_predicate_rejects_a_read_verb_and_an_unread_one() -> None:
    named_get = Endpoint(url="http://t/x", method="GET", method_evidence=MethodEvidence.NAMED)
    assert not _is_observed_write_surface(named_get), "GET is not a write verb"
    unread_get = Endpoint(url="http://t/x", method="GET", method_evidence=MethodEvidence.UNREAD)
    assert not _is_observed_write_surface(unread_get)
    # THE pin: an unread verb that happens to carry a write method string is
    # still excluded — the evidence, not the string, decides.
    unread_post = Endpoint(url="http://t/x", method="POST", method_evidence=MethodEvidence.UNREAD)
    assert not _is_observed_write_surface(unread_post), (
        "an UNREAD verb is no evidence the route writes, whatever its method string"
    )


def test_unread_post_endpoint_reaches_no_write_family_class() -> None:
    agent = _agent()
    unread_post = Endpoint(
        url="http://t/api/thing",
        method="POST",
        params=["name"],
        method_evidence=MethodEvidence.UNREAD,
    )
    methods = set(agent._applicable_methods_for_endpoint(unread_post))
    leaked = methods & _WRITE_FAMILY
    assert not leaked, f"UNREAD endpoint admitted to write-family class(es): {sorted(leaked)}"


def test_named_post_endpoint_reaches_the_write_family() -> None:
    agent = _agent()
    named_post = Endpoint(
        url="http://t/api/thing",
        method="POST",
        params=["name"],
        method_evidence=MethodEvidence.NAMED,
    )
    methods = set(agent._applicable_methods_for_endpoint(named_post))
    # Every write-family class that is gated purely on the verb (not on a path
    # word or a held JWT) must be present.
    expected = {
        "_test_csrf",
        "_test_file_upload",
        "_test_xss_stored",
        "_test_brute_force",
        "_test_input_validation",
        "_test_mass_assignment",
        "_test_write_crossing",
    }
    missing = expected - methods
    assert not missing, f"observed-write endpoint missing write-family class(es): {sorted(missing)}"


def test_the_only_difference_between_the_two_is_the_evidence() -> None:
    """Same URL, same method string, same params — only ``method_evidence``
    differs — and that alone moves every write-family class."""
    agent = _agent()
    common = {"url": "http://t/api/thing", "method": "POST", "params": ["name"]}
    named = set(
        agent._applicable_methods_for_endpoint(
            Endpoint(**common, method_evidence=MethodEvidence.NAMED)
        )
    )
    unread = set(
        agent._applicable_methods_for_endpoint(
            Endpoint(**common, method_evidence=MethodEvidence.UNREAD)
        )
    )
    assert (named - unread) >= _WRITE_FAMILY
    assert not (unread & _WRITE_FAMILY)
