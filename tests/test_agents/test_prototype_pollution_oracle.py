"""The endpoint this class has to get right is the one that is NOT vulnerable.

``/api/v2/notifications`` in ``docker/protopoll/app.js`` is a recursive merge
into a stored record, reached by ``POST`` with a JSON body, answering 200 with
the merged record — the same method, the same content type, the same nesting,
the same status and the same body shape as ``/api/v2/profile``, which IS
pollutable. Its guard is three lines inside the merge. A class that cannot
separate those two reports every deep-merge endpoint on the internet, so this
file asserts the sound endpoints first and the vulnerable one after.

``/api/v2/preferences`` is the second way to be wrong, and the commoner one: a
shallow spread copies ``__proto__`` on as an ordinary own property, nothing
reaches the prototype, and ``JSON.stringify`` then echoes the injected key
straight back. The SOUND endpoint reflects the payload and the vulnerable one
does not, so an oracle that grades the response to its own polluting request
gets the answer exactly backwards.

Every observation here is RECORDED, not written: ``scripts/record_protopoll_
fixtures.py`` runs the Node target and writes down what came back. A fixture
authored by hand would let this file assert the property it is supposed to be
measuring.
"""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

import pytest

from clinkz.agents._prototype_pollution import (
    EffectObservation,
    PollutionGadget,
    grade,
)

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures" / "prototype_pollution" / "observations.json"
)

POLLUTABLE = "/api/v2/profile"
GUARDED_DEEP_MERGE = "/api/v2/notifications"
REFLECTING_SPREAD_MERGE = "/api/v2/preferences"


def _cases() -> list[dict[str, Any]]:
    return list(json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"])


def _case(endpoint: str, gadget: PollutionGadget) -> dict[str, Any]:
    for case in _cases():
        if case["endpoint"] == endpoint and case["gadget"] == gadget.value:
            return case
    raise AssertionError(f"no recorded case for {endpoint} / {gadget.value}")


def _observation(recorded: dict[str, Any]) -> EffectObservation:
    return EffectObservation(status=int(recorded["status"]), headers=dict(recorded["headers"]))


def _grade(case: dict[str, Any], *, swap_arms: bool = False):
    """Grade one recorded case, optionally with the arms taken in the wrong order."""
    control = _observation(case["control_observation"])
    effect = _observation(case["effect_observation"])
    if swap_arms:
        control, effect = effect, control
    header_name = header_value = ""
    if case["gadget"] == PollutionGadget.HEADER_NONCE.value:
        header_name, header_value = str(case["probe_key"]), str(case["probe_value"])
    return grade(
        PollutionGadget(case["gadget"]),
        control=control,
        effect=effect,
        header_name=header_name,
        header_value=header_value,
    )


class TestTheSoundEndpointsProduceNothing:
    """The headline assertion: a guarded merge of identical shape emits nothing."""

    @pytest.mark.parametrize("gadget", list(PollutionGadget))
    def test_the_guarded_recursive_merge_confirms_on_no_gadget(
        self, gadget: PollutionGadget
    ) -> None:
        verdict = _grade(_case(GUARDED_DEEP_MERGE, gadget))
        assert verdict.confirmed is False, (
            f"{GUARDED_DEEP_MERGE} is a recursive merge whose guard skips the "
            f"prototype-reaching key. Confirming on it means the class reports every "
            f"deep-merge endpoint it meets: {verdict.reason}"
        )

    @pytest.mark.parametrize("gadget", list(PollutionGadget))
    def test_the_reflecting_spread_merge_confirms_on_no_gadget(
        self, gadget: PollutionGadget
    ) -> None:
        verdict = _grade(_case(REFLECTING_SPREAD_MERGE, gadget))
        assert verdict.confirmed is False, verdict.reason

    def test_the_sound_endpoints_are_recorded_as_sound(self) -> None:
        """The fixture agrees with this file about which endpoint is which."""
        by_endpoint = {c["endpoint"]: c["pollutable"] for c in _cases()}
        assert by_endpoint[GUARDED_DEEP_MERGE] is False
        assert by_endpoint[REFLECTING_SPREAD_MERGE] is False
        assert by_endpoint[POLLUTABLE] is True


class TestTheResponseBodyCannotSeparateThem:
    """Why the oracle's input type carries no body — measured, not asserted."""

    def test_every_endpoint_echoes_the_probe_value_in_the_polluting_response(self) -> None:
        """A body-reading oracle confirms on all three, sound and vulnerable alike.

        Two independent reasons, both visible in the recording. The spread merge
        stores ``__proto__`` as data and serialises it back. And on every
        endpoint the CONTROL arm — which must carry the same key and the same
        value, or it is not shape-matched — writes that value into the stored
        record under an ordinary key, so the payload's own response echoes it
        for a reason that has nothing to do with the prototype.
        """
        for case in _cases():
            body = case["payload_post"]["body"]
            assert str(case["probe_value"]) in body, (
                f"{case['endpoint']} / {case['gadget']}: the recording is expected to show "
                "the probe value coming back in the polluting response on every endpoint. "
                "If that has stopped being true the fixture changed, and the argument for "
                "excluding the body from the oracle has to be re-made rather than assumed"
            )

    def test_the_observation_type_has_no_body_field(self) -> None:
        """Structural, not a convention: there is nothing to read."""
        assert {f.name for f in fields(EffectObservation)} == {"status", "headers"}


class TestThePollutableEndpointConfirms:
    """Suppressing a true positive is only honest while the true positive exists."""

    @pytest.mark.parametrize("gadget", list(PollutionGadget))
    def test_the_unguarded_recursive_merge_confirms(self, gadget: PollutionGadget) -> None:
        verdict = _grade(_case(POLLUTABLE, gadget))
        assert verdict.confirmed is True, verdict.reason

    def test_the_header_gadget_carries_the_minted_value(self) -> None:
        """The effect observation cites a token minted for this attempt."""
        case = _case(POLLUTABLE, PollutionGadget.HEADER_NONCE)
        headers = case["effect_observation"]["headers"]
        assert headers.get(str(case["probe_key"]).lower()) == str(case["probe_value"])

    def test_the_status_gadget_carries_no_minted_material_at_all(self) -> None:
        """Which is the whole reason it may not emit without a control that refused."""
        case = _case(POLLUTABLE, PollutionGadget.STATUS_CODE)
        assert case["effect_observation"]["status"] == 510
        assert case["control_observation"]["status"] == 200


class TestTheArmsMustRunInThisOrder:
    """The ordering is not style. Taken the other way round, the arm kills the finding."""

    @pytest.mark.parametrize("gadget", list(PollutionGadget))
    def test_a_control_observed_after_the_payload_refuses_a_real_finding(
        self, gadget: PollutionGadget
    ) -> None:
        """A prototype write outlives the request, so a later control sees it too.

        This is the same recorded pollutable case, graded with the two
        observations swapped — which is exactly what a class that dispatched its
        control after its payload would hand the oracle. Both gadgets flip from
        confirmed to refused, and the reason names the confounder rather than
        the endpoint.
        """
        verdict = _grade(_case(POLLUTABLE, gadget), swap_arms=True)
        assert verdict.confirmed is False
        assert "cannot reach the prototype" in verdict.reason
