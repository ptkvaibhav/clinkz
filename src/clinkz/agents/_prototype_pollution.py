"""The server-side prototype-pollution oracle, as pure functions.

Two things make this class different from every other one in the engine, and
both of them are properties of the vulnerability rather than of the code:

**The effect outlives the request.** A confirmed pollution is a write onto the
target process's ``Object.prototype``. It changes how the application answers
requests this engine never sent, it persists until the process restarts, and no
application-level action undoes it. Every other class either observes without
writing or writes an ordinary record the application already knows how to
delete.

**The response to the payload proves nothing.** On a vulnerable recursive merge
the injected key lands on the prototype, so ``JSON.stringify`` — which
serialises own properties — does not echo it. On a sound *shallow spread* merge
the same key is copied on as an ordinary own property and comes straight back
out in the body. So reading the body of the polluting response gets the answer
exactly backwards: the sound endpoint reflects and the vulnerable one is silent.

That second fact is why :class:`EffectObservation` carries a status and headers
and **no body field at all**. This is not an oversight to be tidied up later:
the body is the one channel that cannot distinguish the two, and a type that
does not carry it cannot be talked into reading it. The rest of this module is
written so that the only inputs to a verdict are a status code and a header map
taken from a request made AFTER the merge, and never the merge's own answer.

See :doc:`/methodology/prototype-pollution` for the arms and the fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

__all__ = [
    "ATTRIBUTION_NOTE",
    "CARRIER_LIMITATION",
    "CARRIER_WHY_UNCONFIRMED",
    "GADGET_ATTRIBUTION",
    "PROTO_KEY",
    "STATUS_PROBE_CODE",
    "STATUS_PROBE_KEY",
    "EffectObservation",
    "PollutionGadget",
    "PollutionVerdict",
    "control_body",
    "effect_present",
    "grade",
    "header_probe",
    "observation_text",
    "pollution_body",
    "residual_mutation_note",
]

#: The one key that reaches ``Object.prototype`` through a recursive merge.
#: ``constructor``/``prototype`` reach it too on some merge implementations, and
#: are deliberately NOT probed here: each is a second write to a live process,
#: and the marginal coverage does not justify doubling what a run leaves behind
#: on a target it cannot clean up. The boundary is stated in the deliverable
#: rather than left to a reader to infer — see :data:`CARRIER_LIMITATION`.
PROTO_KEY = "__proto__"

#: The key the status gadget writes. Not a name this engine chose: it is what
#: the framework itself reads out of an options bag when deciding a response
#: code, which is what makes the write observable at all.
STATUS_PROBE_KEY = "status"

#: The code the status gadget writes. 510 (Not Extended) is chosen because
#: essentially no application emits it for its own reasons — but "essentially
#: none" is not "none", which is the entire reason the status gadget may never
#: emit on its own. See :data:`GADGET_ATTRIBUTION`.
STATUS_PROBE_CODE = 510


class PollutionGadget(StrEnum):
    """A reader of the polluted key — what turns a write into an observation.

    A prototype write is invisible by itself. Something in the application has
    to READ the key back, and which readers exist is a property of the target's
    code, not of the payload. Both members here are the ordinary Node idioms
    that make server-side prototype pollution exploitable in the wild.

    Attributes:
        HEADER_NONCE: ``for (const k in bag)`` walks the prototype chain, so a
            polluted key becomes a response header. The engine mints both the
            header NAME and its VALUE, so an observation of it is attributable
            to this attempt without reference to anything else.
        STATUS_CODE: a polluted ``status`` supplies the response code. Carries
            no minted material at all — the observation is a bare integer.
    """

    HEADER_NONCE = "header_nonce"
    STATUS_CODE = "status_code"


#: Whether a gadget's observation attributes itself to this attempt, and why.
#:
#: The distinction decides what a confirmation is allowed to rest on. A minted
#: header name carrying a minted value is a two-sided nonce: no application
#: emits a header nobody has ever named, holding a value nobody has ever sent.
#: A 510 is a number. It is a *good* number — one almost nothing returns — and
#: "almost nothing" is exactly the shape of every phantom this engine has
#: shipped, so the status gadget's entire claim rests on a control arm that
#: refused. The class enforces that by being bound by the never-sent-control
#: rule; this table is what the evidence text reads so a client can see WHICH
#: kind of observation they are being shown.
GADGET_ATTRIBUTION: dict[PollutionGadget, str] = {
    PollutionGadget.HEADER_NONCE: (
        "the response carried a header whose NAME and VALUE were both minted for this "
        "attempt, so the observation names this probe and nothing else could have "
        "produced it"
    ),
    PollutionGadget.STATUS_CODE: (
        "the response carried a bare status code, which is not attributable to this "
        "probe on its own — the claim rests entirely on the control arm, which sent an "
        "identically-shaped merge that could not reach the prototype and did NOT change "
        "the status"
    ),
}

#: Rendered into the evidence of a finding confirmed on the status gadget ALONE,
#: so the weaker of the two observations is never presented as though it were
#: the stronger one. The header gadget is attempted first on every endpoint, so
#: reaching here means the target's response helper reads a polluted ``status``
#: and does not enumerate its header bag with ``for…in``.
ATTRIBUTION_NOTE = (
    "confirmed on the status gadget only: the header-nonce probe was attempted first "
    "and this target's response path does not enumerate its header bag, so no minted "
    "token appears in the observation. What was observed is a status code, and the only "
    "thing separating it from an application returning 510 for its own reasons is the "
    "control arm below, which sent the same merge with the prototype-reaching key "
    "replaced and got the ordinary status back"
)

#: The registered lead reason for the carrier boundary below.
CARRIER_WHY_UNCONFIRMED = "prototype_pollution_carrier_is_json_body_only"

#: The shape this class refuses to claim anything about, as a client reads it.
#:
#: Kept as one sentence in the artifact rather than in a commit message, because
#: the reason is not "we ran out of time" — it is that the answer is genuinely
#: unobservable from outside and therefore cannot be recovered later by reading
#: the report harder. Express's ``qs`` filters ``__proto__`` out of a
#: form-encoded body while letting ``constructor`` through, and ``extended:
#: false`` swaps in ``querystring``, whose result already has a null prototype;
#: which of those is in play depends on the parser the application happens to
#: use, on a flag set in code, and on the version of a transitive dependency.
#: None of the three is visible in a response. A client who reads "we tested
#: this endpoint" must not conclude the form-encoded surface was cleared.
CARRIER_LIMITATION = (
    "Server-side prototype pollution is probed through JSON request bodies only. "
    "Whether the same endpoint can be polluted through a form-encoded body or a query "
    "string depends on which body parser the application uses and how it is configured "
    "— Express's qs filters __proto__ while letting constructor through, and "
    "extended:false parses with querystring, whose result already has a null prototype "
    "— and neither the parser nor its version is observable from outside the "
    "application. A form-encoded endpoint is therefore not cleared by this engine, "
    "only untested."
)


@dataclass(frozen=True)
class EffectObservation:
    """One observation of the target, made AFTER a merge and by a new request.

    Deliberately carries no response body. The body of a polluting request is
    the one channel on which a sound shallow-spread endpoint and a vulnerable
    recursive-merge endpoint answer *in the wrong order* — the sound one echoes
    the injected key and the vulnerable one does not — so an oracle with access
    to it can reach the right verdict by the wrong arm. It has none.

    Attributes:
        status: The response's status code. ``0`` when the request did not
            complete, which is never an effect.
        headers: The response's own headers, lower-cased keys.
    """

    status: int
    headers: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class PollutionVerdict:
    """Whether the effect arm witnessed this gadget's defining effect.

    Attributes:
        confirmed: Whether the effect was present after the payload and absent
            after the control. Both halves are required; neither alone is
            evidence.
        gadget: The gadget graded.
        reason: Why the verdict went the way it did, for the trace and the lead.
    """

    confirmed: bool
    gadget: PollutionGadget
    reason: str


def header_probe(nonce: int) -> tuple[str, str]:
    """The minted ``(header name, header value)`` for one header-gadget attempt.

    Both halves carry the ``clinkz`` stem the attribution guard keys on, and the
    name is a bare HTTP token so a target that reflects it into a header cannot
    fail to send it.

    Args:
        nonce: Caller-supplied randomness. The caller owns the RNG so this stays
            pure and the unit suite can pin it.
    """
    return f"x-clinkz-pp-{nonce}", f"clinkzpp{nonce}"


def pollution_body(key: str, value: object) -> dict[str, object]:
    """The payload: one leaf written under the prototype-reaching key."""
    return {PROTO_KEY: {key: value}}


def control_body(container: str, key: str, value: object) -> dict[str, object]:
    """The control: the same merge with the prototype-reaching key replaced.

    *container* is the engine-minted decoy. It is an ordinary JSON key, so the
    request round-trips through the same handler, the same parser and the same
    recursive merge as the payload and differs in exactly one thing: it does not
    resolve to ``Object.prototype``. A control that took a different code path —
    a malformed body, a rejected type — would take the target's error path and
    differ from everything, which passes on a vulnerable target and a phantom
    alike.
    """
    return {container: {key: value}}


def effect_present(
    gadget: PollutionGadget,
    observation: EffectObservation,
    *,
    header_name: str = "",
    header_value: str = "",
) -> bool:
    """Whether *gadget*'s defining effect is present in *observation*.

    Args:
        gadget: Which reader's effect to look for.
        observation: A response received AFTER a merge, from a new request.
        header_name: The minted header name, for the header gadget.
        header_value: The minted header value, for the header gadget.
    """
    if observation.status == 0:
        return False
    if gadget is PollutionGadget.STATUS_CODE:
        return observation.status == STATUS_PROBE_CODE
    if not header_name or not header_value:
        return False
    return observation.headers.get(header_name.lower(), "") == header_value


def grade(
    gadget: PollutionGadget,
    *,
    control: EffectObservation,
    effect: EffectObservation,
    header_name: str = "",
    header_value: str = "",
) -> PollutionVerdict:
    """Grade one gadget's arms.

    The control observation is taken after an identically-shaped merge that
    cannot reach the prototype, and the effect observation after the merge that
    can. Both are separate requests made after their merge; neither is the
    merge's own response.

    **The control observation must have been taken FIRST.** Ordering is not this
    function's to enforce — it is a property of when the requests were sent, and
    it is forced at the dispatch seam — but the reason belongs here beside the
    grading it protects: a control taken after the payload is observed through a
    prototype the payload has already written to, so it exhibits the effect too,
    and the arm kills the true positive it exists to license.
    """
    on_control = effect_present(gadget, control, header_name=header_name, header_value=header_value)
    if on_control:
        return PollutionVerdict(
            confirmed=False,
            gadget=gadget,
            reason=(
                "the effect was present after a merge that cannot reach the prototype, "
                "so it is not attributable to the prototype write"
            ),
        )
    on_effect = effect_present(gadget, effect, header_name=header_name, header_value=header_value)
    if not on_effect:
        return PollutionVerdict(
            confirmed=False,
            gadget=gadget,
            reason="no effect was observed after the prototype write",
        )
    return PollutionVerdict(
        confirmed=True,
        gadget=gadget,
        reason=(
            "the effect was absent after an identically-shaped merge that cannot reach "
            "the prototype and present after one that can, on a request made after both"
        ),
    )


def observation_text(
    gadget: PollutionGadget,
    *,
    header_name: str = "",
    header_value: str = "",
    status: int = 0,
) -> str:
    """The ``indicator_observed`` line for a confirmation on *gadget*.

    The header gadget's line cites the minted value, which is what the
    attribution guard requires of any observation whose expected indicator was
    minted. The status gadget's cites a number, and says so.
    """
    if gadget is PollutionGadget.HEADER_NONCE:
        return f"response header {header_name}: {header_value} on a later, unrelated request"
    return f"http status {status} on a later, unrelated request (no minted token to cite)"


def residual_mutation_note(key: str) -> str:
    """What the operator has to do about a key this engine left on the prototype.

    Stated as an instruction rather than a description because that is what it
    is: unlike every other artifact a run leaves behind, this one cannot be
    deleted through the application. The process holds it.
    """
    return (
        f"This test wrote the key {key!r} onto the running process's Object.prototype and "
        "it is still there. Nothing in the application can remove it — no request, no "
        "administrative action, no cache clear — because it lives in the process's own "
        "memory rather than in any record. Restart the affected process (every worker, if "
        "the service runs more than one) to clear it. Until then the key is inherited by "
        "every object the process creates, which can change how unrelated requests are "
        "answered."
    )
