"""P7 verdict types — what the browser observed, and what that licenses.

The load-bearing property of this module is a negative one: **the verdict is a
function of the binding-call record and nothing else.**

The oracle renders a page belonging to the host under test. Everything that page
produces — its DOM, its text, its console, its titles, its headers — is chosen
by the target. The engine already learned this the expensive way: a guard that
parsed evidence text let a page emit ``strength=likely`` and suppress a genuine
finding, so :func:`_evidence_strength` was narrowed to fully-structured entries.
A browser oracle multiplies that surface enormously, so the rule here is
structural rather than careful:

* :attr:`WitnessVerdict.executed` is computed in :meth:`WitnessVerdict.decide`
  from three booleans the *Python* side owns — was our binding called, did the
  call carry the nonce we injected, did the never-injected control stay silent.
* Every target-authored artefact on the verdict (:attr:`policy_in_force`,
  :attr:`console_violations`, :attr:`final_url`) is EVIDENCE, recorded verbatim
  for a reviewer, and is never read back to decide anything.

A console line saying "Refused to execute inline script" is a helpful thing to
show an operator and a catastrophic thing to believe: a page that wants to look
protected can print it, and a page that wants to look vulnerable can withhold
it. Only the absence of our nonce decides a non-execution.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class WitnessRefusal(StrEnum):
    """Why P7 produced no witness. Never a synonym for "not vulnerable".

    Every member except :attr:`NOT_EXECUTED` describes a failure of the *oracle*,
    not a property of the target — which is why the caller keeps its
    :class:`~clinkz.models.finding.UnprovenExploitLead` rather than turning it
    into either a finding or a clean result. A missing oracle costs coverage;
    it must never be allowed to read as evidence of safety.

    Attributes:
        NONE: No refusal — the run completed and produced a verdict.
        ORACLE_UNAVAILABLE: Playwright or its browser binary is not installed.
        OUT_OF_SCOPE: The URL is outside the engagement scope. Checked before
            any navigation.
        STATE_CHANGING_URL: Navigating would mutate target state.
        SAFETY_REFUSED: The governor refused the request (halt, window closed,
            destructive classification, action ceiling).
        NAVIGATION_FAILED: The page could not be loaded at all.
        CONTROL_NONCE_OBSERVED: The control nonce — minted and deliberately
            never injected — came back. The channel is not trustworthy for this
            run, so nothing it reported may be believed, including a positive.
        NOT_EXECUTED: The only member that IS a statement about the target: the
            oracle ran cleanly, the control stayed silent, and the payload did
            not execute.
    """

    NONE = "none"
    ORACLE_UNAVAILABLE = "oracle_unavailable"
    OUT_OF_SCOPE = "out_of_scope"
    STATE_CHANGING_URL = "state_changing_url"
    SAFETY_REFUSED = "safety_refused"
    NAVIGATION_FAILED = "navigation_failed"
    CONTROL_NONCE_OBSERVED = "control_nonce_observed"
    NOT_EXECUTED = "not_executed"


class ExecutionWitness(BaseModel):
    """One inbound call on the Clinkz-owned binding.

    Recorded by the oracle's Python-side handler, which is the only writer. The
    page supplies ``value`` (it is the argument of the call it made) — which is
    exactly why the verdict compares it for equality against a nonce the engine
    minted, rather than parsing anything out of it.

    Attributes:
        value: The argument the page passed. Compared for equality with the
            injected nonce; never parsed, never pattern-matched.
        frame_url: URL of the frame that made the call, as the browser reported
            it. Evidence — a call from an unexpected frame is worth showing an
            operator — never a verdict input.
        observed_at: When the call arrived.
    """

    value: str = ""
    frame_url: str = ""
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class WitnessVerdict(BaseModel):
    """The result of one P7 run against one URL.

    Attributes:
        executed: Whether attacker-supplied script ran in the target origin.
            Set ONLY by :meth:`decide`. A caller must never assign it.
        refusal: Why there is no witness, when there is none.
        nonce: The Clinkz-minted nonce carried by the injected payload.
        control_nonce: A second nonce minted in the same call and **never
            injected anywhere**. Its silence is what makes a positive
            admissible: it proves the channel reports traffic it actually
            received rather than anything it was primed with.
        control_silent: Whether the control nonce stayed absent. A confirmation
            with this ``False`` is impossible by construction in :meth:`decide`.
        binding_name: The per-load random name of the witness function.
        injected_payload: The exact payload string that carried the nonce.
        template_id: Which CLINKZ-OWNED template produced it.
        navigated_url: The URL the oracle was asked to load.
        final_url: Where the browser ended up. TARGET-AUTHORED evidence.
        policy_in_force: The Content-Security-Policy header(s) served on the
            document response, verbatim, at the moment execution was attempted.
            TARGET-AUTHORED evidence — recorded because "did script execute
            UNDER THE SERVED POLICY" is unanswerable without it, and never read
            back to decide execution.
        policy_source: Where the policy came from (``"header"``, ``"meta"``,
            ``"none"``).
        bypass_csp_disabled: Proof the oracle did NOT ask the browser to ignore
            CSP. An oracle running with CSP bypassed would confirm every policy.
        witnesses: Every call the binding received, in arrival order.
        console_violations: Console lines the page emitted that mention CSP.
            TARGET-AUTHORED evidence, advisory only.
        blocked_navigations: URLs the rendered page tried to send the browser to
            after the first navigation, and which were refused. Recorded because
            a blocked navigation leaves the browser on an error page, and
            ``final_url`` alone would then read as a failed run rather than as a
            rail doing its job.
        blocked_subresources: Subresource requests the page made that the rails
            refused — out of scope, or carrying a token from the destructive
            vocabulary. ``<img src="/logout">`` is a GET, and it destroys the
            engagement's session; recorded rather than silently dropped so a
            reviewer can see what the page did not get to load.
        blocked_mutations: Page-initiated requests refused for using a method
            outside GET/HEAD/OPTIONS. The one navigation Clinkz authorized is
            exempt — it was classified and logged before the browser started —
            so everything in this list is a mutation the *page* attempted.
        duration_ms: Wall time of the run.
    """

    executed: bool = False
    refusal: WitnessRefusal = WitnessRefusal.NONE
    refusal_detail: str = ""

    nonce: str = ""
    control_nonce: str = ""
    control_silent: bool = True
    binding_name: str = ""
    injected_payload: str = ""
    template_id: str = ""

    navigated_url: str = ""
    final_url: str = ""
    policy_in_force: str = ""
    policy_source: str = "none"
    bypass_csp_disabled: bool = True

    witnesses: list[ExecutionWitness] = Field(default_factory=list)
    console_violations: list[str] = Field(default_factory=list)
    blocked_navigations: list[str] = Field(default_factory=list)
    blocked_subresources: list[str] = Field(default_factory=list)
    blocked_mutations: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0

    def decide(self) -> None:
        """Compute :attr:`executed` from the engine-owned observations only.

        Three conditions, all required, none of them derived from page content:

        1. The Clinkz-owned binding was called with a value **equal** to the
           nonce this run injected. Equality against a minted secret, not a
           search for a pattern inside target bytes.
        2. The control nonce — minted here, injected nowhere — never arrived.
        3. The browser was not asked to bypass CSP, so whatever ran, ran under
           the policy actually served.

        Any failure leaves ``executed`` False and records the reason. A control
        that fires invalidates the whole run, including a positive: if the
        channel can report a nonce that was never sent, it can report one that
        was.
        """
        self.control_silent = not any(
            w.value == self.control_nonce for w in self.witnesses if self.control_nonce
        )

        if not self.control_silent:
            self.executed = False
            self.refusal = WitnessRefusal.CONTROL_NONCE_OBSERVED
            self.refusal_detail = (
                "The never-injected control nonce came back through the witness "
                "channel. The channel is reporting traffic it did not receive, so "
                "no verdict from this run is admissible — including a positive."
            )
            return

        if not self.bypass_csp_disabled:
            self.executed = False
            self.refusal = WitnessRefusal.SAFETY_REFUSED
            self.refusal_detail = (
                "The browser was configured to bypass Content-Security-Policy, so "
                "an execution here would prove nothing about the served policy."
            )
            return

        hit = bool(self.nonce) and any(w.value == self.nonce for w in self.witnesses)
        self.executed = hit
        if not hit:
            self.refusal = WitnessRefusal.NOT_EXECUTED
            self.refusal_detail = (
                "The payload was delivered and the page was rendered in a real "
                "browser, but the witness nonce never came back: nothing executed it."
            )
        else:
            self.refusal = WitnessRefusal.NONE
            self.refusal_detail = ""

    @property
    def is_target_statement(self) -> bool:
        """Whether this verdict says anything about the TARGET.

        True for a witnessed execution and for a clean non-execution. False for
        every oracle failure — those describe Clinkz, and a caller that treats
        them as "not vulnerable" is manufacturing a clean result out of a broken
        tool.
        """
        return self.executed or self.refusal is WitnessRefusal.NOT_EXECUTED

    def evidence_summary(self) -> str:
        """One structured, auditable line: the nonce out, the nonce back, control."""
        back = next((w.value for w in self.witnesses if w.value == self.nonce), "")
        return (
            f"primitive=P7 executed={self.executed} "
            f"nonce_injected={self.nonce!r} nonce_returned={back!r} "
            f"control_nonce={self.control_nonce!r} control_silent={self.control_silent} "
            f"binding={self.binding_name!r} template={self.template_id} "
            f"bypass_csp_disabled={self.bypass_csp_disabled} "
            f"policy_source={self.policy_source} policy_in_force={self.policy_in_force!r}"
        )


__all__ = ["ExecutionWitness", "WitnessRefusal", "WitnessVerdict"]
