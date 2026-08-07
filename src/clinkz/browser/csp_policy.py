"""Reading a served Content-Security-Policy, and choosing what to TRY under it.

This module decides which witness shape is worth attempting. It never decides
whether one worked — :class:`~clinkz.browser.witness.WitnessVerdict` does, from
the nonce channel. That split is what keeps the analysis here safe: a policy
misread costs a MISS (a shape we should have tried and didn't), never a phantom.
So the parser is allowed to be conservative without endangering correctness.

Two behaviours here are measured, not recited from the specification, because
they are the ones that decide real outcomes:

* **A nonce or hash in ``script-src`` makes ``'unsafe-inline'`` inert.** Verified
  live against a policy carrying both: a bare inline script was refused while a
  nonced one executed. A parser that read ``'unsafe-inline'`` as "inline is
  allowed" would pick a shape the browser will always block, and the class would
  report "not bypassable" about a policy that is.
* **A reused nonce is not a control.** A nonce defends only while it is
  unpredictable and per-response; one that comes back byte-identical on
  independent responses is a published constant, and an injected script that
  carries it executes. Staticness is therefore established by OBSERVATION —
  two or more independent fetches — never assumed from the policy text alone.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from clinkz.browser.templates import ClientWitnessTemplateId

# `nonce-<base64>` inside a source expression.
_NONCE_SOURCE_RE = re.compile(r"'nonce-([A-Za-z0-9+/=_-]{1,128})'")
# `sha256-...` / `sha384-...` / `sha512-...`
_HASH_SOURCE_RE = re.compile(r"'(sha(?:256|384|512))-([A-Za-z0-9+/=_-]+)'")


class CSPPolicy(BaseModel):
    """One origin's script-execution posture, as served.

    Attributes:
        raw: Every policy string served, joined — the verbatim evidence.
        source: ``"header"``, ``"meta"``, or ``"none"``.
        effective_directive: Which directive governed script (``script-src``,
            falling back to ``default-src``), or ``""`` when nothing did.
        sources: The source expressions of the effective directive.
        nonces: Nonce values published in the policy.
        hashes: Hash source expressions published in the policy.
        allows_inline: Whether a bare inline ``<script>`` may execute — which
            requires ``'unsafe-inline'`` AND the absence of any nonce or hash.
        allows_self: Whether ``'self'`` is a permitted script source.
        strict_dynamic: Whether ``'strict-dynamic'`` is present, which makes
            host and ``'self'`` sources inert for script loading.
        unsafe_eval: Whether ``'unsafe-eval'`` is present.
        present: Whether any policy governed script at all.
    """

    raw: str = ""
    source: str = "none"
    effective_directive: str = ""
    sources: tuple[str, ...] = ()
    nonces: tuple[str, ...] = ()
    hashes: tuple[str, ...] = ()
    allows_inline: bool = False
    allows_self: bool = False
    strict_dynamic: bool = False
    unsafe_eval: bool = False
    present: bool = False


class CSPBypassRoute(BaseModel):
    """Which witness shape to attempt under a given policy, and why.

    Attributes:
        template_id: The shape to try, or ``None`` when the policy leaves no
            shape this engine can synthesize.
        reason: Human-readable justification, rendered into evidence.
        csp_nonce: The nonce to reuse, when the route is the static-nonce one.
        requires_gadget: Whether the route needs a same-origin script gadget
            that the caller must have discovered.
        unreachable_note: When ``template_id`` is ``None``, what would be needed.
            Stated so "no route" reads as a COVERAGE limit rather than as a
            clean bill of health for the policy.
    """

    template_id: ClientWitnessTemplateId | None = None
    reason: str = ""
    csp_nonce: str | None = None
    requires_gadget: bool = False
    unreachable_note: str = ""


def parse_csp(
    headers: dict[str, str] | None = None,
    *,
    meta_policies: list[str] | None = None,
) -> CSPPolicy:
    """Parse the served Content-Security-Policy into a script-execution posture.

    Report-only policies are deliberately ignored: ``Content-Security-Policy-
    Report-Only`` enforces nothing, and treating it as a control would make the
    engine report a policy as blocking when the browser will happily execute.

    When several enforcing policies are served, ALL of them must permit a shape
    for it to run, so permissions are intersected and restrictions unioned.

    Args:
        headers: Response headers of the document response (case-insensitive).
        meta_policies: Policies declared via ``<meta http-equiv>``, if the
            caller extracted any.

    Returns:
        A :class:`CSPPolicy`. ``present=False`` when nothing governed script.
    """
    raw_policies: list[str] = []
    source = "none"

    for key, value in (headers or {}).items():
        if key.strip().lower() == "content-security-policy" and value.strip():
            raw_policies.append(value.strip())
            source = "header"

    for policy in meta_policies or []:
        if policy.strip():
            raw_policies.append(policy.strip())
            source = source if source == "header" else "meta"

    if not raw_policies:
        return CSPPolicy()

    directives: list[tuple[str, list[str]]] = []
    for policy in raw_policies:
        directive, sources = _effective_script_directive(policy)
        if directive:
            directives.append((directive, sources))

    if not directives:
        # A policy was served but nothing in it governs script (no script-src and
        # no default-src) — script is unconstrained.
        return CSPPolicy(raw="; ".join(raw_policies), source=source, present=False)

    all_sources = [s for _, sources in directives for s in sources]
    nonces = tuple(dict.fromkeys(n for s in all_sources for n in _NONCE_SOURCE_RE.findall(s)))
    hashes = tuple(
        dict.fromkeys(
            f"{alg}-{val}" for s in all_sources for alg, val in _HASH_SOURCE_RE.findall(s)
        )
    )

    def every(pred) -> bool:
        return all(pred(sources) for _, sources in directives)

    def any_(pred) -> bool:
        return any(pred(sources) for _, sources in directives)

    has_nonce_or_hash = bool(nonces or hashes)
    # CSP2+: a nonce or hash source expression makes 'unsafe-inline' inert. This
    # is the branch that decides whether the plain-inline shape is worth sending.
    allows_inline = (not has_nonce_or_hash) and every(lambda ss: "'unsafe-inline'" in ss)

    return CSPPolicy(
        raw="; ".join(raw_policies),
        source=source,
        effective_directive=directives[0][0],
        sources=tuple(all_sources),
        nonces=nonces,
        hashes=hashes,
        allows_inline=allows_inline,
        allows_self=every(lambda ss: "'self'" in ss),
        strict_dynamic=any_(lambda ss: "'strict-dynamic'" in ss),
        unsafe_eval=every(lambda ss: "'unsafe-eval'" in ss),
        present=True,
    )


def _effective_script_directive(policy: str) -> tuple[str, list[str]]:
    """Return the directive governing script in *policy*, and its sources."""
    parsed: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        parts = chunk.split()
        if parts:
            parsed[parts[0].strip().lower()] = [p.strip() for p in parts[1:]]
    for name in ("script-src-elem", "script-src", "default-src"):
        if name in parsed:
            return name, parsed[name]
    return "", []


def nonce_is_static(observed: list[str]) -> bool:
    """Whether a nonce was observed REUSED across independent responses.

    Args:
        observed: One nonce per independent fetch, in fetch order. Entries for
            fetches that carried no nonce should be omitted by the caller.

    Returns:
        ``True`` only when at least two independent observations exist and every
        one of them is byte-identical. One observation proves nothing — a
        per-response nonce looks exactly the same when you have only seen it
        once — so a single sample is deliberately NOT enough.
    """
    return len(observed) >= 2 and len(set(observed)) == 1


def select_bypass_route(
    policy: CSPPolicy,
    *,
    observed_nonces: list[str] | None = None,
    gadget_available: bool = False,
) -> CSPBypassRoute:
    """Choose the witness shape worth attempting under *policy*.

    Ordering is by strength of the resulting claim, not by convenience: a shape
    that needs no target weakness at all comes first, and the gadget route —
    which needs a discovered same-origin endpoint — comes last.

    Args:
        policy: The parsed served policy.
        observed_nonces: Nonces seen on independent fetches of the same URL,
            used to establish reuse.
        gadget_available: Whether a same-origin script gadget was discovered.

    Returns:
        A :class:`CSPBypassRoute`. ``template_id=None`` means this engine has no
        synthesizable shape for the policy — a statement about Clinkz's
        coverage, which :attr:`CSPBypassRoute.unreachable_note` says out loud.
    """
    if not policy.present:
        return CSPBypassRoute(
            template_id=ClientWitnessTemplateId.INLINE_SCRIPT,
            reason="No Content-Security-Policy governs script on this response.",
        )

    if policy.allows_inline:
        return CSPBypassRoute(
            template_id=ClientWitnessTemplateId.INLINE_SCRIPT,
            reason=(
                f"The served policy permits inline script "
                f"({policy.effective_directive} includes 'unsafe-inline' and "
                f"publishes no nonce or hash)."
            ),
        )

    nonces = list(observed_nonces or [])
    if policy.nonces and nonce_is_static(nonces):
        return CSPBypassRoute(
            template_id=ClientWitnessTemplateId.NONCED_INLINE_SCRIPT,
            csp_nonce=nonces[0],
            reason=(
                f"The policy's script nonce was byte-identical across "
                f"{len(nonces)} independent responses, so it is a published "
                f"constant rather than a per-response secret; an injected script "
                f"carrying it satisfies {policy.effective_directive}."
            ),
        )

    if policy.allows_self and not policy.strict_dynamic and gadget_available:
        return CSPBypassRoute(
            template_id=ClientWitnessTemplateId.SAME_ORIGIN_SCRIPT_GADGET,
            requires_gadget=True,
            reason=(
                f"{policy.effective_directive} permits 'self', and a same-origin "
                f"endpoint reflects a request parameter into its own JavaScript "
                f"response, so a script include the policy fully permits carries "
                f"attacker-controlled code."
            ),
        )

    return CSPBypassRoute(
        template_id=None,
        reason=f"No synthesizable shape is permitted by: {policy.raw}",
        unreachable_note=_unreachable_note(
            policy, bool(policy.nonces and not nonce_is_static(nonces))
        ),
    )


def _unreachable_note(policy: CSPPolicy, nonce_rotates: bool) -> str:
    """State what a 'no route' outcome does and does not mean."""
    if nonce_rotates:
        return (
            "The policy publishes a per-response nonce that was NOT observed "
            "repeating, so the static-nonce route does not apply. This is a "
            "statement about the shapes Clinkz can synthesize, not proof that "
            "no bypass exists."
        )
    if policy.allows_self and not policy.strict_dynamic:
        return (
            "The policy permits 'self'. Clinkz found no same-origin endpoint that "
            "reflects a parameter into a JavaScript response, but did not "
            "exhaustively enumerate the origin's scripts — a script gadget "
            "elsewhere on this origin would defeat the policy. Not tested "
            "exhaustively."
        )
    return (
        "Clinkz has no synthesizable witness shape for this policy. That is a "
        "coverage limit of this engine, not a proof that the policy is sound."
    )


def same_origin(url: str, other: str) -> bool:
    """Whether two URLs share scheme, host and port."""
    a, b = urlsplit(url), urlsplit(other)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


class ScriptGadget(BaseModel):
    """A same-origin endpoint that reflects a parameter into a JS response.

    Attributes:
        path: The rooted, same-origin path.
        param: The query parameter whose value is emitted as executable code.
        content_type: The response's declared type.
        evidence: A bounded excerpt of the response showing the reflection at
            the head of the body, where a JSONP wrapper puts its callback.
    """

    path: str = ""
    param: str = ""
    content_type: str = ""
    evidence: str = ""
    probe_url: str = Field(default="")


__all__ = [
    "CSPBypassRoute",
    "CSPPolicy",
    "ScriptGadget",
    "nonce_is_static",
    "parse_csp",
    "same_origin",
    "select_bypass_route",
]
