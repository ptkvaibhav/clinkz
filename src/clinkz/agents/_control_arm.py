"""The control arm an oracle must clear before it is allowed to confirm.

Two rules live here, and both are properties of an oracle's OWN arms rather than
judgements about the target:

**1. The never-sent control.** A class whose oracle is a substring or marker
match confirms by finding a string in a response body. That reads as proof only
while the string can get there by exactly one route — the vulnerability. Every
phantom this engine has shipped was a second route the oracle could not see:

* the portfolio run's SQLi UNION findings, where Next.js App Router echoes the
  request's own query string into the RSC flight payload, so *any* value comes
  back and ``marker in body`` is satisfied by reflection alone; and
* the same run's command-injection findings, where the ``uname`` pattern matched
  the bare word ``Linux`` in a ``<span>Linux</span>`` skill badge that sat on the
  clean baseline before anything was injected.

Neither is reachable by making the oracle cleverer, because the confounder is a
property of the target, not of the payload — the next framework echoes in a
different encoding and the next page contains a different word. What both ARE
reachable by is the arm the classes with a real control already run: dispatch a
probe carrying a marker of the same shape **with the class's exploitation
mechanism removed**, run the SAME oracle over it, and require it to REFUSE. On
Next.js the decoy reflects, the oracle says yes, and the finding dies. On DVWA
the decoy is echoed only inside the payload, the oracle's own echo guard blanks
it, the oracle says no, and the genuine finding stands.

That arm is what P7 (a nonce minted alongside and injected nowhere), D8 (a
shape-matched contradiction one character apart), JWT (a broken-signature reject
baseline), SSRF (a non-resolving control host) and the boolean-blind oracle
already do. Those were the honest classes on the portfolio run. This module makes
the arm a requirement rather than a habit.

**2. Attribution.** A confirmation names what it saw. When what it saw is neither
the marker the engine minted for this attempt nor the output of a command this
attempt actually invoked, the evidence refutes itself on its face — the portfolio
run shipped ``expected_indicator=clinkzcmdi51696`` beside ``indicator_observed=
matched uname output: Linux`` as a CONFIRMED high, from the payload
``;echo clinkzcmdi51696``, which does not print ``uname`` output.

Both rules are read at the emission chokepoint out of fully-structured evidence
entries, so a target echoing ``never_sent_control=refused`` in its own body
cannot manufacture either.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

__all__ = [
    "CONTROL_EXEMPT_CLASSES",
    "indicator_is_self_controlled",
    "rebind_marker",
    "sqli_inert_control",
    "strip_shell_separators",
    "strip_template_delimiters",
    "MARKER_ORACLE_CLASSES",
    "ControlVerdict",
    "attribution_contradiction",
    "control_evidence_lines",
    "control_required",
    "control_verdict_from_evidence",
    "is_minted_marker",
    "mint_decoy",
    "payload_invokes",
    "structured_evidence_field",
]


#: Classes whose confirming observation is a substring or marker match against a
#: response body, and which are therefore bound by the never-sent-control rule.
#: Keyed by ``_test_*`` method name so the registry, the dispatch table and the
#: emission gate all speak one vocabulary.
MARKER_ORACLE_CLASSES: frozenset[str] = frozenset(
    {
        "_test_sqli",
        "_test_cmdi",
        "_test_lfi",
        "_test_ssti",
        "_test_xxe",
        "_test_nosqli",
        "_test_xss_reflected",
        "_test_xss_stored",
        "_test_file_upload",
        "_test_ssrf",
    }
)


#: Every other dispatchable class, with the reason the rule does not bind it.
#: Exemption is DECLARED, never inferred from absence: a class that appears in
#: neither table is a red build, because "nobody classified it" and "it needs no
#: control" are different facts and only one of them is safe.
CONTROL_EXEMPT_CLASSES: dict[str, str] = {
    "_test_xss_dom": (
        "confirms through P7, whose verdict already requires a second nonce minted "
        "alongside and injected nowhere to stay silent — this rule generalised from it"
    ),
    "_test_csp": (
        "confirms through P7 under the served policy, on the same never-injected "
        "control nonce as DOM XSS"
    ),
    "_test_jwt": (
        "confirms on a three-arm status differential whose middle arm is a "
        "broken-signature token the server must REJECT — a dispatched control that refused"
    ),
    "_test_javascript_attacks": (
        "confirms only when the server answers a forged value differently from an "
        "equal-shaped control value it never issued, repeated"
    ),
    "_test_crypto": (
        "forgery is graded against a random token of the same shape; if that is "
        "honoured too the scheme was not broken and the class says so"
    ),
    "_test_open_redirect": (
        "reads a 3xx Location header's browser-resolved host, not text in a body — "
        "there is no substring for a decoy to collide with"
    ),
    "_test_security_headers": (
        "a pure function of the observed header set; nothing is injected, so there "
        "is no arm to control"
    ),
    "_test_idor": (
        "gated on an authorization boundary proven to exist by an out-of-allotment "
        "reference the target refused, then on divergence from a captured baseline"
    ),
    "_test_brute_force": "counts attempts the target accepted; no marker is injected",
    "_test_csrf": "reads whether a token is present and bound; no marker is injected",
    "_test_weak_session": "measures issued session identifiers; no marker is injected",
    "_test_secrets_exposure": (
        "fetches with NO session material and subtracts what the site root also "
        "serves — the anonymous arm IS the control, and material we supplied is "
        "excluded by fingerprint"
    ),
    "_test_input_validation": "probe and control bodies are compared on the read-back",
    "_test_mass_assignment": "probe and control bodies are compared on the read-back",
    "_test_state_sequence": "business logic: graded on a read-back against a control object",
    "_test_constraint_violation": (
        "business logic: graded on a read-back against a boundary control"
    ),
    "_test_repeatability": "business logic: graded on two identical creates read back",
    "_test_log4shell": (
        "confirms out-of-band on a single-use nonce that exists only in the one probe "
        "that carried it, with a second nonce minted alongside and sent nowhere — the "
        "never-sent control, dispatched by P6 itself. There is no response body here "
        "for a decoy to collide with: the channel is an inbound callback"
    ),
    "_test_tier2_technique": (
        "constructs no Finding — the technique applier sends no request and returns an "
        "empty list from all three of its exits, so there is no confirming observation "
        "for a control to discriminate. Registered NOT_IMPLEMENTED in the vuln-class "
        "registry, which is where the report states it"
    ),
    "_test_tier3_technique": (
        "constructs no Finding — the technique applier sends no request and returns an "
        "empty list from all three of its exits, so there is no confirming observation "
        "for a control to discriminate. Registered NOT_IMPLEMENTED in the vuln-class "
        "registry, which is where the report states it"
    ),
}


#: Engine-minted markers: a token this engine generated for one attempt, so "the
#: oracle saw it" and "the oracle saw something else" are distinguishable.
#: Anchored on the ``clinkz`` stem every generator here uses — a descriptive
#: indicator ("response time >= 5s", "no error from second statement") is not a
#: marker and is out of this rule's scope, because there is nothing to have seen.
_MINTED_MARKER_RE: re.Pattern[str] = re.compile(r"^[A-Za-z0-9_-]*clinkz[A-Za-z0-9_-]*$", re.I)

#: Shell commands whose OUTPUT some oracle recognises directly. A finding may
#: cite one of these channels only when the payload actually invoked it.
_COMMAND_CHANNELS: dict[str, tuple[str, ...]] = {
    "id": ("id",),
    "uname": ("uname",),
    "ver": ("ver", "systeminfo"),
    "whoami": ("whoami",),
}

#: How an observation names the channel it read. Matched against the observation
#: string the methodology itself wrote, never against target bytes.
_CHANNEL_CLAIM_RE: re.Pattern[str] = re.compile(
    r"\bmatched\s+(id|uname|ver|whoami)\s+output\b", re.I
)

#: An evidence entry the ENGINE wrote: nothing but ``key=value`` tokens.
_STRUCTURED_TOKEN_RE: re.Pattern[str] = re.compile(r"^[A-Za-z_][\w.-]*=\S*$")

#: The key the structured control entry is addressed by.
_CONTROL_KEY = "never_sent_control"


#: Shell metacharacters that turn a value into a second command. Removing them
#: is what makes a CMDI control inert while leaving the rest of the payload —
#: including the ``echo <marker>`` scaffold the oracle's reflection guard keys on
#: — byte-identical. ``${IFS}`` becomes a space rather than vanishing, because
#: deleting it would fuse ``echo`` to its argument and hide the scaffold from the
#: very guard the control exists to exercise.
_SHELL_SEPARATORS: tuple[tuple[str, str], ...] = (
    ("${IFS}", " "),
    ("$IFS", " "),
    ("$(", ""),
    ("&&", ""),
    ("||", ""),
    ("%0a", ""),
    (";", ""),
    ("|", ""),
    ("&", ""),
    ("`", ""),
    ("\n", ""),
)

#: Template delimiter pairs. A payload with these removed reflects exactly as the
#: original did and evaluates in no engine.
_TEMPLATE_DELIMITERS: tuple[str, ...] = (
    "{{",
    "}}",
    "{%",
    "%}",
    "<%=",
    "<%",
    "%>",
    "${",
    "#{",
    "*{",
    "~{",
    "@{",
    "{",
    "}",
)


def strip_shell_separators(payload: str) -> str:
    """*payload* with every command separator removed, everything else intact.

    ``value;echo clinkz123`` becomes ``valueecho clinkz123``: same reflection
    shape, same scaffold, no second command. What the oracle can still tell apart
    between the two is exactly the separator, which is the primitive.
    """
    out = payload
    for token, replacement in _SHELL_SEPARATORS:
        out = out.replace(token, replacement)
    return out


def strip_template_delimiters(payload: str) -> str:
    """*payload* with every template delimiter removed, everything else intact.

    ``#{...execSync('echo clinkz123')}`` becomes
    ``#...execSync('echo clinkz123')``: an echoing endpoint reflects it exactly
    as it reflected the real gadget, so the oracle's scaffold strip applies to
    both arms and only evaluation can separate them.
    """
    out = payload
    for token in _TEMPLATE_DELIMITERS:
        out = out.replace(token, "")
    return out


#: SQL keywords mapped to same-length non-keywords. Length and character class
#: are preserved deliberately — see :func:`sqli_inert_control`.
_SQL_KEYWORD_MANGLE: dict[str, str] = {
    "UNION": "UNIQN",
    "SELECT": "SELEQT",
    "SLEEP": "SLEEQ",
    "WAITFOR": "WAITFOQ",
    "PG_SLEEP": "PG_SLEEQ",
    "BENCHMARK": "BENCHMAQK",
    "DELAY": "DELAQ",
    "FROM": "FROQ",
    "WHERE": "WHEQE",
    "CONCAT": "CONCAQ",
    "AND": "AQD",
    "OR": "OQ",
    "LIKE": "LIQE",
    "CASE": "CAQE",
    "WHEN": "WHEQ",
}

#: Characters and tokens that let a value escape its literal and become syntax.
_SQL_BREAKOUT = ("'", '"', "`", ")", "(", "--", "#", "/*", "*/", ";")


def sqli_inert_control(payload: str, indicator_type: str, live_marker: str, decoy: str) -> str:
    """The SQLi control payload: same value, no SQL.

    **What the defining effect of a UNION confirmation actually is:** structured
    data the application could not have echoed — a cell the database returned
    because our query asked for it. The oracle approximates that by finding the
    marker somewhere the payload's own echo does not explain, and the whole
    approximation rests on ``_marker_only_in_payload_echo`` recognising the echo.
    That guard blanks a *verbatim* copy of the payload, so it fails against any
    sink that re-encodes on the way out — which is what Next.js App Router does
    when it puts the request's query string into the RSC flight payload
    percent-encoded, and why seven UNION HIGHs shipped from engagement
    ``d67835f5``.

    **The control has to round-trip the same way, or it is not a control.** A
    bare alphanumeric decoy is inert, but it is also encoding-invariant: it comes
    back byte-identical, the echo guard blanks it, and the oracle refuses — on
    the phantom target as readily as on the real one. It would have passed the
    portfolio run cleanly. So the control keeps every space, quote and comment
    marker the confirming payload carried, and neutralises only the SQL: each
    keyword becomes a same-length non-keyword (``UNION`` -> ``UNIQN``), so the
    percent-encoding of the control is byte-for-byte the shape of the confirming
    one and only the semantics differ. Against Next.js the control now reflects
    exactly as the payload did, the guard misses it exactly as it missed the
    payload, the oracle confirms on a probe that cannot union, and the finding
    dies. Against DVWA the mangled keyword is a syntax error, the union branch
    rejects a marker inside a database error, the oracle refuses, and the genuine
    finding stands.

    That is the whole answer to "is a UNION-specific oracle larger than the
    never-sent arm": it is not. The arm is sufficient once the control differs
    from the confirming payload in the primitive and in nothing else.

    Every other channel has a different primitive, so the neutralisation follows
    it: ``error_string`` and ``time_delta`` confirm on the value ESCAPING its
    literal, so the break-out punctuation goes too and what is left is an
    ordinary value; ``content_diff`` and ``auth_bypass`` confirm on a difference
    between two arms, so the caller sends the same value down both and any
    surviving difference is noise rather than signal.

    Args:
        payload: The confirming payload.
        indicator_type: The channel it confirmed on.
        live_marker: The marker the confirming payload carried.
        decoy: The marker the control carries instead.

    Returns:
        A payload that cannot alter a query and reflects like the original.
    """
    out = rebind_marker(payload, live_marker, decoy)
    if not is_minted_marker(live_marker) and live_marker and live_marker in out:
        out = out.replace(live_marker, decoy)
    for keyword, mangled in _SQL_KEYWORD_MANGLE.items():
        out = re.sub(rf"\b{keyword}\b", mangled, out, flags=re.I)
    if (indicator_type or "").strip().lower() not in ("union_data", "union", "union_based"):
        for token in _SQL_BREAKOUT:
            out = out.replace(token, "")
    return out or decoy


def rebind_marker(payload: str, live_marker: str, decoy: str) -> str:
    """*payload* with a minted *live_marker* swapped for *decoy*.

    Left alone when the indicator is not a minted marker (an arithmetic product,
    a threshold description): there is nothing to re-mint, and substituting into
    the payload would change what the control asks for.
    """
    if not is_minted_marker(live_marker):
        return payload
    return payload.replace(live_marker, decoy)


def mint_decoy(stem: str, nonce: int) -> str:
    """A decoy marker of the same shape as *stem*'s live markers.

    Minted alongside the live marker and carried ONLY by the control arm, so a
    confirmation that cites it is citing something the confirming request never
    contained.

    Args:
        stem: Short class stem, e.g. ``"cmdi"``.
        nonce: Caller-supplied randomness. The caller owns the RNG so this stays
            pure and the unit suite can pin it.

    Returns:
        A marker such as ``clinkzdecoycmdi48211``.
    """
    return f"clinkzdecoy{stem}{nonce}"


def is_minted_marker(indicator: str) -> bool:
    """Whether *indicator* is a marker this engine minted for one attempt."""
    return bool(indicator) and bool(_MINTED_MARKER_RE.match(indicator.strip()))


def payload_invokes(payload: str, channel: str) -> bool:
    """Whether *payload* actually invokes the command behind *channel*.

    Word-boundary matched, because ``id`` is a substring of half the parameter
    names on the web and an oracle reading ``uid=`` out of a page must be able to
    say that the payload asked for it.
    """
    tokens = _COMMAND_CHANNELS.get(channel.lower())
    if not tokens:
        return False
    return any(re.search(rf"(?<![\w-]){re.escape(t)}\b", payload, re.I) for t in tokens)


def attribution_contradiction(
    *, expected_indicator: str, indicator_observed: str, payload: str
) -> str | None:
    """The reason *indicator_observed* is not attributable to *payload*, if any.

    A confirmation is a claim that a specific thing was seen. Two ways that claim
    refutes itself in its own evidence, both deterministic:

    1. The observation cites a COMMAND-OUTPUT channel the payload never invoked.
       ``;echo <canary>`` runs ``echo``; it does not print ``uname`` output, so a
       ``uname`` banner in the body came from the page rather than the injection.
    2. The engine minted a marker for this attempt and the observation does not
       cite it — it cites something else entirely.

    Returns:
        A short string naming the contradiction, or ``None`` when the observation
        is attributable. Descriptive indicators (``"response time >= 5s"``) are
        not minted markers and return ``None``: there is no marker to have seen,
        and those channels carry their own thresholds.
    """
    observed = (indicator_observed or "").strip()
    if not observed:
        return None

    claim = _CHANNEL_CLAIM_RE.search(observed)
    if claim is not None:
        channel = claim.group(1).lower()
        if not payload_invokes(payload or "", channel):
            return (
                f"the observation cites {channel!r} command output, which the payload "
                f"{payload!r} never invokes — the banner was already on the page"
            )
        return None

    expected = (expected_indicator or "").strip()
    if not is_minted_marker(expected):
        return None
    if expected.lower() in observed.lower():
        return None
    return (
        f"expected_indicator={expected!r} was minted for this attempt and the "
        f"observation does not cite it: indicator_observed={observed!r}"
    )


@dataclass(frozen=True)
class ControlVerdict:
    """What the control arm did, as a record of arms run rather than an assertion.

    Attributes:
        decoy: The marker the CONTROL arm carried. Minted alongside the live
            marker and never present in the confirming payload.
        dispatched: Whether a control probe actually went out. A control that was
            not sent proves nothing, and is not the same as one that refused.
        oracle_refused: Whether the SAME oracle, run over the control arm, said
            no. This is the whole point: an oracle that confirms on a probe with
            the exploitation mechanism removed is not measuring the vulnerability.
        decoy_absent_from_confirming: Whether the decoy is absent from the
            confirming payload — the literal never-sent property. ``False`` means
            the arms were not independent and the verdict means nothing.
        detail: Note for the trace and the evidence. Never parsed.
    """

    decoy: str
    dispatched: bool
    oracle_refused: bool
    decoy_absent_from_confirming: bool = True
    detail: str = ""

    @property
    def satisfied(self) -> bool:
        """Whether this arm licenses a confirmation."""
        return bool(
            self.decoy
            and self.dispatched
            and self.oracle_refused
            and self.decoy_absent_from_confirming
        )

    @property
    def status(self) -> str:
        """One word for the structured evidence entry and the trace."""
        if not self.dispatched:
            return "not_dispatched"
        if not self.decoy_absent_from_confirming:
            return "decoy_leaked_into_confirming_arm"
        return "refused" if self.oracle_refused else "confirmed_on_control"


def indicator_is_self_controlled(test_method: str, indicator_type: str) -> str | None:
    """Why *indicator_type* on *test_method* dispatches its own control arm.

    Read from the PRODUCER's declaration
    (:attr:`~clinkz.models.vuln_classes.VulnClass.control_arm`) rather than
    inferred, because neither the class name nor the indicator name carries the
    fact: ``_test_sqli``'s ``auth_bypass`` channel is a three-arm differential
    whose contradiction and benign arms are dispatched and must refuse, while
    ``_test_nosqli``'s channel of the same NAME compares a probe against a benign
    baseline and has no shape-matched contradiction at all. A consumer keying on
    either string alone gets one of them wrong.

    Args:
        test_method: The ``_test_*`` class.
        indicator_type: The channel the finding says it confirmed on.

    Returns:
        The declared reason, or ``None`` when this channel is not declared
        self-controlled — which is every channel of every class by default.
    """
    from clinkz.models.vuln_classes import VULN_CLASSES

    indicator = (indicator_type or "").strip().lower()
    if not indicator:
        return None
    for vuln_class in VULN_CLASSES:
        if vuln_class.test_method != test_method:
            continue
        arm = vuln_class.control_arm
        if indicator in tuple(i.lower() for i in arm.self_controlled_indicators):
            return arm.reason
        return None
    return None


def control_required(test_method: str) -> bool:
    """Whether *test_method*'s oracle is bound by the never-sent-control rule."""
    return test_method in MARKER_ORACLE_CLASSES


def control_evidence_lines(verdict: ControlVerdict | None) -> list[str]:
    """Render *verdict* as evidence the emission gate can read back.

    The first entry is fully structured (``key=value`` tokens only, no interior
    whitespace) so it qualifies under the engine-written-entries rule; the detail
    rides a second, prose entry that nothing parses.
    """
    if verdict is None:
        return [f"{_CONTROL_KEY}=absent"]
    lines = [
        f"{_CONTROL_KEY}={verdict.status} "
        f"control_decoy={verdict.decoy or 'none'} "
        f"control_dispatched={verdict.dispatched} "
        f"control_oracle_refused={verdict.oracle_refused} "
        f"control_decoy_absent={verdict.decoy_absent_from_confirming}"
    ]
    if verdict.detail:
        lines.append(f"Control arm: {verdict.detail}")
    return lines


def structured_evidence_field(evidence: list[str], key: str) -> str:
    """The value of *key*, read only from entries the ENGINE wrote.

    Same restriction, and the same reason, as
    :func:`control_verdict_from_evidence`: a finding's evidence carries raw
    response bytes at index 1, so a plain prefix scan reads the TARGET's bytes
    first. Any value that decides how a finding is graded must come from an entry
    made entirely of ``key=value`` tokens, or the host under test gets a vote.

    Args:
        evidence: The finding's evidence entries.
        key: The field name, e.g. ``indicator_type``.

    Returns:
        The first value found, or ``""``.
    """
    for entry in evidence:
        tokens = entry.split()
        if not tokens or not all(_STRUCTURED_TOKEN_RE.match(t) for t in tokens):
            continue
        for token in tokens:
            name, _, value = token.partition("=")
            if name == key:
                return value
    return ""


def control_verdict_from_evidence(evidence: list[str]) -> ControlVerdict | None:
    """Read back the control arm from *evidence*, or ``None`` when absent.

    Only fully-structured entries are read — every whitespace-separated token
    must be ``key=value``. A finding's evidence carries raw response bytes at
    index 1, so a target that echoed ``never_sent_control=refused`` in its own
    body would otherwise hand itself the power to license a phantom. Same rule,
    and the same reason, as the ``strength=`` reader.
    """
    for entry in evidence:
        tokens = entry.split()
        if not tokens or not all(_STRUCTURED_TOKEN_RE.match(t) for t in tokens):
            continue
        fields = {k: v for k, _, v in (t.partition("=") for t in tokens)}
        status = fields.get(_CONTROL_KEY)
        if status is None:
            continue
        if status == "absent":
            return None
        decoy = fields.get("control_decoy", "")
        return ControlVerdict(
            decoy="" if decoy in ("", "none") else decoy,
            dispatched=fields.get("control_dispatched") == "True",
            oracle_refused=fields.get("control_oracle_refused") == "True",
            decoy_absent_from_confirming=fields.get("control_decoy_absent") == "True",
        )
    return None
