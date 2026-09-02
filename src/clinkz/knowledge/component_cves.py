"""Known-CVE matching over the observed component inventory.

The missing rung. Every piece of this path already existed — fingerprinting
names products, ``-sV`` resolves versions, :mod:`clinkz.discovery.versions`
compares them against a predicate grammar, and the Exploit Agent has seven
confirmation oracles — and yet no engagement ever ran
``fingerprint → component+version → known CVE → test``, because nothing joined
the first half to the second.

**The emission rule is the whole design, and it is not negotiable: a CVE match
on a version string is a LEAD, never a finding.** A version number is not an
exploit. It is a claim about what software is installed, made by a fingerprinter
reading a banner the target chose to send, about a component that may be
patched, back-ported, unreachable, or not the code path the CVE describes. The
same rule already correctly demoted the sqlmap-only SQLi, and for the same
reason: somebody else's conclusion is not an observation we made.

So a match produces one of exactly two outcomes:

* **DISPATCH** — an oracle can witness the CVE's defining effect AND this plan
  source can carry the CVE's input to it. The match becomes a *dispatch hint*:
  the class runs against the live target, and if its own oracle witnesses the
  effect, the normal emission path emits a normal finding. The CVE is then
  CONTEXT on that finding ("this is consistent with CVE-…"), never its proof. If
  the oracle does not confirm, the match stays a lead — a version match cannot
  rescue a failed confirmation.
* **LEAD** — anything else. Recorded as an :class:`UnprovenExploitLead` naming
  the observed version, the affected range, and the observation that WOULD prove
  it. This is the honest majority case and it is not a failure: "this host
  reports a version in the affected range and we could not test the effect" is a
  true, useful, actionable sentence. "This host is vulnerable to CVE-…" would
  not be.

An oracle is not enough, and finding out why cost two entries
------------------------------------------------------------
``confirming_test_method`` was the single field deciding between those two, and
it answers only half the question. The other half is WHERE the CVE's input has
to arrive, and the two Apache path-traversal rows are what happens when nobody
asks it: both named ``_test_lfi``, both reserved a plan slot, and the oracle
sends its probe as a QUERY-PARAMETER VALUE while the CVE is reached by
traversing an aliased directory in the URL PATH. Measured — three requests, zero
of them mutating the path. The vector was never sent, and the lead the run
produced said ``version_match_oracle_ran_and_did_not_confirm``: *we tested it
and saw nothing*, about a test that did not happen.

That is this module's own emission rule failing in the direction it was not
watching. It refuses to let a version match become a finding; it did not refuse
to let one become a **coverage claim**. So :class:`CVEVector` is declared per
entry, :data:`CARRIABLE_VECTORS` says what this plan source can actually
deliver, and :attr:`ComponentCVEMatch.can_dispatch` reads both. The rows stay in
the catalogue with their oracle named — the oracle is right, the carrier is
missing, and :data:`LEAD_VECTOR_NOT_CARRIED` is the sentence that says so.

**Catalogue size is bounded by oracle coverage, not by feed size.** An entry
with no oracle behind it is declared lead-only at write time, never discovered
to be lead-only at run time. That is the difference between this and a wall of
"potentially affected" — and the same bound is why the catalogue is small: it
carries no benchmark's vocabulary, every entry is a published CVE against a
widely-deployed component, and an entry earns its place by being matchable from
an observation a producer in this engine actually makes.

Band C: permanently lead-only, and that is a product property
-------------------------------------------------------------
Denial of service, memory safety, local privilege escalation, a vulnerability
conditional on a configuration we cannot observe, and an information leak whose
effect is visible only somewhere we are not: no remote oracle can prove any of
them, and no future confirmation primitive changes that. Proving a
resource-exhaustion claim means degrading the client's service, which
:mod:`clinkz.safety.destructive` refuses on every target; proving a third-party
credential leak means observing the third party. These are not a backlog. They
are marked :attr:`CVEVector.ENVIRONMENTAL`, they are always leads, and the
deliverable states why rather than quietly listing them beside things we tested.

Affected ranges are **half-open**
--------------------------------
Every bounded entry is written ``[introduced, fixed)`` — the form the advisory
itself states, because the advisory names the version the fix landed in and does
not name the last version released before it. Writing the closed form obliges
the author to supply that second fact from memory, and getting it wrong
under-matches by one release, which produces a MISSED finding rather than a
false one: invisible by construction, and unreachable by every control arm in
this engine. The rule and its property tests live in
:mod:`clinkz.discovery.versions`; the artifact it was introduced to remove is
still visible in this file's own history — jQuery CVE-2020-11022 (advisory
``>= 1.2, < 3.5.0``) was carried as ``[1.2.0,3.4.9]``, a hand-guessed "last
vulnerable version" that silently excluded ``3.4.95``.

Back-ports: provenance gates the CLAIM, never the TEST
------------------------------------------------------
A distribution routinely back-ports a security fix without moving the version,
so ``Apache/2.4.49`` from a ``Server:`` header may be patched and a banner
cannot tell you. The obvious response — refuse to dispatch unless the version
came from a lockfile — is the wrong one, and the reason is the shape of this
whole module: **a dispatch is a hypothesis handed to our own oracle, not a
claim.** A back-ported host in the affected range gets tested, the oracle
observes nothing, and the match stays a lead. Nothing false is emitted, because
the oracle is the gate; refusing the dispatch would instead delete the engine's
only published-CVE coverage of the component class most often observed by
banner, and buy no honesty that ``_persist_finding`` does not already enforce.

Where provenance DOES decide is the other outcome. An unconfirmable match
becomes a lead — a sentence in the deliverable, resting entirely on the version
string, with no oracle behind it to catch a back-port. So a lead whose version
came from a string the target composed says so, verbatim
(:data:`BACKPORT_CAVEAT`), and provenance orders the scarce reserved plan slots
(:func:`match_components`) so lockfile-grade evidence is what gets tested when
the ceiling bites. The disposition is recorded per match
(:attr:`ComponentCVEMatch.disposition`) rather than left to emerge from a
conditional somewhere downstream.
"""

from __future__ import annotations

import re
from enum import StrEnum

from pydantic import BaseModel

from clinkz.discovery.versions import version_satisfies
from clinkz.models.recon import DetectedComponent, VersionProvenance, version_provenance_rank


class CVEVector(StrEnum):
    """WHERE in a request the CVE's attacker-controlled input has to arrive.

    The field that decides whether naming an oracle is a real claim or an
    aspiration, and it exists because the catalogue got that wrong twice.

    A dispatch from this plan source builds one
    :class:`~clinkz.models.finding.ExploitTask` and hands it to a ``_test_*``
    method. Every injection oracle in this engine is **parameter-scoped**: it
    iterates ``PageAnalysis.input_params`` and carries its probe as a parameter
    VALUE. Measured, by running each Band-A oracle against a page with a
    file-shaped parameter and recording every request it issued:

        _test_lfi on ``http://host/`` with param ``file``
          GET /?file=            GET /?file=../          GET /?file=/etc/passwd
          0 of 3 requests mutate the URL PATH.

    CVE-2021-41773 is a traversal through an ALIASED DIRECTORY in the URL path
    (``/cgi-bin/.%2e/%2e%2e/etc/passwd``). Those three probes cannot witness it,
    and no ranking, endpoint choice or budget makes them able to — the oracle is
    testing a different vulnerability that shares a name. The entry nonetheless
    declared ``confirming_test_method="_test_lfi"``, so the match spent a
    reserved plan slot and, when nothing came back, recorded the lead
    ``version_match_oracle_ran_and_did_not_confirm`` — "we tested it and saw
    nothing", about a vector never sent.

    That is the emission rule failing in the one direction it was not watching.
    The module refuses to let a version match become a finding; it did not
    refuse to let a version match become a **coverage claim**. Both are claims
    about work done, and only one of them was gated.

    So the vector is DECLARED per entry and the code READS the declaration, the
    same shape as :class:`~clinkz.models.vuln_classes.MultiPrincipalRequirement`
    and :attr:`~clinkz.models.vuln_classes.VulnClass.control_arm`: the producer
    states what its CVE needs, and dispatchability is computed from it rather
    than assumed by whoever wrote the row.
    """

    #: A query-string, form-body or JSON-body parameter VALUE. The only shape
    #: this plan source can carry today, because it is the only shape every
    #: ``_test_*`` method already sends.
    REQUEST_PARAM = "request_param"
    #: The URL path itself — a traversal through an alias, a path segment
    #: substituted into a file name. The discovery engine can carry this
    #: (``ParamLocation.PATH`` plus ``CARRIER_PATH_TRAVERSAL``); a
    #: component-derived task cannot, because it is built with no
    #: ``param_locations`` and no carrier constraints.
    URL_PATH = "url_path"
    #: A request HEADER value (``User-Agent``, ``X-Api-Version``). No
    #: methodology carries a probe here.
    HTTP_HEADER = "http_header"
    #: The whole request BODY as a document — an XML entity, a deserialised
    #: blob, a multipart part. ``_test_xxe`` and ``_test_file_upload`` build
    #: these for themselves; the CVE plan source hands them nothing to build on.
    REQUEST_BODY_DOCUMENT = "request_body_document"
    #: Reached over a protocol that is not the HTTP surface this engine tests.
    NON_HTTP = "non_http"
    #: Not request-carried at all: a configuration the operator writes, a local
    #: user, a resource-exhaustion property of the process. Band C.
    ENVIRONMENTAL = "environmental"


#: The vectors a component-derived :class:`ExploitTask` can actually CARRY.
#:
#: Exactly one, and the narrowness is the point: this set is a statement about
#: the plan source, not about the oracles. ``_test_lfi`` can absolutely witness
#: a path traversal when the discovery engine hands it
#: ``ParamLocation.PATH`` + ``CARRIER_PATH_TRAVERSAL``; the CVE source builds no
#: such task. Widening this set is a CODE change (build the carrier) followed by
#: a live proof, never an edit to a catalogue row.
CARRIABLE_VECTORS: frozenset[CVEVector] = frozenset({CVEVector.REQUEST_PARAM})

#: Vectors that are permanently unprovable from outside the process — Band C.
#:
#: The distinction from the rest of the non-carriable set is the WORD
#: "permanently". A ``URL_PATH`` entry is a missing carrier: build it, prove it
#: live, and the row becomes dispatchable. An ``ENVIRONMENTAL`` entry is not
#: waiting for anything — proving it needs either an attack the safety rails
#: refuse to send or an observation made somewhere this engine does not stand.
#: Read by the report so the two are rendered as different sentences.
BAND_C_VECTORS: frozenset[CVEVector] = frozenset({CVEVector.ENVIRONMENTAL})


class KnownComponentCVE(BaseModel):
    """One published vulnerability, keyed on a component and a version range.

    Attributes:
        cve_id: The CVE identifier.
        component: Case-insensitive regex matched against the observed component
            NAME. A regex rather than a literal because fingerprinters spell the
            same product several ways ("Apache", "Apache httpd", "Apache/2.4.49").
        affected: Version predicate over :mod:`clinkz.discovery.versions`'
            grammar. A bounded entry is written **half-open**,
            ``[introduced,fixed)`` — the advisory's own form, and the only one
            that does not oblige the author to guess the last release before the
            fix (see the module docstring). ``<X`` is its unbounded-below
            spelling. ``*`` means "every version this catalog knows of" and is
            used only where the vulnerability is not version-bounded.
        title: Human summary for the lead or the finding's context line.
        severity: CVSS band, as published. Used for lead ordering ONLY — it never
            becomes a finding's severity, because the finding's severity comes
            from what our own oracle witnessed.
        confirming_test_method: The ``_test_*`` whose oracle can witness this
            CVE's defining effect, or ``""`` when this engine has none. It is
            no longer the single field that decides lead-vs-dispatch — see
            :attr:`vector`, which is the other half of the same question.
        defining_effect: The effect ``confirming_test_method``'s oracle proves,
            in the oracle's own terms. Written so the row can be checked against
            :mod:`clinkz.agents._control_arm`'s partition without opening the
            methodology: if this sentence is not what that oracle confirms on,
            the row names the wrong method. Required whenever a method is named.
        vector: Where the attacker-controlled input has to arrive. Decides
            whether the named oracle is REACHABLE from a component-derived task
            (:data:`CARRIABLE_VECTORS`), which is a different question from
            whether an oracle exists at all.
        identifiable_by: Provenance grades that can NAME this component, or
            ``None`` for "any of them". Not a policy gate on testing — the
            module's position that provenance gates the CLAIM and never the TEST
            is unchanged, and every grade listed here dispatches identically.
            It is an OBSERVABILITY declaration: ``nmap -sV`` and ``whatweb``
            fingerprint servers, so a row reading ``ejs 3.1.6`` with
            :attr:`~clinkz.models.recon.VersionProvenance.BANNER` provenance did
            not come from a weaker observation of ejs, it came from something
            that is not ejs. Refusing to spend a probe on a mis-parse is not
            provenance-gating a test; there is no observation to test.
        proving_observation: What would have to be observed for this to be a
            finding. Rendered verbatim into the lead's ``missing_observation``,
            so a reader is told precisely what was not done.
        reference: Where the affected range comes from, stated precisely enough
            that a reader can re-derive the interval from the advisory.
    """

    cve_id: str
    component: str
    affected: str
    title: str
    severity: str = "medium"
    confirming_test_method: str = ""
    defining_effect: str = ""
    vector: CVEVector = CVEVector.ENVIRONMENTAL
    identifiable_by: frozenset[VersionProvenance] | None = None
    proving_observation: str = ""
    reference: str = ""


class MatchDisposition(StrEnum):
    """What a match is allowed to become. A closed vocabulary of exactly two.

    There is deliberately no third value. A version match either becomes a task
    for an oracle that can witness the CVE's defining effect, or it becomes a
    lead that says what would have proven it — the two outcomes the module
    docstring's emission rule allows.
    """

    #: An oracle exists for this CVE's effect: hand it the hypothesis and let it
    #: decide. The oracle is the gate, so an in-range-but-patched host costs a
    #: plan slot and emits nothing.
    DISPATCH = "dispatch"
    #: The match is a claim about a version string and nothing more, so it
    #: renders as an ``UnprovenExploitLead``. Three different facts land here
    #: and :attr:`ComponentCVEMatch.lead_reason` says which.
    LEAD = "lead"


#: Why a match is a LEAD. Kept as module constants rather than written at the
#: call site because they are also entries in
#: :data:`~clinkz.models.finding.UNPROVEN_WHY_UNCONFIRMED`, and a lead's reason
#: is the only thing an operator can act on — a wrong one is worse than a vague
#: one, which is the mistake the vector split exists to correct.
#:
#: "This engine has no oracle for that effect."
LEAD_NO_ORACLE = "version_match_only_no_oracle_for_this_cve"
#: "This engine HAS the oracle and cannot carry the CVE's vector to it." The
#: distinction matters because the two have different fixes: the first waits on
#: a new confirmation primitive, the second waits on a carrier, and only the
#: second is a coverage gap in a class we already claim.
LEAD_VECTOR_NOT_CARRIED = "version_match_vector_not_carried_by_this_engine"
#: "Nothing that can NAME this component reported it." The observation is not
#: weak, it is not an observation of this component at all.
LEAD_UNIDENTIFIABLE = "version_match_provenance_cannot_identify_this_component"


#: Provenances a back-ported fix defeats without moving the version number.
#:
#: All three are strings the target composed — a ``Server:`` header, a version
#: comment baked into a served bundle, or an observation whose producer declared
#: nothing. None of them names a RESOLVED dependency, which is what a lockfile,
#: an artifact hash or an exact manifest pin does. Read only to qualify a LEAD's
#: wording; it never gates a dispatch (see the module docstring).
BACKPORT_DEFEASIBLE_PROVENANCE: frozenset[VersionProvenance] = frozenset(
    {
        VersionProvenance.ARTIFACT_STRING,
        VersionProvenance.BANNER,
        VersionProvenance.UNDECLARED,
    }
)

#: Appended verbatim to a defeasible match's observation, so the sentence a
#: client reads carries the weakness of the evidence it rests on.
BACKPORT_CAVEAT = (
    "this version was read from a string the target composed, and a back-ported "
    "fix defeats it without moving the number"
)


class ComponentCVEMatch(BaseModel):
    """An observed component that falls inside a published affected range.

    Attributes:
        component: The observation that matched — name, version, and which tool
            made it, so a reader can weigh the fingerprint itself.
        cve: The catalogue entry it matched.
        matched_on: Why it matched, in words, for the lead's raw observation.
    """

    component: DetectedComponent
    cve: KnownComponentCVE
    matched_on: str = ""

    @property
    def is_confirmable(self) -> bool:
        """Whether an oracle in this engine can witness this CVE's effect.

        A statement about the ORACLE only. It stays true for a path-traversal
        CVE whose effect ``_test_lfi`` proves every day on a parameterised
        endpoint — which is why it is no longer sufficient to dispatch on. See
        :attr:`can_dispatch`.
        """
        return bool(self.cve.confirming_test_method)

    @property
    def vector_is_carriable(self) -> bool:
        """Whether a component-derived task can deliver this CVE's input."""
        return self.cve.vector in CARRIABLE_VECTORS

    @property
    def component_is_identifiable(self) -> bool:
        """Whether a producer that can NAME this component made the observation.

        ``None`` means the entry declares no restriction, which is the default
        and matches every row written before the field existed.
        """
        allowed = self.cve.identifiable_by
        return allowed is None or self.provenance in allowed

    @property
    def can_dispatch(self) -> bool:
        """Whether this match may spend a reserved plan slot.

        Three independent facts, all required, none of them provenance-as-policy
        (see :attr:`~KnownComponentCVE.identifiable_by`): an oracle exists for
        the effect, this plan source can carry the CVE's input to it, and
        something capable of naming the component is what reported it.
        """
        return self.is_confirmable and self.vector_is_carriable and self.component_is_identifiable

    @property
    def lead_reason(self) -> str:
        """Which of the three LEAD facts this match is, from the closed set.

        Ordered most-specific-first so a row that is several kinds of
        unconfirmable reports the one an operator can act on: an observation
        that is not of this component at all outranks a missing carrier, which
        outranks a missing oracle.
        """
        if not self.component_is_identifiable:
            return LEAD_UNIDENTIFIABLE
        if not self.is_confirmable:
            return LEAD_NO_ORACLE
        if not self.vector_is_carriable:
            return LEAD_VECTOR_NOT_CARRIED
        return LEAD_NO_ORACLE

    @property
    def provenance(self) -> VersionProvenance:
        """How the version this match rests on was observed."""
        return self.component.provenance

    @property
    def backport_defeasible(self) -> bool:
        """Whether a back-ported fix could defeat this match's version evidence.

        True for every provenance that is a string the target composed. It
        qualifies the wording of a LEAD and orders the reserved plan slots; it
        never decides whether the match is tested.
        """
        return self.provenance in BACKPORT_DEFEASIBLE_PROVENANCE

    @property
    def disposition(self) -> MatchDisposition:
        """What this match may become — recorded here, not inferred downstream.

        Reads :attr:`can_dispatch`, not confirmability alone. Version-evidence
        STRENGTH is still deliberately absent: an oracle refusing a back-ported
        host is the honest outcome, while never running it is a silent coverage
        loss, so a ``BANNER``-derived match of an entry a banner CAN name is
        dispatched exactly as a lockfile-derived one is.
        """
        return MatchDisposition.DISPATCH if self.can_dispatch else MatchDisposition.LEAD


#: The catalogue.
#:
#: Every entry is a published CVE against a component a fingerprinter can name
#: from a banner. ``confirming_test_method`` is filled ONLY where this engine
#: genuinely has an oracle for that CVE's defining effect — an entry claiming a
#: method that cannot actually witness the effect would turn a version match into
#: a finding through the back door, which is the one thing this module exists to
#: prevent.
KNOWN_COMPONENT_CVES: tuple[KnownComponentCVE, ...] = (
    # --- DISPATCH: an oracle exists AND this source can carry the vector -----
    #
    # Every row here satisfies all three parts of ``can_dispatch``. The
    # ``defining_effect`` is written in the named oracle's own terms so the pair
    # can be checked without opening the methodology.
    KnownComponentCVE(
        cve_id="CVE-2021-44228",
        component=r"log4j|solr|elasticsearch|logstash",
        affected="[2.0,2.15.0)",
        title="Log4Shell — JNDI lookup in a logged value",
        severity="critical",
        confirming_test_method="_test_log4shell",
        defining_effect=(
            "an outbound JNDI/DNS resolution performed by the target, carrying a "
            "nonce that existed only in the one probe that was sent"
        ),
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "an out-of-band callback carrying our single-use nonce, arriving at the "
            "collaborator from the target"
        ),
        reference="NVD CVE-2021-44228 (Log4j 2.x, introduced 2.0, fixed 2.15.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2019-17558",
        component=r"^solr$|apache\s+solr",
        affected="[5.0.0,8.4.0)",
        title="Apache Solr Velocity template injection via a request parameter",
        severity="critical",
        confirming_test_method="_test_ssti",
        defining_effect=(
            "a template expression this engine supplied in a parameter value, "
            "EVALUATED server-side and returned as its computed result rather than "
            "as the literal text that was sent"
        ),
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "the arithmetic result of an expression we authored appearing in the "
            "response body, with an inert control expression of the same shape "
            "returning unevaluated"
        ),
        reference=(
            "NVD CVE-2019-17558 (Apache Solr 5.0.0 through 8.3.1; fixed 8.4.0) — "
            "params.resource.loader.enabled permits a Velocity template supplied in "
            "the v.template / v.template.custom.tool request parameters"
        ),
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-27905",
        component=r"^solr$|apache\s+solr",
        affected="[5.0.0,8.8.2)",
        title="Apache Solr ReplicationHandler SSRF via the masterUrl parameter",
        severity="high",
        confirming_test_method="_test_ssrf",
        defining_effect=(
            "content from an address only the SERVER can reach, returned in the "
            "response to a request whose parameter named that address"
        ),
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "an internal-service or cloud-metadata signature in the response body, "
            "chosen so an echo of the URL we sent can never match it — or, for the "
            "blind case, an out-of-band callback bearing our nonce"
        ),
        reference=(
            "NVD CVE-2021-27905 (Apache Solr 5.0.0 through 8.8.1; fixed 8.8.2) — "
            "ReplicationHandler's masterUrl/leaderUrl parameter is not restricted "
            "to an allow-list"
        ),
    ),
    KnownComponentCVE(
        cve_id="CVE-2022-29078",
        component=r"^ejs$",
        affected="<3.1.7",
        title="ejs server-side template injection via render options pollution",
        severity="critical",
        confirming_test_method="_test_ssti",
        defining_effect=(
            "a template expression this engine supplied in a parameter value, "
            "EVALUATED server-side and returned as its computed result"
        ),
        vector=CVEVector.REQUEST_PARAM,
        # ejs runs on the server. Nothing that reads a banner or a served bundle
        # can name it, so a row claiming ``ejs`` at BANNER strength is a
        # mis-parse of something else rather than a weaker sighting of ejs.
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "the arithmetic result of an expression we authored appearing in the "
            "rendered response, with an inert control expression of the same shape "
            "returning unevaluated"
        ),
        reference="NVD CVE-2022-29078 (ejs < 3.1.7; fixed 3.1.7)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-21315",
        component=r"^systeminformation$",
        affected="<5.3.1",
        title="systeminformation command injection through an unsanitised argument",
        severity="high",
        confirming_test_method="_test_cmdi",
        defining_effect=(
            "the output of a command this engine chose, appearing in the response "
            "body, with a shell-separator-stripped control of the same shape "
            "producing no such output"
        ),
        vector=CVEVector.REQUEST_PARAM,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "command output we can attribute to the payload that produced it, "
            "absent from the benign baseline and absent from the control arm"
        ),
        reference="NVD CVE-2021-21315 (systeminformation < 5.3.1; fixed 5.3.1)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2023-22578",
        component=r"^sequelize$",
        affected="<6.28.1",
        title="Sequelize SQL injection through unescaped replacements",
        severity="high",
        confirming_test_method="_test_sqli",
        defining_effect=(
            "the database evaluating an expression this engine supplied — a value "
            "the application never stored appearing in the result set, with an "
            "inert control of the same shape returning the baseline"
        ),
        vector=CVEVector.REQUEST_PARAM,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "a value only the DATABASE could have computed, returned in the "
            "response and absent from both the benign baseline and the never-sent "
            "control"
        ),
        reference="NVD CVE-2023-22578 (Sequelize < 6.28.1; fixed 6.28.1)",
    ),
    # --- LEAD: the oracle EXISTS and this source cannot carry the vector -----
    #
    # A different sentence from "we have no oracle", and it took a measurement
    # to tell them apart. Both Apache rows below declared ``_test_lfi`` and
    # reserved a plan slot for two releases; the oracle sends three
    # QUERY-PARAMETER probes and never mutates the URL path, so the CVE's own
    # vector was never issued and the resulting lead said "the oracle ran and
    # did not confirm". It ran; it did not test this.
    KnownComponentCVE(
        cve_id="CVE-2021-41773",
        component=r"apache(\s+http\w*)?$|^httpd$",
        affected="[2.4.49,2.4.50)",
        title="Apache HTTP Server path traversal / file disclosure",
        severity="critical",
        confirming_test_method="_test_lfi",
        defining_effect=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline"
        ),
        vector=CVEVector.URL_PATH,
        proving_observation=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline. This engine's file-read "
            "oracle carries its probe as a PARAMETER VALUE, and this CVE is reached "
            "by traversing an aliased directory in the URL PATH "
            "(/cgi-bin/.%2e/%2e%2e/etc/passwd), which no component-derived task "
            "sends. The oracle is right and the carrier is missing"
        ),
        reference="NVD CVE-2021-41773 (Apache httpd 2.4.49; fixed 2.4.50)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-42013",
        component=r"apache(\s+http\w*)?$|^httpd$",
        affected="[2.4.50,2.4.51)",
        title="Apache HTTP Server path traversal — incomplete fix for CVE-2021-41773",
        severity="critical",
        confirming_test_method="_test_lfi",
        defining_effect=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline"
        ),
        vector=CVEVector.URL_PATH,
        proving_observation=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline. Same missing carrier as "
            "CVE-2021-41773: the vector is a doubly-encoded traversal in the URL "
            "path, and a component-derived task carries only parameter values"
        ),
        reference="NVD CVE-2021-42013 (Apache httpd 2.4.50; fixed 2.4.51)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-17519",
        component=r"^flink$|apache\s+flink",
        affected="[1.11.0,1.11.3)",
        title="Apache Flink JobManager arbitrary file read via a path segment",
        severity="high",
        confirming_test_method="_test_lfi",
        defining_effect=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline"
        ),
        vector=CVEVector.URL_PATH,
        proving_observation=(
            "file content outside the log directory returned by /jobmanager/logs/. "
            "The traversal is a PATH SEGMENT that must survive as one opaque "
            "%252f-encoded unit; the gray-box discovery engine builds that carrier "
            "(CARRIER_PATH_TRAVERSAL) and the component-CVE plan source does not"
        ),
        reference="NVD CVE-2020-17519 (Apache Flink 1.11.0 through 1.11.2; fixed 1.11.3)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2017-12629",
        component=r"^solr$|apache\s+solr",
        affected="<7.1.0",
        title="Apache Solr XML external entity expansion through a query parameter",
        severity="high",
        confirming_test_method="_test_xxe",
        defining_effect=(
            "the content of a local file, pulled in by an external entity this "
            "engine declared and returned in the response"
        ),
        # The payload is an XML document, but it arrives inside a query
        # parameter rather than as the request body ``_test_xxe`` builds. The
        # oracle is the right one and its carrier is the wrong shape, so this is
        # the vector gap and not the oracle gap.
        vector=CVEVector.REQUEST_BODY_DOCUMENT,
        proving_observation=(
            "file content resolved by an entity we declared, returned in the "
            "response. This engine's XXE oracle sends an XML request BODY; this "
            "CVE is reached with an XML fragment inside the q parameter of a "
            "search request, which no methodology carries"
        ),
        reference="NVD CVE-2017-12629 (Apache Solr before 7.1.0; fixed 7.1.0)",
    ),
    # --- LEAD: no oracle in this engine can witness the effect ---------------
    KnownComponentCVE(
        cve_id="CVE-2022-22965",
        component=r"spring|tomcat",
        affected="<5.3.18",
        title="Spring4Shell — data-binding RCE via classloader access",
        severity="critical",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "remote code execution demonstrated by a canary this engine authored "
            "appearing in command-output position. This engine has no RCE oracle "
            "for the Spring data-binding shape and does not attempt one"
        ),
        reference="NVD CVE-2022-22965 (Spring Framework < 5.3.18 / < 5.2.20)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-28168",
        component=r"^axios$",
        affected="<0.21.1",
        title="axios SSRF — a redirect escapes the configured proxy",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        identifiable_by=frozenset(
            {
                VersionProvenance.LOCKFILE,
                VersionProvenance.MANIFEST,
                VersionProvenance.ARTIFACT_STRING,
            }
        ),
        proving_observation=(
            "a request that bypassed the configured proxy after a redirect. The "
            "defining effect is WHICH ROUTE the request took, and this engine's "
            "SSRF oracle confirms on internal content coming BACK — it cannot see "
            "the difference between a proxied and an unproxied fetch, so naming it "
            "here would be an oracle confirming something else"
        ),
        reference="NVD CVE-2020-28168 (axios < 0.21.1; fixed 0.21.1)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2023-26159",
        component=r"^follow-redirects$",
        affected="<1.15.4",
        title="follow-redirects improper URL handling on redirect",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "a redirect resolved to a host the application did not intend. Same "
            "shape as CVE-2020-28168: the effect is the DESTINATION of an outbound "
            "request, and no oracle here observes the target's own egress except "
            "through P6, which proves that a fetch happened rather than which "
            "host-parsing rule produced it"
        ),
        reference="NVD CVE-2023-26159 (follow-redirects < 1.15.4; fixed 1.15.4)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2019-10744",
        component=r"^lodash$",
        affected="<4.17.12",
        title="lodash prototype pollution via defaultsDeep",
        severity="high",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "a polluted prototype changing the application's behaviour on a "
            "subsequent request. This engine has no prototype-pollution oracle"
        ),
        reference="NVD CVE-2019-10744 (lodash < 4.17.12; fixed 4.17.12)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-8203",
        component=r"^lodash$",
        affected="<4.17.20",
        title="lodash prototype pollution via zipObjectDeep",
        severity="high",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "a polluted prototype changing the application's behaviour on a "
            "subsequent request. This engine has no prototype-pollution oracle"
        ),
        reference="NVD CVE-2020-8203 (lodash < 4.17.20; fixed 4.17.20)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-23337",
        component=r"^lodash$",
        affected="<4.17.21",
        title="lodash command injection via template",
        severity="high",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "attacker-controlled input reaching lodash's template compiler in the "
            "server's own code. Presence of the library in a bundle is not evidence "
            "that any call site is reachable from a request"
        ),
        reference="NVD CVE-2021-23337 (lodash < 4.17.21; fixed 4.17.21)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2018-3721",
        component=r"^lodash$",
        affected="<4.17.5",
        title="lodash prototype pollution",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "a polluted prototype changing the application's behaviour on a "
            "subsequent request. This engine has no prototype-pollution oracle"
        ),
        reference="NVD CVE-2018-3721 (lodash < 4.17.5; fixed 4.17.5)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2019-11358",
        component=r"^jquery$",
        affected="<3.4.0",
        title="jQuery prototype pollution via $.extend",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "a polluted prototype changing application behaviour. This engine has "
            "no prototype-pollution oracle"
        ),
        reference="NVD CVE-2019-11358 (jQuery < 3.4.0; fixed 3.4.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-7699",
        component=r"^express-fileupload$",
        affected="<1.1.10",
        title="express-fileupload prototype pollution via parseNested",
        severity="high",
        vector=CVEVector.REQUEST_PARAM,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "a polluted prototype observed changing a later response. This engine "
            "has no prototype-pollution oracle"
        ),
        reference="NVD CVE-2020-7699 (express-fileupload < 1.1.10; fixed 1.1.10)",
    ),
    # --- LEAD by DESIGN: the XSS band, and why it stays here -----------------
    #
    # This engine has three XSS oracles and none of them may receive one of
    # these rows. A library CVE names a SINK inside a rendering library; what
    # the observation gives us is that the library is PRESENT. Whether any
    # request-controlled value reaches that sink on this application is exactly
    # the question, and the presence of the library is not evidence about it.
    #
    # The second reason is measured rather than argued. On the target class
    # where a bundled library actually lives — a single-page application —
    # ``_test_xss_reflected`` grades a reflection landing in JS/DOM context
    # ``likely``, which ``_NON_CONFIRMING_VERIFICATION_STRENGTHS`` demotes to a
    # lead; ``_test_xss_stored`` issues no probe without a form; and
    # ``_test_xss_dom`` needs P7, which is off unless a browser is wired. So the
    # dispatch would spend a slot to produce the lead these rows already are.
    KnownComponentCVE(
        cve_id="CVE-2020-11022",
        component=r"^jquery$",
        affected="[1.2.0,3.5.0)",
        title="jQuery cross-site scripting via HTML from untrusted sources",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "script execution witnessed in the page's own JavaScript context, from "
            "HTML this engine supplied through a jQuery DOM-manipulation sink. The "
            "library's version alone says nothing about whether any such sink takes "
            "attacker input on this application"
        ),
        reference="NVD CVE-2020-11022 (jQuery >= 1.2, < 3.5.0; fixed 3.5.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-11023",
        component=r"^jquery$",
        affected="[1.0.3,3.5.0)",
        title="jQuery cross-site scripting via HTML containing <option> elements",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "script execution witnessed in the page's own JavaScript context, from "
            "HTML this engine supplied through a jQuery DOM-manipulation sink. Same "
            "reachability gap as CVE-2020-11022 — a different sink in the same "
            "library, and the same absence of evidence that a request reaches it"
        ),
        reference="NVD CVE-2020-11023 (jQuery >= 1.0.3, < 3.5.0; fixed 3.5.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2015-9251",
        component=r"^jquery$",
        affected="<3.0.0",
        title="jQuery cross-site scripting via a cross-domain ajax response",
        severity="medium",
        vector=CVEVector.REQUEST_PARAM,
        proving_observation=(
            "script execution witnessed in the page's own JavaScript context from a "
            "response this engine controlled. The precondition is an application "
            "that issues a cross-domain ajax request to a host we can answer for, "
            "which is not something the version string reports"
        ),
        reference="NVD CVE-2015-9251 (jQuery < 3.0.0; fixed 3.0.0)",
    ),
    # --- BAND C: permanently lead-only, and the report says why -------------
    #
    # Not a coverage gap and not a backlog. No remote oracle can prove any of
    # these from outside the process, so no future confirmation primitive moves
    # them: a resource-exhaustion claim needs the attack the safety rails refuse
    # to send, and an information leak indistinguishable from correct behaviour
    # has no differential for a control arm to establish. Reported as a stated
    # product property (:data:`BAND_C_VECTORS` and the report's own section)
    # rather than as something we have not got round to.
    KnownComponentCVE(
        cve_id="CVE-2021-3749",
        component=r"^axios$",
        affected="<0.21.2",
        title="axios inefficient regular expression — denial of service",
        severity="high",
        vector=CVEVector.ENVIRONMENTAL,
        identifiable_by=frozenset(
            {
                VersionProvenance.LOCKFILE,
                VersionProvenance.MANIFEST,
                VersionProvenance.ARTIFACT_STRING,
            }
        ),
        proving_observation=(
            "the target's own processing time growing super-linearly with an input "
            "we chose. Proving it means degrading the client's service, which the "
            "safety rails refuse to send on any target and no engagement authorises. "
            "Permanently lead-only"
        ),
        reference="NVD CVE-2021-3749 (axios < 0.21.2; fixed 0.21.2)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2023-45857",
        component=r"^axios$",
        affected="<1.6.0",
        title="axios leaks the XSRF-TOKEN cookie to a third-party host",
        severity="medium",
        vector=CVEVector.ENVIRONMENTAL,
        identifiable_by=frozenset(
            {
                VersionProvenance.LOCKFILE,
                VersionProvenance.MANIFEST,
                VersionProvenance.ARTIFACT_STRING,
            }
        ),
        proving_observation=(
            "a request the target's own client issued to a third party carrying a "
            "token it should not have carried. The observation has to be made at "
            "the THIRD PARTY, from inside the victim's browser, and this engine "
            "observes the target's surface. Permanently lead-only"
        ),
        reference="NVD CVE-2023-45857 (axios < 1.6.0; fixed 1.6.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2022-0155",
        component=r"^follow-redirects$",
        affected="<1.14.8",
        title="follow-redirects forwards the Cookie header across hosts",
        severity="medium",
        vector=CVEVector.ENVIRONMENTAL,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "a credential arriving at a host it was not issued for, observed at "
            "that host. Same reason as CVE-2023-45857: the effect is visible where "
            "we are not. Permanently lead-only"
        ),
        reference="NVD CVE-2022-0155 (follow-redirects < 1.14.8; fixed 1.14.8)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-23364",
        component=r"^browserslist$",
        affected="[4.0.0,4.16.5)",
        title="browserslist inefficient regular expression — denial of service",
        severity="medium",
        vector=CVEVector.ENVIRONMENTAL,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "super-linear processing time on an input we chose, which is an attack "
            "on availability rather than a probe. Permanently lead-only. It is also "
            "a BUILD-TIME dependency, so the vulnerable code is very unlikely to be "
            "reachable from any request at all"
        ),
        reference="NVD CVE-2021-23364 (browserslist >= 4.0.0, < 4.16.5; fixed 4.16.5)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2022-25851",
        component=r"^jpeg-js$",
        affected="<0.4.4",
        title="jpeg-js infinite loop on a crafted image",
        severity="high",
        vector=CVEVector.ENVIRONMENTAL,
        identifiable_by=frozenset({VersionProvenance.LOCKFILE, VersionProvenance.MANIFEST}),
        proving_observation=(
            "the decoder failing to terminate on an image we supplied — a worker "
            "this engine would have to hang to observe. Permanently lead-only"
        ),
        reference="NVD CVE-2022-25851 (jpeg-js < 0.4.4; fixed 0.4.4)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2019-20372",
        component=r"^nginx$",
        affected="<1.17.7",
        title="nginx request smuggling via a crafted error_page configuration",
        severity="medium",
        vector=CVEVector.ENVIRONMENTAL,
        proving_observation=(
            "a second request smuggled past the front end and answered by the "
            "back end. The vulnerability is CONDITIONAL on an error_page directive "
            "we cannot observe from outside, so a version match here does not even "
            "establish the precondition — and this engine has no smuggling oracle. "
            "Permanently lead-only"
        ),
        reference="NVD CVE-2019-20372 (nginx before 1.17.7; fixed 1.17.7)",
    ),
    # CVE-2023-44487 (HTTP/2 Rapid Reset) was drafted here and deliberately
    # REMOVED. It is protocol-level, so its honest entry is an unbounded ``*``
    # against every web server — which matches unconditionally and therefore
    # carries no information about the target under test. A lead that is equally
    # true of every host in the world is the version-match form of a phantom: it
    # fills the operator's worklist without distinguishing anything, and its own
    # proving observation would be a denial-of-service attack the safety rails
    # refuse to send. An entry nothing could ever act on does not belong in a
    # deliverable. See ``test_an_unbounded_entry_must_name_a_specific_component``.
)


def _name_matches(pattern: str, name: str) -> bool:
    """Whether an observed component *name* matches a catalogue *pattern*."""
    try:
        return re.search(pattern, name.strip(), re.IGNORECASE) is not None
    except re.error:  # a malformed catalogue entry must not break a run
        return False


def match_components(
    components: list[DetectedComponent],
    catalog: tuple[KnownComponentCVE, ...] = KNOWN_COMPONENT_CVES,
) -> list[ComponentCVEMatch]:
    """Match an observed inventory against the known-CVE catalogue.

    Deterministic and LLM-free. A component with **no observed version** matches
    only entries whose predicate is ``*``: without a version there is no evidence
    the host is in the affected range, and reporting one anyway is the exact
    fabrication this module refuses. That is a deliberate loss of recall — an
    unversioned ``nginx`` may well be vulnerable — taken because a lead that
    names a CVE the host may not be affected by is worse than no lead.

    Args:
        components: The observed inventory, from :class:`ReconResult.components`.
        catalog: Override for tests.

    Returns:
        Matches ordered **dispatchable**-first, then by **version provenance**,
        then by published severity, then by CVE id — deterministic, never
        inventory order, so two runs over the same target produce the same
        worklist.

    Provenance sits ahead of severity deliberately. The list is sliced to a
    per-engagement bound and the survivors claim reserved plan slots, so this
    ordering decides which matches are TESTED. A CRITICAL resting on a
    ``Server:`` banner and a MEDIUM resting on a lockfile entry are not the same
    claim: the banner is a string the target chose and a back-ported fix defeats
    it, while the lockfile names what was actually resolved. Ranking by
    published severity first would spend the scarce slots on the weakest
    evidence in the system and call it prioritisation.

    The leading key is :attr:`ComponentCVEMatch.can_dispatch` and not
    :attr:`~ComponentCVEMatch.is_confirmable`, because those came apart: a match
    whose oracle exists but whose vector this source cannot carry becomes a task
    that sends a probe the CVE is not reachable by, and it would have displaced
    a match that can actually be tested. Sorting on the reachable predicate is
    the same rule as before — a match that cannot become a task must not take a
    slot from one that can — applied to the predicate that is actually true.
    """
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    matches: list[ComponentCVEMatch] = []
    for component in components:
        name = (component.name or "").strip()
        if not name:
            continue
        version = (component.version or "").strip()
        for entry in catalog:
            if not _name_matches(entry.component, name):
                continue
            if not version:
                # No version observed. Only an unbounded entry can honestly match.
                if entry.affected != "*":
                    continue
                matched_on = (
                    f"{name} identified by {component.source or 'a fingerprinter'} with no "
                    f"version reported; {entry.cve_id} is not version-bounded"
                )
            else:
                if not version_satisfies(version, entry.affected):
                    continue
                matched_on = (
                    f"{name} {version} reported by "
                    f"{component.source or 'a fingerprinter'}"
                    + (f" on port {component.port}" if component.port else "")
                    + f" (version provenance: {component.provenance.value})"
                    + f"; {entry.cve_id} affects {entry.affected}"
                )
                if component.provenance in BACKPORT_DEFEASIBLE_PROVENANCE:
                    matched_on += f" — {BACKPORT_CAVEAT}"

            matches.append(ComponentCVEMatch(component=component, cve=entry, matched_on=matched_on))

    matches.sort(
        key=lambda m: (
            0 if m.can_dispatch else 1,
            version_provenance_rank(m.provenance),
            severity_rank.get(m.cve.severity.lower(), 5),
            m.cve.cve_id,
            m.component.name.lower(),
        )
    )
    return matches


__all__ = [
    "BACKPORT_CAVEAT",
    "BACKPORT_DEFEASIBLE_PROVENANCE",
    "BAND_C_VECTORS",
    "CARRIABLE_VECTORS",
    "KNOWN_COMPONENT_CVES",
    "LEAD_NO_ORACLE",
    "LEAD_UNIDENTIFIABLE",
    "LEAD_VECTOR_NOT_CARRIED",
    "CVEVector",
    "ComponentCVEMatch",
    "KnownComponentCVE",
    "MatchDisposition",
    "match_components",
]
