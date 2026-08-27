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

* **The CVE's effect is one of our oracles can prove** — ``confirming_test_method``
  names it. The match becomes a *dispatch hint*: the class runs against the live
  target, and if its own oracle witnesses the defining effect, the normal
  emission path emits a normal finding. The CVE is then CONTEXT on that finding
  ("this is consistent with CVE-…"), never its proof. If the oracle does not
  confirm, the match stays a lead — a version match cannot rescue a failed
  confirmation.
* **We have no oracle for that effect** — ``confirming_test_method`` is ``""``.
  The match is recorded as an :class:`UnprovenExploitLead` naming the observed
  version, the affected range, and the observation that WOULD prove it. This is
  the honest majority case and it is not a failure: "this host reports a version
  in the affected range and we could not test the effect" is a true, useful,
  actionable sentence. "This host is vulnerable to CVE-…" would not be.

The catalog is deliberately small and general. It carries no benchmark's
vocabulary — every entry is a published CVE against a widely-deployed component,
and an entry earns its place by being matchable from a banner a fingerprinter
actually reports.
"""

from __future__ import annotations

import re

from pydantic import BaseModel

from clinkz.discovery.versions import version_satisfies
from clinkz.models.recon import DetectedComponent, VersionProvenance, version_provenance_rank


class KnownComponentCVE(BaseModel):
    """One published vulnerability, keyed on a component and a version range.

    Attributes:
        cve_id: The CVE identifier.
        component: Case-insensitive regex matched against the observed component
            NAME. A regex rather than a literal because fingerprinters spell the
            same product several ways ("Apache", "Apache httpd", "Apache/2.4.49").
        affected: Version predicate over :mod:`clinkz.discovery.versions`'
            grammar (``<X``, ``[X,Y]``, ``=X``, ``*``). ``*`` means "every
            version this catalog knows of" and is used only where the
            vulnerability is not version-bounded.
        title: Human summary for the lead or the finding's context line.
        severity: CVSS band, as published. Used for lead ordering ONLY — it never
            becomes a finding's severity, because the finding's severity comes
            from what our own oracle witnessed.
        confirming_test_method: The ``_test_*`` whose oracle can witness this
            CVE's defining effect, or ``""`` when this engine has none. The
            single field that decides lead-vs-dispatch.
        proving_observation: What would have to be observed for this to be a
            finding. Rendered verbatim into the lead's ``missing_observation``,
            so a reader is told precisely what was not done.
        reference: Where the affected range comes from.
    """

    cve_id: str
    component: str
    affected: str
    title: str
    severity: str = "medium"
    confirming_test_method: str = ""
    proving_observation: str = ""
    reference: str = ""


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
        """Whether an oracle in this engine can witness this CVE's effect."""
        return bool(self.cve.confirming_test_method)

    @property
    def provenance(self) -> VersionProvenance:
        """How the version this match rests on was observed."""
        return self.component.provenance


#: The catalogue.
#:
#: Every entry is a published CVE against a component a fingerprinter can name
#: from a banner. ``confirming_test_method`` is filled ONLY where this engine
#: genuinely has an oracle for that CVE's defining effect — an entry claiming a
#: method that cannot actually witness the effect would turn a version match into
#: a finding through the back door, which is the one thing this module exists to
#: prevent.
KNOWN_COMPONENT_CVES: tuple[KnownComponentCVE, ...] = (
    # --- Confirmable: the effect reduces to an oracle we already run ----------
    KnownComponentCVE(
        cve_id="CVE-2021-41773",
        component=r"apache(\s+http\w*)?$|^httpd$",
        affected="=2.4.49",
        title="Apache HTTP Server path traversal / file disclosure",
        severity="critical",
        confirming_test_method="_test_lfi",
        proving_observation=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline"
        ),
        reference="NVD CVE-2021-41773 (Apache httpd 2.4.49)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-42013",
        component=r"apache(\s+http\w*)?$|^httpd$",
        affected="=2.4.50",
        title="Apache HTTP Server path traversal — incomplete fix for CVE-2021-41773",
        severity="critical",
        confirming_test_method="_test_lfi",
        proving_observation=(
            "file content the server should not serve, returned in a successful "
            "response and absent from the benign baseline"
        ),
        reference="NVD CVE-2021-42013 (Apache httpd 2.4.50)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2021-44228",
        component=r"log4j|solr|elasticsearch|logstash",
        affected="[2.0,2.14.1]",
        title="Log4Shell — JNDI lookup in a logged value",
        severity="critical",
        confirming_test_method="_test_log4shell",
        proving_observation=(
            "an out-of-band callback carrying our single-use nonce, arriving at the "
            "collaborator from the target"
        ),
        reference="NVD CVE-2021-44228 (Log4j 2.x < 2.15.0)",
    ),
    # --- Not confirmable by this engine: leads, and they say so ---------------
    KnownComponentCVE(
        cve_id="CVE-2022-22965",
        component=r"spring|tomcat",
        affected="<5.3.18",
        title="Spring4Shell — data-binding RCE via classloader access",
        severity="critical",
        proving_observation=(
            "remote code execution demonstrated by a canary this engine authored "
            "appearing in command-output position. This engine has no RCE oracle "
            "for the Spring data-binding shape and does not attempt one"
        ),
        reference="NVD CVE-2022-22965 (Spring Framework < 5.3.18 / < 5.2.20)",
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
    KnownComponentCVE(
        cve_id="CVE-2021-23337",
        component=r"^lodash$",
        affected="<4.17.21",
        title="lodash command injection via template",
        severity="high",
        proving_observation=(
            "attacker-controlled input reaching lodash's template compiler in the "
            "server's own code. Presence of the library in a bundle is not evidence "
            "that any call site is reachable from a request"
        ),
        reference="NVD CVE-2021-23337 (lodash < 4.17.21)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-11022",
        component=r"^jquery$",
        affected="[1.2.0,3.4.9]",
        title="jQuery cross-site scripting via HTML from untrusted sources",
        severity="medium",
        proving_observation=(
            "script execution witnessed in the page's own JavaScript context, from "
            "HTML this engine supplied through a jQuery DOM-manipulation sink. The "
            "library's version alone says nothing about whether any such sink takes "
            "attacker input on this application"
        ),
        reference="NVD CVE-2020-11022 (jQuery >= 1.2 < 3.5.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2018-3721",
        component=r"^lodash$",
        affected="<4.17.5",
        title="lodash prototype pollution",
        severity="medium",
        proving_observation=(
            "a polluted prototype changing the application's behaviour on a "
            "subsequent request. This engine has no prototype-pollution oracle"
        ),
        reference="NVD CVE-2018-3721 (lodash < 4.17.5)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2019-11358",
        component=r"^jquery$",
        affected="<3.4.0",
        title="jQuery prototype pollution via $.extend",
        severity="medium",
        proving_observation=(
            "a polluted prototype changing application behaviour. This engine has "
            "no prototype-pollution oracle"
        ),
        reference="NVD CVE-2019-11358 (jQuery < 3.4.0)",
    ),
    KnownComponentCVE(
        cve_id="CVE-2020-7699",
        component=r"^express-fileupload$",
        affected="<1.1.10",
        title="express-fileupload prototype pollution via parseNested",
        severity="high",
        proving_observation=(
            "a polluted prototype observed changing a later response. This engine "
            "has no prototype-pollution oracle"
        ),
        reference="NVD CVE-2020-7699 (express-fileupload < 1.1.10)",
    ),
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
        Matches ordered confirmable-first, then by **version provenance**, then
        by published severity, then by CVE id — deterministic, never inventory
        order, so two runs over the same target produce the same worklist.

    Provenance sits ahead of severity deliberately. The list is sliced to a
    per-engagement bound and the survivors claim reserved plan slots, so this
    ordering decides which matches are TESTED. A CRITICAL resting on a
    ``Server:`` banner and a MEDIUM resting on a lockfile entry are not the same
    claim: the banner is a string the target chose and a back-ported fix defeats
    it, while the lockfile names what was actually resolved. Ranking by
    published severity first would spend the scarce slots on the weakest
    evidence in the system and call it prioritisation. Confirmability still
    outranks both, because a match with no oracle cannot become a task at all
    and would otherwise displace one that can.
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
            matches.append(ComponentCVEMatch(component=component, cve=entry, matched_on=matched_on))

    matches.sort(
        key=lambda m: (
            0 if m.is_confirmable else 1,
            version_provenance_rank(m.provenance),
            severity_rank.get(m.cve.severity.lower(), 5),
            m.cve.cve_id,
            m.component.name.lower(),
        )
    )
    return matches


__all__ = [
    "KNOWN_COMPONENT_CVES",
    "ComponentCVEMatch",
    "KnownComponentCVE",
    "match_components",
]
