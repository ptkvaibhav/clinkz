# SCA catalogue breadth — what a real affected-range predicate would cost

**Originally report-only.** The instruction was to get the shape before the
content, and the shape is the part that turned out to matter: two of the three
limits below were not "add more entries" problems at all, and one of them
silently produced a wrong answer on a real target.

**Two of the four grammar limits have since LANDED** — half-open intervals and
prerelease precedence — because they are the two that make a *silent* error, and
a catalogue may not grow while a new row can under-match by one release without
anybody hearing about it. What each row of §1 says now is marked. The remaining
two (OR-of-ranges, per-branch fixed versions) still bound how many advisories
are encodable, and they fail *loudly*: an advisory that needs them cannot be
written down at all, rather than being written down wrong.

Measured against the catalogue and the version grammar as they stand
(2026-08-30, after the interval rewrite): **9 entries, 3 confirmable, 6
lead-only, 9 distinct predicates, 30 dispatchable `_test_*` classes.**

> **Superseded by §6–§10 (2026-09-02).** The depth pass measured whether those
> "3 confirmable" rows could actually be REACHED, and two of them could not: the
> Apache path-traversal entries named the right oracle and arrive by a route no
> component-derived task sends. The catalogue is now **28 entries, 6 testable,
> 22 lead-only**, with the vector declared per row and the disposition computed
> from it. Read §6 before §3 — §3's table is the question, §6 is the answer.

---

## 1. The 2.4.67 miss was a grammar problem wearing a content problem's clothes

The two Apache entries are `=2.4.49` and `=2.4.50` — single-point predicates.
A live target observed at **2.4.67** missed them, and it is worth being precise
about why, because "add more entries" is the wrong lesson.

CVE-2021-41773 really does affect exactly 2.4.49, so `=2.4.49` is a *faithful*
encoding of that advisory. The miss is not that the range was too narrow. It is
that **a catalogue of point versions cannot express most advisories**, so the
entries that would have matched 2.4.67 could never have been written in this
grammar in the first place. `discovery/versions.py` supported:

```
'<X'  '<=X'  '>X'  '>=X'  '=X'  '[X,Y]'  '*'
```

One interval, one comparison, or everything. Real NVD data is not shaped like
that. The four capabilities missing, in the order they bite — two now closed:

| Missing | Real-world shape it fails on | Consequence today |
|---|---|---|
| **OR of ranges** | Apache httpd advisories are routinely "affects 2.4.x < 2.4.58 **and** 2.2.x < 2.2.34" | Two branches need two entries with the same CVE id, which then match, order and de-duplicate as if they were two vulnerabilities |
| **Half-open intervals** — **LANDED** | `>=2.4.49, <2.4.51` — the overwhelmingly common CPE shape | Was expressible only as `[2.4.49,2.4.50]`, which requires knowing the last affected version rather than the first fixed one. `[X,Y)` is now the primitive and every bounded entry is written in it, held by `test_every_bounded_entry_uses_a_half_open_upper_bound` (domain computed from the catalogue) |
| **Per-branch fixed versions** | Log4j: fixed in 2.16.0 for Java 8, 2.12.2 for Java 7, 2.3.1 for Java 6 | The entry has to collapse to the widest branch, so a patched Java-7 host matches |
| **Pre-release ordering** — **LANDED** | `1.2.3-rc1` precedes `1.2.3` | `parse_version` took the leading integer run per segment and **discarded the tail**, so `1.2.3-rc1 == 1.2.3` and a release candidate of a fixed version was graded fixed. SemVer §11 precedence now decides, with build metadata excluded per §10 |

The two remaining rows are recall limits — an advisory needing them cannot be
written down, which is loud. The two that landed were the ones that produced a
*wrong* answer quietly, and one of them had already left an artifact in the
catalogue: jQuery CVE-2020-11022 (advisory `>= 1.2, < 3.5.0`) was carried as
`[1.2.0,3.4.9]`, a hand-guessed last-vulnerable version that silently excluded
`3.4.95`. No such jQuery shipped, so nothing broke; the next entry written that
way would land on a version that exists.

### What the grammar is now

```
'*'  '=X'  '<X'  '<=X'  '>X'  '>=X'  '[X,Y)'  '[X,Y]'  '(X,Y)'  '(X,Y]'
```

`[introduced, fixed)` is the canonical form, because it is derivable from the
one number an advisory actually states. Three decisions are recorded at the
site rather than left to emerge, each resolving toward the **visible** error —
an over-match becomes a lead or a dispatch an oracle refuses, while an
under-match is silence, and silence is what a correct run against a clean target
also looks like:

* **An inclusive lower bound admits every prerelease and repackaging of its
  core.** `[2.4.49,2.4.50)` contains `2.4.49-1ubuntu3.2`, which is how most real
  hosts spell a vulnerable Apache. Strict §11 drops it. Advisory feeds close
  this with the per-entry `X-0` idiom; a convention an author must remember is
  the guard-domain law waiting to happen, so the *primitive* normalises its own
  bound and the open form `(X,Y)` is the escape hatch.
* **A prerelease of the fixed version is still inside the range.** `1.2.3-rc1`
  is in `[1.0.0,1.2.3)` — the RC may or may not carry the fix, and the oracle
  settles it.
* **The one cost is stated**: adjacent half-open ranges partition the releases
  cleanly and overlap on the prereleases of their shared boundary. Pinned, so
  removing it requires saying so.

The comparator is pinned as **properties over a generated universe** (240
versions × the four bracket forms) rather than a table of cases: total order,
boundary side, and `[a,c) == [a,b) ⊎ [b,c)` — the partition a decrement-by-one
upper bound breaks. See `tests/test_discovery/test_version_range_properties.py`.

## 2. Back-ports: provenance is a mitigation, and it is not a fix

A distribution that back-ports a security patch without moving the version
number defeats **every** version-only matcher, including this one. Debian ships
`2.4.62-1~deb12u2`; `parse_version` reads `(2, 4, 62)` and the distro revision —
the only field that records the back-port — is dropped on the floor.

Three things follow, and only the first is implemented:

1. **Rank the evidence.** `VersionProvenance` exists precisely because a
   `Server:` banner and a lockfile entry are not equally good answers.
   `match_components` orders confirmable-first, then by provenance, then by
   published severity — provenance *ahead of* severity, because the ordering
   decides what is TESTED and a banner-backed CRITICAL is weaker evidence than
   a lockfile-backed MEDIUM. That is shipped.
2. **Read the distro revision.** `2.4.62-1~deb12u2` carries strictly more
   information than `2.4.62`, and the grammar throws it away. Reading it would
   require a per-distribution security-tracker feed to say which revision
   carries which fix — a second data source, not a predicate change.
3. **Stop matching on versions at all for back-port-prone components.** The
   honest end state for a server banner is that it is a *hypothesis* which our
   own oracle settles. This is already how the engine behaves: a match is a
   lead or a dispatch hint, never a finding. Back-ports are the reason that rule
   is correct, not an argument for a better matcher.

**The decision is now recorded rather than emergent**
(`ComponentCVEMatch.disposition`, `BACKPORT_DEFEASIBLE_PROVENANCE`): provenance
gates the CLAIM, never the TEST. The tempting rule — dispatch only on
lockfile-grade provenance — was considered and rejected, because a dispatch is
a hypothesis handed to our own oracle and not a claim. A back-ported host in the
affected range gets tested, the oracle observes nothing, and the match stays a
lead; refusing the dispatch would instead delete the engine's only published-CVE
coverage of the component class most often observed by banner, and buy no
honesty that `_persist_finding` does not already enforce. Where provenance does
decide is the *other* outcome: an unconfirmable match is a sentence in the
deliverable resting entirely on a version string, with no oracle behind it, so
it carries `BACKPORT_CAVEAT` verbatim — and provenance still orders the scarce
reserved plan slots, so lockfile-grade evidence is what gets tested when the
ceiling bites.

## 3. Band A: which shapes have entries, and which have an oracle waiting

This is the part that should drive the content decision. For each Band A shape:
does the catalogue carry an entry, and does this engine have an oracle that
could witness that CVE's defining effect?

| Shape | Oracle | Catalogue entries | Status |
|---|---|---|---|
| **Path traversal / file read** | `_test_lfi` (P3) | 2 — CVE-2021-41773, CVE-2021-42013 | **Wired.** Both confirmable |
| **JNDI / log injection** | `_test_log4shell` (P6 out-of-band) | 1 — CVE-2021-44228 | **Wired.** Confirmable |
| **SSRF** | `_test_ssrf` (P4/P6) | **0** | **Oracle waiting, nothing to feed it** |
| **SQLi / NoSQLi** | `_test_sqli`, `_test_nosqli` (P1/P2) | **0** | **Oracle waiting, nothing to feed it** |
| **XSS** | `_test_xss_*`, and P7 for the client-side effect | 1 — CVE-2020-11022 (jQuery), declared **lead-only** | **Entry present, oracle deliberately not claimed** |

Three of the five have an oracle and zero entries. That is the cheapest
available breadth in the whole system: an SSRF or SQLi entry against a widely
deployed component costs one catalogue row and reuses a confirmation path that
already exists, already dispatches its own control arm, and already carries the
zero-false-positive boundary. No new proof code.

The XSS row is the interesting one and it should stay as it is.
CVE-2020-11022 is a jQuery XSS and this engine has an XSS oracle, so the entry
*could* name `_test_xss_reflected` — and it must not. The CVE's defining effect
is script execution through a jQuery DOM-manipulation sink reached by
attacker-controlled input. Observing that jQuery 3.4.1 is on the page says
nothing about whether any such sink takes request input on *this* application.
Naming an oracle whose gate the observation does not satisfy would turn a
version match into a dispatched task whose confirmation is about something else
— which is the back door this whole module exists to keep shut. It is a lead,
and the lead says what would prove it.

## 4. The dependency-SCA half could not fire at all, and still cannot reserve

Two separate facts, both measured:

* **Before this change, nothing could produce a component the five npm entries
  match.** `whatweb` and `nmap` fingerprint servers. Their zeros were never an
  observation about a target — the question was never asked.
  `agents/_package_identity.py` is the producer that asks it.
* **After it, those entries still reserve zero plan slots — by construction.**
  All five are `confirming_test_method=""`, and `_resolve_component_cve_reservation`
  counts only matches this engine has an oracle for. So package identity can
  now produce *leads* and cannot produce a *task*. That is the correct behaviour
  (prototype pollution has no oracle here, and lodash-in-a-bundle is not
  evidence a template call site is reachable) and it is stated because a reader
  measuring `reserved` after this change would otherwise read the zero as a
  broken producer. `scripts/cve_reservation_corpus.py` carries a control for
  exactly this distinction.

## 5. What expansion would actually cost

In rough order of value per unit of work:

1. ~~**Half-open intervals**~~ and ~~**pre-release precedence**~~ — **DONE.**
   Together they remove the decrement-by-one hazard from every future entry,
   which is what makes the catalogue safe to grow at all.
2. **SSRF / SQLi entries** (~1 row each). Reuses a confirmable oracle. No
   grammar change needed if the advisory happens to be a single interval —
   which, in the new form, is most of them.
3. **OR-of-ranges.** Needed before any multi-branch server advisory can be
   encoded honestly. Changes `KnownComponentCVE.affected` from a string to a
   list, which touches the matcher, the lead text and the corpus replay. Fails
   loudly (the advisory cannot be written down), so it bounds breadth rather
   than correctness.
4. **Per-branch fixed versions.** The same shape as OR-of-ranges and settled by
   the same change: an entry that has to collapse to the widest branch matches a
   patched host on a narrower one.
5. **A digest catalogue** (`ARTIFACT_HASH`). The strongest provenance the enum
   declares and the only one nothing produces. A served bundle's SHA-256 is
   trivially computable and identifies nothing without a table of known digests
   to compare it against, which is a data-acquisition problem rather than a
   code one. Deliberately not built: computing a hash and reporting it as
   identity would be a number with nothing to compare it to.

Breadth is now a content question. The two grammar limits that made a larger
catalogue *unsafe* — a new row that under-matches by one release, and a release
candidate graded as fixed — are closed and pinned as properties. The two that
remain bound how much of NVD is *expressible*, and they refuse loudly: an
advisory needing an OR of ranges cannot be written in this grammar, which is a
visible gap rather than a silent wrong answer.

---

# The depth pass: an oracle you cannot reach is not coverage

**2026-09-02.** §3 above asked which Band A shapes have an oracle waiting. The
answer it gave was right about the oracles and wrong about the reach, and the
difference cost two catalogue entries their dispatch. What follows is the
measurement, the rule it produced, and the entries written under it.

## 6. Part 1 — which bands can receive a match TODAY

Measured, not read. Each Band A oracle was called against a `PageAnalysis` of a
known shape with every network call recorded, and the component-derived task was
built through the real plan seam (`_merge_component_cve_tasks`).

### 6.1 The transverse fact: what a component-derived task actually carries

```
ExploitTask(test_method="_test_lfi", endpoint_url="http://10.0.0.1/",
            endpoint_params=[], param_locations={}, carrier_constraints=[])
```

No params, no request shape, no carrier. `_fetch_page` then derives
`input_params` from the served page's `<input name=…>` tags plus the URL query,
and **every injection oracle iterates that list**. So before the fix below, a
component-derived task's entire reach was whatever form inputs the site root
happened to render.

| Oracle | probes on a page with 0 params | with 2 params |
|---|---|---|
| `_test_lfi` | 0 | 6 |
| `_test_ssrf` | 0 | 6 |
| `_test_sqli` | 0 | 6 |
| `_test_nosqli` | 0 | 6 |
| `_test_xss_reflected` | 0 | 2 |
| `_test_xss_stored` | 0 | 0 (needs a form, not a param) |
| `_test_xss_dom` | 0 | 0 (needs P7) |
| `_test_log4shell` | 0 | 0 (needs a healthy collaborator; P6 off by default) |

### 6.2 Per-band verdicts

Every Band A oracle is dispatchable and every one is classified by the
never-sent-control partition — there is no unclassified class and no oracle
missing its control arm:

| Band | Oracle | Control arm | Reachable by a component-derived task? |
|---|---|---|---|
| **A1** traversal / file read | `_test_lfi` | MARKER (never-sent decoy) | **Only for a PARAMETER-carried file read.** Not for a URL-path traversal — see §6.3 |
| **A2** log-sink JNDI egress | `_test_log4shell` | EXEMPT — P6 dispatches its own never-sent nonce | **Yes, when P6 is wired.** Parameter-scoped; returns without probing if the collaborator is absent, which is the honest black-box floor |
| **A3** SSRF | `_test_ssrf` | MARKER | **Yes.** Parameter-scoped; probes any param, confirms in-band on reflected internal content or out-of-band via P6 |
| **A4** SQLi / NoSQLi | `_test_sqli`, `_test_nosqli` | MARKER (both) | **Yes.** Parameter-scoped |
| **A5** XSS | `_test_xss_reflected` / `_stored` / `_dom` | MARKER, MARKER, EXEMPT (P7) | **No — and it must stay a lead.** See §6.4 |

### 6.3 A1: the finding. Two shipped entries named an oracle that cannot reach them

`_test_lfi`, pointed at the endpoint the CVE source chose, with the most
file-shaped parameter name there is:

```
GET http://10.0.0.1/  params={'file': ''}
GET http://10.0.0.1/  params={'file': '../'}
GET http://10.0.0.1/  params={'file': '/etc/passwd'}
0 of 3 requests mutate the URL PATH.
```

CVE-2021-41773 is a traversal through an **aliased directory in the URL path**
(`/cgi-bin/.%2e/%2e%2e/etc/passwd`). Those three probes cannot witness it. The
second route, `_test_lfi_file_server`, is gated on `_is_file_server_path`, which
is False for `/` and for `/cgi-bin/…` — it recognises `ftp`, `uploads`,
`downloads` and five siblings.

So both Apache rows declared `confirming_test_method="_test_lfi"`, spent a
reserved plan slot, and — when nothing came back — recorded
`version_match_oracle_ran_and_did_not_confirm`: *we tested it and saw nothing*,
about a vector that was never sent.

**This is the emission rule failing in the direction it was not watching.** The
module refuses to let a version match become a finding. It did not refuse to let
one become a *coverage claim*, and both are claims about work done.

The fix is not to delete the rows. The oracle named is the RIGHT oracle — a file
read is exactly what `_test_lfi` proves. What was missing is the carrier, so the
rows keep their oracle, declare `CVEVector.URL_PATH`, and stop dispatching.
`LEAD_VECTOR_NOT_CARRIED` is the sentence that says which:

> This engine HAS an oracle for this CVE's defining effect and could not deliver
> the CVE's input to it: a component-derived task carries its probe as a request
> PARAMETER, and this CVE is reached by another route. Nothing was sent, so this
> is not a statement that the host is clean.

The gray-box discovery engine already builds that carrier
(`ParamLocation.PATH` + `CARRIER_PATH_TRAVERSAL`, the Flink CVE-2020-17519
route). Wiring it into the component-CVE source is a code change plus a live
proof, and it is the named next capability — not a catalogue edit.

### 6.4 A5: checked hardest, and it stays lead-only

Two independent reasons, and the second is measured:

1. **A library CVE names a sink; the observation is that the library is
   present.** Whether any request-controlled value reaches that sink on *this*
   application is the entire question, and the version string is silent on it.
2. **On the target class where a bundled library actually lives — an SPA — the
   XSS oracles cannot confirm anyway.** `_test_xss_reflected` grades a
   reflection landing in JS/DOM context `likely`, which
   `_NON_CONFIRMING_VERIFICATION_STRENGTHS` demotes to an
   `UnprovenExploitLead`; `_test_xss_stored` issues no probe without a form
   (0 requests with params alone); `_test_xss_dom` needs P7, which is off unless
   a browser is wired.

A dispatch would therefore spend a plan slot to produce the lead the row already
is. The four jQuery rows (CVE-2020-11022, CVE-2020-11023, CVE-2015-9251,
CVE-2019-11358) are lead-only **by decision**, not by omission.

### 6.5 The targeting correction

`_component_cve_target_url` preferred the site root, reasoning that a
server-level defect is a property of the ORIGIN. Sound reasoning selecting for
the wrong thing: the oracles carry parameter values, so a parameter-less root is
an endpoint they send nothing to.

The origin argument has not gone away — it has moved. A defect that is a property
of the origin is one whose vector is the URL path, and those rows are
`URL_PATH` leads now. What is left to dispatch is exactly the set for which a
parameterised endpoint is right. So `_component_cve_target_endpoint` returns an
`Endpoint`, prefers one carrying a parameter, and the task is built with that
endpoint's params and its request shape through the declared
`_endpoint_request_shape` seam. No parameterised surface ⇒ a stated lead, never
an inert task.

## 7. Part 2 — the entries, and what each one declares

Every row declares its affected range (half-open), its `confirming_test_method`,
the `defining_effect` that method proves **in the oracle's own terms**, its
`vector`, and the provenance grades that can NAME it.

### 7.1 On `identifiable_by`, and what it is not

It is **not** provenance gating a test. §2's decision stands unchanged: a
back-ported host in the affected range gets tested, the oracle observes nothing,
and the match stays a lead. Every grade an entry lists dispatches identically.

It is an **observability** declaration. `nmap -sV` and `whatweb` fingerprint
servers; nothing that reads a banner can report `ejs`. A row reading `ejs 3.1.6`
at BANNER strength is a mis-parse of something else, not a weaker sighting of
ejs — so there is no observation of that component to test, and refusing to
spend a probe on it is not a policy about evidence strength.

### 7.2 Testable — an oracle witnesses the effect and we can carry the input

| CVE | Component | Affected (half-open) | Oracle | Defining effect that oracle proves | Producer route | May DISPATCH at |
|---|---|---|---|---|---|---|
| CVE-2021-44228 | log4j / solr / elasticsearch / logstash | `[2.0,2.15.0)` | `_test_log4shell` (P6) | an outbound JNDI/DNS resolution carrying a nonce that existed only in the one probe sent | nmap `-sV`, httpx `-tech-detect`, whatweb; **and** `package_identity` lockfile | any |
| CVE-2019-17558 | Apache Solr | `[5.0.0,8.4.0)` | `_test_ssti` | a template expression we supplied, EVALUATED server-side and returned as its computed result | nmap `-sV`, httpx `-tech-detect` | any |
| CVE-2021-27905 | Apache Solr | `[5.0.0,8.8.2)` | `_test_ssrf` (P3/P6) | content from an address only the SERVER can reach, returned to a request whose parameter named it | nmap `-sV`, httpx `-tech-detect` | any |
| CVE-2022-29078 | ejs | `<3.1.7` | `_test_ssti` | server-side template evaluation of our expression | `package_identity` lockfile / manifest | LOCKFILE, MANIFEST |
| CVE-2021-21315 | systeminformation | `<5.3.1` | `_test_cmdi` | the output of a command we chose, with a separator-stripped control producing none | `package_identity` lockfile / manifest | LOCKFILE, MANIFEST |
| CVE-2023-22578 | sequelize | `<6.28.1` | `_test_sqli` | the database evaluating an expression we supplied, absent from baseline and control | `package_identity` lockfile / manifest | LOCKFILE, MANIFEST |

### 7.3 Oracle exists, input not deliverable — a real gap with a named fix

| CVE | Component | Affected | Oracle named | Vector | What is missing |
|---|---|---|---|---|---|
| CVE-2021-41773 | Apache httpd | `[2.4.49,2.4.50)` | `_test_lfi` | `URL_PATH` | a path-segment carrier for a component-derived task |
| CVE-2021-42013 | Apache httpd | `[2.4.50,2.4.51)` | `_test_lfi` | `URL_PATH` | same |
| CVE-2020-17519 | Apache Flink | `[1.11.0,1.11.3)` | `_test_lfi` | `URL_PATH` | same. The discovery engine reaches this CVE today via `CARRIER_PATH_TRAVERSAL`; this plan source does not |
| CVE-2017-12629 | Apache Solr | `<7.1.0` | `_test_xxe` | `REQUEST_BODY_DOCUMENT` | the XXE oracle sends an XML request BODY; this CVE arrives as an XML fragment inside a query parameter |

### 7.4 No oracle for the effect

| CVE | Component | Affected | Why it cannot confirm here |
|---|---|---|---|
| CVE-2022-22965 | spring / tomcat | `<5.3.18` | no RCE oracle for the Spring data-binding shape |
| CVE-2020-28168 | axios | `<0.21.1` | the effect is WHICH ROUTE the request took; our SSRF oracle sees content coming back and cannot tell a proxied fetch from an unproxied one |
| CVE-2023-26159 | follow-redirects | `<1.15.4` | same shape — the effect is the DESTINATION of an outbound request |
| CVE-2019-10744 | lodash | `<4.17.12` | no prototype-pollution oracle |
| CVE-2020-8203 | lodash | `<4.17.20` | no prototype-pollution oracle |
| CVE-2021-23337 | lodash | `<4.17.21` | library presence is not evidence a template call site takes request input |
| CVE-2018-3721 | lodash | `<4.17.5` | no prototype-pollution oracle |
| CVE-2019-11358 | jQuery | `<3.4.0` | no prototype-pollution oracle |
| CVE-2020-7699 | express-fileupload | `<1.1.10` | no prototype-pollution oracle |
| CVE-2020-11022 | jQuery | `[1.2.0,3.5.0)` | §6.4 — sink reachability unevidenced, and the XSS oracles cannot confirm on an SPA |
| CVE-2020-11023 | jQuery | `[1.0.3,3.5.0)` | §6.4 |
| CVE-2015-9251 | jQuery | `<3.0.0` | §6.4, plus a precondition (a cross-domain ajax call to a host we can answer for) the version does not report |

### 7.5 Band C — permanently lead-only

No remote oracle can prove these, now or later. See §8.

| CVE | Component | Affected | Why no future primitive changes it |
|---|---|---|---|
| CVE-2021-3749 | axios | `<0.21.2` | ReDoS. Proving it means degrading the client's service, which the safety rails refuse on every target |
| CVE-2023-45857 | axios | `<1.6.0` | the XSRF token arrives at a THIRD PARTY; the observation has to be made where we are not |
| CVE-2022-0155 | follow-redirects | `<1.14.8` | same — a credential arriving at a host it was not issued for |
| CVE-2021-23364 | browserslist | `[4.0.0,4.16.5)` | ReDoS, and a build-time dependency: very unlikely to be reachable from any request at all |
| CVE-2022-25851 | jpeg-js | `<0.4.4` | an infinite loop — a worker we would have to hang to observe |
| CVE-2019-20372 | nginx | `<1.17.7` | conditional on an `error_page` directive we cannot observe from outside, and there is no smuggling oracle |

### 7.6 Candidates DROPPED, and why — this sizes the gap

**11 dropped**, in two buckets. Both refusals are loud by construction: an
advisory in the first bucket cannot be written in this grammar at all.

*Grammar — needs an OR of ranges or per-branch fixed versions (8):*

| Advisory | The shape that defeats the grammar |
|---|---|
| CVE-2024-6387 (OpenSSH regreSSHion) | affects `< 4.4p1` **and** `[8.5p1, 9.8p1)` — two disjoint ranges |
| CVE-2021-45046 (log4j) | 2.x fixed in 2.16.0, 2.12.x branch fixed in 2.12.2 |
| CVE-2022-24999 (qs) | nine per-branch fixes (6.2.4, 6.3.3, 6.4.1, 6.5.3, 6.6.1, 6.7.3, 6.8.3, 6.9.7, 6.10.3) |
| CVE-2021-44906 (minimist) | fixed in 0.2.4 **and** 1.2.6 |
| CVE-2020-7598 (minimist) | fixed in 0.2.1 **and** 1.2.3 |
| CVE-2022-25883 (semver) | fixed in 5.7.2, 6.3.1 **and** 7.5.2 |
| CVE-2019-8331 (Bootstrap) | fixed in 3.4.1 **and** 4.3.1 |
| CVE-2021-40822 (GeoServer SSRF) | "through 2.18.5 **and** 2.19.x through 2.19.2" |

Writing any of these as a single interval collapses to the widest branch, which
matches a host patched on a narrower one. Writing the narrow branch alone
under-matches — and an under-match is **silence**, which is what a correct run
against a clean target also looks like. So they are refused rather than
approximated.

*No producer route can name the component (3):*

| Advisory | Why nothing in this engine names it |
|---|---|
| CVE-2022-42889 (Apache Commons Text, "Text4Shell") | `_package_identity` reads **npm formats only** — `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `package.json`. There is no `pom.xml` / `build.gradle` reader, so no Java library is producible |
| CVE-2019-7609 (Kibana Timelion) | also two branches (5.6.15, 6.6.1), so it is in both buckets |
| CVE-2019-10758 (mongo-express) | no fingerprinter reports mongo-express with a version |

**The npm-only bound is the larger of the two gaps** and it is structural, not a
content decision: every Java, Python, Ruby and PHP library CVE is unwritable
until a manifest reader for that ecosystem exists.

### 7.7 One stated limitation on the ranges themselves

There is **no offline advisory feed in this repository**. Every interval above
was written from the advisory as recalled, not derived from a feed the build can
re-check. The `reference` field on each row states the advisory's own wording
("Apache Solr 5.0.0 through 8.3.1; fixed 8.4.0") precisely enough that a reader
can verify a row in one lookup, and the half-open form means a wrong number
produces an over-match — a lead or a refused dispatch — rather than the silent
under-match §1 exists to prevent. Ingesting OSV/GHSA so the ranges are derived
rather than recalled is the obvious next step and is not done.

## 8. Part 3 — verification by replay, with the control

`python scripts/cve_reservation_corpus.py` — sends nothing, exit 0.

**The zeros are unchanged.** 76 bundles carry `plan_coverage`, 11 yield a
recoverable inventory, and every one of them reserves 0 and plans
byte-identically. Apache 2.4.67 and PHP 8.5.6 remain the whole recovered
inventory and no new entry matches either.

**The per-entry positive control (new).** A zero from a matcher that fired and a
zero from a row nothing can match are the same number, and only one is a
measurement — so every row is probed with an observation synthesised from **its
own** declaration and put through the real `match_components`:

```
  entries probed ....... 28
  fired ................ 28
  reserved a slot ...... 6
  UNREACHABLE .......... 0
  disposition mismatch . 0
```

The synthesis proposes; `match_components` decides. It found a real defect on
its first run: jQuery CVE-2015-9251 (`<3.0.0`) probed as `3.-1.99`, because the
decrement had no borrow — reported UNREACHABLE rather than skipped, which is the
control working. Fixed (`_version_below`), and the row now fires at `2.99.99`.

**The bundle control's claim changed, and that is the finding rather than a
loosened test.** It required the Apache substitution to RESERVE a slot. Both
Apache rows are `URL_PATH` now and reserve nothing, so requiring a reservation
would be requiring the defect back. The claim moved to *matched, and became
exactly what its row declares* — plus an explicit refusal if either Apache row
ever dispatches again. The dispatch half of the instrument is proved by the
per-entry control above and by the package control's log4j arm, both of which do
reserve.

**Drift removed.** `_target_url_for` was a hand-maintained copy of the agent's
endpoint rule; it went stale the moment the agent stopped preferring the root. It
now calls `ExploitAgent._component_cve_target_endpoint` directly.

## 9. Part 4 — Band C in the deliverable

`ReportAgent._render_version_match_disposition` renders **What a version match
can become** on every run that fingerprinted anything, computed from
`KNOWN_COMPONENT_CVES` so the numbers cannot drift from the rows they describe.

Four dispositions, four different sentences: testable, no oracle, oracle-without-
a-carrier, and Band C. The last is stated as a **product property**:

> Denial of service, memory safety, local privilege escalation, a defect
> conditional on a configuration we cannot observe, and an information leak whose
> effect is visible only at a third party are permanently lead-only here. Proving
> a resource-exhaustion claim means degrading your service, which this engine
> refuses on every target under any authorization; proving a third-party leak
> means observing the third party. These are reported as leads with the reason
> stated, never as findings and never as a coverage gap we intend to close.

That is the differentiator. A competitor prints these as findings; the reason
they can print more rows is that they are not required to be able to prove any
of them. `ENVIRONMENTAL` is also the model's DEFAULT vector — the fail-safe
value, so a row nobody classified cannot dispatch — which makes it the value a
row lands on by accident too. A Band C row therefore has to say
`permanently lead-only` in the sentence a client reads, a claim an author cannot
make by forgetting.

## 10. Not done, deliberately

* **The Vulhub end-to-end proof.** It needs a pinned affected version and is the
  next item.
* **The URL-path carrier**, which would move four rows from §7.3 to §7.2.
* **OSV/GHSA ingestion**, which would replace §7.7's recalled ranges with
  derived ones and close most of §7.6's grammar bucket at the same time.
* **Non-npm manifest readers**, the larger half of §7.6.
