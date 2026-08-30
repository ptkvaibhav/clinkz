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
