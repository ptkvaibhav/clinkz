# SCA catalogue breadth — what a real affected-range predicate would cost

**Report only.** Nothing here changes `knowledge/component_cves.py`. The
instruction was to get the shape before the content, and the shape is the part
that turns out to matter: two of the three limits below are not "add more
entries" problems at all, and one of them silently produced a wrong answer on a
real target.

Measured against the catalogue and the version grammar as they stand
(2026-08-30): **9 entries, 3 confirmable, 6 lead-only, 9 distinct predicates,
30 dispatchable `_test_*` classes.**

---

## 1. The 2.4.67 miss was a grammar problem wearing a content problem's clothes

The two Apache entries are `=2.4.49` and `=2.4.50` — single-point predicates.
A live target observed at **2.4.67** missed them, and it is worth being precise
about why, because "add more entries" is the wrong lesson.

CVE-2021-41773 really does affect exactly 2.4.49, so `=2.4.49` is a *faithful*
encoding of that advisory. The miss is not that the range was too narrow. It is
that **a catalogue of point versions cannot express most advisories**, so the
entries that would have matched 2.4.67 could never have been written in this
grammar in the first place. `discovery/versions.py` supports:

```
'<X'  '<=X'  '>X'  '>=X'  '=X'  '[X,Y]'  '*'
```

One interval, one comparison, or everything. Real NVD data is not shaped like
that. The four capabilities missing, in the order they bite:

| Missing | Real-world shape it fails on | Consequence today |
|---|---|---|
| **OR of ranges** | Apache httpd advisories are routinely "affects 2.4.x < 2.4.58 **and** 2.2.x < 2.2.34" | Two branches need two entries with the same CVE id, which then match, order and de-duplicate as if they were two vulnerabilities |
| **Half-open intervals** | `>=2.4.49, <2.4.51` — the overwhelmingly common CPE shape | Expressible only as `[2.4.49,2.4.50]`, which requires knowing the last affected version rather than the first fixed one. Every entry needs a human to decrement a number, and a decrement that is wrong by one is silent |
| **Per-branch fixed versions** | Log4j: fixed in 2.16.0 for Java 8, 2.12.2 for Java 7, 2.3.1 for Java 6 | The entry has to collapse to the widest branch, so a patched Java-7 host matches |
| **Pre-release ordering** | `1.2.3-rc1` precedes `1.2.3` | `parse_version` takes the leading integer run per segment and **discards the tail**, so `1.2.3-rc1 == 1.2.3`. A release candidate of a fixed version is graded fixed |

The last row is the only one that is a live defect rather than a recall limit,
and it fails in the safe direction (a lead is not emitted). It is recorded here
rather than fixed because fixing it means implementing pre-release precedence,
which is a semver-comparison rewrite, not a catalogue edit.

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

1. **SSRF / SQLi entries** (~1 row each). Reuses a confirmable oracle. No
   grammar change needed if the advisory happens to be a single interval.
2. **Half-open intervals** (`>=X,<Y`). A small addition to
   `version_satisfies`, and it removes the decrement-by-one hazard from every
   future entry. This is the single change that makes the catalogue safe to
   grow.
3. **OR-of-ranges.** Needed before any multi-branch server advisory can be
   encoded honestly. Changes `KnownComponentCVE.affected` from a string to a
   list, which touches the matcher, the lead text and the corpus replay.
4. **Pre-release precedence.** Fixes the `1.2.3-rc1 == 1.2.3` grading. Fails
   safe today, so it is the lowest priority despite being a correctness bug.
5. **A digest catalogue** (`ARTIFACT_HASH`). The strongest provenance the enum
   declares and the only one nothing produces. A served bundle's SHA-256 is
   trivially computable and identifies nothing without a table of known digests
   to compare it against, which is a data-acquisition problem rather than a
   code one. Deliberately not built: computing a hash and reporting it as
   identity would be a number with nothing to compare it to.

Nothing above is a reason to add entries first. The grammar limits in §1 mean a
larger catalogue written today would carry the same silent decrement hazard on
every new row.
