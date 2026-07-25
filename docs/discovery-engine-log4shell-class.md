# Discovery engine — the THIRD capability class (Log4Shell), the payoff of P6

> **Raw artifacts:** the `outputs/…` run artifacts cited below are local-only by policy — retained by the operator, not committed to the repo.

**The thesis test.** Slices 1–2 proved the engine finds + confirms two different-codebase
**SSRF**s from one `EGRESS_FETCH` catalog entry (in-band, P3/P1). The file-read slice
proved the catalog holds a **second class** reducing to an already-built **in-band**
oracle (`_test_lfi`, P3). This slice is the hardest claim and the flagship: does the
engine hold a class whose proof has **no in-band signal at all** — reducing to the
**out-of-band** primitive (P6) — reached by a **channel most scanners never model as
untrusted** (a logging call), at a **heuristic, cross-function, manifest-gated**
reachability grade? Or was the engine quietly in-band-shaped?

**Fixture (verified first, per the premise-verification discipline).** Vulhub
`log4j/CVE-2021-44228`: **Apache Solr 8.11.0** + **`log4j-core` 2.14.1** on :8983,
`GET /solr/admin/cores?action=${jndi:…}` — the `action` value is logged, log4j
interpolates the JNDI lookup. Confirmed live before building: the container ships
`log4j-core-2.14.1.jar`, the endpoint answers, and — the load-bearing empirical check —
a throwaway listener proved which JNDI callback actually fires locally (see
*Paper-vs-live* below).

---

## The deliverable metric — EXACTLY what the log-sink class required

| Layer | SSRF (egress) | File read | **Log-sink (Log4Shell, this slice)** | New code? |
|---|---|---|---|---|
| **Catalog entry** | `EGRESS_FETCH…` → `_test_ssrf`, P1/P3 | `FILE_READ…` → `_test_lfi`, P3 | `LOG4J_INTERPOLATION_JNDI` → `_test_log4shell`, **P6**, manifest-gated | **1 entry** |
| **Matcher / intent / hypothesis** | keyed on `PrimitiveClass` | *unchanged* | *unchanged* (extends, not forks) | **none** |
| **Source sink idiom** | `openConnection()` | `new File(dir,name)` | **logging call** `log(ger)?.(info|warn|…)(…)` w/ request-derived arg | **1 general idiom** |
| **Source capability gate** | tech pattern | tech pattern | **manifest scan** `log4j-core < 2.15` → token (learned from `pom.xml`) | **1 general idiom** |
| **Reachability** | intra-function `STATIC_CONFIRMED` | intra-function `STATIC_CONFIRMED` | **cross-function `STATIC_HEURISTIC`** (the first heuristic edge) | **`_log_sink_edges`** |
| **Proof / oracle** | P3/P1 in-band | P3 in-band | **P6 out-of-band** — same `_oob_send`→`reap`→`ConfirmationEvidence` | **zero new proof code** |
| **Carrier** | Host-align (GeoServer) | path-segment traversal (Flink) | **none** (JNDI string is a param VALUE, shared string carrier) | **none** |

Plus one general broadening reused across classes: the param-read idioms now accept the
two-arg `.get(NAME, default)` form (Solr's `params.get(ACTION, STATUS.toString())`), so
`action` is **learned** from the `ACTION = "action"` constant — never hardcoded.

## Reachability-as-prior, P6 proves (§4.3) — the honest model for a log sink

The channel→sink path is **not** intra-function: `action` flows request → core-admin
dispatch → a `log().info(…, params)` call, and the interpolation happens deep inside
`log4j-core`. And log4j interpolates **any** logged string. So a precise taint trace is
both impossible (regex/bounded ingestor) and beside the point — the honest prior is
loose: *"an untrusted request param plausibly reaches a logging call."* `_log_sink_edges`
wires each untrusted entrypoint param (bounded, `action` first) to a representative log
sink at `STATIC_HEURISTIC`, ranked strictly below an intra-function `STATIC_CONFIRMED`
edge. The prior **ranks** the candidate channels; **P6 proves** which actually reach the
logger. Params that don't call back defer `blind_unconfirmed` — never a false emission.
The zero-FP OOB oracle downstream is exactly what lets the reachability layer
over-approximate honestly.

## N/A by construction — the manifest version gate

`_scan_log4j_manifest` learns the `log4j-core` version from a build manifest / jar name
and emits `LOG4J_VULNERABLE_TOKEN` only for `< 2.15.0`. The catalog primitive matches on
that token, not a bare "java" match. The `solr_log4shell_patched` fixture is **identical
source** with `log4j-core 2.17.1` in its `pom.xml`: no token ⇒ the primitive is not
active ⇒ no Δ, no edge, **no hypothesis**. A patched target is a correct non-finding, not
a miss.

## Paper-vs-live divergence — the JNDI channel is `dns://`, not `ldap://`

The design (§P6.5.4) named `${jndi:ldap://<T>.<zone>/x}`. On a Windows/Docker-Desktop box
that shape does not route: host UDP/53 is already bound (no host-DNS-on-53 for a delegated
`<zone>`), the container's embedded resolver forwards `<nonce>.<zone>` to the real host DNS
(never to us), and an `ldap://host.docker.internal:<port>/<nonce>` connect reached no IPv4
listener (IPv6-first `host.docker.internal`; the nonce-bearing LDAP search only follows a
valid bind). The channel that fires — proven with a throwaway listener before any code —
is **`${jndi:dns://host.docker.internal:<dns_port>/<nonce>}`**: Java's JNDI DNS provider
sends one UDP query for the nonce **directly** to the collaborator's DNS-leg authority,
nonce in the qname, no delegation, no port 53. Carried by a nonce-only `JNDI_DNS` template
+ `OOBCollaborator.dns_authority()` — the existing DNS leg records it with zero recording
changes. (§P6.5.4 already sanctioned "the DNS leg confirms Log4Shell"; this is which DNS
shape actually reaches it locally.)

## Live validation — real Solr + real collaborator + real exploit LLM, no harness

`scripts/live_log4shell_p6_validation.py`, engagement `0be7cb63`
(`outputs/p6-log4shell/`):

- **A. Log-sink reachability** — the engine ingests the real Solr/log4j source
  (`CoreAdminHandler` reads `action`; `CoreAdminOperation:76` `log().info(…, params)` is
  the sink; `pom.xml` declares `log4j-core 2.14.1 < 2.15`) and surfaces 8 `STATIC_HEURISTIC`
  hypotheses (`action` leading, rank 0.3375), each lowering to a `_test_log4shell` /
  `["P6"]` ExploitTask on `/solr/admin/cores`.
- **B. Log4Shell CONFIRMED via P6** — `_test_log4shell` fires the nonce-only JNDI/DNS
  probe; the target's log4j interpolates it and the DNS lookup for the nonce reaches the
  collaborator. **8 CRITICAL findings**, each raw-auditable:
  - `outbound_probe: GET …/solr/admin/cores — action=${jndi:dns://host.docker.internal:15353/<T>}`
  - `confirming_excerpt: inbound callback: proto=dns … host=<T>` (the **same** nonce `<T>`)
  - control: a fresh nonce minted but never sent → `control_bore_it=False` (unforgeability).
  Every one of the 8 params confirmed because Solr logs the **whole** param bag — a
  faithful witness that the loose "any logged param" prior is correct here.
- **C. Real seam (live LLM)** — the `action` hypothesis rides the real
  `run() → _parse_discovery_tasks → _merge_discovery_tasks` handoff and confirms through
  the real dispatch + `_persist_finding` chokepoint, with the live Anthropic planner.
- **D. Exfil guardrail** — the JNDI carrier structurally refuses every non-nonce payload
  (`${env:…}`, traversal, target host, whitespace).
- **E. Zero-FP** — a JNDI probe to an unreachable authority yields **no finding**
  (`blind_unconfirmed`, not `not_vulnerable`), and every confirmed finding carries the
  never-sent control.
- **F. No regression** — the generalized `_oob_send` still confirms a blind SSRF
  out-of-band (GeoServer CVE-2021-40822, HTTP leg), and the file-read discovery class
  still surfaces its Flink hypothesis.

**What it proves:** the capability catalog holds a class with **no in-band signal**, a
**channel scanners don't model** (a log line), and a **heuristic cross-function** prior —
reducing to the built P6 primitive with **zero new proof code**. Reachability-as-prior +
P6-proves works end-to-end, and the flagship's remaining risk lives entirely in recall
(the log-sink channel), exactly where the zero-FP framing predicts — never in the proof.
