# The rediscovery ladder — a pre-registered black-box benchmark

**Status: PRE-REGISTERED. No runs yet.** The commit that adds the "Scoring
rules" section below is the pre-registration: every prediction and grading rule
in this file is fixed as of that commit, and results are recorded beside it in
[`rediscovery-ladder-results.md`](rediscovery-ladder-results.md) — never by
editing a prediction here. This document exists to be wrong in public. It
names six Vulhub targets, one per vulnerability class Clinkz claims, and — before
a single engagement runs — records for each the defining effect the oracle must
witness, the class that should witness it, whether a carriable vector exists
today, and a **hit/miss prediction**. When the runs happen, the result grades the
prediction as much as the engine: a predicted hit that misses is an oracle gap, a
predicted miss that hits is a pleasant surprise worth understanding, and a
predicted miss for a named reason is a Tier-2/3 acceptance case rather than a
failure.

Pre-registration is the whole point. An engine evaluated against targets chosen
*after* seeing what it finds grades itself; this is the opposite discipline, the
same one `juiceshop_benchmark_run.py --record-floor` enforces for the benchmark
floor. Path traversal is already done (`docs/methodology/lfi.md`, rediscovered
black-box on Vulhub Flink 1.11.2), so it is not re-listed here except as the
ladder's one confirmed rung.

## What "carriable" means here

A component-derived or black-box injection task carries its probe as a request
**parameter value** — the one vector every `_test_*` oracle already sends
(`knowledge/component_cves.py::CARRIABLE_VECTORS = {REQUEST_PARAM}`). A target
whose defining input arrives in the **URL path**, a **request header**, or the
**whole request body as a document** needs a carrier the black-box planner does
not build, even when the oracle itself could witness the effect given the right
task. That gap is invariant 86's `LEAD_VECTOR_NOT_CARRIED`, and it is the single
most common predicted-miss reason below. It is a plan-source limitation, not an
oracle limitation — the distinction the prediction has to keep straight.

A second structural limit shapes several predictions: **no out-of-band
collaborator is wired by default** in a plain `scan` (`_test_ssrf` /
`_test_xxe` / `_test_cmdi` all prune their OOB branch unless
`OOB_COLLABORATOR_MODE != disabled`). A class whose only confirmation channel is
out-of-band is a predicted miss in the default profile and a predicted hit with
P6 wired — stated per rung.

## The ladder

Images are pinned to the exact tag in each Vulhub `docker-compose.yml` as read on
2026-10-15. `discovery_base_url` is the target's HTTP surface; the engagement is
black-box (no `source_dir`) unless a rung says otherwise.

| # | Class | Target (Vulhub) | CVE | Pinned image | Defining effect the oracle must witness | Class | Carriable vector today? | Prediction |
|---|---|---|---|---|---|---|---|---|
| 1 | SQLi | `django/CVE-2021-35042` | CVE-2021-35042 | `vulhub/django:3.2.4` (+ `mysql:5.7`) | A backend-attributable effect on a query parameter — a DB error signature, a reproducible boolean content delta, or a time delta — on a value we sent, never the value reflected. | `_test_sqli` | **Yes** — `QuerySet.order_by` injection reaches through a GET param value; `REQUEST_PARAM`. | **HIT** |
| 2 | SSRF | `weblogic/ssrf` | CVE-2014-4210 | `vulhub/weblogic:10.3.6.0-2017` | The in-scope server fetches an internal address. WebLogic's channel is a **port-open/closed error differential**, NOT reflected content — and Clinkz's in-band oracle confirms only on reflected internal content, treating a bare differential as `BLIND_DEFERRED`. | `_test_ssrf` | **Yes** — the internal URL rides as the `operator` query-param value (`REQUEST_PARAM`). Carrier is fine; the confirmation channel is the issue. | **Graded in BOTH profiles; both runs happen.** **2a — OOB disabled (default `scan`): MISS** — reachability noted (`blind_suspected`), no finding, because there is no content reflection. **2b — P6 collaborator wired** (`OOB_COLLABORATOR_MODE != disabled`): **HIT**. States the OOB gate rather than discovering it. |
| 3 | CMDi / RCE | `spring/CVE-2022-22963` | CVE-2022-22963 | `vulhub/spring-cloud-function:3.2.2` | Command execution observable in-band — stdout reflected into the response, or a bounded, reproducible time delta on a value we sent. | `_test_cmdi` | **Partial.** The SpEL payload rides in the `spring.cloud.function.routing-expression` **header**, not a param value. `_test_cmdi` is parameter-scoped and carries no header probe → `HTTP_HEADER`, not carriable. | **MISS — `LEAD_VECTOR_NOT_CARRIED` (header carrier).** Tier-2/3 acceptance case: oracle effect is witnessable (stdout/time), the carrier is the gap. |
| 4 | XXE | `php/php_xxe` | n/a (lab, not a CVE) | `vulhub/php:7.0.30` | The XML parser resolves an external entity and the **expanded file content** (a `root:x:0:0`-shaped signature we never sent) surfaces in the response body — status is not a reject signal for this class. | `_test_xxe` | **Yes** — the endpoint accepts a raw `application/xml` body; `_test_xxe` carries the document itself (a `REQUEST_BODY_DOCUMENT` it builds for itself, not via the CVE plan source). | **HIT** for in-band file disclosure. OOB-exfil-only parsers (no in-band channel): miss without P6, hit with P6. **A lab, not a CVE: this rung is a CLASS CHECK and does not count toward rediscovered CVEs.** |
| 5 | Deserialization | `shiro/CVE-2016-4437` | CVE-2016-4437 | `vulhub/shiro:1.2.4` | **No oracle exists for this class today.** The defining effect (a gadget-chain deserialize → RCE) is confirmable only out-of-band or by a second-order effect no `_test_*` method witnesses; the payload rides in the `rememberMe` **cookie** as an encrypted, serialized blob. | *(none — no deserialization class)* | **No** — no class, and the vector is a cookie-borne opaque blob. | **MISS — no class (Tier-2/3 acceptance case, named).** This is the clearest "predicted miss for lack of a class": it belongs on the roadmap, not the scorecard. |
| 6 | Auth bypass | `nacos/CVE-2021-29441` | CVE-2021-29441 | `vulhub/nacos:1.4.0` | Authenticated as a principal whose credential we never supplied — a protected endpoint returns privileged content to a request carrying a forged `serverIdentity` **header**, with the sessionless control refused. | `_test_*` auth-bypass path (`InjectionType.AUTH_BYPASS`, `agents/_auth_bypass.py`) | **Partial.** The auth-bypass oracle's three arms are sessionless and its defining-effect check is sound, but the Nacos bypass is a **header** injection; the current carrier (`_auth_bypass_send_probe`) rides a login-form field, not an arbitrary header. | **MISS — `LEAD_VECTOR_NOT_CARRIED` (header carrier).** Tier-2/3 acceptance case: the decision logic is right, the carrier is the gap. |

## Reading the predictions

- **Clean hits (rungs 1, 4):** two classes whose defining input is a parameter
  value or a document body the oracle builds for itself, and whose confirmation is
  in-band. These are the rungs that test the oracle; a miss here is a real defect
  and the register gets an entry.
- **OOB-gated (rung 2, and rung 4's exfil-only variants):** miss in the default
  `scan` profile, hit once a P6 collaborator is wired (`OOB_COLLABORATOR_MODE`).
  The prediction is stated for both profiles so the run **confirms** the gate
  rather than discovering it — a predicted miss here that still misses with P6
  wired would be the real defect.
- **Carrier misses (rungs 3, 6):** the oracle *could* witness the effect, but the
  black-box planner builds no task that puts the probe where the target reads it
  (a header). These are invariant-86 `LEAD_VECTOR_NOT_CARRIED` cases and are the
  honest Tier-2/3 acceptance frontier: building a header carrier is a code change
  plus a live proof, exactly as `CARRIABLE_VECTORS` says widening it must be.
- **Class miss (rung 5):** no deserialization class exists. Predicted miss, named
  as such; it does not grade the engine's oracles because there is no oracle to
  grade.

Pre-registered, the tally is kept in two columns that are never summed:

- **Rediscovered CVEs** (rungs 1, 2, 3, 5, 6 — five CVEs): predicted **1 of 5**
  in the default profile (rung 1), **2 of 5** with P6 wired (rungs 1, 2b).
- **Class checks** (rung 4 — a Vulhub lab with no CVE): predicted **1 of 1**.
  A lab exercises the oracle; it is not a rediscovery and never inflates the
  CVE column.

A deliberately sobering count. The ladder is not a scorecard to win; it is a map of exactly
where the oracle coverage ends (rungs 1, 4), where a known OOB gate decides the
outcome (rung 2), where a carrier is missing (rungs 3, 6), and where a whole
class is absent (rung 5). A run that reproduces this table confirms we understand
our own frontier; a run that departs from it is the thing worth investigating.

## Why these six and not others

Each is a **published CVE against a widely-deployed component** with a Vulhub lab
that stands up in one `docker compose up -d`, and each maps to exactly one class
Clinkz claims — the same bar `knowledge/component_cves.py` sets for catalogue
entries. Targets whose only path to the defining effect is an attack the safety
rails refuse to send (session destruction, a security-posture toggle), or an
observation made somewhere this engine does not stand (Band C / `ENVIRONMENTAL`),
are deliberately excluded: they would be predicted misses for a reason that is a
*product property*, not a gap, and the ladder is about gaps.

## Scoring rules (fixed before any run)

1. **Seven engagements, no engine change between them**: rungs 1, 2a, 2b, 3, 4,
   5, 6. Each runs against the pinned image above, with its own authorization
   record and effort defaults. Every container is torn down after its run.
2. **A HIT is graded on the defining effect plus a dispatched control arm that
   REFUSED** (invariants 27, 30), read from the stored finding and the trace.
   It is never graded on a version banner: a finding that rests on a version
   match is a phantom by invariant 57 and grades as a MISS.
3. **A MISS names where it stopped**, read from the trace rather than reasoned:
   **not discovered** (the surface never reached `endpoints`) · **not planned**
   (no `ExploitTask` for the class on the surface) · **not carried** (invariant
   86 `LEAD_VECTOR_NOT_CARRIED`) · **dispatched and not confirmed**.
4. **A predicted HIT that misses** becomes a register entry at the highest
   priority. **A predicted MISS that hits** is explained before it is counted.
5. Each row records the engagement id, the outcome, where it stopped, and the
   cost.
