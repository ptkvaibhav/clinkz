# P7 in the pipeline — validated through `clinkz scan`, not a driver

The companion to [`p7-client-execution-validation.md`](p7-client-execution-validation.md),
and it answers a different question. That document proves the **oracle**
discriminates. This one proves the **product** can reach it: four full
`clinkz scan` engagements against DVWA, one per security level, with no driver,
no environment variable set by hand, and nothing arranged by the operator beyond
starting the containers.

## Why the distinction was not academic

P7 shipped validated and unreachable. The driver ran the browser in-process
against `http://localhost:8080`, which is a set of conditions it assembles for
itself. A real engagement does not have them:

- `TOOL_EXEC_MODE=docker` is the default and the only mode with a port scanner.
  In it, `resolve_target_for_docker_mode` rewrites the operator's
  `http://localhost:8080` into `http://clinkz-dvwa:80` — a network alias that
  resolves on the shared bridge and nowhere else. A browser on the host can
  neither resolve that name nor route to `172.20.0.0/24`, so a host-side oracle
  fails **every** navigation.
- Local exec mode, where a host browser would work, has no `nmap` or `ffuf` on a
  developer machine.
- `CLIENT_ORACLE_MODE` defaulted to `disabled`, so `_provision_client_oracle`
  returned `None` and no oracle was constructed at all.
- `native_availability()` probed the **host** filesystem for Playwright's
  browser registry — the wrong machine in docker mode, answering wrongly in both
  directions.

Verified rather than reasoned: from inside `clinkz-tools`,
`curl http://clinkz-dvwa:80/login.php` returns 200 and
`curl http://localhost:8080/` is unreachable. The two addressing worlds are
disjoint, and the oracle has to be on the target's side of the line.

## What the engagement actually does now

One log line from a plain `python -m clinkz scan --target http://localhost:8080`:

```
OrchestratorAgent P7 client-side execution oracle ready: playwright_chromium
```

resolved by capability (`client_side_execution`), provisioned by the
Orchestrator, with the browser driven inside `clinkz-tools` by
`browser/_container_runner.py` — a module with zero Clinkz imports, delivered to
the container's bare `python3` on stdin because the tools image has Playwright
and nothing of this codebase.

## Pre-flight (all four runs)

- Both providers live-pinged (Anthropic, Gemini) before any run; keys counted,
  never printed.
- `clinkz-tools` rebuilt so the image actually carries Chromium. The Playwright
  layer is self-verifying and immediately earned it: Kali is not a distribution
  Playwright ships a dependency list for, so `playwright install --with-deps`
  printed *"BEWARE: your OS is not officially supported"*, skipped the OS
  packages, and installed an Ubuntu fallback build. The layer launches the
  browser it just installed and fails the build otherwise, so the image cannot
  ship a Chromium that does not start.
- **The DVWA level is switched by RECREATING the container between runs, never
  inside one.** One engagement is one target state — the rule the report-artifact
  fix below exists to enforce — so switching mid-run would reproduce the exact
  defect being fixed.
- The scan waits for `[dvwa-init] database created — admin login verified`, not
  merely for Apache. This is not incidental: `dvwa-init.sh` POSTs `create_db`,
  which **drops and recreates the tables**, and starting on the Apache signal let
  that POST land ~90 s into an engagement, resetting the database under a live
  session. That run reported 10 findings instead of 21 and lost SQLi, command
  injection, file inclusion, upload, brute force, CSRF, stored XSS and
  weak-session — a harness defect that reads exactly like a product regression.
  It is written down because diagnosing it consumed a full validation cycle.

## Results

Four engagements, one per level, each from `python -m clinkz scan --target
http://localhost:8080 --authorization <auth.json>`. Every number below is
re-derived from the reports, action logs and traces themselves — not read off a
runner summary.

| level | engagement | `xss_d` | nonce out → back | control silent | browser navigations | artifact scan |
|---|---|---|---|---|---|---|
| low | `35511096` | **CONFIRMED** | `qibquvw6qagong7rgqmu2d3dmy` → same | yes | 2 | 0 credential shapes |
| medium | `1b23a1ef` | **CONFIRMED** | `2e2p5za4eggsxwagrzyymedgty` → same | yes | 7 | 0 credential shapes |
| high | `946e7036` | **CONFIRMED** | `oinypk6e4pxtrcegc2m5s4q3um` → same | yes | 2 | 0 credential shapes |
| impossible | `f4b0c5c8` | **SILENT** | `xowrxyf4msw3bg2dsdnsrnpdbm` → *(never returned)* | yes | 4 | 0 credential shapes |

**The `impossible` row is the honesty control and it holds.** The inline sink is
byte-identical at low, medium and high; only at `impossible` does DVWA drop the
`decodeURI` call, so the percent-encoded payload stays inert. A primitive that
confirmed at all four would be matching the application's benign response rather
than its vulnerability — the
[uniform-confirm-across-a-graded-control](methodology/dvwa-per-level-honesty.md)
phantom. P7 discriminates because it measures the effect.

### Against the documented baseline

Split by kind, because the two move for different reasons — posture headers are
subject to a per-category cap that exploitation findings are not.

| level | exploitation now | exploitation baseline | posture now | posture baseline |
|---|---|---|---|---|
| low | 14 | 14 | 7 | 7 |
| medium | **12** | 11 | 7 | 7 |
| high | **8** | 7 | **5** | 7 |
| impossible | 0 | n/a | 7 | n/a |

- **medium and high are exactly baseline exploitation + DOM-XSS.** Every baseline
  entry survives and the new class is additive.
- **low nets out level.** DOM-XSS is gained and one *duplicate* SQL-injection
  instance on the login form is displaced by the extra task in the plan; SQL
  injection still confirms twice on `/vulnerabilities/sqli/?id=`, its own module,
  so the class is unaffected. The open-redirect entry confirms a different bypass
  variant (`at_syntax` rather than `direct_redirect`) — pre-existing
  LLM-ranking variance in which bypass is tried first, present in the same-day
  pre-change control too, not a consequence of this change.
- **high's posture count falls 7 → 5** because `_test_security_headers` reaches
  `EXPLOIT_CATEGORY_MAX_FINDINGS` and is rotated to the back; its exploitation
  set is strictly better. This is the documented soft-cap behaviour, not a lost
  detection.

**No engagement contains a contradictory pair** — zero leads matching a confirmed
finding on the same `(endpoint, parameter, technique)`, which is the artifact
defect `908b7130` shipped and the supersession rule now prevents.

### The rails, from the artifacts

`actions.jsonl` carries every navigation, GET included, under
`category=browser_navigation`, e.g.

```
sent GET http://172.20.0.4/vulnerabilities/xss_d/?default=clinkz#<script>window.__clinkz_w_…('…')</script>
```

and `safety_summary` tallies them apart from the state-changing counters
(`"state_changing_sent": 279, "browser_navigations": 9`), so neither number has
to be read with a qualifier.

The recorded invocation shows the redaction holding — cookie names survive,
values do not:

```json
"cookies": {"security": "[REDACTED]", "PHPSESSID": "[REDACTED]"}
```

## What is NOT proven here

**CSP bypass cannot appear in an engagement report at any security level**, and
no amount of oracle wiring changes that. There is no CSP methodology: the
Exploit agent's dispatch table and `models/vuln_classes.py` both hold nineteen
classes, asserted in sync with each other, and none of them is CSP. The
driver's CSP results come from calling `_p7_csp_route` and `_p7_witness`
directly — internals, not a class the planner can schedule.

So the honest split is: P7 supplies the **oracle** a CSP class would confirm
through, and that oracle is proven (a reused static nonce at medium, a
same-origin script gadget under `script-src 'self'` at high). The **class** is
unbuilt. Making it reachable means a twentieth `_test_csp` with a registry
entry, ranking signals, remediation copy, and its own per-level honesty
validation — deliberately scoped as its own piece of work rather than bolted
onto this one.
