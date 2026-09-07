# Auth stack, live — run record #136

Three targets, before and after the branch's changes, on the machine that
produces the bundles. This file is the run record the branch is graded against;
the artifacts it names are local-only by policy (`outputs/` is never committed),
so what is written down here is what the run said, not a summary of it.

**And the headline is a caveat, not a pass.** All three targets authenticate, on
both the pre-fix and the post-fix code, and **that proves nothing about the
promoted-session defect this branch exists to fix.** DVWA sets a fresh
`PHPSESSID` on the credential POST, Juice Shop returns a JWT, Meridian sets
`meridian_portal` — all three hand the credential exchange something the POST
itself produced, so all three reach `PROVEN` by rule 1 whether the
`INDETERMINATE` branch works or not. A green run on these three is a statement
that nothing REGRESSED. The statement that the fix WORKS is
`tests/test_tools/test_promoted_session_login.py`, which builds the shape no
target here has.

---

## What ran

Two passes. The first validates the two commits already on the branch
(`7687809` + `3b920d0`); the second re-runs the two fast targets on the branch
head after the deferral, the budget and the lockout stop landed.

| pass | target | engagement | exit | findings |
|---|---|---|---|---|
| pre-fix | Meridian | `f997bc8e` | 0 | 0 |
| pre-fix | Juice Shop | `7f7bb50f` | 0 | 12 |
| pre-fix | DVWA low | `e0d46633` | 0 | 25 |
| pre-fix | DVWA medium | `94aeced2` | 0 | 8 |
| pre-fix | DVWA high | `e82b4586` | 0 | 8 |
| pre-fix | DVWA impossible | `8ec97614` | 0 | 8 |
| post-fix | Meridian | `bbdcd703` | 0 | 0 |
| post-fix | Juice Shop | `47c9bd5c` | 0 | 9 |

Every bundle passed the disclosure gate: `ARTIFACT SCAN CLEAN … 0 credential
shapes`.

DVWA level was read from the container, not assumed
(`docker exec clinkz-dvwa sh -lc 'echo $DEFAULT_SECURITY_LEVEL'`), and the ladder
pins it per level through compose.

---

## The auth verdict per target, and WHICH RULE carried it

Two verdicts per target, and they are different questions. The **login verdict**
is what the credential exchange itself concluded; the **assertion** is what
`assert_authenticated` proved against an anonymous control. The branch made the
first one three-valued, which is why it is now stated separately.

### Meridian — `login_redirect`

* **Login verdict:** `proven — the credential POST set meridian_portal`
  (rule 1: session material the credential POST produced). The exchange takes
  two POSTs: the form-encoded one is answered `415`, the response names
  `application/json`, and the same credentials are re-POSTed under it.
* **Assertion:** `PROVEN at /api/profile via login_redirect (auth=200 anon=302)`
  for both roles.
* **The rule that carried it, in the assertion's own evidence** — and this is the
  `/portal/gateway` regression, alive:
  1. `Anonymous GET /api/profile -> 302 Location: /portal/gateway?next=%2Fapi%2Fprofile;
     authenticated GET -> 200, not redirected. The session is the only difference
     between the two requests.`
  2. `The redirect carries 'next' naming the path we requested — the destination is
     where you are sent to come back from, which is a login redirect by construction.`
  3. `The destination …/portal/gateway?next=… serves an <input type="password"> —
     it is a login surface by shape, not by name.`

  Three observations, none of them the destination's spelling. `/portal/gateway`
  contains none of the seven substrings the old oracle matched.

### Juice Shop — `status_class`

* **Login verdict:** `PROVEN` via the JSON arm — `JSON/API auth succeeded via
  http://clinkz-juiceshop:3000/rest/user/login (token)`. Rule 1 again, by the
  token branch.
* **Assertion:** `PROVEN at /api/users via status_class (auth=200 anon=401)` for
  both roles. `Multi-role engagement: 2 proven sessions (admin, user) handed to
  Exploit`.
* The rule is a pure boundary: a status class the session changes and nothing
  else. No name is read anywhere on this path.

### DVWA — no discriminator needed

The ladder authenticates a single `admin` through the form arm; the level is
pinned per rung and the admin password hash is compared before and after each
run. `hash_unchanged=True` at all four levels: the run damaged nothing.

Both discriminators match the PR #133 regression baseline exactly
(`login_redirect` @ Meridian `/api/profile`, `status_class` @ Juice Shop
`/api/users`).

---

## The DVWA ladder — the primary gate passed, one secondary gate failed

**PRIMARY (the ladder's own oracle): PASSED.**

> `VERDICT: header findings are IDENTICAL across 4 levels`

seven header findings at low, medium, high and impossible, over origin-root header
sets the runner reports as *divergent* — so the invariance is a property of the
engine's deterministic analysis and not of identical inputs.

| level | rc | seconds | headers | exploitation | auth_bypass | hash_unchanged |
|---|---|---|---|---|---|---|
| low | 0 | 1837.1 | 7 | 18 | 0 | True |
| medium | 0 | 930.3 | 7 | 1 | 0 | True |
| high | 0 | 900.3 | 7 | 1 | 0 | True |
| impossible | 0 | 893.8 | 7 | 1 | 0 | True |

**SECONDARY: `impossible_zero=False`, and the runner therefore exited 1.**

The honesty control group is *impossible emits zero exploitation findings*. It
emitted one, the same one at medium, high and impossible:

> `medium | No Brute-Force Protection on http://172.20.0.3/login.php`

That finding is **level-independent by construction, and the gate cannot see
it.** DVWA's `security` cookie switches which vulnerability MODULE code runs; it
does not touch the application login. Read out of the running container:

```
$ docker exec clinkz-dvwa sh -lc 'grep -niE "security|lockout|attempt|sleep|throttl" /var/www/html/login.php'
(no output)
```

`login.php` contains no reference to the security level, to attempt counting, or
to any delay. It has no brute-force protection at `impossible` for the same
reason it has none at `low`, and the class is reporting that correctly. Note the
endpoint: `/login.php`, the **application** login — not
`/vulnerabilities/brute/`, which is the level-gated module.

This is the blind spot the gate's own docstring already carves out for the other
class of level-independent truth:

> *"a missing `X-Frame-Options` is as true at impossible as at low — counting it
> would make the control group fail for the one reason that is not a phantom."*

`exploitation_findings()` excludes header rows for exactly that reason and
excludes nothing else. A no-lockout finding on an application login is the same
shape.

**The gate was NOT changed.** Loosening an acceptance criterion on the branch it
is grading is the failure mode invariant 35 exists to prevent, and a gate that is
relaxed to make a run pass has stopped being a gate. It is reported here, red,
with the cause named; the fix belongs in its own change with its own evidence.

Two further violations, both at `low`, both pre-existing and both a ranking
question rather than an auth one:

```
VIOLATION: RANKING: _test_nosqli primary target dropped (…/vulnerabilities/captcha/#) and the class emitted nothing
VIOLATION: RANKING: _test_nosqli primary target dropped (…/vulnerabilities/csrf/test_credentials.php) and the class emitted nothing
```

---

## The disclosure fix, measured on a live run

Meridian, two roles, the whole engagement:

| | `State-changing requests sent` |
|---|---|
| pre-fix (`f997bc8e`) | **2** |
| post-fix (`bbdcd703`) | **4** |

Two `authenticate()` calls that each dispatch two credential POSTs. Before, the
action log recorded one entry per CALL and said `POST mutates target state`.
Now it records one per POST, under `credential_attempt`, reading
`credential attempt N of 8 for account 'acct-4417' at http://…` with the account
in `signal` and the password redacted.

The per-shape counts behind that, measured at the transport against Meridian
(`scratchpad/count_attempts.py`, one `authenticate()`, one role, no operator
declarations):

| | docker (curl) | local (aiohttp) |
|---|---|---|
| credential that WORKS — before | 2 | 2 |
| credential that WORKS — after | 2 | 2 |
| credential that does NOT — before | **16** | **18** |
| credential that does NOT — after | **8** | **8** |

The refusal is loud and names the remedy:

> `refused by safety policy [credential_attempt_budget]: 8 credential attempts
> have been made against account 'acct-4417' at http://clinkz-meridian:8090 and
> the per-account budget is 8. Refusing further attempts. If this login genuinely
> needs more, declare login_api_url / login_field / login_content_type so it is
> reached in one, or raise max_credential_attempts_per_account`

---

## Juice Shop, before and after: 12 findings → 9

Seven are common. Two more are the SAME two header findings under a different
origin spelling (`172.20.0.2:3000` before, `clinkz-juiceshop:3000` after) — which
alias the crawl resolved, not a change in what was found. Net: **three findings
dropped** —

* `critical: JSON Web Token (JWT) Attack — alg_none`
* `high: Idor — via UserId parameter (horizontal)`
* `medium: Open Redirect via to parameter (allowlist_bypass)`

**This is plan allocation, and it is the documented residual for this target.**
Both runs truncated the deterministic plan at the same cap of 148; the candidate
sets differed (2,801 dropped before, 3,367 after) because the crawl surfaced a
different endpoint set, and the per-class drops moved with it — `_test_jwt` 158 →
166, `_test_idor` union 1 → 3. The three-run envelope of 2026-08-31 recorded the
same thing: class+param findings reproduce, and plan class allocation is what
moves between runs.

**It is reported rather than resolved.** Attributing it to the crawl's endpoint
set is consistent with both runs' own truncation numbers, and it is not the same
as having isolated it — a third run would be the control, and it was not taken.
Stated so it is not read as a coverage claim.

---

## Running the three again

```bash
docker compose -f docker/docker-compose.yml up -d
# inputs are NOT committed — rebuild from a prior report's authorization block,
# see docs/methodology/authentication-shapes.md and the ladder runner's --help
python -m clinkz scan --target http://localhost:8090 -a meridian_auth.json  -c meridian_creds.json
python -m clinkz scan --target http://localhost:3000 -a juiceshop_auth.json -c juiceshop_creds.json \
    --benchmark-profile juiceshop_bp.json
python scripts/dvwa_ladder_run.py --authorization ladder_auth.json --benchmark-profile ladder_bp.json
```

Meridian ~6 min, Juice Shop ~40 min, the ladder ~75 min for four levels on this
machine (the 2026-08-21 ladder took ~2.7 h; the three ran concurrently here, and
low was the only rung that took its historical time).
