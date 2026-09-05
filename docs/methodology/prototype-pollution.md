# Server-side prototype pollution (CWE-1321)

`_test_prototype_pollution` · oracle in `agents/_prototype_pollution.py` · target
in `docker/protopoll/app.js` · fixtures in
`tests/fixtures/prototype_pollution/observations.json`

This is the first class in the engine whose confirmation leaves the target
changed in a way the target cannot undo, and the first whose remediation section
asks the operator to do something to their own infrastructure *because we ran
the test*. Three of its rules exist for that reason alone, and they are stated
below before the oracle, because they are what makes the oracle safe to run.

---

## The identifier: CWE-1321, and no WSTG id

**WSTG-CLNT-13 is a different vulnerability.** It is *client-side* prototype
pollution: a write onto the browser's `Object.prototype`, in the visitor's
process, whose impact is DOM XSS and client-side logic subversion. This class
writes onto the *server's* prototype, in the client's own process, and its
impact is whatever the server later reads through that prototype.

The two share a mechanism and most of a name, and there is no server-side WSTG
id to reach for. Filing this under WSTG-CLNT-13 would put a memory-resident
compromise of the client's server into the client-side section of every report,
and it is the kind of "correction" a later reader makes in good faith on the
strength of the shared name. So the finding carries `CWE-1321`, the class
docstring says why, and this paragraph exists so nobody has to reconstruct the
reasoning.

---

## 1 · The arms run in the opposite order to every other class

Every other class in this engine observes its effect, then dispatches a control
arm to check whether the same oracle also says yes to something inert, then
grades. That order is *wrong* here, and not marginally:

> A prototype write outlives the request that carried it. After the payload the
> target is polluted, so a control arm dispatched afterwards is observed through
> a prototype the payload has already written to. It exhibits the effect too,
> the arm records `confirmed_on_control`, and a **true positive is killed by its
> own proof**.

So the control is dispatched **first**, and the ordering is owned by
`ExploitAgent._run_control_arm_first` rather than by the methodology: the seam
runs the control, then runs the class's confirming arm, then records both. A
class that could get the order wrong eventually would, and the failure mode is a
silent false negative.

The constraint generalises, and the docstring says so: **any payload whose
effect outlives its request needs this seam.** A write crossing on the
access-control family — one that leaves the other principal's object modified —
is the next class that will hit it, and should reach for
`_run_control_arm_first` rather than re-deriving the reason.

`test_prototype_pollution_oracle.py::TestTheArmsMustRunInThisOrder` pins it on
recorded observations by grading the real pollutable case with the two arms
swapped: both gadgets flip from confirmed to refused.
`test_prototype_pollution_live.py::test_the_control_would_have_confirmed_had_it_run_second`
pins the same thing against the live target, by dispatching a control *after* the
payload and asserting it does show the effect — so if the fixture ever stopped
exhibiting the constraint, the test that depends on it fails rather than passing
vacuously.

## 2 · Terminal dispatch

`TERMINAL_DISPATCH_CLASSES` names the classes whose effect on the target
outlives the run and cannot be undone through the application. The predicate is
narrower than "writes to the target": half the engine's classes write, and the
records they create are ordinary application records a client deletes the way
they delete any record. What makes a class terminal is that **its write changes
the behaviour of requests the class never made, and no request puts it back.**

Three consequences:

* **It is dispatched last.** The rotation in `_step_execute_exploits` only
  reaches a terminal class once no transient task is left, because every
  observation after it — including every other class's control arm — would
  otherwise be a measurement of a target this run had already altered.
* **The partition is asserted at dispatch, on every dispatch**
  (`assert_terminal_dispatch_order`). It holds by construction today, which is
  exactly why the check is there: a scheduler change that interleaved
  differently would break the property silently and the results would look
  exactly like results. It raises `TerminalDispatchOrderError` and stops the run
  rather than warning.
* **The classification is declared for every dispatchable class.**
  `TERMINAL_DISPATCH_CLASSES` / `TRANSIENT_DISPATCH_CLASSES` partition
  `DISPATCHABLE_TEST_METHODS` — a computed domain, both directions asserted, a
  substantive reason per entry. A class in neither is a red build, because
  "nobody classified it" and "it leaves nothing behind" are different facts and
  only one of them is safe to dispatch early.

**A wildcard authorization does not cover a terminal class.** `permits_all` is
how a client says "test everything"; it is not how they say "leave my process
altered until I restart it". `_technique_permitted` withholds the class under a
wildcard and the report's *What was NOT tested* section names it, says why, and
says which key to add to authorize it.

## 3 · The mutation is disclosed in the client-facing document

`ResidualMutation` → `PentestReport.residual_mutations` → a **Changes this test
left on your systems** section in the Markdown and the PDF, ahead of the
findings. It names the key, says the change is still present, and says a process
restart is required.

Two details that are the whole point:

* It is recorded on the **witnessed effect**, not on emission. If the control
  arm then refuses the finding, the operator's process is still altered, and a
  disclosure that only fires when we also got a finding out of it is a
  disclosure that serves us.
* It renders **only when populated**. A section reporting "nothing was left
  behind" on every clean run is a section an operator learns to skip — which is
  the state they must not be in on the run where it is populated. Same reasoning
  as the ledger's benign-alarm rule.

---

## The oracle

### Nothing reads the response to the polluting request

`EffectObservation` carries a **status and headers and no body field**, and that
is structural rather than stylistic. The body answers in the *wrong direction*:

| endpoint shape | pollutable? | echoes the injected key back? |
|---|---|---|
| recursive merge, unguarded | **yes** | no — the key landed on the prototype, and `JSON.stringify` serialises own properties |
| recursive merge, guarded key list | no | no |
| shallow spread `{...stored, ...body}` | no | **yes** — spread *defines* rather than assigns, so `__proto__` becomes an ordinary own property and is serialised |

An oracle grading its own polluting response confirms on the sound spread merge
and misses the vulnerable one. `test_the_observation_type_has_no_body_field`
asserts the type; `test_every_endpoint_echoes_the_probe_value_in_the_polluting_response`
measures the reason on the recording rather than asserting it in prose.

There is a second, subtler reason the body is unusable, and it is visible in the
recording: the control arm has to carry the *same key and the same value* as the
payload or it is not shape-matched, so the control's own write puts the probe
value into the stored record — on every endpoint. The payload's response then
echoes it for a reason that has nothing to do with the prototype.

### Two gadgets, and only one attributes itself

A prototype write is invisible until something reads the key back. Both readers
are ordinary Node idioms:

| gadget | mechanism | attributable on its own? |
|---|---|---|
| `HEADER_NONCE` | `for (const k in bag)` walks the prototype chain, so the polluted key becomes a response header | **yes** — the engine mints both the header NAME and its VALUE |
| `STATUS_CODE` | `opts.status \|\| 200` reads a polluted `status`, so every later response carries it | **no** — the observation is a bare 510 |

**The header probe is attempted first on every endpoint, every time.** The status
probe runs only when the header probe found nothing, and a finding that rests on
it carries `ATTRIBUTION_NOTE` in its own evidence saying so in as many words.

**The class may never emit with `NO_ARM`.** It is registered in
`DIFFERENTIAL_CONTROL_CLASSES`, so `control_required` is true and emission ground
8 refuses a finding carrying no recorded arm. For the header gadget the arm is a
check on the oracle; for the status gadget the arm **is** the oracle — 510 is a
number any server may return for its own reasons, and the only thing separating
it from that is a shape-matched merge that could not reach the prototype and got
the ordinary status back.

Only one gadget's finding is emitted per endpoint. A second confirmed write would
put another key on a process this engine cannot clean up, to prove again what has
just been proven.

### The coverage boundary is in the artifact, not the commit message

`CoverageBoundary(why_unconfirmed="prototype_pollution_carrier_is_json_body_only")`,
rendered verbatim into *What was NOT tested* on every run:

> Server-side prototype pollution is probed through JSON request bodies only.
> Whether the same endpoint can be polluted through a form-encoded body or a
> query string depends on which body parser the application uses and how it is
> configured — Express's `qs` filters `__proto__` while letting `constructor`
> through, and `extended:false` parses with `querystring`, whose result already
> has a null prototype — and neither the parser nor its version is observable
> from outside the application. A form-encoded endpoint is therefore not cleared
> by this engine, only untested.

The reasoning is in the sentence a client reads because it is **version-dependent
and unobservable from outside**: it cannot be recovered later by reading the
report harder, and sending the probe anyway would put a write on a live process
to learn "this parser, this version, this flag", which is not a statement about
the endpoint. The class abstains and records the lead
(`_record_pollution_carrier_boundary`), so the sentence describes an abstain the
engine produces rather than one it merely promises.

`__proto__` is the one key probed. `constructor` and `prototype` reach the
prototype through some merge implementations, and each would be a second write to
a live process the engine cannot clean up.

---

## The fixture

`docker/protopoll/app.js` — Node, standard library only, no `package.json`, no
lockfile entry. **The pollution is real**, not modelled: `JSON.parse` returns
`__proto__` as an own enumerable property, `Object.keys` reports it, and reading
`target['__proto__']` goes through the getter, so the recursion walks into
`Object.prototype` and the leaf assignment lands on every object in the process.

Writing this fixture in Python — as every other target in this repo is — would
have made it a **model**: a dict standing in for `Object.prototype`, whose
distinguishing behaviour is whatever the fixture author decided. The one property
the oracle rests on is exactly the property a model gets to assert rather than
exhibit.

| route | merge | pollutable | why it is here |
|---|---|---|---|
| `POST /api/v2/profile` | recursive, unguarded | **yes** | the true positive |
| `POST /api/v2/notifications` | recursive, guarded key list | no | **the shape twin** — same method, content type, nesting, status and body shape; the guard is three lines inside the merge. A class that cannot separate this from `/profile` reports every deep-merge endpoint on the internet |
| `POST /api/v2/preferences` | shallow spread | no | **the reflection trap** — echoes the injected key straight back |
| `POST /internal/_reset` | — | — | harness only; 404 to anything the engine can send |

Both gadgets live in the single `sendJson` response helper every route calls,
which is how a real application has one.

### `_reset` is unreachable from the engine, on purpose

A reset endpoint the scanner can find is worse than no fixture at all: a run
could un-pollute itself between the payload and the observation, and the effect
arm would read a clean target and report the vulnerable endpoint as sound — a
**false negative manufactured by the test rig**. So it is bound by two conditions
the engine satisfies neither of:

1. the connection is from loopback (under `docker compose` the engine reaches
   the container over the bridge network and is never `127.0.0.1`); **and**
2. the request carries `X-Fixture-Control: $PROTOPOLL_RESET_TOKEN`, a header no
   code path in `clinkz` sends.

Absent either — and absent the environment variable entirely, which is how the
container image ships — the route is 404 on every method, so discovering the path
tells a crawler nothing.

### Running it

```bash
# container (the engine's target)
docker compose -f docker/docker-compose.yml up -d protopoll     # :8095
docker compose -f docker/docker-compose.yml restart protopoll   # the "process restart"

# the tests (self-skip without node on PATH)
pytest tests/test_agents/test_prototype_pollution_oracle.py -q   # recorded observations
pytest tests/test_agents/test_prototype_pollution_live.py -q     # the live class
python scripts/record_protopoll_fixtures.py                      # re-record after an app.js change
```

---

## Acceptance criterion

Read the arms, not the count — the same form as the IDOR criterion. A confirmed
prototype pollution is accepted only when the run's own records show, for that
endpoint:

1. the control arm was **dispatched** and **refused**, and it was dispatched
   **before** the payload;
2. the effect was witnessed on a request made **after** the merge, and not in the
   merge's own response;
3. the finding carries the arm it was licensed by (`never_sent_control=refused`
   read out of its own structured evidence), so a key mismatch between dispatch
   and emit suppresses it rather than passing silently;
4. where the header gadget confirmed, the observation cites a token minted for
   that attempt; where only the status gadget did, the evidence says so; and
5. a `ResidualMutation` was recorded naming the key.

And the sound endpoints produce **nothing** — no finding and no mutation record,
because nothing was mutated.
