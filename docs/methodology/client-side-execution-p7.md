# P7 — the client-side execution oracle

`src/clinkz/browser/` + `_p7_*` on the Exploit Agent. The seventh confirmation
primitive: a client-side capability is confirmed when a Clinkz-minted, single-use
nonce is returned **by a call from inside the page's JavaScript context** to a
Clinkz-owned in-page channel, while a second nonce minted alongside it and
injected nowhere stays silent.

It is an **ORACLE, not a new vulnerability class.** No class was added, renamed
or re-scoped. Three classes that could previously only record an
`UnprovenExploitLead` gained a confirmation path, and nothing else about them
changed.

## The gap it closes

| class | what was witnessed before | why that was not exploitation |
|---|---|---|
| DOM XSS (`_test_xss_dom`) | a DOM source flowing to a dangerous sink, found statically | the sink runs in the client; no server response can show it firing |
| Reflected/stored XSS landing in a client-rendered context | the payload present in a bundle or an SPA shell | presence is not execution |
| CSP | the policy text | "is this policy bypassable" is a question about a *browser* |

Each recorded `why_unconfirmed="execution_not_witnessed_requires_client_side_oracle"`.
P7 is that oracle, and it can **only promote**: a lead becomes a finding when
execution is witnessed, and there is no path by which a P7 verdict lowers,
suppresses or annotates anything. An oracle that is absent, out of budget or
broken leaves the lead exactly as it was. **A missing browser costs coverage,
never honesty.**

## Why the channel is a function call, not a network callback

P6's channel is an out-of-band callback because a blind *server-side* capability
has no in-band channel. Reusing that shape here would have been a mistake, and
the reason is the CSP class: `connect-src` and `img-src` are governed
independently of `script-src`, so under a policy that permits script but forbids
egress, a script that genuinely executed would produce no callback. The oracle
would report "did not execute" about a page that did — the exact wrong answer for
the one class that most needs a browser.

**No CSP directive governs calling a function.** What a call still requires is
JavaScript actually running, which is the entire question. So the channel
measures execution and nothing else.

Playwright's `BrowserContext.expose_binding` installs a Python-backed function in
the page's main world *before any page script runs*. That is the channel.
Playwright was chosen for it: the codebase is asyncio throughout and Playwright
ships a first-class async Python API, `playwright install --with-deps chromium`
provisions a browser that launches inside the existing Kali tools image, and no
other driver offers an equivalent in-page callback (Selenium needs a separate
grid and has no equivalent; a raw CDP client means hand-rolling the same thing).
The tool is nonetheless resolved by **capability** (`client_side_execution`,
`TOOL_CHAINS` ranked) so nothing in the engine names it.

## Unforgeability, stated exactly

A confirmation requires **all** of:

1. the Clinkz-owned binding was called with a value **equal** to the nonce this
   run injected — equality against a minted secret, never a search for a pattern
   inside target bytes;
2. the **never-injected control nonce** never arrived;
3. the browser was not asked to bypass CSP (`bypass_csp=False`, recorded on the
   verdict), so whatever ran, ran under the policy actually served.

Inert reflected bytes cannot call a function. Neither can escaped text, a text
node, or a payload sitting in an attribute the parser never executes. That is the
confounder this primitive structurally excludes — and it is exactly the one that
made every previous DOM-XSS "confirmation" a phantom
([xss.md](xss.md) gap G2).

**A live control invalidates the run, including a positive.** If the channel can
report a nonce that was never sent, it can report one that was.

**The residual, stated rather than glossed:** a page whose own trusted script
enumerated `window`, found the randomised binding, read the nonce out of its own
DOM and called it, could manufacture a signal. That requires the target to run
code written against this oracle. P6 has no comparable residual — nothing on the
target ever sees the collaborator's channel — and this is the price of an
in-browser one. The binding name is minted per page load rather than fixed to
keep it a hardening measure rather than a published constant.

## The page is hostile input

The verdict is computed in `WitnessVerdict.decide()` from three booleans the
Python side owns. Every target-authored artefact on the verdict —
`policy_in_force`, `console_violations`, `final_url` — is EVIDENCE, recorded
verbatim for a reviewer, and is **never read back to decide anything**.

A console line saying "Refused to execute inline script" is useful to show an
operator and catastrophic to believe: a page that wants to look protected can
print it, and one that wants to look vulnerable can withhold it. This is the
`_evidence_strength` rule (a guard never parses text the target controls) applied
to a surface that multiplies it enormously.

## Where the browser runs — and why that decided whether P7 existed at all

An oracle has to observe from a machine that can **reach** the target, and in
this engine that is not the machine Clinkz runs on.

`TOOL_EXEC_MODE=docker` is the default and the only mode with a port scanner. In
it, every tool executes inside `clinkz-tools`, and
`resolve_target_for_docker_mode` rewrites the operator's `http://localhost:8080`
into `http://clinkz-dvwa:80` — a network alias that resolves on the shared bridge
and nowhere else. A browser on the host can neither resolve that name nor route
to `172.20.0.0/24`, so a host-side oracle in a real engagement does not return a
wrong verdict; it fails **every** navigation. Local mode, where a host browser
would work, has no `nmap` or `ffuf` on a developer machine. Neither mode could
deliver P7 — which is why, when P7 was first built, it was reachable only from a
driver that hand-assembled its own conditions, and `clinkz scan` never confirmed
a DOM-XSS.

So the browser runs where the tools run:

- `browser/_container_runner.py` holds the browser-driving half and imports
  **nothing** from Clinkz — the tools image has Playwright and the standard
  library, and no Clinkz install. It is delivered to the container's bare
  `python3` with its source on stdin and its job base64-encoded in `argv`.
- Both runtimes call the same functions: in-process for local mode, `docker exec`
  for docker mode. There is one implementation of the rails, so what a driver
  exercises is what a real engagement runs under.
- The runtime is **tied to `TOOL_EXEC_MODE`, never configured separately**. The
  target address is a consequence of that setting, so an independent switch would
  permit exactly one combination that silently fails every navigation.
- Availability is answered **about the machine the browser would run on**
  (`runtime_available`). The previous check asked the host unconditionally and so
  answered wrongly in both directions.

The Dockerfile layer is self-verifying: Kali is not a distribution Playwright
carries a dependency list for, so `playwright install --with-deps chromium` can
exit 0 having installed a browser that never launches. The layer launches it at
build time and fails the build otherwise — an image that ships a dead Chromium
would surface as "oracle unavailable" mid-engagement, which is a coverage loss
discovered at the worst possible moment.

## Who gets a browser (`CLIENT_ORACLE_MODE`)

Three states, because two requirements pull in opposite directions. A real
engagement should confirm these classes whenever a browser is available — an
oracle only a driver can reach is not a capability the product has. A **directly
invoked** agent must never launch one, or the engine behaves differently on a
developer machine with Playwright than on CI without it (LESSONS #35), and the
unit suites go from 1.8 s to 21 s.

The switch is therefore on *who is asking*, not on what is installed:

| mode | engagement | direct invocation (unit suite, replay, smoke cell) |
|---|---|---|
| `auto` (default) | Orchestrator provisions it | never self-resolves |
| `playwright` | provisioned | self-resolves — what a live driver opts into |
| `disabled` | never | never |

## Safety — a browser is a new destructive surface

Every P1 rail applies, and the browser gets its own. The rails that must be
evaluated *inside* the routing callback travel there as data, because that
callback may be running where Clinkz cannot be imported.

- **Scope before navigation.** `_check_scope` runs before the browser launches.
  Subresources are checked again inside the browser against an explicit host
  allowlist projected from the scope — one-directional, so it is *stricter* than
  `EngagementScope.contains` against a CIDR or wildcard, which is the correct
  direction for a guard whose failure mode is a hostile page steering our
  browser off-engagement. Refusals are recorded (`blocked_subresources`).
- **The governor decides.** Navigation goes through `authorize()` like any probe:
  rate, concurrency, kill switch, window, destructive classifier. A refusal
  acquires nothing and releases nothing.
- **Every navigation is in the action log** — a GET as well as a POST. This is a
  deliberate exception to "only mutations are logged": what is being recorded is
  not the request but that a real engine was pointed at the target and ran its
  code, and `clinkz actions` answers "what did it do to my app" wrongly if that
  is absent. Navigations are tallied apart from `state_changing_sent`, so neither
  number has to be read with a qualifier.
- **`is_state_changing_url` refuses outright** — a browser that renders a logout
  link also runs its scripts.
- **Nothing is clicked or submitted.** The oracle never calls `click`, `fill`,
  `press` or `submit`; dialogs are dismissed, never accepted; downloads are off.
- **One navigation.** Any page-initiated navigation after the first is aborted
  and recorded (`blocked_navigations`) — without that record, a blocked
  navigation leaves Chromium on an internal error page and the run reads as a
  failed load rather than as a rail working.
- **Only the authorized request may mutate.** Blocking navigations is not
  enough: `fetch('/user/5', {method:'DELETE'})` reaches the target as a
  subresource request, not a navigation. Every page-initiated request is held to
  `GET`/`HEAD`/`OPTIONS`; the one navigation Clinkz itself authorized — which the
  governor classified and the action log recorded before the browser started — is
  the only exemption. Refusals are recorded (`blocked_mutations`).
- **A safe method is not automatically safe.** `<img src="/logout">` is a GET
  that destroys the engagement's session. Subresource paths are matched against
  `safety/destructive.py::subresource_guard_spec()` — the same module that owns
  the vocabulary everywhere else, projected to serializable tokens rather than
  copied. The projection is coarser and stricter than `classify_request` on
  purpose: it judges a request the *page* chose, where over-refusing costs an
  asset load and under-refusing costs the session. Matching is on **tokens, not
  substrings**, so `undeleted.css` is not `delete`.
- **CSP is never bypassed**, and the verdict records that it was not.

## The carrier (`browser/templates.py`)

Same structural discipline as `oob/templates.py`: a methodology **selects** a
`ClientWitnessTemplateId` and a `MarkupBreakout`; it never authors the payload.
The executable surface of every template is one expression,
`window.<binding>('<nonce>')` — it reads nothing, writes nothing, opens no
connection.

Two target-derived values are admitted, deliberately, each shape-validated so it
cannot break its own syntactic slot. This is where P7 diverges from P6 **on
purpose**: P6's channel leaves the machine, so anything interpolated there could
be exfiltrated; P7's is a call inside a browser Clinkz owns and throws away.

- `csp_nonce` — a nonce the target published in its own policy.
- `gadget_path` / `gadget_param` — a **same-origin** endpoint. Validated as a
  rooted path with no scheme and no authority; the protocol-relative case
  (`//evil.tld/x`) is rejected by name, because it matches every other rule and
  is the one shape that turns a same-origin include into an off-origin one.

## CSP: "did script execute UNDER THE SERVED POLICY"

`browser/csp_policy.py` chooses what to ATTEMPT; the oracle decides whether it
worked, so a policy misread costs a MISS and never a phantom. Two branches are
**measured, not recited**:

- **A nonce or hash makes `'unsafe-inline'` inert.** Verified live against a
  policy carrying both: the bare inline script was refused, the nonced one
  executed. A parser that read `'unsafe-inline'` as "inline is allowed" would
  pick a shape the browser always blocks and report "not bypassable" about a
  policy that is.
- **A reused nonce is not a control.** Staticness is established by
  OBSERVATION — two independent fetches, byte-identical — never assumed from the
  policy text. One sample cannot distinguish a per-response nonce from a
  published constant.

The third route is the **same-origin script gadget**: under `script-src 'self'`,
an endpoint that reflects a request parameter into its own JavaScript response
(the JSONP-callback shape) is a script include the policy *fully permits*. The
browser is not tricked. Candidates come from the origin's own surface — the
`<script src>` elements the page declares **and URL literals inside those
scripts**, because a JSONP endpoint is almost never a static tag; it is a URL a
script builds at runtime. The gadget is cached per **origin**, not per page,
since that is what it is a property of.

A route of `None` renders an explicit `unreachable_note` so "no route" reads as a
**coverage limit of this engine**, never as a clean bill of health for the policy.

## Live validation

Two validations, and they answer different questions. Keep both.

1. **The oracle** — `scripts/live_p7_client_execution_validation.py` against the
   running DVWA at every security level. Full results in
   [docs/p7-client-execution-validation.md](../p7-client-execution-validation.md).
   This proves the primitive discriminates, under conditions the driver
   assembles for itself (in-process browser, `localhost:8080`).
2. **The engagement** — four full `clinkz scan` runs, one per security level,
   with no driver and nothing arranged by the operator. Full results in
   [docs/p7-pipeline-validation.md](../p7-pipeline-validation.md). This is what
   proves the capability is reachable from the product rather than from a
   script, and it is the validation that was missing when the table below was
   first produced.

| module | low | medium | high | impossible |
|---|---|---|---|---|
| `xss_d` (DOM XSS) | **confirmed** | **confirmed** | **confirmed** | **silent** |
| `csp` † | no route | **confirmed** (static nonce) | **confirmed** (script gadget) | no route |

> † **The `csp` row is a DRIVER result and is not reachable from `clinkz scan`.**
> There is no CSP methodology: the Exploit agent's dispatch table and
> `models/vuln_classes.py` both hold nineteen classes and none of them is CSP.
> The driver produces this row by calling `_p7_csp_route` and `_p7_witness`
> directly — internals, not a class the planner can schedule — so no engagement
> report can contain a CSP finding at any security level, however the oracle is
> wired. What P7 supplies is the *oracle* a CSP class would confirm through;
> the class itself is unbuilt, and the honest reading of this row is "the
> primitive works, the capability is missing". Building it means a twentieth
> `_test_csp` with a registry entry, ranking signals, remediation copy and its
> own per-level honesty validation.

The `xss_d` row is the point. The inline sink is *byte-identical* at low, medium
and high — which is why the old static scan confirmed identically at all four
levels and was a textbook
[uniform-confirm-across-a-graded-control](dvwa-per-level-honesty.md) phantom.
P7 discriminates because it measures the effect rather than the shape: at
`impossible` DVWA drops the `decodeURI` call, the payload stays percent-encoded,
and nothing runs. **Nothing confirmed at `impossible` in either module.**

### The encoding bug the live run caught, and the unit suite did not

The first live run confirmed at **no** `xss_d` level, including one the spike had
proven exploitable. The probe was percent-encoding its whole payload, and the
sink used `decodeURI` — which by definition does **not** decode the reserved set
(`; / ? : @ & = + $ , #`). So `%2F` stayed `%2F`, `</script>` never reformed, and
the class would have reported "not exploitable" about a page that executes at
three levels. The fixture that was supposed to catch it used
`decodeURIComponent`, which decodes everything and hid the whole class of bug.

`_url_place` now encodes only what would break the URL and lets the browser
normalise the rest, and the fixture site grew `decodeURI` routes for both the
fragment and query channels. This is the false-green precedent in miniature: a
green unit suite over the wrong fixture is not evidence.
