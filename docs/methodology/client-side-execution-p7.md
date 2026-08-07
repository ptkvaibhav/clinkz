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

## Safety — a browser is a new destructive surface

Every P1 rail applies, and the browser gets its own:

- **Scope before navigation.** `_check_scope` runs before the browser launches;
  every subresource is checked again at the interception seam, so a page cannot
  steer the browser at a host the engagement does not cover. Refused
  subresources are recorded (`blocked_subresources`).
- **The governor decides.** Navigation goes through `authorize()` like any probe:
  rate, concurrency, kill switch, window, destructive classifier. A POST
  navigation is recorded in the action log, so `clinkz actions` still answers
  "what did it do to my app". A refusal acquires nothing and releases nothing.
- **`is_state_changing_url` refuses outright** — a browser that renders a logout
  link also runs its scripts.
- **Nothing is clicked or submitted.** The oracle never calls `click`, `fill`,
  `press` or `submit`; dialogs are dismissed, never accepted; downloads are off.
- **One navigation.** Any page-initiated navigation after the first is aborted
  and recorded (`blocked_navigations`) — without that record, a blocked
  navigation leaves Chromium on an internal error page and the run reads as a
  failed load rather than as a rail working.
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

`scripts/live_p7_client_execution_validation.py`, against the running DVWA at
every security level. Full results in
[docs/p7-client-execution-validation.md](../p7-client-execution-validation.md).

| module | low | medium | high | impossible |
|---|---|---|---|---|
| `xss_d` (DOM XSS) | **confirmed** | **confirmed** | **confirmed** | **silent** |
| `csp` | no route | **confirmed** (static nonce) | **confirmed** (script gadget) | no route |

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
