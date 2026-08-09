# P7 live validation — DVWA, all four security levels

Driver: `scripts/live_p7_client_execution_validation.py`. Real containers, a real
Chromium, and the shipped methodology/emission code — no harness and no mocks.
Run with `CLIENT_ORACLE_MODE=playwright` and `TOOL_EXEC_MODE=local`.

> **This validated the primitive, not the product.** The driver runs the browser
> in-process against `http://localhost:8080`, which is a set of conditions it
> assembles for itself. A real engagement runs in docker tool-mode, where the
> target has been rewritten to a container-network alias a host browser cannot
> reach — so at the time of this run, every result below was reproducible only
> through the driver, and `clinkz scan` confirmed none of it. The pipeline
> wiring that closed that gap, and its own end-to-end validation through
> `clinkz scan`, are in
> [`p7-pipeline-validation.md`](p7-pipeline-validation.md). Keep both: this file
> is the evidence about the *oracle*, that one about the *engagement*.

## Pre-flight

- `clinkz-dvwa` up on `localhost:8080`, authenticated as `admin`.
- P7 oracle installed (Playwright + Chromium); the driver **exits non-zero** if
  it is not, rather than substituting inference.
- Anthropic key present for section D (the emission path takes an LLM synthesis
  checkpoint).

## A. DOM XSS (`xss_d`)

| level | executed | shape that won |
|---|---|---|
| low | **yes** | fragment / inline_script |
| medium | **yes** | fragment / inline_script |
| high | **yes** | fragment / inline_script |
| impossible | **no** | 4 shapes tried, none executed |

This is the result the primitive exists to produce. The inline sink is
*byte-identical* at low, medium and high:

```js
if (document.location.href.indexOf("default=") >= 0) {
  var lang = document.location.href.substring(document.location.href.indexOf("default=")+8);
  document.write("<option value='" + lang + "'>" + decodeURI(lang) + "</option>");
```

which is exactly why the old static source→sink scan confirmed **identically at
all four levels** — the textbook
[uniform-confirm-across-a-graded-control](methodology/dvwa-per-level-honesty.md)
phantom. At `impossible` DVWA drops the `decodeURI` call, the percent-encoded
payload stays inert, and P7 is silent. The oracle discriminates because it
measures the effect rather than the shape.

The server-side whitelist at medium/high 302-redirects a `<script>`-bearing
QUERY, which is why the fragment channel is the one that wins there: a fragment
is never transmitted to the server, so no server-side filter can see it — and no
server-side observation could ever have witnessed the result.

**Nothing confirmed at `impossible` in either module.** The honesty control holds.

## B. CSP bypass (`csp`)

| level | served policy | route chosen | executed |
|---|---|---|---|
| low | `script-src 'self' https://pastebin.com … digi.ninja` | none | no |
| medium | `script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIg…'` | `nonced_inline_script` | **yes** |
| high | `script-src 'self'` | `same_origin_script_gadget` | **yes** |
| impossible | `script-src 'self'` | none | no |

Two things are worth reading carefully.

**Medium** is the static-nonce finding end to end. The nonce came back
byte-identical on two independent fetches, so it is a published constant rather
than a per-response secret; the injected script carrying it executed **under that
very policy**, with `bypass_csp_disabled=True` recorded. The bare inline script
was refused on the same page, which is the live confirmation that a nonce makes
`'unsafe-inline'` inert.

**High** is the script-gadget route. `high.js` builds
`source/jsonp.php?callback=solveSum` at runtime; the gadget probe mined that URL
literal out of the origin's own script, confirmed the endpoint wraps its response
around the callback (`clinkzgadget…({"answer":"15"})`), and the witness executed
under `script-src 'self'`. The policy is not circumvented — it genuinely permits
the include.

### What "no route" at low and impossible does and does not mean

It is a statement about **this engine's coverage**, and the report says so in the
finding's own `unreachable_note`. It is not a clean bill of health, and the
measured truth is that both levels ARE bypassable:

A nonce-carrying probe run by hand confirmed execution at **all four** levels via
`source/jsonp.php` — at low through the bare-URL landing (`<script src='<INPUT>'>`)
and at medium/high/impossible through the raw-reflection landing. Clinkz does not
reach low or impossible today because the gadget is discovered from *the page's
own scripts*, and neither of those pages references `jsonp.php`. The gadget cache
is keyed per origin, so a full engagement that touches the high page first would
carry it; a run that never does will not.

That gap is named here rather than left implicit, because "no synthesizable
route" and "not vulnerable" are different claims and only the first one is being
made.

## C. Inert-reflection control

`xss_r` at `impossible`, where the payload is escaped on the way out:

```
executed=False  refusal=not_executed
nonce OUT  : vvwfnbdmauckwbrevbycidcscy
  payload  : <script>window.__clinkz_w_7d2cb800ed9f78de('vvwfnbdmauckwbrevbycidcscy')</script>
nonce BACK : None
CONTROL    : 7ezhzinut5f7k7jnjzvku5wkqu   silent=True
```

The payload was delivered and rendered; nothing ran it. This is the confounder
the primitive is built to exclude.

## D. Real engagement — the shipped emission path

Engagement `908b7130-111a-42b5-a187-241d158ab2de`, two security levels in ONE
report so the graded control is visible in the deliverable itself:

| level | findings | unproven leads |
|---|---|---|
| low | 1 (`DOM-based XSS — script execution witnessed in a browser`, high/confirmed) | 0 |
| impossible | 0 | 1 |

The finding's own evidence, verbatim from `report_*.json`:

```
Request: GET …/vulnerabilities/xss_d/?default=English#<script>window.__clinkz_w_1a81…('iahreq37gt7jrvfj37zepfzn7q')</script>
confirmation=P7 target=… status=200
outbound_probe: inline_script payload injected: <script>window.__clinkz_w_1a81…('iahreq37…')</script>
witness_nonce='iahreq37gt7jrvfj37zepfzn7q' (returned by CALLING a Clinkz-owned in-page
  function, a channel only executing script can reach; control_bore_it=False)
control [a second nonce minted in the same call and injected NOWHERE (7gfonwp3mx6v4r3xf6zsbsblhe)] status=0
control_excerpt: no call bearing the control nonce was received
primitive=P7 executed=True nonce_injected='iahreq37…' nonce_returned='iahreq37…'
  control_nonce='7gfonwp3…' control_silent=True bypass_csp_disabled=True
reachability=Static analysis of an inline <script> block: DOM source
  document.location.href flows to sink document.write(
```

and the `impossible` lead:

```
claim  : Candidate DOM-based XSS via URL fragment / location source
why    : execution_not_witnessed_requires_client_side_oracle
missing: The payload was delivered and the page was rendered in a real browser with
         Content-Security-Policy enforcement left ON, and the witness nonce never
         came back: nothing executed it. The reachability evidence above stands;
         the exploitation claim is not made.
```

## The bug this run caught that the unit suite did not

The first live run confirmed at **no** `xss_d` level, including one a hand-run
spike had already proven exploitable. The probe was percent-encoding its entire
payload, and the sink used `decodeURI`, which does not decode the reserved set
(`; / ? : @ & = + $ , #`). `%2F` stayed `%2F`, `</script>` never reformed, and the
class would have reported "not exploitable" about a page that executes at three
levels.

The fixture meant to cover this used `decodeURIComponent`, which decodes
everything and hid the entire class of bug. `_url_place` now encodes only what
would break the URL; the fixture site gained `decodeURI` routes for both the
fragment and query channels. A green unit suite over the wrong fixture is not
evidence — which is the false-green precedent, in miniature.

## Known limitation: docker tool-exec mode

The oracle runs in-process. With `TOOL_EXEC_MODE=docker` the tools container
reaches DVWA on the compose bridge network (`172.20.0.x`), which is **not**
routable from the host, so a host-side browser cannot reach the target the rest
of the pipeline is scanning. `docker/Dockerfile.tools` now carries Playwright +
Chromium so the oracle can run container-side, but wiring the oracle to execute
there (as the HTTP client already does via `curl`) is not built. Until it is, P7
should be run with `TOOL_EXEC_MODE=local` against a host-reachable target.
