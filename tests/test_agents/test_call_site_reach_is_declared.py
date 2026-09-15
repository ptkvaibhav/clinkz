"""A call site the miner SAW and could not address is a declared state.

The miner's output has always been the calls it resolved. A call it recognised
as HTTP and could not turn into a route left no trace at all, so a bundle the
engine cannot read and an application that makes no HTTP calls produced
byte-identical output — the same failure as ``method = "GET"`` standing in for a
verb nobody read, one layer further upstream.

Measured live before any of this was written, against the local cal.com and
Juice Shop containers:

* Juice Shop resolves **88 of 89** HTTP call sites. The one it does not is
  socket.io's polling transport, ``this.request({method:"POST",data:a})``, whose
  address is ``this.uri()`` one frame up.
* cal.com resolves **2** and leaves **7**, one of which is the Next.js Server
  Action dispatcher ``fetch(e.canonicalUrl,{method:"POST",...})``.

These tests are written against those SHAPES — the idioms — never against either
application's routes.
"""

from __future__ import annotations

from clinkz.agents._js_api_mining import (
    ApiCallSite,
    CallSiteRejection,
    mine_api_call_sites,
    mine_api_surface,
)
from clinkz.models.scan import MethodEvidence


def _by_route(sites: tuple[ApiCallSite, ...]) -> dict[tuple[str, str], ApiCallSite]:
    return {(s.method, s.url_template): s for s in sites}


# ---------------------------------------------------------------------------
# The config-object call form
# ---------------------------------------------------------------------------


def test_config_object_at_argument_zero_yields_url_and_method() -> None:
    """``$.ajax(cfg)`` puts the whole request where every other idiom puts the URL.

    Reading argument 0 as a URL there is reading a request description as a
    route name: it resolves to nothing and the verb is never examined.
    """
    for source in (
        """$.ajax({url: '/api/items/42', method: 'PUT', data: {name: 'x'}})""",
        """client.request({url: '/api/items/42', method: 'PUT', data: {name: 'x'}})""",
        """axios({url: '/api/items/42', method: 'PUT', data: {name: 'x'}})""",
    ):
        sites = _by_route(mine_api_surface(source).call_sites)
        assert ("PUT", "/api/items/42") in sites, source
        assert sites[("PUT", "/api/items/42")].method_evidence is MethodEvidence.NAMED


def test_config_object_hoisted_into_a_local_still_resolves() -> None:
    """A bundler routinely lifts a shared config out of the call.

    The miner already resolves a hoisted URL and a hoisted verb; an object is
    the same fact one level out, and without it the call reads as having no
    config at all — which is to say, as a GET to an unknown URL.
    """
    js = """
    function save(payload) {
      const opts = {url: '/api/profile', method: 'PATCH', data: payload};
      return http.request(opts);
    }
    """
    assert ("PATCH", "/api/profile") in _by_route(mine_api_surface(js).call_sites)


def test_config_object_form_does_not_capture_a_positional_url_call() -> None:
    """``.post(url, body)`` must be untouched by the config path."""
    sites = _by_route(mine_api_surface("api.post('/v1/orders', {sku: 1})").call_sites)
    assert ("POST", "/v1/orders") in sites
    assert sites[("POST", "/v1/orders")].body_fields == ("sku",)


def test_an_application_payload_is_not_a_request_config() -> None:
    """``walletService.put({balance, paymentId})`` is a call to the app's OWN wrapper.

    Its real HTTP call site is one layer down and the miner already reads it.
    Claiming the wrapper would invent a URL for a request that has one, so a
    config object is recognised by ``url``/``method`` — never by ``data``, which
    is an ordinary application field name.
    """
    js = "this.walletService.put({balance: this.totalPrice, paymentId: this.paymentId})"
    result = mine_api_surface(js)
    assert result.call_sites == ()
    assert result.unresolvable == ()


# ---------------------------------------------------------------------------
# The unresolvable state
# ---------------------------------------------------------------------------


def test_minified_identifier_argument_is_declared_not_dropped() -> None:
    """``fetch(e,n)`` is evidence of surface we cannot reach, and it must say so."""
    result = mine_api_surface("function send(e, n) { return fetch(e, n); }")
    assert result.call_sites == ()
    assert len(result.unresolvable) == 1
    site = result.unresolvable[0]
    assert site.callee == "fetch"
    assert site.reason is CallSiteRejection.UNRESOLVABLE_URL
    assert site.expression == "e"


def test_a_config_naming_a_write_with_no_address_reports_the_verb() -> None:
    """The socket.io shape: the verb is right there, the address is one frame up.

    Knowing a write call site exists that we cannot address is worth more than a
    bare count, and it is a different fact from an address we tried to read and
    could not — so it gets its own reason.
    """
    js = 'doWrite(a, e) { let i = this.request({method: "POST", data: a}); }'
    result = mine_api_surface(js)
    assert len(result.unresolvable) == 1
    site = result.unresolvable[0]
    assert site.method_named == "POST"
    assert site.names_a_write is True
    assert site.reason is CallSiteRejection.UNNAMED_URL


def test_a_map_is_not_an_unreachable_endpoint() -> None:
    """``.get(k)``/``.set(k,v)`` on a Map is most of what these regexes match.

    Counting them would fire the disclosure on every run of every target, and a
    permanent alarm is one an operator learns to skim.
    """
    js = """
    const cache = new Map();
    cache.set(k, v); cache.get(k); cache.delete(k);
    store.get(id); registry.set(name, handler);
    """
    result = mine_api_surface(js)
    assert result.call_sites == ()
    assert result.unresolvable == ()


def test_a_method_named_fetch_is_not_a_call_to_the_platforms() -> None:
    """TanStack Query defines ``fetch(e,t){...}``, and cal.com ships TanStack Query.

    No call expression can be followed directly by ``{``, so what follows the
    parameter list decides it.
    """
    js = "class Query { fetch(e, t) { if (this.state.fetchStatus !== 'idle') return; } }"
    result = mine_api_surface(js)
    assert result.call_sites == ()
    assert result.unresolvable == ()


def test_prose_naming_fetch_is_not_a_call_site() -> None:
    """Next.js warns about "uncached external data (`fetch(...)`, etc...)".

    The argument the scanner reads there is the literal text ``...``, which
    denotes nothing. A disclosure inflated by an error message is one an
    operator stops believing.
    """
    js = (
        'throw Error(`Route "${e.route}" depends on uncached external data '
        "(\\`fetch(...)\\`, etc...) without allowing dynamic rendering.`)"
    )
    assert mine_api_surface(js).unresolvable == ()


# ---------------------------------------------------------------------------
# The regression this cost, pinned
# ---------------------------------------------------------------------------


def test_a_regex_character_class_does_not_hide_the_rest_of_the_bundle() -> None:
    """Skipping matches "inside a string literal" is unsound on minified JS.

    Measured, not reasoned about: a quote-counting pre-pass over Juice Shop's
    main bundle marked **60%** of it as literal — a regex character class such
    as ``/(['"])/`` opens a quote the scanner closes 39 KB later — and silently
    hid **30 of its 88** readable call sites. Telling a regex literal from
    division needs real parsing context, so the cheap version of that guard
    destroys far more than it protects.

    This pins the outcome rather than the implementation: a call site AFTER such
    a pattern must still be read.
    """
    js = (
        """const strong = /([!"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~])/.test(pw);\n"""
        """this.http.post('/api/feedback', {comment: c});"""
    )
    assert ("POST", "/api/feedback") in _by_route(mine_api_surface(js).call_sites)


def test_mine_api_call_sites_still_returns_the_resolved_half() -> None:
    """The old name is what every existing caller uses; it must keep its contract."""
    js = "fetch('/api/x', {method: 'POST', body: JSON.stringify({a: 1})})"
    sites = mine_api_call_sites(js)
    assert isinstance(sites, list)
    assert [(s.method, s.url_template) for s in sites] == [("POST", "/api/x")]


# ---------------------------------------------------------------------------
# Routes the source DECLARES, as opposed to calls it makes
# ---------------------------------------------------------------------------


def test_a_route_manifest_declares_a_path_and_its_verb() -> None:
    """``{path, method}`` is how route guards and gateway rules name a route.

    A minified SPA that builds every URL at runtime states its routes nowhere
    else. On the live cal.com target this recovers the ONLY same-origin write
    route named anywhere in the bundle — the fetch-shaped writes there address
    ``e.canonicalUrl``, chosen per navigation — so without it the whole write
    surface is invisible to the seven classes gated on the verb.
    """
    js = 'init({protect: [{path: "*/api/book/event", method: "POST"}]})'
    declared = mine_api_surface(js).route_declarations
    assert [(d.method, d.url_template) for d in declared] == [("POST", "/api/book/event")]
    assert declared[0].method_evidence is MethodEvidence.NAMED


def test_a_route_manifest_is_read_in_either_key_order() -> None:
    js = 'routes=[{method:"DELETE",path:"/api/keys/:id"},{path:"/api/health",method:"GET"}]'
    declared = mine_api_surface(js).route_declarations
    assert [(d.method, d.url_template) for d in declared] == [
        ("DELETE", "/api/keys/:id"),
        ("GET", "/api/health"),
    ]


def test_a_declaration_is_held_to_the_same_bar_as_a_call_site() -> None:
    """A non-URL path and a non-HTTP verb are both refused.

    The manifest is the application's own word that the route exists; it is not
    a licence to emit anything shaped vaguely like one.
    """
    js = '{path:"redis-cache-key",method:"POST"} {path:"/ok",method:"SUBSCRIBE"}'
    assert mine_api_surface(js).route_declarations == ()


def test_declarations_are_not_counted_as_call_sites() -> None:
    """A route the app HAS and a call the frontend MAKES are different facts.

    Folding them together would make the reach disclosure's denominator include
    things that are not calls, and its whole job is to say how many of the
    frontend's calls we could address.
    """
    js = 'register({path: "/api/x", method: "PUT"})'
    result = mine_api_surface(js)
    assert result.call_sites == ()
    assert result.unresolvable == ()
    assert len(result.route_declarations) == 1


def test_a_declared_write_route_has_no_invented_body() -> None:
    """A manifest names the route and says nothing about what it accepts."""
    js = '{path: "/api/book/event", method: "POST"}'
    declared = mine_api_surface(js).route_declarations[0]
    assert declared.body_fields == ()
    assert declared.content_type is None


# ---------------------------------------------------------------------------
# The target does not author the document that describes it
# ---------------------------------------------------------------------------


def test_target_source_cannot_inject_structure_into_the_report() -> None:
    """A call-site expression is a fragment of the TARGET's own JavaScript.

    It is rendered into the client-facing report inside a code span, so a
    fragment carrying a backtick and a newline closes that span and writes what
    follows as document structure — a bundle could inject a heading reading "No
    issues found" into its own pentest report. Invariant 55's shape with the
    direction reversed: a FABRICATION primitive rather than a suppression one.

    Observed red against the unflattened producer.
    """
    backtick = chr(96)
    newline = chr(10)
    # Carries every character the flattening exists for: a backtick and a
    # newline (Markdown structure) AND angle brackets (ReportLab's Paragraph
    # markup). A fixture missing one of them makes that assertion unfalsifiable,
    # which is coverage that can only pass.
    hostile = (
        f"function f(e){{ return fetch({backtick}x{newline}{newline}"
        f"## Fabricated section{newline}{newline}"
        f'<para><font color="red">No issues found.</font></para>{newline}'
        f"{backtick}, e) }}"
    )
    site = mine_api_surface(hostile).unresolvable[0]
    for field in (site.expression, site.evidence):
        assert newline not in field
        assert backtick not in field
        # Angle brackets go too, for ReportLab's Paragraph rather than for
        # Markdown: it interprets a mini-markup and raises on an unbalanced tag.
        # The PDF does not render this section yet, and flattening at the
        # producer is what means whoever adds it need not know that.
        assert "<" not in field
        assert ">" not in field
