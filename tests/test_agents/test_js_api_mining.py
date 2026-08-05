"""Unit tests for the JS API call-site miner (keyless — pure text analysis).

The miner is what replaced a hardcoded list of one benchmark application's
endpoints, so these tests are written against *idioms* — Angular HttpClient,
axios, fetch, XHR, browser navigation — never against a particular app's routes.
The two shapes that carry the most risk get the most attention:

* **body-field scoping** — a minified bundle reuses one-letter parameter names
  across every method of a class, so a body shape read from too wide a window
  is a fabrication that would be injected into a real endpoint; and
* **URL resolution** — the URL is assembled from class fields, so a miner that
  cannot resolve them reports no routes at all.
"""

from __future__ import annotations

from clinkz.agents._js_api_mining import (
    ApiCallSite,
    mine_api_call_sites,
    object_literal_fields,
)


def _by_route(sites: list[ApiCallSite]) -> dict[tuple[str, str], ApiCallSite]:
    return {(s.method, s.url_template): s for s in sites}


# ---------------------------------------------------------------------------
# The invocation idioms
# ---------------------------------------------------------------------------


def test_fetch_with_options_object_yields_method_and_body() -> None:
    js = """
    function send(t) {
      return fetch('/api/orders', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({sku: t.sku, qty: 2, ship: {city: 'x'}})
      });
    }
    """
    site = _by_route(mine_api_call_sites(js))[("POST", "/api/orders")]
    assert site.content_type == "application/json"
    assert set(site.body_fields) == {"sku", "qty", "ship", "ship.city"}


def test_axios_shorthand_and_config_object() -> None:
    shorthand = mine_api_call_sites("axios.post('/v1/items', {name: 'a', price: 1})")
    assert _by_route(shorthand)[("POST", "/v1/items")].body_fields == ("name", "price")

    config = mine_api_call_sites("axios({url: '/v1/items', method: 'PUT', data: {name: 'a'}})")
    assert ("PUT", "/v1/items") in _by_route(config)


def test_xhr_open_names_its_own_method() -> None:
    js = "var x=new XMLHttpRequest(); x.open('DELETE', '/api/session'); x.send();"
    assert ("DELETE", "/api/session") in _by_route(mine_api_call_sites(js))


def test_navigation_is_a_server_surface_too() -> None:
    """A URL the app sends the BROWSER to is surface, and is never an XHR.

    This is the general replacement for the literal route words that used to be
    hardcoded in route discovery: the idiom is recognised, so the route is found
    on any application without knowing that application's vocabulary.
    """
    js = """
      function go(u){ window.location.replace('/gateway?next=' + encodeURIComponent(u)); }
      function out(u){ location.href = '/leave?dest=' + u; }
    """
    routes = _by_route(mine_api_call_sites(js))
    assert routes[("GET", "/gateway")].query_params == ("next",)
    assert routes[("GET", "/leave")].query_params == ("dest",)


def test_non_http_dot_get_is_not_a_call_site() -> None:
    """``map.get(k)`` resolves to nothing URL-shaped, so it is not a route.

    The filter is a property of what resolution produced — never an allowlist
    of route names, which is what makes it work on an unseen application.
    """
    js = "var m=new Map(); m.get(key); cache.get('user'); params.get('id');"
    assert mine_api_call_sites(js) == []


# ---------------------------------------------------------------------------
# URL resolution through class fields (the minified-bundle case)
# ---------------------------------------------------------------------------


def test_url_resolves_through_a_class_field_binding() -> None:
    """The Angular shape: ``host`` is a field built from a host variable."""
    js = """
      let S=(()=>{class n{
        http=inject(k);
        hostServer=env.hostServer;
        host=this.hostServer+"/api/Widgets";
        find(e){return this.http.get(this.host+"/",{params:e})}
        get(e){return this.http.get(`${this.host}/${e}`)}
      }})();
    """
    routes = _by_route(mine_api_call_sites(js))
    assert ("GET", "/api/Widgets") in routes
    assert any(m == "GET" and t.startswith("/api/Widgets/:") for m, t in routes)


def test_template_literal_query_and_path_holes() -> None:
    js = "this.http.get(`${h}/search/${cat}?q=${term}&page=1`)"
    site = mine_api_call_sites(js)[0]
    assert site.url_template.startswith("/search/:")
    assert site.query_params == ("q", "page")


def test_concatenated_query_parameters_are_recovered() -> None:
    js = 'this.http.get(this.h+"/account/settings?current="+e.current+"&next="+e.next)'
    site = _by_route(mine_api_call_sites(js))[("GET", "/account/settings")]
    assert site.query_params == ("current", "next")


# ---------------------------------------------------------------------------
# Body-field scoping — the fabrication risk
# ---------------------------------------------------------------------------


def test_body_shape_does_not_leak_from_a_sibling_method() -> None:
    """A shape read past the enclosing function is a fabricated body.

    Both methods take a one-letter parameter, as every minifier emits. Reading
    a fixed window around the call site gave ``signIn`` the fields of
    ``changeSecret`` — fields that endpoint has never accepted, which a probe
    would then have posted to it.
    """
    js = """
      class A{
        signIn(e){return this.http.post(this.h+"/auth/session",e)}
        changeSecret(e){return this.http.post(this.h+"/auth/secret",
          {current:e.current,next:e.next,repeat:e.repeat})}
      }
    """
    routes = _by_route(mine_api_call_sites(js))
    assert routes[("POST", "/auth/session")].body_fields == ()
    assert set(routes[("POST", "/auth/secret")].body_fields) == {"current", "next", "repeat"}


def test_response_handler_fields_are_not_request_fields() -> None:
    """``.pipe(t => t.data)`` reads the RESPONSE, and minifiers reuse the name."""
    js = "class A{save(o){return this.http.put(this.h+'/api/thing', o).pipe(map(o=>o.data))}}"
    site = _by_route(mine_api_call_sites(js))[("PUT", "/api/thing")]
    assert "data" not in site.body_fields


def test_unknown_body_stays_unknown() -> None:
    """A body the source never names is reported as unknown, not guessed."""
    js = "class A{save(e){return this.http.post(this.h+'/api/thing', e)}}"
    assert _by_route(mine_api_call_sites(js))[("POST", "/api/thing")].body_fields == ()


def test_formdata_multipart_fields_are_read_from_append_calls() -> None:
    js = """
      function up(f){ var d = new FormData();
        d.append('avatar', f); d.append('caption', 'x');
        return this.http.post('/api/media', d); }
    """
    site = _by_route(mine_api_call_sites(js))[("POST", "/api/media")]
    assert set(site.body_fields) == {"avatar", "caption"}
    assert site.content_type == "multipart/form-data"


def test_nested_object_literal_fields_are_dotted_paths() -> None:
    assert object_literal_fields("{a:1,b:{c:2,d:{e:3}}}") == ["a", "b", "b.c", "b.d", "b.d.e"]
    assert object_literal_fields("notAnObject") == []


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


def test_hostile_input_does_not_hang_or_raise() -> None:
    """Bundles are attacker-controllable; every scan is bounded."""
    for source in (
        "fetch(" * 5000,
        "this.http.post('/a'" + ",{x:1}" * 2000,
        "`" + "${a}" * 5000,
        '"' * 20000,
        "{" * 5000,
    ):
        assert isinstance(mine_api_call_sites(source), list)


def test_results_are_order_stable_and_deduped() -> None:
    js = "fetch('/api/x');fetch('/api/x');fetch('/api/y');"
    first = mine_api_call_sites(js)
    assert [s.url_template for s in first] == ["/api/x", "/api/y"]
    assert first == mine_api_call_sites(js)
