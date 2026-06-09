// Synthetic excerpt mirroring OWASP Juice Shop's Angular production bundle.
// Route literals appear exactly as the minified HttpClient calls reference
// them: plain string concatenation AND ${}-interpolated template literals — the
// two shapes katana's -jc link extractor under-reports. Used by
// tests/test_agents/test_route_discovery.py to assert the static bundle
// discoverer recovers /api and /rest routes with their param structure.
(() => {
  class ProductService {
    constructor(t) { this.http = t; this.hostServer = environment.hostServer; }
    search(t) { return this.http.get(this.hostServer + "/rest/products/search?q=" + t); }
    get(t) { return this.http.get(`${this.hostServer}/api/Products/${t}`); }
  }
  class BasketService {
    find(t) { return this.http.get(`${this.host}/rest/basket/` + t); }
    addItem(t) { return this.http.post(this.host + "/api/BasketItems/", t); }
  }
  class FeedbackService {
    save(t) { return this.http.post(this.hostServer + "/api/Feedbacks", t); }
    find() { return this.http.get(this.hostServer + "/api/Feedbacks"); }
  }
  class UserService {
    whoAmI() { return this.http.get("rest/user/whoami"); }
    get(t) { return this.http.get("api/Users/" + t); }
  }
  const ROUTES = [
    { path: "search", component: S },
    { path: "redirect", component: R },
    { path: "score-board", component: B },
  ];
  function go(u) { window.location.replace("/redirect?to=" + encodeURIComponent(u)); }
  // Decoys that MUST NOT be matched as routes:
  var label = "restaurant", msg = "redirection in progress", note = "interesting api note";
})();
