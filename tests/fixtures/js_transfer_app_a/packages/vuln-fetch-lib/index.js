// vuln-fetch-lib — the bundled local package's OWN code. Discovery-ingestor fixture ONLY.
// The request-controlled `url` flows into a server-side fetch with no host allow-list —
// the EGRESS_FETCH sink shape. Because this sink lives in the LIBRARY (not the importing
// app), the discovery engine keys the capability on vuln-fetch-lib@version — the
// library-borne case that transfers to any other app bundling this package.
export function makeProxyHandler () {
  return async (req, res) => {
    const url = req.query.url;
    const response = await fetch(url);
    res.send(await response.text());
  };
}
