// App B — PARTIAL source (JS→JS transfer fixture, A2a). Discovery-ingestor fixture ONLY.
// A DIFFERENT app that also bundles vuln-fetch-lib (declared below). This engagement the
// library's source is WITHHELD (only its package.json is present, so its version is
// observable) — the CoreAdminOperation.java analogue. The /proxy route reads the request
// channel inline and delegates the actual fetch to the withheld library, so NO egress
// sink is derived here. Cold ⇒ zero egress hypotheses; warm (with the vuln-fetch-lib fact
// recalled) ⇒ the capability is SEEDED on this `url` channel at HYPOTHESIZED reachability
// and the live proof confirms it.
import express from 'express';
import { runProxy } from 'vuln-fetch-lib';

const app = express();

app.get('/proxy', (req, res) => {
  const url = req.query.url;
  res.send(runProxy(url));
});

app.listen(3000);
