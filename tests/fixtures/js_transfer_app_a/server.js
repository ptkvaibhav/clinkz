// App A — FULL source (JS→JS transfer fixture, A2a). Discovery-ingestor fixture ONLY.
// The route registers a handler FACTORY imported from the bundled local package
// vuln-fetch-lib; the vulnerable server-side fetch lives in that package's own code, so
// the surfaced EGRESS_FETCH capability is LIBRARY-BORNE (keyed on vuln-fetch-lib@version,
// not on this app).
import express from 'express';
import { makeProxyHandler } from 'vuln-fetch-lib';

const app = express();

// SSRF: the sink is in vuln-fetch-lib/index.js (a bundled local dependency).
app.get('/proxy', makeProxyHandler());

app.listen(3000);
