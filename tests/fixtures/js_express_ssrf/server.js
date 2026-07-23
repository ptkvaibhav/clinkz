// Minimal vulnerable Express backend — a discovery-ingestor fixture ONLY.
// Two intentionally vulnerable routes exercising the JS sink shapes that reduce to
// the existing discovery primitives (EGRESS_FETCH / FILE_READ). Not a real service.
const express = require('express');
const axios = require('axios');
const fs = require('fs');

const app = express();
app.use(express.json());

// SSRF: the request-controlled `url` flows straight into a server-side fetch
// (axios.get) with no host allow-list — the EGRESS_FETCH sink shape.
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  try {
    const response = await axios.get(url);
    res.send(response.data);
  } catch (err) {
    res.status(502).send('fetch failed');
  }
});

// Arbitrary file read: the request-controlled `file` flows into fs.readFile with no
// basename-strip / normalize guard — the FILE_READ sink shape.
app.get('/download', (req, res) => {
  const file = req.query.file;
  fs.readFile(file, 'utf8', (err, data) => {
    if (err) {
      res.status(404).send('not found');
      return;
    }
    res.send(data);
  });
});

app.listen(3000);
