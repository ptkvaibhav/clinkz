/*
 * Protopoll — a target whose prototype can actually be polluted.
 *
 * Every other fixture in this repo is Python, and for prototype pollution that
 * would have been a MODEL: a dict standing in for ``Object.prototype``, whose
 * distinguishing behaviour is whatever the fixture author decided to write. The
 * one property this class's oracle rests on — that a merge reaches an object
 * every later request reads through, and that a guarded merge of identical
 * SHAPE does not — is exactly the property a model gets to assert rather than
 * exhibit. So this is Node, the pollution is real, and the merge endpoints
 * differ only inside the merge.
 *
 * Node ships everything used here. There is no ``package.json``, no dependency
 * to resolve and no lockfile entry: same reasoning as ``docker/meridian``, so
 * the container image cannot drift from the file the test harness runs.
 *
 * ------------------------------------------------------------------------
 * The surface
 * ------------------------------------------------------------------------
 *
 *   GET  /                        index, links every route below
 *   GET  /api/v2/profile          read the stored profile
 *   POST /api/v2/profile          recursive merge of the JSON body  — POLLUTABLE
 *   GET  /api/v2/notifications    read the stored preferences
 *   POST /api/v2/notifications    GUARDED recursive merge           — not pollutable
 *   GET  /api/v2/preferences      read the stored display settings
 *   POST /api/v2/preferences      shallow spread merge              — not pollutable, REFLECTS
 *   POST /internal/_reset         harness-only; 404 to anything the engine sends
 *
 * Three merge endpoints, one vulnerability, and each of the two sound ones is a
 * different way to be wrong about it.
 *
 * ``/api/v2/notifications`` is the shape twin. It accepts the same JSON, merges
 * the same nested objects, answers 200 with the same body shape, and its guard
 * is three lines inside the merge — the modern lodash/``deepmerge`` behaviour.
 * From outside, the polluting request to it and the polluting request to
 * ``/api/v2/profile`` are indistinguishable: same method, same content type,
 * same status, same echoed record, and neither response contains the injected
 * key, because on the vulnerable one the key landed on the PROTOTYPE and
 * ``JSON.stringify`` serialises own properties. Nothing in the response to the
 * payload separates them. Only a separate, later request does.
 *
 * That is the endpoint the class has to get right. An oracle that grades the
 * response to its own polluting request cannot tell these two apart at all, and
 * an engine that ships it reports every deep-merge endpoint on the internet.
 *
 * ``/api/v2/preferences`` is the reflection trap, and it is the commoner shape
 * of the two: ``{...stored, ...body}`` copies ``__proto__`` on as an ordinary
 * own property — spread defines, it does not assign, so nothing reaches the
 * prototype — and ``JSON.stringify`` then serialises it straight back. So the
 * SOUND endpoint echoes the payload and the vulnerable one does not. Every
 * phantom this engine has shipped was an oracle reading its own input back out
 * of a body; this route is here so that oracle fails loudly on the fixture
 * rather than quietly on a client.
 *
 * ------------------------------------------------------------------------
 * The gadgets
 * ------------------------------------------------------------------------
 *
 * Pollution is not observable by itself; something has to READ the polluted
 * key. Both readers here are the ordinary Node idioms that make server-side
 * prototype pollution exploitable in real applications, and both live in the
 * single response helper every route calls — which is how a real application
 * has one:
 *
 *   * ``for (const name in headerBag)`` — ``for…in`` walks the prototype chain,
 *     so a polluted key becomes a RESPONSE HEADER. Attributable on its own: the
 *     engine mints both the header name and its value, and no application emits
 *     a header nobody has ever named carrying a value nobody has ever sent.
 *   * ``opts.status || 200`` — a polluted ``status`` supplies the response code
 *     for every later response. NOT attributable on its own: 510 is a number any
 *     server may return for its own reasons, which is why the class that reads
 *     it may never emit without a control arm that refused first.
 *
 * ------------------------------------------------------------------------
 * Why the reset endpoint is bound the way it is
 * ------------------------------------------------------------------------
 *
 * Pollution outlives the request that caused it. A real target needs its
 * process restarted; this one carries ``POST /internal/_reset`` so the harness
 * can run cases back to back without a respawn per case.
 *
 * A reset endpoint the scanner can reach is worse than no fixture at all: a run
 * could un-pollute itself between the payload and the observation, and the
 * effect arm would read a clean target and report the vulnerable endpoint as
 * sound — a false negative manufactured by the test rig. So it is bound by two
 * conditions the engine satisfies neither of:
 *
 *   1. the connection is from loopback — under ``docker compose`` the engine
 *      reaches this container over the bridge network and is never 127.0.0.1;
 *      and
 *   2. the request carries ``X-Fixture-Control: <PROTOPOLL_RESET_TOKEN>``, a
 *      header no code path in ``clinkz`` sends.
 *
 * Absent either, and absent the environment variable entirely, the route is 404
 * on every method — so discovering the path tells a crawler nothing.
 */

'use strict';

const http = require('node:http');

const PORT = Number(process.env.PROTOPOLL_PORT || 8095);
const HOST = process.env.PROTOPOLL_HOST || '0.0.0.0';
const RESET_TOKEN = process.env.PROTOPOLL_RESET_TOKEN || '';
const ACCESS_LOG = process.env.PROTOPOLL_ACCESS_LOG !== '0';

const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
const MAX_BODY_BYTES = 64 * 1024;

function freshStore() {
  return {
    profile: { displayName: 'Ada Lovelace', locale: 'en-GB', theme: { mode: 'light' } },
    notifications: { email: true, digest: 'weekly', channels: { push: false } },
    preferences: { density: 'comfortable', timezone: 'Europe/London' },
  };
}

/* The application's own state. Ordinary records; nothing here is shared with
 * Object.prototype, which is the point — the pollution reaches the prototype
 * THROUGH the merge, not through the data. */
let store = freshStore();

/* Keys this process has had written onto Object.prototype, so /internal/_reset
 * can undo exactly what a run added rather than guessing. A real target has no
 * such record and no such endpoint. */
const pollutedKeys = new Set();

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/*
 * The vulnerable merge, written the way it is written in the wild.
 *
 * ``JSON.parse`` gives ``__proto__`` back as an ordinary OWN enumerable
 * property, so ``Object.keys`` reports it. Reading ``target['__proto__']`` then
 * goes through the getter and hands back Object.prototype, the recursion walks
 * into it, and the leaf assignment lands on every object in the process.
 */
function deepMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (target === Object.prototype) {
      pollutedKeys.add(key);
    }
    if (isPlainObject(value)) {
      if (!isPlainObject(target[key])) {
        target[key] = {};
      }
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

/*
 * The same merge, guarded. Three lines different; identical from outside.
 */
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

function safeDeepMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) {
      continue;
    }
    const value = source[key];
    if (isPlainObject(value)) {
      if (!isPlainObject(target[key])) {
        target[key] = {};
      }
      safeDeepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

/*
 * The reflection trap: a shallow spread. Nothing reaches the prototype, and the
 * injected key comes straight back out in the response body.
 */
function spreadMerge(target, source) {
  return { ...target, ...source };
}

/*
 * The one response helper — and therefore the one place the gadgets live.
 *
 * ``opts`` is a fresh empty object on the common path, so every property read
 * off it resolves through the prototype chain: that is not a contrivance, it is
 * what ``options = options || {}`` does in every Node codebase.
 */
function sendJson(res, payload, opts) {
  const options = opts || {};
  const headerBag = { 'content-type': 'application/json; charset=utf-8' };

  // Gadget 1 — for…in walks the prototype chain.
  for (const name in headerBag) {
    try {
      res.setHeader(name, String(headerBag[name]));
    } catch {
      /* an invalid header name from a polluted key is not worth a 500 */
    }
  }

  // Gadget 2 — a polluted `status` supplies the code.
  const status = options.status || 200;

  res.writeHead(Number(status) || 200);
  res.end(JSON.stringify(payload));
}

function sendHtml(res, html) {
  res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
  res.end(html);
}

function notFound(res) {
  res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
  res.end('not found');
}

const INDEX = `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Protopoll</title></head>
<body>
<h1>Protopoll</h1>
<p>A small account service.</p>
<ul>
  <li><a href="/api/v2/profile">/api/v2/profile</a> — display name, locale, theme</li>
  <li><a href="/api/v2/notifications">/api/v2/notifications</a> — delivery preferences</li>
  <li><a href="/api/v2/preferences">/api/v2/preferences</a> — display settings</li>
</ul>
<p>Each accepts <code>POST</code> with an <code>application/json</code> body and
merges it into the stored record.</p>
</body>
</html>
`;

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function handleMerge(req, res, record, merge) {
  let parsed;
  try {
    const raw = await readBody(req);
    parsed = raw ? JSON.parse(raw) : {};
  } catch {
    sendJson(res, { error: 'invalid json body' }, { status: 400 });
    return;
  }
  if (!isPlainObject(parsed)) {
    sendJson(res, { error: 'body must be an object' }, { status: 400 });
    return;
  }
  store[record] = merge(store[record], parsed);
  sendJson(res, { [record]: store[record] });
}

function handleReset(req, res) {
  const remote = req.socket.remoteAddress || '';
  const supplied = req.headers['x-fixture-control'];
  if (!RESET_TOKEN || !LOOPBACK.has(remote) || supplied !== RESET_TOKEN) {
    notFound(res);
    return;
  }
  for (const key of pollutedKeys) {
    delete Object.prototype[key];
  }
  const cleared = [...pollutedKeys];
  pollutedKeys.clear();
  store = freshStore();
  res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify({ reset: true, cleared }));
}

const MERGERS = {
  '/api/v2/profile': ['profile', deepMerge],
  '/api/v2/notifications': ['notifications', safeDeepMerge],
  '/api/v2/preferences': ['preferences', spreadMerge],
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  const method = (req.method || 'GET').toUpperCase();

  if (ACCESS_LOG) {
    process.stdout.write(`${JSON.stringify({ method, path })}\n`);
  }

  try {
    if (path === '/internal/_reset') {
      if (method !== 'POST') {
        notFound(res);
        return;
      }
      handleReset(req, res);
      return;
    }
    if (path === '/' && method === 'GET') {
      sendHtml(res, INDEX);
      return;
    }
    if (Object.hasOwn(MERGERS, path)) {
      const [record, merge] = MERGERS[path];
      if (method === 'GET') {
        sendJson(res, { [record]: store[record] });
        return;
      }
      if (method === 'POST') {
        await handleMerge(req, res, record, merge);
        return;
      }
    }
    notFound(res);
  } catch (err) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`error: ${err && err.message ? err.message : 'unknown'}`);
  }
});

server.listen(PORT, HOST, () => {
  process.stderr.write(`protopoll listening on ${HOST}:${PORT}\n`);
});
