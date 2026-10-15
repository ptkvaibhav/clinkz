# Running Clinkz against an app it can't log into itself

*A one-page guide for the pentester running the engagement — not for the people
who build Clinkz.*

Most of the time you hand Clinkz a username and password and it logs in for you.
But some applications can't be logged into by a tool: the sign-in goes through a
separate identity provider, or there's MFA, a CAPTCHA, or a hardware-key prompt.
For those, **you** sign in once in your browser and hand Clinkz the session your
browser is now holding. This page is how.

Everything here assumes you already have an authorization record (`-a auth.json`)
— Clinkz refuses to start without one, supplied session or not.

## 1. Export the session from your browser

Sign in to the target in a normal browser tab. You now need two things from that
authenticated tab: its **cookies** and, if the app uses a token, the
**Authorization header**.

**Cookies.** Open DevTools (F12) → **Application** tab (Chrome/Edge) or
**Storage** tab (Firefox) → **Cookies** → pick the target's origin. You'll see a
table of name/value pairs. You want the ones that carry the session — typically a
single session cookie (`session`, `JSESSIONID`, `connect.sid`, `PHPSESSID`, …),
sometimes two. Copy each **name** and its **value** exactly.

**Bearer / JWT token.** If the app authenticates with a token instead of (or as
well as) a cookie, it rides in a request header. In DevTools → **Network** tab,
click any authenticated request (an XHR/fetch to the app's own API is easiest),
look under **Request Headers** for `Authorization: Bearer eyJ…`, and copy the
part after `Bearer `.

Copy the values from the **application's own origin**, not an identity provider's
— it's the target's session Clinkz needs to carry, not the IdP's.

## 2. Write the credentials file

Clinkz reads roles from an **untracked local JSON file** you pass with `-c`
(a.k.a. `--creds`). A supplied session goes in a `session` block on the role,
instead of a password:

```json
{
  "credentials": [
    {
      "role": "user",
      "session": {
        "cookies": { "session": "PASTE_COOKIE_VALUE_HERE" },
        "headers": { "Authorization": "Bearer PASTE_TOKEN_HERE" }
      }
    },
    { "role": "anonymous" }
  ]
}
```

Rules the file enforces, so you get a clear error instead of a silent misfire:

- **A `session` needs at least one cookie or header.** An empty one would be
  indistinguishable from an anonymous session and is refused.
- **Cookie/header NAMES are kept; VALUES are secret.** Clinkz registers every
  value for redaction at load time, exactly as it does a password. Names appear in
  the report (`cookie session`); values never do.
- **Don't put `Cookie`, `Host`, `Content-Length`, `Content-Type`, `Connection`,
  or `Transfer-Encoding` under `headers`.** Cookies go in `cookies`; the rest are
  transport framing Clinkz owns, and it refuses them by name.
- **Unknown keys are refused, not ignored.** A misplaced or misspelled key (a
  `login_url` where it doesn't belong, `coookies`) is a hard error that names the
  key — because a silently-dropped key in a hand-written credential file is
  impossible to tell from one that did nothing.
- **Keep the file out of git.** Clinkz *refuses* to read a credential file that
  git tracks (a tracked credential file is a leaked one), and *warns* if it's
  inside the repo but merely untracked. Put it outside the repo, or gitignore it.

If the app's protected area lives at an unconventional path, add
`"assert_url": "https://app/the/protected/path"` to the role — see step 4 for why.

Run it:

```
python -m clinkz scan -t https://app.example.com -a auth.json -c creds.json
```

## 3. What the report says about a supplied session

Clinkz does **not** take your session on faith. It puts the material through the
same anonymous-control assertion it uses for a session it logged in for itself:
it compares an authenticated request against a sessionless one and only accepts
the session if a real authorization boundary moves. So the report states, per
role, one of two things, naming the cookies/headers you supplied (names only):

- *"Session supplied by the operator (user): cookie `session`. Not obtained by
  this engine and not trusted on that basis — **PROVEN** by the anonymous-control
  assertion."*
- *"… — **REFUSED** by the anonymous-control assertion."* (See step 4.)

When **every** proven role was a supplied session, the report adds a line making
clear this engine performed no login at all — the coverage is only as current as
the browser session you handed it, and nothing in the engine renewed it.

## 4. If it's refused at the start

A refusal means the assertion could not see an authorization boundary between
your session and an anonymous request. The run aborts loudly rather than scanning
blind (which is correct — a tool that scanned on an unproven session would report
"authenticated" coverage it never had). Fix one of:

- **The session expired or was revoked** before Clinkz used it — sign in again in
  the browser and copy fresh cookies/headers.
- **The material is from the wrong origin or path** — copy it from the
  application's own origin, not an identity provider's.
- **The protected surface is at an unconventional path** the assertion's default
  guesses miss — name it with `"assert_url"` on the role. This is the single most
  common fix for an app whose "you're logged in" page isn't at a conventional URL.

## 5. What happens at expiry (mid-run)

A browser session is a clock. If it stops passing the assertion partway through
the engagement, Clinkz **halts** — it does not quietly carry on. The reason is
structural: a password-backed role would simply log in again, but a supplied
session has no password behind it, so this engine *cannot* renew it. Carrying on
would mean running the rest of the engagement anonymously against an
authenticated app while the report still claimed "authenticated."

So on expiry the report records the exact time the session stopped passing, and
states plainly that **everything not yet tested at that point is UNTESTED, not
clean.** Supply a fresh session and re-run.

Practically: if the app's sessions are short-lived, sign in immediately before
launching the scan, and expect to re-run if the engagement outlasts the session's
lifetime. There is no partial-credit mode — an expired session is a hard stop by
design, because the alternative is a report that lies.

## Quick reference

| You have | Put it here | Shows in report | Survives expiry? |
|---|---|---|---|
| A session cookie | `session.cookies` (name → value) | cookie **name** only | No — run halts, re-run |
| A bearer/JWT token | `session.headers.Authorization` | header **name** only | No — run halts, re-run |
| A username + password | `username` + `password` on the role | neither | Yes — engine re-logs-in |
| An unconventional protected path | `assert_url` on the role | — | — |

See also `docs/productization-engagement-safety.md` for the invariants behind
this (116, 117, 11), and `docs/methodology/adaptive-authentication.md` for the
assertion that proves a session.
