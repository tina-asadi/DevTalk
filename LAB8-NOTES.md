# Lab 8 — Browser and API Security (notes)

## Part A — CORS

### The vulnerability (before)
`src/api/cors.php` reflected the request's `Origin` header straight back into
`Access-Control-Allow-Origin` and always sent `Access-Control-Allow-Credentials: true`.
That means **any** origin — including the attacker on `http://localhost:9000` —
was told it could read credentialed API responses.

- **Test 1 — read `profile.php?id=2`:** the browser refused to let the attacker
  page read the response, and the Console showed a CORS error. But in DevTalk's
  terminal the request logged as `GET /profile.php?id=2` → **200**, and it carried
  alice's `Cookie`. So the request *was* sent with her session; the Same-Origin
  Policy only stopped the attacker's JavaScript from **reading** the HTML back
  (`profile.php` is a normal page and sends no CORS headers).
- **Tests 2 & 3 — read `/api/me` and `/api/messages`:** these succeeded for the
  attacker, because the API reflected `Origin: http://localhost:9000` and allowed
  credentials. alice's profile and private messages were posted to the attacker's
  `collect.php` and appended to `stolen.log`.
- **The two headers that enabled the read:** `Access-Control-Allow-Origin: http://localhost:9000`
  (reflected) and `Access-Control-Allow-Credentials: true`.
- **Why alice's cookie was sent at all:** the cookie is `SameSite=Lax`, but
  SameSite compares *sites*, and `localhost:8000` and `localhost:9000` are the
  same site (port is not part of a site). So the browser treated the request as
  same-site and attached the cookie. On the real internet `attacker.example` and
  `devtalk.example` are different sites and Lax would withhold it — which is why,
  in this lab, **the CORS policy is the only thing protecting alice's data.**

### The fix — Patch #A1
`api_cors()` rewritten with:
- an explicit allowlist containing exactly `http://localhost:5173`;
- an **exact** `in_array($origin, $allowed, true)` comparison (no `str_contains`,
  `str_ends_with`, `strpos`, or regex);
- `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials` sent **only**
  when the Origin is on the list; the `null` origin is never on the list;
- `Vary: Origin` on every response, so a cache never serves one origin's CORS
  headers to another;
- preflight (`OPTIONS`) gets `Allow-Methods`/`Allow-Headers` only from an allowed
  origin; any other origin gets no `Access-Control-*` headers at all.

### After the fix
Reloading the attacker page and running Tests 2 & 3, both are **refused** — the
Console shows a CORS error (`No 'Access-Control-Allow-Origin' header is present`),
and nothing new lands in `stolen.log`.

**But the request still arrived.** DevTalk's terminal still logs `GET /api/me` →
**200**. This is the key point: **CORS protects the confidentiality of the
*response* — it stops a cross-origin script from *reading* the answer. It does not
stop the request from being sent or the server from processing it.** Anything with
a side effect (a state change) still needs its own protection (CSRF tokens, and not
treating a GET as an action), because the browser will still deliver the request
with the victim's cookie.

**Trusted origin still works:** serving the same front end from the allowlisted
`http://localhost:5173` and running Test 2 there, the read succeeds — the allowlist
does exactly what it says: listed origins can read logged-in users' data, everyone
else cannot.

## Part B — Cookie vs JWT

### The session cookie (`PHPSESSID`)
In DevTools → Application → Cookies: **HttpOnly = true, SameSite = Lax, Secure =
false** (Secure is off because the site runs on plain `http://localhost`; it would
be enabled in production over HTTPS).

Running `document.cookie` in the Console does **not** show `PHPSESSID`, because the
cookie is `HttpOnly` — JavaScript is not allowed to read it. That is exactly the
defence: an injected script cannot steal the session id from the cookie.

### The JWT (`devtalk_token` in Local Storage)
`signIn()` stores the token in `localStorage`; `api()` sends it as
`Authorization: Bearer <token>`. Decoding the payload shows these claims:

| Claim | Meaning |
|-------|---------|
| `iss` | issuer — `"devtalk"` |
| `sub` | subject — the user's id |
| `username` | the user's username — **personal information** |
| `email` | the user's email — **personal information** |
| `role` | `user` or `admin` — the privilege the API trusts |
| `iat` | issued-at (Unix time) |
| `exp` | expiry (Unix time) = `iat` + 8 hours |

**Personal information:** `username` and `email` (and the `sub` id). **Lifetime:**
8 hours (`API_JWT_LIFETIME = 8 * 60 * 60`).

**Why not paste a real token into an online "JWT decoder":** the token *is* a live
bearer credential — anyone holding it can act as you until it expires (8 hours
here), with no password needed. A third-party site could log or keep it, and a
promise that it "decodes only in your browser" cannot be verified. You just decoded
it yourself with three lines of `atob()`, so there is no reason to hand it to anyone.

**Encoded is not encrypted, but it is signed.** Forging a token with `role` changed
to `admin` and sending it to `/api/me` returns **HTTP 401 `{"error":"Invalid or
expired token."}`**. The payload was changed but the HMAC signature was not (and
cannot be, without the server's key), so `jwt_decode()` in `src/api/jwt.php`
rejects it at:
`if ($given === false || !hash_equals($expected, $given)) { return null; }`
— the signature no longer matches `hash_hmac('sha256', "$h.$p", jwt_secret())`.

### What XSS could do with each credential
An injected script (or the Console standing in for one) running on a DevTalk tab:
- **can** read `localStorage.getItem('devtalk_token')` — the JWT is readable by JS;
- **cannot** read `document.cookie` — `PHPSESSID` is `HttpOnly`.

So storing the token in `localStorage` is the weaker spot: an XSS steals the JWT,
not the session cookie. Using the stolen token from a terminal (no browser, no
cookie) works:
`curl -s http://localhost:8000/api/messages -H "Authorization: Bearer <token>"`
returns alice's messages — a bearer token is portable and needs nothing else.

After **Sign out of Messages** (which deletes the token from `localStorage`), the
**same curl still works** until the token's `exp` passes. Signing out only removes
the client's copy; the server does not track or revoke JWTs — it just re-checks the
signature and `exp` on each request. That is the central trade-off of stateless
JWTs: you cannot revoke one by deleting it on the client, so they are kept short-lived
(here, 8 hours) and, for real logout/revocation, need server-side state (a denylist
or token versioning).
