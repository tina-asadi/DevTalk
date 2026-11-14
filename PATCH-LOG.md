# DevTalk — Patch Log (Lab 5: Secure Coding Practices)

Each entry below fixes a vulnerability documented in the Lab 4 Vulnerability Log.
For every one: the original exploit was re-run against the current code and
confirmed to still work, the root cause was fixed, the same exploit was re-run
and now fails (screenshot in `docs/screenshots/`), and the affected feature was
exercised as a normal user to confirm it still works.

Environment used for testing: PHP 8.3 built-in server (`composer start`), fresh
database (`composer reset-db`).

---

## Patch #1 — Parameterize login query (A05 Injection — SQLi)

- **Location:** `public/login.php`
- **Exploit re-run:** Logging in with username `admin'--` and any password logged
  in as admin, because the username was concatenated into
  `SELECT * FROM users WHERE username = '$username' AND password = '$password'`
  and the `--` commented out the password check.
- **Root cause:** User input concatenated directly into the SQL string.
- **Fix:** Replaced the query with a prepared statement that binds the username
  (`WHERE username = ?`) and compares the password in PHP. Removed the handler
  that echoed the raw SQL on error.
- **Re-run result:** The injection payload is now treated as a literal username,
  no row matches, and login is refused. See
  `docs/screenshots/01-sqli-login-blocked.png`.
- **Functional check:** Logging in with a valid account (e.g. `alice` /
  `password123`) still succeeds and redirects to the homepage.

## Patch #2 — Parameterize search query (A05 Injection — SQLi)

- **Location:** `public/search.php`
- **Exploit re-run:** A `q` value containing a `UNION SELECT ... FROM users`
  payload returned user data, because `q` was concatenated into
  `... WHERE title LIKE '%$q%' OR body LIKE '%$q%'`.
- **Root cause:** User input concatenated into the SQL string.
- **Fix:** Prepared statement with bound `LIKE ?` parameters; the `%` wildcards
  are added to the bound value, not the SQL. Removed the catch block that
  appended the failing SQL to the page.
- **Re-run result:** The payload is matched literally against titles/bodies and
  returns no injected rows.
- **Functional check:** A normal search such as `CSS` still returns the matching
  topics.

## Patch #3 — Encode user content on output (A05 Injection — XSS)

- **Location:** `public/topic.php` (topic body and comment body),
  `public/search.php` (the echoed `q`).
- **Exploit re-run:** A topic/comment body of `<script>alert(document.cookie)</script>`
  executed when the page was viewed (stored XSS), and `search.php?q=<script>...`
  executed on reflection (reflected XSS), because all three were printed with a
  raw `echo`.
- **Root cause:** User-supplied text rendered into HTML without encoding.
- **Fix:** Each sink is wrapped in `htmlspecialchars` (with `nl2br` on the bodies
  to preserve line breaks). Note: this intentionally removes the "raw HTML in
  posts" behaviour, which was the source of the stored XSS.
- **Re-run result:** The payload is displayed as inert text and does not run. See
  `docs/screenshots/02-xss-reflected-escaped.png` and
  `docs/screenshots/03-xss-stored-escaped.png`.
- **Functional check:** Topics and comments still post and display normally, with
  line breaks preserved.

## Patch #4 — Enforce object ownership (A01 Broken Access Control — IDOR)

- **Location:** `public/delete_topic.php`, `public/delete_comment.php`,
  `public/edit_topic.php`, `public/profile.php`.
- **Exploit re-run:** Any logged-in user could edit or delete another user's
  topic or comment by changing the `id` in the request, and could overwrite any
  user's bio by posting a different `user_id`, because each handler acted on the
  request id with no ownership check.
- **Root cause:** Actions operated on a request-supplied id without verifying the
  current user owns the object.
- **Fix:** Each handler loads the target, confirms the session user is the owner
  (or an admin), and returns HTTP 403 otherwise. The bio update ignores any
  posted `user_id` and always uses the session id.
- **Re-run result:** Cross-owner edit/delete attempts return 403. See
  `docs/screenshots/05-csrf-idor-403.png`.
- **Functional check:** A user can still edit/delete their *own* topics and
  comments, and update their own bio.

## Patch #5 — Anti-CSRF tokens and POST-only state changes (A01 Broken Access Control — CSRF)

- **Location:** `src/helpers.php` (new `csrf_token` / `csrf_field` /
  `require_post_with_csrf` helpers) and every state-changing handler/form:
  `create_topic.php`, `edit_topic.php`, `add_comment.php`, `profile.php`,
  `delete_topic.php`, `delete_comment.php`, `topic.php`.
- **Exploit re-run:** Deleting a topic or comment required only a `GET` request
  (`delete_topic.php?id=1`), so a cross-site `<img>`/link could trigger it, and
  no form carried an anti-forgery token.
- **Root cause:** State-changing actions carried no CSRF token, and some ran over
  a plain `GET`.
- **Fix:** Added a per-session CSRF token to every state-changing form. The delete
  flows are now POST-only, read the id from the body, and reject any request
  without a matching token (`require_post_with_csrf`).
- **Re-run result:** A `GET` delete, or a `POST` with no/invalid token, returns
  403. See `docs/screenshots/05-csrf-idor-403.png`.
- **Functional check:** Creating, editing, commenting, deleting and bio updates
  all still work through the UI (each form now carries a token).

## Patch #6 — Restrict server-side image fetch (A01 Broken Access Control — SSRF)

- **Location:** `public/fetch_image.php`
- **Exploit re-run:** `fetch_image.php?url=file:///etc/passwd` returned local file
  contents, and `url=http://127.0.0.1/...` reached internal services, because the
  user-supplied URL was passed straight to `file_get_contents`.
- **Root cause:** The server fetched an arbitrary user-supplied URL with no scheme
  or address restrictions.
- **Fix:** Only `http`/`https` are accepted; the host is resolved and any private,
  loopback, link-local or reserved IP is rejected; redirects are disabled so a 302
  cannot bypass the check; and the response is served only when it is really an
  image.
- **Re-run result:** `file://` and internal-host requests return 400 "not
  allowed". See `docs/screenshots/04-ssrf-blocked.png`.
- **Functional check:** A normal public image URL still previews on a topic.

## Patch #7 — Hash passwords, stop error disclosure (A02 Security Misconfiguration / A10)

- **Location:** `src/config.php`, `public/login.php`, `public/register.php`,
  `database/build_db.php`.
- **Exploit re-run:** A database dump (via the SQLi above) exposed usable
  plaintext passwords, and triggering a PHP/SQL error printed stack traces and
  the failing query to the browser.
- **Root cause:** Passwords stored/compared in plaintext; `display_errors` on and
  exception text echoed to users.
- **Fix:** Seeds and registration store a bcrypt hash (`password_hash`); login
  verifies with `password_verify`; `display_errors` is off with server-side
  logging; registration shows a generic message instead of the PDO exception.
- **Re-run result:** Stored passwords are now bcrypt hashes (`$2y$...`), so a dump
  yields no usable passwords, and error pages no longer leak schema or SQL.
- **Functional check:** Registration and login with valid credentials both still
  work.
