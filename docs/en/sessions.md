---
title: Sessions
summary: Server-side sessions with id rotation on login, idle and absolute timeouts, hashed ids in the store, logout with Clear-Site-Data, and e-mail verification links.
category: access
order: 11
---

`SessionManager` keeps sessions on the server and only gives the browser a random id in a hardened cookie. It follows OWASP's Session Management cheat sheet: new id at login, timeouts enforced server side, a complete logout. The `Sessions` guard loads the session of every request.

## Threats mitigated

- **Session fixation** (CWE-384): `login` and `regenerate` give the session a new id; an id planted by an attacker dies at once.
- **Session hijacking**: 256-bit ids from the OS RNG, `__Host-` cookie with `Secure`, `HttpOnly`, `SameSite=Lax` and `Path=/`.
- **Stale sessions** (CWE-613): idle timeout (30 min) and absolute timeout (12 h), checked on the server whatever the cookie says.
- **Store leaks**: the store only sees the SHA-256 of each id; a Redis dump does not hand out live sessions.
- **Data left after logout**: `logout` deletes the session, expires the cookie and sends `Clear-Site-Data`.

## Quick start

```rust
use std::sync::Arc;
use securite::session::{MemorySessionStore, Session, SessionManager, Sessions};
use securite::prelude::*;

let sessions = SessionManager::new(Arc::new(MemorySessionStore::new(100_000)));
let shield = Shield::builder().guard(Sessions::new(sessions.clone())).build();

// POST /login, after the password check:
let mut session = req.extensions().get::<Session>().cloned().unwrap_or_else(|| sessions.start());
sessions.login(&mut session, &user.id);      // new id + user
let set_cookie = sessions.commit(&session);  // add as `Set-Cookie`

// Any handler:
if let Some(session) = req.extensions().get::<Session>() {
    let user = session.user();
}

// POST /logout:
for (name, value) in sessions.logout(session) { /* add to the response */ }
```

With `Sessions` in the shield, a logged-in session also puts a `Principal` (scheme `session`) in the request, so [access control](/docs/access-control) works with it.

## Configuration

| Method | Description |
|---|---|
| `SessionManager::new(store)` | Cookie `__Host-session`, 30 min idle, 12 h absolute. |
| `.idle_timeout(d)` / `.absolute_timeout(d)` | Timeouts. |
| `.cookie_name(name)` / `.same_site(s)` | Cookie settings. |
| `.insecure_dev()` | `http://localhost` only: no `Secure`, no `__Host-` prefix. |
| `.start()` / `.load(headers)` / `.commit(&session)` | Life cycle. |
| `.regenerate(&mut s)` / `.login(&mut s, user)` | New id (every privilege change). |
| `.logout(s)` / `.destroy(s)` | End a session, with or without `Clear-Site-Data`. |

`Session` offers `get`, `insert`, `remove`, `user` and `created_at`. Its `Debug` output never shows the id.

## Shared store

`MemorySessionStore` is bounded and fine for one instance. For several, implement `SessionStore` (`load`, `save` with a TTL, `delete`) over Redis or your database. Keys are 64 hex characters; treat a store error as a missing session, which logs the user out rather than in.

## Clear-Site-Data on logout

`logout` already sends it. To add it to any route, use the `ClearSiteData` guard:

```rust
use securite::clear_site_data::{ClearSiteData, Directive};

Shield::builder().guard(ClearSiteData::on(["/logout", "/account/delete"]));
// or choose: .directives([Directive::Cookies, Directive::Storage])
```

It only decorates successful (`2xx` / `3xx`) responses; browsers honour it over HTTPS.

## E-mail verification links

`Signer` builds links that prove a user reads a mailbox, like Laravel's `MustVerifyEmail`:

```rust
use std::time::Duration;
use securite::signing::Signer;

let signer = Signer::new(secret).purpose("verify-email");
let link = signer.email_verification_url("/email/verify", &user.id, &user.email, Duration::from_secs(3600));
// → /email/verify/42/<hash of the address>?expires=…&signature=…

// GET /email/verify/...:
let user_id = signer.verify_email_url(req.uri().path_and_query().unwrap().as_str(), &current_email)?;
```

The link only works for the same user **and** the same address: after an e-mail change, older links stop working.

## Pitfalls and tips

- Call `login` (or `regenerate`) on every privilege change: login, sudo mode, role change.
- Combine with [CSRF protection](/docs/csrf): a cookie session is sent by the browser on cross-site requests.
- Keep `SameSite=Lax` or `Strict`; `None` needs a reason.

## Related pages

- [Cookies](/docs/cookies)
- [CSRF](/docs/csrf)
- [Access control](/docs/access-control)
- [Signed URLs and tokens](/docs/signed-urls)
