---
title: Cookie hardening
summary: Adds the missing Secure, HttpOnly and SameSite attributes to every Set-Cookie header, including cookies set by crates you do not control.
category: browser
order: 3
---

`CookieHardening` rewrites the `Set-Cookie` headers of your responses so that every cookie gets `Secure`, `HttpOnly` and `SameSite`, whichever handler, session library or OAuth crate created it. Attributes that are already present are never changed.

## The threat

Session cookies are bearer credentials: whoever holds one is the user. Each missing attribute opens a known path to steal or abuse it:

- without `HttpOnly`, a single XSS can read `document.cookie` and exfiltrate the session;
- without `Secure`, the cookie travels in clear text over any HTTP request, including one forced by an attacker on public Wi-Fi;
- without `SameSite`, the browser attaches the cookie to cross-site requests, which is the root cause of CSRF.

These issues fall under OWASP Top 10 2021 A07 Identification and Authentication Failures. The OWASP Session Management Cheat Sheet requires all three attributes, and WSTG-SESS-02 tests for them. They are easy to forget because cookies are set in many places; this guard fixes them in one.

## How it works

The guard runs on the response path at priority 910, after every other guard, and rewrites each `Set-Cookie` value:

- `Secure` is added unless present. It is always added to `SameSite=None` cookies and to `__Host-` and `__Secure-` prefixed cookies, even in development mode, because browsers reject them otherwise.
- `HttpOnly` is added unless present, unless the cookie name is listed in `readable_by_js` or `no_http_only()` is set.
- `SameSite=<default>` is added only when the cookie has no `SameSite` attribute.
- Other attributes (`Path`, `Domain`, `Max-Age`, `Partitioned` …) are left untouched, and values that are not valid UTF-8 are passed through unchanged.

Cookies added by other guards, such as the [CSRF](/docs/csrf) token cookie, are hardened too.

| Set by the application | Sent to the browser (defaults) |
|---|---|
| `sid=abc` | `sid=abc; Secure; HttpOnly; SameSite=Lax` |
| `sid=abc; Path=/;` | `sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax` |
| `sid=abc; secure; HTTPONLY; SameSite=Strict` | unchanged |

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(CookieHardening::new()).build());
    app.get("/login", |_req: Request| async {
        res::text("welcome").header("set-cookie", "sid=abc; Path=/")
    });
    app
}
```

`Shield::recommended()` and `Shield::api()` already include `CookieHardening::new()`; `Shield::strict()` uses `SameSite::Strict`. The guard is named `cookies`.

## Configuration

| Method | Default | Description |
|---|---|---|
| `CookieHardening::new()` | `Secure; HttpOnly; SameSite=Lax` | Recommended defaults. |
| `same_site(SameSite)` | `SameSite::Lax` | `SameSite` value added to cookies that have none. |
| `readable_by_js(names)` | none | Cookie names that must stay readable by JavaScript (no `HttpOnly`). Can be called several times. |
| `no_http_only()` | `HttpOnly` added | Never adds `HttpOnly`. |
| `insecure_dev()` | `Secure` added | Does not add `Secure`, for plain-HTTP local development only. |
| `harden(&str)` | — | Returns the hardened version of one `Set-Cookie` value; handy in unit tests. |

### SameSite values

| Value | Cookie sent on | Typical use |
|---|---|---|
| `SameSite::Strict` | same-site requests only | admin back-offices, banking actions |
| `SameSite::Lax` | same-site requests and top-level `GET` navigations from other sites | session cookies of most sites |
| `SameSite::None` | every request (`Secure` is forced) | embedded widgets, cross-site SSO |

## Examples

### Strict sessions for a back-office

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    Shield::builder()
        .guard(SecurityHeaders::new())
        .guard(CookieHardening::new().same_site(SameSite::Strict))
        .build()
}
```

### Cookies read by JavaScript

A theme preference or a framework's `XSRF-TOKEN` cookie must stay readable by scripts; every other cookie keeps `HttpOnly`:

```rust
use securite::prelude::*;

pub fn cookies() -> CookieHardening {
    CookieHardening::new().readable_by_js(["theme", "XSRF-TOKEN"])
}
```

### Local development over plain HTTP

```rust
use securite::prelude::*;

pub fn cookies(dev: bool) -> CookieHardening {
    let cookies = CookieHardening::new();
    if dev { cookies.insecure_dev() } else { cookies }
}
```

### Unit-testing your cookies

```rust
use securite::prelude::*;

#[test]
fn session_cookie_is_hardened() {
    let hardening = CookieHardening::new();
    assert_eq!(
        hardening.harden("sid=abc; Path=/"),
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
}
```

## Standalone guard

The guard only sees `Set-Cookie` headers that exist when the response passes through it. With Vitesse the first middleware added is the outermost, so add it before the middlewares that set cookies:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::from(CookieHardening::new())); // first: sees the final Set-Cookie headers
    // app.middleware(session_middleware);               // sets the session cookie
    app.post("/login", |_req: Request| async {
        res::text("ok").header("set-cookie", "sid=abc; Path=/")
    });
    app
}
```

The same rule applies to a `Shield`: it must wrap your session middleware.

## Pitfalls and tips

> **Warning:** `insecure_dev()` must never reach production. Derive it from your configuration, not from a hard-coded flag.

- **`SameSite=Strict` and incoming links**: a user who follows a link from an email or another site arrives without the cookie and looks logged out on that first page. `Lax` is the right default for session cookies; keep `Strict` for sensitive cookies.
- **SameSite is not full CSRF protection**: it does not cover attacks from sibling subdomains, which are "same-site", and `Lax` still allows top-level `GET` navigations. Keep the [CSRF](/docs/csrf) guard on.
- **`__Host-` prefix**: browsers also require `Path=/` and no `Domain` attribute. The guard adds `Secure` but cannot invent the rest; set them in your code.
- **Local development**: Chromium-based browsers and Firefox accept `Secure` cookies on `http://localhost`. You mostly need `insecure_dev()` when testing over plain HTTP on a LAN address or a custom host name.
- **Scope**: cookies written by JavaScript (`document.cookie`) or added by a reverse proxy never pass through the guard.
- `HttpOnly` stops cookie theft, not XSS itself; pair it with a strict [CSP](/docs/security-headers).

> **Tip:** `readable_by_js` matches cookie names exactly and case-sensitively, like browsers do.

## Related pages

- [CSRF protection](/docs/csrf)
- [Security headers](/docs/security-headers)
- [HTTPS redirect](/docs/https-redirect)
- [CORS](/docs/cors)
