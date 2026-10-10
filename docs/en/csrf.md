---
title: CSRF protection
summary: Stateless Fetch Metadata protection using the algorithm of Go 1.25 CrossOriginProtection, with an optional HMAC-signed double-submit token.
category: access
order: 4
---

`Csrf` rejects state-changing requests that a browser sends on behalf of another site. Its default mode needs no configuration, no session and no template change; an optional signed token mode adds a second, independent layer.

## The threat

In a cross-site request forgery, a malicious page makes the victim's browser send a request to your application (a hidden form, an `<img>`, a `fetch` call). The browser attaches the ambient credentials (cookies, HTTP authentication, client certificates), so your server sees a perfectly authenticated request: a money transfer, a password change, an account deletion.

CSRF (CWE-352) belongs to OWASP Top 10 2021 A01 Broken Access Control; see the OWASP Cross-Site Request Forgery Prevention Cheat Sheet and WSTG-SESS-05. `SameSite` cookies help, but they do not cover attacks from sibling subdomains, and `Lax` still allows top-level `GET` navigations.

## How it works

### Fetch Metadata and Origin verification

Modern browsers label every request with `Sec-Fetch-Site`, which an attacker's page cannot forge. The guard (priority 130) applies the same decision procedure as Go 1.25's `http.CrossOriginProtection`:

1. `GET`, `HEAD` and `OPTIONS`, and paths under an `exempt` prefix, are never checked. Every other method, `TRACE` included, is.
2. If `Sec-Fetch-Site` is present: `same-origin` and `none` (the user typed the URL or used a bookmark) pass; `same-site` passes only with `allow_same_site(true)`; anything else passes only if `Origin` is a trusted origin.
3. Without `Sec-Fetch-Site` (older browsers): no `Origin` header means a non-browser client, which passes; a trusted `Origin` passes; otherwise the host of `Origin` must equal the `Host` header.
4. Rejections answer `403` with the code `csrf_rejected`.

### Signed double-submit token

With `with_token(secret)`, every client also receives a token: 24 random bytes followed by their HMAC-SHA256 signature, base64url-encoded. It is stored in the cookie `__Host-csrf` (`Path=/; HttpOnly; SameSite=Strict; Secure`) and exposed to handlers as the `CsrfToken` request extension. Each unsafe request must pass the origin check **and** carry the same token in the `X-CSRF-Token` header. The comparison runs in constant time, and the signature means an attacker cannot plant a token of their own choosing. A missing or wrong token yields `403` with the code `csrf_token_invalid`.

The cookie is `HttpOnly`: scripts never read it. Render the token from `CsrfToken` into your pages instead.

## Quick start

`Shield::recommended()` and `Shield::strict()` already include `Csrf::new()`. On its own:

```rust
use axum::{Router, routing::{get, post}};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "form" }))
        .route("/transfer", post(|| async { "done" }))
        .layer(Shield::builder().guard(Csrf::new()).build())
}
```

The guard is named `csrf`; `ShieldBuilder::recommended().without("csrf")` removes it.

## Configuration

| Method | Default | Description |
|---|---|---|
| `Csrf::new()` | Fetch Metadata only | Stateless protection. |
| `trusted_origin(&str)` | none | Accepts unsafe requests from this origin (`https://admin.example.com`). Can be called several times. |
| `exempt(prefix)` | none | Path prefix that skips the checks (webhooks, token-authenticated APIs). |
| `allow_same_site(bool)` | `false` | Accepts `Sec-Fetch-Site: same-site`, that is every subdomain of your site. |
| `with_token(secret)` | off | Enables the signed double-submit token. Panics if the secret is shorter than 32 bytes. |
| `cookie_name(&str)` | `__Host-csrf` | Token cookie name. Token mode only. |
| `header_name(&str)` | `x-csrf-token` | Header carrying the token. Token mode only. |
| `insecure_dev_cookie()` | `Secure` cookie | Drops `Secure` and renames `__Host-csrf` to `csrf`, for plain-HTTP development. Token mode only. |
| `monitor()` | enforce | Reports violations without blocking. |

> **Tip:** `cookie_name`, `header_name` and `insecure_dev_cookie` can be called before or after `with_token`: the order does not matter. Without `with_token` they have no effect.

## Examples

### Server-rendered app with htmx

```rust
use axum::{Extension, Router, response::Html, routing::{get, post}};
use securite::prelude::*;

async fn page(Extension(CsrfToken(token)): Extension<CsrfToken>) -> Html<String> {
    // htmx adds this header to every request it sends.
    Html(format!(
        r#"<body hx-headers='{{"X-CSRF-Token": "{token}"}}'>
  <button hx-post="/transfer">Send</button>
</body>"#
    ))
}

pub fn app(secret: String) -> Router {
    let shield = ShieldBuilder::recommended()
        .guard(Csrf::new().with_token(secret).exempt("/webhooks"))
        .build();

    Router::new()
        .route("/", get(page))
        .route("/transfer", post(|| async { "sent" }))
        .route("/webhooks/payments", post(|| async { "ok" }))
        .layer(shield)
}
```

Load the secret from your secret store, for example `std::env::var("CSRF_SECRET")`, and share it between all instances.

### Sending the token with fetch

If the page renders `<meta name="csrf-token" content="…">` from `CsrfToken`:

```text
const token = document.querySelector('meta[name="csrf-token"]').content;
await fetch("/transfer", {
  method: "POST",
  headers: { "Content-Type": "application/json", "X-CSRF-Token": token },
  body: JSON.stringify({ amount: 10 }),
});
```

### Admin front-end, webhooks and a bearer-token API

```rust
use securite::prelude::*;

pub fn csrf() -> Csrf {
    Csrf::new()
        .trusted_origin("https://admin.example.com")
        .exempt("/webhooks") // verified by signature instead
        .exempt("/api/v1") // bearer tokens, no cookies
}
```

### Local development

```rust
use securite::prelude::*;

pub fn csrf(secret: &str, dev: bool) -> Csrf {
    let csrf = Csrf::new().with_token(secret);
    if dev { csrf.insecure_dev_cookie() } else { csrf }
}
```

### What a rejection looks like

```json
{"type":"about:blank","title":"Forbidden","status":403,"code":"csrf_rejected","detail":"Cross-site request rejected."}
```

## Standalone layer

```rust
use axum::{Router, routing::post};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/settings", post(|| async { "saved" }))
        .layer(Csrf::new())
}
```

## Pitfalls and tips

- **Safe methods are never checked**: a `GET` handler that changes state is unprotected by design. Keep `GET`, `HEAD` and `OPTIONS` free of side effects.
- **Plain HTML forms cannot send headers**: token mode needs JavaScript (`fetch`, htmx …). Classic forms are covered by the Fetch Metadata mode in every modern browser.
- **`allow_same_site(true)`** trusts every subdomain, including user-content hosts or a subdomain taken over through a dangling DNS record. Prefer `trusted_origin` for each front-end.
- **Exempt paths** must be protected otherwise, for example by webhook signatures or bearer tokens. Prefixes match on segment boundaries.
- **Proxies**: the fallback for old browsers compares `Origin` with `Host`; your reverse proxy must forward the original `Host`.
- **Secret rotation** invalidates every token. Clients receive a new cookie on their next request, but a request already in flight fails once.
- **Cookie name**: renaming the cookie without the `__Host-` prefix lets a sibling subdomain overwrite it.
- **APIs**: `Shield::api()` has no CSRF guard, because APIs normally authenticate with tokens. Add `Csrf::new()` back if your API relies on cookies.
- **Missing extension**: extracting `Extension<CsrfToken>` without `with_token` makes axum answer 500.

> **Tip:** any XSS defeats every CSRF defence, since the script runs on your own origin. Pair this guard with a strict [Content-Security-Policy](/docs/security-headers).

## Related pages

- [Cookie hardening](/docs/cookies)
- [CORS](/docs/cors)
- [Content-Type allow-list](/docs/content-type)
- [Host filter](/docs/host-filter)
- [Webhook signatures](/docs/webhook-signatures)
- [Monitor mode](/docs/monitor-mode)
