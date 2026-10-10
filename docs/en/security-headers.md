---
title: Security headers
summary: Helmet-style response headers with a strict Content-Security-Policy (nonces or hashes), HSTS, cross-origin isolation and fingerprint removal.
category: browser
order: 1
---

`SecurityHeaders` adds the headers recommended by the [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) to every response, including the error responses produced by other guards. It also ships a typed builder for the `Content-Security-Policy`, with per-request nonces and hashes for inline scripts. Every `Shield` preset includes it.

## The threat

Browsers do whatever your responses allow. Without explicit instructions they run injected scripts, let other sites frame your pages, guess content types and fall back to plain HTTP. These headers close those doors:

- **Cross-site scripting** (OWASP Top 10 2021 A03 Injection): a strict CSP stops injected scripts from running, even when an escaping bug slips through.
- **Clickjacking**: `frame-ancestors 'none'` and `X-Frame-Options: DENY` forbid framing.
- **MIME sniffing**: `X-Content-Type-Options: nosniff`.
- **Downgrade and SSL stripping** (A02 Cryptographic Failures): `Strict-Transport-Security`.
- **Cross-origin leaks and Spectre-class side channels**: COOP, CORP and, optionally, COEP isolate your origin.
- **Fingerprinting**: `Server`, `X-Powered-By` and similar headers are removed.

Missing headers are one of the most frequent A05 Security Misconfiguration findings.

## How it works

The guard has priority 900, so it runs after the blocking guards. On the request path it only works when nonces are enabled: it draws 128 bits from the OS CSPRNG, encodes them in base64url and stores them as a `CspNonce` request extension. On the response path it:

1. removes `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version` and `X-Runtime`;
2. adds each configured header **only if the handler did not already set it** (unless `overwrite(true)`);
3. writes the CSP, with the nonce substituted. When a guard that runs earlier rejected the request, no nonce was drawn: the complete policy is then sent without the nonce source, never truncated.

The policy is rendered and validated once, when the guard is built: an invalid value panics at startup, never during a request.

## Quick start

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "Hello" }))
        .layer(Shield::builder().guard(SecurityHeaders::new()).build())
}
```

Adding a guard with the same name replaces the existing one, so upgrading a preset is a single line:

```rust
use securite::prelude::*;

pub fn shield() -> Shield {
    ShieldBuilder::recommended()
        .guard(SecurityHeaders::strict()) // replaces the preset's SecurityHeaders::new()
        .build()
}
```

## Default headers

| Header | `new()` | `strict()` | `api()` |
|---|---|---|---|
| `Content-Security-Policy` | `ContentSecurityPolicy::strict()` | same | `ContentSecurityPolicy::api()` |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` | same | same |
| `X-Content-Type-Options` | `nosniff` | same | same |
| `X-Frame-Options` | `DENY` | same | same |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | `no-referrer` | `no-referrer` |
| `Permissions-Policy` | disables 15 features (see below) | same | same |
| `Cross-Origin-Opener-Policy` | `same-origin` | same | same |
| `Cross-Origin-Resource-Policy` | `same-origin` | same | same |
| `Cross-Origin-Embedder-Policy` | not sent | `require-corp` | not sent |
| `Origin-Agent-Cluster` | `?1` | same | same |
| `X-DNS-Prefetch-Control` | `off` | same | same |
| `X-Download-Options` | `noopen` | same | same |
| `X-Permitted-Cross-Domain-Policies` | `none` | same | same |
| `X-XSS-Protection` | `0` (the legacy auditor is harmful) | same | same |
| `Cache-Control` | not sent | not sent | `no-store` |

The default `Permissions-Policy` sets an empty allow-list for `accelerometer`, `autoplay`, `camera`, `display-capture`, `encrypted-media`, `geolocation`, `gyroscope`, `magnetometer`, `microphone`, `midi`, `payment`, `picture-in-picture`, `screen-wake-lock`, `usb` and `xr-spatial-tracking`. `publickey-credentials-get` is left alone, so passkeys (WebAuthn sign-in) work by default.

`ContentSecurityPolicy::strict()` renders `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests`. `ContentSecurityPolicy::api()` renders `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.

## Configuration

### SecurityHeaders

| Method | Default | Description |
|---|---|---|
| `new()` / `strict()` / `api()` | — | Presets described above. |
| `csp(policy)` / `content_security_policy(policy)` | `ContentSecurityPolicy::strict()` | Sets the CSP. Accepts a policy or an `Option`. |
| `hsts(Option<Hsts>)` | `Hsts::default()` | Configures HSTS; `None` removes it. |
| `frame_options(&str)` | `DENY` | `X-Frame-Options` (`DENY` or `SAMEORIGIN`). |
| `referrer_policy(&str)` | `strict-origin-when-cross-origin` | `Referrer-Policy`. |
| `permissions_policy(&str)` | see above | `Permissions-Policy`. |
| `cross_origin_opener_policy(&str)` | `same-origin` | COOP. |
| `cross_origin_resource_policy(&str)` | `same-origin` | CORP (`same-origin`, `same-site`, `cross-origin`). |
| `cross_origin_embedder_policy(&str)` | not sent | COEP (`require-corp`, `credentialless`). |
| `cache_control(&str)` | not sent | `Cache-Control`. |
| `set(name, value)` | — | Sets or replaces any header. Panics on an invalid name or value. |
| `unset(name)` | — | Removes a configured header; `unset("content-security-policy")` disables the CSP. |
| `overwrite(bool)` | `false` | When `true`, replaces headers already set by handlers. |
| `keep_fingerprinting_headers()` | headers stripped | Keeps `Server`, `X-Powered-By` and similar. |
| `policy()` | — | Returns the configured CSP, if any. |

### ContentSecurityPolicy

| Method | Default | Description |
|---|---|---|
| `new()` | empty | Empty policy. |
| `strict()` / `api()` | — | Presets described above. |
| `default_src`, `script_src`, `script_src_elem`, `script_src_attr`, `style_src`, `style_src_elem`, `style_src_attr`, `img_src`, `font_src`, `connect_src`, `media_src`, `object_src`, `frame_src`, `child_src`, `worker_src`, `manifest_src`, `frame_ancestors`, `base_uri`, `form_action`, `sandbox`, `report_to`, `report_uri` | from the preset | Set (replace) that directive with the given sources. |
| `directive(name, sources)` | — | Sets or replaces any directive. |
| `add_sources(name, sources)` | — | Appends sources to a directive, creating it if needed. The name is normalised (trimmed, lowercased). |
| `remove_directive(name)` | — | Removes a directive, for example `upgrade-insecure-requests` for plain-HTTP development. |
| `upgrade_insecure_requests()` | on in `strict()` | Adds `upgrade-insecure-requests`. |
| `require_trusted_types()` | off | Adds `require-trusted-types-for 'script'` (DOM XSS). |
| `with_nonce()` | off | Fresh nonce per request, appended to `script-src`, `script-src-elem` and `style-src`. Without `script-src`, adds one made of the `default-src` sources plus the nonce. |
| `report_only()` | off | Sends `Content-Security-Policy-Report-Only` instead. |
| `hashes_for_inline_scripts(html)` | — | Returns `'sha256-…'` sources for every inline `<script>` of `html`. |
| `hashes_for_inline_styles(html)` | — | Same for inline `<style>` elements. |

Source keywords live in `securite::headers::src`: `SELF`, `NONE`, `UNSAFE_INLINE`, `UNSAFE_EVAL`, `WASM_UNSAFE_EVAL`, `STRICT_DYNAMIC`, `UNSAFE_HASHES`, `DATA`, `BLOB` and `HTTPS`. Plain strings such as `"https://cdn.example.com"` work too. A source containing `;`, `,` or a control character panics, which rules out header injection. `policy.to_string()` shows the rendered value.

### Hsts

`securite::headers::Hsts` is a plain struct with public fields: `max_age` (default two years), `include_subdomains` (default `true`) and `preload` (default `false`). No preset enables `preload`, not even `strict()`; opt in explicitly:

```rust
use securite::headers::Hsts;
use securite::prelude::*;

pub fn headers() -> SecurityHeaders {
    // Only once the domain and every sub-domain are HTTPS only.
    SecurityHeaders::strict().hsts(Some(Hsts { preload: true, ..Hsts::default() }))
}
```

## Examples

### Nonces in server-rendered pages

```rust
use axum::{Extension, Router, response::Html, routing::get};
use securite::prelude::*;

async fn index(Extension(CspNonce(nonce)): Extension<CspNonce>) -> Html<String> {
    Html(format!(
        r#"<!doctype html>
<script nonce="{nonce}">console.log("runs: it carries the nonce");</script>
<script>console.log("blocked: no nonce");</script>"#
    ))
}

pub fn app() -> Router {
    let headers = SecurityHeaders::new().csp(ContentSecurityPolicy::strict().with_nonce());
    Router::new()
        .route("/", get(index))
        .layer(Shield::builder().guard(headers).build())
}
```

### Hashes for single-page apps

Trunk, Vite and similar bundlers inject an inline bootstrap script into `index.html`. Hash it at startup and keep a strict `script-src`:

```rust
use axum::{Router, response::Html, routing::get};
use securite::headers::src;
use securite::prelude::*;

pub fn spa(index_html: String) -> Router {
    let csp = ContentSecurityPolicy::strict()
        .add_sources("script-src", ContentSecurityPolicy::hashes_for_inline_scripts(&index_html))
        .add_sources("script-src", [src::WASM_UNSAFE_EVAL]); // Rust/WASM front-ends
    Router::new()
        .route("/", get(move || async move { Html(index_html) }))
        .layer(SecurityHeaders::new().csp(csp))
}
```

### A strict-dynamic policy

The nonce-based policy recommended by modern CSP guidance. Browsers that understand nonces ignore `https:` and `'unsafe-inline'`, which only serve as fallbacks for old browsers:

```rust
use securite::headers::src;
use securite::prelude::*;

pub fn policy() -> ContentSecurityPolicy {
    ContentSecurityPolicy::new()
        .script_src([src::STRICT_DYNAMIC, src::HTTPS, src::UNSAFE_INLINE])
        .object_src([src::NONE])
        .base_uri([src::NONE])
        .frame_ancestors([src::NONE])
        .with_nonce()
}
```

### Report-only rollout and Trusted Types

```rust
use securite::prelude::*;

pub fn rollout() -> SecurityHeaders {
    SecurityHeaders::new()
        .csp(
            ContentSecurityPolicy::strict()
                .require_trusted_types()
                .report_to(["csp"])
                .report_only(),
        )
        .set("reporting-endpoints", r#"csp="https://example.com/csp-reports""#)
}
```

Collect violations for a few days, fix them, then remove `report_only()`.

### Relaxing a header on one route

Headers set by a handler win by default, so a single route can opt out:

```rust
use axum::response::{Html, IntoResponse};

// This widget may be framed by a partner site; CSP frame-ancestors overrides X-Frame-Options.
pub async fn widget() -> impl IntoResponse {
    (
        [("content-security-policy", "default-src 'self'; frame-ancestors https://partner.example.com")],
        Html("<p>Embeddable widget</p>"),
    )
}
```

### Custom HSTS and local development

```rust
use std::time::Duration;

use securite::headers::Hsts;
use securite::prelude::*;

pub fn headers(dev: bool) -> SecurityHeaders {
    if dev {
        // Plain-HTTP local development: no HSTS, no upgrade-insecure-requests.
        return SecurityHeaders::new()
            .hsts(None)
            .csp(ContentSecurityPolicy::strict().remove_directive("upgrade-insecure-requests"));
    }
    SecurityHeaders::new().hsts(Some(Hsts {
        max_age: Duration::from_secs(31_536_000), // one year
        include_subdomains: true,
        preload: false,
    }))
}
```

## Standalone layer

```rust
use axum::{Router, routing::get};
use securite::prelude::*;

pub fn app() -> Router {
    Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SecurityHeaders::strict())
}
```

## Pitfalls and tips

> **Warning:** `preload` is hard to undo. Once a domain serves that directive, it can be submitted to the browsers' HSTS preload list, and every subdomain will then be HTTPS-only for months. No preset sends it: enable it only on purpose, as shown in the Hsts section above.

- **Media and payments**: the default `Permissions-Policy` disables `encrypted-media`, `autoplay` and `payment` for your own pages too; passkeys (`publickey-credentials-get`) are not restricted. Override it, for example with `permissions_policy("camera=(), microphone=(), geolocation=(), payment=(self)")`.
- **Framing**: to allow framing by your own pages, change both headers: `.frame_options("SAMEORIGIN")` and `frame_ancestors([src::SELF])` in the CSP.
- **Public assets**: CORP `same-origin` prevents other sites from embedding your images or fonts. A public asset host needs `cross_origin_resource_policy("cross-origin")`.
- **COEP**: `require-corp` in `strict()` blocks cross-origin resources that do not opt in through CORP or CORS. `credentialless` is a softer alternative.
- **Nonces**: `with_nonce()` also nonces `style-src`, so `'unsafe-inline'` is ignored there. Inline `style="…"` attributes need `style_src_attr([src::UNSAFE_INLINE])`. If the policy has no `script-src`, `with_nonce()` adds one made of the `default-src` sources plus the nonce (`script-src 'self' 'nonce-…'` after `default-src 'self'`), so same-origin script files keep loading.
- **Caching**: never let a shared cache store an HTML page that carries a nonce. Static HTML should use hashes instead.
- **Missing extension**: extracting `Extension<CspNonce>` without `with_nonce()` makes axum answer 500.
- **Plain HTTP**: `upgrade-insecure-requests` breaks sub-resources when a site is served over plain HTTP, for instance on a LAN address. Remove it there with `ContentSecurityPolicy::strict().remove_directive("upgrade-insecure-requests")`, as in the local development example above.
- **Overwrite**: handler headers win by default. Use `.overwrite(true)` if no route may weaken the policy.
- **Proxies**: fingerprinting headers are only removed from responses that pass through the layer; a reverse proxy may add its own `Server` header.

> **Tip:** roll out any CSP change with `report_only()` first, then enforce it.

## Related pages

- [CORS](/docs/cors)
- [Cookie hardening](/docs/cookies)
- [HTTPS redirect](/docs/https-redirect)
- [CSRF protection](/docs/csrf)
- [Shield and presets](/docs/shield-presets)
