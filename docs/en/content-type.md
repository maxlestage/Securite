---
title: Content-Type allow-list
summary: Rejects request bodies whose media type your service does not expect, closing content-type confusion, CSRF through simple requests and XXE vectors.
category: access
order: 5
---

`ContentTypeGuard` answers `415 Unsupported Media Type` when a request body is declared with a media type you did not allow. It is a cheap, early check that removes whole classes of parser confusion before any handler runs.

## The threat

- **CSRF against JSON endpoints**: browsers send `text/plain`, `application/x-www-form-urlencoded` and `multipart/form-data` cross-site without a CORS preflight. A handler that parses the raw body as JSON, whatever its declared type, can be driven by a hidden form on any website.
- **XML External Entities (XXE)**: an endpoint that negotiates formats may hand an attacker's XML to an XML parser, leading to file disclosure or SSRF.
- **Parser differentials**: a WAF, a proxy and your handler may interpret the same body differently when its type is ambiguous or missing.

The OWASP REST Security Cheat Sheet asks services to validate the request `Content-Type`; see also the OWASP XXE Prevention Cheat Sheet, OWASP Top 10 2021 A05 Security Misconfiguration (which absorbed XXE) and the OWASP API Security Top 10 2023 (API8 Security Misconfiguration).

## How it works

The guard runs at priority 150, after authentication. It only looks at `POST`, `PUT`, `PATCH` and `DELETE` requests that carry a body, and whose path is not skipped. A body is present when the request has a `Content-Length` other than `0` or a `Transfer-Encoding` header; over HTTP/2 and HTTP/3, which need neither header to send a body, a request without `Content-Length` is assumed to carry one.

The media type essence (the part before `;`, lowercased) must match one allowed entry:

- an exact type, such as `application/json`;
- a wildcard subtype, such as `text/*` (or `*/*`, which allows everything);
- a structured-syntax suffix, such as `application/*+json`, which matches `application/problem+json` or `application/merge-patch+json`.

A missing or disallowed `Content-Type` yields `415` with the code `unsupported_media_type`. The offending value is recorded in the event details only.

| `Content-Type` | `json()` | `new()` |
|---|---|---|
| `application/json; charset=utf-8` | allowed | allowed |
| `application/merge-patch+json` | allowed | allowed |
| `application/x-www-form-urlencoded` | 415 | allowed |
| `multipart/form-data; boundary=x` | 415 | allowed |
| `text/plain` | 415 | 415 |
| `application/xml` | 415 | 415 |
| missing | 415 | 415 |

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut app = App::new();
    app.middleware(Shield::builder().guard(ContentTypeGuard::json()).build());
    app.post("/orders", |req: Request| async move { req.text().await });
    app
}
```

`Shield::api()` includes `ContentTypeGuard::json()` and `Shield::strict()` includes `ContentTypeGuard::new()`. The guard is named `content_type`.

## Configuration

| Method | Default | Description |
|---|---|---|
| `ContentTypeGuard::new()` | JSON, `*+json`, URL-encoded and multipart forms | Suited to web applications. |
| `ContentTypeGuard::json()` | `application/json`, `application/*+json` | Suited to JSON APIs. |
| `allow(&str)` | — | Adds a media type (`application/xml`, `text/csv`, `text/*` …). Can be called several times. |
| `skip(prefix)` | none | Path prefix that is not checked. Can be called several times. |
| `is_allowed(&str)` | — | Tells whether a `Content-Type` value, parameters included, is allowed. |

## Examples

### Web application with a CSV import and webhooks

```rust
use securite::prelude::*;

pub fn content_types() -> ContentTypeGuard {
    ContentTypeGuard::new()
        .allow("text/csv") // bulk import endpoint
        .skip("/webhooks") // third-party payloads, verified by signature
}
```

### Testing your configuration

```rust
use securite::prelude::*;

#[test]
fn json_api_accepts_only_json() {
    let guard = ContentTypeGuard::json();
    assert!(guard.is_allowed("application/json; charset=utf-8"));
    assert!(guard.is_allowed("application/merge-patch+json"));
    assert!(!guard.is_allowed("text/plain"));
    assert!(!guard.is_allowed("application/xml"));
}
```

### Checking with curl

```bash
curl -i -X POST https://api.example.com/orders \
  -H "Content-Type: text/plain" \
  --data '{"amount": 10}'
```

```text
HTTP/2 415
content-type: application/problem+json
cache-control: no-store
```

## Standalone guard

Apply the guard to a sub-router only, for example a JSON API mounted next to HTML pages:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

pub fn app() -> App {
    let mut api = Router::new();
    api.middleware(Shield::from(ContentTypeGuard::json()));
    api.post("/orders", |req: Request| async move { req.text().await });

    let mut app = App::new();
    app.get("/", |_req: Request| async { "home" });
    app.mount("/api", api);
    app
}
```

The guard sees the full request path, mount prefix included: write `skip` prefixes as the client sends them (`/api/orders`).

## Pitfalls and tips

> **Warning:** over HTTP/2 and HTTP/3, a `POST`, `PUT`, `PATCH` or `DELETE` without `Content-Length` is checked as if it had a body, so streamed bodies cannot slip through. A body-less request of that kind, such as a `DELETE` sent without `Content-Length: 0` or `Content-Type`, gets `415`: have the client send `Content-Length: 0` or skip the path.

- **Defence in depth**: a handler that parses JSON itself rarely checks the content type first; the guard refuses unexpected types before any body is read, for every route at once.
- `allow()` only adds types. To accept fewer types than `new()`, start from `json()` and add what you need.
- `*/*` or a broad `text/*` defeats the purpose; allow precise types.
- `GET` bodies are not checked; `DELETE` bodies are.
- Multipart uploads are accepted as a whole; the types of individual parts and files still need validation in your code.

> **Tip:** a JSON-only API combined with strict [CORS](/docs/cors) forces every cross-site write through a preflight, which is a strong complement to [CSRF protection](/docs/csrf).

## Related pages

- [CSRF protection](/docs/csrf)
- [CORS](/docs/cors)
- [Host filter](/docs/host-filter)
- [Security headers](/docs/security-headers)
- [Body limit](/docs/body-limit)
- [Webhook signatures](/docs/webhook-signatures)
