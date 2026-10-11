---
title: HTTP hygiene
summary: Reject malformed and ambiguous requests used for request smuggling, path traversal, header injection and parser exhaustion.
category: traffic
order: 5
---

`Hygiene` is a set of cheap protocol sanity checks run on every request head. Legitimate browsers and HTTP clients never trip them; attack tools, smuggling payloads and broken scanners do. It is part of every preset.

## What it protects against

* **HTTP request smuggling** (CL.TE, TE.CL, TE.TE): ambiguous message framing that makes a proxy and your server disagree on where a request ends.
* **Path traversal** (OWASP A01:2021): `../` sequences, raw or percent-encoded, even double-encoded, used to escape a directory.
* **Header and response splitting**: `NUL`, `CR` and `LF` smuggled into the path.
* **Resource exhaustion and HashDoS**: huge URIs, hundreds of headers or thousands of query parameters that stress parsers and hash maps.
* **Host confusion**: several `Host` headers, used for cache poisoning and routing bypasses.

## Request smuggling in a nutshell

HTTP/1.1 has two ways to delimit a body: `Content-Length` (CL) and `Transfer-Encoding: chunked` (TE). When a request carries both, or an obfuscated variant, a front-end proxy and the back-end may each pick a different one. The bytes one of them considers "the rest of the body" are read by the other as the **start of the next request**, which is then attached to another user's connection.

```text
CL.TE: the front-end trusts Content-Length, the back-end trusts Transfer-Encoding

POST / HTTP/1.1
Host: shop.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED

front-end: forwards the 13 body bytes "0\r\n\r\nSMUGGLED"
back-end : chunk "0" ends the body; "SMUGGLED" is prefixed to the next request
```

TE.CL is the mirror image: the front-end follows the chunks while the back-end stops after a small `Content-Length`, and the remaining chunk data becomes a request. TE.TE variants hide the header from one side with values such as `Transfer-Encoding: xchunked`, `chunked, identity` or a duplicated header.

`Hygiene` does not try to guess which interpretation is right: an ambiguous request is refused outright, so there is no disagreement left to exploit.

## Checks and defaults

Checks run in this order; the first failure answers.

| Check | Default | Status | Code |
|---|---|---|---|
| URI length (path and query) | 8 KiB | `414` | `uri_too_long` |
| Number of headers | 100 | `431` | `too_many_headers` |
| Total size of header names and values | 32 KiB | `431` | `headers_too_large` |
| Both `Content-Length` and `Transfer-Encoding` | rejected | `400` | `ambiguous_framing` |
| `Transfer-Encoding` other than a single `chunked` | rejected | `400` | `bad_transfer_encoding` |
| Invalid `Content-Length` (sign, letters, empty value) | rejected | `400` | `bad_content_length` |
| Conflicting `Content-Length` values | rejected | `400` | `bad_content_length` |
| Several `Host` headers | rejected | `400` | `duplicate_host` |
| Control characters in the raw path | rejected | `400` | `bad_path` |
| Malformed percent-encoding in the path | rejected | `400` | `bad_path_encoding` |
| `NUL`, `CR`, `LF` in the decoded path | rejected | `400` | `bad_path` |
| `..` or `.` segments (raw, encoded, double-encoded, `\` separators) | rejected | `400` | `path_traversal` |
| Number of query parameters | 256 | `400` | `too_many_params` |
| `%00` in the query string | rejected | `400` | `bad_query` |

Repeated identical lengths (`Content-Length: 5, 5`) are accepted, as RFC 9110 allows. Dot segments are matched as whole segments: `/files/report..pdf` is fine, `/a/%252e%252e/etc` is not (the path is decoded twice to catch double encoding).

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::builder().guard(Hygiene::new()).build());
app.get("/", |_req: Request| async { "hello" });
```

## Configuration

| Method | Default | Description |
|---|---|---|
| `Hygiene::new()` | – | All checks enabled with the defaults above. |
| `.max_uri_length(bytes)` | `8192` | Maximum URI length (`414 URI Too Long`). |
| `.max_headers(n)` | `100` | Maximum number of request headers (`431`). |
| `.max_header_bytes(bytes)` | `32768` | Maximum cumulated size of header names and values (`431`). |
| `.max_query_params(n)` | `256` | Maximum number of query parameters. |
| `.allow_dot_segments()` | rejected | Accept `..` and `.` path segments (not recommended). |
| `.allow_bad_encoding()` | rejected | Accept malformed percent-encoding in paths. |

The framing, `Host`, control character and `NUL` checks cannot be disabled.

## Examples

### Tighter limits for a JSON API

```rust
use securite::prelude::*;

let hygiene = Hygiene::new()
    .max_uri_length(2 * 1024)
    .max_headers(50)
    .max_header_bytes(16 * 1024)
    .max_query_params(32);

let shield = ShieldBuilder::api()
    .guard(hygiene) // replaces the preset's Hygiene
    .build();
```

### Legacy clients

Some old clients send unescaped `%` signs in paths. Relax only that check, and only if you must:

```rust
use securite::prelude::*;

let hygiene = Hygiene::new().allow_bad_encoding();
```

## Standalone guard

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let mut app = App::new();
app.middleware(Shield::from(Hygiene::new()));
app.get("/", |_req: Request| async { "hello" });
```

## Response headers

`Hygiene` adds no specific header. Rejections use the shield's error format:

```text
HTTP/1.1 400 Bad Request
content-type: application/problem+json
cache-control: no-store

{"type":"about:blank","title":"Bad Request","status":400,"code":"path_traversal","detail":"Dot segments are not allowed."}
```

## Pitfalls and tips

* **Large cookies or tokens**: big JWTs and many cookies can exceed 32 KiB of headers. Raise `max_header_bytes` rather than disabling checks.
* **Search forms and filters** with many fields can exceed `max_query_params`; size it to your largest legitimate form.
* `Hygiene` sees the request after your HTTP server parsed it. It is defence in depth: also keep your proxy and server up to date and configured to reject ambiguous framing.
* With `AutoBan` in the same shield, every hygiene rejection counts as a strike, so persistent offenders end up banned. Across separate standalone layers, `AutoBan` only sees the `400` status: add `count_status(400)` in that case.

> **Tip:** `Hygiene` runs at priority 50, before rate limiting and the WAF. Garbage requests are dropped before any expensive check runs.

## Related pages

* [Body limit](/docs/body-limit)
* [Method filter](/docs/method-filter)
* [Web application firewall](/docs/waf)
* [Auto-ban](/docs/auto-ban)
