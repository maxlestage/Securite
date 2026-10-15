---
title: Signed URLs and tokens
summary: Tamper-proof, expiring, purpose-bound tokens and URLs with HMAC-SHA256 and key rotation, plus a guard that verifies signed links before your handler.
category: integrity
order: 5
---

`Signer` makes values tamper-proof: password-reset and e-mail verification links, unsubscribe links, invitations, temporary download links, or any identifier you hand to a client and must get back unchanged. The `SignedUrls` guard verifies signed links before your handler runs, like Laravel's `signed` middleware.

## Threats mitigated

- **A01:2021 Broken Access Control**: links whose parameters can be edited (`/unsubscribe?user=42` → `user=43`), download links that never expire.
- **A08:2021 Software and Data Integrity Failures**: values round-tripped through the client and trusted without verification (CWE-345, CWE-565).
- **Token confusion**: a token issued for one feature replayed in another; every token is bound to a *purpose*.

## Signed URLs

```rust
use std::time::Duration;
use securite::prelude::*;

let signer = Signer::new(std::env::var("LINK_SECRET").expect("LINK_SECRET must be set"));

// In the e-mail:
let link = signer.sign_url("/downloads/report.pdf?user=42", Some(Duration::from_secs(15 * 60)));
// /downloads/report.pdf?user=42&expires=1767225600&signature=Qm9...
let absolute = format!("https://example.com{link}");

// In the application:
let mut app = App::new();
app.middleware(
    ShieldBuilder::recommended()
        .guard(SignedUrls::new(signer).protect(["/downloads", "/unsubscribe"]))
        .build(),
);
```

On the protected prefixes, a request whose URL was not signed, was modified or has expired gets `403 Forbidden` with the code `invalid_signature` or `expired_signature`.

The signature covers the path and every parameter before it, including `expires`. The `signature` parameter must be the last one: a parameter appended after it (`&admin=1`) invalidates the link. A `#fragment` is kept at the end and not signed, since browsers never send it.

## Tokens

```rust
use std::time::Duration;
use securite::signing::{Signer, TokenError};

let resets = Signer::new(secret).purpose("password-reset");
let token = resets.sign_with_ttl(&user.id.to_string(), Duration::from_secs(3600));

// Later, when the link is opened:
match resets.unsign(&token) {
    Ok(user_id) => { /* show the reset form for user_id */ }
    Err(TokenError::Expired) => { /* ask for a new link */ }
    Err(_) => { /* 400 */ }
}
```

A token is `base64url(payload).expiry.base64url(hmac)`. It is **signed, not encrypted**: anyone can read the payload, so never put secrets in it. For a one-time use (password reset), also include something that changes once the token is used, for example the current password hash's last characters or a counter stored with the user.

## How it works

- HMAC-SHA256 over a domain separator (tokens and URLs can never be swapped), the purpose (length-prefixed) and the signed text.
- Signatures are compared in constant time against every configured key, without early exit.
- The expiry is checked only after the signature: a forged link learns nothing.
- Secrets shorter than 32 bytes are refused at startup.

## Key rotation

```rust
use securite::signing::Signer;

let signer = Signer::new(new_secret)    // signs everything new
    .fallback_key(old_secret);          // still accepted until the old links expire
```

## Configuration

| Method | Description |
|---|---|
| `Signer::new(secret)` | At least 32 bytes (`openssl rand -base64 48`). |
| `.purpose(name)` | Binds tokens and URLs to a use (default `"default"`). |
| `.fallback_key(secret)` | Also verifies with an older secret. |
| `.sign(value)` / `.sign_with_ttl(value, ttl)` / `.sign_bytes(bytes, ttl)` | Tokens. |
| `.unsign(token)` / `.unsign_bytes(token)` | `Result<_, TokenError>` (`Malformed`, `Invalid`, `Expired`). |
| `.sign_url(url, ttl)` | Relative, already percent-encoded URL; panics on `//host` or existing `signature` / `expires` parameters. |
| `.verify_url(path_and_query)` | `Result<(), TokenError>`. |
| `SignedUrls::new(signer)` | Guard; every path until `.protect(prefixes)` narrows it. |
| `.monitor()` | Reports invalid links without blocking. |

## Pitfalls and tips

- Sign the URL exactly as the browser will request it: same path, same encoding, same parameter order. Build it, then sign it, then do not touch it.
- Mail clients and trackers sometimes append `utm_` parameters: keep signed links out of tracked campaigns, or strip them at the edge.
- Use one purpose per feature, and short lifetimes for anything that grants access.
- `SignedUrls` checks integrity, not identity: a signed download link works for whoever has it. Combine with [authentication](/docs/auth) when the user must also be logged in.

## Related pages

- [Webhook signatures](/docs/webhook-signatures)
- [Authorization](/docs/authorization)
- [CSRF protection](/docs/csrf)
