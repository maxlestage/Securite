---
title: Webhook signatures
summary: Verifies HMAC-SHA256 signatures from GitHub, Stripe, Slack, Shopify or your own senders in constant time, with timestamp-based replay protection.
category: integrity
order: 2
---

A webhook endpoint is a public URL that triggers business actions: marking an invoice as paid, deploying a commit, provisioning an account. Anyone who discovers the URL can post a forged event, so every serious provider signs its payloads with a shared secret. `SignatureLayer` verifies those signatures before your handler runs and hands it the exact body that was signed.

## Threats mitigated

- **A08:2021 Software and Data Integrity Failures**: forged or tampered webhook payloads accepted as genuine (CWE-345, insufficient verification of data authenticity).
- **A07:2021 Identification and Authentication Failures**: the signature proves that the sender knows the shared secret.
- **Replay attacks (CWE-294)**: for timestamped schemes, captured requests are rejected once they are older than the tolerance window.

## How it works

Unlike the other guards, signature verification needs the request body, so it is a dedicated tower layer rather than a shield guard. For each request whose path matches:

1. The body is buffered, up to `max_body` (1 MiB by default). Larger bodies are rejected with `413`, code `body_too_large`.
2. The HMAC-SHA256 of the signed content is computed and compared with the received signature in constant time.
3. For timestamped schemes, the timestamp must be within the tolerance (5 minutes by default, in both directions).
4. Any failure answers `401` with the code `invalid_signature` and the message `Invalid webhook signature.` The precise reason (missing, malformed, expired, mismatch) is logged under the `securite` tracing target with `guard="signature"`, never sent to the client.
5. On success, the request is rebuilt with an identical body and passed to your handler.

## Supported providers

| Constructor | Headers | Signed content | Replay protection |
|---|---|---|---|
| `SignatureVerifier::github(secret)` | `X-Hub-Signature-256: sha256=<hex>` | body | no |
| `SignatureVerifier::stripe(secret)` | `Stripe-Signature: t=<ts>,v1=<hex>` | `<ts>.<body>` | yes |
| `SignatureVerifier::slack(secret)` | `X-Slack-Signature: v0=<hex>` and `X-Slack-Request-Timestamp` | `v0:<ts>:<body>` | yes |
| `SignatureVerifier::shopify(secret)` | `X-Shopify-Hmac-Sha256: <base64>` | body | no |
| `SignatureVerifier::hmac_hex(secret, header, prefix)` | `<header>: <prefix><hex>` | body | no |
| `SignatureVerifier::hmac_base64(secret, header, prefix)` | `<header>: <prefix><base64>` | body | no |
| `SignatureVerifier::hmac_hex_timestamped(secret, header, ts_header, prefix)` | `<header>: <prefix><hex>` and `<ts_header>: <unix seconds>` | `<ts>.<body>` | yes |

For Stripe, every `v1` entry of the header is tried, which keeps working while you roll your endpoint secret. Secrets accept anything that implements `AsRef<[u8]>` (`String`, `&str`, `Vec<u8>`…).

## Quick start

```rust
use securite::prelude::*;
use vitesse::prelude::*;

let secret = std::env::var("GITHUB_WEBHOOK_SECRET").expect("GITHUB_WEBHOOK_SECRET must be set");

let mut app = App::new();
app.middleware(Shield::recommended());
app.middleware(SignatureLayer::new(SignatureVerifier::github(secret)).paths(["/webhooks/github"]));
app.post("/webhooks/github", |req: Request| async move {
    // Only reached when the signature is valid.
    let body = req.text().await?;
    Ok::<_, Error>(format!("received {} bytes", body.len()))
});
```

The shield is added last, so it runs first: rate limiting, IP filtering and header checks happen before any body is buffered.

## Configuration

| Method | Default | Description |
|---|---|---|
| `SignatureLayer::new(verifier)` | every path | Creates the layer. |
| `.paths(prefixes)` | every request | Only verifies these path prefixes (segment boundaries); other requests pass untouched. |
| `SignatureVerifier::tolerance(Duration)` | 5 minutes | Maximum age or clock skew for timestamped schemes. |
| `SignatureVerifier::max_body(usize)` | 1 MiB | Maximum body size buffered for verification. |
| `SignatureVerifier::sign(&[u8])` | — | Hex HMAC-SHA256 of a payload, for tests and outgoing webhooks. |
| `SignatureVerifier::verify(&HeaderMap, &[u8])` | — | Verifies manually; returns `Result<(), SignatureError>`. |

`SignatureError` (in `securite::signature`) has four variants: `Missing`, `Malformed`, `Expired` and `Mismatch`.

## Several providers

Stack one layer per provider, each restricted to its own path:

```rust
use std::time::Duration;

use securite::prelude::*;
use vitesse::prelude::*;

let env = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set"));

async fn size(req: Request) -> Result<String, Error> {
    Ok(req.text().await?.len().to_string())
}

let mut app = App::new();
app.middleware(Shield::recommended());
app.middleware(
    SignatureLayer::new(SignatureVerifier::github(env("GITHUB_WEBHOOK_SECRET")))
        .paths(["/webhooks/github"]),
);
app.middleware(
    SignatureLayer::new(
        SignatureVerifier::stripe(env("STRIPE_WEBHOOK_SECRET"))
            .tolerance(Duration::from_secs(120))
            .max_body(256 * 1024),
    )
    .paths(["/webhooks/stripe"]),
);
app.middleware(
    SignatureLayer::new(SignatureVerifier::slack(env("SLACK_SIGNING_SECRET")))
        .paths(["/webhooks/slack"]),
);
app.post("/webhooks/github", size);
app.post("/webhooks/stripe", size);
app.post("/webhooks/slack", size);
```

## Body requirement

With Vitesse, the middleware reads the body, checks it and gives it back to the request: handlers read it as usual. In a tower service, the layer rebuilds the request from the buffered bytes, so the request body type must implement `http_body::Body` and `From<Bytes>`; hyper's `Incoming` does not, so convert it to a body type that does (a boxed body, for instance) before the layer.

## Testing with `sign()`

`sign()` computes the hex HMAC of exactly the bytes you pass, which makes signed test requests easy to build:

```rust
use securite::prelude::*;
use vitesse::prelude::*;
use vitesse::test::TestClient;

#[tokio::test]
async fn accepts_signed_github_payload() {
    let verifier = SignatureVerifier::github("test-secret");
    let payload = r#"{"action":"opened"}"#;
    let signature = format!("sha256={}", verifier.sign(payload.as_bytes()));

    let mut app = App::new();
    app.middleware(SignatureLayer::new(verifier).paths(["/webhooks/github"]));
    app.post("/webhooks/github", |req: Request| async move { req.text().await });

    let client = TestClient::new(app);
    let response = client
        .post("/webhooks/github")
        .header("x-hub-signature-256", &signature)
        .body(payload)
        .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.text(), payload);
}
```

For timestamped schemes, sign the composed content yourself:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use securite::prelude::*;

let verifier = SignatureVerifier::stripe("whsec_test");
let payload = r#"{"type":"invoice.paid"}"#;
let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

let v1 = verifier.sign(format!("{ts}.{payload}").as_bytes());
let stripe_signature = format!("t={ts},v1={v1}");
// Slack: sign format!("v0:{ts}:{payload}") and send "v0=<hex>".
```

## Signing your own outgoing webhooks

The same type signs the webhooks you send. Share the secret with your customers and give them the matching constructor:

```rust
use std::time::{SystemTime, UNIX_EPOCH};

use securite::prelude::*;

let secret = std::env::var("OUTGOING_WEBHOOK_SECRET").expect("OUTGOING_WEBHOOK_SECRET must be set");
let signer = SignatureVerifier::hmac_hex_timestamped(secret, "x-acme-signature", "x-acme-timestamp", "sha256=");

let body = r#"{"event":"order.shipped","order_id":"ord_8812"}"#;
let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
let signature = format!("sha256={}", signer.sign(format!("{ts}.{body}").as_bytes()));
// Send `body` with the headers x-acme-timestamp: <ts> and x-acme-signature: <signature>.
```

## Replay protection

- Stripe, Slack and `hmac_hex_timestamped` reject timestamps outside the tolerance window, in the past or in the future. A captured request cannot be replayed hours later.
- Within the window, a replay is still possible. Make handlers idempotent and deduplicate on the provider's event identifier: the Stripe event `id`, `X-GitHub-Delivery`, `X-Shopify-Webhook-Id`.
- GitHub, Shopify, `hmac_hex` and `hmac_base64` carry no timestamp: only deduplication protects you against replays.
- Keep your servers synchronised with NTP. A large clock drift turns every legitimate delivery into an `Expired` error.

## Pitfalls and tips

- Do not place a layer that rewrites the body (decompression, transcoding) between the provider and `SignatureLayer`: the signature covers the exact bytes that were sent.
- A wrong secret turns every delivery into a `401`, which `AutoBan` counts as a strike against the provider's IP addresses. Exclude webhook paths with `AutoBan::new().ignore_paths(["/webhooks"])`.
- `ContentTypeGuard::json()`, used by the `api` preset, rejects the form-encoded payloads of Slack slash commands: add `.skip("/webhooks/slack")`. In token mode, `Csrf` must exempt webhook paths with `.exempt("/webhooks")`.
- Signature rejections are not routed through the shield's `on_event` hook and statistics, and are always rendered as problem+json. Watch the `securite` tracing target to catch misconfigurations.
- A verifier holds a single secret. To rotate your own secrets, accept both during the transition, for example by calling `verify` manually with two verifiers.
- `sign()` returns hex. For Shopify or `hmac_base64` tests, base64-encode the raw MAC bytes yourself.

## Related pages

- [Authentication](/docs/auth)
- [Auto-ban](/docs/auto-ban)
- [Content-Type allow-list](/docs/content-type)
- [CSRF protection](/docs/csrf)
- [Body limit](/docs/body-limit)
- [Request IDs](/docs/request-id)
