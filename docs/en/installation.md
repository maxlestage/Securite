---
title: Installation
summary: Add securite to your project, choose the right features for axum, hyper or tonic, and give the shield the real client IP address.
category: start
order: 2
---

Securite is a regular crates.io package with no native dependencies: no OpenSSL, no C toolchain, no build script to configure.

## Add the crate

```bash
cargo add securite
```

Or declare it by hand in `Cargo.toml`:

```toml
[dependencies]
securite = "0.1"
```

A typical axum application needs:

```toml
[dependencies]
securite = "0.1"
axum = "0.8"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

## Requirements

| Item | Value |
|---|---|
| Current version | 0.1.0 |
| Minimum supported Rust version | 1.85 (edition 2024) |
| License | Proprietary (© Maxime Nathan Lestage, all rights reserved): free to use as a dependency, see [LICENSE](https://maxlestage.github.io/Securite/LICENSE.txt) |
| Unsafe code | None, the crate is `#![forbid(unsafe_code)]` |
| Native dependencies | None (pure Rust) |
| Repository | `https://maxlestage.github.io/Securite/` |

## Cargo features

| Feature | Default | Effect |
|---|---|---|
| `axum` | Enabled | Reads the TCP peer address from axum's `ConnectInfo<SocketAddr>` extension. Pulls `axum` 0.8 with minimal features. |

If you use hyper, tonic or another tower stack without axum, disable the default features:

```toml
[dependencies]
securite = { version = "0.1", default-features = false }
```

> **Tip:** Disabling the `axum` feature only removes the axum dependency. Every guard, preset and layer remains available; the peer address is then read from the `PeerAddr` or `SocketAddr` request extension.

## Expose the client IP

Rate limiting, concurrency limits, auto-ban and IP filtering key their state on the client address, so the shield must know who is connecting.

### axum

Serve the router with `into_make_service_with_connect_info::<SocketAddr>()`:

```rust
use std::net::SocketAddr;

use axum::{Router, routing::get};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        .layer(Shield::recommended());

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(
        listener,
        // Without this, the shield cannot see the client address.
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
```

> **Warning:** With a plain `axum::serve(listener, app)` no client address is known: the per-IP rate limiter falls back to a single bucket shared by every client, and auto-ban and concurrency limits are skipped. The shield logs a warning once, under the `securite` target, to point this out.

> **Warning:** securite reads the `ConnectInfo` type of axum 0.8. If your application depends on another axum major version, insert `PeerAddr` yourself, as in the hyper example below.

### hyper

With a raw hyper 1 server, insert `PeerAddr` into each request before it reaches the shield. Dependencies for this example:

```toml
[dependencies]
securite = { version = "0.1", default-features = false }
hyper = { version = "1", features = ["server", "http1"] }
hyper-util = { version = "0.1", features = ["tokio", "service"] }
http = "1"
http-body-util = "0.1"
bytes = "1"
tower = { version = "0.5", features = ["util"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread", "net"] }
```

```rust
use std::convert::Infallible;

use bytes::Bytes;
use http::{Request, Response};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use securite::prelude::*;
use tower::{ServiceBuilder, service_fn};

async fn hello(_req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    Ok(Response::new(Full::new(Bytes::from_static(b"Hello, secure world!"))))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shield = Shield::recommended();
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;

    loop {
        let (stream, peer) = listener.accept().await?;
        let svc = ServiceBuilder::new()
            // Tell the shield who the client is.
            .map_request(move |mut req: Request<Incoming>| {
                req.extensions_mut().insert(PeerAddr(peer));
                req
            })
            .layer(shield.clone())
            .service(service_fn(hello));

        tokio::spawn(async move {
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), TowerToHyperService::new(svc))
                .await;
        });
    }
}
```

### tonic

tonic records the peer address in its own `TcpConnectInfo` extension, which securite does not read. Add a `map_request` step in front of the shield that copies `remote_addr()` into `PeerAddr`, exactly like the hyper example, then add the shield with `Server::builder().layer(...)`.

### Behind a reverse proxy

Behind Heroku, Cloudflare, Fly.io, a load balancer or Nginx, the TCP peer is the proxy, not the client. Tell the shield which header to trust:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();
```

Set the source on the outermost shield: inner shields and standalone layers reuse the address it resolved. The [Client IP](/docs/client-ip) page explains every source and its spoofing risks.

## Check the setup

This handler echoes the address resolved by the shield. Behind a proxy it must print the visitor's IP, not the proxy's:

```rust
use axum::Extension;
use securite::prelude::*;

async fn whoami(Extension(ClientIp(ip)): Extension<ClientIp>) -> String {
    ip.to_string()
}
```

The `ClientIp` extension only exists when an address could be resolved; otherwise this extractor answers `500`, which makes a misconfiguration obvious during setup. Next step: the [Quick start](/docs/quick-start).
