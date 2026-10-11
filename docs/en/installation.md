---
title: Installation
summary: Add Securite to your project, choose the right features for Vitesse, hyper or tonic, and give the shield the real client IP address.
category: start
order: 2
---

Securite is a regular crates.io package with no native dependencies: no OpenSSL, no C toolchain, no build script to configure.

## Add the crate

```bash
cargo add securite --git https://github.com/maxlestage/Securite
```

Or declare it by hand in `Cargo.toml`:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite" }
```

A typical Vitesse application needs:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite" }
vitesse = { git = "https://github.com/maxlestage/Vitesse" }
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
| `vitesse` | Enabled | The `Shield` and the `SignatureLayer` are Vitesse middlewares: `app.middleware(Shield::recommended())`. Pulls `vitesse` with minimal features. |

If you use hyper, tonic or another tower stack without Vitesse, disable the default features:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite", default-features = false }
```

> **Tip:** Disabling the `vitesse` feature only removes the Vitesse dependency. Every guard, preset and tower layer remains available; the peer address is then read from the `PeerAddr` or `SocketAddr` request extension.

## Expose the client IP

Rate limiting, concurrency limits, auto-ban and IP filtering key their state on the client address, so the shield must know who is connecting.

### Vitesse

Nothing to configure: Vitesse hands the shield the address of each connection.

```rust
use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
    let mut app = App::new();
    // The shield reads the address of each connection: nothing else to do.
    app.middleware(Shield::recommended());
    app.get("/", |_req: Request| async { "Hello, secure world!" });
    app.run(3000)
}
```

> **Warning:** In a tower service without a `PeerAddr` (see below) no client address is known: the per-IP rate limiter falls back to a single bucket shared by every client, and auto-ban and concurrency limits are skipped. The shield logs a warning once, under the `securite` target, to point this out.

### hyper

With a raw hyper 1 server, insert `PeerAddr` into each request before it reaches the shield. Dependencies for this example:

```toml
[dependencies]
securite = { git = "https://github.com/maxlestage/Securite", default-features = false }
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

tonic records the peer address in its own `TcpConnectInfo` extension, which Securite does not read. Add a `map_request` step in front of the shield that copies `remote_addr()` into `PeerAddr`, exactly like the hyper example, then add the shield with `Server::builder().layer(...)`.

### Behind a reverse proxy

Behind Heroku, Cloudflare, Fly.io, a load balancer or Nginx, the TCP peer is the proxy, not the client. Tell the shield which header to trust:

```rust
use securite::prelude::*;

let shield = ShieldBuilder::recommended()
    .client_ip(ClientIpSource::heroku())
    .build();
```

Set the source on the outermost shield: inner shields and standalone guards reuse the address it resolved. The [Client IP](/docs/client-ip) page explains every source and its spoofing risks.

## Check the setup

This handler echoes the address resolved by the shield. Behind a proxy it must print the visitor's IP, not the proxy's:

```rust
use securite::prelude::*;
use vitesse::prelude::*;

async fn whoami(req: Request) -> String {
    match req.get::<ClientIp>() {
        Some(ClientIp(ip)) => ip.to_string(),
        None => "unknown".to_owned(),
    }
}
```

The `ClientIp` value only exists when an address could be resolved: if the handler prints `unknown`, fix the setup before going live. Next step: the [Quick start](/docs/quick-start).
