//! The simplest possible setup: one line of security.
//!
//! ```sh
//! cargo run --example axum_basic
//! curl -i "http://127.0.0.1:3000/"
//! curl -i "http://127.0.0.1:3000/?q=1'%20OR%20'1'='1"   # blocked by the WAF
//! ```

use std::net::SocketAddr;

use axum::{Router, routing::get};
use securite::prelude::*;

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(|| async { "Hello, secure world!" }))
        // Security headers, WAF, rate limiting, CSRF, request ids …
        .layer(Shield::recommended());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        // Gives the shield the real client IP.
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
