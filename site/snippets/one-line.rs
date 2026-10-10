use axum::{routing::get, Router};
use securite::prelude::*;

let app = Router::new()
    .route("/", get(|| async { "Hello, secure world!" }))
    // Headers, WAF, rate limiting, CSRF, request ids…
    .layer(Shield::recommended());
