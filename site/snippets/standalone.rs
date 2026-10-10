use securite::prelude::*;

// Every guard is also a standalone tower layer.
let app = Router::new()
    .route("/api", get(api))
    .layer(SecurityHeaders::api())
    .layer(Cors::new().allow_origin("https://app.example.com"))
    .layer(RateLimit::per_minute(600))
    .layer(Waf::new().monitor()); // log only, never block

// Verify GitHub webhooks (HMAC-SHA256, constant time):
let hooks = Router::new()
    .route("/webhooks/github", post(github))
    .layer(SignatureLayer::new(SignatureVerifier::github(secret)));
