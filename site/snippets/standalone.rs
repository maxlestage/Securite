use securite::prelude::*;

// Every guard is also a standalone middleware.
app.middleware(Shield::from(SecurityHeaders::api()));
app.middleware(Shield::from(Cors::new().allow_origin("https://app.example.com")));
app.middleware(Shield::from(RateLimit::per_minute(600)));
app.middleware(Shield::from(Waf::new().monitor())); // log only, never block

// Verify GitHub webhooks (HMAC-SHA256, constant time):
app.middleware(
    SignatureLayer::new(SignatureVerifier::github(secret)).paths(["/webhooks/github"]),
);
