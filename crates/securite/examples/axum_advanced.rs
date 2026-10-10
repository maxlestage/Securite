//! A fully customised shield: every middleware configured explicitly.
//!
//! ```sh
//! cargo run --example axum_advanced
//! curl -i http://127.0.0.1:3000/
//! curl -i http://127.0.0.1:3000/admin -H "Authorization: Bearer change-me-please"
//! curl -i http://127.0.0.1:3000/stats
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use axum::extract::{Extension, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use securite::headers::src;
use securite::prelude::*;

#[derive(Clone)]
struct AppState {
    shield: Shield,
    waf: Waf,
}

#[tokio::main]
async fn main() {
    let waf = Waf::new().paranoia(Paranoia::Medium);

    let shield = Shield::builder()
        // Where the client IP comes from (use ClientIpSource::heroku() on Heroku).
        .client_ip(ClientIpSource::Peer)
        .guard(RequestId::new())
        .guard(Hygiene::new().max_query_params(64))
        .guard(MethodFilter::new())
        .guard(HostFilter::new(["example.com", "*.example.com"]).allow_localhost())
        .guard(BodyLimit::new(256 * 1024).route("/upload", 20 * 1024 * 1024))
        .guard(
            Cors::new()
                .allow_origins(["https://app.example.com"])
                .allow_credentials(true)
                .max_age(Duration::from_secs(3600)),
        )
        .guard(
            RateLimit::new(Quota::per_second(20).burst(60))
                .route_methods("/login", [http::Method::POST], Quota::per_minute(5))
                .skip_paths(["/health"]),
        )
        .guard(ConcurrencyLimit::per_ip(32))
        .guard(AutoBan::new().max_strikes(15).count_status(404))
        .guard(BotBlocker::new())
        .guard(waf.clone())
        .guard(Csrf::new().exempt("/webhooks"))
        .guard(
            Auth::bearer()
                .token("admin", "change-me-please")
                .protect(["/admin"]),
        )
        .guard(ContentTypeGuard::new())
        .guard(
            SecurityHeaders::strict().csp(
                ContentSecurityPolicy::strict()
                    .script_src([src::SELF])
                    .img_src([src::SELF, src::DATA, "https://images.example.com"])
                    .with_nonce(),
            ),
        )
        .guard(CookieHardening::new().same_site(SameSite::Strict))
        .on_event(|e| {
            // Ship it to your SIEM / metrics.
            eprintln!(
                "[security] {} {} {} -> {}",
                e.guard, e.code, e.path, e.status
            );
        })
        .build();

    let state = AppState {
        shield: shield.clone(),
        waf,
    };

    let app = Router::new()
        .route(
            "/",
            get(|Extension(nonce): Extension<CspNonce>| async move {
                axum::response::Html(format!(
                    "<h1>Protected</h1><script nonce=\"{}\">console.log('allowed by CSP')</script>",
                    nonce.0
                ))
            }),
        )
        .route("/health", get(|| async { "ok" }))
        .route(
            "/admin",
            get(|Extension(p): Extension<Principal>| async move { format!("hello {}", p.name) }),
        )
        .route(
            "/comment",
            post(|State(s): State<AppState>, body: String| async move {
                // The WAF can also inspect bodies on demand.
                if s.waf.inspect_body(&body).blocked {
                    return (http::StatusCode::FORBIDDEN, "malicious comment");
                }
                (http::StatusCode::CREATED, "saved")
            }),
        )
        .route(
            "/stats",
            get(|State(s): State<AppState>| async move {
                let st = s.shield.stats();
                Json(serde_like(&st))
            }),
        )
        .with_state(state)
        .layer(shield);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("listening on http://{}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Tiny helper so the example does not depend on serde.
fn serde_like(s: &StatsSnapshot) -> std::collections::BTreeMap<&'static str, u64> {
    let mut m = std::collections::BTreeMap::new();
    m.insert("total", s.total);
    m.insert("allowed", s.allowed());
    m.insert("blocked", s.blocked);
    m.insert("monitored", s.monitored);
    for (g, c) in &s.by_guard {
        m.insert(g, *c);
    }
    m
}
