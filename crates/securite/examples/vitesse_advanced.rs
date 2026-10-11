//! A fully customised shield: every middleware configured explicitly.
//!
//! ```sh
//! cargo run --example vitesse_advanced
//! curl -i http://127.0.0.1:3000/
//! curl -i http://127.0.0.1:3000/admin -H "Authorization: Bearer change-me-please"
//! curl -i http://127.0.0.1:3000/stats
//! ```

use std::collections::BTreeMap;
use std::time::Duration;

use securite::headers::src;
use securite::prelude::*;
use vitesse::prelude::*;

fn main() -> std::io::Result<()> {
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
                .route_methods("/login", [Method::POST], Quota::per_minute(5))
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

    let mut app = App::new();
    // Shared with the handlers: `req.state::<Shield>()`, `req.state::<Waf>()`.
    app.state(shield.clone());
    app.state(waf);
    app.middleware(shield);

    app.get("/", |req: Request| async move {
        // The nonce of this response's CSP, for the scripts the page runs.
        let nonce = req
            .get::<CspNonce>()
            .map(|n| n.0.clone())
            .unwrap_or_default();
        Html(format!(
            "<h1>Protected</h1><script nonce=\"{nonce}\">console.log('allowed by CSP')</script>"
        ))
    });
    app.get("/health", |_req: Request| async { "ok" });
    app.get("/admin", |req: Request| async move {
        // Inserted by the `Auth` guard on the paths it protects.
        let who = req
            .get::<Principal>()
            .map_or("nobody".to_string(), |p| p.name.to_string());
        format!("hello {who}")
    });
    app.post("/comment", |req: Request| async move {
        // The WAF can also inspect bodies on demand.
        let body = req.text().await?;
        if req.state::<Waf>().inspect_body(&body).blocked {
            return Err(Error::forbidden("malicious comment"));
        }
        Ok(res::status(201).text("saved"))
    });
    app.get("/stats", |req: Request| async move {
        res::json(counters(&req.state::<Shield>().stats()))
    });

    println!("listening on http://127.0.0.1:3000");
    app.run("127.0.0.1:3000")
}

/// The live counters of the shield, as a flat map.
fn counters(s: &StatsSnapshot) -> BTreeMap<&'static str, u64> {
    let mut m = BTreeMap::new();
    m.insert("total", s.total);
    m.insert("allowed", s.allowed());
    m.insert("blocked", s.blocked);
    m.insert("monitored", s.monitored);
    for (g, c) in &s.by_guard {
        m.insert(g, *c);
    }
    m
}
