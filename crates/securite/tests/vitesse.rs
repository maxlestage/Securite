//! End-to-end tests with a real Vitesse application.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use securite::prelude::*;
use securite::signature::{SignatureLayer, SignatureVerifier};
use vitesse::prelude::*;
use vitesse::test::{TestClient, TestResponse};

/// The test routes behind `shield`. The test client connects from `127.0.0.1`.
fn app(shield: Shield) -> TestClient {
    let mut app = App::new();
    app.middleware(shield);
    routes(&mut app);
    TestClient::new(app)
}

fn routes(app: &mut App) {
    app.get("/", |_req: Request| async { "home" });
    app.get("/ip", |req: Request| async move {
        req.get::<ClientIp>()
            .map_or("unknown".to_string(), |ip| ip.0.to_string())
    });
    app.get("/nonce", |req: Request| async move {
        req.get::<CspNonce>()
            .map(|n| n.0.clone())
            .unwrap_or_default()
    });
    app.post("/submit", |_req: Request| async { "saved" });
    app.get("/secret", |_req: Request| async {
        res::status(401).text("nope")
    });
    app.get("/cookie", |_req: Request| async {
        res::text("ok").header("set-cookie", "sid=abc; Path=/")
    });
}

fn header<'a>(res: &'a TestResponse, name: &str) -> &'a str {
    res.header(name).unwrap_or("")
}

#[tokio::test]
async fn recommended_preset_adds_headers() {
    let client = app(Shield::recommended());
    let res = client.get("/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text(), "home");
    assert_eq!(header(&res, "x-content-type-options"), "nosniff");
    assert_eq!(header(&res, "x-frame-options"), "DENY");
    assert!(header(&res, "content-security-policy").contains("default-src 'self'"));
    assert!(header(&res, "strict-transport-security").starts_with("max-age="));
    assert_eq!(header(&res, "cross-origin-opener-policy"), "same-origin");
    assert!(res.header("x-request-id").is_some());
    assert!(res.header("ratelimit-remaining").is_some());
    // Responses that Vitesse builds itself (here a 404) are decorated too.
    let missing = client.get("/missing").await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    assert_eq!(header(&missing, "x-content-type-options"), "nosniff");
    assert!(missing.header("x-request-id").is_some());
}

#[tokio::test]
async fn the_peer_address_is_the_client_ip() {
    let client = app(Shield::recommended());
    assert_eq!(client.get("/ip").await.text(), "127.0.0.1");
}

#[tokio::test]
async fn waf_blocks_with_problem_json() {
    let client = app(Shield::recommended());
    let res = client
        .get("/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--")
        .await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert_eq!(header(&res, "content-type"), "application/problem+json");
    assert_eq!(header(&res, "cache-control"), "no-store");
    let body = res.text();
    assert!(body.contains("\"code\":\"waf_blocked\""), "{body}");
    assert!(body.contains("\"request_id\""), "{body}");
    // Security headers are added to rejections too.
    assert_eq!(header(&res, "x-content-type-options"), "nosniff");
}

#[tokio::test]
async fn rate_limit_returns_429_per_ip() {
    // Behind a proxy that appends the client to X-Forwarded-For, as on Heroku.
    let shield = Shield::builder()
        .client_ip(ClientIpSource::heroku())
        .guard(RateLimit::new(Quota::per_minute(2)))
        .build();
    let client = app(shield.clone());
    let from = |ip: &str| client.get("/").header("x-forwarded-for", ip);
    for _ in 0..2 {
        assert_eq!(from("10.0.0.1").await.status(), StatusCode::OK);
    }
    let res = from("10.0.0.1").await;
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(header(&res, "retry-after").parse::<u64>().unwrap() >= 1);
    assert_eq!(header(&res, "ratelimit-remaining"), "0");
    // Another client is not affected.
    assert_eq!(from("10.0.0.2").await.status(), StatusCode::OK);

    let stats = shield.stats();
    assert_eq!(stats.total, 4);
    assert_eq!(stats.blocked, 1);
    assert_eq!(stats.by_guard, vec![("rate_limit", 1)]);
    assert!(stats.to_json().contains("\"blocked\":1"));
}

#[tokio::test]
async fn client_ip_from_heroku_router() {
    let shield = Shield::builder()
        .client_ip(ClientIpSource::heroku())
        .build();
    let client = app(shield);
    let res = client
        .get("/ip")
        .header("x-forwarded-for", "6.6.6.6, 203.0.113.50")
        .await;
    assert_eq!(res.text(), "203.0.113.50");
}

#[tokio::test]
async fn csp_nonce_is_shared_with_handlers() {
    let shield = Shield::builder()
        .guard(SecurityHeaders::new().csp(ContentSecurityPolicy::strict().with_nonce()))
        .build();
    let client = app(shield);
    let res = client.get("/nonce").await;
    let nonce = res.text();
    let csp = header(&res, "content-security-policy");
    assert!(!nonce.is_empty());
    assert!(csp.contains(&format!("'nonce-{nonce}'")), "{csp}");
    assert_ne!(client.get("/nonce").await.text(), nonce);
}

#[tokio::test]
async fn csrf_blocks_cross_site_posts() {
    let client = app(Shield::builder().guard(Csrf::new()).build());
    let cross = client
        .post("/submit")
        .header("sec-fetch-site", "cross-site")
        .await;
    assert_eq!(cross.status(), StatusCode::FORBIDDEN);
    let same = client
        .post("/submit")
        .header("sec-fetch-site", "same-origin")
        .await;
    assert_eq!(same.status(), StatusCode::OK);
}

#[tokio::test]
async fn cors_preflight_and_actual_request() {
    let cors = Cors::new()
        .allow_origin("https://app.example.com")
        .allow_credentials(true);
    let client = app(Shield::builder().guard(cors).build());
    let preflight = client
        .request(Method::OPTIONS, "/submit")
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .await;
    assert_eq!(preflight.status(), StatusCode::NO_CONTENT);
    assert!(preflight.bytes().is_empty());
    assert_eq!(
        header(&preflight, "access-control-allow-origin"),
        "https://app.example.com"
    );
    assert_eq!(
        header(&preflight, "access-control-allow-credentials"),
        "true"
    );
    assert!(header(&preflight, "access-control-allow-methods").contains("POST"));

    let evil = client
        .request(Method::OPTIONS, "/submit")
        .header("origin", "https://evil.com")
        .header("access-control-request-method", "POST")
        .await;
    assert_eq!(evil.status(), StatusCode::FORBIDDEN);

    let simple = client.get("/").header("origin", "https://evil.com").await;
    assert_eq!(simple.status(), StatusCode::OK);
    assert!(simple.header("access-control-allow-origin").is_none());
    assert_eq!(header(&simple, "vary"), "origin");
}

#[tokio::test]
async fn auto_ban_after_repeated_failures() {
    let ban = AutoBan::new()
        .max_strikes(3)
        .ban_for(Duration::from_secs(60));
    let shield = Shield::builder()
        .client_ip(ClientIpSource::heroku())
        .guard(ban.clone())
        .build();
    let client = app(shield);
    let attacker = "198.51.100.9";
    for _ in 0..3 {
        let res = client
            .get("/secret")
            .header("x-forwarded-for", attacker)
            .await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }
    let res = client.get("/").header("x-forwarded-for", attacker).await;
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    assert!(res.text().contains("banned"));
    assert!(res.header("retry-after").is_some());
    assert!(ban.is_banned(attacker.parse().unwrap()));
    ban.unban(attacker.parse().unwrap());
    let res = client.get("/").header("x-forwarded-for", attacker).await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn monitor_mode_reports_but_allows() {
    let seen = Arc::new(AtomicUsize::new(0));
    let counter = seen.clone();
    let shield = Shield::builder()
        .guard(Waf::new().monitor())
        .on_event(move |e| {
            assert!(!e.enforced);
            assert_eq!(e.guard, "waf");
            counter.fetch_add(1, Ordering::SeqCst);
        })
        .build();
    let client = app(shield.clone());
    let res = client.get("/?q=%3Cscript%3Ealert(1)%3C/script%3E").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(shield.stats().monitored, 1);
    assert_eq!(shield.stats().blocked, 0);
}

#[tokio::test]
async fn cookies_are_hardened() {
    let client = app(Shield::builder().guard(CookieHardening::new()).build());
    let res = client.get("/cookie").await;
    assert_eq!(
        header(&res, "set-cookie"),
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
}

#[tokio::test]
async fn auth_protects_paths() {
    let auth = Auth::bearer()
        .token("ci", "token-123456")
        .protect(["/submit"]);
    let client = app(Shield::builder().guard(auth).build());
    assert_eq!(client.get("/").await.status(), StatusCode::OK);
    let res = client.post("/submit").await;
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(header(&res, "www-authenticate").starts_with("Bearer"));
    let ok = client
        .post("/submit")
        .header("authorization", "Bearer token-123456")
        .await;
    assert_eq!(ok.status(), StatusCode::OK);
}

#[tokio::test]
async fn hygiene_method_and_body_limit() {
    let client = app(ShieldBuilder::recommended()
        .guard(BodyLimit::new(10))
        .build());
    let res = client.request(Method::TRACE, "/").await;
    assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
    assert!(header(&res, "allow").contains("GET"));
    let res = client
        .post("/submit")
        .header("content-length", "100")
        .body(vec![b'a'; 100])
        .await;
    assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let res = client.get("/static/%2e%2e/%2e%2e/etc/passwd").await;
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn standalone_guards_compose() {
    let mut app = App::new();
    // Each guard is a one-guard shield; the first one added is the outermost.
    app.middleware(Shield::from(SecurityHeaders::strict()));
    app.middleware(Shield::from(RequestId::new()));
    app.middleware(Shield::from(HostFilter::new(["example.com"])));
    app.get("/", |_req: Request| async { "ok" });
    let client = TestClient::new(app);
    let ok = client.get("/").header("host", "example.com").await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(header(&ok, "cross-origin-embedder-policy"), "require-corp");
    assert!(ok.header("x-request-id").is_some());
    let bad = client.get("/").header("host", "evil.com").await;
    assert_eq!(bad.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn a_mounted_router_keeps_its_shield_to_itself() {
    // The host filter protects the site, mounted as a router; the health check,
    // a route of the app itself, stays reachable by IP (as in the docs).
    let mut site = Router::new();
    site.middleware(
        Shield::builder()
            .guard(HostFilter::new(["example.com"]))
            .build(),
    );
    site.get("/", |_req: Request| async { "hello" });
    let mut app = App::new();
    app.get("/healthz", |_req: Request| async { "ok" });
    app.mount("/", site);
    let client = TestClient::new(app);
    assert_eq!(
        client
            .get("/healthz")
            .header("host", "10.0.0.7")
            .await
            .status(),
        StatusCode::OK
    );
    let ok = client.get("/").header("host", "example.com").await;
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(ok.text(), "hello");
    let bad = client.get("/").header("host", "10.0.0.7").await;
    assert_eq!(bad.status(), StatusCode::MISDIRECTED_REQUEST);
    // Unknown addresses under the prefix are filtered too.
    let nope = client.get("/nope").header("host", "10.0.0.7").await;
    assert_eq!(nope.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn https_redirect_behind_proxy() {
    let client = app(Shield::builder().guard(HttpsRedirect::new()).build());
    let res = client
        .get("/path?x=1")
        .header("host", "example.com")
        .header("x-forwarded-proto", "http")
        .await;
    assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&res, "location"), "https://example.com/path?x=1");
    let res = client.get("/").header("x-forwarded-proto", "https").await;
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn webhook_signatures() {
    let verifier = SignatureVerifier::github("secret");
    let sig = verifier.sign(b"{\"ok\":true}");
    let mut app = App::new();
    app.middleware(SignatureLayer::new(verifier).paths(["/hook"]));
    app.post("/hook", |req: Request| async move { req.text().await });
    app.post("/open", |_req: Request| async { "unchecked" });
    let client = TestClient::new(app);
    let good = client
        .post("/hook")
        .header("x-hub-signature-256", &format!("sha256={sig}"))
        .body("{\"ok\":true}")
        .await;
    assert_eq!(good.status(), StatusCode::OK);
    assert_eq!(good.text(), "{\"ok\":true}", "handler still gets the body");
    let bad = client
        .post("/hook")
        .header("x-hub-signature-256", &format!("sha256={sig}"))
        .body("{\"ok\":false}")
        .await;
    assert_eq!(bad.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(header(&bad, "content-type"), "application/problem+json");
    assert!(bad.text().contains("invalid_signature"));
    // Other paths are not checked.
    assert_eq!(client.post("/open").body("x").await.text(), "unchecked");
}

#[tokio::test]
async fn custom_guard_and_error_format() {
    struct NoFridays;
    impl Guard for NoFridays {
        fn name(&self) -> &'static str {
            "no_fridays"
        }
        fn on_request(
            &self,
            req: &mut securite::http::request::Parts,
            _ctx: &mut Context,
        ) -> Result<(), Rejection> {
            if req.headers.contains_key("x-friday") {
                return Err(Rejection::new(
                    StatusCode::IM_A_TEAPOT,
                    "friday",
                    "No deploys on Friday",
                ));
            }
            Ok(())
        }
    }
    let client = app(Shield::builder()
        .guard(NoFridays)
        .error_format(ErrorFormat::PlainText)
        .build());
    let res = client.get("/").header("x-friday", "1").await;
    assert_eq!(res.status(), StatusCode::IM_A_TEAPOT);
    assert_eq!(header(&res, "content-type"), "text/plain; charset=utf-8");
    assert_eq!(res.text(), "418 I'm a teapot: No deploys on Friday\n");
}

#[tokio::test]
async fn presets_have_expected_guards() {
    assert_eq!(
        Shield::recommended().guard_names(),
        [
            "request_id",
            "hygiene",
            "method",
            "body_limit",
            "rate_limit",
            "bot_blocker",
            "waf",
            "csrf",
            "security_headers",
            "cookies"
        ]
    );
    let strict = Shield::strict().guard_names();
    for g in ["https_redirect", "ban", "concurrency", "content_type"] {
        assert!(strict.contains(&g), "{g} missing in strict");
    }
    let api = Shield::api().guard_names();
    assert!(!api.contains(&"csrf"));
    assert!(api.contains(&"content_type"));
    let custom = ShieldBuilder::recommended()
        .without("csrf")
        .build()
        .guard_names();
    assert!(!custom.contains(&"csrf"));
}
