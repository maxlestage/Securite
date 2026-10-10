//! End-to-end tests with a real axum router.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Extension};
use axum::routing::{get, post};
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use securite::prelude::*;
use securite::signature::{SignatureLayer, SignatureVerifier};
use tower::ServiceExt;

fn app(shield: Shield) -> Router {
    Router::new()
        .route("/", get(|| async { "home" }))
        .route(
            "/ip",
            get(|Extension(ClientIp(ip)): Extension<ClientIp>| async move { ip.to_string() }),
        )
        .route(
            "/nonce",
            get(|Extension(CspNonce(n)): Extension<CspNonce>| async move { n }),
        )
        .route("/submit", post(|| async { "saved" }))
        .route(
            "/secret",
            get(|| async { (StatusCode::UNAUTHORIZED, "nope") }),
        )
        .route(
            "/cookie",
            get(|| async { ([("set-cookie", "sid=abc; Path=/")], "ok") }),
        )
        .layer(shield)
}

fn req(method: &str, uri: &str) -> http::request::Builder {
    Request::builder().method(method).uri(uri)
}

fn with_peer(mut r: Request<Body>, ip: &str) -> Request<Body> {
    let addr: SocketAddr = format!("{ip}:4000").parse().unwrap();
    r.extensions_mut().insert(ConnectInfo(addr));
    r
}

async fn send(app: &Router, r: Request<Body>) -> (StatusCode, http::HeaderMap, String) {
    let res = app.clone().oneshot(r).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, headers, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn recommended_preset_adds_headers() {
    let app = app(Shield::recommended());
    let (status, h, body) = send(
        &app,
        with_peer(req("GET", "/").body(Body::empty()).unwrap(), "1.2.3.4"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "home");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["x-frame-options"], "DENY");
    assert!(
        h["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("default-src 'self'")
    );
    assert!(
        h["strict-transport-security"]
            .to_str()
            .unwrap()
            .starts_with("max-age=")
    );
    assert_eq!(h["cross-origin-opener-policy"], "same-origin");
    assert!(h.contains_key("x-request-id"));
    assert!(h.contains_key("ratelimit-remaining"));
}

#[tokio::test]
async fn waf_blocks_with_problem_json() {
    let app = app(Shield::recommended());
    let r = with_peer(
        req(
            "GET",
            "/?q=1%27%20UNION%20SELECT%20password%20FROM%20users--",
        )
        .body(Body::empty())
        .unwrap(),
        "1.2.3.4",
    );
    let (status, h, body) = send(&app, r).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(h["content-type"], "application/problem+json");
    assert_eq!(h["cache-control"], "no-store");
    assert!(body.contains("\"code\":\"waf_blocked\""), "{body}");
    assert!(body.contains("\"request_id\""), "{body}");
    // Security headers are added to rejections too.
    assert_eq!(h["x-content-type-options"], "nosniff");
}

#[tokio::test]
async fn rate_limit_returns_429_per_ip() {
    let shield = Shield::builder()
        .guard(RateLimit::new(Quota::per_minute(2)))
        .build();
    let app = app(shield.clone());
    for _ in 0..2 {
        let r = with_peer(req("GET", "/").body(Body::empty()).unwrap(), "10.0.0.1");
        assert_eq!(send(&app, r).await.0, StatusCode::OK);
    }
    let r = with_peer(req("GET", "/").body(Body::empty()).unwrap(), "10.0.0.1");
    let (status, h, _) = send(&app, r).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(h["retry-after"].to_str().unwrap().parse::<u64>().unwrap() >= 1);
    assert_eq!(h["ratelimit-remaining"], "0");
    // Another client is not affected.
    let r = with_peer(req("GET", "/").body(Body::empty()).unwrap(), "10.0.0.2");
    assert_eq!(send(&app, r).await.0, StatusCode::OK);

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
    let app = app(shield);
    let r = with_peer(
        req("GET", "/ip")
            .header("x-forwarded-for", "6.6.6.6, 203.0.113.50")
            .body(Body::empty())
            .unwrap(),
        "10.1.2.3",
    );
    assert_eq!(send(&app, r).await.2, "203.0.113.50");
}

#[tokio::test]
async fn csp_nonce_is_shared_with_handlers() {
    let shield = Shield::builder()
        .guard(SecurityHeaders::new().csp(ContentSecurityPolicy::strict().with_nonce()))
        .build();
    let app = app(shield);
    let (_, h, nonce) = send(&app, req("GET", "/nonce").body(Body::empty()).unwrap()).await;
    let csp = h["content-security-policy"].to_str().unwrap();
    assert!(csp.contains(&format!("'nonce-{nonce}'")), "{csp}");
    let (_, _, nonce2) = send(&app, req("GET", "/nonce").body(Body::empty()).unwrap()).await;
    assert_ne!(nonce, nonce2);
}

#[tokio::test]
async fn csrf_blocks_cross_site_posts() {
    let app = app(Shield::builder().guard(Csrf::new()).build());
    let cross = req("POST", "/submit")
        .header("sec-fetch-site", "cross-site")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, cross).await.0, StatusCode::FORBIDDEN);
    let same = req("POST", "/submit")
        .header("sec-fetch-site", "same-origin")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, same).await.0, StatusCode::OK);
}

#[tokio::test]
async fn cors_preflight_and_actual_request() {
    let cors = Cors::new()
        .allow_origin("https://app.example.com")
        .allow_credentials(true);
    let app = app(Shield::builder().guard(cors).build());
    let preflight = req("OPTIONS", "/submit")
        .header("origin", "https://app.example.com")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "content-type")
        .body(Body::empty())
        .unwrap();
    let (status, h, body) = send(&app, preflight).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty());
    assert_eq!(h["access-control-allow-origin"], "https://app.example.com");
    assert_eq!(h["access-control-allow-credentials"], "true");
    assert!(
        h["access-control-allow-methods"]
            .to_str()
            .unwrap()
            .contains("POST")
    );

    let evil = req("OPTIONS", "/submit")
        .header("origin", "https://evil.com")
        .header("access-control-request-method", "POST")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, evil).await.0, StatusCode::FORBIDDEN);

    let simple = req("GET", "/")
        .header("origin", "https://evil.com")
        .body(Body::empty())
        .unwrap();
    let (status, h, _) = send(&app, simple).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!h.contains_key("access-control-allow-origin"));
    assert_eq!(h["vary"], "origin");
}

#[tokio::test]
async fn auto_ban_after_repeated_failures() {
    let ban = AutoBan::new()
        .max_strikes(3)
        .ban_for(Duration::from_secs(60));
    let app = app(Shield::builder().guard(ban.clone()).build());
    for _ in 0..3 {
        let r = with_peer(
            req("GET", "/secret").body(Body::empty()).unwrap(),
            "198.51.100.9",
        );
        assert_eq!(send(&app, r).await.0, StatusCode::UNAUTHORIZED);
    }
    let r = with_peer(req("GET", "/").body(Body::empty()).unwrap(), "198.51.100.9");
    let (status, h, body) = send(&app, r).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(body.contains("banned"));
    assert!(h.contains_key("retry-after"));
    assert!(ban.is_banned("198.51.100.9".parse().unwrap()));
    ban.unban("198.51.100.9".parse().unwrap());
    let r = with_peer(req("GET", "/").body(Body::empty()).unwrap(), "198.51.100.9");
    assert_eq!(send(&app, r).await.0, StatusCode::OK);
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
    let app = app(shield.clone());
    let r = req("GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, r).await.0, StatusCode::OK);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    assert_eq!(shield.stats().monitored, 1);
    assert_eq!(shield.stats().blocked, 0);
}

#[tokio::test]
async fn cookies_are_hardened() {
    let app = app(Shield::builder().guard(CookieHardening::new()).build());
    let (_, h, _) = send(&app, req("GET", "/cookie").body(Body::empty()).unwrap()).await;
    assert_eq!(
        h["set-cookie"],
        "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
    );
}

#[tokio::test]
async fn auth_protects_paths() {
    let auth = Auth::bearer()
        .token("ci", "token-123456")
        .protect(["/submit"]);
    let app = app(Shield::builder().guard(auth).build());
    assert_eq!(
        send(&app, req("GET", "/").body(Body::empty()).unwrap())
            .await
            .0,
        StatusCode::OK
    );
    let (status, h, _) = send(&app, req("POST", "/submit").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(
        h["www-authenticate"]
            .to_str()
            .unwrap()
            .starts_with("Bearer")
    );
    let ok = req("POST", "/submit")
        .header("authorization", "Bearer token-123456")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, ok).await.0, StatusCode::OK);
}

#[tokio::test]
async fn hygiene_method_and_body_limit() {
    let app = app(ShieldBuilder::recommended()
        .guard(BodyLimit::new(10))
        .build());
    let r = req("TRACE", "/").body(Body::empty()).unwrap();
    let (status, h, _) = send(&app, r).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert!(h["allow"].to_str().unwrap().contains("GET"));
    let r = req("POST", "/submit")
        .header("content-length", "100")
        .body(Body::from(vec![b'a'; 100]))
        .unwrap();
    assert_eq!(send(&app, r).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    let r = req("GET", "/static/%2e%2e/%2e%2e/etc/passwd")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, r).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn standalone_layers_compose() {
    let app = Router::new()
        .route("/", get(|| async { "ok" }))
        .layer(SecurityHeaders::strict())
        .layer(RequestId::new())
        .layer(HostFilter::new(["example.com"]));
    let ok = req("GET", "/")
        .header("host", "example.com")
        .body(Body::empty())
        .unwrap();
    let (status, h, _) = send(&app, ok).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h["cross-origin-embedder-policy"], "require-corp");
    assert!(h.contains_key("x-request-id"));
    let bad = req("GET", "/")
        .header("host", "evil.com")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, bad).await.0, StatusCode::MISDIRECTED_REQUEST);
}

#[tokio::test]
async fn https_redirect_behind_proxy() {
    let app = app(Shield::builder().guard(HttpsRedirect::new()).build());
    let r = req("GET", "/path?x=1")
        .header("host", "example.com")
        .header("x-forwarded-proto", "http")
        .body(Body::empty())
        .unwrap();
    let (status, h, _) = send(&app, r).await;
    assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
    assert_eq!(h["location"], "https://example.com/path?x=1");
    let r = req("GET", "/")
        .header("x-forwarded-proto", "https")
        .body(Body::empty())
        .unwrap();
    assert_eq!(send(&app, r).await.0, StatusCode::OK);
}

#[tokio::test]
async fn webhook_signatures() {
    let verifier = SignatureVerifier::github("secret");
    let sig = verifier.sign(b"{\"ok\":true}");
    let app = Router::new()
        .route("/hook", post(|body: String| async move { body }))
        .layer(SignatureLayer::new(verifier).paths(["/hook"]));
    let good = req("POST", "/hook")
        .header("x-hub-signature-256", format!("sha256={sig}"))
        .body(Body::from("{\"ok\":true}"))
        .unwrap();
    let (status, _, body) = send(&app, good).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "{\"ok\":true}", "handler still gets the body");
    let bad = req("POST", "/hook")
        .header("x-hub-signature-256", format!("sha256={sig}"))
        .body(Body::from("{\"ok\":false}"))
        .unwrap();
    assert_eq!(send(&app, bad).await.0, StatusCode::UNAUTHORIZED);
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
            req: &mut http::request::Parts,
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
    let app = app(Shield::builder()
        .guard(NoFridays)
        .error_format(ErrorFormat::PlainText)
        .build());
    let r = req("GET", "/")
        .header("x-friday", "1")
        .body(Body::empty())
        .unwrap();
    let (status, h, body) = send(&app, r).await;
    assert_eq!(status, StatusCode::IM_A_TEAPOT);
    assert_eq!(h["content-type"], "text/plain; charset=utf-8");
    assert_eq!(body, "418 I'm a teapot: No deploys on Friday\n");
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
