//! End-to-end tests with a real Vitesse application.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use pratique::prelude::*;
use vitesse::prelude::*;
use vitesse::test::{TestClient, TestResponse};

fn header<'a>(res: &'a TestResponse, name: &str) -> &'a str {
    res.header(name).unwrap_or("")
}

fn routes(app: &mut App) {
    app.get("/", |_req: Request| async { "home" });
    app.get("/about", |_req: Request| async { "about" });
    app.get("/json", |_req: Request| async {
        Json(json!({ "big": "x".repeat(2000) }))
    });
    app.get("/private", |_req: Request| async {
        res::text("mine").header("cache-control", "private")
    });
    app.get("/cookie", |_req: Request| async {
        res::text("ok").header("set-cookie", "sid=1")
    });
    app.get("/lang", |req: Request| async move {
        req.get::<Lang>().map(|l| l.0.clone()).unwrap_or_default()
    });
    app.post("/submit", |_req: Request| async { "saved" });
}

fn client(setup: impl FnOnce(&mut App)) -> TestClient {
    let mut app = App::new();
    setup(&mut app);
    routes(&mut app);
    TestClient::new(app)
}

#[tokio::test]
async fn etag_and_304() {
    let c = client(|app| {
        app.middleware(ETag::new());
    });
    let res = c.get("/json").await;
    assert_eq!(res.status(), StatusCode::OK);
    let etag = header(&res, "etag").to_owned();
    assert!(etag.starts_with('"') && etag.ends_with('"'), "{etag}");
    assert_eq!(res.text().len(), 2000 + "{\"big\":\"\"}".len());

    let again = c.get("/json").header("if-none-match", &etag).await;
    assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
    assert!(again.text().is_empty());
    assert_eq!(header(&again, "etag"), etag);

    let other = c.get("/json").header("if-none-match", "\"nope\"").await;
    assert_eq!(other.status(), StatusCode::OK);
    // Writes are left alone.
    assert!(c.post("/submit").await.header("etag").is_none());
}

#[tokio::test]
async fn cache_control_by_route() {
    let c = client(|app| {
        app.middleware(
            CacheControl::new()
                .fallback(CacheControl::NO_CACHE)
                .route("/about", CacheControl::IMMUTABLE),
        );
    });
    assert_eq!(header(&c.get("/").await, "cache-control"), "no-cache");
    assert_eq!(
        header(&c.get("/about").await, "cache-control"),
        CacheControl::IMMUTABLE
    );
    // The handler's own value wins.
    assert_eq!(header(&c.get("/private").await, "cache-control"), "private");
    // Errors are not cached.
    assert!(c.get("/missing").await.header("cache-control").is_none());
}

#[tokio::test]
async fn response_cache_hits_and_purges() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let cache = ResponseCache::new(Duration::from_secs(60));
    let handle = cache.handle();
    let mut app = App::new();
    app.middleware(cache);
    app.get("/count", |_req: Request| async {
        format!("call {}", CALLS.fetch_add(1, Ordering::SeqCst))
    });
    routes(&mut app);
    let c = TestClient::new(app);

    let first = c.get("/count").await;
    assert_eq!(header(&first, "x-cache"), "MISS");
    let second = c.get("/count").await;
    assert_eq!(header(&second, "x-cache"), "HIT");
    assert_eq!(second.text(), first.text());
    assert!(second.header("age").is_some());
    // Another query string is another entry.
    assert_eq!(header(&c.get("/count?page=2").await, "x-cache"), "MISS");
    // Personal requests and responses are never cached.
    assert_eq!(
        header(&c.get("/count").header("cookie", "a=1").await, "x-cache"),
        ""
    );
    c.get("/private").await;
    assert_eq!(header(&c.get("/private").await, "x-cache"), "MISS");
    c.get("/cookie").await;
    assert_eq!(header(&c.get("/cookie").await, "x-cache"), "MISS");
    assert_eq!(handle.len(), 2);

    handle.invalidate("/count");
    assert!(handle.is_empty());
    assert_eq!(c.get("/count").await.text(), "call 3");
}

#[tokio::test]
async fn response_time_headers() {
    let c = client(|app| {
        app.middleware(ResponseTime::new());
    });
    let res = c.get("/").await;
    assert!(header(&res, "x-response-time").ends_with("ms"));
    assert!(header(&res, "server-timing").starts_with("app;dur="));
}

#[tokio::test]
async fn trailing_slash_redirects_or_rewrites() {
    let c = client(|app| {
        app.middleware(TrailingSlash::trim());
    });
    let res = c.get("/about/?x=1").await;
    assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&res, "location"), "/about?x=1");
    assert_eq!(c.get("/about").await.text(), "about");

    let c = client(|app| {
        app.middleware(TrailingSlash::trim().rewrite());
    });
    let res = c.get("/about/").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(res.text(), "about");
}

#[tokio::test]
async fn redirect_rules() {
    let c = client(|app| {
        app.middleware(
            Redirects::new()
                .host("www.example.com", "https://example.com")
                .permanent("/old", "/about")
                .temporary("/sale", "/?promo=1")
                .prefix("/blog", "/articles"),
        );
    });
    let res = c.get("/old?ref=mail").await;
    assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(header(&res, "location"), "/about?ref=mail");

    let res = c.get("/sale?x=1").await;
    assert_eq!(res.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(header(&res, "location"), "/?promo=1");

    assert_eq!(
        header(&c.get("/blog/2024/hello").await, "location"),
        "/articles/2024/hello"
    );
    assert_eq!(header(&c.get("/blog").await, "location"), "/articles");
    assert_eq!(c.get("/blogger").await.status(), StatusCode::NOT_FOUND);

    let res = c
        .get("/about?a=b")
        .header("host", "WWW.example.com:443")
        .await;
    assert_eq!(header(&res, "location"), "https://example.com/about?a=b");
    assert_eq!(
        c.get("/about").header("host", "example.com").await.text(),
        "about"
    );
}

#[tokio::test]
async fn maintenance_mode() {
    let maintenance = Maintenance::new()
        .allow("/about")
        .retry_after(Duration::from_secs(120))
        .html("<h1>Back soon</h1>");
    let switch = maintenance.switch();
    let c = client(|app| {
        app.middleware(maintenance);
    });
    assert_eq!(c.get("/").await.status(), StatusCode::OK);

    switch.on();
    let res = c.get("/").await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header(&res, "retry-after"), "120");
    assert_eq!(header(&res, "cache-control"), "no-store");
    let page = c.get("/").header("accept", "text/html,*/*").await;
    assert_eq!(page.text(), "<h1>Back soon</h1>");
    let api = c.get("/").header("accept", "application/json").await;
    assert_eq!(
        api.json::<serde_json_value::Value>()["error"],
        "maintenance"
    );
    assert_eq!(c.get("/about").await.status(), StatusCode::OK);

    switch.off();
    assert_eq!(c.get("/").await.status(), StatusCode::OK);
}

/// `vitesse::serde_json`, under a name that doesn't clash with the prelude.
mod serde_json_value {
    pub use vitesse::serde_json::Value;
}

#[tokio::test]
async fn health_checks() {
    let up = Arc::new(AtomicBool::new(true));
    let probe = up.clone();
    let c = client(|app| {
        app.middleware(
            Health::new()
                .version("1.2.3")
                .check("database", move || probe.load(Ordering::SeqCst)),
        );
    });
    let res = c.get("/health").await;
    assert_eq!(res.status(), StatusCode::OK);
    assert_eq!(header(&res, "content-type"), "application/health+json");
    let body: serde_json_value::Value = res.json();
    assert_eq!(body["status"], "pass");
    assert_eq!(body["version"], "1.2.3");
    assert_eq!(body["checks"]["database"]["status"], "pass");

    up.store(false, Ordering::SeqCst);
    let res = c.get("/health").await;
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(res.json::<serde_json_value::Value>()["status"], "fail");
    // Other paths go to the routes.
    assert_eq!(c.get("/").await.text(), "home");
}

#[tokio::test]
async fn prometheus_metrics() {
    let metrics = Metrics::new();
    let handle = metrics.handle();
    let c = client(|app| {
        app.middleware(metrics);
    });
    c.get("/").await;
    c.get("/about").await;
    c.get("/missing").await;
    c.post("/submit").await;
    assert_eq!(handle.total(), 4);
    assert_eq!(handle.by_class(2), 3);
    assert_eq!(handle.by_class(4), 1);
    assert_eq!(handle.in_flight(), 0);

    let res = c.get("/metrics").await;
    assert!(header(&res, "content-type").starts_with("text/plain; version=0.0.4"));
    let text = res.text();
    assert!(
        text.contains("http_requests_total{method=\"GET\",status=\"2xx\"} 2\n"),
        "{text}"
    );
    assert!(
        text.contains("http_requests_total{method=\"GET\",status=\"4xx\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("http_requests_total{method=\"POST\",status=\"2xx\"} 1\n"),
        "{text}"
    );
    assert!(
        text.contains("http_request_duration_seconds_count 4\n"),
        "{text}"
    );
    // The endpoint doesn't count itself.
    assert_eq!(handle.total(), 4);
}

#[tokio::test]
async fn access_log_lines() {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let c = client(|app| {
        app.middleware(
            AccessLog::json()
                .skip("/about")
                .to(move |line| sink.lock().unwrap().push(line.to_owned())),
        );
    });
    c.get("/?q=1").header("user-agent", "tests").await;
    c.get("/about").await;
    let lines = lines.lock().unwrap();
    assert_eq!(lines.len(), 1);
    let line: serde_json_value::Value = vitesse::serde_json::from_str(&lines[0]).unwrap();
    assert_eq!(line["ip"], "127.0.0.1");
    assert_eq!(line["method"], "GET");
    assert_eq!(line["path"], "/?q=1");
    assert_eq!(line["status"], 200);
    assert_eq!(line["bytes"], 4);
    assert_eq!(line["user_agent"], "tests");
}

#[tokio::test]
async fn access_log_behind_a_proxy() {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let c = client(|app| {
        app.middleware(
            AccessLog::combined()
                .ip_from_header("x-forwarded-for")
                .to(move |line| sink.lock().unwrap().push(line.to_owned())),
        );
    });
    c.get("/")
        .header("x-forwarded-for", "10.0.0.1, 203.0.113.9")
        .await;
    c.get("/").header("x-forwarded-for", "garbage").await;
    c.get("/").await;
    let lines = lines.lock().unwrap();
    assert!(lines[0].starts_with("203.0.113.9 - - ["), "{}", lines[0]);
    assert!(lines[1].starts_with("127.0.0.1 - - ["), "{}", lines[1]);
    assert!(lines[2].starts_with("127.0.0.1 - - ["), "{}", lines[2]);
    assert!(
        lines[2].contains("\"GET / HTTP/1.1\" 200 4 \"-\" \"-\""),
        "{}",
        lines[2]
    );
}

#[tokio::test]
async fn headers_on_every_response() {
    let c = client(|app| {
        app.middleware(
            SetHeaders::new()
                .set("x-powered-by", "Vitesse")
                .if_missing("cache-control", "no-cache")
                .remove("set-cookie"),
        );
    });
    let res = c.get("/private").await;
    assert_eq!(header(&res, "x-powered-by"), "Vitesse");
    assert_eq!(header(&res, "cache-control"), "private");
    assert_eq!(header(&c.get("/").await, "cache-control"), "no-cache");
    assert!(c.get("/cookie").await.header("set-cookie").is_none());
    assert_eq!(header(&c.get("/missing").await, "x-powered-by"), "Vitesse");
}

#[tokio::test]
async fn locale_negotiation() {
    let c = client(|app| {
        app.middleware(Locale::new(["en", "fr", "es"]));
    });
    let res = c
        .get("/lang")
        .header("accept-language", "fr-CA,fr;q=0.9,en;q=0.5")
        .await;
    assert_eq!(res.text(), "fr");
    assert_eq!(header(&res, "content-language"), "fr");
    assert!(header(&res, "vary").contains("accept-language"));
    assert_eq!(
        c.get("/lang").header("accept-language", "de").await.text(),
        "en"
    );
    assert_eq!(
        c.get("/lang").header("cookie", "lang=es").await.text(),
        "es"
    );
    let forced = c
        .get("/lang?lang=es")
        .header("cookie", "lang=fr")
        .header("accept-language", "fr")
        .await;
    assert_eq!(forced.text(), "es");
    // Unknown values are ignored.
    assert_eq!(c.get("/lang?lang=xx").await.text(), "en");
}

#[tokio::test]
async fn deprecation_headers() {
    let since = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    let c = client(|app| {
        app.middleware(
            Deprecation::since(since)
                .sunset(since + Duration::from_secs(365 * 86_400))
                .link("https://example.com/migrate")
                .only("/about"),
        );
    });
    let res = c.get("/about").await;
    assert_eq!(header(&res, "deprecation"), "@1767225600");
    assert_eq!(header(&res, "sunset"), "Fri, 01 Jan 2027 00:00:00 GMT");
    assert_eq!(
        header(&res, "link"),
        "<https://example.com/migrate>; rel=\"deprecation\"; type=\"text/html\""
    );
    assert!(c.get("/").await.header("deprecation").is_none());
}

#[tokio::test]
async fn everything_together() {
    let c = client(|app| {
        app.middleware(AccessLog::json().to(|_| {}));
        app.middleware(Metrics::new());
        app.middleware(Health::new());
        app.middleware(ResponseTime::new());
        app.middleware(TrailingSlash::trim());
        app.middleware(ETag::new());
        app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
        app.middleware(Locale::new(["en", "fr"]));
    });
    let res = c.get("/about").header("accept-language", "fr").await;
    assert_eq!(res.text(), "about");
    assert!(res.header("etag").is_some());
    assert_eq!(header(&res, "cache-control"), "no-cache");
    assert_eq!(header(&res, "content-language"), "fr");
    assert!(res.header("x-response-time").is_some());
    assert_eq!(c.get("/health").await.status(), StatusCode::OK);
    assert_eq!(
        c.get("/about/").await.status(),
        StatusCode::PERMANENT_REDIRECT
    );
}
