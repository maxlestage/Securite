//! Edge cases: middlewares combined, HEAD requests, expiry and eviction.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pratique::prelude::*;
use vitesse::prelude::*;
use vitesse::test::TestClient;

#[tokio::test]
async fn head_requests_share_get_entries_and_tags() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let mut app = App::new();
    app.middleware(ETag::new());
    app.middleware(ResponseCache::new(Duration::from_secs(60)));
    app.get("/", |_req: Request| async {
        CALLS.fetch_add(1, Ordering::SeqCst);
        "home"
    });
    let c = TestClient::new(app);
    // A HEAD miss is not stored.
    assert_eq!(
        c.request(Method::HEAD, "/").await.header("x-cache"),
        Some("MISS")
    );
    let get = c.get("/").await;
    assert_eq!(get.header("x-cache"), Some("MISS"));
    let head = c.request(Method::HEAD, "/").await;
    assert_eq!(head.header("x-cache"), Some("HIT"));
    assert_eq!(head.header("etag"), get.header("etag"));
    // A cached answer still gets its 304 (ETag is outside the cache).
    let etag = get.header("etag").unwrap().to_owned();
    let res = c.get("/").header("if-none-match", &etag).await;
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn entries_expire_and_are_evicted() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let cache = ResponseCache::new(Duration::from_millis(50)).max_entries(2);
    let handle = cache.handle();
    let mut app = App::new();
    app.middleware(cache);
    app.get("/:n", |req: Request| async move {
        CALLS.fetch_add(1, Ordering::SeqCst);
        req.param("n").unwrap_or("").to_owned()
    });
    let c = TestClient::new(app);
    for p in ["/a", "/b", "/c"] {
        c.get(p).await;
    }
    assert_eq!(handle.len(), 2);
    assert_eq!(c.get("/c").await.header("x-cache"), Some("HIT"));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert_eq!(c.get("/c").await.header("x-cache"), Some("MISS"));
    // `Cache-Control: no-cache` from the client refreshes the entry.
    assert_eq!(
        c.get("/c")
            .header("cache-control", "no-cache")
            .await
            .header("x-cache"),
        Some("MISS")
    );
    assert_eq!(CALLS.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn metrics_count_answers_of_inner_middlewares() {
    let metrics = Metrics::new();
    let handle = metrics.handle();
    let mut app = App::new();
    app.middleware(metrics);
    app.middleware(TrailingSlash::trim());
    app.middleware(ETag::new());
    app.get("/x", |_req: Request| async { "x" });
    app.get("/boom", |_req: Request| async {
        panic!("boom");
        #[allow(unreachable_code)]
        ""
    });
    let c = TestClient::new(app);
    c.get("/x/").await; // 308
    let tag = c.get("/x").await.header("etag").unwrap().to_owned(); // 200
    c.get("/x").header("if-none-match", &tag).await; // 304
    assert_eq!(
        c.get("/boom").await.status(),
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(handle.by_class(2), 1);
    assert_eq!(handle.by_class(3), 2);
    assert_eq!(handle.by_class(5), 1);
    assert_eq!(handle.in_flight(), 0);
}

#[tokio::test]
async fn rewrite_keeps_the_query_and_params() {
    let mut app = App::new();
    app.middleware(TrailingSlash::trim().rewrite());
    app.get("/users/:id", |req: Request| async move {
        format!(
            "{} {}",
            req.param("id").unwrap_or("?"),
            req.query("tab").unwrap_or_default()
        )
    });
    let c = TestClient::new(app);
    assert_eq!(c.get("/users/42/?tab=posts").await.text(), "42 posts");
}

#[tokio::test]
async fn maintenance_answers_head_and_writes() {
    let maintenance = Maintenance::new().enabled(true);
    let mut app = App::new();
    app.middleware(maintenance);
    app.post("/", |_req: Request| async { "saved" });
    let c = TestClient::new(app);
    assert_eq!(c.post("/").await.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        c.request(Method::HEAD, "/").await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn locale_reads_encoded_queries_and_cookie_case() {
    let mut app = App::new();
    app.middleware(Locale::new(["en", "pt-BR"]));
    app.get("/", |req: Request| async move {
        req.get::<Lang>().unwrap().0.clone()
    });
    let c = TestClient::new(app);
    assert_eq!(c.get("/?lang=pt%2DBR").await.text(), "pt-BR");
    assert_eq!(
        c.get("/").header("cookie", "a=1; lang=PT-br").await.text(),
        "pt-BR"
    );
}

#[tokio::test]
async fn redirect_rules_dont_loop_or_leak() {
    let mut app = App::new();
    app.middleware(
        Redirects::new()
            .prefix("/", "/v2")
            .permanent("/a", "https://example.com/b"),
    );
    app.get("/v2/x", |_req: Request| async { "x" });
    let c = TestClient::new(app);
    // Exact rules win over prefixes.
    assert_eq!(
        c.get("/a").await.header("location"),
        Some("https://example.com/b")
    );
    assert_eq!(c.get("/x?q=1").await.header("location"), Some("/v2/x?q=1"));
    // The target is under the source prefix: no second hop, no loop.
    assert_eq!(c.get("/v2/x").await.text(), "x");

    let mut app = App::new();
    app.middleware(
        Redirects::new()
            .prefix("/docs", "/docs/v2")
            .prefix("/old", "/"),
    );
    app.get("/docs/v2/a", |_req: Request| async { "a" });
    let c = TestClient::new(app);
    assert_eq!(
        c.get("/docs/a").await.header("location"),
        Some("/docs/v2/a")
    );
    assert_eq!(c.get("/docs/v2/a").await.text(), "a");
    assert_eq!(c.get("/old/page").await.header("location"), Some("/page"));
    assert_eq!(c.get("/old").await.header("location"), Some("/"));
}
