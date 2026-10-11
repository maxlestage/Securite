//! The response cache: variants, languages, credentials, freshness and, with
//! the `redis` feature, a store shared by several instances.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pratique::prelude::*;
use vitesse::Bytes;
use vitesse::prelude::*;
use vitesse::test::TestClient;

fn counter() -> &'static AtomicUsize {
    Box::leak(Box::new(AtomicUsize::new(0)))
}

#[tokio::test]
async fn each_language_of_locale_gets_its_own_entry() {
    let calls = counter();
    let mut app = App::new();
    app.middleware(Locale::new(["en", "fr"]));
    app.middleware(ResponseCache::new(Duration::from_secs(60)));
    app.get("/", move |req: Request| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        match req.get::<Lang>().map(Lang::as_str) {
            Some("fr") => "Bonjour",
            _ => "Hello",
        }
    });
    let c = TestClient::new(app);
    let fr = || c.get("/").header("accept-language", "fr-CA,fr;q=0.9");
    let en = || c.get("/").header("accept-language", "en-US");
    assert_eq!(fr().await.text(), "Bonjour");
    assert_eq!(en().await.text(), "Hello");
    let hit = fr().await;
    assert_eq!(
        (hit.text().as_str(), hit.header("x-cache")),
        ("Bonjour", Some("HIT"))
    );
    assert_eq!(hit.header("content-language"), Some("fr"));
    // Any `Accept-Language` that negotiates English shares the English entry.
    let hit = c.get("/").header("accept-language", "de, en;q=0.5").await;
    assert_eq!(
        (hit.text().as_str(), hit.header("x-cache")),
        ("Hello", Some("HIT"))
    );
    assert_eq!(c.get("/?lang=fr").await.text(), "Bonjour");
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn vary_headers_split_entries() {
    let calls = counter();
    let mut app = App::new();
    app.middleware(ResponseCache::new(Duration::from_secs(60)));
    app.get("/", move |req: Request| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        let lang = req.header("accept-language").unwrap_or("none").to_owned();
        res::text(lang).header("vary", "Accept-Language")
    });
    app.get("/star", move |_req: Request| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        res::text("x").header("vary", "*")
    });
    let c = TestClient::new(app);
    assert_eq!(
        c.get("/").header("accept-language", "fr").await.text(),
        "fr"
    );
    assert_eq!(
        c.get("/").header("accept-language", "es").await.text(),
        "es"
    );
    assert_eq!(c.get("/").await.text(), "none");
    let hit = c.get("/").header("accept-language", "fr").await;
    assert_eq!(
        (hit.text().as_str(), hit.header("x-cache")),
        ("fr", Some("HIT"))
    );
    let hit = c.get("/").await;
    assert_eq!(
        (hit.text().as_str(), hit.header("x-cache")),
        ("none", Some("HIT"))
    );
    c.get("/star").await;
    assert_eq!(c.get("/star").await.header("x-cache"), Some("MISS"));
    assert_eq!(calls.load(Ordering::SeqCst), 5);
}

#[tokio::test]
async fn credentials_bypass_the_cache() {
    let calls = counter();
    let mut app = App::new();
    app.middleware(ResponseCache::new(Duration::from_secs(60)).bypass_header("x-auth-token"));
    app.get("/me", move |req: Request| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        req.header("x-api-key")
            .or(req.header("x-auth-token"))
            .unwrap_or("anonymous")
            .to_owned()
    });
    let c = TestClient::new(app);
    assert_eq!(
        c.get("/me").header("x-api-key", "alice").await.text(),
        "alice"
    );
    assert_eq!(c.get("/me").header("x-api-key", "bob").await.text(), "bob");
    assert_eq!(
        c.get("/me").header("x-auth-token", "carol").await.text(),
        "carol"
    );
    assert_eq!(
        c.get("/me")
            .header("authorization", "Bearer d")
            .await
            .text(),
        "anonymous"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn max_age_and_conditional_hits() {
    let mut app = App::new();
    app.middleware(ResponseCache::new(Duration::from_secs(60)));
    app.middleware(ETag::new());
    app.get("/short", |_req: Request| async {
        res::text("x").header("cache-control", "public, max-age=1")
    });
    app.get("/zero", |_req: Request| async {
        res::text("x").header("cache-control", "max-age=0")
    });
    let c = TestClient::new(app);
    let first = c.get("/short").await;
    let etag = first.header("etag").unwrap().to_owned();
    let hit = c.get("/short").header("if-none-match", &etag).await;
    assert_eq!(hit.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(hit.header("x-cache"), Some("HIT"));
    assert!(hit.text().is_empty());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(c.get("/short").await.header("x-cache"), Some("MISS"));
    c.get("/zero").await;
    assert_eq!(c.get("/zero").await.header("x-cache"), Some("MISS"));
}

/// A store that always fails, like a Redis that is down.
struct Broken;

impl CacheStore for Broken {
    fn get<'a>(&'a self, _key: &'a str) -> pratique::cache::StoreFuture<'a, Option<Bytes>> {
        Box::pin(async { Err("connection refused".into()) })
    }
    fn set<'a>(
        &'a self,
        _: &'a str,
        _: Bytes,
        _: Duration,
    ) -> pratique::cache::StoreFuture<'a, ()> {
        Box::pin(async { Err("connection refused".into()) })
    }
    fn remove_prefixes<'a>(&'a self, _: &'a [String]) -> pratique::cache::StoreFuture<'a, ()> {
        Box::pin(async { Err("connection refused".into()) })
    }
    fn clear(&self) -> pratique::cache::StoreFuture<'_, ()> {
        Box::pin(async { Err("connection refused".into()) })
    }
}

#[tokio::test]
async fn a_failing_store_is_a_miss() {
    let seen = Arc::new(AtomicUsize::new(0));
    let hook = seen.clone();
    let cache = ResponseCache::new(Duration::from_secs(60))
        .store(Broken)
        .on_error(move |_| {
            hook.fetch_add(1, Ordering::SeqCst);
        });
    let handle = cache.handle();
    let mut app = App::new();
    app.middleware(cache);
    app.get("/", |_req: Request| async { "home" });
    let c = TestClient::new(app);
    let res = c.get("/").await;
    assert_eq!(
        (res.status(), res.text().as_str()),
        (StatusCode::OK, "home")
    );
    assert_eq!(res.header("x-cache"), Some("MISS"));
    // One failed lookup and one failed write.
    assert_eq!(handle.errors(), 2);
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    assert!(handle.clear().await.is_err());
}

/// Redis tests: set `REDIS_URL` (CI runs a Redis service), otherwise they
/// are skipped.
#[cfg(feature = "redis")]
mod redis {
    use super::*;

    fn url() -> Option<String> {
        let url = std::env::var("REDIS_URL").ok();
        if url.is_none() {
            eprintln!("REDIS_URL not set: Redis tests skipped");
        }
        url
    }

    /// One instance of the app, with its own handler counter.
    fn instance(url: &str, prefix: &str) -> (TestClient, CacheHandle, &'static AtomicUsize) {
        let calls = counter();
        let cache = ResponseCache::new(Duration::from_secs(60))
            .store(RedisStore::open(url).unwrap().prefix(prefix));
        let handle = cache.handle();
        let mut app = App::new();
        app.middleware(Locale::new(["en", "fr"]));
        app.middleware(cache);
        app.get("/catalog", move |req: Request| async move {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            format!("{} {n}", req.get::<Lang>().unwrap().as_str())
        });
        app.get("/catalog/:id", move |req: Request| async move {
            calls.fetch_add(1, Ordering::SeqCst);
            req.param("id").unwrap_or("").to_owned()
        });
        (TestClient::new(app), handle, calls)
    }

    #[tokio::test]
    async fn instances_share_one_cache() {
        let Some(url) = url() else { return };
        let prefix = format!("pratique-test:{}:", std::process::id());
        let (a, handle_a, calls_a) = instance(&url, &prefix);
        let (b, handle_b, calls_b) = instance(&url, &prefix);
        handle_a.clear().await.unwrap();

        // Computed by instance A, served by instance B.
        assert_eq!(a.get("/catalog").await.text(), "en 0");
        let hit = b.get("/catalog").await;
        assert_eq!(
            (hit.text().as_str(), hit.header("x-cache")),
            ("en 0", Some("HIT"))
        );
        assert!(hit.header("age").is_some());
        // Each language is a variant.
        assert_eq!(
            b.get("/catalog")
                .header("accept-language", "fr")
                .await
                .text(),
            "fr 0"
        );
        assert_eq!(
            a.get("/catalog?lang=fr").await.header("x-cache"),
            Some("MISS")
        );
        assert_eq!(
            a.get("/catalog")
                .header("accept-language", "fr")
                .await
                .text(),
            "fr 0"
        );
        assert_eq!(a.get("/catalog/7").await.text(), "7");
        assert_eq!(b.get("/catalog/7").await.header("x-cache"), Some("HIT"));
        assert_eq!(
            (
                calls_a.load(Ordering::SeqCst),
                calls_b.load(Ordering::SeqCst)
            ),
            (3, 1)
        );

        // A purge from B reaches A, for the path, its query strings and below.
        handle_b.invalidate("/catalog").await.unwrap();
        assert_eq!(a.get("/catalog").await.header("x-cache"), Some("MISS"));
        assert_eq!(a.get("/catalog/7").await.header("x-cache"), Some("MISS"));
        assert_eq!(handle_a.errors() + handle_b.errors(), 0);
        handle_a.clear().await.unwrap();
    }

    #[tokio::test]
    async fn redis_down_means_handler() {
        // Nothing listens there: every call fails fast and the app answers.
        let store = RedisStore::open("redis://127.0.0.1:1/")
            .unwrap()
            .timeout(Duration::from_millis(100));
        let cache = ResponseCache::new(Duration::from_secs(60)).store(store);
        let handle = cache.handle();
        let mut app = App::new();
        app.middleware(cache);
        app.get("/", |_req: Request| async { "home" });
        let c = TestClient::new(app);
        let start = std::time::Instant::now();
        assert_eq!(c.get("/").await.text(), "home");
        assert_eq!(c.get("/").await.text(), "home");
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "{:?}",
            start.elapsed()
        );
        assert!(handle.errors() >= 2);
    }
}
