//! Regression tests from the review of every middleware. Some requests are
//! sent as raw HTTP over a socket: their targets (`"`, `<`, `\`) are accepted
//! by Vitesse but refused by `http::Uri`, so the test client cannot send them.

use std::net::SocketAddr;

use pratique::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use vitesse::prelude::*;
use vitesse::test::TestClient;
use vitesse::tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serves `app` on a free port.
async fn serve(app: App) -> SocketAddr {
    let server = app.bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr();
    vitesse::tokio::spawn(server.run());
    addr
}

/// Sends `request` (without the final blank line) and returns the raw answer.
async fn raw(addr: SocketAddr, request: &str) -> String {
    let mut stream = vitesse::tokio::net::TcpStream::connect(addr).await.unwrap();
    let request = format!("{request}\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn header<'a>(answer: &'a str, name: &str) -> Option<&'a str> {
    answer
        .split("\r\n\r\n")
        .next()?
        .lines()
        .find_map(|l| {
            l.split_once(": ")
                .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        })
        .map(|(_, v)| v)
}

fn body(answer: &str) -> &str {
    answer.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

#[tokio::test]
async fn raw_targets_are_not_poisoning_the_cache() {
    let mut app = App::new();
    app.middleware(ResponseCache::new(Duration::from_secs(60)));
    app.get("/", |_req: Request| async { "home" });
    app.get("/x", |_req: Request| async { "x" });
    let addr = serve(app).await;
    // `http::Uri` refuses this target: before the fix it was stored as `/`.
    assert_eq!(body(&raw(addr, "GET /x?a=<b> HTTP/1.1").await), "x");
    let home = raw(addr, "GET / HTTP/1.1").await;
    assert_eq!(body(&home), "home");
    let again = raw(addr, "GET /x?a=<b> HTTP/1.1").await;
    assert_eq!(
        (body(&again), header(&again, "x-cache")),
        ("x", Some("HIT"))
    );
}

#[tokio::test]
async fn raw_targets_are_logged_as_sent() {
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = lines.clone();
    let mut app = App::new();
    app.middleware(AccessLog::combined().to(move |l| sink.lock().unwrap().push(l.to_owned())));
    app.get("/secret/x", |_req: Request| async { "x" });
    let addr = serve(app).await;
    raw(addr, "GET /secret/x?q=\"a\" HTTP/1.1").await;
    raw(addr, "HEAD /secret/x HTTP/1.1").await;
    let lines = lines.lock().unwrap();
    assert!(
        lines[0].contains(r#""GET /secret/x?q=\"a\" HTTP/1.1" 200 1 "#),
        "{}",
        lines[0]
    );
    // No body is sent in answer to HEAD: `-`, like Apache.
    assert!(
        lines[1].contains(r#""HEAD /secret/x HTTP/1.1" 200 - "#),
        "{}",
        lines[1]
    );
}

#[tokio::test]
async fn trailing_slash_keeps_raw_queries_and_stays_local() {
    let mut app = App::new();
    app.middleware(TrailingSlash::trim());
    app.get("/search", |_req: Request| async { "search" });
    let addr = serve(app).await;
    let answer = raw(addr, "GET /search/?q=\"x\"&page=2 HTTP/1.1").await;
    assert_eq!(
        header(&answer, "location"),
        Some("/search?q=%22x%22&page=2")
    );
    let answer = raw(addr, "GET /\\evil.example/ HTTP/1.1").await;
    assert_eq!(header(&answer, "location"), Some("/evil.example"));
    // `OPTIONS *` is not a path.
    let answer = raw(addr, "OPTIONS * HTTP/1.1").await;
    assert_eq!(header(&answer, "location"), None);

    let mut app = App::new();
    app.middleware(TrailingSlash::trim().rewrite());
    app.get("/search", |req: Request| async move {
        req.query("q").unwrap_or_default().into_owned()
    });
    let addr = serve(app).await;
    assert_eq!(
        body(&raw(addr, "GET /search/?q=\"x\" HTTP/1.1").await),
        "\"x\""
    );
}

#[tokio::test]
async fn prefix_redirects_stay_on_the_site() {
    let mut app = App::new();
    app.middleware(
        Redirects::new()
            .prefix("/old", "/")
            .prefix("/blog", "/articles"),
    );
    let addr = serve(app).await;
    let answer = raw(addr, "GET /old//evil.example HTTP/1.1").await;
    assert_eq!(header(&answer, "location"), Some("/evil.example"));
    let answer = raw(addr, "GET /old/\\evil.example HTTP/1.1").await;
    assert_eq!(header(&answer, "location"), Some("/evil.example"));
    let answer = raw(addr, "GET /blog/a?q=\"x\" HTTP/1.1").await;
    assert_eq!(header(&answer, "location"), Some("/articles/a?q=%22x%22"));
}

#[tokio::test]
async fn locale_cookie_is_in_vary_and_vary_stays_one_line() {
    let mut app = App::new();
    app.middleware(Locale::new(["en", "fr"]));
    app.get("/", |_req: Request| async {
        res::text("x").header("vary", "Origin")
    });
    let c = TestClient::new(app);
    let res = c.get("/").header("cookie", "lang=fr").await;
    assert_eq!(res.header("content-language"), Some("fr"));
    let vary: Vec<_> = res.headers().get_all("vary").iter().collect();
    assert_eq!(vary, ["Origin, accept-language, cookie"]);

    let mut app = App::new();
    app.middleware(Locale::new(["en", "fr"]).cookie(None));
    app.get("/", |_req: Request| async { "x" });
    let c = TestClient::new(app);
    assert_eq!(c.get("/").await.header("vary"), Some("accept-language"));
}

#[tokio::test]
async fn temporary_redirects_are_not_cached_for_a_year() {
    let mut app = App::new();
    app.middleware(CacheControl::new().route("/assets", CacheControl::IMMUTABLE));
    app.get("/assets/latest.js", |_req: Request| async {
        Redirect::to("/assets/app.3f9a.js")
    });
    app.get("/assets/old.js", |_req: Request| async {
        Redirect::permanent("/assets/app.3f9a.js")
    });
    app.get("/assets/app.3f9a.js", |_req: Request| async { "js" });
    let c = TestClient::new(app);
    assert_eq!(
        c.get("/assets/latest.js").await.header("cache-control"),
        None
    );
    let permanent = c.get("/assets/old.js").await;
    assert_eq!(permanent.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(
        permanent.header("cache-control"),
        Some(CacheControl::IMMUTABLE)
    );
    assert_eq!(
        c.get("/assets/app.3f9a.js").await.header("cache-control"),
        Some(CacheControl::IMMUTABLE)
    );
}

#[tokio::test]
async fn if_none_match_over_several_lines() {
    let mut app = App::new();
    app.middleware(ETag::new());
    app.get("/", |_req: Request| async { "home" });
    let c = TestClient::new(app);
    let etag = c.get("/").await.header("etag").unwrap().to_owned();
    let res = c
        .get("/")
        .header("if-none-match", "\"zzz\"")
        .header("if-none-match", &etag)
        .await;
    assert_eq!(res.status(), StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn metrics_and_health_answer_head_and_a_final_slash() {
    let metrics = Metrics::new();
    let handle = metrics.handle();
    let mut app = App::new();
    app.middleware(metrics);
    app.middleware(Health::new());
    let c = TestClient::new(app);
    assert_eq!(
        c.request(Method::HEAD, "/metrics").await.status(),
        StatusCode::OK
    );
    assert_eq!(c.get("/metrics/").await.status(), StatusCode::OK);
    assert_eq!(c.get("/health/").await.status(), StatusCode::OK);
    // The endpoint isn't counted; the health probe is.
    assert_eq!(handle.total(), 1);
    let text = c.get("/metrics").await.text();
    let sum: f64 = text
        .lines()
        .find_map(|l| l.strip_prefix("http_request_duration_seconds_sum "))
        .unwrap()
        .parse()
        .unwrap();
    assert!(sum > 0.0, "{text}");
}

#[tokio::test]
async fn trailing_slash_except_static_directories() {
    let dir = std::env::temp_dir().join(format!("pratique-site-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("docs")).unwrap();
    std::fs::write(dir.join("docs/index.html"), "<h1>docs</h1>").unwrap();
    let mut app = App::new();
    app.middleware(TrailingSlash::trim().except("/site"));
    app.static_dir("/site", &dir);
    let c = TestClient::new(app);
    let res = c.get("/site/docs").await;
    assert!(res.status().is_redirection());
    let to = res.header("location").unwrap().to_owned();
    assert_eq!(c.get(&to).await.text(), "<h1>docs</h1>");
    std::fs::remove_dir_all(dir).ok();
}
