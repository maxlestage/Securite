//! `Idempotency-Key`: replays, conflicts, reuse with another request, errors not stored.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use pratique::prelude::*;
use vitesse::prelude::*;
use vitesse::test::TestClient;

fn counter() -> &'static AtomicUsize {
    Box::leak(Box::new(AtomicUsize::new(0)))
}

fn app(idempotency: Idempotency, calls: &'static AtomicUsize) -> App {
    let mut app = App::new();
    app.middleware(idempotency);
    app.post("/payments", move |req: Request| async move {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        let body = req.text().await.unwrap_or_default();
        Response::new()
            .status(201)
            .header("x-payment", n.to_string())
            .text(format!("paid {body} #{n}"))
    });
    app.post("/flaky", move |_req: Request| async move {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        if n == 1 {
            Response::new().status(503).text("down")
        } else {
            Response::new().text("ok")
        }
    });
    app.post("/slow", move |_req: Request| async move {
        calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        "done"
    });
    app
}

#[tokio::test]
async fn a_retried_request_gets_the_first_answer_without_running_again() {
    let calls = counter();
    let c = TestClient::new(app(Idempotency::new(), calls));
    let pay = || {
        c.post("/payments")
            .header("idempotency-key", "k-1")
            .body("10€")
    };
    let first = pay().await;
    assert_eq!(
        (first.status().as_u16(), first.text().as_str()),
        (201, "paid 10€ #1")
    );
    assert_eq!(first.header("idempotent-replayed"), None);
    let again = pay().await;
    assert_eq!(
        (again.status().as_u16(), again.text().as_str()),
        (201, "paid 10€ #1")
    );
    assert_eq!(again.header("x-payment"), Some("1"));
    assert_eq!(again.header("idempotent-replayed"), Some("true"));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    // Another key, or no key: runs.
    c.post("/payments")
        .header("idempotency-key", "k-2")
        .body("10€")
        .await;
    c.post("/payments").body("10€").await;
    assert_eq!(calls.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn the_same_key_for_another_request_is_refused() {
    let calls = counter();
    let c = TestClient::new(app(Idempotency::new(), calls));
    c.post("/payments")
        .header("idempotency-key", "k")
        .body("10€")
        .await;
    let other = c
        .post("/payments")
        .header("idempotency-key", "k")
        .body("99€")
        .await;
    assert_eq!(other.status().as_u16(), 422);
    assert_eq!(
        other.header("content-type"),
        Some("application/problem+json")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn server_errors_are_not_stored_so_the_retry_runs() {
    let calls = counter();
    let c = TestClient::new(app(Idempotency::new(), calls));
    let send = || c.post("/flaky").header("idempotency-key", "f");
    assert_eq!(send().await.status().as_u16(), 503);
    let retry = send().await;
    assert_eq!(
        (retry.status().as_u16(), retry.text().as_str()),
        (200, "ok")
    );
    let replay = send().await;
    assert_eq!(
        (replay.text().as_str(), replay.header("idempotent-replayed")),
        ("ok", Some("true"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_key_still_running_gets_409() {
    let calls = counter();
    let c = TestClient::new(app(Idempotency::new(), calls));
    let (a, b) = tokio::join!(
        c.post("/slow").header("idempotency-key", "s").send(),
        async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            c.post("/slow").header("idempotency-key", "s").send().await
        }
    );
    assert_eq!(a.status().as_u16(), 200);
    assert_eq!(
        (b.status().as_u16(), b.header("retry-after")),
        (409, Some("1"))
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn keys_are_scoped_by_credentials_and_can_be_required() {
    let calls = counter();
    let c = TestClient::new(app(Idempotency::new().required(), calls));
    assert_eq!(c.post("/payments").body("1").await.status().as_u16(), 400);
    let bad = c.post("/payments").header("idempotency-key", "a b").await;
    assert_eq!(bad.status().as_u16(), 400);
    let alice = c
        .post("/payments")
        .header("idempotency-key", "same")
        .header("authorization", "Bearer alice")
        .body("1")
        .await;
    let bob = c
        .post("/payments")
        .header("idempotency-key", "same")
        .header("authorization", "Bearer bob")
        .body("1")
        .await;
    assert_eq!(alice.text(), "paid 1 #1");
    assert_eq!(
        (bob.text().as_str(), bob.header("idempotent-replayed")),
        ("paid 1 #2", None)
    );
    // GET is not concerned.
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_body_too_large_is_refused() {
    let calls = counter();
    let c = TestClient::new(app(Idempotency::new().max_body(4), calls));
    let res = c
        .post("/payments")
        .header("idempotency-key", "big")
        .body("123456")
        .await;
    assert_eq!(res.status().as_u16(), 413);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

/// Two instances sharing their answers through Redis: set `REDIS_URL`, otherwise skipped.
#[cfg(feature = "redis")]
#[tokio::test]
async fn instances_share_answers_through_redis() {
    let Ok(url) = std::env::var("REDIS_URL") else {
        eprintln!("REDIS_URL not set: Redis test skipped");
        return;
    };
    let prefix = format!("idem-test-{}:", std::process::id());
    let instance = |calls| {
        let store = RedisStore::open(&url).unwrap().prefix(&prefix);
        TestClient::new(app(Idempotency::new().store(store), calls))
    };
    let (calls_a, calls_b) = (counter(), counter());
    let (a, b) = (instance(calls_a), instance(calls_b));
    let first = a.post("/payments").header("idempotency-key", "shared").body("5").await;
    let again = b.post("/payments").header("idempotency-key", "shared").body("5").await;
    assert_eq!(first.text(), again.text());
    assert_eq!(again.header("idempotent-replayed"), Some("true"));
    assert_eq!((calls_a.load(Ordering::SeqCst), calls_b.load(Ordering::SeqCst)), (1, 0));
}
