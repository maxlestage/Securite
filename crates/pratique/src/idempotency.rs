//! `Idempotency-Key`: a request sent again gets the first answer again, as with Stripe's
//! API and the IETF `Idempotency-Key` header draft.
//!
//! A phone loses its network right after tapping "Pay": did the payment go through? The
//! app sends the same `POST` again, with the same `Idempotency-Key`. Without this
//! middleware, the customer pays twice; with it, the second request is not run: it gets the
//! stored answer to the first one, marked `Idempotent-Replayed: true`.
//!
//! ```no_run
//! use pratique::prelude::*;
//! use vitesse::prelude::*;
//!
//! let mut app = App::new();
//! app.middleware(Idempotency::new()); // POST and PATCH carrying an `Idempotency-Key`
//! app.post("/payments", |_req: Request| async { (201, "paid") });
//! ```
//!
//! - The answer is stored for 24 hours (see [`Idempotency::ttl`]), in memory or, to share it
//!   between instances, in Redis ([`Idempotency::store`], like the response cache).
//! - The same key with a different request (another path, another body) is refused with
//!   `422`: a client bug, not a retry.
//! - While the first request runs, the same key gets `409` with `Retry-After: 1`.
//! - Server errors (`5xx`), `408`, `409` and `429` are not stored: the client may retry, and
//!   the retry runs.
//! - Keys are scoped by the client's credentials (`Authorization`, `X-Api-Key`): one client
//!   cannot read another's answers by guessing its key.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use vitesse::http::header::{self, HeaderName, HeaderValue};
use vitesse::{
    Body, BoxFuture, Bytes, IntoResponse, Method, Middleware, Next, Request, Response, StatusCode,
    json,
};

use crate::cache::{CacheStore, MemoryStore, StoreError};
use crate::util::target;

/// Longest key accepted (the IETF draft recommends UUIDs).
const MAX_KEY: usize = 255;

type ErrorHook = dyn Fn(&StoreError) + Send + Sync;

/// The middleware: see the [module documentation](self).
#[derive(Clone)]
pub struct Idempotency {
    header: HeaderName,
    methods: Vec<Method>,
    required: bool,
    ttl: Duration,
    max_body: usize,
    store: Arc<dyn CacheStore>,
    running: Arc<Mutex<HashSet<String>>>,
    on_error: Option<Arc<ErrorHook>>,
}

impl std::fmt::Debug for Idempotency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Idempotency")
            .field("header", &self.header)
            .field("methods", &self.methods)
            .field("required", &self.required)
            .field("ttl", &self.ttl)
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

impl Default for Idempotency {
    fn default() -> Self {
        Self::new()
    }
}

impl Idempotency {
    /// `POST` and `PATCH` requests carrying an `Idempotency-Key`, answers kept 24 hours in
    /// memory.
    pub fn new() -> Self {
        Self {
            header: HeaderName::from_static("idempotency-key"),
            methods: vec![Method::POST, Method::PATCH],
            required: false,
            ttl: Duration::from_secs(24 * 3600),
            max_body: 1024 * 1024,
            store: Arc::new(MemoryStore::new().max_entries(10_000)),
            running: Arc::default(),
            on_error: None,
        }
    }

    /// How long an answer is kept (24 hours by default).
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// The methods it applies to (`POST` and `PATCH` by default; `PUT` and `DELETE` are
    /// idempotent by nature).
    pub fn methods(mut self, methods: impl IntoIterator<Item = Method>) -> Self {
        self.methods = methods.into_iter().collect();
        self
    }

    /// Refuses (`400`) the requests of these methods that carry no key: every client must
    /// send one.
    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    /// Another header than `Idempotency-Key` (`X-Idempotency-Key`, `X-Request-Id`…).
    pub fn header(mut self, name: &str) -> Self {
        self.header = HeaderName::from_bytes(name.as_bytes()).expect("invalid header name");
        self
    }

    /// Largest request body, and largest answer stored, in bytes (1 MiB by default). A
    /// larger body is refused with `413`; a larger answer is sent but not stored.
    pub fn max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    /// Where answers are kept: a [`MemoryStore`] by default, or a
    /// [`RedisStore`](crate::cache::RedisStore) shared by every instance.
    pub fn store(mut self, store: impl CacheStore) -> Self {
        self.store = Arc::new(store);
        self
    }

    /// Called when the store fails (the request then runs as if it had no key).
    pub fn on_error<F>(mut self, f: F) -> Self
    where
        F: Fn(&StoreError) + Send + Sync + 'static,
    {
        self.on_error = Some(Arc::new(f));
        self
    }

    fn error(&self, err: &StoreError) {
        if let Some(hook) = &self.on_error {
            hook(err);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashSet<String>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// FNV-1a: a fingerprint that is the same in every process (answers may be shared through
/// Redis).
fn fnv(parts: &[&[u8]]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for &b in part.iter().chain(&[0xff]) {
            hash ^= u64::from(b);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
    }
    hash
}

fn problem(status: StatusCode, title: &str, detail: &str) -> Response {
    let mut res = Response::new().status(status).json(json!({
        "type": "about:blank",
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    }));
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

fn storable(status: StatusCode) -> bool {
    !status.is_server_error()
        && !status.is_informational()
        && !matches!(status.as_u16(), 408 | 409 | 429)
}

/// Removes the key from the running set, even if the handler panics.
struct Running<'a>(&'a Idempotency, String);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.lock().remove(&self.1);
    }
}

impl Middleware for Idempotency {
    fn handle(&'static self, mut req: Request, next: Next) -> BoxFuture<Response> {
        if !self.methods.contains(req.method()) {
            return next.run(req);
        }
        let key = match req.header(&self.header) {
            Some(key) => key.trim().to_owned(),
            None if self.required => {
                let detail = format!("This request needs an `{}` header.", self.header);
                let res = problem(StatusCode::BAD_REQUEST, "Idempotency key missing", &detail);
                return Box::pin(std::future::ready(res));
            }
            None => return next.run(req),
        };
        if key.is_empty() || key.len() > MAX_KEY || !key.bytes().all(|b| (0x21..0x7f).contains(&b))
        {
            let detail = format!(
                "`{}` must be 1 to {MAX_KEY} visible ASCII characters.",
                self.header
            );
            let res = problem(StatusCode::BAD_REQUEST, "Invalid idempotency key", &detail);
            return Box::pin(std::future::ready(res));
        }
        // Scoped by the client's credentials.
        let credentials = fnv(&[
            req.header(header::AUTHORIZATION).unwrap_or("").as_bytes(),
            req.header("x-api-key").unwrap_or("").as_bytes(),
        ]);
        let slot = format!("idempotency\u{1e}{credentials:016x}\u{1e}{key}");
        let method = req.method().as_str().to_owned();
        let path = target(&req);
        Box::pin(async move {
            let declared = req
                .header("content-length")
                .and_then(|v| v.trim().parse::<usize>().ok());
            if declared.is_some_and(|n| n > self.max_body) {
                return problem(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large", "");
            }
            let body = match req.bytes().await {
                Ok(body) if body.len() <= self.max_body => body,
                Ok(_) => {
                    return problem(StatusCode::PAYLOAD_TOO_LARGE, "Request body too large", "");
                }
                Err(error) => return error.into_response(),
            };
            let fingerprint = fnv(&[method.as_bytes(), path.as_bytes(), &body]);
            req.set_body(body);

            // Taken before looking in the store: two requests with the same key never both run.
            if !self.lock().insert(slot.clone()) {
                let mut res = problem(
                    StatusCode::CONFLICT,
                    "Request in progress",
                    "A request with this idempotency key is still being processed: retry shortly.",
                );
                res.headers_mut()
                    .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
                return res;
            }
            let _running = Running(self, slot.clone());

            match self.store.get(&slot).await {
                Ok(Some(stored)) => {
                    let (print, answer) = stored.split_at(stored.len().min(8));
                    if print != fingerprint.to_be_bytes() {
                        return problem(
                            StatusCode::UNPROCESSABLE_ENTITY,
                            "Idempotency key reused",
                            "This idempotency key was already used for a different request.",
                        );
                    }
                    if let Some(mut res) = crate::cache::decode(&Bytes::copy_from_slice(answer)) {
                        let headers = res.headers_mut();
                        headers.remove("x-cache");
                        headers.remove(header::AGE);
                        headers.insert("idempotent-replayed", HeaderValue::from_static("true"));
                        return res;
                    }
                }
                Ok(None) => {}
                Err(err) => {
                    self.error(&err);
                    return next.run(req).await;
                }
            }

            let mut res = next.run(req).await;
            let small = res.body().size().is_some_and(|n| n <= self.max_body as u64);
            if !storable(res.status_code()) || res.error().is_some() || !small {
                return res;
            }
            let Ok(bytes) = std::mem::take(res.body_mut()).to_bytes().await else {
                res.set_status(StatusCode::INTERNAL_SERVER_ERROR);
                return res;
            };
            if let Some(answer) = crate::cache::encode(&res, &bytes) {
                let mut record = Vec::with_capacity(8 + answer.len());
                record.extend_from_slice(&fingerprint.to_be_bytes());
                record.extend_from_slice(&answer);
                if let Err(err) = self.store.set(&slot, Bytes::from(record), self.ttl).await {
                    self.error(&err);
                }
            }
            *res.body_mut() = Body::from(bytes);
            res
        })
    }
}
