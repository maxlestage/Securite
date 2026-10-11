//! An in-memory cache of whole responses.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use vitesse::http::header::{self, HeaderMap, HeaderValue};
use vitesse::{Body, BoxFuture, Bytes, Method, Middleware, Next, Request, Response, StatusCode};

use crate::util::{normalize_prefix, path_matches};

struct Entry {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    stored: Instant,
    expires: Instant,
}

#[derive(Default)]
struct Store {
    entries: Mutex<HashMap<String, Entry>>,
}

impl Store {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Keeps `GET` responses in memory for a while and answers the next
/// identical requests (same path and query) without running the handler.
///
/// Only shareable responses are stored: status `200`, complete body of known
/// size, no `Set-Cookie`, no `Vary`, no `Content-Encoding`, and no
/// `Cache-Control: private / no-store / no-cache`. Requests carrying
/// `Authorization` or `Cookie` always go to the handler. Responses get
/// `X-Cache: HIT` or `MISS`, and `Age` when they come from the cache.
///
/// Put it *after* a compression middleware, so that it stores the original
/// bytes.
///
/// ```
/// use pratique::prelude::*;
/// use std::time::Duration;
/// use vitesse::prelude::*;
///
/// let cache = ResponseCache::new(Duration::from_secs(30)).only("/api/catalog");
/// let handle = cache.handle(); // e.g. `handle.clear()` after an update
///
/// let mut app = App::new();
/// app.middleware(cache);
/// ```
#[derive(Clone)]
pub struct ResponseCache {
    ttl: Duration,
    max_entries: usize,
    max_body: u64,
    only: Vec<String>,
    store: Arc<Store>,
}

impl std::fmt::Debug for ResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCache")
            .field("ttl", &self.ttl)
            .field("max_entries", &self.max_entries)
            .field("max_body", &self.max_body)
            .field("only", &self.only)
            .finish_non_exhaustive()
    }
}

impl ResponseCache {
    /// Responses live `ttl`; at most 1 000 entries of 1 MiB each.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            max_entries: 1000,
            max_body: 1024 * 1024,
            only: Vec::new(),
            store: Arc::default(),
        }
    }

    /// Maximum number of stored responses.
    pub fn max_entries(mut self, n: usize) -> Self {
        self.max_entries = n;
        self
    }

    /// Largest body stored, in bytes.
    pub fn max_body(mut self, bytes: u64) -> Self {
        self.max_body = bytes;
        self
    }

    /// Only cache under this path prefix (can be called several times).
    /// Default: every path.
    pub fn only(mut self, prefix: impl Into<String>) -> Self {
        self.only.push(normalize_prefix(prefix));
        self
    }

    /// A handle to inspect or purge the cache while the app runs.
    pub fn handle(&self) -> CacheHandle {
        CacheHandle {
            store: self.store.clone(),
        }
    }

    fn cacheable_request(&self, req: &Request) -> bool {
        matches!(*req.method(), Method::GET | Method::HEAD)
            && !req.headers().contains_key(header::AUTHORIZATION)
            && !req.headers().contains_key(header::COOKIE)
            && (self.only.is_empty() || self.only.iter().any(|p| path_matches(req.path(), p)))
    }

    fn cacheable_response(&self, res: &Response) -> bool {
        let headers = res.headers();
        let cache_control = headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(|d| d.trim().to_ascii_lowercase())
            .any(|d| matches!(d.as_str(), "private" | "no-store" | "no-cache"));
        res.status_code() == StatusCode::OK
            && res.error().is_none()
            && !cache_control
            && !headers.contains_key(header::SET_COOKIE)
            && !headers.contains_key(header::VARY)
            && !headers.contains_key(header::CONTENT_ENCODING)
            && res.body().size().is_some_and(|n| n <= self.max_body)
    }

    fn insert(&self, key: String, entry: Entry) {
        let mut entries = self.store.lock();
        if entries.len() >= self.max_entries && !entries.contains_key(&key) {
            let now = Instant::now();
            entries.retain(|_, e| e.expires > now);
            if entries.len() >= self.max_entries {
                let oldest = entries
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| k.clone());
                if let Some(oldest) = oldest {
                    entries.remove(&oldest);
                }
            }
        }
        if self.max_entries > 0 {
            entries.insert(key, entry);
        }
    }

    fn lookup(&self, key: &str) -> Option<Response> {
        let entries = self.store.lock();
        let entry = entries.get(key)?;
        let now = Instant::now();
        if entry.expires <= now {
            return None;
        }
        let mut res = Response::new().status(entry.status);
        *res.headers_mut() = entry.headers.clone();
        *res.body_mut() = Body::from(entry.body.clone());
        let age = now.duration_since(entry.stored).as_secs();
        res.headers_mut()
            .insert(header::AGE, HeaderValue::from(age));
        res.headers_mut()
            .insert("x-cache", HeaderValue::from_static("HIT"));
        Some(res)
    }
}

impl Middleware for ResponseCache {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if !self.cacheable_request(&req) {
            return next.run(req);
        }
        let key = req
            .uri()
            .path_and_query()
            .map_or_else(|| req.path().to_owned(), |pq| pq.as_str().to_owned());
        let refresh = req
            .header(header::CACHE_CONTROL)
            .is_some_and(|v| v.contains("no-cache"));
        if !refresh {
            if let Some(res) = self.lookup(&key) {
                return Box::pin(std::future::ready(res));
            }
        }
        let store = *req.method() == Method::GET;
        Box::pin(async move {
            let mut res = next.run(req).await;
            if store && self.cacheable_response(&res) {
                let Ok(body) = std::mem::take(res.body_mut()).to_bytes().await else {
                    res.set_status(StatusCode::INTERNAL_SERVER_ERROR);
                    return res;
                };
                let now = Instant::now();
                let entry = Entry {
                    status: res.status_code(),
                    headers: res.headers().clone(),
                    body: body.clone(),
                    stored: now,
                    expires: now + self.ttl,
                };
                self.insert(key, entry);
                *res.body_mut() = Body::from(body);
            }
            res.headers_mut()
                .insert("x-cache", HeaderValue::from_static("MISS"));
            res
        })
    }
}

/// Inspects or purges a [`ResponseCache`] while the app runs.
#[derive(Clone)]
pub struct CacheHandle {
    store: Arc<Store>,
}

impl std::fmt::Debug for CacheHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheHandle")
            .field("len", &self.len())
            .finish()
    }
}

impl CacheHandle {
    /// Number of stored responses (expired ones included until evicted).
    pub fn len(&self) -> usize {
        self.store.lock().len()
    }

    /// Whether nothing is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets every response.
    pub fn clear(&self) {
        self.store.lock().clear();
    }

    /// Forgets the responses for `path` (every query string) and below it.
    pub fn invalidate(&self, path: &str) {
        self.store.lock().retain(|key, _| {
            let key_path = key.split('?').next().unwrap_or(key);
            !path_matches(key_path, path)
        });
    }
}
