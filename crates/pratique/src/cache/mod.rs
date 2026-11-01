//! A cache of whole responses, in memory or shared through Redis.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vitesse::http::header::{self, HeaderMap, HeaderName, HeaderValue};
use vitesse::{Body, BoxFuture, Bytes, Method, Middleware, Next, Request, Response, StatusCode};

use crate::etag::none_match;
use crate::locale::Lang;
use crate::util::{normalize_prefix, path_matches, target};

#[cfg(feature = "redis")]
mod redis_store;
mod store;

#[cfg(feature = "redis")]
#[cfg_attr(docsrs, doc(cfg(feature = "redis")))]
pub use redis_store::RedisStore;
pub use store::{CacheStore, MemoryStore, StoreError, StoreFuture};

/// Separates a path from its `Vary` record in the store keys.
const SPEC: char = '\u{1e}';
/// Separates a path from the variant of a response in the store keys.
const VARIANT: char = '\u{1f}';
/// Longest variant kept in a key: beyond, the request is not cached.
const MAX_VARIANT: usize = 1024;

/// Headers that belong to one exchange, not to the stored response.
const PER_REQUEST: [&str; 9] = [
    "age",
    "connection",
    "content-length",
    "date",
    "server-timing",
    "transfer-encoding",
    "x-cache",
    "x-request-id",
    "x-response-time",
];

type ErrorHook = dyn Fn(&StoreError) + Send + Sync;

#[derive(Debug, Default)]
struct Stats {
    hits: AtomicU64,
    misses: AtomicU64,
    errors: AtomicU64,
}

/// Keeps `GET` responses for a while and answers the next identical requests
/// without running the handler: in the memory of the process by default, or
/// in Redis with [`store`](ResponseCache::store) so that every instance of the
/// app shares one cache.
///
/// **What is stored.** Status `200`, complete body of known size, no
/// `Set-Cookie`, no `Cache-Control: private / no-store / no-cache`, no
/// `Vary: *`, no CSP nonce. A `max-age` or `s-maxage` shorter than the
/// cache's TTL wins; an invalid one means "don't store".
///
/// **Which requests use it.** `GET` and `HEAD` without credentials:
/// `Authorization`, `Proxy-Authorization`, `Cookie` and `X-Api-Key` (add
/// others with [`bypass_header`](ResponseCache::bypass_header)) always go to
/// the handler, and so does `Cache-Control: no-store`. Restrict the cache to
/// public endpoints with [`only`](ResponseCache::only).
///
/// **Variants.** The key is the path and the query string as sent, the site
/// (`Host`, `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Proto`) and the
/// CORS `Origin`, the headers named by the response's `Vary`
/// (`Accept-Encoding`, `Accept-Language` …), and the language chosen by a
/// [`Locale`](crate::locale::Locale) middleware added before the cache, so
/// each language gets its own entry.
///
/// **Order.** Add `Locale`, CORS and Securite's `Shield` before the cache,
/// and `CacheControl`, `ETag` or `SetHeaders` after it, so that it sees the
/// `Cache-Control: private` they set.
///
/// Answers carry `X-Cache: HIT` or `MISS`, and `Age` on hits; a hit answers
/// `304` itself when `If-None-Match` matches the stored `ETag`. When the store
/// fails (Redis down), requests go to the handler: the error is counted and
/// passed to [`on_error`](ResponseCache::on_error). A response computed while
/// a purge ran is not stored after it.
///
/// ```
/// use pratique::prelude::*;
/// use std::time::Duration;
/// use vitesse::prelude::*;
///
/// let cache = ResponseCache::new(Duration::from_secs(30)).only("/api/catalog");
/// let handle = cache.handle(); // `handle.invalidate("/api/catalog").await` after an update
///
/// let mut app = App::new();
/// app.middleware(cache);
/// ```
#[derive(Clone)]
pub struct ResponseCache {
    ttl: Duration,
    max_body: u64,
    only: Vec<String>,
    bypass: Vec<HeaderName>,
    store: Arc<dyn CacheStore>,
    stats: Arc<Stats>,
    /// Bumped by every purge: a response computed before a purge is not
    /// stored after it.
    epoch: Arc<AtomicU64>,
    on_error: Option<Arc<ErrorHook>>,
}

impl std::fmt::Debug for ResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCache")
            .field("ttl", &self.ttl)
            .field("max_body", &self.max_body)
            .field("only", &self.only)
            .field("bypass", &self.bypass)
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl ResponseCache {
    /// Responses live `ttl`, bodies up to 1 MiB, in a [`MemoryStore`] of
    /// 1 000 entries.
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl: ttl.min(store::MAX_TTL),
            max_body: 1024 * 1024,
            only: Vec::new(),
            bypass: [
                "authorization",
                "proxy-authorization",
                "cookie",
                "x-api-key",
            ]
            .into_iter()
            .map(HeaderName::from_static)
            .collect(),
            store: Arc::new(MemoryStore::new()),
            stats: Arc::default(),
            epoch: Arc::default(),
            on_error: None,
        }
    }

    /// Where the responses are kept: a [`MemoryStore`] with other limits, a
    /// [`RedisStore`] shared by every instance, or your own [`CacheStore`].
    pub fn store(mut self, store: impl CacheStore) -> Self {
        self.store = Arc::new(store);
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

    /// Requests carrying this header always go to the handler (a custom
    /// credential such as `X-Auth-Token`).
    ///
    /// # Panics
    /// If `name` is not a valid header name.
    pub fn bypass_header(mut self, name: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("invalid header name");
        if !self.bypass.contains(&name) {
            self.bypass.push(name);
        }
        self
    }

    /// Called when the store fails (the request is served by the handler).
    pub fn on_error<F>(mut self, f: F) -> Self
    where
        F: Fn(&StoreError) + Send + Sync + 'static,
    {
        self.on_error = Some(Arc::new(f));
        self
    }

    /// A handle to purge the cache and read its counters while the app runs.
    pub fn handle(&self) -> CacheHandle {
        CacheHandle {
            store: self.store.clone(),
            stats: self.stats.clone(),
            epoch: self.epoch.clone(),
        }
    }

    fn cacheable_request(&self, req: &Request) -> bool {
        let no_store = req
            .header_all("cache-control")
            .any(|v| v.to_ascii_lowercase().contains("no-store"));
        matches!(*req.method(), Method::GET | Method::HEAD)
            && !no_store
            && !self.bypass.iter().any(|h| req.headers().contains_key(h))
            && (self.only.is_empty() || self.only.iter().any(|p| path_matches(req.path(), p)))
    }

    /// How long `res` may be stored, if it may.
    fn freshness(&self, res: &Response) -> Option<Duration> {
        let headers = res.headers();
        if res.status_code() != StatusCode::OK
            || res.error().is_some()
            || headers.contains_key(header::SET_COOKIE)
            || !res.body().size().is_some_and(|n| n <= self.max_body)
        {
            return None;
        }
        // A page carrying a CSP nonce must get a fresh nonce on every answer.
        let nonce = headers
            .get_all(header::CONTENT_SECURITY_POLICY)
            .iter()
            .any(|v| {
                v.as_bytes()
                    .windows(7)
                    .any(|w| w.eq_ignore_ascii_case(b"'nonce-"))
            });
        if nonce {
            return None;
        }
        let mut max_age: Option<u64> = None;
        let mut s_maxage: Option<u64> = None;
        for directive in list(headers, &header::CACHE_CONTROL) {
            let (name, value) = directive
                .split_once('=')
                .map_or((directive.as_str(), ""), |(n, v)| (n.trim(), v.trim()));
            // An invalid age (`-1`, `10.5`) means stale (RFC 9111 §1.2.2),
            // and repeated directives keep the shortest age.
            let seconds = |previous: Option<u64>| {
                let secs = value.trim_matches('"').parse::<u64>().ok()?;
                Some(previous.map_or(secs, |p| p.min(secs)))
            };
            match name {
                "private" | "no-store" | "no-cache" => return None,
                "max-age" => max_age = Some(seconds(max_age)?),
                "s-maxage" => s_maxage = Some(seconds(s_maxage)?),
                _ => {}
            }
        }
        let ttl = match s_maxage.or(max_age) {
            Some(secs) => self.ttl.min(Duration::from_secs(secs)),
            None => self.ttl,
        };
        (!ttl.is_zero()).then_some(ttl)
    }

    fn error(&self, err: &StoreError) {
        self.stats.errors.fetch_add(1, Ordering::Relaxed);
        if let Some(hook) = &self.on_error {
            hook(err);
        }
    }

    /// The stored response for this request, if any.
    async fn lookup(
        &self,
        primary: &str,
        headers: &HeaderMap,
        lang: Option<&str>,
    ) -> Result<Option<Response>, StoreError> {
        let Some(spec) = self.store.get(&format!("{primary}{SPEC}")).await? else {
            return Ok(None);
        };
        let names = std::str::from_utf8(&spec).unwrap_or("");
        let names: Vec<&str> = names.split(',').filter(|n| !n.is_empty()).collect();
        let Some(variant) = variant(&names, headers, lang) else {
            return Ok(None);
        };
        let entry = self
            .store
            .get(&format!("{primary}{VARIANT}{variant}"))
            .await?;
        Ok(entry.and_then(|bytes| decode(&bytes)))
    }

    /// The two records that store `res` (whose body is `body`) for the
    /// request it answers: its `Vary` record and the response itself.
    fn records(
        &self,
        primary: &str,
        headers: &HeaderMap,
        lang: Option<&str>,
        res: &Response,
        body: &Bytes,
    ) -> Option<[(String, Bytes); 2]> {
        let names = vary(res.headers())?;
        // A body encoded for this client only fits clients sending the same
        // `Accept-Encoding`.
        if res.headers().contains_key(header::CONTENT_ENCODING)
            && !names.iter().any(|n| n == "accept-encoding")
        {
            return None;
        }
        let names_ref: Vec<&str> = names.iter().map(String::as_str).collect();
        let variant = variant(&names_ref, headers, lang)?;
        Some([
            (format!("{primary}{SPEC}"), Bytes::from(names.join(","))),
            (format!("{primary}{VARIANT}{variant}"), encode(res, body)?),
        ])
    }

    /// Writes the records of [`records`](Self::records).
    async fn insert(&self, records: [(String, Bytes); 2], ttl: Duration) -> Result<(), StoreError> {
        let [(spec_key, spec), (entry_key, entry)] = records;
        // The `Vary` record outlives the entries it describes.
        self.store.set(&spec_key, spec, self.ttl).await?;
        self.store.set(&entry_key, entry, ttl).await
    }
}

/// The comma-separated items of every `name` header, trimmed and lowercased.
fn list(headers: &HeaderMap, name: &HeaderName) -> Vec<String> {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

/// The sorted header names of `Vary`, or `None` for `Vary: *`.
fn vary(headers: &HeaderMap) -> Option<Vec<String>> {
    let mut names = list(headers, &header::VARY);
    if names.iter().any(|n| n == "*") {
        return None;
    }
    names.sort();
    names.dedup();
    Some(names)
}

/// Request headers that are always part of the key, because handlers and
/// other middlewares commonly answer differently for them: the site
/// (`Host`, and the original host and scheme behind a proxy) and the CORS
/// `Origin`.
const KEY_HEADERS: [&str; 5] = [
    "host",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-proto",
    "origin",
];

/// Appends `name` and the values of the `name` headers to a variant. Bytes
/// other than visible ASCII are percent-encoded, so distinct values never
/// share a key.
fn push_header(out: &mut String, name: &str, headers: &HeaderMap) {
    out.push(VARIANT);
    out.push_str(name);
    let mut values = headers.get_all(name).iter().peekable();
    if values.peek().is_none() {
        return;
    }
    out.push('=');
    for (i, value) in values.enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        for &b in value.as_bytes() {
            let b = if name == "host" {
                b.to_ascii_lowercase()
            } else {
                b
            };
            if (0x20..0x7f).contains(&b) && b != b'%' {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
    }
}

/// The part of the key that tells variants apart: the site and origin
/// ([`KEY_HEADERS`]), the language chosen by `Locale`, then each header
/// named by `Vary`. `None` when it would be too long to be a key.
fn variant(names: &[&str], headers: &HeaderMap, lang: Option<&str>) -> Option<String> {
    let mut out = String::new();
    if let Some(lang) = lang {
        out.push_str("lang=");
        out.push_str(lang);
    }
    for name in KEY_HEADERS {
        push_header(&mut out, name, headers);
    }
    for name in names {
        // Already in the key, or chosen from by `Locale`, whose choice is.
        if KEY_HEADERS.contains(name) || (lang.is_some() && *name == "accept-language") {
            continue;
        }
        push_header(&mut out, name, headers);
        if out.len() > MAX_VARIANT {
            return None;
        }
    }
    (out.len() <= MAX_VARIANT).then_some(out)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// `1 | status u16 | stored at, ms u64 | n u16 | n × (len u16, name, len u32, value) | body`,
/// or `None` when the headers don't fit the format (never truncated).
pub(crate) fn encode(res: &Response, body: &Bytes) -> Option<Bytes> {
    let headers: Vec<_> = res
        .headers()
        .iter()
        .filter(|(name, _)| !PER_REQUEST.contains(&name.as_str()))
        .collect();
    let mut out = Vec::with_capacity(body.len() + 64 * headers.len() + 16);
    out.push(1);
    out.extend_from_slice(&res.status_code().as_u16().to_be_bytes());
    out.extend_from_slice(&now_millis().to_be_bytes());
    out.extend_from_slice(&u16::try_from(headers.len()).ok()?.to_be_bytes());
    for (name, value) in headers {
        out.extend_from_slice(&u16::try_from(name.as_str().len()).ok()?.to_be_bytes());
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(&u32::try_from(value.len()).ok()?.to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out.extend_from_slice(body);
    Some(Bytes::from(out))
}

/// The response stored by [`encode`], with its `Age`; `None` if the bytes are
/// not a stored response.
pub(crate) fn decode(bytes: &Bytes) -> Option<Response> {
    let mut at: usize = 0;
    let mut take = |n: usize| {
        let end = at.checked_add(n)?;
        let slice = bytes.get(at..end)?;
        at = end;
        Some(slice)
    };
    if take(1)? != [1] {
        return None;
    }
    let status = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let stored = u64::from_be_bytes(take(8)?.try_into().ok()?);
    let count = u16::from_be_bytes(take(2)?.try_into().ok()?);
    let mut res = Response::new().status(StatusCode::from_u16(status).ok()?);
    let headers = res.headers_mut();
    for _ in 0..count {
        let len = u16::from_be_bytes(take(2)?.try_into().ok()?) as usize;
        let name = HeaderName::from_bytes(take(len)?).ok()?;
        let len = u32::from_be_bytes(take(4)?.try_into().ok()?) as usize;
        let value = HeaderValue::from_bytes(take(len)?).ok()?;
        headers.append(name, value);
    }
    let age = now_millis().saturating_sub(stored) / 1000;
    headers.insert(header::AGE, HeaderValue::from(age));
    headers.insert("x-cache", HeaderValue::from_static("HIT"));
    *res.body_mut() = Body::from(bytes.slice(at..));
    Some(res)
}

impl Middleware for ResponseCache {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if !self.cacheable_request(&req) {
            return next.run(req);
        }
        // The raw target: `req.uri()` turns targets that `Uri` rejects into
        // `/`, and the response of `/x?a=<b>` must not be stored as `/`.
        let primary = target(&req);
        let refresh = req
            .header(header::CACHE_CONTROL)
            .is_some_and(|v| v.contains("no-cache"));
        let lang = req.get::<Lang>().map(|l| l.0.clone());
        let headers = req.headers().clone();
        let mut store = *req.method() == Method::GET;
        Box::pin(async move {
            let epoch = self.epoch.load(Ordering::SeqCst);
            if !refresh {
                match self.lookup(&primary, &headers, lang.as_deref()).await {
                    Ok(Some(mut res)) => {
                        self.stats.hits.fetch_add(1, Ordering::Relaxed);
                        let etag = res.get_header("etag").map(str::to_owned);
                        let inm: Vec<&str> = headers
                            .get_all(header::IF_NONE_MATCH)
                            .iter()
                            .filter_map(|v| v.to_str().ok())
                            .collect();
                        if let Some(etag) = etag.filter(|_| !inm.is_empty()) {
                            if none_match(&inm.join(","), &etag) {
                                res.set_status(StatusCode::NOT_MODIFIED);
                                *res.body_mut() = Body::empty();
                            }
                        }
                        return res;
                    }
                    Ok(None) => {}
                    Err(err) => {
                        self.error(&err);
                        // The store is failing: don't make the request wait
                        // for it a second time.
                        store = false;
                    }
                }
            }
            self.stats.misses.fetch_add(1, Ordering::Relaxed);
            let mut res = next.run(req).await;
            if let Some(ttl) = store.then(|| self.freshness(&res)).flatten() {
                let Ok(body) = std::mem::take(res.body_mut()).to_bytes().await else {
                    res.set_status(StatusCode::INTERNAL_SERVER_ERROR);
                    return res;
                };
                let records = self.records(&primary, &headers, lang.as_deref(), &res, &body);
                *res.body_mut() = Body::from(body);
                // Not after a purge that happened while the handler ran.
                let purged = self.epoch.load(Ordering::SeqCst) != epoch;
                if let Some(records) = records.filter(|_| !purged) {
                    if let Err(err) = self.insert(records, ttl).await {
                        self.error(&err);
                    }
                }
            }
            res.headers_mut()
                .insert("x-cache", HeaderValue::from_static("MISS"));
            res
        })
    }
}

/// Purges a [`ResponseCache`] and reads its counters while the app runs.
///
/// Purges act on the store, so with a [`RedisStore`] they reach every
/// instance; the counters are those of this process.
#[derive(Clone)]
pub struct CacheHandle {
    store: Arc<dyn CacheStore>,
    stats: Arc<Stats>,
    epoch: Arc<AtomicU64>,
}

impl std::fmt::Debug for CacheHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheHandle")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

impl CacheHandle {
    /// Forgets every response.
    pub async fn clear(&self) -> Result<(), StoreError> {
        self.epoch.fetch_add(1, Ordering::SeqCst);
        let cleared = self.store.clear().await;
        self.epoch.fetch_add(1, Ordering::SeqCst);
        cleared
    }

    /// Forgets the responses for `path` and below it, whatever their query
    /// string and variant (`/api/catalog` covers `/api/catalog?page=2` and
    /// `/api/catalog/42`, not `/api/catalogs`).
    pub async fn invalidate(&self, path: &str) -> Result<(), StoreError> {
        let path = normalize_prefix(path);
        let path = path.trim_end_matches('/');
        if path.is_empty() {
            return self.clear().await;
        }
        let prefixes: Vec<String> = ["/", "?", "\u{1e}", "\u{1f}"]
            .iter()
            .map(|sep| format!("{path}{sep}"))
            .collect();
        self.epoch.fetch_add(1, Ordering::SeqCst);
        let removed = self.store.remove_prefixes(&prefixes).await;
        self.epoch.fetch_add(1, Ordering::SeqCst);
        removed
    }

    /// Requests answered from the cache.
    pub fn hits(&self) -> u64 {
        self.stats.hits.load(Ordering::Relaxed)
    }

    /// Cacheable requests that went to the handler.
    pub fn misses(&self) -> u64 {
        self.stats.misses.load(Ordering::Relaxed)
    }

    /// Store failures (each one served by the handler).
    pub fn errors(&self) -> u64 {
        self.stats.errors.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(*k, HeaderValue::from_static(v));
        }
        map
    }

    #[test]
    fn variants() {
        // The key headers, absent here.
        const BASE: &str =
            "\u{1f}host\u{1f}forwarded\u{1f}x-forwarded-host\u{1f}x-forwarded-proto\u{1f}origin";
        let h = headers(&[("accept-encoding", "br"), ("accept-language", "fr")]);
        assert_eq!(variant(&[], &h, None).as_deref(), Some(BASE));
        assert_eq!(variant(&[], &h, Some("fr")), Some(format!("lang=fr{BASE}")));
        assert_eq!(
            variant(&["accept-encoding", "x-missing"], &h, None),
            Some(format!("{BASE}\u{1f}accept-encoding=br\u{1f}x-missing"))
        );
        // With `Locale`, the language replaces the raw header.
        assert_eq!(
            variant(&["accept-language"], &h, Some("fr")),
            Some(format!("lang=fr{BASE}"))
        );
        // The site is always in the key, lowercased; `Vary: Origin` adds nothing.
        let h = headers(&[("host", "Shop.Example"), ("origin", "https://a.example")]);
        let v = variant(&["origin"], &h, None).unwrap();
        assert!(v.starts_with("\u{1f}host=shop.example\u{1f}"), "{v:?}");
        assert!(v.ends_with("\u{1f}origin=https://a.example"), "{v:?}");
        // Distinct non-UTF-8 values stay distinct.
        let mut a = HeaderMap::new();
        a.insert("x-v", HeaderValue::from_bytes(b"\xe9").unwrap());
        let mut b = HeaderMap::new();
        b.insert("x-v", HeaderValue::from_bytes(b"\xe8").unwrap());
        assert_ne!(variant(&["x-v"], &a, None), variant(&["x-v"], &b, None));
        assert!(variant(&["x-v"], &a, None).unwrap().ends_with("x-v=%E9"));
        let long = HeaderValue::from_str(&"a".repeat(2000)).unwrap();
        let mut h = HeaderMap::new();
        h.insert("accept-language", long);
        assert_eq!(variant(&["accept-language"], &h, None), None);
    }

    #[test]
    fn vary_lists() {
        let h = headers(&[
            ("vary", "Accept-Encoding, origin"),
            ("vary", "accept-encoding"),
        ]);
        assert_eq!(vary(&h).unwrap(), ["accept-encoding", "origin"]);
        assert_eq!(vary(&headers(&[("vary", "*")])), None);
        assert!(vary(&HeaderMap::new()).unwrap().is_empty());
    }

    #[test]
    fn freshness_follows_cache_control() {
        let cache = ResponseCache::new(Duration::from_secs(60));
        let res = |cc: &'static str| Response::new().text("x").header("cache-control", cc);
        assert_eq!(
            cache.freshness(&Response::new().text("x")),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            cache.freshness(&res("public, max-age=10")),
            Some(Duration::from_secs(10))
        );
        assert_eq!(
            cache.freshness(&res("max-age=10, s-maxage=20")),
            Some(Duration::from_secs(20))
        );
        assert_eq!(
            cache.freshness(&res("max-age=3600")),
            Some(Duration::from_secs(60))
        );
        assert_eq!(cache.freshness(&res("max-age=0")), None);
        assert_eq!(cache.freshness(&res("Private")), None);
        assert_eq!(cache.freshness(&res("no-cache=\"set-cookie\"")), None);
        assert_eq!(
            cache.freshness(&Response::new().status(404).text("x")),
            None
        );
    }

    #[test]
    fn entries_round_trip() {
        let res = Response::new()
            .status(200)
            .header("etag", "\"x\"")
            .header("x-request-id", "abc")
            .append_header("link", "<a>")
            .append_header("link", "<b>")
            .text("hello");
        let bytes = encode(&res, &Bytes::from_static(b"hello")).unwrap();
        let back = decode(&bytes).unwrap();
        assert_eq!(back.status_code(), 200);
        assert_eq!(back.get_header("etag"), Some("\"x\""));
        assert_eq!(back.get_header("x-request-id"), None);
        assert_eq!(back.get_header("x-cache"), Some("HIT"));
        assert_eq!(back.get_header("age"), Some("0"));
        assert_eq!(back.headers().get_all("link").iter().count(), 2);
        assert_eq!(back.body().size(), Some(5));
        // Truncated or foreign bytes are a miss, never a panic.
        for n in 0..bytes.len() - 5 {
            assert!(decode(&bytes.slice(..n)).is_none(), "{n}");
        }
        assert!(decode(&Bytes::from_static(b"\x02junk")).is_none());
    }
}
