//! Rate limiting with the GCRA algorithm (Generic Cell Rate Algorithm).
//!
//! GCRA is a token-bucket equivalent that stores a single `u64` per client:
//! it is exact, smooth (no window boundary bursts) and very fast.

use std::fmt;
use std::hash::Hash;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue, RETRY_AFTER};
use http::{Method, StatusCode, request, response};

use crate::guard::impl_layer;
use crate::ip::mask;
use crate::store::ShardedMap;
use crate::util::{any_path_matches, ceil_secs, normalize_prefix, path_matches};
use crate::{Context, Guard, Mode, Rejection, priority};

/// How many requests are allowed, and how fast they replenish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Time to replenish one request.
    interval: Duration,
    /// Requests allowed instantly.
    burst: u32,
}

impl Quota {
    /// `n` requests per `period`. Burst defaults to `n`.
    ///
    /// # Panics
    ///
    /// If `n == 0` or `period` is zero.
    pub fn new(n: u32, period: Duration) -> Self {
        assert!(n > 0, "quota must allow at least one request");
        assert!(!period.is_zero(), "quota period must be non-zero");
        Self {
            interval: period / n,
            burst: n,
        }
    }

    /// `n` requests per second.
    pub fn per_second(n: u32) -> Self {
        Self::new(n, Duration::from_secs(1))
    }

    /// `n` requests per minute.
    pub fn per_minute(n: u32) -> Self {
        Self::new(n, Duration::from_secs(60))
    }

    /// `n` requests per hour.
    pub fn per_hour(n: u32) -> Self {
        Self::new(n, Duration::from_secs(3600))
    }

    /// Maximum number of requests allowed at once (bucket capacity).
    pub fn burst(mut self, burst: u32) -> Self {
        self.burst = burst.max(1);
        self
    }

    /// Bucket capacity.
    pub fn burst_size(&self) -> u32 {
        self.burst
    }

    /// Time to replenish one request.
    pub fn replenish_interval(&self) -> Duration {
        self.interval
    }
}

/// Custom key function of [`RateLimitKey::Custom`].
pub type KeyFn = dyn Fn(&request::Parts, &Context) -> Option<String> + Send + Sync;

/// What a rate-limit rule counts requests by.
#[derive(Clone, Default)]
pub enum RateLimitKey {
    /// Client IP (IPv6 grouped by `/64` by default). Default.
    #[default]
    Ip,
    /// The value of a header (e.g. `x-api-key`); falls back to the IP when
    /// the header is missing.
    Header(HeaderName),
    /// One bucket for everybody (global throughput cap).
    Global,
    /// Your own key function. Return `None` to skip rate limiting.
    Custom(Arc<KeyFn>),
}

impl RateLimitKey {
    /// Builds a [`RateLimitKey::Custom`].
    pub fn custom<F>(f: F) -> Self
    where
        F: Fn(&request::Parts, &Context) -> Option<String> + Send + Sync + 'static,
    {
        Self::Custom(Arc::new(f))
    }
}

impl fmt::Debug for RateLimitKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip => f.write_str("Ip"),
            Self::Header(h) => f.debug_tuple("Header").field(h).finish(),
            Self::Global => f.write_str("Global"),
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Ip(IpAddr),
    Text(Box<str>),
    Global,
}

/// Which rate-limit headers are sent back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HeaderStyle {
    /// `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`
    /// (IETF draft, widely supported). Default.
    #[default]
    Standard,
    /// `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`.
    Legacy,
    /// Only `Retry-After` on 429.
    None,
}

/// Current state of the most restrictive matching rule (for headers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitSnapshot {
    /// Bucket capacity.
    pub limit: u32,
    /// Requests left right now.
    pub remaining: u32,
    /// Seconds until the bucket is full again.
    pub reset_secs: u64,
}

struct Rule {
    quota: Quota,
    key: RateLimitKey,
    path: Option<String>,
    methods: Option<Vec<Method>>,
    store: ShardedMap<Key, u64>,
}

impl Rule {
    fn new(quota: Quota, max_entries: usize) -> Self {
        Self {
            quota,
            key: RateLimitKey::Ip,
            path: None,
            methods: None,
            store: ShardedMap::new(max_entries),
        }
    }

    fn applies(&self, method: &Method, path: &str) -> bool {
        self.path.as_deref().is_none_or(|p| path_matches(path, p))
            && self.methods.as_ref().is_none_or(|m| m.contains(method))
    }

    /// GCRA check. Returns `Ok(snapshot)` or `Err(retry_after_nanos)`.
    fn check(&self, key: Key, now: u64) -> Result<RateLimitSnapshot, u64> {
        let t = self.quota.interval.as_nanos().min(u128::from(u64::MAX)) as u64;
        let t = t.max(1);
        let burst = u64::from(self.quota.burst);
        let tau = t.saturating_mul(burst - 1);
        let outcome = self.store.update(
            key,
            |&tat| tat <= now,
            |entry| {
                let tat = entry_value(&entry).unwrap_or(now).max(now);
                if tat - now > tau {
                    return Err(tat - now - tau);
                }
                let new_tat = tat + t;
                entry_set(entry, new_tat);
                let used = new_tat - now;
                let remaining = if tau + t >= used {
                    (tau + t - used) / t
                } else {
                    0
                };
                Ok(RateLimitSnapshot {
                    limit: self.quota.burst,
                    remaining: remaining.min(burst) as u32,
                    reset_secs: ceil_secs(used),
                })
            },
        );
        // Store full of live entries: fail closed for unknown clients.
        outcome.unwrap_or(Err(t))
    }
}

fn entry_value(entry: &std::collections::hash_map::Entry<'_, Key, u64>) -> Option<u64> {
    match entry {
        std::collections::hash_map::Entry::Occupied(o) => Some(*o.get()),
        std::collections::hash_map::Entry::Vacant(_) => None,
    }
}

fn entry_set(entry: std::collections::hash_map::Entry<'_, Key, u64>, value: u64) {
    match entry {
        std::collections::hash_map::Entry::Occupied(mut o) => {
            o.insert(value);
        }
        std::collections::hash_map::Entry::Vacant(v) => {
            v.insert(value);
        }
    }
}

/// GCRA rate limiter with per-route rules.
///
/// ```
/// use securite::prelude::*;
///
/// let limiter = RateLimit::new(Quota::per_second(20).burst(50))
///     // brute-force protection on the login form:
///     .route("/login", Quota::per_minute(5))
///     // API clients are limited by API key:
///     .route_keyed("/api", Quota::per_second(100), RateLimitKey::Header("x-api-key".parse().unwrap()));
/// ```
///
/// Every matching rule must pass. Rejected requests get `429 Too Many
/// Requests` with `Retry-After`.
#[derive(Clone)]
pub struct RateLimit {
    rules: Vec<Arc<Rule>>,
    pending: Vec<PendingRule>,
    headers: HeaderStyle,
    ipv6_prefix: u8,
    skip_paths: Vec<String>,
    max_entries: usize,
    mode: Mode,
}

#[derive(Clone)]
struct PendingRule {
    quota: Quota,
    key: RateLimitKey,
    path: Option<String>,
    methods: Option<Vec<Method>>,
}

impl fmt::Debug for RateLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RateLimit")
            .field("rules", &self.pending.len())
            .field("headers", &self.headers)
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl RateLimit {
    /// A limiter with one global, per-IP rule.
    pub fn new(quota: Quota) -> Self {
        let mut s = Self {
            rules: Vec::new(),
            pending: vec![PendingRule {
                quota,
                key: RateLimitKey::Ip,
                path: None,
                methods: None,
            }],
            headers: HeaderStyle::Standard,
            ipv6_prefix: 64,
            skip_paths: Vec::new(),
            max_entries: 1_000_000,
            mode: Mode::Enforce,
        };
        s.rebuild();
        s
    }

    /// `n` requests per second per IP (burst `n`).
    pub fn per_second(n: u32) -> Self {
        Self::new(Quota::per_second(n))
    }

    /// `n` requests per minute per IP (burst `n`).
    pub fn per_minute(n: u32) -> Self {
        Self::new(Quota::per_minute(n))
    }

    /// `n` requests per hour per IP (burst `n`).
    pub fn per_hour(n: u32) -> Self {
        Self::new(Quota::per_hour(n))
    }

    /// Sets the burst of the global rule.
    pub fn burst(mut self, burst: u32) -> Self {
        self.pending[0].quota = self.pending[0].quota.burst(burst);
        self.rebuild();
        self
    }

    /// Changes what the global rule counts by.
    pub fn key(mut self, key: RateLimitKey) -> Self {
        self.pending[0].key = key;
        self.rebuild();
        self
    }

    /// Adds a per-IP rule for a path prefix.
    pub fn route(self, prefix: impl Into<String>, quota: Quota) -> Self {
        self.route_keyed(prefix, quota, RateLimitKey::Ip)
    }

    /// Adds a rule for a path prefix with a custom key.
    pub fn route_keyed(
        mut self,
        prefix: impl Into<String>,
        quota: Quota,
        key: RateLimitKey,
    ) -> Self {
        self.pending.push(PendingRule {
            quota,
            key,
            path: Some(normalize_prefix(prefix)),
            methods: None,
        });
        self.rebuild();
        self
    }

    /// Adds a rule for some methods on a path prefix (e.g. only `POST /login`).
    pub fn route_methods(
        mut self,
        prefix: impl Into<String>,
        methods: impl IntoIterator<Item = Method>,
        quota: Quota,
    ) -> Self {
        self.pending.push(PendingRule {
            quota,
            key: RateLimitKey::Ip,
            path: Some(normalize_prefix(prefix)),
            methods: Some(methods.into_iter().collect()),
        });
        self.rebuild();
        self
    }

    /// Which headers are sent back (default: [`HeaderStyle::Standard`]).
    pub fn headers(mut self, style: HeaderStyle) -> Self {
        self.headers = style;
        self
    }

    /// Groups IPv6 clients by prefix length (default `/64`).
    pub fn ipv6_prefix(mut self, bits: u8) -> Self {
        self.ipv6_prefix = bits.min(128);
        self
    }

    /// Paths never rate limited (health checks, static assets …).
    pub fn skip_paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.skip_paths
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Maximum tracked clients per rule (default 1 000 000, ≈ 50 MB worst
    /// case; the store is split in 64 shards of at least 16 entries). When
    /// full, *new* clients are rejected (fail closed).
    pub fn max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self.rebuild();
        self
    }

    /// Monitor-only mode.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    fn rebuild(&mut self) {
        self.rules = self
            .pending
            .iter()
            .map(|p| {
                let mut rule = Rule::new(p.quota, self.max_entries);
                rule.key = p.key.clone();
                rule.path = p.path.clone();
                rule.methods = p.methods.clone();
                Arc::new(rule)
            })
            .collect();
    }

    fn key_for(&self, rule: &Rule, req: &request::Parts, ctx: &Context) -> Option<Key> {
        let ip_key = || ctx.client_ip.map(|ip| Key::Ip(mask(ip, self.ipv6_prefix)));
        match &rule.key {
            RateLimitKey::Ip => Some(ip_key().unwrap_or(Key::Global)),
            RateLimitKey::Global => Some(Key::Global),
            RateLimitKey::Header(name) => match req.headers.get(name).map(HeaderValue::as_bytes) {
                Some(v) if !v.is_empty() && v.len() <= 256 => {
                    Some(Key::Text(String::from_utf8_lossy(v).into()))
                }
                _ => Some(ip_key().unwrap_or(Key::Global)),
            },
            RateLimitKey::Custom(f) => f(req, ctx).map(|s| Key::Text(s.into_boxed_str())),
        }
    }
}

impl Guard for RateLimit {
    fn name(&self) -> &'static str {
        "rate_limit"
    }

    fn priority(&self) -> u16 {
        priority::RATE_LIMIT
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let path = req.uri.path();
        if any_path_matches(path, &self.skip_paths) {
            return Ok(());
        }
        let mut tightest: Option<RateLimitSnapshot> = None;
        for rule in &self.rules {
            if !rule.applies(&req.method, path) {
                continue;
            }
            let Some(key) = self.key_for(rule, req, ctx) else {
                continue;
            };
            let now = rule.store.now();
            match rule.check(key, now) {
                Ok(snap) => {
                    if tightest.is_none_or(|t| snap.remaining < t.remaining) {
                        tightest = Some(snap);
                    }
                }
                Err(retry_nanos) => {
                    let retry = ceil_secs(retry_nanos).max(1);
                    let snap = RateLimitSnapshot {
                        limit: rule.quota.burst,
                        remaining: 0,
                        reset_secs: retry,
                    };
                    ctx.rate_limit = Some(snap);
                    return Err(Rejection::new(
                        StatusCode::TOO_MANY_REQUESTS,
                        "rate_limited",
                        "Too many requests, slow down.",
                    )
                    .with_header(RETRY_AFTER, HeaderValue::from(retry)));
                }
            }
        }
        ctx.rate_limit = tightest;
        Ok(())
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        let Some(snap) = ctx.rate_limit else { return };
        let (limit, remaining, reset) = match self.headers {
            HeaderStyle::Standard => ("ratelimit-limit", "ratelimit-remaining", "ratelimit-reset"),
            HeaderStyle::Legacy => (
                "x-ratelimit-limit",
                "x-ratelimit-remaining",
                "x-ratelimit-reset",
            ),
            HeaderStyle::None => return,
        };
        let h = &mut res.headers;
        h.insert(
            HeaderName::from_static(limit),
            HeaderValue::from(snap.limit),
        );
        h.insert(
            HeaderName::from_static(remaining),
            HeaderValue::from(snap.remaining),
        );
        h.insert(
            HeaderName::from_static(reset),
            HeaderValue::from(snap.reset_secs),
        );
    }
}

impl_layer!(RateLimit);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcra_burst_then_block() {
        let rule = Rule::new(Quota::per_second(10).burst(3), 1000);
        let k = || Key::Global;
        let now = 1_000_000_000;
        let a = rule.check(k(), now).unwrap();
        assert_eq!(a.remaining, 2);
        let b = rule.check(k(), now).unwrap();
        assert_eq!(b.remaining, 1);
        let c = rule.check(k(), now).unwrap();
        assert_eq!(c.remaining, 0);
        let retry = rule.check(k(), now).unwrap_err();
        assert_eq!(retry, 100_000_000, "one interval (100ms) to wait");
        // After 100 ms one request is available again.
        assert!(rule.check(k(), now + 100_000_000).is_ok());
        assert!(rule.check(k(), now + 100_000_000).is_err());
    }

    #[test]
    fn gcra_smooth_rate() {
        let rule = Rule::new(Quota::per_second(1).burst(1), 1000);
        let mut now = 0;
        for _ in 0..10 {
            assert!(rule.check(Key::Global, now).is_ok());
            assert!(rule.check(Key::Global, now).is_err());
            now += 1_000_000_000;
        }
    }

    #[test]
    fn keys_are_independent() {
        let rule = Rule::new(Quota::per_minute(1), 1000);
        let a = Key::Ip("1.1.1.1".parse().unwrap());
        let b = Key::Ip("2.2.2.2".parse().unwrap());
        assert!(rule.check(a.clone(), 0).is_ok());
        assert!(rule.check(a, 0).is_err());
        assert!(rule.check(b, 0).is_ok());
    }

    #[test]
    fn quota_math() {
        let q = Quota::per_minute(60);
        assert_eq!(q.replenish_interval(), Duration::from_secs(1));
        assert_eq!(q.burst_size(), 60);
        assert_eq!(q.burst(0).burst_size(), 1);
    }
}
