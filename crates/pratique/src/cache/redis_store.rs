//! A cache store in Redis (or Valkey, KeyDB, Dragonfly …), shared by every
//! instance of the app.

use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use redis::RedisResult;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use vitesse::Bytes;
use vitesse::tokio::time::timeout;

use super::store::{CacheStore, MAX_TTL, StoreError, StoreFuture};

/// Keys removed per `UNLINK` command when purging.
const BATCH: usize = 500;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// One connection per store and per thread: Vitesse runs one runtime per
    /// core, and each runtime gets its own connection instead of funnelling
    /// every command through the thread that happened to connect first.
    static CONNECTIONS: RefCell<HashMap<u64, ConnectionManager>> = RefCell::new(HashMap::new());
}

/// Keeps the cached responses in Redis, so that every instance of the app
/// (several dynos, pods or servers behind a load balancer) shares one cache,
/// and a purge reaches all of them. Needs the `redis` feature (`redis-tls`
/// for `rediss://` addresses).
///
/// Redis must never make the app slower than without a cache:
///
/// * the connection opens on first use, from the app's runtime (one per
///   worker thread), and reopens by itself;
/// * every operation, connection included, gives up after the
///   [`timeout`](RedisStore::timeout) (250 ms by default);
/// * after a failure, Redis is left alone for the
///   [`cooldown`](RedisStore::cooldown) (1 s by default): meanwhile every
///   operation fails at once and requests go straight to the handler.
///
/// Keys start with `pratique:cache:` (see [`prefix`](RedisStore::prefix))
/// and expire with the responses (`PX`), so Redis never needs a manual
/// clean-up. A purge uses `SCAN` and `UNLINK`, never `KEYS`.
///
/// ```no_run
/// use pratique::prelude::*;
/// use std::time::Duration;
/// use vitesse::prelude::*;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// let url = std::env::var("REDIS_URL").unwrap_or("redis://127.0.0.1/".into());
/// let cache = ResponseCache::new(Duration::from_secs(60))
///     .store(RedisStore::open(&url)?.prefix("shop:cache:"))
///     .on_error(|e| eprintln!("cache: {e}"));
///
/// let mut app = App::new();
/// app.middleware(cache);
/// # Ok(())
/// # }
/// ```
pub struct RedisStore {
    id: u64,
    client: redis::Client,
    prefix: String,
    timeout: Duration,
    cooldown: Duration,
    /// Milliseconds after `epoch` until which Redis is left alone.
    down_until: AtomicU64,
    epoch: Instant,
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStore")
            .field("prefix", &self.prefix)
            .field("timeout", &self.timeout)
            .field("cooldown", &self.cooldown)
            .finish_non_exhaustive()
    }
}

impl RedisStore {
    /// A store for this address (`redis://user:password@host:6379/0`, or
    /// `rediss://…` with the `redis-tls` feature; add `#insecure` for a
    /// self-signed certificate, as on Heroku). Nothing is connected yet:
    /// only the address is checked.
    pub fn open(url: &str) -> Result<Self, StoreError> {
        Ok(Self::from_client(redis::Client::open(url)?))
    }

    /// A store for an already configured client.
    pub fn from_client(client: redis::Client) -> Self {
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            client,
            prefix: "pratique:cache:".into(),
            timeout: Duration::from_millis(250),
            cooldown: Duration::from_secs(1),
            down_until: AtomicU64::new(0),
            epoch: Instant::now(),
        }
    }

    /// Prefix of every key (default `pratique:cache:`): one per app when
    /// several apps share a Redis. `clear` only removes this prefix's keys,
    /// even when another prefix starts the same way (`app` and `app2`).
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Longest an operation may take, connection included (default 250 ms).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// How long Redis is left alone after a failure (default 1 s).
    pub fn cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self
    }

    fn now_millis(&self) -> u64 {
        u64::try_from(self.epoch.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// This thread's connection, created (without waiting) if needed.
    fn connection(&self) -> Result<ConnectionManager, StoreError> {
        if let Some(conn) = CONNECTIONS.with(|c| c.borrow().get(&self.id).cloned()) {
            return Ok(conn);
        }
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.timeout))
            .set_response_timeout(Some(self.timeout))
            .set_number_of_retries(0);
        let conn = ConnectionManager::new_lazy_with_config(self.client.clone(), config)?;
        CONNECTIONS.with(|c| c.borrow_mut().insert(self.id, conn.clone()));
        Ok(conn)
    }

    /// Runs `op` with the timeout and the cooldown.
    async fn call<T, F, Fut>(&self, op: F) -> Result<T, StoreError>
    where
        F: FnOnce(ConnectionManager) -> Fut,
        Fut: Future<Output = RedisResult<T>>,
    {
        if self.now_millis() < self.down_until.load(Ordering::Relaxed) {
            return Err("Redis unavailable: cooling down after a failure".into());
        }
        let conn = self.connection()?;
        let failure: StoreError = match timeout(self.timeout, op(conn)).await {
            Ok(Ok(value)) => return Ok(value),
            // An answer from Redis (a wrong type …): the connection is fine.
            Ok(Err(err))
                if !(err.is_io_error()
                    || err.is_timeout()
                    || err.is_connection_dropped()
                    || err.is_connection_refusal()) =>
            {
                return Err(err.into());
            }
            Ok(Err(err)) => err.into(),
            Err(_) => "Redis timed out".into(),
        };
        let until = self
            .now_millis()
            .saturating_add(u64::try_from(self.cooldown.as_millis()).unwrap_or(u64::MAX));
        self.down_until.store(until, Ordering::Relaxed);
        // A connection whose runtime is gone never recovers: start afresh.
        CONNECTIONS.with(|c| c.borrow_mut().remove(&self.id));
        Err(failure)
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    /// Deletes every key matching `pattern` (a `SCAN` glob).
    async fn remove_matching(&self, pattern: String) -> Result<(), StoreError> {
        let mut cursor: u64 = 0;
        let pattern = &pattern;
        loop {
            let (next, keys): (u64, Vec<Vec<u8>>) = self
                .call(|mut conn| async move {
                    redis::cmd("SCAN")
                        .arg(cursor)
                        .arg("MATCH")
                        .arg(pattern)
                        .arg("COUNT")
                        .arg(BATCH)
                        .query_async(&mut conn)
                        .await
                })
                .await?;
            for chunk in keys.chunks(BATCH) {
                self.call(|mut conn| async move {
                    redis::cmd("UNLINK")
                        .arg(chunk)
                        .query_async::<()>(&mut conn)
                        .await
                })
                .await?;
            }
            if next == 0 {
                return Ok(());
            }
            cursor = next;
        }
    }
}

/// Escapes the characters that `SCAN MATCH` reads as a pattern.
fn glob_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '\\' | '^') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

impl CacheStore for RedisStore {
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Bytes>> {
        Box::pin(async move {
            let key = self.key(key);
            let value: Option<Vec<u8>> =
                self.call(|mut conn| async move {
                    redis::cmd("GET").arg(key).query_async(&mut conn).await
                })
                .await?;
            Ok(value.map(Bytes::from))
        })
    }

    fn set<'a>(&'a self, key: &'a str, value: Bytes, ttl: Duration) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let millis = u64::try_from(ttl.min(MAX_TTL).as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            let key = self.key(key);
            self.call(|mut conn| async move {
                redis::cmd("SET")
                    .arg(key)
                    .arg(value.as_ref())
                    .arg("PX")
                    .arg(millis)
                    .query_async::<()>(&mut conn)
                    .await
            })
            .await
        })
    }

    fn remove_prefixes<'a>(&'a self, prefixes: &'a [String]) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            for prefix in prefixes {
                self.remove_matching(format!("{}*", glob_escape(&self.key(prefix))))
                    .await?;
            }
            Ok(())
        })
    }

    fn clear(&self) -> StoreFuture<'_, ()> {
        // Every key of the cache starts with the prefix then `/`: `app` must
        // not remove the keys of `app2`.
        Box::pin(self.remove_matching(format!("{}/*", glob_escape(&self.prefix))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_are_escaped() {
        assert_eq!(glob_escape("a*b?c[d]e\\f^"), "a\\*b\\?c\\[d\\]e\\\\f\\^");
        assert_eq!(glob_escape("/api?x=1"), "/api\\?x=1");
    }

    #[test]
    fn addresses_are_checked() {
        assert!(RedisStore::open("redis://127.0.0.1:6379/0").is_ok());
        assert!(RedisStore::open("http://example.com").is_err());
    }
}
