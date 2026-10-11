//! A cache store in Redis (or Valkey, KeyDB, Dragonfly …), shared by every
//! instance of the app.

use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use vitesse::Bytes;
use vitesse::tokio::sync::OnceCell;

use super::store::{CacheStore, StoreError, StoreFuture};

/// Keys removed per `UNLINK` command when purging.
const BATCH: usize = 500;

/// Keeps the cached responses in Redis, so that every instance of the app
/// (several dynos, pods or servers behind a load balancer) shares one cache,
/// and a purge reaches all of them. Needs the `redis` feature (`redis-tls`
/// for `rediss://` addresses).
///
/// The connection is opened on first use, from the app's runtime, and
/// re-opened automatically after a failure. Every command has a timeout
/// (250 ms by default): when Redis is slow or down, requests are served by
/// the handler instead of waiting.
///
/// Keys start with `pratique:cache:` (see [`prefix`](RedisStore::prefix))
/// and expire with the responses (`PX`), so Redis never needs a manual
/// clean-up. A purge uses `SCAN`, never `KEYS`.
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
    client: redis::Client,
    prefix: String,
    timeout: Duration,
    connection: OnceCell<ConnectionManager>,
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStore")
            .field("prefix", &self.prefix)
            .field("timeout", &self.timeout)
            .field("connected", &self.connection.initialized())
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
            client,
            prefix: "pratique:cache:".into(),
            timeout: Duration::from_millis(250),
            connection: OnceCell::new(),
        }
    }

    /// Prefix of every key (default `pratique:cache:`): one per app when
    /// several apps share a Redis.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Timeout of every command and of connection attempts (default 250 ms).
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    async fn connection(&self) -> Result<ConnectionManager, StoreError> {
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.timeout))
            .set_response_timeout(Some(self.timeout))
            .set_number_of_retries(1)
            .set_max_delay(self.timeout);
        let manager = self
            .connection
            .get_or_try_init(|| ConnectionManager::new_with_config(self.client.clone(), config))
            .await?;
        Ok(manager.clone())
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }

    /// Deletes every key matching `pattern` (a `SCAN` glob).
    async fn remove_matching(&self, pattern: String) -> Result<(), StoreError> {
        let mut conn = self.connection().await?;
        let mut cursor: u64 = 0;
        loop {
            let (next, keys): (u64, Vec<Vec<u8>>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(BATCH)
                .query_async(&mut conn)
                .await?;
            for chunk in keys.chunks(BATCH) {
                redis::cmd("UNLINK")
                    .arg(chunk)
                    .query_async::<()>(&mut conn)
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
            let mut conn = self.connection().await?;
            let value: Option<Vec<u8>> = redis::cmd("GET")
                .arg(self.key(key))
                .query_async(&mut conn)
                .await?;
            Ok(value.map(Bytes::from))
        })
    }

    fn set<'a>(&'a self, key: &'a str, value: Bytes, ttl: Duration) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let millis = ttl.as_millis().clamp(1, u128::from(u64::MAX)) as u64;
            let mut conn = self.connection().await?;
            redis::cmd("SET")
                .arg(self.key(key))
                .arg(value.as_ref())
                .arg("PX")
                .arg(millis)
                .query_async::<()>(&mut conn)
                .await?;
            Ok(())
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
        Box::pin(self.remove_matching(format!("{}*", glob_escape(&self.prefix))))
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
