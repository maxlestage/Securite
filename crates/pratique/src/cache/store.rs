//! Where the response cache keeps its entries.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use vitesse::Bytes;

/// An error of a cache store (a lost connection to Redis …).
pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

/// The future returned by the methods of a [`CacheStore`].
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// A key-value store with expiry, where a
/// [`ResponseCache`](super::ResponseCache) keeps its responses.
///
/// Two stores come with the crate: [`MemoryStore`] (the default, one per
/// process) and, with the `redis` feature, [`RedisStore`](super::RedisStore),
/// shared by every instance of the app. Implement it to use another backend
/// (Memcached, a database …).
///
/// Keys are short strings without spaces; values are opaque bytes. A store
/// that fails returns an error: the cache then behaves as a miss and the
/// request goes to the handler.
pub trait CacheStore: Send + Sync + 'static {
    /// The value under `key`, if it exists and has not expired.
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Bytes>>;

    /// Stores `value` under `key` for `ttl`, replacing any previous value.
    fn set<'a>(&'a self, key: &'a str, value: Bytes, ttl: Duration) -> StoreFuture<'a, ()>;

    /// Removes every key that starts with one of `prefixes`.
    fn remove_prefixes<'a>(&'a self, prefixes: &'a [String]) -> StoreFuture<'a, ()>;

    /// Removes every key.
    fn clear(&self) -> StoreFuture<'_, ()>;
}

impl<S: CacheStore> CacheStore for Arc<S> {
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Bytes>> {
        (**self).get(key)
    }

    fn set<'a>(&'a self, key: &'a str, value: Bytes, ttl: Duration) -> StoreFuture<'a, ()> {
        (**self).set(key, value, ttl)
    }

    fn remove_prefixes<'a>(&'a self, prefixes: &'a [String]) -> StoreFuture<'a, ()> {
        (**self).remove_prefixes(prefixes)
    }

    fn clear(&self) -> StoreFuture<'_, ()> {
        (**self).clear()
    }
}

fn ready<'a, T: Send + 'a>(value: T) -> StoreFuture<'a, T> {
    Box::pin(std::future::ready(Ok(value)))
}

/// The default store: a map in the memory of the process, shared by all its
/// threads, bounded in number of entries.
///
/// When it is full, expired entries are dropped first, then the ones closest
/// to expiry. Every instance of the app has its own: behind a load balancer,
/// use a [`RedisStore`](super::RedisStore) to share one cache.
///
/// ```
/// use pratique::prelude::*;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let store = Arc::new(MemoryStore::new().max_entries(10_000));
/// let cache = ResponseCache::new(Duration::from_secs(60)).store(store.clone());
/// assert!(store.is_empty());
/// ```
#[derive(Debug)]
pub struct MemoryStore {
    max_entries: usize,
    entries: Mutex<HashMap<String, (Bytes, Instant)>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// At most 1 000 entries.
    pub fn new() -> Self {
        Self {
            max_entries: 1000,
            entries: Mutex::default(),
        }
    }

    /// Maximum number of entries (each response takes one, plus one per path
    /// for its `Vary` record).
    pub fn max_entries(mut self, n: usize) -> Self {
        self.max_entries = n;
        self
    }

    /// Number of entries that have not expired.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.lock().values().filter(|(_, exp)| *exp > now).count()
    }

    /// Whether no entry is alive.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, (Bytes, Instant)>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl CacheStore for MemoryStore {
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Bytes>> {
        let mut entries = self.lock();
        let value = match entries.get(key) {
            Some((value, expires)) if *expires > Instant::now() => Some(value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        };
        ready(value)
    }

    fn set<'a>(&'a self, key: &'a str, value: Bytes, ttl: Duration) -> StoreFuture<'a, ()> {
        if self.max_entries == 0 {
            return ready(());
        }
        let now = Instant::now();
        let mut entries = self.lock();
        if entries.len() >= self.max_entries && !entries.contains_key(key) {
            entries.retain(|_, (_, expires)| *expires > now);
            if entries.len() >= self.max_entries {
                let soonest = entries
                    .iter()
                    .min_by_key(|(_, (_, expires))| *expires)
                    .map(|(k, _)| k.clone());
                if let Some(soonest) = soonest {
                    entries.remove(&soonest);
                }
            }
        }
        entries.insert(key.to_owned(), (value, now + ttl));
        ready(())
    }

    fn remove_prefixes<'a>(&'a self, prefixes: &'a [String]) -> StoreFuture<'a, ()> {
        self.lock()
            .retain(|key, _| !prefixes.iter().any(|p| key.starts_with(p.as_str())));
        ready(())
    }

    fn clear(&self) -> StoreFuture<'_, ()> {
        self.lock().clear();
        ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block<T>(f: StoreFuture<'_, T>) -> T {
        // Memory store futures are always ready.
        let waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(waker);
        let mut f = f;
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v.unwrap(),
            std::task::Poll::Pending => unreachable!(),
        }
    }

    #[test]
    fn expiry_eviction_and_prefixes() {
        let store = MemoryStore::new().max_entries(2);
        let ttl = Duration::from_secs(60);
        block(store.set("/a", Bytes::from_static(b"a"), ttl));
        block(store.set("/b", Bytes::from_static(b"b"), Duration::from_secs(1)));
        block(store.set("/c", Bytes::from_static(b"c"), ttl));
        // `/b` expired first: it was evicted.
        assert_eq!(block(store.get("/b")), None);
        assert_eq!(block(store.get("/a")).as_deref(), Some(&b"a"[..]));
        assert_eq!(store.len(), 2);
        block(store.set("/x", Bytes::new(), Duration::ZERO));
        assert_eq!(block(store.get("/x")), None);
        block(store.remove_prefixes(&["/a".to_string()]));
        assert_eq!(block(store.get("/a")), None);
        block(store.clear());
        assert!(store.is_empty());
    }
}
