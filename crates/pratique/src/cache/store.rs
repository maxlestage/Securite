//! Where the response cache keeps its entries.

use std::collections::{BTreeMap, HashMap};
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

/// Longest time an entry is kept, whatever the TTL asked: ten years.
pub(crate) const MAX_TTL: Duration = Duration::from_secs(10 * 365 * 86_400);

/// Bytes counted for an entry besides its key and value.
const OVERHEAD: usize = 64;

#[derive(Debug, Default)]
struct Entries {
    map: HashMap<String, Entry>,
    /// Keys by expiry: the soonest is evicted first, in `O(log n)`.
    expiry: BTreeMap<(Instant, u64), String>,
    bytes: usize,
    seq: u64,
}

#[derive(Debug)]
struct Entry {
    value: Bytes,
    expires: Instant,
    seq: u64,
}

impl Entries {
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.map.remove(key) {
            self.expiry.remove(&(entry.expires, entry.seq));
            self.bytes -= cost(key, &entry.value);
        }
    }

    fn evict_soonest(&mut self) -> bool {
        match self.expiry.pop_first() {
            Some((_, key)) => {
                if let Some(entry) = self.map.remove(&key) {
                    self.bytes -= cost(&key, &entry.value);
                }
                true
            }
            None => false,
        }
    }
}

fn cost(key: &str, value: &Bytes) -> usize {
    key.len() + value.len() + OVERHEAD
}

/// The default store: a map in the memory of the process, shared by all its
/// threads, bounded in number of entries and in bytes.
///
/// When it is full, the entries closest to expiry (expired ones first) make
/// room. Every instance of the app has its own: behind a load balancer, use
/// a [`RedisStore`](super::RedisStore) to share one cache.
///
/// ```
/// use pratique::prelude::*;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let store = Arc::new(MemoryStore::new().max_entries(10_000).max_bytes(256 << 20));
/// let cache = ResponseCache::new(Duration::from_secs(60)).store(store.clone());
/// assert!(store.is_empty());
/// ```
#[derive(Debug)]
pub struct MemoryStore {
    max_entries: usize,
    max_bytes: usize,
    entries: Mutex<Entries>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    /// At most 1 000 entries and 64 MiB.
    pub fn new() -> Self {
        Self {
            max_entries: 1000,
            max_bytes: 64 << 20,
            entries: Mutex::default(),
        }
    }

    /// Maximum number of entries (each response takes one, plus one per path
    /// for its `Vary` record).
    pub fn max_entries(mut self, n: usize) -> Self {
        self.max_entries = n;
        self
    }

    /// Maximum memory used by the keys and values, in bytes.
    pub fn max_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = bytes;
        self
    }

    /// Number of entries that have not expired.
    pub fn len(&self) -> usize {
        let now = Instant::now();
        self.lock().map.values().filter(|e| e.expires > now).count()
    }

    /// Whether no entry is alive.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Bytes used by the entries (keys, values and bookkeeping).
    pub fn bytes(&self) -> usize {
        self.lock().bytes
    }

    fn lock(&self) -> MutexGuard<'_, Entries> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl CacheStore for MemoryStore {
    fn get<'a>(&'a self, key: &'a str) -> StoreFuture<'a, Option<Bytes>> {
        let mut entries = self.lock();
        let value = match entries.map.get(key) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        };
        ready(value)
    }

    fn set<'a>(&'a self, key: &'a str, value: Bytes, ttl: Duration) -> StoreFuture<'a, ()> {
        let mut entries = self.lock();
        entries.remove(key);
        let size = cost(key, &value);
        if self.max_entries == 0 || size > self.max_bytes || ttl.is_zero() {
            return ready(());
        }
        while entries.map.len() >= self.max_entries || entries.bytes + size > self.max_bytes {
            if !entries.evict_soonest() {
                break;
            }
        }
        let now = Instant::now();
        let expires = now
            .checked_add(ttl.min(MAX_TTL))
            .unwrap_or(now + Duration::from_secs(86_400));
        entries.seq += 1;
        let seq = entries.seq;
        entries.expiry.insert((expires, seq), key.to_owned());
        entries.bytes += size;
        entries.map.insert(
            key.to_owned(),
            Entry {
                value,
                expires,
                seq,
            },
        );
        ready(())
    }

    fn remove_prefixes<'a>(&'a self, prefixes: &'a [String]) -> StoreFuture<'a, ()> {
        let mut entries = self.lock();
        let doomed: Vec<String> = entries
            .map
            .keys()
            .filter(|key| prefixes.iter().any(|p| key.starts_with(p.as_str())))
            .cloned()
            .collect();
        for key in doomed {
            entries.remove(&key);
        }
        ready(())
    }

    fn clear(&self) -> StoreFuture<'_, ()> {
        *self.lock() = Entries::default();
        ready(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block<T>(f: StoreFuture<'_, T>) -> T {
        // Memory store futures are always ready.
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let mut f = f;
        match f.as_mut().poll(&mut cx) {
            std::task::Poll::Ready(v) => v.unwrap(),
            std::task::Poll::Pending => unreachable!(),
        }
    }

    fn bytes(s: &'static str) -> Bytes {
        Bytes::from_static(s.as_bytes())
    }

    #[test]
    fn the_soonest_to_expire_makes_room() {
        let store = MemoryStore::new().max_entries(2);
        block(store.set("/a", bytes("a"), Duration::from_secs(60)));
        block(store.set("/b", bytes("b"), Duration::from_secs(1)));
        block(store.set("/c", bytes("c"), Duration::from_secs(60)));
        assert_eq!(block(store.get("/b")), None);
        assert_eq!(block(store.get("/a")).as_deref(), Some(&b"a"[..]));
        assert_eq!(store.len(), 2);
        // Replacing a key doesn't evict another one.
        block(store.set("/a", bytes("A"), Duration::from_secs(60)));
        assert_eq!(block(store.get("/c")).as_deref(), Some(&b"c"[..]));
        assert_eq!(block(store.get("/a")).as_deref(), Some(&b"A"[..]));
    }

    #[test]
    fn bytes_are_bounded() {
        let store = MemoryStore::new().max_bytes(3 * (2 + 100 + OVERHEAD));
        let value = Bytes::from(vec![0u8; 100]);
        for key in ["/1", "/2", "/3", "/4"] {
            block(store.set(key, value.clone(), Duration::from_secs(60)));
        }
        assert_eq!(store.len(), 3);
        assert_eq!(store.bytes(), 3 * (2 + 100 + OVERHEAD));
        assert_eq!(block(store.get("/1")), None);
        // Bigger than the whole budget: not stored.
        block(store.set(
            "/big",
            Bytes::from(vec![0u8; 1000]),
            Duration::from_secs(60),
        ));
        assert_eq!(block(store.get("/big")), None);
        assert_eq!(store.len(), 3);
    }

    #[test]
    fn ttls_prefixes_and_clear() {
        let store = MemoryStore::new();
        // Huge TTLs are capped instead of overflowing.
        block(store.set("/forever", bytes("x"), Duration::MAX));
        assert!(block(store.get("/forever")).is_some());
        block(store.set("/zero", bytes("x"), Duration::ZERO));
        assert_eq!(block(store.get("/zero")), None);
        block(store.set("/api?x", bytes("x"), Duration::from_secs(60)));
        block(store.set("/apix", bytes("x"), Duration::from_secs(60)));
        block(store.remove_prefixes(&["/api?".to_string()]));
        assert_eq!(block(store.get("/api?x")), None);
        assert!(block(store.get("/apix")).is_some());
        block(store.clear());
        assert!(store.is_empty());
        assert_eq!(store.bytes(), 0);
    }
}
