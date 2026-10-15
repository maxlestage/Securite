//! Shared counters, so that several instances of an application enforce one
//! limit together (Laravel's cache-backed `RateLimiter`).
//!
//! Each instance of an application keeps its own memory: behind a load
//! balancer with 4 instances, a limit of 5 login failures becomes 20. A
//! [`CounterStore`] moves the counters out of the process (Redis, Memcached,
//! a database …); [`LoginThrottle::with_store`](crate::throttle::LoginThrottle::with_store)
//! uses it.
//!
//! The model is a **fixed window counter**, which every store implements
//! atomically: Redis `INCR` + `PEXPIRE key ttl NX` + `PTTL` (in a `MULTI` or
//! a Lua script), SQL `INSERT … ON CONFLICT DO UPDATE … RETURNING`.
//!
//! Keys handed to the store are already hashed (64 hex characters, prefixed
//! by a namespace such as `securite:throttle:`): no e-mail address or IP ends
//! up in Redis.
//!
//! **Fail closed**: when the store answers an error, the throttle treats the
//! key as locked. An attacker who can make Redis fail cannot use it to
//! brute-force passwords.
//!
//! ```
//! use std::sync::Arc;
//! use std::time::Duration;
//! use securite::counter::MemoryCounterStore;
//! use securite::throttle::LoginThrottle;
//!
//! let store = Arc::new(MemoryCounterStore::new(100_000));
//! // Two "instances" sharing the store share the limit.
//! let a = LoginThrottle::with_store(3, Duration::from_secs(60), store.clone());
//! let b = LoginThrottle::with_store(3, Duration::from_secs(60), store);
//! a.hit("alice");
//! b.hit("alice");
//! a.hit("alice");
//! assert!(b.too_many_attempts("alice"));
//! ```
//!
//! A Redis store, with the synchronous API of the `redis` crate:
//!
//! ```ignore
//! struct RedisCounters(r2d2::Pool<redis::Client>);
//!
//! impl CounterStore for RedisCounters {
//!     fn increment(&self, key: &str, window: Duration) -> Result<Window, StoreError> {
//!         let mut c = self.0.get().map_err(|_| StoreError)?;
//!         let (count, ttl): (u64, i64) = redis::pipe().atomic()
//!             .incr(key, 1)
//!             .cmd("PEXPIRE").arg(key).arg(window.as_millis() as u64).arg("NX").ignore()
//!             .cmd("PTTL").arg(key)
//!             .query(&mut *c).map_err(|_| StoreError)?;
//!         Ok(Window { count, resets_in: Duration::from_millis(ttl.max(1) as u64) })
//!     }
//!     // get: GET + PTTL, delete: DEL …
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A store could not be reached or answered an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StoreError;

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("counter store unavailable")
    }
}

impl std::error::Error for StoreError {}

/// The state of a counter in its window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Window {
    /// Hits in the current window.
    pub count: u64,
    /// Time left before the window ends and the counter disappears.
    pub resets_in: Duration,
}

/// Fixed-window counters shared by several instances. See the
/// [module docs](self).
pub trait CounterStore: Send + Sync + 'static {
    /// Adds one to `key`; a new (or expired) key starts a window of
    /// `window`. Must be atomic.
    fn increment(&self, key: &str, window: Duration) -> Result<Window, StoreError>;
    /// The current window of `key`, `None` when absent or expired.
    fn get(&self, key: &str) -> Result<Option<Window>, StoreError>;
    /// Removes `key`.
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}

/// In-process [`CounterStore`] (tests, single instance), bounded: when full
/// of live counters, new keys get a [`StoreError`] (fail closed).
#[derive(Debug)]
pub struct MemoryCounterStore {
    map: Mutex<HashMap<String, (u64, Instant)>>,
    max: usize,
}

impl MemoryCounterStore {
    /// A store of at most `max_keys` counters.
    pub fn new(max_keys: usize) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            max: max_keys.max(1),
        }
    }
}

impl CounterStore for MemoryCounterStore {
    fn increment(&self, key: &str, window: Duration) -> Result<Window, StoreError> {
        let now = Instant::now();
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        if map.len() >= self.max && !map.contains_key(key) {
            map.retain(|_, (_, until)| *until > now);
            if map.len() >= self.max {
                return Err(StoreError);
            }
        }
        let e = map.entry(key.to_owned()).or_insert((0, now + window));
        if e.1 <= now {
            *e = (0, now + window);
        }
        e.0 = e.0.saturating_add(1);
        Ok(Window {
            count: e.0,
            resets_in: e.1 - now,
        })
    }

    fn get(&self, key: &str) -> Result<Option<Window>, StoreError> {
        let now = Instant::now();
        let map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        Ok(map
            .get(key)
            .filter(|(_, until)| *until > now)
            .map(|(c, until)| Window {
                count: *c,
                resets_in: *until - now,
            }))
    }

    fn delete(&self, key: &str) -> Result<(), StoreError> {
        self.map
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_window() {
        let s = MemoryCounterStore::new(10);
        let w = Duration::from_millis(50);
        assert_eq!(s.increment("k", w).unwrap().count, 1);
        assert_eq!(s.increment("k", w).unwrap().count, 2);
        assert_eq!(s.get("k").unwrap().unwrap().count, 2);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(s.get("k").unwrap(), None);
        assert_eq!(s.increment("k", w).unwrap().count, 1);
        s.delete("k").unwrap();
        assert_eq!(s.get("k").unwrap(), None);
    }

    #[test]
    fn full_store_fails_closed() {
        let s = MemoryCounterStore::new(2);
        let w = Duration::from_secs(60);
        s.increment("a", w).unwrap();
        s.increment("b", w).unwrap();
        assert_eq!(s.increment("c", w), Err(StoreError));
        assert!(s.increment("a", w).is_ok(), "existing keys still count");
    }
}
