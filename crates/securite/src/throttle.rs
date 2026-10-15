//! Brute-force protection for logins, password resets, 2FA codes and any
//! other guessable secret: Laravel's `RateLimiter` / `ThrottlesLogins` for
//! Rust.
//!
//! [`RateLimit`](crate::rate_limit::RateLimit) counts *requests* per IP before
//! the handler runs; it cannot know whether a login failed, nor which account
//! was targeted. [`LoginThrottle`] counts *failures* per key that your handler
//! chooses: the account and the client IP together (one attacker on one
//! account), the account alone (credential stuffing from many IPs), or the IP
//! alone (password spraying across accounts).
//!
//! ```
//! use std::time::Duration;
//! use securite::throttle::LoginThrottle;
//!
//! // 5 failures per account and IP, then locked until the 15 minutes are over.
//! let throttle = LoginThrottle::new(5, Duration::from_secs(15 * 60));
//!
//! let key = LoginThrottle::key("Alice@Example.com", Some("203.0.113.7".parse().unwrap()));
//! assert_eq!(key, "alice@example.com|203.0.113.7");
//!
//! let password_ok = |_: &str| false;
//! for _ in 0..5 {
//!     assert_eq!(throttle.attempt(&key, || password_ok("guess")), Ok(false));
//! }
//! // Sixth try: refused without even checking the password.
//! let retry_after = throttle.attempt(&key, || password_ok("guess")).unwrap_err();
//! assert!(retry_after <= Duration::from_secs(15 * 60));
//! ```
//!
//! Keys are stored as SHA-256 digests (no e-mail addresses in memory dumps),
//! in a sharded, bounded map; when it is full of live entries, new keys are
//! refused (fail closed) rather than tracked.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::counter::CounterStore;
use crate::store::ShardedMap;
use crate::util::ceil_secs;

#[derive(Clone, Copy)]
struct Entry {
    attempts: u32,
    /// When the window ends (store nanoseconds).
    resets_at: u64,
}

struct Inner {
    max_attempts: u32,
    decay: u64,
    store: ShardedMap<[u8; 32], Entry>,
    shared: Option<Arc<dyn CounterStore>>,
}

/// Counts failures per key and locks the key once `max_attempts` is reached,
/// until the decay window started by the first failure is over. Cheap to
/// clone (shared state). See the [module docs](self).
#[derive(Clone)]
pub struct LoginThrottle {
    inner: Arc<Inner>,
}

impl fmt::Debug for LoginThrottle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoginThrottle")
            .field("max_attempts", &self.inner.max_attempts)
            .field("decay", &Duration::from_nanos(self.inner.decay))
            .finish()
    }
}

impl Default for LoginThrottle {
    /// 5 failures per 15 minutes (OWASP ASVS 2.2.1 asks for at most 100
    /// failures per hour per account).
    fn default() -> Self {
        Self::new(5, Duration::from_secs(15 * 60))
    }
}

impl LoginThrottle {
    /// `max_attempts` failures per `decay` window, tracking up to 100 000 keys.
    pub fn new(max_attempts: u32, decay: Duration) -> Self {
        Self::with_capacity(max_attempts, decay, 100_000)
    }

    /// Like [`new`](Self::new) with a bound on the number of tracked keys.
    pub fn with_capacity(max_attempts: u32, decay: Duration, max_keys: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                max_attempts: max_attempts.max(1),
                decay: (decay.as_nanos().min(u128::from(u64::MAX)) as u64).max(1),
                store: ShardedMap::new(max_keys),
                shared: None,
            }),
        }
    }

    /// Like [`new`](Self::new), with the counters in a shared
    /// [`CounterStore`] (Redis …), so that every instance of the application
    /// enforces the same limit. A store error locks the key (fail closed).
    /// See [`counter`](crate::counter).
    pub fn with_store(max_attempts: u32, decay: Duration, store: Arc<dyn CounterStore>) -> Self {
        Self {
            inner: Arc::new(Inner {
                max_attempts: max_attempts.max(1),
                decay: (decay.as_nanos().min(u128::from(u64::MAX)) as u64).max(1),
                store: ShardedMap::new(16),
                shared: Some(store),
            }),
        }
    }

    fn shared_key(key: &str) -> String {
        format!(
            "securite:throttle:{}",
            crate::util::hex_encode(&Self::digest(key))
        )
    }

    fn decay(&self) -> Duration {
        Duration::from_nanos(self.inner.decay)
    }

    /// The conventional key for "this account from this address":
    /// the trimmed, lowercased identifier, `|`, then the IP (Laravel's
    /// `throttleKey`). Use the identifier alone for a per-account limit.
    pub fn key(identifier: &str, ip: Option<IpAddr>) -> String {
        let id = identifier.trim().to_lowercase();
        match ip {
            Some(ip) => format!("{id}|{}", crate::ip::canonical(ip)),
            None => id,
        }
    }

    fn digest(key: &str) -> [u8; 32] {
        Sha256::digest(key.as_bytes()).into()
    }

    fn now(&self) -> u64 {
        self.inner.store.now()
    }

    /// Records a failure and returns the number of failures in the current
    /// window (`max_attempts` when the key cannot be tracked).
    pub fn hit(&self, key: &str) -> u32 {
        self.hit_at(key, self.now())
    }

    fn hit_at(&self, key: &str, now: u64) -> u32 {
        self.try_hit_at(key, now).unwrap_or(self.inner.max_attempts)
    }

    /// `None` when the key cannot be tracked (store full of live entries).
    fn try_hit_at(&self, key: &str, now: u64) -> Option<u32> {
        if let Some(shared) = &self.inner.shared {
            return shared
                .increment(&Self::shared_key(key), self.decay())
                .ok()
                .map(|w| u32::try_from(w.count).unwrap_or(u32::MAX));
        }
        let decay = self.inner.decay;
        self.inner.store.update(
            Self::digest(key),
            |e| e.resets_at <= now,
            |entry| {
                let e = entry.or_insert(Entry {
                    attempts: 0,
                    resets_at: now + decay,
                });
                if e.resets_at <= now {
                    *e = Entry {
                        attempts: 0,
                        resets_at: now + decay,
                    };
                }
                e.attempts = e.attempts.saturating_add(1);
                e.attempts
            },
        )
    }

    /// Failures recorded in the current window.
    pub fn attempts(&self, key: &str) -> u32 {
        self.attempts_at(key, self.now())
    }

    fn attempts_at(&self, key: &str, now: u64) -> u32 {
        if let Some(shared) = &self.inner.shared {
            return match shared.get(&Self::shared_key(key)) {
                Ok(w) => w.map_or(0, |w| u32::try_from(w.count).unwrap_or(u32::MAX)),
                Err(_) => self.inner.max_attempts,
            };
        }
        self.inner.store.get(&Self::digest(key), |e| match e {
            Some(e) if e.resets_at > now => e.attempts,
            _ => 0,
        })
    }

    /// Failures left before the key is locked.
    pub fn remaining(&self, key: &str) -> u32 {
        self.inner.max_attempts.saturating_sub(self.attempts(key))
    }

    /// Whether the key is locked.
    pub fn too_many_attempts(&self, key: &str) -> bool {
        self.check(key).is_err()
    }

    /// `Ok` when the key may try again, else `Err(retry_after)` (send it in a
    /// `Retry-After` header with a `429`).
    pub fn check(&self, key: &str) -> Result<(), Duration> {
        self.check_at(key, self.now())
    }

    fn check_at(&self, key: &str, now: u64) -> Result<(), Duration> {
        if let Some(shared) = &self.inner.shared {
            return match shared.get(&Self::shared_key(key)) {
                Ok(Some(w)) if w.count >= u64::from(self.inner.max_attempts) => Err(
                    Duration::from_secs(w.resets_in.as_secs_f64().ceil().max(1.0) as u64),
                ),
                Ok(_) => Ok(()),
                Err(_) => Err(self.decay()),
            };
        }
        self.inner.store.get(&Self::digest(key), |e| match e {
            Some(e) if e.resets_at > now && e.attempts >= self.inner.max_attempts => {
                Err(Duration::from_secs(ceil_secs(e.resets_at - now).max(1)))
            }
            _ => Ok(()),
        })
    }

    /// Forgets the failures of `key` (call it after a successful login).
    pub fn clear(&self, key: &str) {
        if let Some(shared) = &self.inner.shared {
            let _ = shared.delete(&Self::shared_key(key));
            return;
        }
        self.inner.store.remove(&Self::digest(key));
    }

    /// The whole flow in one call: refuses a locked key without running
    /// `verify`, otherwise runs it, clears the key on success and records a
    /// failure otherwise.
    ///
    /// Returns `Ok(verified)`, or `Err(retry_after)` when the key is locked
    /// (or cannot be tracked).
    pub fn attempt(&self, key: &str, verify: impl FnOnce() -> bool) -> Result<bool, Duration> {
        self.check(key)?;
        if verify() {
            self.clear(key);
            Ok(true)
        } else {
            match self.try_hit_at(key, self.now()) {
                // Untrackable key (store full): fail closed.
                None => Err(Duration::from_nanos(self.inner.decay)),
                Some(_) => Ok(false),
            }
        }
    }

    /// Checks several keys at once (for instance per account+IP *and* per
    /// account): the longest wait wins.
    pub fn check_all<'a>(&self, keys: impl IntoIterator<Item = &'a str>) -> Result<(), Duration> {
        let mut wait: Option<Duration> = None;
        for key in keys {
            if let Err(d) = self.check(key) {
                wait = Some(wait.map_or(d, |w| w.max(d)));
            }
        }
        wait.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::counter::{MemoryCounterStore, StoreError, Window};

    #[test]
    fn shared_store_is_shared_and_hashed() {
        let store = Arc::new(MemoryCounterStore::new(100));
        let a = LoginThrottle::with_store(2, Duration::from_secs(60), store.clone());
        let b = LoginThrottle::with_store(2, Duration::from_secs(60), store.clone());
        assert_eq!(a.attempt("bob@x.io|1.2.3.4", || false), Ok(false));
        assert_eq!(b.attempt("bob@x.io|1.2.3.4", || false), Ok(false));
        let wait = a.attempt("bob@x.io|1.2.3.4", || true).unwrap_err();
        assert!(wait <= Duration::from_secs(60) && wait >= Duration::from_secs(59));
        assert_eq!(b.attempts("bob@x.io|1.2.3.4"), 2);
        assert_eq!(b.remaining("bob@x.io|1.2.3.4"), 0);
        // The store never sees the e-mail address.
        let key = LoginThrottle::shared_key("bob@x.io|1.2.3.4");
        assert!(key.starts_with("securite:throttle:") && !key.contains("bob"));
        assert!(store.get(&key).unwrap().is_some());
        b.clear("bob@x.io|1.2.3.4");
        assert!(a.check("bob@x.io|1.2.3.4").is_ok());
    }

    struct Down;
    impl CounterStore for Down {
        fn increment(&self, _: &str, _: Duration) -> Result<Window, StoreError> {
            Err(StoreError)
        }
        fn get(&self, _: &str) -> Result<Option<Window>, StoreError> {
            Err(StoreError)
        }
        fn delete(&self, _: &str) -> Result<(), StoreError> {
            Err(StoreError)
        }
    }

    #[test]
    fn store_outage_fails_closed() {
        let t = LoginThrottle::with_store(5, Duration::from_secs(30), Arc::new(Down));
        let mut verified = false;
        assert_eq!(
            t.attempt("k", || {
                verified = true;
                true
            }),
            Err(Duration::from_secs(30))
        );
        assert!(!verified, "the password is not even checked");
        assert!(t.too_many_attempts("k"));
        assert_eq!(t.hit("k"), 5);
    }

    const S: u64 = 1_000_000_000;

    #[test]
    fn locks_after_max_attempts_until_the_window_ends() {
        let t = LoginThrottle::new(3, Duration::from_secs(60));
        let k = "bob|1.2.3.4";
        assert_eq!(t.hit_at(k, 0), 1);
        assert_eq!(t.hit_at(k, S), 2);
        assert!(t.check_at(k, S).is_ok());
        assert_eq!(t.hit_at(k, 2 * S), 3);
        assert_eq!(t.check_at(k, 2 * S), Err(Duration::from_secs(58)));
        assert_eq!(t.check_at(k, 59 * S + 1), Err(Duration::from_secs(1)));
        assert!(t.check_at(k, 60 * S).is_ok(), "window over");
        assert_eq!(t.attempts_at(k, 60 * S), 0);
        assert_eq!(t.hit_at(k, 60 * S), 1, "a new window starts");
    }

    #[test]
    fn keys_are_independent_and_clear_resets() {
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        t.hit("a");
        t.hit("a");
        assert!(t.too_many_attempts("a"));
        assert!(!t.too_many_attempts("b"));
        assert_eq!(t.remaining("b"), 2);
        t.clear("a");
        assert!(!t.too_many_attempts("a"));
        assert_eq!(t.attempts("a"), 0);
    }

    #[test]
    fn attempt_flow() {
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        assert_eq!(t.attempt("k", || false), Ok(false));
        assert_eq!(t.attempt("k", || true), Ok(true));
        assert_eq!(t.attempts("k"), 0, "success clears");
        assert_eq!(t.attempt("k", || false), Ok(false));
        assert_eq!(t.attempt("k", || false), Ok(false));
        let mut called = false;
        assert!(
            t.attempt("k", || {
                called = true;
                true
            })
            .is_err()
        );
        assert!(
            !called,
            "the right password is not even checked once locked"
        );
    }

    #[test]
    fn key_normalisation() {
        let ip: IpAddr = "::ffff:10.0.0.1".parse().unwrap();
        assert_eq!(
            LoginThrottle::key("  Bob@X.org ", Some(ip)),
            "bob@x.org|10.0.0.1"
        );
        assert_eq!(LoginThrottle::key("Bob", None), "bob");
        // Case variations hit the same counter.
        let t = LoginThrottle::new(2, Duration::from_secs(60));
        t.hit(&LoginThrottle::key("ALICE", None));
        t.hit(&LoginThrottle::key("alice", None));
        assert!(t.too_many_attempts("alice"));
    }

    #[test]
    fn check_all_takes_the_longest_wait() {
        let t = LoginThrottle::new(1, Duration::from_secs(60));
        assert!(t.check_all(["a", "b"]).is_ok());
        t.hit("b");
        assert!(t.check_all(["a", "b"]).is_err());
    }

    #[test]
    fn full_store_fails_closed() {
        // 64 shards with at least 16 entries each.
        let t = LoginThrottle::with_capacity(5, Duration::from_secs(60), 0);
        for i in 0..5_000 {
            t.hit(&format!("flood-{i}"));
        }
        let mut refused = 0;
        for i in 0..200 {
            if t.attempt(&format!("victim-{i}"), || false).is_err() {
                refused += 1;
            }
        }
        assert!(refused > 0, "untracked keys are refused");
    }

    #[test]
    fn debug_does_not_leak_keys() {
        let t = LoginThrottle::default();
        t.hit("secret@example.com");
        assert!(!format!("{t:?}").contains("secret"));
    }
}
