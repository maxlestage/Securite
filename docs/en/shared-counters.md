---
title: Shared counters
summary: One login-throttling limit for every instance of your application, with counters in Redis or any store, hashed keys and fail-closed behaviour.
category: traffic
order: 8
---

Each instance of an application counts in its own memory: behind a load balancer with four instances, "5 failures per 15 minutes" becomes 20. A `CounterStore` moves the counters out of the process (Redis, Memcached, a database), and `LoginThrottle::with_store` uses it.

## Threats mitigated

- **Distributed brute force** (CWE-307): an attacker spreads attempts over every instance to multiply the limit.
- **Store outages**: when the store answers an error, the key is treated as locked (fail closed); breaking Redis does not open the door.
- **Privacy**: keys reach the store as `securite:throttle:<sha-256>`, never as e-mail addresses or IPs.

## Quick start

```rust
use std::sync::Arc;
use std::time::Duration;
use securite::throttle::LoginThrottle;

let store = Arc::new(MyRedisCounters::new(pool)); // implements CounterStore
let throttle = LoginThrottle::with_store(5, Duration::from_secs(15 * 60), store);
// Same API as before: attempt, check, hit, clear …
```

`MemoryCounterStore` implements the trait in memory (tests, one instance).

## Implementing a store

The model is a fixed-window counter, which every store can do atomically:

```rust
use std::time::Duration;
use securite::counter::{CounterStore, StoreError, Window};

impl CounterStore for MyRedisCounters {
    fn increment(&self, key: &str, window: Duration) -> Result<Window, StoreError> {
        let mut c = self.pool.get().map_err(|_| StoreError)?;
        let (count, ttl): (u64, i64) = redis::pipe().atomic()
            .incr(key, 1)
            .cmd("PEXPIRE").arg(key).arg(window.as_millis() as u64).arg("NX").ignore()
            .cmd("PTTL").arg(key)
            .query(&mut *c).map_err(|_| StoreError)?;
        Ok(Window { count, resets_in: Duration::from_millis(ttl.max(1) as u64) })
    }
    fn get(&self, key: &str) -> Result<Option<Window>, StoreError> { /* GET + PTTL */ }
    fn delete(&self, key: &str) -> Result<(), StoreError> { /* DEL */ }
}
```

Calls are synchronous: use a connection pool and short timeouts (a few hundred milliseconds), since a slow store slows down logins.

## Pitfalls and tips

- `PEXPIRE … NX` (Redis 7) only sets the TTL of a new window; on older versions, set it when `INCR` returns 1.
- Keep the in-memory throttle for single-instance deployments: it is faster and has no external dependency.
- [Rate limiting](/docs/rate-limit) and [auto-ban](/docs/auto-ban) still count per instance.

## Related pages

- [Login throttling](/docs/login-throttle)
- [Rate limiting](/docs/rate-limit)
