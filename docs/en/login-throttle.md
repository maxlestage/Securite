---
title: Login throttling
summary: Locks an account, an address or both after repeated failures, against password guessing, credential stuffing and 2FA brute force.
category: traffic
order: 7
---

`LoginThrottle` counts **failed attempts** per key you choose and locks the key once a limit is reached, until its window is over. It is Laravel's `RateLimiter` / `ThrottlesLogins` for Rust. Where [rate limiting](/docs/rate-limit) counts requests per IP before your handler runs, `LoginThrottle` is called from the handler, once you know which account was targeted and whether the attempt failed.

## Threats mitigated

- **A07:2021 Identification and Authentication Failures**: online password guessing against one account (CWE-307).
- **Credential stuffing and password spraying**: leaked credentials tried from thousands of IPs, or one common password tried on every account.
- **2FA brute force**: a 6-digit code has a million values; without a limit, it falls in hours.

## Quick start

```rust
use std::time::Duration;
use securite::prelude::*;

// 5 failures per account and IP; then locked until the 15 minutes are over.
let throttle = LoginThrottle::new(5, Duration::from_secs(15 * 60));

// In the login handler:
let key = LoginThrottle::key(&form.email, client_ip); // "alice@example.com|203.0.113.7"
match throttle.attempt(&key, || hasher.verify(&form.password, &user.password_hash)) {
    Ok(true) => { /* logged in: the failures of this key are forgotten */ }
    Ok(false) => { /* 401: wrong credentials */ }
    Err(retry_after) => { /* 429 with `Retry-After: retry_after.as_secs()` */ }
}
```

`attempt` refuses a locked key **without running** the verification: even the right password is refused until the window ends, so an attacker learns nothing from a lucky guess.

## How it works

1. The first failure of a key opens a window of `decay`.
2. Each failure inside the window increments the counter; `check` fails once it reaches `max_attempts`, with the time left as `Retry-After`.
3. When the window is over the counter starts again from zero; a success (`clear`) forgets it at once.
4. Keys are stored as SHA-256 digests in a sharded, bounded map (100 000 keys by default) that cleans itself. When it is full of live entries, new keys are refused (fail closed) instead of being silently untracked.

## Choosing keys

One throttle per question you want to answer:

| Key | Stops | Example |
|---|---|---|
| account + IP | one attacker on one account, without locking the real user out from elsewhere | `LoginThrottle::key(email, Some(ip))` |
| account | credential stuffing from many IPs | `LoginThrottle::key(email, None)`, with a higher limit |
| IP | password spraying across accounts | `ip.to_string()` |

```rust
use std::time::Duration;
use securite::prelude::*;

let per_account_ip = LoginThrottle::new(5, Duration::from_secs(15 * 60));
let per_account = LoginThrottle::new(50, Duration::from_secs(60 * 60));

let k1 = LoginThrottle::key(&email, Some(ip));
let k2 = LoginThrottle::key(&email, None);
per_account_ip.check(&k1).and(per_account.check(&k2))?; // Err(retry_after): 429
if hasher.verify(&password, &hash) {
    per_account_ip.clear(&k1);
    per_account.clear(&k2);
} else {
    per_account_ip.hit(&k1);
    per_account.hit(&k2);
}
```

`key` trims and lowercases the identifier, so `Alice@Example.com` and `alice@example.com` share a counter.

## Configuration

| Method | Description |
|---|---|
| `LoginThrottle::new(max_attempts, decay)` | Limit and window; tracks up to 100 000 keys. |
| `LoginThrottle::default()` | 5 failures per 15 minutes. |
| `LoginThrottle::with_capacity(max, decay, keys)` | Custom bound on tracked keys. |
| `LoginThrottle::key(identifier, ip)` | `"identifier\|ip"`, normalised. |
| `.attempt(key, verify)` | `Ok(bool)` or `Err(retry_after)`; clears on success, counts failures. |
| `.check(key)` / `.too_many_attempts(key)` | Whether the key is locked. |
| `.check_all(keys)` | Several keys of one throttle; the longest wait wins. |
| `.hit(key)` | Records a failure, returns the count. |
| `.clear(key)` | Forgets the failures (after a success). |
| `.attempts(key)` / `.remaining(key)` | Current counters. |

## Pitfalls and tips

- A lockout per account alone lets an attacker lock any user out on purpose: prefer account + IP for the strict limit and keep the per-account limit high.
- Use the same throttle for 2FA codes, password-reset requests and e-mail verification resends, each with its own keys.
- The state is in memory, per process. With several instances, each counts on its own: share the counters with `LoginThrottle::with_store` (see [shared counters](/docs/shared-counters)), or divide your limits accordingly.
- Behind a proxy, configure the [client IP](/docs/client-ip) (and trusted proxies) or every user shares the proxy's address.
- [Auto-ban](/docs/auto-ban) complements it: repeated `401` and `429` responses ban the address across the whole application.

## Related pages

- [Password hashing](/docs/passwords)
- [Two-factor authentication](/docs/two-factor)
- [Rate limiting](/docs/rate-limit)
- [Auto-ban](/docs/auto-ban)
