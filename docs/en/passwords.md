---
title: Password hashing
summary: Argon2id password hashing with the OWASP parameters, transparent upgrades at login, an optional pepper and protection against account enumeration.
category: access
order: 6
---

`PasswordHasher` stores passwords the way OWASP and RFC 9106 recommend: with **Argon2id**, a memory-hard function that makes GPU and ASIC cracking expensive, and a fresh random salt per password. It wraps the audited RustCrypto `argon2` crate and adds what a login flow needs on top: rehashing on login when you raise the cost, a dummy verification for unknown accounts, a pepper and sane limits.

## Threats mitigated

- **A02:2021 Cryptographic Failures** / **A07:2021 Identification and Authentication Failures**: passwords stored in clear, with a fast hash (MD5, SHA-256) or without salt are cracked within hours once the database leaks (CWE-916, CWE-759).
- **Account enumeration** (CWE-204): a login that answers faster when the e-mail address is unknown tells attackers which accounts exist.
- **Denial of service through hashing**: huge passwords, or a tampered hash row requesting gigabytes of memory.

## Quick start

The module is behind the `password` feature, enabled by default.

```rust
use securite::password::PasswordHasher;

let hasher = PasswordHasher::new(); // Argon2id, m = 19 MiB, t = 2, p = 1

// Registration: store this string as is (it contains the salt and the parameters).
let stored = hasher.hash("correct horse battery staple")?;
// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>

// Login.
assert!(hasher.verify("correct horse battery staple", &stored));
```

Hashing is deliberately slow (tens of milliseconds, 19 MiB of memory). In an async server, run it on a blocking thread so it does not stall other requests:

```rust
let hasher = hasher.clone(); // cheap: the hasher is shared
let ok = tokio::task::spawn_blocking(move || hasher.verify(&password, &stored)).await?;
```

## A complete login

```rust
use securite::password::{PasswordCheck, PasswordHasher};

fn login(hasher: &PasswordHasher, db: &Db, email: &str, password: &str) -> Result<User, LoginError> {
    let Some(user) = db.find_user_by_email(email) else {
        // Same work as a real verification: response times do not reveal
        // whether the address is registered.
        hasher.verify_dummy(password);
        return Err(LoginError::InvalidCredentials);
    };
    match hasher.check(password, &user.password_hash) {
        PasswordCheck::Valid => Ok(user),
        PasswordCheck::ValidNeedsRehash(new_hash) => {
            // The stored hash used weaker parameters (or Argon2i): upgrade it now,
            // the only moment the plain password is known.
            db.update_password_hash(user.id, &new_hash);
            Ok(user)
        }
        PasswordCheck::Invalid => Err(LoginError::InvalidCredentials),
    }
}
```

Return the same error and message for an unknown account and a wrong password. Combine with [login throttling](/docs/login-throttle) so a single account cannot be guessed at.

## How it works

1. **Hashing.** A 16-byte salt is drawn from the operating system's CSPRNG, then Argon2id (version 0x13) computes a 32-byte hash. The result is a PHC string that records the algorithm, the version, the costs and the salt, so every hash can be verified later even if the defaults change.
2. **Verification.** The PHC string is parsed and the password is hashed again with *the stored parameters*; outputs are compared in constant time. Malformed strings, bcrypt or PBKDF2 hashes, empty passwords and passwords above the length limit never match.
3. **Cost cap.** Before computing anything, the stored costs are compared with the configured ones: a row that asks for more than four times the configured memory or time is refused, so a tampered database cannot make the server allocate gigabytes.
4. **Upgrades.** `check` reports `ValidNeedsRehash` when the stored hash is weaker than the current parameters or is not Argon2id, together with a new hash made with the current parameters.

## Configuration

| Method | Default | Description |
|---|---|---|
| `PasswordHasher::new()` | — | Argon2id, `m = 19456 KiB, t = 2, p = 1` (OWASP). |
| `PasswordHasher::with_params(m_kib, t, p)` | — | Custom costs; panics below the OWASP minimum (`m ≥ 7168 KiB`, `m × t ≥ 35840`). |
| `.pepper(secret)` | none | Secret mixed into every hash (Argon2's secret input); at least 16 bytes. |
| `.max_password_bytes(n)` | `1024` | Longer passwords are refused, never truncated. |
| `.hash(password)` | — | `Result<String, PasswordError>` (`Empty`, `TooLong`, `Hashing`). |
| `.verify(password, hash)` | — | `bool`. |
| `.check(password, hash)` | — | `Invalid`, `Valid` or `ValidNeedsRehash(new_hash)`. |
| `.needs_rehash(hash)` | — | Whether the hash is weaker than the current parameters. |
| `.verify_dummy(password)` | — | Burns one verification and returns `false`. |

OWASP lists equivalent settings that trade memory for iterations, for example `with_params(47104, 1, 1)`, `with_params(12288, 3, 1)` or `with_params(9216, 4, 1)`. Raise them as your hardware allows: existing users are upgraded at their next login.

## Pepper

A pepper is a secret that lives outside the database (environment variable, secret manager). With it, a leaked database alone is useless to an attacker:

```rust
use securite::password::PasswordHasher;

let pepper = std::env::var("PASSWORD_PEPPER").expect("PASSWORD_PEPPER must be set");
let hasher = PasswordHasher::new().pepper(pepper);
```

Losing the pepper means every user must reset their password, and every hash made with it can only be verified with it: back it up like an encryption key.

## Pitfalls and tips

- Never hash passwords with SHA-256, MD5 or HMAC: they are designed to be fast. `Auth::token_sha256` is fine for random API tokens, not for human passwords.
- Do not truncate or normalise passwords silently. Let users type long passphrases; `1024` bytes is generous.
- Apply a password policy separately: minimum length (8 to 15 characters, per NIST SP 800-63B), a check against breached passwords, no composition rules.
- `PasswordCheck`'s `Debug` output never prints the hash, but keep the hashes themselves out of your logs.

## Related pages

- [Login throttling](/docs/login-throttle)
- [Two-factor authentication](/docs/two-factor)
- [Authentication](/docs/auth)
- [Authorization](/docs/authorization)
