---
title: Encryption
summary: Laravel-style Crypt with XChaCha20-Poly1305, versioned keys and rotation, purposes and contexts, expiring tokens and encrypted cookies bound to their name.
category: integrity
order: 6
---

`Encrypter` turns bytes into an opaque, URL- and cookie-safe token that only your server can read, and that cannot be changed without detection. It is Laravel's `Crypt` for Rust, built on the audited RustCrypto `chacha20poly1305` crate (feature `crypt`, on by default).

## Threats mitigated

- **A02:2021 Cryptographic Failures**: values the client must hold but not read (CWE-311) or change (CWE-345).
- **Tampering**: XChaCha20-Poly1305 is authenticated encryption; a single flipped bit makes decryption fail.
- **Nonce reuse**: the 192-bit nonce is drawn from the operating system RNG for each message, so random nonces never collide in practice.
- **Cookie swapping**: an encrypted cookie only decrypts under its own name, so the value of `prefs` cannot be replayed as `role`.

## Quick start

```rust
use securite::crypt::Encrypter;

// Once: `Encrypter::generate_key()` → keep it in a secret (APP_KEY).
let crypt = Encrypter::from_base64(&std::env::var("APP_KEY")?)?;

let token = crypt.encrypt_str("4111 1111 1111 1111");
let card = crypt.decrypt_str(&token)?;
```

## Purposes, contexts and expiry

```rust
use std::time::Duration;

// A token for one use does not open anywhere else.
let remember = crypt.clone().purpose("remember-me");
let t = remember.encrypt_with_ttl(b"user:42", Duration::from_secs(30 * 24 * 3600));

// Bind a value to its row: copying a ciphertext to another user's row breaks it.
let iban = crypt.encrypt_in("user:42:iban", b"FR76...", None);
assert!(crypt.decrypt_in("user:43:iban", &iban).is_err());
```

## Encrypted cookies

```rust
let value = crypt.encrypt_cookie("prefs", "theme=dark", None);
// Set-Cookie: prefs=<value>; Path=/; HttpOnly; Secure; SameSite=Lax
// (or let CookieHardening add the attributes)

let prefs = crypt.read_cookie(req.headers(), "prefs"); // None if forged, expired or moved
```

When the client may read the value but must not change it, sign it instead: `Signer::sign_cookie(name, value)` and `unsign_cookie` (see [signed URLs and tokens](/docs/signed-urls)).

## Key rotation

Every token carries a format version and the id of the key that sealed it (a 4-byte fingerprint, never the key itself). Rotate without logging anybody out:

```rust
let crypt = Encrypter::from_base64(&new_key)?
    .fallback_key_base64(&old_key)?; // still decrypts old tokens
```

New tokens are sealed with the new key; drop the old one once the longest-lived token has expired. `crypt.key_id()` prints the id of the current key, handy to check a deployment.

## Configuration

| Method | Description |
|---|---|
| `Encrypter::new(&[u8; 32])` / `try_new` / `from_base64` | The key (32 random bytes; `base64:` prefix accepted). |
| `Encrypter::generate_key()` | A new random key, base64. |
| `.purpose(p)` | Binds tokens to a use. |
| `.fallback_key(old)` | Key rotation. |
| `.encrypt` / `.encrypt_str` / `.encrypt_with_ttl` | Seal. |
| `.decrypt` / `.decrypt_str` | `Err(Malformed / Invalid / Expired)`. |
| `.encrypt_in(context, …)` / `.decrypt_in` | Values bound to a context. |
| `.encrypt_cookie` / `.decrypt_cookie` / `.read_cookie` | Encrypted cookies. |

## Pitfalls and tips

- The key is everything: keep it out of the repository, and never reuse it for another purpose (e.g. as a signing secret).
- Encryption hides the content, not the size: pad values if the length is sensitive.
- Do not encrypt passwords: [hash them](/docs/passwords).

## Related pages

- [Signed URLs and tokens](/docs/signed-urls)
- [Cookies](/docs/cookies)
- [Sessions](/docs/sessions)
