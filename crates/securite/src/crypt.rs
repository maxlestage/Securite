//! Authenticated encryption, like Laravel's `Crypt` facade and its encrypted
//! cookies.
//!
//! An [`Encrypter`] turns bytes into an opaque, URL- and cookie-safe token that
//! only the server can read, and that cannot be modified without detection.
//! Use it for values that you hand to a client but that the client must not
//! read: encrypted cookies, "remember me" payloads, state parameters of OAuth
//! flows, values stored in hidden form fields, data at rest in a database
//! column …
//!
//! * **Audited primitives only**: XChaCha20-Poly1305 (RFC 8439 with the
//!   extended 192-bit nonce) from the RustCrypto `chacha20poly1305` crate. The
//!   192-bit nonce is drawn from the operating system RNG for every message,
//!   so random nonces never collide in practice (no counter to persist).
//! * **Versioned keys and rotation**: every token carries a format version and
//!   the id of the key that sealed it (a 4-byte fingerprint, never the key).
//!   Encrypt with the new key and keep reading old tokens with
//!   [`Encrypter::fallback_key`].
//! * **Purposes and contexts** are authenticated (AEAD associated data): a
//!   token sealed for the `"remember-me"` purpose, or for the cookie
//!   `session`, does not open anywhere else. This stops the cookie swapping
//!   attacks of naive encrypted cookies.
//! * **Optional expiry**, sealed inside the ciphertext.
//!
//! ```
//! use std::time::Duration;
//! use securite::crypt::{DecryptError, Encrypter};
//!
//! // 32 random bytes, e.g. from `Encrypter::generate_key()` kept in an env variable.
//! let key = [7u8; 32];
//! let crypt = Encrypter::new(&key);
//!
//! let token = crypt.encrypt_str("4111 1111 1111 1111");
//! assert_ne!(token, "4111 1111 1111 1111");
//! assert_eq!(crypt.decrypt_str(&token).unwrap(), "4111 1111 1111 1111");
//!
//! // Purposes are bound to the ciphertext.
//! let remember = Encrypter::new(&key).purpose("remember-me");
//! assert_eq!(remember.decrypt_str(&token), Err(DecryptError::Invalid));
//!
//! // Expiring tokens.
//! let short = crypt.encrypt_with_ttl(b"one-time", Duration::from_secs(600));
//! assert_eq!(crypt.decrypt(&short).unwrap(), b"one-time");
//! ```
//!
//! # Encrypted cookies
//!
//! ```
//! use http::{HeaderMap, HeaderValue};
//! use securite::crypt::Encrypter;
//!
//! let crypt = Encrypter::new(&[9u8; 32]);
//! let value = crypt.encrypt_cookie("prefs", "theme=dark", None);
//! // Send `Set-Cookie: prefs=<value>; Path=/; HttpOnly; Secure; SameSite=Lax` …
//!
//! // … and read it back from the next request:
//! let mut headers = HeaderMap::new();
//! headers.insert("cookie", HeaderValue::from_str(&format!("prefs={value}")).unwrap());
//! assert_eq!(crypt.read_cookie(&headers, "prefs").as_deref(), Some("theme=dark"));
//!
//! // The same value under another cookie name is refused.
//! assert!(crypt.decrypt_cookie("admin", &value).is_err());
//! ```

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use http::HeaderMap;
use http::header::COOKIE;
use sha2::{Digest, Sha256};

use crate::util::{b64std, b64std_decode, b64url, b64url_decode, cookie_pairs, secure_random};

/// Length of a key, in bytes.
pub const KEY_BYTES: usize = 32;

/// Current token format version.
const VERSION: u8 = 1;
const KID_BYTES: usize = 4;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 1 + KID_BYTES;
/// Longest token that is even looked at (bigger inputs are malformed).
const MAX_TOKEN: usize = 64 * 1024;

/// Why a token could not be decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecryptError {
    /// Not a token of this format (bad encoding, too short, unknown version …).
    Malformed,
    /// Authentication failed: tampered, another purpose or context, unknown key.
    Invalid,
    /// The token is authentic but has expired.
    Expired,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            DecryptError::Malformed => "malformed ciphertext",
            DecryptError::Invalid => "ciphertext authentication failed",
            DecryptError::Expired => "expired ciphertext",
        })
    }
}

impl std::error::Error for DecryptError {}

/// A key that is not exactly [`KEY_BYTES`] long, or not valid base64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidKey;

impl fmt::Display for InvalidKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "an encryption key must be exactly {KEY_BYTES} random bytes"
        )
    }
}

impl std::error::Error for InvalidKey {}

#[derive(Clone)]
struct Key {
    id: [u8; KID_BYTES],
    cipher: XChaCha20Poly1305,
}

/// Encrypts and decrypts tokens. Cheap to clone. See the [module docs](self).
#[derive(Clone)]
pub struct Encrypter {
    /// The first key encrypts; every key decrypts.
    keys: Arc<Vec<Key>>,
    purpose: String,
}

impl fmt::Debug for Encrypter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Encrypter")
            .field("keys", &self.keys.len())
            .field("purpose", &self.purpose)
            .finish()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn make_key(raw: &[u8]) -> Result<Key, InvalidKey> {
    if raw.len() != KEY_BYTES || raw.iter().all(|&b| b == 0) {
        return Err(InvalidKey);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(raw).map_err(|_| InvalidKey)?;
    let digest = Sha256::new()
        .chain_update(b"securite.crypt.kid\0")
        .chain_update(raw)
        .finalize();
    let mut id = [0u8; KID_BYTES];
    id.copy_from_slice(&digest[..KID_BYTES]);
    Ok(Key { id, cipher })
}

/// Decodes a key written as base64 (standard or URL-safe, optionally with
/// Laravel's `base64:` prefix).
fn decode_key(encoded: &str) -> Result<Vec<u8>, InvalidKey> {
    let s = encoded.trim();
    let s = s.strip_prefix("base64:").unwrap_or(s);
    b64std_decode(s)
        .or_else(|| b64url_decode(s.trim_end_matches('=')))
        .ok_or(InvalidKey)
}

impl Encrypter {
    /// An encrypter with `key`, exactly [`KEY_BYTES`] random bytes (see
    /// [`generate_key`](Self::generate_key)).
    ///
    /// # Panics
    ///
    /// If the key is not 32 bytes long, or is all zeros. Use
    /// [`try_new`](Self::try_new) to handle the error.
    pub fn new(key: &[u8]) -> Self {
        Self::try_new(key).expect("invalid encryption key")
    }

    /// Like [`new`](Self::new), without panicking.
    pub fn try_new(key: &[u8]) -> Result<Self, InvalidKey> {
        Ok(Self {
            keys: Arc::new(vec![make_key(key)?]),
            purpose: String::from("default"),
        })
    }

    /// An encrypter with a base64 key (`base64:` prefix accepted), as printed
    /// by [`generate_key`](Self::generate_key) and kept in an environment
    /// variable.
    pub fn from_base64(key: &str) -> Result<Self, InvalidKey> {
        Self::try_new(&decode_key(key)?)
    }

    /// A new random key, base64 encoded (Laravel's `php artisan key:generate`).
    pub fn generate_key() -> String {
        let mut key = [0u8; KEY_BYTES];
        secure_random(&mut key);
        b64std(&key)
    }

    /// Binds every token to a purpose: tokens sealed for one purpose do not
    /// open for any other one.
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = purpose.into();
        self
    }

    /// Also decrypts tokens sealed with `old_key` (key rotation). New tokens
    /// are always sealed with the key given to [`new`](Self::new).
    ///
    /// # Panics
    ///
    /// If the key is invalid (see [`new`](Self::new)).
    pub fn fallback_key(mut self, old_key: &[u8]) -> Self {
        let key = make_key(old_key).expect("invalid encryption key");
        Arc::make_mut(&mut self.keys).push(key);
        self
    }

    /// [`fallback_key`](Self::fallback_key) with a base64 key.
    pub fn fallback_key_base64(self, old_key: &str) -> Result<Self, InvalidKey> {
        let raw = decode_key(old_key)?;
        make_key(&raw)?;
        Ok(self.fallback_key(&raw))
    }

    /// The identifier of the current key, as stored in new tokens (8 hex
    /// characters). Handy to check, in logs, which key a deployment uses.
    pub fn key_id(&self) -> String {
        crate::util::hex_encode(&self.keys[0].id)
    }

    fn aad(&self, header: &[u8], context: &str) -> Vec<u8> {
        let mut aad = Vec::with_capacity(48 + self.purpose.len() + context.len());
        aad.extend_from_slice(b"securite.crypt.v1\0");
        aad.extend_from_slice(header);
        aad.extend_from_slice(&(self.purpose.len() as u64).to_be_bytes());
        aad.extend_from_slice(self.purpose.as_bytes());
        aad.extend_from_slice(&(context.len() as u64).to_be_bytes());
        aad.extend_from_slice(context.as_bytes());
        aad
    }

    fn seal(&self, plaintext: &[u8], expires: Option<u64>, context: &str) -> String {
        let key = &self.keys[0];
        let mut header = [0u8; HEADER_BYTES];
        header[0] = VERSION;
        header[1..].copy_from_slice(&key.id);
        let mut nonce = [0u8; NONCE_BYTES];
        secure_random(&mut nonce);
        let mut message = Vec::with_capacity(8 + plaintext.len());
        message.extend_from_slice(&expires.unwrap_or(0).to_be_bytes());
        message.extend_from_slice(plaintext);
        let aad = self.aad(&header, context);
        let ciphertext = key
            .cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: &message,
                    aad: &aad,
                },
            )
            .expect("XChaCha20-Poly1305 encryption cannot fail below 256 GiB");
        let mut out = Vec::with_capacity(HEADER_BYTES + NONCE_BYTES + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        b64url(&out)
    }

    fn open(&self, token: &str, context: &str, now: u64) -> Result<Vec<u8>, DecryptError> {
        if token.len() > MAX_TOKEN {
            return Err(DecryptError::Malformed);
        }
        let raw = b64url_decode(token).ok_or(DecryptError::Malformed)?;
        if raw.len() < HEADER_BYTES + NONCE_BYTES + TAG_BYTES + 8 {
            return Err(DecryptError::Malformed);
        }
        let (header, rest) = raw.split_at(HEADER_BYTES);
        if header[0] != VERSION {
            return Err(DecryptError::Malformed);
        }
        let (nonce, ciphertext) = rest.split_at(NONCE_BYTES);
        let nonce = XNonce::try_from(nonce).map_err(|_| DecryptError::Malformed)?;
        let aad = self.aad(header, context);
        let message = self
            .keys
            .iter()
            .filter(|k| k.id[..] == header[1..])
            .find_map(|k| {
                k.cipher
                    .decrypt(
                        &nonce,
                        Payload {
                            msg: ciphertext,
                            aad: &aad,
                        },
                    )
                    .ok()
            })
            .ok_or(DecryptError::Invalid)?;
        let (exp, plaintext) = message.split_at(8);
        let exp = u64::from_be_bytes(exp.try_into().map_err(|_| DecryptError::Malformed)?);
        if exp != 0 && now > exp {
            return Err(DecryptError::Expired);
        }
        Ok(plaintext.to_vec())
    }

    /// Encrypts `plaintext` (no expiry).
    pub fn encrypt(&self, plaintext: &[u8]) -> String {
        self.seal(plaintext, None, "")
    }

    /// Encrypts `plaintext`; the token expires after `ttl`.
    pub fn encrypt_with_ttl(&self, plaintext: &[u8], ttl: Duration) -> String {
        let exp = now_unix().saturating_add(ttl.as_secs().max(1));
        self.seal(plaintext, Some(exp), "")
    }

    /// Encrypts a string (no expiry).
    pub fn encrypt_str(&self, plaintext: &str) -> String {
        self.encrypt(plaintext.as_bytes())
    }

    /// Decrypts a token made by [`encrypt`](Self::encrypt) or
    /// [`encrypt_with_ttl`](Self::encrypt_with_ttl).
    pub fn decrypt(&self, token: &str) -> Result<Vec<u8>, DecryptError> {
        self.open(token, "", now_unix())
    }

    /// Decrypts a token holding UTF-8 text.
    pub fn decrypt_str(&self, token: &str) -> Result<String, DecryptError> {
        String::from_utf8(self.decrypt(token)?).map_err(|_| DecryptError::Malformed)
    }

    /// Encrypts `plaintext` for one context (a database column, a user id …):
    /// it only decrypts with [`decrypt_in`](Self::decrypt_in) and the same
    /// context.
    pub fn encrypt_in(&self, context: &str, plaintext: &[u8], ttl: Option<Duration>) -> String {
        let exp = ttl.map(|t| now_unix().saturating_add(t.as_secs().max(1)));
        self.seal(plaintext, exp, &format!("ctx:{context}"))
    }

    /// Decrypts a token made by [`encrypt_in`](Self::encrypt_in).
    pub fn decrypt_in(&self, context: &str, token: &str) -> Result<Vec<u8>, DecryptError> {
        self.open(token, &format!("ctx:{context}"), now_unix())
    }

    /// The value of an encrypted cookie named `name`, bound to that name (a
    /// value moved to another cookie does not decrypt). The result is
    /// base64url, safe in a `Set-Cookie` header without quoting.
    pub fn encrypt_cookie(&self, name: &str, value: &str, ttl: Option<Duration>) -> String {
        let exp = ttl.map(|t| now_unix().saturating_add(t.as_secs().max(1)));
        self.seal(value.as_bytes(), exp, &format!("cookie:{name}"))
    }

    /// Decrypts the value of the cookie `name`.
    pub fn decrypt_cookie(&self, name: &str, value: &str) -> Result<String, DecryptError> {
        let bytes = self.open(value, &format!("cookie:{name}"), now_unix())?;
        String::from_utf8(bytes).map_err(|_| DecryptError::Malformed)
    }

    /// Reads and decrypts the cookie `name` from the `Cookie` headers of a
    /// request. Cookies that do not decrypt (forged, expired, another key)
    /// are ignored.
    pub fn read_cookie(&self, headers: &HeaderMap, name: &str) -> Option<String> {
        headers
            .get_all(COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(cookie_pairs)
            .filter(|(n, _)| *n == name)
            .find_map(|(_, v)| self.decrypt_cookie(name, v).ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: [u8; 32] = [1u8; 32];
    const K2: [u8; 32] = [2u8; 32];

    #[test]
    fn roundtrip_and_randomised() {
        let c = Encrypter::new(&K1);
        let a = c.encrypt(b"hello");
        let b = c.encrypt(b"hello");
        assert_ne!(a, b, "a fresh nonce for every message");
        assert_eq!(c.decrypt(&a).unwrap(), b"hello");
        assert_eq!(c.decrypt(&c.encrypt(b"")).unwrap(), b"");
        assert!(!a.contains("hello"));
    }

    #[test]
    fn every_bit_flip_is_detected() {
        let c = Encrypter::new(&K1);
        let token = c.encrypt(b"amount=100");
        let raw = b64url_decode(&token).unwrap();
        for i in 0..raw.len() {
            let mut bad = raw.clone();
            bad[i] ^= 0x01;
            let err = c.decrypt(&b64url(&bad)).unwrap_err();
            assert!(matches!(
                err,
                DecryptError::Invalid | DecryptError::Malformed
            ));
        }
        // Truncation and extension.
        assert!(c.decrypt(&b64url(&raw[..raw.len() - 1])).is_err());
        let mut longer = raw.clone();
        longer.push(0);
        assert!(c.decrypt(&b64url(&longer)).is_err());
    }

    #[test]
    fn malformed_inputs() {
        let c = Encrypter::new(&K1);
        for bad in ["", "!!!", "AAAA", &"A".repeat(MAX_TOKEN + 1)] {
            assert_eq!(c.decrypt(bad), Err(DecryptError::Malformed), "{bad:.10}");
        }
        // Unknown version.
        let mut raw = b64url_decode(&c.encrypt(b"x")).unwrap();
        raw[0] = 2;
        assert_eq!(c.decrypt(&b64url(&raw)), Err(DecryptError::Malformed));
    }

    #[test]
    fn wrong_key_purpose_or_context() {
        let token = Encrypter::new(&K1).encrypt(b"secret");
        assert_eq!(
            Encrypter::new(&K2).decrypt(&token),
            Err(DecryptError::Invalid)
        );
        assert_eq!(
            Encrypter::new(&K1).purpose("other").decrypt(&token),
            Err(DecryptError::Invalid)
        );
        let c = Encrypter::new(&K1);
        let t = c.encrypt_in("user:1", b"iban", None);
        assert_eq!(c.decrypt_in("user:1", &t).unwrap(), b"iban");
        assert_eq!(c.decrypt_in("user:2", &t), Err(DecryptError::Invalid));
        assert_eq!(c.decrypt(&t), Err(DecryptError::Invalid));
    }

    #[test]
    fn key_rotation() {
        let old = Encrypter::new(&K1);
        let token = old.encrypt(b"legacy");
        let rotated = Encrypter::new(&K2).fallback_key(&K1);
        assert_eq!(rotated.decrypt(&token).unwrap(), b"legacy");
        let fresh = rotated.encrypt(b"new");
        assert_eq!(Encrypter::new(&K2).decrypt(&fresh).unwrap(), b"new");
        assert_eq!(old.decrypt(&fresh), Err(DecryptError::Invalid));
        assert_ne!(old.key_id(), rotated.key_id());
    }

    #[test]
    fn expiry() {
        let c = Encrypter::new(&K1);
        let t = c.seal(b"x", Some(100), "");
        assert_eq!(c.open(&t, "", 100).unwrap(), b"x");
        assert_eq!(c.open(&t, "", 101), Err(DecryptError::Expired));
        let t = c.encrypt_with_ttl(b"y", Duration::from_secs(60));
        assert_eq!(c.decrypt(&t).unwrap(), b"y");
    }

    #[test]
    fn cookies_are_bound_to_their_name() {
        let c = Encrypter::new(&K1);
        let v = c.encrypt_cookie("role", "user", None);
        assert!(
            v.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
        assert_eq!(c.decrypt_cookie("role", &v).unwrap(), "user");
        assert_eq!(c.decrypt_cookie("admin", &v), Err(DecryptError::Invalid));
        let mut h = HeaderMap::new();
        h.append(
            COOKIE,
            format!("a=1; role=forged; role={v}").parse().unwrap(),
        );
        assert_eq!(c.read_cookie(&h, "role").as_deref(), Some("user"));
        assert_eq!(c.read_cookie(&h, "a"), None);
    }

    #[test]
    fn keys() {
        assert_eq!(Encrypter::try_new(&[1u8; 31]).unwrap_err(), InvalidKey);
        assert!(Encrypter::try_new(&[0u8; 32]).is_err());
        let k = Encrypter::generate_key();
        let a = Encrypter::from_base64(&k).unwrap();
        let b = Encrypter::from_base64(&format!("base64:{k}")).unwrap();
        assert_eq!(b.decrypt(&a.encrypt(b"z")).unwrap(), b"z");
        assert!(Encrypter::from_base64("nope").is_err());
        assert!(format!("{a:?}").contains("keys: 1"));
    }
}
