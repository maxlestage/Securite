//! Signed tokens and signed URLs (HMAC-SHA256), like Laravel's
//! `URL::temporarySignedRoute` and Django's `signing` module.
//!
//! A [`Signer`] turns a value into a tamper-proof token, optionally with an
//! expiry, and checks it back. Use it for password-reset and e-mail
//! verification links, unsubscribe links, invitation codes, download links,
//! or any value you hand to a client and must get back unchanged.
//!
//! * **Purposes** separate the uses of one secret: a token signed for
//!   `"password-reset"` is rejected where `"email-verification"` is expected.
//! * **Key rotation**: sign with the new secret and keep accepting the old one
//!   with [`Signer::fallback_key`].
//! * **Constant time**: signatures are compared with `subtle`.
//! * Tokens are **signed, not encrypted**: the payload is readable by the
//!   client (base64url). Never put secrets in it.
//!
//! ```
//! use std::time::Duration;
//! use securite::signing::{Signer, TokenError};
//!
//! let signer = Signer::new(b"a secret of at least thirty-two bytes!!").purpose("password-reset");
//! let token = signer.sign_with_ttl("user:42", Duration::from_secs(3600));
//! assert_eq!(signer.unsign(&token).unwrap(), "user:42");
//!
//! let other = Signer::new(b"a secret of at least thirty-two bytes!!").purpose("unsubscribe");
//! assert_eq!(other.unsign(&token), Err(TokenError::Invalid));
//! ```
//!
//! Signed URLs are verified before your handler by the [`SignedUrls`] guard:
//!
//! ```
//! use std::time::Duration;
//! use securite::prelude::*;
//! use securite::signing::{SignedUrls, Signer};
//!
//! let signer = Signer::new(b"a secret of at least thirty-two bytes!!");
//! let link = signer.sign_url("/downloads/report.pdf?user=42", Some(Duration::from_secs(900)));
//! assert!(link.starts_with("/downloads/report.pdf?user=42&expires="));
//! assert!(signer.verify_url(&link).is_ok());
//!
//! let shield = Shield::builder()
//!     .guard(SignedUrls::new(signer).protect(["/downloads"]))
//!     .build();
//! ```

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use http::{StatusCode, request};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::guard::impl_layer;
use crate::util::{any_path_matches, b64url, b64url_decode, normalize_prefix};
use crate::{Context, Guard, Mode, Rejection, priority};

/// Minimum secret length, in bytes.
pub const MIN_SECRET_BYTES: usize = 32;

/// Longest token or URL that is even looked at (bigger inputs are invalid).
const MAX_INPUT: usize = 16 * 1024;

/// Why a token or a signed URL was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenError {
    /// Not a token (wrong shape, bad encoding, no signature in the URL …).
    Malformed,
    /// The signature does not match: tampered, another purpose, unknown key.
    Invalid,
    /// The signature is valid but the expiry has passed.
    Expired,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TokenError::Malformed => "malformed token",
            TokenError::Invalid => "invalid signature",
            TokenError::Expired => "expired token",
        })
    }
}

impl std::error::Error for TokenError {}

/// Signs and verifies tokens and URLs. Cheap to clone. See the
/// [module docs](self).
#[derive(Clone)]
pub struct Signer {
    /// The first key signs; every key verifies.
    keys: Vec<Arc<[u8]>>,
    purpose: String,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
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

impl Signer {
    /// A signer with `secret` (at least [`MIN_SECRET_BYTES`] bytes, e.g.
    /// `openssl rand -base64 48`) and the default purpose.
    ///
    /// # Panics
    ///
    /// If the secret is shorter than 32 bytes.
    pub fn new(secret: impl AsRef<[u8]>) -> Self {
        Self {
            keys: vec![check_secret(secret.as_ref())],
            purpose: String::from("default"),
        }
    }

    /// Binds every token to a purpose (`"password-reset"`, `"invite"` …):
    /// tokens signed for one purpose are invalid for every other one.
    pub fn purpose(mut self, purpose: impl Into<String>) -> Self {
        self.purpose = purpose.into();
        self
    }

    /// Also accepts tokens signed with `old_secret` (key rotation). New
    /// tokens are always signed with the key given to [`new`](Self::new).
    ///
    /// # Panics
    ///
    /// If the secret is shorter than 32 bytes.
    pub fn fallback_key(mut self, old_secret: impl AsRef<[u8]>) -> Self {
        self.keys.push(check_secret(old_secret.as_ref()));
        self
    }

    fn mac(&self, key: &[u8], domain: &[u8], message: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("any key length");
        mac.update(domain);
        mac.update(&(self.purpose.len() as u64).to_be_bytes());
        mac.update(self.purpose.as_bytes());
        mac.update(message);
        mac.finalize().into_bytes().into()
    }

    /// Constant-time check against every key (no early exit on a match).
    fn matches(&self, domain: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let mut ok = subtle::Choice::from(0);
        for key in &self.keys {
            ok |= self.mac(key, domain, message).as_slice().ct_eq(signature);
        }
        ok.into()
    }

    /// Signs `value` with no expiry.
    pub fn sign(&self, value: &str) -> String {
        self.sign_bytes_at(value.as_bytes(), None)
    }

    /// Signs `value`; the token expires after `ttl`.
    pub fn sign_with_ttl(&self, value: &str, ttl: Duration) -> String {
        self.sign_bytes_at(
            value.as_bytes(),
            Some(now_unix().saturating_add(ttl.as_secs())),
        )
    }

    /// Signs raw bytes, with an optional time to live.
    pub fn sign_bytes(&self, value: &[u8], ttl: Option<Duration>) -> String {
        self.sign_bytes_at(value, ttl.map(|t| now_unix().saturating_add(t.as_secs())))
    }

    fn sign_bytes_at(&self, value: &[u8], expires: Option<u64>) -> String {
        let mut body = b64url(value);
        body.push('.');
        if let Some(exp) = expires {
            body.push_str(&exp.to_string());
        }
        let sig = self.mac(&self.keys[0], b"securite.token.v1\0", body.as_bytes());
        body.push('.');
        body.push_str(&b64url(&sig));
        body
    }

    /// Verifies `token` and returns the signed value.
    pub fn unsign(&self, token: &str) -> Result<String, TokenError> {
        let bytes = self.unsign_bytes(token)?;
        String::from_utf8(bytes).map_err(|_| TokenError::Malformed)
    }

    /// Verifies `token` and returns the signed bytes.
    pub fn unsign_bytes(&self, token: &str) -> Result<Vec<u8>, TokenError> {
        self.unsign_bytes_at(token, now_unix())
    }

    fn unsign_bytes_at(&self, token: &str, now: u64) -> Result<Vec<u8>, TokenError> {
        if token.len() > MAX_INPUT {
            return Err(TokenError::Malformed);
        }
        let (body, sig) = token.rsplit_once('.').ok_or(TokenError::Malformed)?;
        let (payload, exp) = body.split_once('.').ok_or(TokenError::Malformed)?;
        let sig = b64url_decode(sig).ok_or(TokenError::Malformed)?;
        if sig.len() != 32 {
            return Err(TokenError::Malformed);
        }
        if !self.matches(b"securite.token.v1\0", body.as_bytes(), &sig) {
            return Err(TokenError::Invalid);
        }
        if !exp.is_empty() {
            let exp: u64 = exp.parse().map_err(|_| TokenError::Malformed)?;
            if now > exp {
                return Err(TokenError::Expired);
            }
        }
        b64url_decode(payload).ok_or(TokenError::Malformed)
    }

    /// Signs a relative URL (`/path?query`, already percent-encoded) by
    /// appending `expires=<unix time>` (with a `ttl`) and
    /// `signature=<base64url>`. A `#fragment` is kept at the end and not
    /// signed (browsers never send it).
    ///
    /// # Panics
    ///
    /// If `url` does not start with `/` (or starts with `//`), or already has
    /// a `signature` or `expires` parameter.
    pub fn sign_url(&self, url: &str, ttl: Option<Duration>) -> String {
        self.sign_url_at(url, ttl.map(|t| now_unix().saturating_add(t.as_secs())))
    }

    fn sign_url_at(&self, url: &str, expires: Option<u64>) -> String {
        assert!(
            url.starts_with('/') && !url.starts_with("//"),
            "sign_url takes a relative URL starting with a single `/`"
        );
        let (url, fragment) = match url.split_once('#') {
            Some((u, f)) => (u, Some(f)),
            None => (url, None),
        };
        assert!(
            !query_params(url).any(|(k, _)| k == "signature" || k == "expires"),
            "the URL already has a `signature` or `expires` parameter"
        );
        let url = url.trim_end_matches(['?', '&']);
        let mut out = String::with_capacity(url.len() + 80);
        out.push_str(url);
        let mut sep = if url.contains('?') { '&' } else { '?' };
        if let Some(exp) = expires {
            out.push(sep);
            out.push_str("expires=");
            out.push_str(&exp.to_string());
            sep = '&';
        }
        let sig = self.mac(&self.keys[0], b"securite.url.v1\0", out.as_bytes());
        out.push(sep);
        out.push_str("signature=");
        out.push_str(&b64url(&sig));
        if let Some(f) = fragment {
            out.push('#');
            out.push_str(f);
        }
        out
    }

    /// Verifies a relative URL produced by [`sign_url`](Self::sign_url), as
    /// received (path and query). The `signature` parameter must be the last
    /// one: anything appended after it invalidates the URL.
    pub fn verify_url(&self, path_and_query: &str) -> Result<(), TokenError> {
        self.verify_url_at(path_and_query, now_unix())
    }

    fn verify_url_at(&self, url: &str, now: u64) -> Result<(), TokenError> {
        if url.len() > MAX_INPUT {
            return Err(TokenError::Malformed);
        }
        let url = url.split_once('#').map_or(url, |(u, _)| u);
        let idx = url.rfind("signature=").ok_or(TokenError::Malformed)?;
        let sep = idx.checked_sub(1).ok_or(TokenError::Malformed)?;
        if !matches!(url.as_bytes()[sep], b'?' | b'&') {
            return Err(TokenError::Malformed);
        }
        let encoded = &url[idx + "signature=".len()..];
        if encoded.contains('&') {
            return Err(TokenError::Malformed);
        }
        let sig = b64url_decode(encoded).ok_or(TokenError::Malformed)?;
        if sig.len() != 32 {
            return Err(TokenError::Malformed);
        }
        let signed = &url[..sep];
        if !self.matches(b"securite.url.v1\0", signed.as_bytes(), &sig) {
            return Err(TokenError::Invalid);
        }
        let mut expires = query_params(signed).filter(|(k, _)| *k == "expires");
        if let Some((_, exp)) = expires.next() {
            if expires.next().is_some() {
                return Err(TokenError::Malformed);
            }
            let exp: u64 = exp.parse().map_err(|_| TokenError::Malformed)?;
            if now > exp {
                return Err(TokenError::Expired);
            }
        }
        Ok(())
    }
}

/// E-mail verification links, like Laravel's `MustVerifyEmail`.
impl Signer {
    /// A signed link `base/<user_id>/<email hash>?expires=…&signature=…` to
    /// send to `email`. The link proves that its owner reads that mailbox:
    /// it only verifies for the same user **and** the same address (a link
    /// sent before an e-mail change no longer works), and expires after
    /// `ttl`. Use a [`purpose`](Self::purpose) such as `"verify-email"`.
    ///
    /// ```
    /// use std::time::Duration;
    /// use securite::signing::{Signer, TokenError};
    ///
    /// let signer = Signer::new(b"a secret of at least thirty-two bytes!!").purpose("verify-email");
    /// let link = signer.email_verification_url("/email/verify", "42", "Ada@Example.com", Duration::from_secs(3600));
    ///
    /// // In the handler of `/email/verify/...`, with the current address of user 42:
    /// assert_eq!(signer.verify_email_url(&link, "ada@example.com").unwrap(), "42");
    /// assert_eq!(signer.verify_email_url(&link, "mallory@example.com"), Err(TokenError::Invalid));
    /// ```
    ///
    /// # Panics
    ///
    /// If `base` is not a relative path, or `user_id` is empty or contains
    /// other characters than ASCII letters, digits, `-` and `_`.
    pub fn email_verification_url(
        &self,
        base: &str,
        user_id: &str,
        email: &str,
        ttl: Duration,
    ) -> String {
        assert!(
            !user_id.is_empty()
                && user_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "user ids in verification links are limited to [A-Za-z0-9_-]"
        );
        let base = base.trim_end_matches('/');
        let url = format!("{base}/{user_id}/{}", email_hash(email));
        self.sign_url(&url, Some(ttl))
    }

    /// Checks a link made by
    /// [`email_verification_url`](Self::email_verification_url) against the
    /// user's *current* e-mail address, and returns the user id.
    pub fn verify_email_url(&self, url: &str, current_email: &str) -> Result<String, TokenError> {
        self.verify_url(url)?;
        let path = url.split(['?', '#']).next().unwrap_or("");
        let mut segments = path.rsplit('/');
        let hash = segments.next().ok_or(TokenError::Malformed)?;
        let id = segments.next().ok_or(TokenError::Malformed)?;
        if id.is_empty() {
            return Err(TokenError::Malformed);
        }
        let ok: bool = email_hash(current_email)
            .as_bytes()
            .ct_eq(hash.as_bytes())
            .into();
        if !ok {
            return Err(TokenError::Invalid);
        }
        Ok(id.to_owned())
    }

    /// Signs a cookie value for the cookie `name` (readable by the client,
    /// but tamper-proof, and bound to that cookie name). Encrypt instead
    /// with [`Encrypter`](crate::crypt::Encrypter) when the client must not
    /// read it.
    pub fn sign_cookie(&self, name: &str, value: &str) -> String {
        self.cookie_signer(name).sign(value)
    }

    /// Verifies a value made by [`sign_cookie`](Self::sign_cookie) for the
    /// same cookie name.
    pub fn unsign_cookie(&self, name: &str, value: &str) -> Result<String, TokenError> {
        self.cookie_signer(name).unsign(value)
    }

    fn cookie_signer(&self, name: &str) -> Signer {
        let mut s = self.clone();
        s.purpose = format!("{}\0cookie:{name}", self.purpose);
        s
    }
}

/// base64url SHA-256 of the trimmed, lowercased address.
fn email_hash(email: &str) -> String {
    use sha2::Digest as _;
    b64url(&Sha256::digest(email.trim().to_lowercase().as_bytes()))
}

fn check_secret(secret: &[u8]) -> Arc<[u8]> {
    assert!(
        secret.len() >= MIN_SECRET_BYTES,
        "the signing secret must be at least {MIN_SECRET_BYTES} bytes"
    );
    Arc::from(secret)
}

fn query_params(url: &str) -> impl Iterator<Item = (&str, &str)> {
    url.split_once('?')
        .map_or("", |(_, q)| q)
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| p.split_once('=').unwrap_or((p, "")))
}

/// Guard that only lets requests through when their URL was signed with
/// [`Signer::sign_url`] and has not expired. Laravel's `signed` middleware.
///
/// Requests on the protected prefixes without a valid signature get
/// `403 Forbidden` (code `invalid_signature` or `expired_signature`).
///
/// ```
/// use securite::prelude::*;
/// use securite::signing::{SignedUrls, Signer};
///
/// let signer = Signer::new(std::env::var("LINK_SECRET").unwrap_or_else(|_| "x".repeat(32)));
/// let guard = SignedUrls::new(signer).protect(["/unsubscribe", "/invitations/accept"]);
/// ```
#[derive(Clone, Debug)]
pub struct SignedUrls {
    signer: Signer,
    prefixes: Vec<String>,
    mode: Mode,
}

impl SignedUrls {
    /// Every path requires a signature until [`protect`](Self::protect) narrows it.
    pub fn new(signer: Signer) -> Self {
        Self {
            signer,
            prefixes: Vec::new(),
            mode: Mode::Enforce,
        }
    }

    /// Only these path prefixes require a signed URL (segment boundaries:
    /// `/files` covers `/files/a`, not `/filesystem`).
    pub fn protect<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.prefixes
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Reports invalid signatures without blocking.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }
}

impl Guard for SignedUrls {
    fn name(&self) -> &'static str {
        "signed_url"
    }

    fn priority(&self) -> u16 {
        priority::SIGNED_URL
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let path = req.uri.path();
        if !self.prefixes.is_empty() && !any_path_matches(path, &self.prefixes) {
            return Ok(());
        }
        let target = req.uri.path_and_query().map_or(path, |pq| pq.as_str());
        match self.signer.verify_url(target) {
            Ok(()) => Ok(()),
            Err(TokenError::Expired) => Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "expired_signature",
                "This link has expired.",
            )),
            Err(e) => Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "invalid_signature",
                "Invalid signature.",
            )
            .with_details(e.to_string())),
        }
    }
}

impl_layer!(SignedUrls);

#[cfg(test)]
mod email_tests {
    use super::*;

    fn signer() -> Signer {
        Signer::new([5u8; 32]).purpose("verify-email")
    }

    #[test]
    fn verification_links() {
        let s = signer();
        let link = s.email_verification_url("/verify/", "u_1", "A@b.io", Duration::from_secs(60));
        assert!(link.starts_with("/verify/u_1/"));
        assert_eq!(s.verify_email_url(&link, " a@B.io ").unwrap(), "u_1");
        // Address changed since the link was sent.
        assert_eq!(
            s.verify_email_url(&link, "c@b.io"),
            Err(TokenError::Invalid)
        );
        // Another user id swapped in the path.
        let swapped = link.replacen("/u_1/", "/u_2/", 1);
        assert_eq!(
            s.verify_email_url(&swapped, "a@b.io"),
            Err(TokenError::Invalid)
        );
        // Another purpose (e.g. a password reset link) is refused.
        let other = Signer::new([5u8; 32]).purpose("password-reset");
        assert_eq!(
            other.verify_email_url(&link, "a@b.io"),
            Err(TokenError::Invalid)
        );
        // Expired.
        let old = s.sign_url_at(&format!("/verify/u_1/{}", email_hash("a@b.io")), Some(1));
        assert_eq!(s.verify_email_url(&old, "a@b.io"), Err(TokenError::Expired));
    }

    #[test]
    #[should_panic(expected = "limited to")]
    fn ids_cannot_inject_paths() {
        let _ =
            signer().email_verification_url("/v", "1/../admin", "a@b.io", Duration::from_secs(1));
    }

    #[test]
    fn signed_cookies() {
        let s = Signer::new([6u8; 32]);
        let v = s.sign_cookie("cart", "42");
        assert_eq!(s.unsign_cookie("cart", &v).unwrap(), "42");
        assert_eq!(s.unsign_cookie("role", &v), Err(TokenError::Invalid));
        assert_eq!(s.unsign(&v), Err(TokenError::Invalid));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
    const OLD: &[u8] = b"fedcba9876543210fedcba9876543210";

    fn signer() -> Signer {
        Signer::new(KEY)
    }

    #[test]
    fn token_round_trip() {
        let s = signer();
        let t = s.sign("hello world");
        assert_eq!(s.unsign(&t).unwrap(), "hello world");
        assert_eq!(
            s.unsign_bytes(&s.sign_bytes(&[0, 1, 255], None)).unwrap(),
            [0, 1, 255]
        );
        assert_eq!(s.unsign(&s.sign("")).unwrap(), "");
    }

    #[test]
    fn tampering_is_detected() {
        let s = signer();
        let t = s.sign("user:42");
        let forged = t.replacen(&b64url(b"user:42"), &b64url(b"user:1"), 1);
        assert_eq!(s.unsign(&forged), Err(TokenError::Invalid));
        // Adding an expiry or removing one breaks the signature too.
        let (body, sig) = t.rsplit_once('.').unwrap();
        assert_eq!(
            s.unsign(&format!("{body}9999999999.{sig}")),
            Err(TokenError::Invalid)
        );
        for bad in [
            "",
            ".",
            "..",
            "a.b",
            "a..",
            "a..!!!",
            &format!("{body}.AAAA"),
        ] {
            assert_eq!(s.unsign(bad), Err(TokenError::Malformed), "{bad}");
        }
        assert_eq!(
            s.unsign(&"a".repeat(MAX_INPUT + 1)),
            Err(TokenError::Malformed)
        );
    }

    #[test]
    fn expiry() {
        let s = signer();
        let t = s.sign_bytes_at(b"x", Some(1_000));
        assert!(s.unsign_bytes_at(&t, 1_000).is_ok());
        assert_eq!(s.unsign_bytes_at(&t, 1_001), Err(TokenError::Expired));
        let live = s.sign_with_ttl("x", Duration::from_secs(60));
        assert_eq!(s.unsign(&live).unwrap(), "x");
    }

    #[test]
    fn purposes_and_keys_are_isolated() {
        let reset = signer().purpose("password-reset");
        let t = reset.sign("42");
        assert_eq!(signer().unsign(&t), Err(TokenError::Invalid));
        assert_eq!(
            signer().purpose("invite").unsign(&t),
            Err(TokenError::Invalid)
        );
        assert_eq!(
            Signer::new(OLD).purpose("password-reset").unsign(&t),
            Err(TokenError::Invalid)
        );
        // Purpose length is part of the MAC: no ambiguity between purpose and payload.
        assert_eq!(
            signer().purpose("password-rese").unsign(&t),
            Err(TokenError::Invalid)
        );
    }

    #[test]
    fn key_rotation() {
        let old = Signer::new(OLD);
        let rotated = Signer::new(KEY).fallback_key(OLD);
        let t = old.sign("v");
        assert_eq!(rotated.unsign(&t).unwrap(), "v");
        let fresh = rotated.sign("v");
        assert_eq!(
            signer().unsign(&fresh).unwrap(),
            "v",
            "signed with the new key"
        );
        assert_eq!(old.unsign(&fresh), Err(TokenError::Invalid));
    }

    #[test]
    #[should_panic(expected = "at least 32 bytes")]
    fn short_secret_panics() {
        let _ = Signer::new("short");
    }

    #[test]
    fn url_round_trip() {
        let s = signer();
        let u = s.sign_url("/unsubscribe?user=42", None);
        assert!(u.starts_with("/unsubscribe?user=42&signature="), "{u}");
        assert!(s.verify_url(&u).is_ok());
        let u = s.sign_url("/a", None);
        assert!(u.starts_with("/a?signature="));
        assert!(s.verify_url(&u).is_ok());
        let u = s.sign_url("/a?", None);
        assert!(u.starts_with("/a?signature="), "{u}");
        let u = s.sign_url("/a?x=1#top", Some(Duration::from_secs(60)));
        assert!(u.ends_with("#top"));
        assert!(s.verify_url(&u).is_ok());
    }

    #[test]
    fn url_tampering_is_detected() {
        let s = signer();
        let u = s.sign_url_at("/files/report.pdf?user=42", Some(2_000));
        assert!(s.verify_url_at(&u, 2_000).is_ok());
        assert_eq!(s.verify_url_at(&u, 2_001), Err(TokenError::Expired));
        let attacks = [
            u.replace("user=42", "user=43"),
            u.replace("/files/report.pdf", "/files/secret.pdf"),
            u.replace("expires=2000", "expires=9999999999"),
            u.replace("&expires=2000", ""),
        ];
        for a in &attacks {
            assert_eq!(s.verify_url_at(a, 0), Err(TokenError::Invalid), "{a}");
        }
        // Parameters appended after the signature are refused.
        assert_eq!(
            s.verify_url_at(&format!("{u}&admin=1"), 0),
            Err(TokenError::Malformed)
        );
        // Another signer, purpose or a token signature reused as a URL one.
        assert_eq!(
            signer().purpose("x").verify_url_at(&u, 0),
            Err(TokenError::Invalid)
        );
        let tok = s.sign("/files/report.pdf?user=42");
        let sig = tok.rsplit_once('.').unwrap().1;
        assert_eq!(
            s.verify_url_at(&format!("/files/report.pdf?user=42&signature={sig}"), 0),
            Err(TokenError::Invalid)
        );
        for bad in [
            "/x",
            "/x?a=1",
            "/x?signature=",
            "/x?mysignature=AAAA",
            "signature=x",
        ] {
            assert_eq!(s.verify_url_at(bad, 0), Err(TokenError::Malformed), "{bad}");
        }
    }

    #[test]
    fn duplicated_expires_is_refused() {
        let s = signer();
        // Even a correctly signed URL with two expiries is ambiguous.
        let mut out = String::from("/x?expires=1&expires=99999999999");
        let sig = s.mac(KEY, b"securite.url.v1\0", out.as_bytes());
        out.push_str("&signature=");
        out.push_str(&b64url(&sig));
        assert_eq!(s.verify_url_at(&out, 5), Err(TokenError::Malformed));
    }

    #[test]
    #[should_panic(expected = "already has")]
    fn sign_url_refuses_reserved_params() {
        let _ = signer().sign_url("/x?signature=1", None);
    }

    #[test]
    #[should_panic(expected = "relative URL")]
    fn sign_url_refuses_protocol_relative() {
        let _ = signer().sign_url("//evil.example/x", None);
    }

    fn run(guard: &SignedUrls, uri: &str) -> Result<(), Rejection> {
        let mut parts = Request::get(uri).body(()).unwrap().into_parts().0;
        let mut ctx = Context::new(parts.method.clone(), parts.uri.clone(), None);
        guard.on_request(&mut parts, &mut ctx)
    }

    #[test]
    fn guard_checks_only_protected_paths() {
        let s = signer();
        let g = SignedUrls::new(s.clone()).protect(["/downloads"]);
        assert!(run(&g, "/public").is_ok());
        assert!(run(&g, "/downloadsx").is_ok());
        let link = s.sign_url("/downloads/a.zip?u=1", Some(Duration::from_secs(60)));
        assert!(run(&g, &link).is_ok());
        let err = run(&g, "/downloads/a.zip?u=1").unwrap_err();
        assert_eq!(
            (err.status(), err.code()),
            (StatusCode::FORBIDDEN, "invalid_signature")
        );
        let expired = s.sign_url_at("/downloads/a.zip", Some(1));
        let err = run(&g, &expired).unwrap_err();
        assert_eq!(err.code(), "expired_signature");
        let forged = link.replace("u=1", "u=2");
        assert_eq!(run(&g, &forged).unwrap_err().code(), "invalid_signature");
        assert_eq!(g.name(), "signed_url");
        assert_eq!(SignedUrls::new(s).monitor().mode(), Mode::Monitor);
    }
}
