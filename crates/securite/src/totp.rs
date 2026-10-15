//! Time-based one-time passwords (TOTP, RFC 6238) for two-factor
//! authentication, compatible with Google Authenticator, Authy, 1Password,
//! Bitwarden, FreeOTP and every other authenticator app.
//!
//! ```
//! use securite::totp::Totp;
//!
//! // Enrolment: generate a secret, store it (encrypted) with the user and
//! // show the provisioning URI as a QR code.
//! let totp = Totp::generate();
//! let uri = totp.provisioning_uri("Example Inc", "alice@example.com");
//! assert!(uri.starts_with("otpauth://totp/Example%20Inc:alice%40example.com?secret="));
//!
//! // Login: check the 6-digit code typed by the user, refusing replays.
//! let code = totp.current_code();
//! let last_used_step = None; // read from the user record
//! let step = totp.verify_once(&code, last_used_step).expect("valid code");
//! // ... store `step` as the new `last_used_step` ...
//! assert_eq!(totp.verify_once(&code, Some(step)), None, "a code works only once");
//! ```
//!
//! Codes are compared in constant time, all the accepted time steps are
//! checked without early exit, and secrets never appear in `Debug` output.
//! Rate-limit the verification endpoint ([`LoginThrottle`](crate::throttle::LoginThrottle)):
//! a 6-digit code only has a million values.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use subtle::ConstantTimeEq;

use crate::util::secure_random;

/// Minimum secret length (RFC 4226 requires 128 bits, recommends 160).
pub const MIN_SECRET_BYTES: usize = 16;

/// The HMAC function of a [`Totp`]. Authenticator apps universally support
/// [`Sha1`](TotpAlgorithm::Sha1); the others are for apps known to support them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    /// HMAC-SHA1 (default; HMAC-SHA1 remains secure, SHA-1 collisions do not apply).
    #[default]
    Sha1,
    /// HMAC-SHA256.
    Sha256,
    /// HMAC-SHA512.
    Sha512,
}

impl TotpAlgorithm {
    fn name(self) -> &'static str {
        match self {
            TotpAlgorithm::Sha1 => "SHA1",
            TotpAlgorithm::Sha256 => "SHA256",
            TotpAlgorithm::Sha512 => "SHA512",
        }
    }
}

/// Why a TOTP secret could not be loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpError {
    /// Not valid base32.
    InvalidBase32,
    /// Shorter than [`MIN_SECRET_BYTES`].
    SecretTooShort,
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TotpError::InvalidBase32 => "invalid base32 secret",
            TotpError::SecretTooShort => "TOTP secret shorter than 128 bits",
        })
    }
}

impl std::error::Error for TotpError {}

/// A TOTP generator and verifier. See the [module docs](self).
///
/// Defaults: SHA-1, 6 digits, 30-second period, one step of clock skew
/// accepted on each side (codes are valid for about 90 seconds).
#[derive(Clone)]
pub struct Totp {
    secret: Vec<u8>,
    algorithm: TotpAlgorithm,
    digits: u32,
    period: u64,
    skew: u64,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Totp")
            .field("secret", &"<redacted>")
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("skew", &self.skew)
            .finish()
    }
}

impl Drop for Totp {
    fn drop(&mut self) {
        // Best effort: do not leave the shared secret lying in freed memory.
        for b in self.secret.iter_mut() {
            *b = 0;
        }
        std::hint::black_box(&self.secret);
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Totp {
    /// A TOTP with a raw secret.
    ///
    /// # Panics
    ///
    /// If the secret is shorter than [`MIN_SECRET_BYTES`].
    pub fn new(secret: impl Into<Vec<u8>>) -> Self {
        let secret = secret.into();
        assert!(
            secret.len() >= MIN_SECRET_BYTES,
            "TOTP secrets must be at least 128 bits"
        );
        Self {
            secret,
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            skew: 1,
        }
    }

    /// A TOTP with a fresh 160-bit random secret.
    pub fn generate() -> Self {
        let mut secret = vec![0u8; 20];
        secure_random(&mut secret);
        Self::new(secret)
    }

    /// Loads a base32 secret (as stored, or as shown to users). Case, spaces,
    /// dashes and `=` padding are ignored.
    pub fn from_base32(secret: &str) -> Result<Self, TotpError> {
        let bytes = base32_decode(secret).ok_or(TotpError::InvalidBase32)?;
        if bytes.len() < MIN_SECRET_BYTES {
            return Err(TotpError::SecretTooShort);
        }
        Ok(Self::new(bytes))
    }

    /// The secret in base32 (no padding): store it encrypted, or let users
    /// type it when they cannot scan the QR code.
    pub fn secret_base32(&self) -> String {
        base32_encode(&self.secret)
    }

    /// The HMAC function (default SHA-1).
    pub fn algorithm(mut self, algorithm: TotpAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Number of digits, 6 (default) to 8.
    ///
    /// # Panics
    ///
    /// Outside `6..=8`.
    pub fn digits(mut self, digits: u32) -> Self {
        assert!((6..=8).contains(&digits), "TOTP codes have 6 to 8 digits");
        self.digits = digits;
        self
    }

    /// Length of a time step (default 30 seconds, at least one second).
    pub fn period(mut self, period: Duration) -> Self {
        self.period = period.as_secs().max(1);
        self
    }

    /// Steps of clock drift accepted before and after the current one
    /// (default 1, at most 10).
    pub fn skew(mut self, steps: u64) -> Self {
        self.skew = steps.min(10);
        self
    }

    /// The time step that contains `unix_secs`.
    pub fn step_at(&self, unix_secs: u64) -> u64 {
        unix_secs / self.period
    }

    fn code_for_step(&self, step: u64) -> u32 {
        let msg = step.to_be_bytes();
        let digest: Vec<u8> = match self.algorithm {
            TotpAlgorithm::Sha1 => hmac_of::<Hmac<sha1::Sha1>>(&self.secret, &msg),
            TotpAlgorithm::Sha256 => hmac_of::<Hmac<sha2::Sha256>>(&self.secret, &msg),
            TotpAlgorithm::Sha512 => hmac_of::<Hmac<sha2::Sha512>>(&self.secret, &msg),
        };
        // RFC 4226 dynamic truncation.
        let offset = usize::from(digest[digest.len() - 1] & 0x0f);
        let bin = u32::from_be_bytes([
            digest[offset] & 0x7f,
            digest[offset + 1],
            digest[offset + 2],
            digest[offset + 3],
        ]);
        bin % 10u32.pow(self.digits)
    }

    fn format(&self, code: u32) -> String {
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// The code at `unix_secs`.
    pub fn code_at(&self, unix_secs: u64) -> String {
        self.format(self.code_for_step(self.step_at(unix_secs)))
    }

    /// The current code (handy in tests and for "send me a code" flows).
    pub fn current_code(&self) -> String {
        self.code_at(now_unix())
    }

    /// Whether `code` is valid now. Prefer [`verify_once`](Self::verify_once),
    /// which also refuses a code that was already used.
    pub fn verify(&self, code: &str) -> bool {
        self.verify_at(code, now_unix()).is_some()
    }

    /// Checks `code` at `unix_secs` and returns the matching time step.
    /// Spaces in the code are ignored (`"123 456"`).
    pub fn verify_at(&self, code: &str, unix_secs: u64) -> Option<u64> {
        self.verify_after(code, unix_secs, None)
    }

    /// Checks `code` now, refusing the time steps up to `last_used_step`
    /// (the step this function returned at the previous successful login,
    /// stored with the user). Returns the new step to store.
    ///
    /// This stops an attacker who saw a code (shoulder surfing, phishing
    /// proxy, logs) from reusing it during its validity window (RFC 6238 §5.2).
    pub fn verify_once(&self, code: &str, last_used_step: Option<u64>) -> Option<u64> {
        self.verify_after(code, now_unix(), last_used_step)
    }

    fn verify_after(&self, code: &str, unix_secs: u64, last: Option<u64>) -> Option<u64> {
        let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        if code.len() != self.digits as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let current = self.step_at(unix_secs);
        let mut found: Option<u64> = None;
        // Every candidate is computed and compared: no early exit.
        for step in current.saturating_sub(self.skew)..=current.saturating_add(self.skew) {
            let expected = self.format(self.code_for_step(step));
            let ok: bool = expected.as_bytes().ct_eq(code.as_bytes()).into();
            let fresh = last.is_none_or(|l| step > l);
            if ok && fresh && found.is_none() {
                found = Some(step);
            }
        }
        found
    }

    /// The `otpauth://` URI to show as a QR code during enrolment
    /// ([Key URI format](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)).
    pub fn provisioning_uri(&self, issuer: &str, account: &str) -> String {
        let issuer_enc = uri_encode(issuer);
        let mut uri = format!(
            "otpauth://totp/{issuer_enc}:{}?secret={}&issuer={issuer_enc}",
            uri_encode(account),
            self.secret_base32()
        );
        if self.algorithm != TotpAlgorithm::Sha1 {
            uri.push_str("&algorithm=");
            uri.push_str(self.algorithm.name());
        }
        if self.digits != 6 {
            uri.push_str(&format!("&digits={}", self.digits));
        }
        if self.period != 30 {
            uri.push_str(&format!("&period={}", self.period));
        }
        uri
    }
}

fn hmac_of<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <M as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// `n` single-use recovery codes such as `k3m7q-2vx9t` (50 random bits
/// each). Show them once, then store only their hashes (e.g. with
/// [`PasswordHasher`](crate::password::PasswordHasher) or SHA-256) and delete
/// each code when it is used.
pub fn recovery_codes(n: usize) -> Vec<String> {
    const ALPHABET: &[u8; 32] = b"abcdefghijkmnpqrstuvwxyz23456789";
    (0..n)
        .map(|_| {
            let mut raw = [0u8; 10];
            secure_random(&mut raw);
            let mut s = String::with_capacity(11);
            for (i, b) in raw.iter().enumerate() {
                if i == 5 {
                    s.push('-');
                }
                s.push(ALPHABET[usize::from(b & 31)] as char);
            }
            s
        })
        .collect()
}

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        if c == b' ' || c == b'-' || c == b'=' {
            continue;
        }
        let v = B32.iter().position(|&x| x == c.to_ascii_uppercase())? as u32;
        buffer = (buffer << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    Some(out)
}

fn uri_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Appendix B.
    const VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn rfc6238_vectors() {
        let sha1 = Totp::new(b"12345678901234567890".to_vec()).digits(8);
        let sha256 = Totp::new(b"12345678901234567890123456789012".to_vec())
            .digits(8)
            .algorithm(TotpAlgorithm::Sha256);
        let sha512 =
            Totp::new(b"1234567890123456789012345678901234567890123456789012345678901234".to_vec())
                .digits(8)
                .algorithm(TotpAlgorithm::Sha512);
        for (t, a, b, c) in VECTORS {
            assert_eq!(sha1.code_at(t), a, "sha1 {t}");
            assert_eq!(sha256.code_at(t), b, "sha256 {t}");
            assert_eq!(sha512.code_at(t), c, "sha512 {t}");
            assert_eq!(sha1.verify_at(a, t), Some(t / 30));
        }
    }

    #[test]
    fn skew_window() {
        let totp = Totp::new(b"12345678901234567890".to_vec());
        let t = 1_000_000_000;
        let code = totp.code_at(t);
        assert!(totp.verify_at(&code, t + 30).is_some(), "one step late");
        assert!(totp.verify_at(&code, t - 30).is_some(), "one step early");
        assert!(totp.verify_at(&code, t + 90).is_none(), "too late");
        assert!(totp.clone().skew(0).verify_at(&code, t + 30).is_none());
        let spaced = format!("{} {}", &code[..3], &code[3..]);
        assert!(totp.verify_at(&spaced, t).is_some());
    }

    #[test]
    fn wrong_codes_are_refused() {
        let totp = Totp::new(b"12345678901234567890".to_vec());
        let t = 1_234_567_890;
        let code = totp.code_at(t);
        let wrong = format!("{:06}", (code.parse::<u32>().unwrap() + 1) % 1_000_000);
        for bad in [
            wrong.as_str(),
            "",
            "12345",
            "1234567",
            "abcdef",
            "12345a",
            "+12345",
            "１２３４５６",
        ] {
            assert!(totp.verify_at(bad, t).is_none(), "{bad}");
        }
    }

    #[test]
    fn replay_is_refused() {
        let totp = Totp::generate();
        let t = 1_700_000_000;
        let code = totp.code_at(t);
        let step = totp.verify_after(&code, t, None).unwrap();
        assert_eq!(totp.verify_after(&code, t, Some(step)), None);
        assert_eq!(totp.verify_after(&code, t + 30, Some(step)), None);
        let next = totp.code_at(t + 30);
        assert_eq!(totp.verify_after(&next, t + 30, Some(step)), Some(step + 1));
    }

    #[test]
    fn base32_round_trip() {
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
        assert_eq!(base32_decode("MZXW6YTBOI======").unwrap(), b"foobar");
        assert_eq!(base32_decode("mzxw 6ytb-oi").unwrap(), b"foobar");
        assert!(base32_decode("MZXW1").is_none());
        let totp = Totp::generate();
        let again = Totp::from_base32(&totp.secret_base32()).unwrap();
        assert_eq!(totp.code_at(42), again.code_at(42));
        assert!(matches!(
            Totp::from_base32("MZXW6YTBOI"),
            Err(TotpError::SecretTooShort)
        ));
        assert!(matches!(
            Totp::from_base32("!!"),
            Err(TotpError::InvalidBase32)
        ));
    }

    #[test]
    #[should_panic(expected = "128 bits")]
    fn short_secret_panics() {
        let _ = Totp::new(b"short".to_vec());
    }

    #[test]
    fn provisioning_uri_and_debug() {
        let totp = Totp::new(b"12345678901234567890".to_vec());
        assert_eq!(
            totp.provisioning_uri("ACME Co", "john@example.com"),
            "otpauth://totp/ACME%20Co:john%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=ACME%20Co"
        );
        let custom = totp
            .clone()
            .algorithm(TotpAlgorithm::Sha256)
            .digits(8)
            .period(Duration::from_secs(60));
        assert!(
            custom
                .provisioning_uri("a", "b")
                .ends_with("&algorithm=SHA256&digits=8&period=60")
        );
        // Injection through the label is encoded.
        assert!(
            totp.provisioning_uri("x?secret=AAAA&", "y")
                .starts_with("otpauth://totp/x%3Fsecret%3DAAAA%26:y?")
        );
        let dbg = format!("{totp:?}");
        assert!(dbg.contains("redacted") && !dbg.contains("GEZDG"));
    }

    #[test]
    fn recovery_codes_are_unique_and_formatted() {
        let codes = recovery_codes(10);
        assert_eq!(codes.len(), 10);
        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 10);
        for c in codes {
            assert_eq!(c.len(), 11);
            assert_eq!(&c[5..6], "-");
        }
    }
}
