//! Password hashing with **Argon2id**, the algorithm recommended by OWASP and
//! RFC 9106 (feature `password`, enabled by default).
//!
//! [`PasswordHasher`] wraps the audited [`argon2`](https://docs.rs/argon2)
//! crate (RustCrypto) with secure defaults and the helpers a login flow needs:
//!
//! * [`hash`](PasswordHasher::hash) produces a self-describing PHC string
//!   (`$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`) with a fresh 16-byte
//!   random salt;
//! * [`verify`](PasswordHasher::verify) checks a password in constant time,
//!   with the parameters stored in the hash;
//! * [`check`](PasswordHasher::check) also tells you when a stored hash was
//!   made with weaker parameters and hands you its replacement (like
//!   Laravel's `Hash::needsRehash`), so cost upgrades happen at login;
//! * [`verify_dummy`](PasswordHasher::verify_dummy) burns the same time as a
//!   real verification when the account does not exist, so response times do
//!   not reveal which e-mail addresses are registered;
//! * an optional [`pepper`](PasswordHasher::pepper) (a secret kept out of the
//!   database) makes a stolen database useless on its own.
//!
//! ```
//! use securite::password::{PasswordCheck, PasswordHasher};
//!
//! let hasher = PasswordHasher::new();
//! let stored = hasher.hash("correct horse battery staple").unwrap();
//! assert!(stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
//!
//! assert!(hasher.verify("correct horse battery staple", &stored));
//! assert!(!hasher.verify("Tr0ub4dor&3", &stored));
//!
//! match hasher.check("correct horse battery staple", &stored) {
//!     PasswordCheck::Valid => { /* log in */ }
//!     PasswordCheck::ValidNeedsRehash(new_hash) => { /* log in, store new_hash */ let _ = new_hash; }
//!     PasswordCheck::Invalid => { /* reject */ }
//! }
//! ```
//!
//! Hashing is deliberately slow (around 20 to 50 ms and 19 MiB of memory with
//! the defaults): in an async server, call it from a blocking task
//! (`tokio::task::spawn_blocking`) and keep a rate limit on the login route.

use std::fmt;
use std::sync::{Arc, OnceLock};

use argon2::password_hash::phc::PasswordHash;
use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier as _, Version};

use crate::util::secure_random;

/// Longest password accepted, in bytes (passwords above it are refused, not
/// truncated). Generous for passphrases and password managers, small enough
/// to keep hashing cheap.
pub const DEFAULT_MAX_PASSWORD_BYTES: usize = 1024;

const SALT_LEN: usize = 16;

/// Why a password could not be hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PasswordError {
    /// The password is longer than the configured maximum
    /// ([`DEFAULT_MAX_PASSWORD_BYTES`] by default).
    TooLong,
    /// The password is empty.
    Empty,
    /// The Argon2 implementation reported an error (invalid parameters …).
    Hashing(String),
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PasswordError::TooLong => f.write_str("password too long"),
            PasswordError::Empty => f.write_str("empty password"),
            PasswordError::Hashing(e) => write!(f, "password hashing failed: {e}"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Outcome of [`PasswordHasher::check`].
#[derive(Clone, PartialEq, Eq)]
pub enum PasswordCheck {
    /// Wrong password, malformed hash, or a hash this hasher cannot verify.
    Invalid,
    /// Right password; the stored hash uses the current parameters.
    Valid,
    /// Right password, but the stored hash is weaker than the current
    /// parameters (or uses another Argon2 variant): store the new hash.
    ValidNeedsRehash(String),
}

impl PasswordCheck {
    /// Whether the password matched.
    pub fn is_valid(&self) -> bool {
        !matches!(self, PasswordCheck::Invalid)
    }
}

impl fmt::Debug for PasswordCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print hashes in logs.
        f.write_str(match self {
            PasswordCheck::Invalid => "Invalid",
            PasswordCheck::Valid => "Valid",
            PasswordCheck::ValidNeedsRehash(_) => "ValidNeedsRehash(..)",
        })
    }
}

/// Argon2id password hasher. Cheap to clone. See the [module docs](self).
///
/// Defaults are the first OWASP recommendation for Argon2id:
/// `m = 19 MiB, t = 2, p = 1`.
#[derive(Clone)]
pub struct PasswordHasher {
    params: Params,
    pepper: Option<Arc<[u8]>>,
    max_bytes: usize,
    dummy: Arc<OnceLock<String>>,
}

impl Default for PasswordHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for PasswordHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PasswordHasher")
            .field("m_cost_kib", &self.params.m_cost())
            .field("t_cost", &self.params.t_cost())
            .field("p_cost", &self.params.p_cost())
            .field("pepper", &self.pepper.is_some())
            .field("max_bytes", &self.max_bytes)
            .finish()
    }
}

impl PasswordHasher {
    /// Argon2id with the OWASP parameters `m = 19456 KiB, t = 2, p = 1`.
    pub fn new() -> Self {
        Self::with_params(19 * 1024, 2, 1)
    }

    /// Argon2id with explicit costs: memory in KiB, iterations, parallelism.
    ///
    /// OWASP lists equivalent settings, for instance `(47104, 1, 1)`,
    /// `(12288, 3, 1)` or `(9216, 4, 1)`; RFC 9106 recommends `(2097152, 1, 4)`
    /// where 2 GiB per hash is affordable.
    ///
    /// # Panics
    ///
    /// If the parameters are invalid for Argon2 or weaker than the lowest OWASP
    /// setting (`m >= 7168 KiB` and `m * t >= 35840`).
    pub fn with_params(memory_kib: u32, iterations: u32, parallelism: u32) -> Self {
        assert!(
            memory_kib >= 7 * 1024 && u64::from(memory_kib) * u64::from(iterations) >= 35_840,
            "Argon2 parameters below the OWASP minimum (m >= 7168 KiB, m*t >= 35840)"
        );
        let params = Params::new(memory_kib, iterations, parallelism, None)
            .unwrap_or_else(|e| panic!("invalid Argon2 parameters: {e}"));
        Self {
            params,
            pepper: None,
            max_bytes: DEFAULT_MAX_PASSWORD_BYTES,
            dummy: Arc::new(OnceLock::new()),
        }
    }

    /// Cheap parameters for **tests only** (`m = 8 KiB, t = 1`): never use
    /// them in production.
    #[doc(hidden)]
    pub fn insecure_fast_for_tests() -> Self {
        Self {
            params: Params::new(8, 1, 1, None).expect("valid test params"),
            pepper: None,
            max_bytes: DEFAULT_MAX_PASSWORD_BYTES,
            dummy: Arc::new(OnceLock::new()),
        }
    }

    /// A secret "pepper" mixed into every hash (Argon2's secret input). Keep
    /// it outside the database (environment, secret manager): a leaked
    /// database alone then cannot be cracked. Hashes made with a pepper can
    /// only be verified with the same pepper.
    ///
    /// # Panics
    ///
    /// If the pepper is shorter than 16 bytes.
    pub fn pepper(mut self, secret: impl AsRef<[u8]>) -> Self {
        let secret = secret.as_ref();
        assert!(secret.len() >= 16, "the pepper must be at least 16 bytes");
        self.pepper = Some(Arc::from(secret));
        self.dummy = Arc::new(OnceLock::new());
        self
    }

    /// Longest accepted password in bytes (default
    /// [`DEFAULT_MAX_PASSWORD_BYTES`]).
    pub fn max_password_bytes(mut self, bytes: usize) -> Self {
        self.max_bytes = bytes.max(1);
        self
    }

    fn argon2_with(&self, params: Params) -> Argon2<'_> {
        match &self.pepper {
            Some(p) => Argon2::new_with_secret(p, Algorithm::Argon2id, Version::V0x13, params)
                .expect("pepper length is validated"),
            None => Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
        }
    }

    /// Hashes `password` with a fresh random salt and returns its PHC string.
    pub fn hash(&self, password: &str) -> Result<String, PasswordError> {
        if password.is_empty() {
            return Err(PasswordError::Empty);
        }
        if password.len() > self.max_bytes {
            return Err(PasswordError::TooLong);
        }
        let mut salt = [0u8; SALT_LEN];
        secure_random(&mut salt);
        self.argon2_with(self.params.clone())
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| PasswordError::Hashing(e.to_string()))
    }

    /// Whether `password` matches `hash` (a PHC string made by
    /// [`hash`](Self::hash)). Malformed hashes, other algorithms and
    /// over-long passwords never match.
    pub fn verify(&self, password: &str, hash: &str) -> bool {
        self.check(password, hash).is_valid()
    }

    /// Verifies `password` and tells whether the stored hash should be
    /// replaced, giving the replacement (see [`PasswordCheck`]).
    pub fn check(&self, password: &str, hash: &str) -> PasswordCheck {
        if password.is_empty() || password.len() > self.max_bytes {
            return PasswordCheck::Invalid;
        }
        let Ok(parsed) = PasswordHash::new(hash) else {
            return PasswordCheck::Invalid;
        };
        // Only Argon2 hashes, and never absurd costs taken from a tampered row
        // (a denial of service): at most 4 times the configured memory/time.
        let Some(alg) = argon2_algorithm(parsed.algorithm.as_str()) else {
            return PasswordCheck::Invalid;
        };
        let Ok(stored) = Params::try_from(&parsed) else {
            return PasswordCheck::Invalid;
        };
        if stored.m_cost() > self.params.m_cost().saturating_mul(4)
            || stored.t_cost() > self.params.t_cost().saturating_mul(4).max(8)
            || stored.p_cost() > self.params.p_cost().saturating_mul(4).max(8)
        {
            return PasswordCheck::Invalid;
        }
        let ok = self
            .argon2_with(self.params.clone())
            .verify_password(password.as_bytes(), &parsed)
            .is_ok();
        if !ok {
            return PasswordCheck::Invalid;
        }
        if self.is_current(alg, parsed.version, &stored) {
            PasswordCheck::Valid
        } else {
            match self.hash(password) {
                Ok(h) => PasswordCheck::ValidNeedsRehash(h),
                Err(_) => PasswordCheck::Valid,
            }
        }
    }

    fn is_current(&self, alg: Algorithm, version: Option<u32>, stored: &Params) -> bool {
        alg == Algorithm::Argon2id
            && version == Some(0x13)
            && stored.m_cost() >= self.params.m_cost()
            && stored.t_cost() >= self.params.t_cost()
            && stored.p_cost() >= self.params.p_cost()
    }

    /// Whether `hash` was made with weaker parameters than this hasher's (or
    /// is not an Argon2id hash at all). Prefer [`check`](Self::check), which
    /// also gives the new hash.
    pub fn needs_rehash(&self, hash: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(hash) else {
            return true;
        };
        let (Some(alg), Ok(stored)) = (
            argon2_algorithm(parsed.algorithm.as_str()),
            Params::try_from(&parsed),
        ) else {
            return true;
        };
        !self.is_current(alg, parsed.version, &stored)
    }

    /// Runs a full verification against a hash of a random password and
    /// returns `false`. Call it when the account does not exist, so that an
    /// attacker cannot tell registered e-mail addresses from response times
    /// (OWASP ASVS 2.2 / CWE-204).
    ///
    /// ```
    /// # use securite::password::PasswordHasher;
    /// # let hasher = PasswordHasher::insecure_fast_for_tests();
    /// # let find_user = |_: &str| -> Option<String> { None };
    /// let ok = match find_user("alice@example.com") {
    ///     Some(stored_hash) => hasher.verify("pa55word", &stored_hash),
    ///     None => hasher.verify_dummy("pa55word"),
    /// };
    /// assert!(!ok);
    /// ```
    pub fn verify_dummy(&self, password: &str) -> bool {
        let dummy = self.dummy.get_or_init(|| {
            let mut random = [0u8; 24];
            secure_random(&mut random);
            self.hash(&crate::util::b64url(&random))
                .unwrap_or_else(|_| String::from("$argon2id$v=19$m=8,t=1,p=1$AAAAAAAAAAA$AAAA"))
        });
        let _ = self.check(password, dummy);
        false
    }
}

fn argon2_algorithm(ident: &str) -> Option<Algorithm> {
    match ident {
        "argon2id" => Some(Algorithm::Argon2id),
        "argon2i" => Some(Algorithm::Argon2i),
        "argon2d" => Some(Algorithm::Argon2d),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast() -> PasswordHasher {
        PasswordHasher::insecure_fast_for_tests()
    }

    #[test]
    fn hash_and_verify() {
        let h = fast();
        let stored = h.hash("hunter42-but-longer").unwrap();
        assert!(stored.starts_with("$argon2id$v=19$m=8,t=1,p=1$"));
        assert!(h.verify("hunter42-but-longer", &stored));
        assert!(!h.verify("hunter42-but-longeR", &stored));
        assert!(!h.verify("", &stored));
    }

    #[test]
    fn salts_are_random() {
        let h = fast();
        assert_ne!(h.hash("same").unwrap(), h.hash("same").unwrap());
    }

    #[test]
    fn default_params_are_owasp() {
        let h = PasswordHasher::new();
        let stored = h.hash("pw").unwrap();
        assert!(
            stored.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{stored}"
        );
        assert!(h.verify("pw", &stored));
        assert_eq!(h.check("pw", &stored), PasswordCheck::Valid);
    }

    #[test]
    fn rejects_empty_and_long_passwords() {
        let h = fast().max_password_bytes(10);
        assert_eq!(h.hash(""), Err(PasswordError::Empty));
        assert_eq!(h.hash("01234567890"), Err(PasswordError::TooLong));
        let stored = fast().hash("01234567890").unwrap();
        assert!(!h.verify("01234567890", &stored));
    }

    #[test]
    fn malformed_and_foreign_hashes_never_match() {
        let h = fast();
        for bad in [
            "",
            "plain-text-password",
            "$2y$10$abcdefghijklmnopqrstuuJ8z4m3l3oRNTSbH5I4uB7pqgM6q7hO.",
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$",
            "$argon2id$v=19$m=8,t=1,p=1$$AAAA",
            "$pbkdf2-sha256$i=1000$c2FsdA$aGFzaA",
        ] {
            assert!(!h.verify("password", bad), "{bad}");
            assert!(h.needs_rehash(bad), "{bad}");
        }
    }

    #[test]
    fn tampered_hash_does_not_verify() {
        let h = fast();
        let stored = h.hash("secret").unwrap();
        let mut bytes = stored.into_bytes();
        let last = bytes.len() - 2;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        assert!(!h.verify("secret", &String::from_utf8(bytes).unwrap()));
    }

    #[test]
    fn absurd_costs_are_refused_without_hashing() {
        // A tampered row asking for 4 GiB must not be computed.
        let h = fast();
        let evil = "$argon2id$v=19$m=4194304,t=1,p=1$c2FsdHNhbHRzYWx0$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(!h.verify("x", evil));
    }

    #[test]
    fn weaker_hashes_are_upgraded() {
        let weak = fast().hash("pw").unwrap();
        let strong = PasswordHasher::new();
        assert!(strong.needs_rehash(&weak));
        // A hash from a weaker setting is far below 4x: still verified.
        match strong.check("pw", &weak) {
            PasswordCheck::ValidNeedsRehash(new_hash) => {
                assert!(new_hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
                assert!(strong.verify("pw", &new_hash));
                assert!(!strong.needs_rehash(&new_hash));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(strong.check("wrong", &weak), PasswordCheck::Invalid);
    }

    #[test]
    fn argon2i_hashes_are_verified_then_upgraded() {
        let h = fast();
        let argon2i = Argon2::new(Algorithm::Argon2i, Version::V0x13, h.params.clone())
            .hash_password_with_salt(b"pw", b"saltsaltsalt")
            .unwrap()
            .to_string();
        assert!(argon2i.starts_with("$argon2i$"));
        assert!(matches!(
            h.check("pw", &argon2i),
            PasswordCheck::ValidNeedsRehash(_)
        ));
    }

    #[test]
    fn pepper_is_required_to_verify() {
        let peppered = fast().pepper("a-secret-pepper-of-32-bytes-long");
        let stored = peppered.hash("pw").unwrap();
        assert!(peppered.verify("pw", &stored));
        assert!(!fast().verify("pw", &stored));
        assert!(
            !fast()
                .pepper("another-pepper-0123456789")
                .verify("pw", &stored)
        );
        assert!(!format!("{peppered:?}").contains("secret"));
    }

    #[test]
    #[should_panic(expected = "at least 16 bytes")]
    fn short_pepper_panics() {
        let _ = fast().pepper("short");
    }

    #[test]
    #[should_panic(expected = "OWASP minimum")]
    fn weak_params_panic() {
        let _ = PasswordHasher::with_params(1024, 1, 1);
    }

    #[test]
    fn dummy_verification_is_always_false() {
        let h = fast();
        assert!(!h.verify_dummy("anything"));
        assert!(!h.verify_dummy(""));
        assert!(!format!("{:?}", PasswordCheck::ValidNeedsRehash("$x".into())).contains("$x"));
    }
}
