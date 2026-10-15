//! JSON Web Token validation (RFC 7519) with JWKS key sets (RFC 7517), through
//! the `jsonwebtoken` crate. Feature `jwt`.
//!
//! A [`JwtValidator`] checks access tokens issued by an identity provider
//! (Auth0, Keycloak, Cognito, Entra ID, Google, your own service …), and
//! [`Auth::jwt`](crate::auth::Auth::jwt) turns it into a guard.
//!
//! Secure by default, against the classic JWT mistakes:
//!
//! * **Algorithm allow-list**: the `alg` of the token header must be in the
//!   list, and must match the family of the key (no RS256 → HS256
//!   confusion, where the public key is used as an HMAC secret). `none` is
//!   never accepted, whatever the configuration.
//! * **`exp` is required**, `nbf` is checked, with a small clock leeway
//!   (30 s by default).
//! * **`iss` and `aud`** are required and checked once configured; a token
//!   that names an audience is refused when none is configured.
//! * **Key rotation**: keys are chosen by `kid`, and the key set can be
//!   replaced at runtime with [`JwtValidator::set_jwks`] (every clone of the
//!   validator sees the new keys). Symmetric (`oct`) and encryption keys of a
//!   JWKS are ignored.
//! * Tokens larger than 8 KiB are refused before any parsing.
//!
//! ```
//! use securite::jwt::{Algorithm, JwtValidator};
//! use securite::prelude::*;
//!
//! let jwks = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"2026-10","alg":"EdDSA",
//!     "x":"YUcsWk2QCCAk6Ql-KNZmokyJkaT4A9Ykdhdd8kyR9P0"}]}"#;
//! let validator = JwtValidator::jwks(jwks)
//!     .unwrap()
//!     .algorithms([Algorithm::EdDSA, Algorithm::RS256])
//!     .issuer("https://id.example.com/")
//!     .audience("api://orders")
//!     .roles_claim("realm_access.roles");
//!
//! let shield = Shield::builder()
//!     .guard(Auth::jwt(validator.clone()).protect(["/api"]))
//!     .build();
//!
//! // Later, e.g. every 10 minutes from a background task that downloads the
//! // provider's `jwks_uri`: every clone, the guard's included, sees the new keys.
//! validator.set_jwks(jwks).unwrap();
//! ```
//!
//! **RSA**: the RustCrypto `rsa` crate has a known timing side channel on
//! *private key* operations (RUSTSEC-2023-0071); this module only *verifies*
//! signatures with public keys, which it does not affect.

use std::collections::HashSet;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet, PublicKeyUse};
use jsonwebtoken::{AlgorithmFamily, DecodingKey, Validation};
use serde_json::{Map, Value};

/// Largest token that is even parsed, in bytes.
pub const MAX_TOKEN_BYTES: usize = 8 * 1024;

/// A JWS signature algorithm (`none` does not exist here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(clippy::upper_case_acronyms)]
pub enum Algorithm {
    /// HMAC with SHA-256 (shared secret).
    HS256,
    /// HMAC with SHA-384.
    HS384,
    /// HMAC with SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 with SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 with SHA-512.
    RS512,
    /// RSASSA-PSS with SHA-256.
    PS256,
    /// RSASSA-PSS with SHA-384.
    PS384,
    /// RSASSA-PSS with SHA-512.
    PS512,
    /// ECDSA on P-256 with SHA-256.
    ES256,
    /// ECDSA on P-384 with SHA-384.
    ES384,
    /// Ed25519.
    EdDSA,
}

impl Algorithm {
    fn to_jwt(self) -> jsonwebtoken::Algorithm {
        use jsonwebtoken::Algorithm as A;
        match self {
            Algorithm::HS256 => A::HS256,
            Algorithm::HS384 => A::HS384,
            Algorithm::HS512 => A::HS512,
            Algorithm::RS256 => A::RS256,
            Algorithm::RS384 => A::RS384,
            Algorithm::RS512 => A::RS512,
            Algorithm::PS256 => A::PS256,
            Algorithm::PS384 => A::PS384,
            Algorithm::PS512 => A::PS512,
            Algorithm::ES256 => A::ES256,
            Algorithm::ES384 => A::ES384,
            Algorithm::EdDSA => A::EdDSA,
        }
    }

    fn from_jwt(alg: jsonwebtoken::Algorithm) -> Self {
        use jsonwebtoken::Algorithm as A;
        match alg {
            A::HS256 => Algorithm::HS256,
            A::HS384 => Algorithm::HS384,
            A::HS512 => Algorithm::HS512,
            A::RS256 => Algorithm::RS256,
            A::RS384 => Algorithm::RS384,
            A::RS512 => Algorithm::RS512,
            A::PS256 => Algorithm::PS256,
            A::PS384 => Algorithm::PS384,
            A::PS512 => Algorithm::PS512,
            A::ES256 => Algorithm::ES256,
            A::ES384 => Algorithm::ES384,
            A::EdDSA => Algorithm::EdDSA,
        }
    }

    fn family(self) -> AlgorithmFamily {
        match self {
            Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => AlgorithmFamily::Hmac,
            Algorithm::ES256 | Algorithm::ES384 => AlgorithmFamily::Ec,
            Algorithm::EdDSA => AlgorithmFamily::Ed,
            _ => AlgorithmFamily::Rsa,
        }
    }
}

/// Why a token, or a key, was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtError {
    /// Not a JWT (shape, encoding, JSON, too large, unknown or `none` algorithm).
    Malformed,
    /// The algorithm of the token is not in the allow-list, or does not
    /// match the key.
    AlgorithmNotAllowed,
    /// No key matches the `kid` (and algorithm) of the token.
    UnknownKey,
    /// The signature does not verify.
    InvalidSignature,
    /// `exp` has passed.
    Expired,
    /// `nbf` is in the future.
    NotYetValid,
    /// A required claim is missing, or `iss` / `aud` / a claim format is wrong.
    InvalidClaims,
    /// A key or a key set given to the validator is invalid or empty.
    InvalidKey,
}

impl fmt::Display for JwtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JwtError::Malformed => "malformed token",
            JwtError::AlgorithmNotAllowed => "algorithm not allowed",
            JwtError::UnknownKey => "unknown signing key",
            JwtError::InvalidSignature => "invalid signature",
            JwtError::Expired => "expired token",
            JwtError::NotYetValid => "token not yet valid",
            JwtError::InvalidClaims => "invalid claims",
            JwtError::InvalidKey => "invalid key",
        })
    }
}

impl std::error::Error for JwtError {}

/// The claims of a validated token, inserted in the request extensions by
/// [`Auth::jwt`](crate::auth::Auth::jwt).
#[derive(Debug, Clone, PartialEq)]
pub struct JwtClaims {
    subject: String,
    roles: Vec<String>,
    claims: Map<String, Value>,
}

impl JwtClaims {
    /// The subject (`sub`, or the configured subject claim).
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The roles read from the roles claim (empty if none).
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// A claim by name (`"email"`, `"tenant"` …).
    pub fn get(&self, name: &str) -> Option<&Value> {
        self.claims.get(name)
    }

    /// A string claim.
    pub fn get_str(&self, name: &str) -> Option<&str> {
        self.claims.get(name).and_then(Value::as_str)
    }

    /// Every claim.
    pub fn all(&self) -> &Map<String, Value> {
        &self.claims
    }
}

#[derive(Clone)]
struct KeyEntry {
    kid: Option<String>,
    alg: Option<Algorithm>,
    key: DecodingKey,
}

#[derive(Clone)]
struct Config {
    algorithms: Vec<Algorithm>,
    issuers: Vec<String>,
    audiences: Vec<String>,
    leeway: u64,
    required: Vec<String>,
    subject_claim: String,
    roles_claim: Option<String>,
}

/// Validates JWTs. Cheap to clone; clones share the key set. See the
/// [module docs](self).
#[derive(Clone)]
pub struct JwtValidator {
    config: Arc<Config>,
    keys: Arc<RwLock<Arc<Vec<KeyEntry>>>>,
}

impl fmt::Debug for JwtValidator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JwtValidator")
            .field("algorithms", &self.config.algorithms)
            .field("issuers", &self.config.issuers)
            .field("audiences", &self.config.audiences)
            .field("keys", &self.current_keys().len())
            .finish()
    }
}

fn ensure_provider() {
    // With `jsonwebtoken`'s two backends enabled in one build (feature
    // unification), it cannot pick one: install RustCrypto, unless the
    // application already installed a provider.
    let _ = jsonwebtoken::crypto::CryptoProvider::install_default(
        &jsonwebtoken::crypto::rust_crypto::DEFAULT_PROVIDER,
    );
}

fn parse_jwks(json: &str) -> Result<Vec<KeyEntry>, JwtError> {
    let set: JwkSet = serde_json::from_str(json).map_err(|_| JwtError::InvalidKey)?;
    let mut out = Vec::new();
    for jwk in &set.keys {
        if matches!(jwk.algorithm, AlgorithmParameters::OctetKey(_))
            || matches!(
                jwk.common.public_key_use,
                Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
            )
        {
            continue;
        }
        let alg = match jwk.common.key_algorithm {
            None => None,
            Some(a) => match a.to_string().parse::<jsonwebtoken::Algorithm>() {
                Ok(a) => Some(Algorithm::from_jwt(a)),
                // An encryption algorithm (RSA-OAEP …) or an unknown one.
                Err(_) => continue,
            },
        };
        let Ok(key) = DecodingKey::from_jwk(jwk) else {
            continue;
        };
        out.push(KeyEntry {
            kid: jwk.common.key_id.clone(),
            alg,
            key,
        });
    }
    if out.is_empty() {
        return Err(JwtError::InvalidKey);
    }
    Ok(out)
}

impl JwtValidator {
    fn with_keys(keys: Vec<KeyEntry>, algorithms: Vec<Algorithm>) -> Self {
        ensure_provider();
        Self {
            config: Arc::new(Config {
                algorithms,
                issuers: Vec::new(),
                audiences: Vec::new(),
                leeway: 30,
                required: Vec::new(),
                subject_claim: "sub".into(),
                roles_claim: Some("roles".into()),
            }),
            keys: Arc::new(RwLock::new(Arc::new(keys))),
        }
    }

    /// Tokens signed with HS256 and a shared secret of at least 32 bytes.
    ///
    /// # Panics
    ///
    /// If the secret is shorter than 32 bytes.
    pub fn hmac(secret: &[u8]) -> Self {
        assert!(
            secret.len() >= 32,
            "a JWT HMAC secret must be at least 32 bytes"
        );
        let entry = KeyEntry {
            kid: None,
            alg: None,
            key: DecodingKey::from_secret(secret),
        };
        Self::with_keys(vec![entry], vec![Algorithm::HS256])
    }

    fn pem(
        pem: &[u8],
        f: fn(&[u8]) -> jsonwebtoken::errors::Result<DecodingKey>,
        alg: Algorithm,
    ) -> Result<Self, JwtError> {
        let key = f(pem).map_err(|_| JwtError::InvalidKey)?;
        let entry = KeyEntry {
            kid: None,
            alg: None,
            key,
        };
        Ok(Self::with_keys(vec![entry], vec![alg]))
    }

    /// An RSA public key in PEM (PKCS#1 or SPKI); allows RS256.
    pub fn rsa_pem(pem: &[u8]) -> Result<Self, JwtError> {
        Self::pem(pem, DecodingKey::from_rsa_pem, Algorithm::RS256)
    }

    /// An EC P-256 / P-384 public key in PEM; allows ES256.
    pub fn ec_pem(pem: &[u8]) -> Result<Self, JwtError> {
        Self::pem(pem, DecodingKey::from_ec_pem, Algorithm::ES256)
    }

    /// An Ed25519 public key in PEM; allows EdDSA.
    pub fn ed_pem(pem: &[u8]) -> Result<Self, JwtError> {
        Self::pem(pem, DecodingKey::from_ed_pem, Algorithm::EdDSA)
    }

    /// A JSON Web Key Set (the document at the provider's `jwks_uri`).
    /// Allows RS256, ES256 and EdDSA by default (see
    /// [`algorithms`](Self::algorithms)).
    pub fn jwks(json: &str) -> Result<Self, JwtError> {
        Ok(Self::with_keys(
            parse_jwks(json)?,
            vec![Algorithm::RS256, Algorithm::ES256, Algorithm::EdDSA],
        ))
    }

    /// Replaces the key set (rotation); every clone sees the new keys. On
    /// error the current keys are kept.
    pub fn set_jwks(&self, json: &str) -> Result<(), JwtError> {
        let keys = parse_jwks(json)?;
        *self.keys.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(keys);
        Ok(())
    }

    fn config_mut(&mut self) -> &mut Config {
        Arc::make_mut(&mut self.config)
    }

    /// The allowed algorithms (replaces the defaults).
    ///
    /// # Panics
    ///
    /// If the list is empty.
    pub fn algorithms<I: IntoIterator<Item = Algorithm>>(mut self, algorithms: I) -> Self {
        let list: Vec<Algorithm> = algorithms.into_iter().collect();
        assert!(!list.is_empty(), "at least one JWT algorithm is required");
        self.config_mut().algorithms = list;
        self
    }

    /// An accepted issuer (`iss`); the claim becomes required. Call again
    /// for several issuers.
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.config_mut().issuers.push(issuer.into());
        self
    }

    /// An accepted audience (`aud`); the claim becomes required. Call again
    /// for several audiences.
    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.config_mut().audiences.push(audience.into());
        self
    }

    /// Clock skew allowed on `exp` and `nbf` (default 30 seconds).
    pub fn leeway(mut self, leeway: Duration) -> Self {
        self.config_mut().leeway = leeway.as_secs();
        self
    }

    /// Claims that must be present (besides `exp` and the subject).
    pub fn require_claims<I, S>(mut self, claims: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.config_mut()
            .required
            .extend(claims.into_iter().map(Into::into));
        self
    }

    /// The claim that names the user (default `sub`), required.
    pub fn subject_claim(mut self, claim: impl Into<String>) -> Self {
        self.config_mut().subject_claim = claim.into();
        self
    }

    /// The claim that holds the roles (default `roles`): an array of strings
    /// or a space separated string (`scope`). Dotted paths reach nested
    /// claims, e.g. Keycloak's `realm_access.roles`.
    pub fn roles_claim(mut self, claim: impl Into<String>) -> Self {
        self.config_mut().roles_claim = Some(claim.into());
        self
    }

    /// Reads no roles from the token.
    pub fn no_roles(mut self) -> Self {
        self.config_mut().roles_claim = None;
        self
    }

    fn current_keys(&self) -> Arc<Vec<KeyEntry>> {
        self.keys.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Validates `token` (without the `Bearer ` prefix).
    pub fn validate(&self, token: &str) -> Result<JwtClaims, JwtError> {
        if token.len() > MAX_TOKEN_BYTES || token.bytes().filter(|&b| b == b'.').count() != 2 {
            return Err(JwtError::Malformed);
        }
        let header = jsonwebtoken::decode_header(token).map_err(|_| JwtError::Malformed)?;
        let alg = Algorithm::from_jwt(header.alg);
        let cfg = &*self.config;
        if !cfg.algorithms.contains(&alg) {
            return Err(JwtError::AlgorithmNotAllowed);
        }
        let mut validation = Validation::new(alg.to_jwt());
        let mut required: HashSet<String> = HashSet::from(["exp".to_owned()]);
        required.extend(cfg.required.iter().cloned());
        if !cfg.issuers.is_empty() {
            validation.set_issuer(&cfg.issuers);
            required.insert("iss".into());
        }
        if !cfg.audiences.is_empty() {
            validation.set_audience(&cfg.audiences);
            required.insert("aud".into());
        }
        validation.required_spec_claims = required.clone();
        validation.validate_nbf = true;
        validation.leeway = cfg.leeway;

        let keys = self.current_keys();
        let candidates: Vec<&KeyEntry> = keys
            .iter()
            .filter(|k| match (&header.kid, &k.kid) {
                (Some(want), Some(have)) => want == have,
                (Some(_), None) => keys.len() == 1,
                (None, _) => true,
            })
            .filter(|k| k.alg.is_none_or(|a| a == alg) && k.key.family() == alg.family())
            .collect();
        if candidates.is_empty() {
            return Err(if keys.iter().any(|k| k.key.family() == alg.family()) {
                JwtError::UnknownKey
            } else {
                JwtError::AlgorithmNotAllowed
            });
        }
        let mut last = JwtError::InvalidSignature;
        for entry in candidates {
            match jsonwebtoken::decode::<Map<String, Value>>(token, &entry.key, &validation) {
                Ok(data) => return self.claims(data.claims, &required),
                Err(e) => {
                    use jsonwebtoken::errors::ErrorKind as K;
                    last = match e.kind() {
                        K::InvalidSignature => JwtError::InvalidSignature,
                        K::ExpiredSignature => return Err(JwtError::Expired),
                        K::ImmatureSignature => return Err(JwtError::NotYetValid),
                        K::InvalidIssuer
                        | K::InvalidAudience
                        | K::InvalidSubject
                        | K::MissingRequiredClaim(_)
                        | K::InvalidClaimFormat(_) => return Err(JwtError::InvalidClaims),
                        K::InvalidAlgorithm | K::InvalidKeyFormat => JwtError::AlgorithmNotAllowed,
                        _ => JwtError::Malformed,
                    };
                }
            }
        }
        Err(last)
    }

    fn claims(
        &self,
        claims: Map<String, Value>,
        required: &HashSet<String>,
    ) -> Result<JwtClaims, JwtError> {
        let cfg = &*self.config;
        // `jsonwebtoken` only knows the registered claims: check the others.
        if required.iter().any(|c| !claims.contains_key(c)) {
            return Err(JwtError::InvalidClaims);
        }
        let subject = match claims.get(&cfg.subject_claim) {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(Value::Number(n)) => n.to_string(),
            _ => return Err(JwtError::InvalidClaims),
        };
        let roles = cfg
            .roles_claim
            .as_deref()
            .and_then(|path| {
                let mut parts = path.split('.');
                let first = claims.get(parts.next()?)?;
                parts.try_fold(first, |v, p| v.get(p))
            })
            .map(|v| match v {
                Value::Array(items) => items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                Value::String(s) => s.split_whitespace().map(str::to_owned).collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        Ok(JwtClaims {
            subject,
            roles,
            claims,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    pub(crate) const SECRET: &[u8] = b"an hmac secret of at least 32 bytes!!";

    // Test keys only (generated with `openssl genpkey`).
    const ED_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIMw1wAWlN3C6ey0O9tl7R3AO0Eum5JTyjja6zqeW2iV8\n-----END PRIVATE KEY-----\n";
    const ED_PUBLIC: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAYUcsWk2QCCAk6Ql+KNZmokyJkaT4A9Ykdhdd8kyR9P0=\n-----END PUBLIC KEY-----\n";
    const ED_X: &str = "YUcsWk2QCCAk6Ql-KNZmokyJkaT4A9Ykdhdd8kyR9P0";
    const ED2_PRIVATE: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINIxYe+ovRJF8VJIzr5bd/WbmzXyuYpuJwJzpGrdGeo2\n-----END PRIVATE KEY-----\n";

    pub(crate) fn now() -> u64 {
        jsonwebtoken::get_current_timestamp()
    }

    pub(crate) fn hs(claims: &Value) -> String {
        encode(
            &Header::new(jsonwebtoken::Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    fn ed(private: &str, kid: Option<&str>, claims: &Value) -> String {
        let mut h = Header::new(jsonwebtoken::Algorithm::EdDSA);
        h.kid = kid.map(str::to_owned);
        encode(
            &h,
            claims,
            &EncodingKey::from_ed_pem(private.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    fn jwks() -> String {
        format!(
            r#"{{"keys":[
              {{"kty":"oct","kid":"sym","k":"c2VjcmV0"}},
              {{"kty":"OKP","crv":"Ed25519","kid":"k1","alg":"EdDSA","use":"sig","x":"{ED_X}"}}
            ]}}"#
        )
    }

    fn b64(v: &Value) -> String {
        crate::util::b64url(v.to_string().as_bytes())
    }

    #[test]
    fn hmac_happy_path_and_roles() {
        let v = JwtValidator::hmac(SECRET);
        let t =
            hs(&json!({"sub": "u1", "exp": now() + 60, "roles": ["ROLE_ADMIN"], "email": "a@b.c"}));
        let c = v.validate(&t).unwrap();
        assert_eq!(c.subject(), "u1");
        assert_eq!(c.roles(), ["ROLE_ADMIN"]);
        assert_eq!(c.get_str("email"), Some("a@b.c"));
        let scoped = JwtValidator::hmac(SECRET).roles_claim("scope");
        let t = hs(&json!({"sub": 7, "exp": now() + 60, "scope": "read write"}));
        let c = scoped.validate(&t).unwrap();
        assert_eq!(c.subject(), "7");
        assert_eq!(c.roles(), ["read", "write"]);
        let kc = JwtValidator::hmac(SECRET).roles_claim("realm_access.roles");
        let t = hs(&json!({"sub": "k", "exp": now() + 60, "realm_access": {"roles": ["r"]}}));
        assert_eq!(kc.validate(&t).unwrap().roles(), ["r"]);
    }

    #[test]
    fn time_claims() {
        let v = JwtValidator::hmac(SECRET);
        assert_eq!(
            v.validate(&hs(&json!({"sub": "u"}))),
            Err(JwtError::InvalidClaims),
            "exp is required"
        );
        assert_eq!(
            v.validate(&hs(&json!({"sub": "u", "exp": now() - 120}))),
            Err(JwtError::Expired)
        );
        assert!(
            v.validate(&hs(&json!({"sub": "u", "exp": now() - 5})))
                .is_ok(),
            "leeway"
        );
        assert_eq!(
            v.validate(&hs(
                &json!({"sub": "u", "exp": now() + 600, "nbf": now() + 300})
            )),
            Err(JwtError::NotYetValid)
        );
        assert_eq!(
            v.validate(&hs(&json!({"sub": "u", "exp": "tomorrow"}))),
            Err(JwtError::InvalidClaims)
        );
        assert_eq!(
            v.validate(&hs(&json!({"exp": now() + 60}))),
            Err(JwtError::InvalidClaims),
            "subject required"
        );
    }

    #[test]
    fn issuer_audience_and_required_claims() {
        let v = JwtValidator::hmac(SECRET)
            .issuer("https://id")
            .audience("api")
            .require_claims(["tenant"]);
        let ok = json!({"sub": "u", "exp": now() + 60, "iss": "https://id", "aud": "api", "tenant": "t"});
        assert!(v.validate(&hs(&ok)).is_ok());
        for (k, val) in [("iss", json!("https://evil")), ("aud", json!("other"))] {
            let mut c = ok.clone();
            c[k] = val;
            assert_eq!(v.validate(&hs(&c)), Err(JwtError::InvalidClaims), "{k}");
        }
        for k in ["iss", "aud", "tenant"] {
            let mut c = ok.clone();
            c.as_object_mut().unwrap().remove(k);
            assert_eq!(v.validate(&hs(&c)), Err(JwtError::InvalidClaims), "{k}");
        }
        // A token for another audience is refused even without configuration.
        let plain = JwtValidator::hmac(SECRET);
        assert_eq!(
            plain.validate(&hs(
                &json!({"sub": "u", "exp": now() + 60, "aud": "billing"})
            )),
            Err(JwtError::InvalidClaims)
        );
    }

    #[test]
    fn signature_attacks() {
        let v = JwtValidator::hmac(SECRET);
        let t = hs(&json!({"sub": "u", "exp": now() + 60}));
        // Tampered payload.
        let parts: Vec<&str> = t.split('.').collect();
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            b64(&json!({"sub": "admin", "exp": now() + 60})),
            parts[2]
        );
        assert_eq!(v.validate(&forged), Err(JwtError::InvalidSignature));
        // Wrong secret.
        let other = encode(
            &Header::default(),
            &json!({"sub": "u", "exp": now() + 60}),
            &EncodingKey::from_secret(b"another secret of at least 32 bytes!!!"),
        )
        .unwrap();
        assert_eq!(v.validate(&other), Err(JwtError::InvalidSignature));
        // alg: none, with and without a signature.
        let payload = b64(&json!({"sub": "admin", "exp": now() + 60}));
        for alg in ["none", "None", "NONE"] {
            let h = b64(&json!({"alg": alg, "typ": "JWT"}));
            assert_eq!(
                v.validate(&format!("{h}.{payload}.")),
                Err(JwtError::Malformed)
            );
            assert_eq!(
                v.validate(&format!("{h}.{payload}.{}", parts[2])),
                Err(JwtError::Malformed)
            );
        }
        // Algorithm not in the allow-list.
        let h = b64(&json!({"alg": "HS512"}));
        assert_eq!(
            v.validate(&format!("{h}.{payload}.AAAA")),
            Err(JwtError::AlgorithmNotAllowed)
        );
        // Garbage and oversized input.
        for bad in [
            "",
            "a.b",
            "a.b.c",
            "a.b.c.d",
            "....",
            &"a".repeat(MAX_TOKEN_BYTES + 1),
        ] {
            assert_eq!(v.validate(bad), Err(JwtError::Malformed), "{bad:.12}");
        }
    }

    #[test]
    fn jwks_rotation_and_kid() {
        let v = JwtValidator::jwks(&jwks()).unwrap();
        let claims = json!({"sub": "u", "exp": now() + 60});
        assert!(v.validate(&ed(ED_PRIVATE, Some("k1"), &claims)).is_ok());
        assert!(v.validate(&ed(ED_PRIVATE, None, &claims)).is_ok());
        assert_eq!(
            v.validate(&ed(ED_PRIVATE, Some("unknown"), &claims)),
            Err(JwtError::UnknownKey)
        );
        // Signed by another key with a known kid.
        assert_eq!(
            v.validate(&ed(ED2_PRIVATE, Some("k1"), &claims)),
            Err(JwtError::InvalidSignature)
        );
        // Rotation: an empty / invalid set keeps the current keys.
        let clone = v.clone();
        assert_eq!(v.set_jwks(r#"{"keys":[]}"#), Err(JwtError::InvalidKey));
        assert_eq!(v.set_jwks("not json"), Err(JwtError::InvalidKey));
        assert!(clone.validate(&ed(ED_PRIVATE, Some("k1"), &claims)).is_ok());
        v.set_jwks(r#"{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k2","x":"YUcsWk2QCCAk6Ql-KNZmokyJkaT4A9Ykdhdd8kyR9P0"}]}"#)
            .unwrap();
        assert_eq!(
            clone.validate(&ed(ED_PRIVATE, Some("k1"), &claims)),
            Err(JwtError::UnknownKey),
            "clones see the new key set"
        );
        assert!(clone.validate(&ed(ED_PRIVATE, Some("k2"), &claims)).is_ok());
    }

    #[test]
    fn algorithm_confusion_is_refused() {
        // HS256 signed with the *public* key bytes, kid of the Ed25519 key.
        let v = JwtValidator::jwks(&jwks())
            .unwrap()
            .algorithms([Algorithm::EdDSA, Algorithm::HS256]);
        let mut h = Header::new(jsonwebtoken::Algorithm::HS256);
        h.kid = Some("k1".into());
        let t = encode(
            &h,
            &json!({"sub": "admin", "exp": now() + 60}),
            &EncodingKey::from_secret(ED_X.as_bytes()),
        )
        .unwrap();
        assert_eq!(v.validate(&t), Err(JwtError::AlgorithmNotAllowed));
        // The `oct` key of the set is ignored.
        let mut h = Header::new(jsonwebtoken::Algorithm::HS256);
        h.kid = Some("sym".into());
        let t = encode(
            &h,
            &json!({"sub": "admin", "exp": now() + 60}),
            &EncodingKey::from_secret(b"secret"),
        )
        .unwrap();
        assert!(v.validate(&t).is_err());
        // HS256 is not allowed by default with a JWKS.
        assert_eq!(
            JwtValidator::jwks(&jwks()).unwrap().validate(&t),
            Err(JwtError::AlgorithmNotAllowed)
        );
    }

    #[test]
    fn pem_keys() {
        let v = JwtValidator::ed_pem(ED_PUBLIC.as_bytes()).unwrap();
        assert!(
            v.validate(&ed(
                ED_PRIVATE,
                Some("any"),
                &json!({"sub": "u", "exp": now() + 60})
            ))
            .is_ok()
        );
        assert_eq!(
            JwtValidator::rsa_pem(b"nope").unwrap_err(),
            JwtError::InvalidKey
        );
        assert!(JwtValidator::jwks(r#"{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}"#).is_err());
        assert!(format!("{v:?}").contains("EdDSA"));
    }

    #[test]
    #[should_panic(expected = "at least 32 bytes")]
    fn short_hmac_secret() {
        let _ = JwtValidator::hmac(b"short");
    }
}
