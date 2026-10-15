//! Bearer token, API key and Basic authentication with constant-time checks.

use std::fmt;
use std::sync::Arc;

use http::header::{AUTHORIZATION, HeaderName, HeaderValue, WWW_AUTHENTICATE};
use http::{Method, StatusCode, request};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::access::Roles;
use crate::guard::impl_layer;
use crate::util::{any_path_matches, b64std_decode, hex_decode, normalize_prefix};
use crate::{Context, Guard, Rejection, priority};

/// The authenticated principal, inserted in the request extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// Label of the matching credential (or the Basic auth user name).
    pub name: Arc<str>,
    /// `bearer`, `api_key`, `basic` or `custom`.
    pub scheme: &'static str,
}

type Validator = dyn Fn(&str, &request::Parts) -> Option<String> + Send + Sync;

#[derive(Clone)]
enum Scheme {
    Bearer,
    ApiKey(HeaderName),
    Basic,
    Custom(Arc<Validator>),
    #[cfg(feature = "jwt")]
    Jwt(crate::jwt::JwtValidator),
}

/// Authentication guard.
///
/// Secrets are stored as SHA-256 digests and compared in constant time
/// against **every** configured credential, so neither the length nor the
/// position of a secret leaks through timing.
///
/// ```
/// use securite::prelude::*;
///
/// // `Authorization: Bearer <token>` on /api and /admin only:
/// let auth = Auth::bearer()
///     .token("ci-bot", "s3cr3t-token-from-env")
///     .protect(["/api", "/admin"])
///     .public(["/api/health"]);
///
/// // `X-API-Key: <key>`:
/// let auth = Auth::api_key("x-api-key").token("partner-a", "k_live_123");
///
/// // HTTP Basic (only a SHA-256 digest of `user:password` is kept in memory):
/// let auth = Auth::basic("Admin area").user("admin", "correct horse battery staple");
///
/// // Your own validation (JWT, database lookup …):
/// let auth = Auth::custom(|token, _req| (token == "valid").then(|| "user-42".to_string()));
/// ```
#[derive(Clone)]
pub struct Auth {
    scheme: Scheme,
    credentials: Vec<(Arc<str>, [u8; 32])>,
    realm: String,
    protect: Vec<String>,
    public: Vec<String>,
    allow_options: bool,
    grants: Vec<(Arc<str>, Roles)>,
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match &self.scheme {
            Scheme::Bearer => "bearer",
            Scheme::ApiKey(_) => "api_key",
            Scheme::Basic => "basic",
            Scheme::Custom(_) => "custom",
            #[cfg(feature = "jwt")]
            Scheme::Jwt(_) => "jwt",
        };
        f.debug_struct("Auth")
            .field("scheme", &scheme)
            .field("credentials", &self.credentials.len())
            .field("protect", &self.protect)
            .field("public", &self.public)
            .finish()
    }
}

fn digest(secret: &[u8]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

impl Auth {
    fn with_scheme(scheme: Scheme) -> Self {
        Self {
            scheme,
            credentials: Vec::new(),
            realm: "restricted".into(),
            protect: Vec::new(),
            public: Vec::new(),
            allow_options: true,
            grants: Vec::new(),
        }
    }

    /// `Authorization: Bearer <token>`.
    pub fn bearer() -> Self {
        Self::with_scheme(Scheme::Bearer)
    }

    /// API key in a custom header (e.g. `x-api-key`).
    pub fn api_key(header: &str) -> Self {
        Self::with_scheme(Scheme::ApiKey(
            HeaderName::from_bytes(header.as_bytes()).expect("invalid header name"),
        ))
    }

    /// HTTP Basic authentication.
    pub fn basic(realm: &str) -> Self {
        Self::with_scheme(Scheme::Basic).realm(realm)
    }

    /// Bearer token checked by your own function, which returns the
    /// principal name when the token is valid.
    pub fn custom<F>(validate: F) -> Self
    where
        F: Fn(&str, &request::Parts) -> Option<String> + Send + Sync + 'static,
    {
        Self::with_scheme(Scheme::Custom(Arc::new(validate)))
    }

    /// JSON Web Tokens in `Authorization: Bearer <jwt>`, checked by a
    /// [`JwtValidator`](crate::jwt::JwtValidator) (feature `jwt`).
    ///
    /// On success the request extensions get a [`Principal`] (scheme `jwt`,
    /// named after the subject), the [`JwtClaims`](crate::jwt::JwtClaims) and
    /// the [`Roles`] of the token. On failure the `401` carries
    /// `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750) and the
    /// reason is only written to the audit log.
    ///
    /// ```
    /// use securite::jwt::JwtValidator;
    /// use securite::prelude::*;
    ///
    /// let auth = Auth::jwt(JwtValidator::hmac(b"a shared secret of at least 32 bytes"))
    ///     .protect(["/api"]);
    /// ```
    #[cfg(feature = "jwt")]
    #[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
    pub fn jwt(validator: crate::jwt::JwtValidator) -> Self {
        Self::with_scheme(Scheme::Jwt(validator))
    }

    /// Gives roles to the credential labelled `label` (a token label or a
    /// Basic user): on success, they are put in the request extensions as
    /// [`Roles`], for [`AccessControl`](crate::access::AccessControl) and
    /// your handlers.
    pub fn grant<I, S>(mut self, label: &str, roles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.grants.push((Arc::from(label), Roles::new(roles)));
        self
    }

    /// Adds an accepted token / API key with a label.
    ///
    /// # Panics
    ///
    /// If the secret is shorter than 8 bytes.
    pub fn token(mut self, label: &str, secret: &str) -> Self {
        assert!(secret.len() >= 8, "secrets must be at least 8 bytes long");
        self.credentials
            .push((Arc::from(label), digest(secret.as_bytes())));
        self
    }

    /// Adds an accepted token by its SHA-256 hex digest (keep plain secrets
    /// out of your config).
    ///
    /// # Panics
    ///
    /// If `sha256_hex` is not 64 hex characters.
    pub fn token_sha256(mut self, label: &str, sha256_hex: &str) -> Self {
        let raw = hex_decode(sha256_hex.trim()).expect("invalid hex digest");
        let arr: [u8; 32] = raw.try_into().expect("a SHA-256 digest is 32 bytes");
        self.credentials.push((Arc::from(label), arr));
        self
    }

    /// Basic auth user (password stored as SHA-256 of `user:password`).
    pub fn user(mut self, user: &str, password: &str) -> Self {
        assert!(!user.contains(':'), "user names cannot contain ':'");
        self.credentials.push((
            Arc::from(user),
            digest(format!("{user}:{password}").as_bytes()),
        ));
        self
    }

    /// Realm shown by browsers (`WWW-Authenticate`).
    pub fn realm(mut self, realm: &str) -> Self {
        self.realm = realm.replace(['"', '\\'], "");
        self
    }

    /// Only these path prefixes require authentication (default: all).
    pub fn protect<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.protect
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Path prefixes that never require authentication.
    pub fn public<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.public
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Also require credentials on `OPTIONS` (CORS preflights never carry
    /// credentials, so this is off by default).
    pub fn protect_options(mut self) -> Self {
        self.allow_options = false;
        self
    }

    fn find(&self, secret: &[u8]) -> Option<Arc<str>> {
        let d = digest(secret);
        let mut found: Option<Arc<str>> = None;
        // Always compare against every credential (no early exit).
        for (label, expected) in &self.credentials {
            if bool::from(d.ct_eq(expected)) {
                found = Some(label.clone());
            }
        }
        found
    }

    fn challenge(&self) -> HeaderValue {
        let v = match &self.scheme {
            Scheme::Basic => format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.realm),
            Scheme::ApiKey(h) => format!("ApiKey realm=\"{}\", header=\"{}\"", self.realm, h),
            _ => format!("Bearer realm=\"{}\"", self.realm),
        };
        HeaderValue::from_str(&v).unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
    }

    fn authenticate(&self, req: &request::Parts) -> Option<Principal> {
        let authz = || {
            req.headers
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
        };
        let bearer = || {
            authz().and_then(|a| {
                let (scheme, token) = a.split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then(|| token.trim())
            })
        };
        match &self.scheme {
            Scheme::Bearer => {
                bearer()
                    .and_then(|t| self.find(t.as_bytes()))
                    .map(|name| Principal {
                        name,
                        scheme: "bearer",
                    })
            }
            Scheme::Custom(validate) => {
                bearer()
                    .and_then(|t| validate(t, req))
                    .map(|name| Principal {
                        name: name.into(),
                        scheme: "custom",
                    })
            }
            Scheme::ApiKey(header) => req
                .headers
                .get(header)
                .and_then(|v| self.find(v.as_bytes()))
                .map(|name| Principal {
                    name,
                    scheme: "api_key",
                }),
            #[cfg(feature = "jwt")]
            Scheme::Jwt(_) => None,
            Scheme::Basic => {
                let encoded = authz().and_then(|a| {
                    let (scheme, rest) = a.split_once(' ')?;
                    scheme.eq_ignore_ascii_case("basic").then(|| rest.trim())
                })?;
                let decoded = b64std_decode(encoded)?;
                self.find(&decoded).map(|name| Principal {
                    name,
                    scheme: "basic",
                })
            }
        }
    }
}

#[cfg(feature = "jwt")]
impl Auth {
    fn authenticate_jwt(
        &self,
        validator: &crate::jwt::JwtValidator,
        req: &mut request::Parts,
    ) -> Result<(), Rejection> {
        let token = req
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| {
                let (scheme, token) = a.trim().split_once(' ')?;
                scheme
                    .eq_ignore_ascii_case("bearer")
                    .then(|| token.trim().to_owned())
            });
        let Some(token) = token else {
            return Err(Rejection::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required.",
            )
            .with_header(WWW_AUTHENTICATE, self.challenge()));
        };
        match validator.validate(&token) {
            Ok(claims) => {
                req.extensions.insert(Principal {
                    name: Arc::from(claims.subject()),
                    scheme: "jwt",
                });
                req.extensions
                    .insert(Roles::new(claims.roles().iter().cloned()));
                req.extensions.insert(claims);
                Ok(())
            }
            Err(e) => {
                let challenge = format!("Bearer realm=\"{}\", error=\"invalid_token\"", self.realm);
                Err(Rejection::new(
                    StatusCode::UNAUTHORIZED,
                    "invalid_token",
                    "Authentication required.",
                )
                .with_header(
                    WWW_AUTHENTICATE,
                    HeaderValue::from_str(&challenge)
                        .unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
                )
                .with_details(format!("jwt: {e}")))
            }
        }
    }
}

impl Guard for Auth {
    fn name(&self) -> &'static str {
        "auth"
    }

    fn priority(&self) -> u16 {
        priority::AUTH
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let path = req.uri.path();
        let protected = (self.protect.is_empty() || any_path_matches(path, &self.protect))
            && !any_path_matches(path, &self.public);
        if !protected || (self.allow_options && req.method == Method::OPTIONS) {
            return Ok(());
        }
        #[cfg(feature = "jwt")]
        if let Scheme::Jwt(validator) = &self.scheme {
            return self.authenticate_jwt(validator, req);
        }
        match self.authenticate(req) {
            Some(principal) => {
                if let Some((_, roles)) = self.grants.iter().find(|(l, _)| *l == principal.name) {
                    req.extensions.insert(roles.clone());
                }
                req.extensions.insert(principal);
                Ok(())
            }
            None => Err(Rejection::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Authentication required.",
            )
            .with_header(WWW_AUTHENTICATE, self.challenge())),
        }
    }
}

impl_layer!(Auth);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{b64std, hex_encode};
    use http::Request;

    fn run(
        auth: &Auth,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<Option<Principal>, Rejection> {
        let mut b = Request::builder().uri(path);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut p = b.body(()).unwrap().into_parts().0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        auth.on_request(&mut p, &mut ctx)
            .map(|()| p.extensions.get::<Principal>().cloned())
    }

    #[test]
    fn bearer() {
        let a = Auth::bearer().token("bot", "supersecret");
        assert!(run(&a, "/", &[]).is_err());
        assert!(run(&a, "/", &[("authorization", "Bearer nope-nope")]).is_err());
        let p = run(&a, "/", &[("authorization", "bearer supersecret")])
            .unwrap()
            .unwrap();
        assert_eq!(&*p.name, "bot");
    }

    #[test]
    fn hashed_token_and_paths() {
        let hex = hex_encode(&digest(b"another-secret"));
        let a = Auth::bearer()
            .token_sha256("ops", &hex)
            .protect(["/admin"])
            .public(["/admin/login"]);
        assert!(run(&a, "/", &[]).unwrap().is_none());
        assert!(run(&a, "/admin/login", &[]).is_ok());
        assert!(run(&a, "/admin", &[]).is_err());
        assert!(
            run(
                &a,
                "/admin/x",
                &[("authorization", "Bearer another-secret")]
            )
            .is_ok()
        );
    }

    #[test]
    fn api_key_and_basic() {
        let a = Auth::api_key("x-api-key").token("p", "k_live_123");
        assert!(run(&a, "/", &[("x-api-key", "k_live_123")]).is_ok());
        assert!(run(&a, "/", &[("x-api-key", "k_live_124")]).is_err());
        let b = Auth::basic("Admin").user("admin", "pa:ss word");
        let ok = format!("Basic {}", b64std(b"admin:pa:ss word"));
        assert!(run(&b, "/", &[("authorization", &ok)]).is_ok());
        let bad = format!("Basic {}", b64std(b"admin:nope"));
        let err = run(&b, "/", &[("authorization", &bad)]).unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert!(
            err.headers()[0]
                .1
                .to_str()
                .unwrap()
                .starts_with("Basic realm=\"Admin\"")
        );
    }

    #[test]
    fn grants_give_roles() {
        let a = Auth::bearer()
            .token("ci", "a-long-token")
            .token("bot", "another-token")
            .grant("ci", ["ROLE_DEPLOY"]);
        let mut p = Request::builder()
            .uri("/")
            .header("authorization", "Bearer a-long-token")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        a.on_request(&mut p, &mut ctx).unwrap();
        assert!(p.extensions.get::<Roles>().unwrap().contains("ROLE_DEPLOY"));
        let mut p = Request::builder()
            .uri("/")
            .header("authorization", "Bearer another-token")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        a.on_request(&mut p, &mut ctx).unwrap();
        assert!(p.extensions.get::<Roles>().is_none());
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn jwt_scheme() {
        use crate::jwt::tests::{SECRET, hs, now};
        use crate::jwt::{JwtClaims, JwtValidator};
        let a = Auth::jwt(JwtValidator::hmac(SECRET));
        let t = hs(&serde_json::json!({"sub": "u9", "exp": now() + 60, "roles": ["ROLE_X"]}));
        let mut p = Request::builder()
            .uri("/")
            .header("authorization", format!("Bearer {t}"))
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        a.on_request(&mut p, &mut ctx).unwrap();
        assert_eq!(&*p.extensions.get::<Principal>().unwrap().name, "u9");
        assert!(p.extensions.get::<Roles>().unwrap().contains("ROLE_X"));
        assert_eq!(p.extensions.get::<JwtClaims>().unwrap().subject(), "u9");
        let err = run(&a, "/", &[("authorization", "Bearer x.y.z")]).unwrap_err();
        assert_eq!(err.code(), "invalid_token");
        assert!(err.details().unwrap().contains("malformed"));
        assert!(
            err.headers()[0]
                .1
                .to_str()
                .unwrap()
                .contains("error=\"invalid_token\"")
        );
        assert_eq!(run(&a, "/", &[]).unwrap_err().code(), "unauthorized");
    }

    #[test]
    fn custom_validator() {
        let a = Auth::custom(|t, _| (t == "jwt-ok").then(|| "u1".to_string()));
        assert_eq!(
            &*run(&a, "/", &[("authorization", "Bearer jwt-ok")])
                .unwrap()
                .unwrap()
                .name,
            "u1"
        );
        assert!(run(&a, "/", &[("authorization", "Bearer jwt-bad")]).is_err());
    }
}
