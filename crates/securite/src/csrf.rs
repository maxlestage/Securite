//! Cross-Site Request Forgery protection.
//!
//! Two complementary defences:
//!
//! 1. **Fetch Metadata / Origin verification** (default, stateless, zero
//!    config). Modern browsers send `Sec-Fetch-Site` with every request; a
//!    state-changing request coming from another site is rejected. Older
//!    browsers are handled by comparing `Origin` with `Host`. This is the
//!    same algorithm as Go 1.25's `http.CrossOriginProtection`.
//! 2. **Signed double-submit token** (optional, [`Csrf::with_token`]): an
//!    HMAC-signed random token stored in a `__Host-` cookie must be echoed in
//!    the `X-CSRF-Token` header.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use http::header::{self, HeaderName, HeaderValue};
use http::{Method, StatusCode, request};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::guard::impl_layer;
use crate::util::{
    any_path_matches, b64url, b64url_decode, cookie_pairs, normalize_prefix, secure_random,
};
use crate::{Context, Guard, Mode, Rejection, priority};

/// The CSRF token for the current request (token mode only).
///
/// Render it in your pages (`<meta name="csrf-token" content="…">`) and send
/// it back in the `X-CSRF-Token` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfToken(pub String);

#[derive(Clone)]
struct TokenConfig {
    key: Arc<[u8]>,
    cookie_name: String,
    header: HeaderName,
    secure: bool,
}

/// CSRF protection. See the [module docs](self).
///
/// ```
/// use securite::prelude::*;
///
/// // Stateless Fetch-Metadata protection (recommended default):
/// let csrf = Csrf::new()
///     .trusted_origin("https://admin.example.com")
///     .exempt("/webhooks");
///
/// // + signed double-submit token:
/// let csrf = Csrf::new().with_token(b"a 32+ bytes long secret key ......");
/// ```
#[derive(Clone)]
pub struct Csrf {
    trusted_origins: Vec<String>,
    exempt: Vec<String>,
    allow_same_site: bool,
    token: Option<TokenConfig>,
    cookie_name: String,
    header: HeaderName,
    secure: bool,
    mode: Mode,
}

impl std::fmt::Debug for Csrf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Csrf")
            .field("trusted_origins", &self.trusted_origins)
            .field("exempt", &self.exempt)
            .field("allow_same_site", &self.allow_same_site)
            .field("token", &self.token.is_some())
            .field("mode", &self.mode)
            .finish()
    }
}

impl Default for Csrf {
    fn default() -> Self {
        Self::new()
    }
}

impl Csrf {
    /// Fetch-Metadata / Origin based protection.
    pub fn new() -> Self {
        Self {
            trusted_origins: Vec::new(),
            exempt: Vec::new(),
            allow_same_site: false,
            token: None,
            cookie_name: "__Host-csrf".into(),
            header: HeaderName::from_static("x-csrf-token"),
            secure: true,
            mode: Mode::Enforce,
        }
    }

    /// Allows state-changing requests from another origin
    /// (`https://admin.example.com`).
    pub fn trusted_origin(mut self, origin: &str) -> Self {
        self.trusted_origins
            .push(origin.trim().trim_end_matches('/').to_ascii_lowercase());
        self
    }

    /// Path prefixes that skip CSRF checks (webhooks, token-authenticated
    /// APIs …).
    pub fn exempt(mut self, prefix: impl Into<String>) -> Self {
        self.exempt.push(normalize_prefix(prefix));
        self
    }

    /// Accept `Sec-Fetch-Site: same-site` (sub-domains of the same site).
    /// Off by default: a compromised sub-domain could forge requests.
    pub fn allow_same_site(mut self, allow: bool) -> Self {
        self.allow_same_site = allow;
        self
    }

    /// Enables the signed double-submit token.
    ///
    /// # Panics
    ///
    /// If `secret` is shorter than 32 bytes.
    pub fn with_token(mut self, secret: impl AsRef<[u8]>) -> Self {
        let secret = secret.as_ref();
        assert!(secret.len() >= 32, "CSRF secret must be at least 32 bytes");
        self.token = Some(TokenConfig {
            key: Arc::from(secret),
            cookie_name: self.cookie_name.clone(),
            header: self.header.clone(),
            secure: self.secure,
        });
        self
    }

    /// Cookie name (default `__Host-csrf`). Token mode only.
    pub fn cookie_name(mut self, name: &str) -> Self {
        self.cookie_name = name.to_owned();
        if let Some(t) = &mut self.token {
            t.cookie_name = name.to_owned();
        }
        self
    }

    /// Header carrying the token (default `x-csrf-token`). Token mode only.
    pub fn header_name(mut self, name: &str) -> Self {
        self.header = HeaderName::from_bytes(name.as_bytes()).expect("invalid header name");
        if let Some(t) = &mut self.token {
            t.header = self.header.clone();
        }
        self
    }

    /// Drop the `Secure` cookie flag — **only** for plain-HTTP local
    /// development. Also switches the default cookie name to `csrf`.
    pub fn insecure_dev_cookie(mut self) -> Self {
        self.secure = false;
        if self.cookie_name.starts_with("__Host-") {
            self.cookie_name = "csrf".into();
        }
        if let Some(t) = &mut self.token {
            t.secure = false;
            if t.cookie_name.starts_with("__Host-") {
                t.cookie_name = "csrf".into();
            }
        }
        self
    }

    /// Monitor-only mode.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    fn is_safe(method: &Method) -> bool {
        matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
    }

    fn trusted(&self, origin: Option<&str>) -> bool {
        origin.is_some_and(|o| {
            let o = o.to_ascii_lowercase();
            self.trusted_origins.contains(&o)
        })
    }

    fn check_origin(&self, req: &request::Parts) -> Result<(), &'static str> {
        let origin = req
            .headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok());
        if let Some(site) = req.headers.get("sec-fetch-site") {
            return match site.as_bytes() {
                b"same-origin" | b"none" => Ok(()),
                b"same-site" if self.allow_same_site => Ok(()),
                _ if self.trusted(origin) => Ok(()),
                _ => Err("cross-site request (Sec-Fetch-Site)"),
            };
        }
        let Some(origin) = origin else {
            // Neither header: same-origin request from an old browser or a
            // non-browser client (curl, server-to-server) — not CSRF.
            return Ok(());
        };
        if self.trusted(Some(origin)) {
            return Ok(());
        }
        let host = req
            .headers
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .or_else(|| req.uri.authority().map(|a| a.as_str()));
        let origin_host = origin.split_once("://").map(|(_, h)| h);
        match (origin_host, host) {
            (Some(o), Some(h)) if o.eq_ignore_ascii_case(h) => Ok(()),
            _ => Err("Origin does not match Host"),
        }
    }

    fn sign(key: &[u8], nonce: &[u8]) -> Vec<u8> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("hmac accepts any key");
        mac.update(b"securite-csrf-v1");
        mac.update(nonce);
        mac.finalize().into_bytes().to_vec()
    }

    fn new_token(key: &[u8]) -> String {
        let mut nonce = [0u8; 24];
        secure_random(&mut nonce);
        format!("{}.{}", b64url(&nonce), b64url(&Self::sign(key, &nonce)))
    }

    fn token_valid(key: &[u8], token: &str) -> bool {
        let Some((n, s)) = token.split_once('.') else {
            return false;
        };
        match (b64url_decode(n), b64url_decode(s)) {
            (Some(nonce), Some(sig)) if nonce.len() == 24 => {
                bool::from(Self::sign(key, &nonce).ct_eq(&sig))
            }
            _ => false,
        }
    }
}

impl Guard for Csrf {
    fn name(&self) -> &'static str {
        "csrf"
    }

    fn priority(&self) -> u16 {
        priority::CSRF
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let exempt = any_path_matches(req.uri.path(), &self.exempt);

        // Token mode: make sure every client holds a valid token.
        let mut cookie_token: Option<String> = None;
        if let Some(cfg) = &self.token {
            cookie_token = req
                .headers
                .get_all(header::COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(cookie_pairs)
                .find(|(name, _)| *name == cfg.cookie_name)
                .map(|(_, v)| v.to_owned())
                .filter(|t| Self::token_valid(&cfg.key, t));
            let token = match &cookie_token {
                Some(t) => t.clone(),
                None => {
                    let t = Self::new_token(&cfg.key);
                    let cookie = format!(
                        "{}={}; Path=/; HttpOnly; SameSite=Strict{}",
                        cfg.cookie_name,
                        t,
                        if cfg.secure { "; Secure" } else { "" }
                    );
                    if let Ok(v) = HeaderValue::from_str(&cookie) {
                        ctx.add_set_cookie(v);
                    }
                    t
                }
            };
            req.extensions.insert(CsrfToken(token));
        }

        if exempt || Self::is_safe(&req.method) {
            return Ok(());
        }

        if let Err(why) = self.check_origin(req) {
            return Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "csrf_rejected",
                "Cross-site request rejected.",
            )
            .with_details(why));
        }

        if let Some(cfg) = &self.token {
            let sent = req.headers.get(&cfg.header).map(HeaderValue::as_bytes);
            let ok = match (sent, &cookie_token) {
                (Some(sent), Some(cookie)) => bool::from(sent.ct_eq(cookie.as_bytes())),
                _ => false,
            };
            if !ok {
                return Err(Rejection::new(
                    StatusCode::FORBIDDEN,
                    "csrf_token_invalid",
                    "Missing or invalid CSRF token.",
                ));
            }
        }
        Ok(())
    }
}

impl_layer!(Csrf);

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn req(method: &str, headers: &[(&str, &str)]) -> request::Parts {
        let mut b = Request::builder().method(method).uri("/submit");
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(()).unwrap().into_parts().0
    }

    fn check(csrf: &Csrf, mut parts: request::Parts) -> Result<(), Rejection> {
        let mut ctx = Context::new(parts.method.clone(), parts.uri.clone(), None);
        csrf.on_request(&mut parts, &mut ctx)
    }

    #[test]
    fn fetch_metadata() {
        let c = Csrf::new();
        assert!(check(&c, req("POST", &[("sec-fetch-site", "same-origin")])).is_ok());
        assert!(check(&c, req("POST", &[("sec-fetch-site", "none")])).is_ok());
        assert!(check(&c, req("POST", &[("sec-fetch-site", "cross-site")])).is_err());
        assert!(check(&c, req("POST", &[("sec-fetch-site", "same-site")])).is_err());
        assert!(check(&c, req("GET", &[("sec-fetch-site", "cross-site")])).is_ok());
        let c = Csrf::new().allow_same_site(true);
        assert!(check(&c, req("POST", &[("sec-fetch-site", "same-site")])).is_ok());
    }

    #[test]
    fn origin_fallback() {
        let c = Csrf::new();
        assert!(check(&c, req("POST", &[])).is_ok(), "non-browser client");
        assert!(
            check(
                &c,
                req("POST", &[("origin", "https://a.com"), ("host", "a.com")])
            )
            .is_ok()
        );
        assert!(
            check(
                &c,
                req("POST", &[("origin", "https://evil.com"), ("host", "a.com")])
            )
            .is_err()
        );
        let c = Csrf::new().trusted_origin("https://evil.com");
        assert!(
            check(
                &c,
                req("POST", &[("origin", "https://evil.com"), ("host", "a.com")])
            )
            .is_ok()
        );
        assert!(
            check(
                &c,
                req(
                    "POST",
                    &[
                        ("sec-fetch-site", "cross-site"),
                        ("origin", "https://evil.com")
                    ]
                )
            )
            .is_ok()
        );
    }

    #[test]
    fn tokens() {
        let key = [7u8; 32];
        let t = Csrf::new_token(&key);
        assert!(Csrf::token_valid(&key, &t));
        assert!(!Csrf::token_valid(&[8u8; 32], &t));
        assert!(!Csrf::token_valid(&key, "garbage"));
        let c = Csrf::new().with_token(key);
        let cookie = format!("__Host-csrf={t}");
        assert!(
            check(&c, req("POST", &[("cookie", &cookie)])).is_err(),
            "header missing"
        );
        assert!(
            check(
                &c,
                req("POST", &[("cookie", &cookie), ("x-csrf-token", &t)])
            )
            .is_ok()
        );
        let other = Csrf::new_token(&key);
        assert!(
            check(
                &c,
                req("POST", &[("cookie", &cookie), ("x-csrf-token", &other)])
            )
            .is_err()
        );
    }
}
