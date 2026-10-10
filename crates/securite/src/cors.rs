//! Strict, allow-list based CORS.

use std::time::Duration;

use http::header::{self, HeaderName, HeaderValue};
use http::{Method, StatusCode, request, response};

use crate::guard::impl_layer;
use crate::{Context, Guard, Rejection, priority};

#[derive(Debug, Clone, PartialEq, Eq)]
enum OriginRule {
    Exact(String),
    /// `https://*.example.com` → prefix `https://`, suffix `.example.com`.
    Wildcard {
        prefix: String,
        suffix: String,
    },
}

impl OriginRule {
    fn parse(origin: &str) -> Self {
        let origin = origin.trim().trim_end_matches('/').to_ascii_lowercase();
        assert!(
            origin != "*",
            "use Cors::allow_any_origin() instead of \"*\""
        );
        match origin.split_once("*.") {
            Some((prefix, suffix)) => {
                assert!(
                    prefix.ends_with("://") && !suffix.contains('*') && suffix.contains('.'),
                    "invalid wildcard origin {origin:?}, expected e.g. https://*.example.com"
                );
                OriginRule::Wildcard {
                    prefix: prefix.to_owned(),
                    suffix: format!(".{suffix}"),
                }
            }
            None => {
                assert!(
                    origin == "null" || origin.contains("://"),
                    "invalid origin {origin:?}, expected scheme://host[:port]"
                );
                OriginRule::Exact(origin)
            }
        }
    }

    fn matches(&self, origin: &str) -> bool {
        match self {
            OriginRule::Exact(o) => o.eq_ignore_ascii_case(origin),
            OriginRule::Wildcard { prefix, suffix } => {
                let lower = origin.to_ascii_lowercase();
                let Some(rest) = lower.strip_prefix(prefix.as_str()) else {
                    return false;
                };
                let Some(sub) = rest.strip_suffix(suffix.as_str()) else {
                    return false;
                };
                !sub.is_empty()
                    && !sub.starts_with('.')
                    && sub
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            }
        }
    }
}

/// Cross-Origin Resource Sharing with secure defaults.
///
/// * Only listed origins are allowed (no reflection of arbitrary origins).
/// * `"null"` is never allowed unless explicitly listed.
/// * `allow_any_origin()` + `allow_credentials(true)` is refused at startup.
/// * Disallowed preflights get `403`, disallowed simple requests simply get
///   no CORS headers (the browser blocks them).
///
/// ```
/// use securite::prelude::*;
/// use std::time::Duration;
///
/// let cors = Cors::new()
///     .allow_origins(["https://app.example.com", "https://*.example.org"])
///     .allow_credentials(true)
///     .max_age(Duration::from_secs(3600));
/// ```
#[derive(Debug, Clone)]
pub struct Cors {
    origins: Vec<OriginRule>,
    any_origin: bool,
    methods: Vec<Method>,
    allow_headers: Vec<HeaderName>,
    expose_headers: Vec<HeaderName>,
    credentials: bool,
    max_age: Duration,
    private_network: bool,
    methods_value: HeaderValue,
    headers_value: Option<HeaderValue>,
    expose_value: Option<HeaderValue>,
}

impl Default for Cors {
    fn default() -> Self {
        Self::new()
    }
}

impl Cors {
    /// No origin allowed yet; common methods and headers pre-configured.
    pub fn new() -> Self {
        let mut s = Self {
            origins: Vec::new(),
            any_origin: false,
            methods: vec![
                Method::GET,
                Method::HEAD,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
            ],
            allow_headers: [
                "accept",
                "accept-language",
                "content-language",
                "content-type",
                "authorization",
                "x-requested-with",
                "x-csrf-token",
                "x-request-id",
            ]
            .iter()
            .map(|h| HeaderName::from_static(h))
            .collect(),
            expose_headers: Vec::new(),
            credentials: false,
            max_age: Duration::from_secs(600),
            private_network: false,
            methods_value: HeaderValue::from_static(""),
            headers_value: None,
            expose_value: None,
        };
        s.refresh();
        s
    }

    /// Allows one origin (`https://app.example.com`) or a wildcard
    /// sub-domain pattern (`https://*.example.com`).
    pub fn allow_origin(mut self, origin: &str) -> Self {
        self.origins.push(OriginRule::parse(origin));
        self
    }

    /// Allows several origins.
    pub fn allow_origins<I, S>(mut self, origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.origins
            .extend(origins.into_iter().map(|o| OriginRule::parse(o.as_ref())));
        self
    }

    /// Allows every origin (`Access-Control-Allow-Origin: *`). Only for
    /// public, unauthenticated APIs.
    pub fn allow_any_origin(mut self) -> Self {
        self.any_origin = true;
        self.check();
        self
    }

    /// Allowed methods.
    pub fn allow_methods(mut self, methods: impl IntoIterator<Item = Method>) -> Self {
        self.methods = methods.into_iter().collect();
        self.refresh();
        self
    }

    /// Allowed request headers.
    pub fn allow_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.allow_headers = headers
            .into_iter()
            .map(|h| HeaderName::from_bytes(h.as_ref().as_bytes()).expect("invalid header name"))
            .collect();
        self.refresh();
        self
    }

    /// Response headers readable by the browser.
    pub fn expose_headers<I, S>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.expose_headers = headers
            .into_iter()
            .map(|h| HeaderName::from_bytes(h.as_ref().as_bytes()).expect("invalid header name"))
            .collect();
        self.refresh();
        self
    }

    /// Allows cookies / `Authorization` on cross-origin requests.
    ///
    /// # Panics
    ///
    /// When combined with [`allow_any_origin`](Self::allow_any_origin).
    pub fn allow_credentials(mut self, allow: bool) -> Self {
        self.credentials = allow;
        self.check();
        self
    }

    /// How long browsers may cache a preflight (default 10 minutes).
    pub fn max_age(mut self, max_age: Duration) -> Self {
        self.max_age = max_age;
        self
    }

    /// Answers Private Network Access preflights
    /// (`Access-Control-Allow-Private-Network: true`).
    pub fn allow_private_network(mut self, allow: bool) -> Self {
        self.private_network = allow;
        self
    }

    fn check(&self) {
        assert!(
            !(self.any_origin && self.credentials),
            "insecure CORS: allow_any_origin() cannot be combined with allow_credentials(true)"
        );
    }

    fn refresh(&mut self) {
        let join = |items: Vec<&str>| items.join(", ");
        self.methods_value =
            HeaderValue::from_str(&join(self.methods.iter().map(Method::as_str).collect()))
                .expect("valid methods");
        self.headers_value = (!self.allow_headers.is_empty()).then(|| {
            HeaderValue::from_str(&join(
                self.allow_headers.iter().map(HeaderName::as_str).collect(),
            ))
            .expect("valid headers")
        });
        self.expose_value = (!self.expose_headers.is_empty()).then(|| {
            HeaderValue::from_str(&join(
                self.expose_headers.iter().map(HeaderName::as_str).collect(),
            ))
            .expect("valid headers")
        });
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        if self.any_origin {
            return origin != "null" || self.origins.iter().any(|o| o.matches("null"));
        }
        self.origins.iter().any(|rule| rule.matches(origin))
    }

    fn allow_origin_value(&self, origin: &HeaderValue) -> HeaderValue {
        if self.any_origin && !self.credentials {
            HeaderValue::from_static("*")
        } else {
            origin.clone()
        }
    }

    fn headers_allowed(&self, requested: &str) -> bool {
        requested
            .split(',')
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .all(|h| {
                self.allow_headers
                    .iter()
                    .any(|a| a.as_str().eq_ignore_ascii_case(h))
            })
    }
}

impl Guard for Cors {
    fn name(&self) -> &'static str {
        "cors"
    }

    fn priority(&self) -> u16 {
        priority::CORS
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let Some(origin) = req.headers.get(header::ORIGIN).cloned() else {
            return Ok(());
        };
        let origin_str = origin.to_str().unwrap_or("");
        let allowed = self.origin_allowed(origin_str);
        let preflight = req.method == Method::OPTIONS
            && req
                .headers
                .contains_key(header::ACCESS_CONTROL_REQUEST_METHOD);

        if !preflight {
            if allowed {
                ctx.cors_origin = Some(origin);
            }
            return Ok(());
        }

        let method_ok = req
            .headers
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|m| Method::from_bytes(m.as_bytes()).ok())
            .is_some_and(|m| self.methods.contains(&m));
        let headers_ok = req
            .headers
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .map(|h| self.headers_allowed(h.to_str().unwrap_or("\u{0}")))
            .unwrap_or(true);

        if !(allowed && method_ok && headers_ok) {
            let why = match (allowed, method_ok) {
                (false, _) => "origin not allowed",
                (_, false) => "method not allowed",
                _ => "header not allowed",
            };
            return Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "cors_rejected",
                "CORS preflight rejected.",
            )
            .with_details(format!("{why}: origin={origin_str}")));
        }

        let mut r = Rejection::respond(StatusCode::NO_CONTENT, "cors_preflight")
            .with_header(
                header::ACCESS_CONTROL_ALLOW_METHODS,
                self.methods_value.clone(),
            )
            .with_header(
                header::ACCESS_CONTROL_MAX_AGE,
                HeaderValue::from(self.max_age.as_secs()),
            );
        if let Some(h) = &self.headers_value {
            r = r.with_header(header::ACCESS_CONTROL_ALLOW_HEADERS, h.clone());
        }
        if self.private_network
            && req
                .headers
                .get("access-control-request-private-network")
                .is_some_and(|v| v == "true")
        {
            r = r.with_header(
                HeaderName::from_static("access-control-allow-private-network"),
                HeaderValue::from_static("true"),
            );
        }
        ctx.cors_origin = Some(origin);
        Err(r)
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        let has_vary = res.headers.get_all(header::VARY).iter().any(|v| {
            v.to_str().is_ok_and(|v| {
                v.split(',')
                    .any(|p| p.trim().eq_ignore_ascii_case("origin"))
            })
        });
        if !has_vary {
            res.headers
                .append(header::VARY, HeaderValue::from_static("origin"));
        }
        let Some(origin) = &ctx.cors_origin else {
            return;
        };
        res.headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            self.allow_origin_value(origin),
        );
        if self.credentials {
            res.headers.insert(
                header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        if let Some(expose) = &self.expose_value {
            res.headers
                .insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, expose.clone());
        }
    }
}

impl_layer!(Cors);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_matching() {
        let r = OriginRule::parse("https://*.example.com");
        assert!(r.matches("https://app.example.com"));
        assert!(r.matches("https://a.b.example.com"));
        assert!(!r.matches("https://example.com"));
        assert!(!r.matches("http://app.example.com"));
        assert!(!r.matches("https://evil.com/.example.com"));
        assert!(!r.matches("https://evilexample.com"));
        assert!(!r.matches("https://app.example.com.evil.com"));
    }

    #[test]
    fn exact_matching() {
        let r = OriginRule::parse("https://App.Example.com/");
        assert!(r.matches("https://app.example.com"));
        assert!(!r.matches("https://app.example.com.evil.com"));
    }

    #[test]
    #[should_panic(expected = "insecure CORS")]
    fn any_origin_with_credentials_panics() {
        let _ = Cors::new().allow_any_origin().allow_credentials(true);
    }

    #[test]
    fn null_origin_never_implicit() {
        let c = Cors::new().allow_any_origin();
        assert!(!c.origin_allowed("null"));
        assert!(c.origin_allowed("https://x.dev"));
    }
}
