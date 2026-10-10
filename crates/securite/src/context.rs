use std::any::Any;
use std::fmt;
use std::net::IpAddr;
use std::time::Instant;

use http::{HeaderValue, Method, Uri};

/// Per-request state shared by all guards of a [`Shield`](crate::Shield).
///
/// It is created before the first guard runs and lives until the response
/// head has been produced.
pub struct Context {
    pub(crate) client_ip: Option<IpAddr>,
    pub(crate) method: Method,
    pub(crate) uri: Uri,
    pub(crate) started: Instant,
    pub(crate) request_id: Option<HeaderValue>,
    pub(crate) rejected_by: Option<&'static str>,
    pub(crate) blocked: bool,
    pub(crate) rate_limit: Option<crate::rate_limit::RateLimitSnapshot>,
    pub(crate) cors_origin: Option<HeaderValue>,
    pub(crate) csp_nonce: Option<String>,
    pub(crate) set_cookies: Vec<HeaderValue>,
    pub(crate) holds: Vec<Box<dyn Any + Send + Sync>>,
    extensions: http::Extensions,
}

impl Context {
    /// Creates a context (useful to unit-test custom guards).
    pub fn new(method: Method, uri: Uri, client_ip: Option<IpAddr>) -> Self {
        Self {
            client_ip,
            method,
            uri,
            started: Instant::now(),
            request_id: None,
            rejected_by: None,
            blocked: false,
            rate_limit: None,
            cors_origin: None,
            csp_nonce: None,
            set_cookies: Vec::new(),
            holds: Vec::new(),
            extensions: http::Extensions::new(),
        }
    }

    /// The resolved client IP address, if known.
    pub fn client_ip(&self) -> Option<IpAddr> {
        self.client_ip
    }

    /// The request method.
    pub fn method(&self) -> &Method {
        &self.method
    }

    /// The request URI.
    pub fn uri(&self) -> &Uri {
        &self.uri
    }

    /// The request path.
    pub fn path(&self) -> &str {
        self.uri.path()
    }

    /// The request id (when a [`RequestId`](crate::request_id::RequestId) guard runs).
    pub fn request_id(&self) -> Option<&str> {
        self.request_id.as_ref().and_then(|v| v.to_str().ok())
    }

    /// Name of the guard that rejected the request, if any.
    pub fn rejected_by(&self) -> Option<&'static str> {
        self.rejected_by
    }

    /// Whether a guard blocked the request (benign short-circuits such as
    /// CORS preflights or HTTPS redirects do not count).
    pub fn blocked(&self) -> bool {
        self.blocked
    }

    /// When the shield started processing the request.
    pub fn started(&self) -> Instant {
        self.started
    }

    /// The per-request CSP nonce, when nonces are enabled.
    pub fn csp_nonce(&self) -> Option<&str> {
        self.csp_nonce.as_deref()
    }

    /// Adds a `Set-Cookie` header to the final response.
    pub fn add_set_cookie(&mut self, value: HeaderValue) {
        self.set_cookies.push(value);
    }

    /// Keeps `value` alive until the response head is produced (RAII permits,
    /// timers …). Dropped when the request completes or is cancelled.
    pub fn hold<T: Any + Send + Sync>(&mut self, value: T) {
        self.holds.push(Box::new(value));
    }

    /// Free-form typed storage for custom guards.
    pub fn extensions(&self) -> &http::Extensions {
        &self.extensions
    }

    /// Mutable free-form typed storage for custom guards.
    pub fn extensions_mut(&mut self) -> &mut http::Extensions {
        &mut self.extensions
    }
}

impl fmt::Debug for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("client_ip", &self.client_ip)
            .field("method", &self.method)
            .field("uri", &self.uri)
            .field("request_id", &self.request_id)
            .field("rejected_by", &self.rejected_by)
            .finish_non_exhaustive()
    }
}
