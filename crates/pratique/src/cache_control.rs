//! `Cache-Control` by path and by content type.

use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Method, Middleware, Next, Request, Response};

use crate::util::{longest_match, normalize_prefix};

/// Sets `Cache-Control` on successful `GET` / `HEAD` responses that don't
/// have one: by path prefix first (longest wins), then by content type, then
/// the [`fallback`](CacheControl::fallback).
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(
///     CacheControl::new()
///         .fallback(CacheControl::NO_CACHE)
///         .route("/assets", CacheControl::IMMUTABLE)
///         .content_type("image/", "public, max-age=86400"),
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct CacheControl {
    default: Option<HeaderValue>,
    routes: Vec<(String, HeaderValue)>,
    types: Vec<(String, HeaderValue)>,
    overwrite: bool,
}

impl CacheControl {
    /// Fingerprinted files (`app.3f9a.js`): cached for a year, never revalidated.
    pub const IMMUTABLE: &'static str = "public, max-age=31536000, immutable";
    /// Cached, but revalidated on every use (pairs well with [`ETag`](crate::etag::ETag)).
    pub const NO_CACHE: &'static str = "no-cache";
    /// Never stored (personal or volatile data).
    pub const NO_STORE: &'static str = "no-store";

    /// No rule yet: responses are left alone.
    pub fn new() -> Self {
        Self::default()
    }

    /// Value used when no route or content type matches.
    ///
    /// # Panics
    /// If `value` is not a valid header value.
    pub fn fallback(mut self, value: &str) -> Self {
        self.default = Some(Self::value(value));
        self
    }

    /// Value for a path prefix (`/assets` covers `/assets/app.js`).
    ///
    /// # Panics
    /// If `value` is not a valid header value.
    pub fn route(mut self, prefix: impl Into<String>, value: &str) -> Self {
        self.routes
            .push((normalize_prefix(prefix), Self::value(value)));
        self
    }

    /// Value for a content type prefix (`image/`, `text/css`, `application/json` …).
    ///
    /// # Panics
    /// If `value` is not a valid header value.
    pub fn content_type(mut self, prefix: &str, value: &str) -> Self {
        self.types
            .push((prefix.to_ascii_lowercase(), Self::value(value)));
        self
    }

    /// Replace a `Cache-Control` set by the handler (default: keep it).
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    fn value(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).expect("invalid Cache-Control value")
    }

    /// The value for a response to `path` with this content type.
    fn pick(&self, path: &str, content_type: Option<&str>) -> Option<&HeaderValue> {
        longest_match(&self.routes, path)
            .or_else(|| {
                let ty = content_type?.trim().to_ascii_lowercase();
                self.types
                    .iter()
                    .find(|(prefix, _)| ty.starts_with(prefix.as_str()))
                    .map(|(_, v)| v)
            })
            .or(self.default.as_ref())
    }
}

impl Middleware for CacheControl {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if !matches!(*req.method(), Method::GET | Method::HEAD) {
            return next.run(req);
        }
        let path = req.path().to_owned();
        Box::pin(async move {
            let mut res = next.run(req).await;
            let status = res.status_code();
            if !(status.is_success() || status.is_redirection()) {
                return res;
            }
            if !self.overwrite && res.headers().contains_key(header::CACHE_CONTROL) {
                return res;
            }
            if let Some(value) = self.pick(&path, res.get_header("content-type")).cloned() {
                res.headers_mut().insert(header::CACHE_CONTROL, value);
            }
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_then_types_then_default() {
        let cc = CacheControl::new()
            .fallback("no-cache")
            .route("/assets", CacheControl::IMMUTABLE)
            .route("/assets/live", "no-store")
            .content_type("image/", "max-age=60");
        let pick = |path, ty| cc.pick(path, ty).map(|v| v.to_str().unwrap().to_owned());
        assert_eq!(
            pick("/assets/a.js", None).as_deref(),
            Some(CacheControl::IMMUTABLE)
        );
        assert_eq!(pick("/assets/live/x", None).as_deref(), Some("no-store"));
        assert_eq!(
            pick("/logo", Some("image/png")).as_deref(),
            Some("max-age=60")
        );
        assert_eq!(pick("/", Some("text/html")).as_deref(), Some("no-cache"));
        assert_eq!(CacheControl::new().pick("/", None), None);
    }
}
