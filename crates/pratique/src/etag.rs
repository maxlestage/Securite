//! `ETag`s and `304 Not Modified` for every response.

use vitesse::http::header::{self, HeaderValue};
use vitesse::{Body, BoxFuture, Method, Middleware, Next, Request, Response, StatusCode};

use crate::util::fnv1a;

/// Gives `GET` / `HEAD` responses an `ETag` computed from their body, and
/// answers `304 Not Modified` (no body) when the browser already has it
/// (`If-None-Match`).
///
/// Only bodies of known size are hashed (JSON, HTML, text …, and streams
/// that announce their exact length): other streams and bodies above
/// [`max_size`](ETag::max_size) pass through untouched, and so does a response that already has an `ETag` (static
/// files), which still gets its `304`.
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(ETag::new());
/// ```
#[derive(Debug, Clone)]
pub struct ETag {
    max_size: u64,
    weak: bool,
}

impl Default for ETag {
    fn default() -> Self {
        Self::new()
    }
}

impl ETag {
    /// Strong `ETag`s for bodies up to 4 MiB.
    pub fn new() -> Self {
        Self {
            max_size: 4 * 1024 * 1024,
            weak: false,
        }
    }

    /// Largest body hashed, in bytes.
    pub fn max_size(mut self, bytes: u64) -> Self {
        self.max_size = bytes;
        self
    }

    /// Weak `ETag`s (`W/"…"`): use them when a later middleware (e.g.
    /// compression) may change the bytes but not the meaning.
    pub fn weak(mut self, weak: bool) -> Self {
        self.weak = weak;
        self
    }

    fn tag(&self, body: &[u8]) -> String {
        let prefix = if self.weak { "W/" } else { "" };
        format!("{prefix}\"{:x}-{:016x}\"", body.len(), fnv1a(body))
    }
}

/// `If-None-Match` lists `etag` (weak comparison, RFC 9110 §13.1.2).
pub(crate) fn none_match(if_none_match: &str, etag: &str) -> bool {
    let etag = etag.trim_start_matches("W/");
    if_none_match
        .split(',')
        .map(str::trim)
        .any(|t| t == "*" || t.trim_start_matches("W/") == etag)
}

impl Middleware for ETag {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if !matches!(*req.method(), Method::GET | Method::HEAD) {
            return next.run(req);
        }
        // Every `If-None-Match` line: a list may be split over several.
        let if_none_match: Vec<&str> = req.header_all("if-none-match").collect();
        let if_none_match = (!if_none_match.is_empty()).then(|| if_none_match.join(","));
        Box::pin(async move {
            let mut res = next.run(req).await;
            if res.status_code() != StatusCode::OK {
                return res;
            }
            let etag = match res.get_header("etag") {
                Some(etag) => etag.to_owned(),
                None => {
                    if !res.body().size().is_some_and(|n| n <= self.max_size) {
                        return res;
                    }
                    let Ok(bytes) = std::mem::take(res.body_mut()).to_bytes().await else {
                        res.set_status(StatusCode::INTERNAL_SERVER_ERROR);
                        return res;
                    };
                    let etag = self.tag(&bytes);
                    *res.body_mut() = Body::from(bytes);
                    if let Ok(value) = HeaderValue::from_str(&etag) {
                        res.headers_mut().insert(header::ETAG, value);
                    }
                    etag
                }
            };
            if if_none_match.is_some_and(|inm| none_match(&inm, &etag)) {
                res.set_status(StatusCode::NOT_MODIFIED);
                *res.body_mut() = Body::empty();
                res.headers_mut().remove(header::CONTENT_LENGTH);
            }
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_is_weak() {
        assert!(none_match("\"a\"", "\"a\""));
        assert!(none_match("W/\"a\"", "\"a\""));
        assert!(none_match("\"b\", W/\"a\"", "W/\"a\""));
        assert!(none_match("*", "\"a\""));
        assert!(!none_match("\"b\"", "\"a\""));
    }

    #[test]
    fn tags_depend_on_the_body() {
        let etag = ETag::new();
        assert_eq!(etag.tag(b"hello"), etag.tag(b"hello"));
        assert_ne!(etag.tag(b"hello"), etag.tag(b"world"));
        assert!(ETag::new().weak(true).tag(b"x").starts_with("W/\""));
    }
}
