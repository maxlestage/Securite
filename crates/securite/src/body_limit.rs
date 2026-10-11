//! Request body size limits.
//!
//! [`BodyLimit`] (a [`Guard`]) rejects requests whose `Content-Length` is
//! too large *before* your handler runs. In tower services, [`BodyLimitLayer`]
//! additionally enforces the limit while streaming (chunked bodies without
//! `Content-Length`); Vitesse has its own streaming limit, `app.body_limit`.

use std::task::{Context as TaskContext, Poll};

use http::header::{CONTENT_LENGTH, TRANSFER_ENCODING};
use http::{Method, Request, StatusCode, request};
use http_body_util::Limited;
use tower_layer::Layer;
use tower_service::Service;

use crate::guard::impl_layer;
use crate::util::{normalize_prefix, path_matches};
use crate::{Context, Guard, Rejection, priority};

/// Rejects oversized bodies with `413 Payload Too Large`, based on
/// `Content-Length`.
///
/// ```
/// use securite::prelude::*;
///
/// let limit = BodyLimit::new(1024 * 1024)            // 1 MiB everywhere…
///     .route("/upload", 50 * 1024 * 1024)          // 50 MiB for uploads
///     .require_content_length(true);               // 411 for chunked bodies
/// ```
#[derive(Debug, Clone)]
pub struct BodyLimit {
    default: u64,
    routes: Vec<(String, u64)>,
    require_length: bool,
}

impl BodyLimit {
    /// Maximum body size in bytes.
    pub fn new(max_bytes: u64) -> Self {
        Self {
            default: max_bytes,
            routes: Vec::new(),
            require_length: false,
        }
    }

    /// Different limit for a path prefix (longest prefix wins).
    pub fn route(mut self, prefix: impl Into<String>, max_bytes: u64) -> Self {
        self.routes.push((normalize_prefix(prefix), max_bytes));
        self.routes.sort_by_key(|(p, _)| std::cmp::Reverse(p.len()));
        self
    }

    /// Reject bodies without `Content-Length` (`411 Length Required`) for
    /// `POST`, `PUT` and `PATCH`.
    pub fn require_content_length(mut self, require: bool) -> Self {
        self.require_length = require;
        self
    }

    /// Limit applying to `path`.
    pub fn limit_for(&self, path: &str) -> u64 {
        self.routes
            .iter()
            .find(|(p, _)| path_matches(path, p))
            .map_or(self.default, |(_, l)| *l)
    }
}

impl Guard for BodyLimit {
    fn name(&self) -> &'static str {
        "body_limit"
    }

    fn priority(&self) -> u16 {
        priority::BODY_LIMIT
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let limit = self.limit_for(req.uri.path());
        match req.headers.get(CONTENT_LENGTH) {
            Some(len) => {
                let len = len
                    .to_str()
                    .ok()
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .ok_or_else(|| {
                        Rejection::new(
                            StatusCode::BAD_REQUEST,
                            "bad_content_length",
                            "Invalid Content-Length.",
                        )
                    })?;
                if len > limit {
                    return Err(Rejection::new(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "body_too_large",
                        format!("Request body too large (max {limit} bytes)."),
                    ));
                }
            }
            None => {
                let has_body = req.headers.contains_key(TRANSFER_ENCODING);
                let writes = matches!(req.method, Method::POST | Method::PUT | Method::PATCH);
                if self.require_length && has_body && writes {
                    return Err(Rejection::new(
                        StatusCode::LENGTH_REQUIRED,
                        "length_required",
                        "Content-Length required.",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl_layer!(BodyLimit);

/// Streaming body limit: wraps the request body in
/// [`http_body_util::Limited`]. Reading more than `max_bytes` fails with
/// `LengthLimitError`. With Vitesse, use `app.body_limit(bytes)` instead
/// (1 MiB by default).
#[derive(Debug, Clone, Copy)]
pub struct BodyLimitLayer {
    max: usize,
}

impl BodyLimitLayer {
    /// Maximum body size in bytes.
    pub fn new(max_bytes: usize) -> Self {
        Self { max: max_bytes }
    }
}

impl<S> Layer<S> for BodyLimitLayer {
    type Service = BodyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        BodyLimitService {
            inner,
            max: self.max,
        }
    }
}

/// Service produced by [`BodyLimitLayer`].
#[derive(Debug, Clone)]
pub struct BodyLimitService<S> {
    inner: S,
    max: usize,
}

impl<S, B> Service<Request<B>> for BodyLimitService<S>
where
    S: Service<Request<Limited<B>>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let (parts, body) = req.into_parts();
        self.inner
            .call(Request::from_parts(parts, Limited::new(body, self.max)))
    }
}
