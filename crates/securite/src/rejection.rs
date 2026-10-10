use std::borrow::Cow;
use std::fmt;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, Response, StatusCode};

use crate::Context;
use crate::util::json_escape;

/// Why a request was stopped by a [`Guard`](crate::Guard).
///
/// The `message` is sent to the client; `details` are only written to the
/// audit log / events (never leaked to the client).
#[derive(Clone)]
pub struct Rejection {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: Cow<'static, str>,
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) details: Option<String>,
    pub(crate) benign: bool,
}

impl Rejection {
    /// Creates a blocking rejection.
    ///
    /// `code` is a short machine readable identifier such as `rate_limited`.
    pub fn new(
        status: StatusCode,
        code: &'static str,
        message: impl Into<Cow<'static, str>>,
    ) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            headers: Vec::new(),
            details: None,
            benign: false,
        }
    }

    /// A short-circuit answer that is *not* an attack (CORS preflight,
    /// HTTPS redirect …). It is not logged, not counted as blocked and has an
    /// empty body.
    pub fn respond(status: StatusCode, code: &'static str) -> Self {
        Self {
            benign: true,
            ..Self::new(status, code, "")
        }
    }

    /// Adds a response header (e.g. `Retry-After`, `WWW-Authenticate`).
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.push((name, value));
        self
    }

    /// Attaches audit-only details (rule ids, matched values …).
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// HTTP status code.
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Machine readable code.
    pub fn code(&self) -> &'static str {
        self.code
    }

    /// Human readable message sent to the client.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Audit-only details.
    pub fn details(&self) -> Option<&str> {
        self.details.as_deref()
    }

    /// Whether this is a benign short-circuit (not an attack).
    pub fn is_benign(&self) -> bool {
        self.benign
    }

    /// Extra response headers.
    pub fn headers(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }
}

impl fmt::Debug for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rejection")
            .field("status", &self.status)
            .field("code", &self.code)
            .field("message", &self.message)
            .field("details", &self.details)
            .field("benign", &self.benign)
            .finish()
    }
}

type CustomResponder = dyn Fn(&Rejection, &Context) -> Response<Bytes> + Send + Sync;

/// How rejections are rendered.
#[derive(Clone, Default)]
pub enum ErrorFormat {
    /// RFC 9457 `application/problem+json` (default).
    #[default]
    ProblemJson,
    /// `text/plain; charset=utf-8`.
    PlainText,
    /// Status code only, empty body.
    Empty,
    /// Your own renderer.
    Custom(Arc<CustomResponder>),
}

impl ErrorFormat {
    /// Builds an [`ErrorFormat::Custom`] from a closure.
    pub fn custom<F>(f: F) -> Self
    where
        F: Fn(&Rejection, &Context) -> Response<Bytes> + Send + Sync + 'static,
    {
        Self::Custom(Arc::new(f))
    }

    pub(crate) fn render(
        &self,
        rejection: &Rejection,
        ctx: &Context,
    ) -> (http::response::Parts, Bytes) {
        let (mut parts, body) = if rejection.benign {
            let (parts, ()) = Response::new(()).into_parts();
            (parts, Bytes::new())
        } else {
            match self {
                ErrorFormat::Custom(f) => f(rejection, ctx).into_parts(),
                other => {
                    let (mut parts, ()) = Response::new(()).into_parts();
                    let (ct, body) = other.body(rejection, ctx);
                    if let Some(ct) = ct {
                        parts
                            .headers
                            .insert(CONTENT_TYPE, HeaderValue::from_static(ct));
                    }
                    (parts, body)
                }
            }
        };
        parts.status = rejection.status;
        if !rejection.benign {
            parts
                .headers
                .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        append_all(&mut parts.headers, &rejection.headers);
        (parts, body)
    }

    fn body(&self, r: &Rejection, ctx: &Context) -> (Option<&'static str>, Bytes) {
        match self {
            ErrorFormat::ProblemJson => {
                let mut s = String::with_capacity(160);
                s.push_str("{\"type\":\"about:blank\",\"title\":\"");
                json_escape(r.status.canonical_reason().unwrap_or("Error"), &mut s);
                s.push_str("\",\"status\":");
                s.push_str(r.status.as_str());
                s.push_str(",\"code\":\"");
                json_escape(r.code, &mut s);
                s.push_str("\",\"detail\":\"");
                json_escape(&r.message, &mut s);
                s.push('"');
                if let Some(id) = ctx.request_id() {
                    s.push_str(",\"request_id\":\"");
                    json_escape(id, &mut s);
                    s.push('"');
                }
                s.push('}');
                (Some("application/problem+json"), Bytes::from(s))
            }
            ErrorFormat::PlainText => {
                let mut s = String::with_capacity(64);
                s.push_str(r.status.as_str());
                s.push(' ');
                s.push_str(r.status.canonical_reason().unwrap_or("Error"));
                if !r.message.is_empty() {
                    s.push_str(": ");
                    s.push_str(&r.message);
                }
                s.push('\n');
                (Some("text/plain; charset=utf-8"), Bytes::from(s))
            }
            ErrorFormat::Empty | ErrorFormat::Custom(_) => (None, Bytes::new()),
        }
    }
}

impl fmt::Debug for ErrorFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProblemJson => f.write_str("ProblemJson"),
            Self::PlainText => f.write_str("PlainText"),
            Self::Empty => f.write_str("Empty"),
            Self::Custom(_) => f.write_str("Custom(..)"),
        }
    }
}

fn append_all(map: &mut HeaderMap, headers: &[(HeaderName, HeaderValue)]) {
    for (name, value) in headers {
        map.append(name.clone(), value.clone());
    }
}
