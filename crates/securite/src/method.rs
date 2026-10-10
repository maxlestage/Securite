//! HTTP method allow-list.

use http::header::{ALLOW, HeaderValue};
use http::{Method, StatusCode, request};

use crate::guard::impl_layer;
use crate::{Context, Guard, Rejection, priority};

const OVERRIDE_HEADERS: [&str; 3] = [
    "x-http-method-override",
    "x-http-method",
    "x-method-override",
];

/// Only lets allowed methods through (`405 Method Not Allowed` + `Allow`).
///
/// Defaults: `GET HEAD POST PUT PATCH DELETE OPTIONS`. `TRACE`, `TRACK`,
/// `CONNECT` and exotic WebDAV methods are refused (Cross-Site Tracing,
/// proxy abuse). Method-override headers (`X-HTTP-Method-Override` …), which
/// can bypass method based access rules, are rejected too.
#[derive(Debug, Clone)]
pub struct MethodFilter {
    allowed: Vec<Method>,
    allow_value: HeaderValue,
    block_override: bool,
}

impl Default for MethodFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl MethodFilter {
    /// Default allow-list.
    pub fn new() -> Self {
        Self::only([
            Method::GET,
            Method::HEAD,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
    }

    /// Exactly these methods.
    ///
    /// # Panics
    ///
    /// If `methods` is empty.
    pub fn only(methods: impl IntoIterator<Item = Method>) -> Self {
        let allowed: Vec<Method> = methods.into_iter().collect();
        assert!(
            !allowed.is_empty(),
            "MethodFilter needs at least one method"
        );
        let allow_value = HeaderValue::from_str(
            &allowed
                .iter()
                .map(Method::as_str)
                .collect::<Vec<_>>()
                .join(", "),
        )
        .expect("valid methods");
        Self {
            allowed,
            allow_value,
            block_override: true,
        }
    }

    /// Read-only site: `GET HEAD OPTIONS`.
    pub fn read_only() -> Self {
        Self::only([Method::GET, Method::HEAD, Method::OPTIONS])
    }

    /// Accept method-override headers (legacy clients).
    pub fn allow_method_override(mut self) -> Self {
        self.block_override = false;
        self
    }
}

impl Guard for MethodFilter {
    fn name(&self) -> &'static str {
        "method"
    }

    fn priority(&self) -> u16 {
        priority::METHOD
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        if !self.allowed.contains(&req.method) {
            return Err(Rejection::new(
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "Method not allowed.",
            )
            .with_header(ALLOW, self.allow_value.clone())
            .with_details(format!("method={}", req.method)));
        }
        if self.block_override
            && OVERRIDE_HEADERS
                .iter()
                .any(|h| req.headers.contains_key(*h))
        {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "method_override",
                "Method override headers are not allowed.",
            ));
        }
        Ok(())
    }
}

impl_layer!(MethodFilter);
