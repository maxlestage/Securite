//! Allowed request media types.

use http::header::{CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use http::{Method, StatusCode, request};

use crate::guard::impl_layer;
use crate::util::{any_path_matches, normalize_prefix};
use crate::{Context, Guard, Rejection, priority};

/// Rejects request bodies whose `Content-Type` is not allowed
/// (`415 Unsupported Media Type`).
///
/// Blocks content-type confusion attacks (e.g. a `text/plain` "simple" CORS
/// request parsed as JSON, XML/XXE payloads sent to a JSON API).
///
/// ```
/// use securite::prelude::*;
///
/// let api = ContentTypeGuard::json();                 // application/json, application/*+json
/// let web = ContentTypeGuard::new()                   // json, form, multipart
///     .allow("application/xml")
///     .skip("/webhooks");
/// ```
#[derive(Debug, Clone)]
pub struct ContentTypeGuard {
    allowed: Vec<String>,
    skip: Vec<String>,
}

impl Default for ContentTypeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ContentTypeGuard {
    /// JSON, URL-encoded forms and multipart forms.
    pub fn new() -> Self {
        Self {
            allowed: vec![
                "application/json".into(),
                "application/*+json".into(),
                "application/x-www-form-urlencoded".into(),
                "multipart/form-data".into(),
            ],
            skip: Vec::new(),
        }
    }

    /// JSON only.
    pub fn json() -> Self {
        Self {
            allowed: vec!["application/json".into(), "application/*+json".into()],
            skip: Vec::new(),
        }
    }

    /// Allows another media type (`application/xml`, `text/*` …).
    pub fn allow(mut self, media_type: &str) -> Self {
        self.allowed.push(media_type.trim().to_ascii_lowercase());
        self
    }

    /// Path prefixes not checked.
    pub fn skip(mut self, prefix: impl Into<String>) -> Self {
        self.skip.push(normalize_prefix(prefix));
        self
    }

    /// Whether `content_type` (with parameters) is allowed.
    pub fn is_allowed(&self, content_type: &str) -> bool {
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let Some((ty, sub)) = essence.split_once('/') else {
            return false;
        };
        self.allowed.iter().any(|a| {
            let Some((aty, asub)) = a.split_once('/') else {
                return false;
            };
            (aty == "*" || aty == ty)
                && (asub == "*"
                    || asub == sub
                    || asub
                        .strip_prefix("*+")
                        .is_some_and(|suffix| sub.ends_with(&format!("+{suffix}"))))
        })
    }
}

impl Guard for ContentTypeGuard {
    fn name(&self) -> &'static str {
        "content_type"
    }

    fn priority(&self) -> u16 {
        priority::CONTENT_TYPE
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        if !matches!(
            req.method,
            Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            return Ok(());
        }
        let has_body = match req.headers.get(CONTENT_LENGTH) {
            Some(len) => len.to_str().map_or(true, |v| v.trim() != "0"),
            // HTTP/2 and HTTP/3 bodies need neither Content-Length nor
            // Transfer-Encoding: assume a body is present.
            None => {
                req.headers.contains_key(TRANSFER_ENCODING) || req.version >= http::Version::HTTP_2
            }
        };
        if !has_body || any_path_matches(req.uri.path(), &self.skip) {
            return Ok(());
        }
        match req.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()) {
            Some(ct) if self.is_allowed(ct) => Ok(()),
            other => Err(Rejection::new(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                "Unsupported Content-Type.",
            )
            .with_details(format!("content-type={:?}", other.unwrap_or("<none>")))),
        }
    }
}

impl_layer!(ContentTypeGuard);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_types() {
        let g = ContentTypeGuard::json();
        assert!(g.is_allowed("application/json"));
        assert!(g.is_allowed("Application/JSON; charset=utf-8"));
        assert!(g.is_allowed("application/problem+json"));
        assert!(!g.is_allowed("text/plain"));
        assert!(!g.is_allowed("application/xml"));
        assert!(!g.is_allowed("application/jsonx"));
        let g = ContentTypeGuard::new().allow("text/*");
        assert!(g.is_allowed("multipart/form-data; boundary=x"));
        assert!(g.is_allowed("text/csv"));
    }
}
