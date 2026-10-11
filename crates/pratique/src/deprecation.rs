//! Announce that an API is deprecated, and when it goes away.

use std::time::SystemTime;

use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response};

use crate::util::{http_date, normalize_prefix, path_matches, unix_secs};

/// Marks responses as deprecated, in the standard headers that API clients
/// and gateways understand:
///
/// * `Deprecation: @1767225600` (RFC 9745), since when;
/// * `Sunset: Thu, 01 Jan 2027 00:00:00 GMT` (RFC 8594), when it stops working;
/// * `Link: <https://…>; rel="deprecation"`, where to read about it.
///
/// Limit it to path prefixes with [`only`](Deprecation::only), or add it to a
/// [`Router`](vitesse::Router) mounted on the old version.
///
/// ```
/// use pratique::prelude::*;
/// use std::time::{Duration, SystemTime, UNIX_EPOCH};
/// use vitesse::prelude::*;
///
/// let since = UNIX_EPOCH + Duration::from_secs(1_767_225_600); // 2026-01-01
/// let mut app = App::new();
/// app.middleware(
///     Deprecation::since(since)
///         .sunset(since + Duration::from_secs(365 * 86_400))
///         .link("https://example.com/docs/migrate-to-v2")
///         .only("/api/v1"),
/// );
/// ```
#[derive(Debug, Clone)]
pub struct Deprecation {
    deprecation: HeaderValue,
    sunset: Option<HeaderValue>,
    link: Option<HeaderValue>,
    only: Vec<String>,
}

impl Deprecation {
    /// Deprecated since `time`.
    pub fn since(time: SystemTime) -> Self {
        let value = format!("@{}", unix_secs(time));
        Self {
            deprecation: HeaderValue::from_str(&value).expect("a number is a valid header"),
            sunset: None,
            link: None,
            only: Vec::new(),
        }
    }

    /// Stops working at `time`.
    pub fn sunset(mut self, time: SystemTime) -> Self {
        self.sunset =
            Some(HeaderValue::from_str(&http_date(time)).expect("a date is a valid header"));
        self
    }

    /// Page explaining the deprecation and the migration.
    ///
    /// # Panics
    /// If `url` contains characters not allowed in a header.
    pub fn link(mut self, url: &str) -> Self {
        let value = format!("<{url}>; rel=\"deprecation\"; type=\"text/html\"");
        self.link = Some(HeaderValue::from_str(&value).expect("invalid deprecation link"));
        self
    }

    /// Only responses under this path prefix (can be called several times).
    /// Default: every response.
    pub fn only(mut self, prefix: impl Into<String>) -> Self {
        self.only.push(normalize_prefix(prefix));
        self
    }
}

impl Middleware for Deprecation {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if !self.only.is_empty() && !self.only.iter().any(|p| path_matches(req.path(), p)) {
            return next.run(req);
        }
        Box::pin(async move {
            let mut res = next.run(req).await;
            let headers = res.headers_mut();
            headers.insert("deprecation", self.deprecation.clone());
            if let Some(sunset) = &self.sunset {
                headers.insert("sunset", sunset.clone());
            }
            if let Some(link) = &self.link {
                headers.append(header::LINK, link.clone());
            }
            res
        })
    }
}
