//! Redirection rules: moved pages, renamed sections, canonical domain.

use std::collections::HashMap;

use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response, StatusCode};

use crate::util::{normalize_prefix, path_matches};

/// Redirects old addresses to new ones before the routes run.
///
/// * [`permanent`](Redirects::permanent) / [`temporary`](Redirects::temporary):
///   one exact path (`308` / `307`, the method and body are kept);
/// * [`prefix`](Redirects::prefix): a whole section, the rest of the path
///   follows (`/blog/2024/hello` → `/articles/2024/hello`);
/// * [`host`](Redirects::host): every request for a host goes to another
///   origin (`www.example.com` → `https://example.com`).
///
/// The query string follows the request, unless the target has its own.
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(
///     Redirects::new()
///         .host("www.example.com", "https://example.com")
///         .permanent("/old-pricing", "/pricing")
///         .prefix("/blog", "/articles")
///         .temporary("/sale", "/products?promo=autumn"),
/// );
/// ```
#[derive(Debug, Clone, Default)]
pub struct Redirects {
    exact: HashMap<String, (String, StatusCode)>,
    prefixes: Vec<(String, String, StatusCode)>,
    hosts: HashMap<String, String>,
}

impl Redirects {
    /// No rule.
    pub fn new() -> Self {
        Self::default()
    }

    /// `from` (exact path) → `to`, `308 Permanent Redirect`.
    pub fn permanent(self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.exact(from, to, StatusCode::PERMANENT_REDIRECT)
    }

    /// `from` (exact path) → `to`, `307 Temporary Redirect`.
    pub fn temporary(self, from: impl Into<String>, to: impl Into<String>) -> Self {
        self.exact(from, to, StatusCode::TEMPORARY_REDIRECT)
    }

    /// `from` (exact path) → `to` with any `3xx` status (`301`, `302`, `303` …).
    ///
    /// # Panics
    /// If `status` is not a redirection.
    pub fn exact(
        mut self,
        from: impl Into<String>,
        to: impl Into<String>,
        status: StatusCode,
    ) -> Self {
        assert!(status.is_redirection(), "{status} is not a redirection");
        self.exact
            .insert(normalize_prefix(from), (to.into(), status));
        self
    }

    /// Every path under `from` moves under `to` (permanent, `308`). The
    /// longest matching prefix wins. Paths already under `to` are left alone,
    /// so `to` may be inside `from` (`/docs` → `/docs/v2`).
    pub fn prefix(mut self, from: impl Into<String>, to: impl Into<String>) -> Self {
        let from = normalize_prefix(from);
        let to = to.into().trim_end_matches('/').to_owned();
        self.prefixes
            .push((from, to, StatusCode::PERMANENT_REDIRECT));
        self.prefixes
            .sort_by_key(|(p, _, _)| std::cmp::Reverse(p.len()));
        self
    }

    /// Every request for `host` (without port, case-insensitive) goes to
    /// `origin` (`https://example.com`), same path and query, `308`.
    pub fn host(mut self, host: &str, origin: impl Into<String>) -> Self {
        let origin = origin.into().trim_end_matches('/').to_owned();
        self.hosts.insert(host.to_ascii_lowercase(), origin);
        self
    }

    /// Where `req` goes, if a rule applies.
    fn target(&self, req: &Request) -> Option<(String, StatusCode)> {
        let path = req.path();
        let query = req.uri().query();
        let with_query = |target: String| match query {
            Some(q) if !target.contains('?') => format!("{target}?{q}"),
            _ => target,
        };
        if !self.hosts.is_empty() {
            let host = req
                .header(header::HOST)
                .map(|h| {
                    h.rsplit_once(':').map_or(h, |(name, port)| {
                        // `[::1]:8080` → `[::1]`, but not `[::1]` alone.
                        if port.bytes().all(|b| b.is_ascii_digit()) {
                            name
                        } else {
                            h
                        }
                    })
                })
                .map(str::to_ascii_lowercase);
            if let Some(origin) = host.and_then(|h| self.hosts.get(&h)) {
                return Some((
                    with_query(format!("{origin}{path}")),
                    StatusCode::PERMANENT_REDIRECT,
                ));
            }
        }
        if let Some((to, status)) = self.exact.get(path) {
            return Some((with_query(to.clone()), *status));
        }
        let (from, to, status) = self
            .prefixes
            .iter()
            // A path already under the target is not redirected again:
            // `/docs` → `/docs/v2` must not loop to `/docs/v2/v2`.
            .find(|(from, to, _)| {
                path_matches(path, from) && (to.is_empty() || !path_matches(path, to))
            })?;
        let rest = &path[from.trim_end_matches('/').len()..];
        let target = format!("{to}{rest}");
        let target = if target.is_empty() {
            "/".to_owned()
        } else {
            target
        };
        Some((with_query(target), *status))
    }
}

impl Middleware for Redirects {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        let Some((target, status)) = self.target(&req) else {
            return next.run(req);
        };
        let mut res = Response::new().status(status);
        if let Ok(location) = HeaderValue::from_str(&target) {
            res.headers_mut().insert(header::LOCATION, location);
        }
        Box::pin(std::future::ready(res))
    }
}
