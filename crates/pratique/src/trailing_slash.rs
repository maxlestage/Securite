//! One address per page: with or without the trailing slash.

use vitesse::http::Uri;
use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response, StatusCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Style {
    Trim,
    Append,
}

/// Normalises the trailing slash of every path: `/about/` → `/about`
/// ([`trim`](TrailingSlash::trim)) or `/about` → `/about/`
/// ([`append`](TrailingSlash::append)), with a `308 Permanent Redirect`
/// (search engines keep one address, the method and body are kept) or by
/// rewriting the request in place ([`rewrite`](TrailingSlash::rewrite)).
///
/// The query string is kept. With `append`, paths whose last segment looks
/// like a file (`/app.js`) are left alone.
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(TrailingSlash::trim());
/// app.get("/about", |_req: Request| async { "about" }); // `/about/` works too
/// ```
#[derive(Debug, Clone)]
pub struct TrailingSlash {
    style: Style,
    redirect: bool,
}

impl TrailingSlash {
    /// `/about/` → `/about`.
    pub fn trim() -> Self {
        Self {
            style: Style::Trim,
            redirect: true,
        }
    }

    /// `/about` → `/about/`.
    pub fn append() -> Self {
        Self {
            style: Style::Append,
            redirect: true,
        }
    }

    /// Rewrite the request instead of redirecting: the client keeps its
    /// address and the routes see the normalised one.
    pub fn rewrite(mut self) -> Self {
        self.redirect = false;
        self
    }

    /// The normalised path, if it differs.
    fn normalize(&self, path: &str) -> Option<String> {
        let normalized = match self.style {
            Style::Trim => {
                if path == "/" || !path.ends_with('/') {
                    return None;
                }
                let trimmed = path.trim_end_matches('/');
                if trimmed.is_empty() { "/" } else { trimmed }.to_owned()
            }
            Style::Append => {
                let last = path.rsplit('/').next().unwrap_or("");
                if path.ends_with('/') || last.contains('.') {
                    return None;
                }
                format!("{path}/")
            }
        };
        // `//evil.example/` must not become a protocol-relative `Location`.
        let collapsed = format!("/{}", normalized.trim_start_matches('/'));
        Some(collapsed)
    }
}

impl Middleware for TrailingSlash {
    fn handle(&'static self, mut req: Request, next: Next) -> BoxFuture<Response> {
        let Some(path) = self.normalize(req.path()) else {
            return next.run(req);
        };
        let target = match req.uri().query() {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        if self.redirect {
            let mut res = Response::new().status(StatusCode::PERMANENT_REDIRECT);
            if let Ok(location) = HeaderValue::from_str(&target) {
                res.headers_mut().insert(header::LOCATION, location);
            }
            return Box::pin(std::future::ready(res));
        }
        match target.parse::<Uri>() {
            Ok(uri) => {
                req.set_uri(uri);
                next.run(req)
            }
            Err(_) => next.run(req),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trim() {
        let t = TrailingSlash::trim();
        assert_eq!(t.normalize("/about/").as_deref(), Some("/about"));
        assert_eq!(t.normalize("/about///").as_deref(), Some("/about"));
        assert_eq!(t.normalize("/about"), None);
        assert_eq!(t.normalize("/"), None);
        assert_eq!(t.normalize("//").as_deref(), Some("/"));
        assert_eq!(
            t.normalize("//evil.example/").as_deref(),
            Some("/evil.example")
        );
    }

    #[test]
    fn append() {
        let t = TrailingSlash::append();
        assert_eq!(t.normalize("/docs").as_deref(), Some("/docs/"));
        assert_eq!(t.normalize("/docs/"), None);
        assert_eq!(t.normalize("/app.js"), None);
        assert_eq!(t.normalize("//evil/x").as_deref(), Some("/evil/x/"));
    }
}
