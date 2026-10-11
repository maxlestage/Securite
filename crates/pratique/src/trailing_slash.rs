//! One address per page: with or without the trailing slash.

use vitesse::http::Uri;
use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response, StatusCode};

use crate::util::{encode_target, local_path, normalize_prefix, path_matches};

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
/// like a file (`/app.js`) are left alone. With a static directory served by
/// Vitesse, exclude it with [`except`](TrailingSlash::except).
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
    except: Vec<String>,
}

impl TrailingSlash {
    /// `/about/` → `/about`.
    pub fn trim() -> Self {
        Self {
            style: Style::Trim,
            redirect: true,
            except: Vec::new(),
        }
    }

    /// `/about` → `/about/`.
    pub fn append() -> Self {
        Self {
            style: Style::Append,
            redirect: true,
            except: Vec::new(),
        }
    }

    /// Rewrite the request instead of redirecting: the client keeps its
    /// address and the routes see the normalised one.
    pub fn rewrite(mut self) -> Self {
        self.redirect = false;
        self
    }

    /// Leaves the paths under this prefix alone (can be called several
    /// times). Needed for a static directory served by Vitesse with `trim()`:
    /// `ServeDir` redirects a folder to its address with a final `/`
    /// (`/docs` → `/docs/`), and trimming it again would loop.
    pub fn except(mut self, prefix: impl Into<String>) -> Self {
        self.except.push(normalize_prefix(prefix));
        self
    }

    /// The normalised path, if it differs.
    fn normalize(&self, path: &str) -> Option<String> {
        // `OPTIONS *` and other targets that are not paths.
        if !path.starts_with('/') || self.except.iter().any(|p| path_matches(path, p)) {
            return None;
        }
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
        // `//evil.example/` and `/\\evil.example/` must not become
        // protocol-relative addresses.
        Some(local_path(&normalized))
    }
}

impl Middleware for TrailingSlash {
    fn handle(&'static self, mut req: Request, next: Next) -> BoxFuture<Response> {
        let Some(path) = self.normalize(req.path()) else {
            return next.run(req);
        };
        // The raw query string: `req.uri()` drops targets that `Uri` rejects.
        let target = match req.query_string() {
            Some(query) => format!("{path}?{query}"),
            None => path,
        };
        let target = encode_target(&target);
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
        assert_eq!(t.normalize("/\\evil/x").as_deref(), Some("/evil/x/"));
        assert_eq!(t.normalize("*"), None);
    }
}
