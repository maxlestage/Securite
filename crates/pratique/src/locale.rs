//! The language of each request: query string, cookie or `Accept-Language`.

use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response};

use crate::util::add_vary;

/// The language chosen for a request, read by handlers with
/// `req.get::<Lang>()`. Always one of the supported tags, as written in
/// [`Locale::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lang(pub String);

impl Lang {
    /// The tag (`fr`, `en-GB` …).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Picks the language of every request among the supported ones: from the
/// query string (`?lang=fr`), then a cookie (`lang=fr`), then the browser's
/// `Accept-Language` (weights and regional variants understood: `fr-CA`
/// matches `fr`), else the default (the first supported language).
///
/// Handlers read it with `req.get::<Lang>()`; responses get
/// `Content-Language` (when they have none) and `Vary: Accept-Language`,
/// plus `Cookie` while the cookie source is on (turn it off with
/// `.cookie(None)` to let CDNs cache the pages).
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(Locale::new(["en", "fr", "es"]));
/// app.get("/", |req: Request| async move {
///     match req.get::<Lang>().map(Lang::as_str) {
///         Some("fr") => "Bonjour !",
///         Some("es") => "¡Hola!",
///         _ => "Hello!",
///     }
/// });
/// ```
#[derive(Debug, Clone)]
pub struct Locale {
    supported: Vec<String>,
    default: String,
    query: Option<String>,
    cookie: Option<String>,
}

impl Locale {
    /// The supported languages, the first being the default. The query
    /// parameter and the cookie are both named `lang`.
    ///
    /// # Panics
    /// If `supported` is empty.
    pub fn new<I, S>(supported: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let supported: Vec<String> = supported.into_iter().map(Into::into).collect();
        let default = supported
            .first()
            .expect("Locale needs at least one language")
            .clone();
        Self {
            supported,
            default,
            query: Some("lang".into()),
            cookie: Some("lang".into()),
        }
    }

    /// The language used when nothing matches (added to the supported ones).
    pub fn fallback(mut self, lang: impl Into<String>) -> Self {
        let lang = lang.into();
        if self.find(&lang).is_none() {
            self.supported.push(lang.clone());
        }
        self.default = lang;
        self
    }

    /// Query parameter that forces the language, or `None`.
    pub fn query_param(mut self, name: Option<&str>) -> Self {
        self.query = name.map(str::to_owned);
        self
    }

    /// Cookie that remembers the language, or `None`.
    pub fn cookie(mut self, name: Option<&str>) -> Self {
        self.cookie = name.map(str::to_owned);
        self
    }

    /// The supported tag equal to `tag` (case-insensitive).
    fn find(&self, tag: &str) -> Option<&str> {
        self.supported
            .iter()
            .find(|s| s.eq_ignore_ascii_case(tag.trim()))
            .map(String::as_str)
    }

    /// The best supported tag for an `Accept-Language` header.
    fn negotiate(&self, accept: &str) -> Option<&str> {
        let mut ranges: Vec<(&str, f32)> = Vec::new();
        // `q=0` means "not this one", even through a regional variant.
        let mut refused: Vec<&str> = Vec::new();
        for part in accept.split(',') {
            let mut pieces = part.split(';');
            let tag = pieces.next().unwrap_or("").trim();
            if tag.is_empty() {
                continue;
            }
            let q = pieces
                .map(str::trim)
                .find(|p| p.get(..2).is_some_and(|k| k.eq_ignore_ascii_case("q=")))
                .map_or(Some(1.0), |p| p[2..].trim().parse::<f32>().ok());
            match q {
                Some(q) if q > 0.0 => ranges.push((tag, q)),
                Some(_) => refused.push(tag),
                None => {}
            }
        }
        let allowed = |tag: &str| !refused.iter().any(|r| r.eq_ignore_ascii_case(tag));
        // Stable: equal weights keep the browser's order.
        ranges.sort_by(|a, b| b.1.total_cmp(&a.1));
        for (tag, _) in ranges {
            if tag == "*" {
                let default = Some(self.default.as_str()).filter(|d| allowed(d));
                return default.or_else(|| {
                    self.supported
                        .iter()
                        .map(String::as_str)
                        .find(|s| allowed(s))
                });
            }
            if let Some(found) = self.find(tag).filter(|f| allowed(f)) {
                return Some(found);
            }
            // `fr-CA` → `fr`, and `fr` → `fr-FR` when only a regional variant exists.
            let primary = tag.split('-').next().unwrap_or(tag);
            let regional = self.supported.iter().find(|s| {
                allowed(s)
                    && s.split('-')
                        .next()
                        .is_some_and(|p| p.eq_ignore_ascii_case(primary))
            });
            if let Some(found) = regional {
                return Some(found);
            }
        }
        None
    }

    fn choose(&self, req: &Request) -> &str {
        let from_query = self
            .query
            .as_deref()
            .and_then(|name| req.query(name))
            .and_then(|lang| self.find(&lang));
        let from_cookie = || {
            self.cookie
                .as_deref()
                .and_then(|name| req.cookie(name))
                .and_then(|lang| self.find(lang))
        };
        let from_header = || {
            req.header(header::ACCEPT_LANGUAGE)
                .and_then(|accept| self.negotiate(accept))
        };
        from_query
            .or_else(from_cookie)
            .or_else(from_header)
            .unwrap_or(&self.default)
    }
}

impl Middleware for Locale {
    fn handle(&'static self, mut req: Request, next: Next) -> BoxFuture<Response> {
        let lang = self.choose(&req);
        req.set(Lang(lang.to_owned()));
        Box::pin(async move {
            let mut res = next.run(req).await;
            if let Ok(value) = HeaderValue::from_str(lang) {
                res.headers_mut()
                    .entry(header::CONTENT_LANGUAGE)
                    .or_insert(value);
            }
            add_vary(&mut res, "accept-language");
            // The language cookie chooses too: a shared cache must not give
            // the French page of a visitor's cookie to everyone else.
            if self.cookie.is_some() {
                add_vary(&mut res, "cookie");
            }
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_language() {
        let l = Locale::new(["en", "fr", "pt-BR"]);
        assert_eq!(l.negotiate("fr-CA,fr;q=0.9,en;q=0.8"), Some("fr"));
        assert_eq!(l.negotiate("de, en;q=0.5"), Some("en"));
        assert_eq!(l.negotiate("en;q=0.2, fr;q=0.9"), Some("fr"));
        assert_eq!(l.negotiate("pt"), Some("pt-BR"));
        assert_eq!(l.negotiate("PT-br"), Some("pt-BR"));
        assert_eq!(l.negotiate("de, *;q=0.1"), Some("en"));
        assert_eq!(l.negotiate("fr;q=0, de"), None);
        assert_eq!(l.negotiate("fr;Q=0, en"), Some("en"));
        assert_eq!(l.negotiate("fr;q=0, fr-CA"), None);
        assert_eq!(l.negotiate("en;q=0, *"), Some("fr"));
        assert_eq!(l.negotiate("fr;q=1.0;level=1"), Some("fr"));
        assert_eq!(l.negotiate(""), None);
    }

    #[test]
    fn fallback_is_supported() {
        let l = Locale::new(["fr"]).fallback("en");
        assert_eq!(l.default, "en");
        assert_eq!(l.find("EN"), Some("en"));
    }
}
