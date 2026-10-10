//! Hardens every `Set-Cookie` header of your responses.

use http::header::{HeaderValue, SET_COOKIE};
use http::response;

use crate::guard::impl_layer;
use crate::{Context, Guard, priority};

/// `SameSite` cookie attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    /// `SameSite=Strict`
    Strict,
    /// `SameSite=Lax` (default)
    #[default]
    Lax,
    /// `SameSite=None` (implies `Secure`)
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// Adds the missing `Secure`, `HttpOnly` and `SameSite` attributes to every
/// cookie set by your application — even the ones set by third-party
/// crates you do not control.
///
/// Attributes already present are left untouched.
///
/// ```
/// use securite::prelude::*;
///
/// let cookies = CookieHardening::new()
///     .same_site(SameSite::Strict)
///     .readable_by_js(["theme"]); // no HttpOnly for this one
/// ```
#[derive(Debug, Clone)]
pub struct CookieHardening {
    secure: bool,
    http_only: bool,
    same_site: SameSite,
    js_readable: Vec<String>,
}

impl Default for CookieHardening {
    fn default() -> Self {
        Self::new()
    }
}

impl CookieHardening {
    /// `Secure; HttpOnly; SameSite=Lax`.
    pub fn new() -> Self {
        Self {
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            js_readable: Vec::new(),
        }
    }

    /// Default `SameSite` value.
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Do not add `Secure` (plain-HTTP local development only).
    pub fn insecure_dev(mut self) -> Self {
        self.secure = false;
        self
    }

    /// Do not add `HttpOnly` at all.
    pub fn no_http_only(mut self) -> Self {
        self.http_only = false;
        self
    }

    /// Cookies that must stay readable by JavaScript (no `HttpOnly`).
    pub fn readable_by_js<I, S>(mut self, names: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.js_readable.extend(names.into_iter().map(Into::into));
        self
    }

    /// Returns the hardened version of one `Set-Cookie` value.
    pub fn harden(&self, cookie: &str) -> String {
        let mut parts = cookie.split(';');
        let name_value = parts.next().unwrap_or("").trim();
        let name = name_value.split('=').next().unwrap_or("").trim();
        let (mut has_secure, mut has_http_only, mut same_site) = (false, false, None::<String>);
        for attr in parts {
            let key = attr.split('=').next().unwrap_or("").trim();
            if key.eq_ignore_ascii_case("secure") {
                has_secure = true;
            } else if key.eq_ignore_ascii_case("httponly") {
                has_http_only = true;
            } else if key.eq_ignore_ascii_case("samesite") {
                same_site = Some(
                    attr.split('=')
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase(),
                );
            }
        }
        let mut out = cookie.trim_end().trim_end_matches(';').to_owned();
        let same_site_none = same_site.as_deref() == Some("none")
            || (same_site.is_none() && self.same_site == SameSite::None);
        if !has_secure
            && (self.secure
                || same_site_none
                || name.starts_with("__Host-")
                || name.starts_with("__Secure-"))
        {
            out.push_str("; Secure");
        }
        if !has_http_only && self.http_only && !self.js_readable.iter().any(|n| n == name) {
            out.push_str("; HttpOnly");
        }
        if same_site.is_none() {
            out.push_str("; SameSite=");
            out.push_str(self.same_site.as_str());
        }
        out
    }
}

impl Guard for CookieHardening {
    fn name(&self) -> &'static str {
        "cookies"
    }

    fn priority(&self) -> u16 {
        priority::COOKIES
    }

    fn on_response(&self, res: &mut response::Parts, _ctx: &Context) {
        if !res.headers.contains_key(SET_COOKIE) {
            return;
        }
        let hardened: Vec<HeaderValue> = res
            .headers
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|v| match v.to_str() {
                Ok(s) => HeaderValue::from_str(&self.harden(s)).ok(),
                Err(_) => Some(v.clone()),
            })
            .collect();
        res.headers.remove(SET_COOKIE);
        for v in hardened {
            res.headers.append(SET_COOKIE, v);
        }
    }
}

impl_layer!(CookieHardening);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_missing() {
        let c = CookieHardening::new();
        assert_eq!(
            c.harden("sid=abc"),
            "sid=abc; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            c.harden("sid=abc; Path=/;"),
            "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn keeps_existing() {
        let c = CookieHardening::new();
        assert_eq!(
            c.harden("sid=abc; secure; HTTPONLY; SameSite=Strict"),
            "sid=abc; secure; HTTPONLY; SameSite=Strict"
        );
    }

    #[test]
    fn js_readable_and_dev() {
        let c = CookieHardening::new()
            .readable_by_js(["theme"])
            .insecure_dev();
        assert_eq!(c.harden("theme=dark"), "theme=dark; SameSite=Lax");
        assert_eq!(
            c.harden("__Host-x=1"),
            "__Host-x=1; Secure; HttpOnly; SameSite=Lax"
        );
        assert_eq!(
            c.harden("x=1; SameSite=None"),
            "x=1; SameSite=None; Secure; HttpOnly"
        );
    }
}
