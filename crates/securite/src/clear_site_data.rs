//! `Clear-Site-Data` on logout and account deletion (W3C Clear Site Data).
//!
//! After a logout, the browser may still hold the user's data: cached
//! pages (the back button shows the inbox), `localStorage`, IndexedDB,
//! service workers, other cookies. `Clear-Site-Data` tells it to wipe them
//! for the whole origin. OWASP ASVS 5 (V14) asks for it.
//!
//! ```
//! use securite::clear_site_data::ClearSiteData;
//! use securite::prelude::*;
//!
//! // `"cache", "cookies", "storage"` on successful responses of these paths.
//! let shield = Shield::builder()
//!     .guard(ClearSiteData::on(["/logout", "/account/delete"]))
//!     .build();
//! ```
//!
//! Browsers only honour the header over HTTPS (and on `localhost`).

use http::header::{HeaderName, HeaderValue};
use http::response;

use crate::guard::impl_layer;
use crate::util::{any_path_matches, normalize_prefix};
use crate::{Context, Guard, priority};

/// A data type `Clear-Site-Data` can clear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Directive {
    /// `"cache"`: cached responses (and, in some browsers, the bfcache).
    Cache,
    /// `"cookies"`: every cookie of the registrable domain, and HTTP auth.
    Cookies,
    /// `"storage"`: localStorage, sessionStorage, IndexedDB, service workers …
    Storage,
    /// `"executionContexts"`: reloads the open documents of the origin.
    ExecutionContexts,
}

impl Directive {
    fn as_str(self) -> &'static str {
        match self {
            Directive::Cache => "\"cache\"",
            Directive::Cookies => "\"cookies\"",
            Directive::Storage => "\"storage\"",
            Directive::ExecutionContexts => "\"executionContexts\"",
        }
    }
}

/// Adds `Clear-Site-Data` to the successful (`2xx`, `3xx`) responses of some
/// paths. Exact paths and their sub-paths match (`/logout` covers
/// `/logout/all`).
#[derive(Debug, Clone)]
pub struct ClearSiteData {
    paths: Vec<String>,
    value: HeaderValue,
}

impl ClearSiteData {
    /// `"cache", "cookies", "storage"` on these paths.
    pub fn on<I, S>(paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            paths: paths.into_iter().map(normalize_prefix).collect(),
            value: HeaderValue::from_static(crate::session::CLEAR_SITE_DATA_LOGOUT),
        }
    }

    /// The data types to clear (replaces the default).
    ///
    /// # Panics
    ///
    /// If the list is empty.
    pub fn directives<I: IntoIterator<Item = Directive>>(mut self, directives: I) -> Self {
        let list: Vec<&str> = directives.into_iter().map(Directive::as_str).collect();
        assert!(!list.is_empty(), "at least one Clear-Site-Data directive");
        self.value = HeaderValue::from_str(&list.join(", ")).expect("static values");
        self
    }
}

impl Guard for ClearSiteData {
    fn name(&self) -> &'static str {
        "clear_site_data"
    }

    fn priority(&self) -> u16 {
        priority::CLEAR_SITE_DATA
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        let ok = res.status.is_success() || res.status.is_redirection();
        if ok && any_path_matches(ctx.path(), &self.paths) {
            res.headers.insert(
                HeaderName::from_static("clear-site-data"),
                self.value.clone(),
            );
        }
    }
}

impl_layer!(ClearSiteData);

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Response, StatusCode};

    fn run(g: &ClearSiteData, path: &str, status: StatusCode) -> Option<String> {
        let mut res = Response::builder()
            .status(status)
            .body(())
            .unwrap()
            .into_parts()
            .0;
        let ctx = Context::new(Method::POST, path.parse().unwrap(), None);
        g.on_response(&mut res, &ctx);
        res.headers
            .get("clear-site-data")
            .map(|v| v.to_str().unwrap().to_owned())
    }

    #[test]
    fn only_on_listed_paths_and_success() {
        let g = ClearSiteData::on(["logout"]);
        assert_eq!(
            run(&g, "/logout", StatusCode::SEE_OTHER).as_deref(),
            Some("\"cache\", \"cookies\", \"storage\"")
        );
        assert!(run(&g, "/logout/all", StatusCode::OK).is_some());
        assert!(run(&g, "/logouts", StatusCode::OK).is_none());
        assert!(run(&g, "/", StatusCode::OK).is_none());
        assert!(run(&g, "/logout", StatusCode::FORBIDDEN).is_none());
        let g = ClearSiteData::on(["/bye"])
            .directives([Directive::Cookies, Directive::ExecutionContexts]);
        assert_eq!(
            run(&g, "/bye", StatusCode::OK).as_deref(),
            Some("\"cookies\", \"executionContexts\"")
        );
    }
}
