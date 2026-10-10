//! URLs of the site: `/{lang}/`, `/{lang}/docs/`, `/{lang}/docs/{slug}/` and
//! `/{lang}/playground/`, all behind an optional base path (`/Securite` when the site is
//! published on GitHub Pages).

use crate::i18n::Lang;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Page {
    Home,
    Docs,
    Doc(String),
    Playground,
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub lang: Lang,
    pub page: Page,
}

impl Route {
    pub fn new(lang: Lang, page: Page) -> Route {
        Route { lang, page }
    }

    /// Parses a path without the base path. `None` when it does not start with a
    /// language; `exists` tells whether a documentation page exists.
    pub fn parse(path: &str, exists: impl Fn(&str) -> bool) -> Option<Route> {
        let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
        let lang = Lang::parse(parts.first()?)?;
        let page = match parts[1..] {
            [] => Page::Home,
            ["docs"] => Page::Docs,
            ["docs", slug] if exists(slug) => Page::Doc(slug.to_string()),
            ["playground"] => Page::Playground,
            _ => Page::NotFound,
        };
        Some(Route { lang, page })
    }

    /// The path of the page, without the base path.
    pub fn path(&self) -> String {
        let l = self.lang.code();
        match &self.page {
            Page::Home => format!("/{l}/"),
            Page::Docs => format!("/{l}/docs/"),
            Page::Doc(slug) => format!("/{l}/docs/{slug}/"),
            Page::Playground => format!("/{l}/playground/"),
            Page::NotFound => format!("/{l}/404/"),
        }
    }

    /// A link to the page behind `base` (`""` or `/Securite`).
    pub fn href(&self, base: &str) -> String {
        format!("{base}{}", self.path())
    }

    /// The same page in another language.
    pub fn with_lang(&self, lang: Lang) -> Route {
        Route {
            lang,
            page: self.page.clone(),
        }
    }
}

/// Normalizes a base path: `""`, `"/"` → `""`; `"Securite/"` → `"/Securite"`.
pub fn normalize_base(base: &str) -> String {
    let base = base.trim().trim_matches('/');
    if base.is_empty() {
        String::new()
    } else {
        format!("/{base}")
    }
}

/// The link to a documentation page.
pub fn doc_href(base: &str, lang: Lang, slug: &str) -> String {
    format!("{base}/{}/docs/{slug}/", lang.code())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_builds_urls() {
        let exists = |s: &str| ["waf", "csrf"].contains(&s);
        let doc = Route::parse("/fr/docs/waf/", exists).unwrap();
        assert_eq!(doc, Route::new(Lang::Fr, Page::Doc("waf".into())));
        assert_eq!(doc.href(""), "/fr/docs/waf/");
        assert_eq!(doc.href("/Securite"), "/Securite/fr/docs/waf/");
        assert_eq!(doc.with_lang(Lang::Es).path(), "/es/docs/waf/");
        assert_eq!(Route::parse("/en", exists).unwrap().page, Page::Home);
        assert_eq!(Route::parse("/en/docs", exists).unwrap().page, Page::Docs);
        assert_eq!(
            Route::parse("/es/playground/", exists).unwrap().page,
            Page::Playground
        );
        assert_eq!(
            Route::parse("/en/docs/nope/", exists).unwrap().page,
            Page::NotFound
        );
        assert_eq!(Route::parse("/de/", exists), None);
        assert_eq!(Route::parse("/", exists), None);
    }

    #[test]
    fn normalizes_base_paths() {
        assert_eq!(normalize_base(""), "");
        assert_eq!(normalize_base("/"), "");
        assert_eq!(normalize_base("Securite/"), "/Securite");
        assert_eq!(normalize_base("/Securite"), "/Securite");
    }
}
