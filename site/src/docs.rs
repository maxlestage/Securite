//! Documentation pages compiled by `build.rs`.

use crate::i18n::Lang;

pub struct DocPage {
    pub lang: &'static str,
    pub slug: &'static str,
    pub category: &'static str,
    pub order: u32,
    pub title: &'static str,
    pub summary: &'static str,
    /// Content-hashed URL of the rendered HTML body.
    pub url: &'static str,
    pub toc: &'static [(&'static str, &'static str, u8)],
    pub search: &'static str,
}

include!(concat!(env!("OUT_DIR"), "/docs_gen.rs"));

/// Category ids in display order.
pub const CATEGORY_ORDER: [&str; 7] = [
    "start",
    "browser",
    "traffic",
    "access",
    "threats",
    "integrity",
    "deploy",
];

pub fn category_icon(id: &str) -> &'static str {
    match id {
        "start" => "rocket",
        "browser" => "layers",
        "traffic" => "gauge",
        "access" => "key",
        "threats" => "bug",
        "integrity" => "fingerprint",
        "deploy" => "smartphone",
        _ => "book",
    }
}

/// The page for `slug` in `lang`, falling back to English.
pub fn find(lang: Lang, slug: &str) -> Option<(&'static DocPage, bool)> {
    DOCS.iter()
        .find(|d| d.lang == lang.code() && d.slug == slug)
        .map(|d| (d, true))
        .or_else(|| {
            DOCS.iter()
                .find(|d| d.lang == "en" && d.slug == slug)
                .map(|d| (d, false))
        })
}

/// Every page (one per slug) in `lang`, falling back to English, sorted by
/// category then order.
pub fn pages(lang: Lang) -> Vec<&'static DocPage> {
    let mut slugs: Vec<&str> = DOCS.iter().map(|d| d.slug).collect();
    slugs.sort_unstable();
    slugs.dedup();
    let mut out: Vec<&'static DocPage> = slugs
        .into_iter()
        .filter_map(|s| find(lang, s).map(|(d, _)| d))
        .collect();
    out.sort_by_key(|d| {
        (
            CATEGORY_ORDER
                .iter()
                .position(|c| *c == d.category)
                .unwrap_or(99),
            d.order,
        )
    });
    out
}

thread_local! {
    static CACHE: std::cell::RefCell<std::collections::HashMap<&'static str, std::rc::Rc<str>>> =
        std::cell::RefCell::new(std::collections::HashMap::new());
}

/// Returns the HTML body of `page`, fetched once and cached.
pub async fn body(page: &'static DocPage) -> Result<std::rc::Rc<str>, String> {
    if let Some(hit) = CACHE.with(|c| c.borrow().get(page.url).cloned()) {
        return Ok(hit);
    }
    let res = gloo::net::http::Request::get(page.url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.ok() {
        return Err(format!("HTTP {}", res.status()));
    }
    let html: std::rc::Rc<str> = res.text().await.map_err(|e| e.to_string())?.into();
    CACHE.with(|c| c.borrow_mut().insert(page.url, html.clone()));
    Ok(html)
}

/// Whether the body of `page` is already cached.
pub fn cached(page: &'static DocPage) -> Option<std::rc::Rc<str>> {
    CACHE.with(|c| c.borrow().get(page.url).cloned())
}
