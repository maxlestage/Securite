//! Documentation categories (shared) and, on the server, the pages compiled by `build.rs`
//! from `docs/{en,fr,es}/*.md`.

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

#[cfg(not(target_arch = "wasm32"))]
pub use compiled::*;

#[cfg(not(target_arch = "wasm32"))]
mod compiled {
    use super::CATEGORY_ORDER;
    use crate::i18n::Lang;

    pub struct DocPage {
        pub lang: &'static str,
        pub slug: &'static str,
        pub category: &'static str,
        pub order: u32,
        pub title: &'static str,
        pub summary: &'static str,
        /// HTML body; internal links hold `@BASE@` and `@LANG@` placeholders.
        pub body: &'static str,
        pub toc: &'static [(&'static str, &'static str, u8)],
        pub search: &'static str,
    }

    include!(concat!(env!("OUT_DIR"), "/docs_gen.rs"));

    /// The page for `slug` in `lang`, falling back to English (`false`: not translated).
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

    /// Whether a page exists (in English at least).
    pub fn exists(slug: &str) -> bool {
        DOCS.iter().any(|d| d.slug == slug)
    }

    /// Every slug, sorted.
    pub fn slugs() -> Vec<&'static str> {
        let mut slugs: Vec<&str> = DOCS.iter().map(|d| d.slug).collect();
        slugs.sort_unstable();
        slugs.dedup();
        slugs
    }

    /// Every page (one per slug) in `lang`, falling back to English, sorted by category
    /// then order.
    pub fn pages(lang: Lang) -> Vec<&'static DocPage> {
        let mut out: Vec<&'static DocPage> = slugs()
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

    /// The body of `page` with its internal links behind `base`, in `lang`.
    pub fn body(page: &DocPage, base: &str, lang: Lang) -> String {
        page.body
            .replace("@BASE@", base)
            .replace("@LANG@", lang.code())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn every_page_exists_in_three_languages_with_known_categories() {
            let slugs = slugs();
            assert!(slugs.len() >= 33, "{} pages", slugs.len());
            for lang in Lang::ALL {
                for slug in &slugs {
                    let (page, translated) = find(lang, slug).unwrap();
                    assert!(translated, "{slug} missing in {}", lang.code());
                    assert!(
                        CATEGORY_ORDER.contains(&page.category),
                        "{slug}: category {:?}",
                        page.category
                    );
                    assert!(!page.title.is_empty() && !page.summary.is_empty(), "{slug}");
                }
            }
        }

        #[test]
        fn internal_links_follow_the_base_path_and_the_language() {
            let (page, _) = find(Lang::Fr, "quick-start").unwrap();
            let html = body(page, "/Securite", Lang::Fr);
            assert!(!html.contains("@BASE@") && !html.contains("@LANG@"));
            assert!(!html.contains("href=\"/docs/"), "unconverted link");
            assert!(html.contains("href=\"/Securite/fr/docs/"), "{html}");
        }
    }
}
