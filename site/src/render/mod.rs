//! Server side of the site: every page rendered with active (complete SEO), the web app
//! manifest, the service worker, the sitemap and `robots.txt`. Used by `securite-server`,
//! which serves them and writes them to files for GitHub Pages.

pub mod assets;
pub mod pages;

use std::path::{Path, PathBuf};

use active::pwa::{Manifest, ServiceWorker};

use crate::i18n::Lang;
use crate::routes::{Page, Route, normalize_base};
use assets::Assets;

/// The license, served by the site itself (a copy of the repository's LICENSE): proprietary,
/// all rights reserved.
pub const LICENSE_PATH: &str = "/static/LICENSE.txt";
/// Who designed and built securite and its sister projects.
pub const AUTHOR: &str = "Maxime Nathan Lestage";
/// The sister projects of securite, by the same author: (name, website). The footer links
/// them in this order; `i18n::Texts::footer_projects` describes each one in the same order.
pub const ECOSYSTEM: [(&str, &str); 7] = [
    ("Active", "https://maxlestage.github.io/Active/"),
    ("Vitesse", "https://maxlestage.github.io/Vitesse/"),
    ("Securite", "https://maxlestage.github.io/Securite/"),
    ("Memoire", "https://maxlestage.github.io/Memoire/"),
    ("Paquets", "https://maxlestage.github.io/Paquets/"),
    ("FerroSwift", "https://maxlestage.github.io/FerroSwift/"),
    ("Solidify", "https://maxlestage.github.io/Solidify/"),
];
pub const CRATES_IO: &str = "https://github.com/maxlestage/Securite";
pub const DOCS_RS: &str = "https://docs.rs/securite";
/// Background of the site (`--bg` in main.css): theme and splash screen color.
pub const THEME: &str = "#05060a";

mod snippets {
    include!(concat!(env!("OUT_DIR"), "/snippets_gen.rs"));
}

/// Snippet `i` of the home page code tabs: (highlighted HTML, raw text).
pub fn snippet(i: usize) -> (&'static str, &'static str) {
    match i {
        0 => (snippets::ONE_LINE, snippets::ONE_LINE_RAW),
        1 => (snippets::TAILORED, snippets::TAILORED_RAW),
        _ => (snippets::STANDALONE, snippets::STANDALONE_RAW),
    }
}

/// Everything needed to render the site.
pub struct Site {
    /// `""`, or `/Securite` on GitHub Pages.
    pub base: String,
    /// Public address with the base path (`https://maxlestage.github.io/Securite`); taken
    /// from each request when not set.
    pub site_url: Option<String>,
    /// A server answers `/api/` (the live playground). `false` for the static export.
    pub live: bool,
    pub assets: Assets,
}

/// The `site/` folder: `SITE_DIR`, or this crate's folder when run with cargo.
pub fn site_dir() -> PathBuf {
    std::env::var_os("SITE_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
}

impl Site {
    /// Reads `static/` and `pkg/` (the browser bundle) from `dir`.
    pub fn load(dir: &Path, base: &str, site_url: Option<String>, live: bool) -> Site {
        let base = normalize_base(base);
        let mut assets = Assets::default();
        assets.load(&dir.join("static"), "/static");
        assets.load(&dir.join("pkg"), "/pkg");
        let site_url = site_url
            .map(|u| u.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
            .map(|u| {
                if u.ends_with(&base) {
                    u
                } else {
                    format!("{u}{base}")
                }
            });
        Site {
            base,
            site_url,
            live,
            assets,
        }
    }

    /// Whether the browser bundle was built (`site/pkg`).
    pub fn has_bundle(&self) -> bool {
        self.assets.get("/pkg/securite_site_bg.wasm").is_some()
    }

    /// A link behind the base path.
    pub fn link(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    /// Every page of the site, in every language.
    pub fn routes(&self) -> Vec<Route> {
        let mut routes = Vec::new();
        for lang in Lang::ALL {
            routes.push(Route::new(lang, Page::Home));
            routes.push(Route::new(lang, Page::Docs));
            routes.extend(
                crate::docs::slugs()
                    .into_iter()
                    .map(|s| Route::new(lang, Page::Doc(s.to_string()))),
            );
            routes.push(Route::new(lang, Page::Playground));
        }
        routes
    }

    /// The route of `path` (without the base path), if it starts with a language.
    pub fn route(&self, path: &str) -> Option<Route> {
        Route::parse(path, crate::docs::exists)
    }

    /// The public address (with the base path) for a request to `host`.
    pub fn public_url(&self, host: Option<&str>, https: bool) -> String {
        if let Some(url) = &self.site_url {
            return url.clone();
        }
        let host = host
            .filter(|h| {
                !h.is_empty()
                    && h.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
            })
            .unwrap_or("localhost");
        let scheme = if https { "https" } else { "http" };
        format!("{scheme}://{host}{}", self.base)
    }

    /// The HTML of `route`; `public` is the public address (see [`public_url`](Self::public_url)).
    pub fn page(&self, route: &Route, public: &str) -> String {
        pages::render(&pages::Ctx {
            site: self,
            route,
            public,
        })
    }

    /// Changes with every deployment: the content compiled into the site and the files it
    /// serves (style sheet, WebAssembly bundle, icons).
    pub fn version(&self) -> String {
        let mut all = String::from(crate::docs::CONTENT_HASH);
        for (url, asset) in self.assets.iter() {
            all.push_str(url);
            all.push_str(&asset.version);
        }
        format!("{:016x}", assets::hash(all.as_bytes()))[..12].to_string()
    }

    /// The web app manifest: the site can be installed on a phone's home screen.
    pub fn manifest(&self) -> Manifest {
        let base = &self.base;
        let t = Lang::En.t();
        Manifest::new("Securite")
            .short_name("Securite")
            .description(t.site_description)
            .id(format!("{base}/"))
            .start_url(format!("{base}/"))
            .scope(format!("{base}/"))
            .theme_color(THEME)
            .background_color(THEME)
            .lang("en")
            .categories(["developer", "security", "utilities"])
            .icon(
                self.assets.url(base, "/static/icon-192.png"),
                "192x192",
                "image/png",
            )
            .icon(
                self.assets.url(base, "/static/icon-512.png"),
                "512x512",
                "image/png",
            )
            .maskable_icon(
                self.assets.url(base, "/static/icon-maskable-512.png"),
                "512x512",
                "image/png",
            )
            .icon(
                self.assets.url(base, "/static/favicon.svg"),
                "any",
                "image/svg+xml",
            )
    }

    /// The service worker: pages from the network first (cached for offline use), files
    /// from the cache, the playground API always from the network.
    pub fn service_worker(&self) -> ServiceWorker {
        let base = &self.base;
        let mut precache: Vec<String> = Vec::new();
        for lang in Lang::ALL {
            precache.push(Route::new(lang, Page::Home).href(base));
            precache.push(Route::new(lang, Page::Docs).href(base));
        }
        for file in [
            "/static/main.css",
            "/pkg/securite_site.js",
            "/pkg/securite_site_bg.wasm",
            "/static/favicon.svg",
            "/static/icon-192.png",
            "/static/icon-512.png",
            "/static/icon-maskable-512.png",
        ] {
            if self.assets.get(file).is_some() {
                precache.push(self.assets.url(base, file));
            }
        }
        precache.push(format!("{base}/manifest.webmanifest"));
        ServiceWorker::new("securite-site", self.version())
            .precache(precache)
            .offline_page(Route::new(Lang::En, Page::Home).href(base))
            .network_only(format!("{base}/api/"))
    }

    /// `sitemap.xml`, with the language versions of every page.
    pub fn sitemap(&self, public: &str) -> String {
        let mut xml = String::from(concat!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
            "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n"
        ));
        for route in self.routes() {
            xml.push_str(&format!("<url><loc>{public}{}</loc>", route.path()));
            for lang in Lang::ALL {
                xml.push_str(&format!(
                    r#"<xhtml:link rel="alternate" hreflang="{}" href="{public}{}"/>"#,
                    lang.code(),
                    route.with_lang(lang).path()
                ));
            }
            xml.push_str(&format!(
                r#"<xhtml:link rel="alternate" hreflang="x-default" href="{public}{}"/></url>"#,
                route.with_lang(Lang::En).path()
            ));
            xml.push('\n');
        }
        xml.push_str("</urlset>\n");
        xml
    }

    /// `robots.txt`.
    pub fn robots(&self, public: &str) -> String {
        format!("User-agent: *\nAllow: /\n\nSitemap: {public}/sitemap.xml\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(base: &str) -> Site {
        Site::load(
            &site_dir(),
            base,
            Some("https://maxlestage.github.io/".into()),
            false,
        )
    }

    #[test]
    fn the_manifest_is_valid_json_with_the_base_path() {
        let json = site("/Securite").manifest().to_json();
        assert!(json.starts_with(r#"{"name":"Securite","short_name":"Securite""#));
        assert!(json.ends_with("]}"));
        assert!(json.contains(r#""start_url":"/Securite/""#));
        assert!(json.contains(r#""scope":"/Securite/""#));
        assert!(json.contains(r##""theme_color":"#05060a""##));
        assert!(json.contains(r#""src":"/Securite/static/icon-512.png?v="#));
        assert!(json.contains(r#""purpose":"maskable""#));
        // Balanced braces and brackets, quotes paired: JSON-ish enough without a parser.
        assert_eq!(json.matches('{').count(), json.matches('}').count());
        assert_eq!(json.matches('[').count(), json.matches(']').count());
        assert_eq!(json.matches('"').count() % 2, 0);
    }

    #[test]
    fn the_worker_precaches_pages_and_files_behind_the_base_path() {
        let site = site("/Securite");
        let js = site.service_worker().to_js();
        for url in [
            "\"/Securite/en/\"",
            "\"/Securite/fr/\"",
            "\"/Securite/es/\"",
            "\"/Securite/fr/docs/\"",
            "\"/Securite/static/main.css?v=",
            "\"/Securite/static/icon-192.png?v=",
            "\"/Securite/manifest.webmanifest\"",
        ] {
            assert!(js.contains(url), "{url} not precached");
        }
        assert!(js.contains(r#"const NETWORK_ONLY = ["/Securite/api/"];"#));
        assert!(js.contains(r#"const OFFLINE = "/Securite/en/";"#));
        assert!(js.contains(&format!("\"securite-site-{}\"", site.version())));
        let root = Site::load(&site_dir(), "", None, true)
            .service_worker()
            .to_js();
        assert!(root.contains(r#"const NETWORK_ONLY = ["/api/"];"#));
        assert!(root.contains("\"/en/\""));
    }

    #[test]
    fn public_urls_and_sitemap() {
        let site = site("/Securite");
        assert_eq!(
            site.public_url(Some("evil"), false),
            "https://maxlestage.github.io/Securite"
        );
        let local = Site::load(&site_dir(), "", None, true);
        assert_eq!(local.public_url(Some("x.dev"), true), "https://x.dev");
        assert_eq!(local.public_url(Some("a\"b"), false), "http://localhost");
        let xml = site.sitemap("https://maxlestage.github.io/Securite");
        assert!(xml.contains("<loc>https://maxlestage.github.io/Securite/es/docs/waf/</loc>"));
        assert!(xml.contains(
            r#"hreflang="x-default" href="https://maxlestage.github.io/Securite/en/playground/""#
        ));
        assert_eq!(site.routes().len(), 3 * (3 + crate::docs::slugs().len()));
    }
}
