//! `securite-server export <dir>`: the whole site as static files, for GitHub Pages or
//! any static host. The pages come from the same code as the server's.
//!
//! What a static host cannot do is replaced: the security headers by a strict
//! Content-Security-Policy `<meta>` tag (inline scripts allowed by hash), the language
//! detection of `/` by a page linking the three languages, and the live playground by a
//! notice that it needs the server. `404.html` is the English "not found" page.

use std::io;
use std::path::Path;

use securite_site::i18n::Lang;
use securite_site::render::{Site, pages, site_dir};
use securite_site::routes::{Page, Route};

/// Writes the site into `out`, links behind `base` (`""` or `/Securite`), absolute URLs
/// (canonical, sitemap, Open Graph) on `site_url`. Returns the number of files written.
pub fn export(out: &Path, base: &str, site_url: Option<String>) -> io::Result<usize> {
    let site = Site::load(&site_dir(), base, site_url, false);
    if !site.has_bundle() {
        eprintln!(
            "warning: site/pkg is missing, the pages will not be interactive (see CONTRIBUTING.md)"
        );
    }
    if site.site_url.is_none() {
        eprintln!("warning: SITE_URL is not set, absolute URLs use http://localhost");
    }
    let public = site.public_url(None, false);
    let mut written = 0;
    let mut write = |path: &str, bytes: &[u8]| -> io::Result<()> {
        let file = out.join(path.trim_start_matches('/'));
        if let Some(dir) = file.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(file, bytes)?;
        written += 1;
        Ok(())
    };
    let page = |route: &Route| crate::csp::with_meta_policy(&site.page(route, &public));

    for route in site.routes() {
        write(
            &format!("{}index.html", route.path()),
            page(&route).as_bytes(),
        )?;
    }
    // The visitor's language, chosen in the browser: at the root and on a missing address
    // (the static host serves `404.html`), then the "not found" page of each language.
    for (file, target) in [("index.html", ""), ("404.html", "404/")] {
        let html = pages::language_picker(&site, &public, target);
        write(file, crate::csp::with_meta_policy(&html).as_bytes())?;
    }
    for lang in Lang::ALL {
        write(
            &format!("{}/404/index.html", lang.code()),
            page(&Route::new(lang, Page::NotFound)).as_bytes(),
        )?;
    }
    write("manifest.webmanifest", site.manifest().to_json().as_bytes())?;
    write("sw.js", site.service_worker().to_js().as_bytes())?;
    write("sitemap.xml", site.sitemap(&public).as_bytes())?;
    write("robots.txt", site.robots(&public).as_bytes())?;
    for (url, asset) in site.assets.iter() {
        write(url, &asset.bytes)?;
    }
    if let Some(icon) = site.assets.get("/static/favicon.svg") {
        write("favicon.svg", &icon.bytes)?;
    }
    // Files are served as they are: no Jekyll processing on GitHub Pages.
    write(".nojekyll", b"")?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exports_every_page_behind_the_base_path_with_a_meta_policy() {
        let dir = std::env::temp_dir().join(format!("securite-export-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let files = export(
            &dir,
            "/Securite",
            Some("https://maxlestage.github.io/Securite".into()),
        )
        .unwrap();
        assert!(files > 100, "{files} files");
        let read = |p: &str| std::fs::read_to_string(dir.join(p)).unwrap();

        let home = read("fr/index.html");
        assert!(home.contains(r#"<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-"#));
        let (scripts, styles) = crate::csp::inline_hashes(&home);
        for hash in scripts.iter().chain(&styles) {
            assert!(home.contains(hash.as_str()), "{hash}");
        }
        assert!(home.contains(r#"href="/Securite/fr/docs/waf/""#));
        assert!(home.contains(
            r#"<link rel="canonical" href="https://maxlestage.github.io/Securite/fr/"/>"#
        ));
        assert!(home.contains(r#"navigator.serviceWorker.register("/Securite/sw.js")"#));

        let playground = read("en/playground/index.html");
        assert!(playground.contains("lab-static"));
        assert!(read("es/docs/waf/index.html").contains("(WAF)</h1>"));
        assert!(read("404.html").contains("navigator.languages"));
        assert!(read("fr/404/index.html").contains("404"));
        assert!(read("index.html").contains("navigator.languages"));
        assert!(read("index.html").contains(r#"url=/Securite/en/"#));
        assert!(read("manifest.webmanifest").contains(r#""start_url":"/Securite/""#));
        let worker = read("sw.js");
        assert!(worker.contains(r#""/Securite/fr/""#));
        assert!(worker.contains(r#"const NETWORK_ONLY = ["/Securite/api/"];"#));
        assert!(
            read("sitemap.xml").contains("https://maxlestage.github.io/Securite/en/docs/csrf/")
        );
        assert!(dir.join("static/main.css").exists());
        assert!(dir.join("static/icon-512.png").exists());
        assert!(dir.join(".nojekyll").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
