//! The Content-Security-Policy of the site, shared by the HTTP header (server) and the
//! `<meta>` tag of the static export (GitHub Pages cannot send headers).
//!
//! Strict: no `'unsafe-inline'` for scripts or style sheets. The only inline scripts are
//! the WebAssembly loader written by active and the service worker registration: both are
//! allowed by their SHA-256 hash, like the inline `<style>` of active. WebAssembly needs
//! `'wasm-unsafe-eval'`.

use securite::headers::{ContentSecurityPolicy, src};

/// `'sha256-…'` sources of the inline scripts and styles of `html` that the browser runs.
/// JSON-LD blocks are data, not scripts: they are left out.
pub fn inline_hashes(html: &str) -> (Vec<String>, Vec<String>) {
    let mut executable = String::with_capacity(html.len());
    let mut rest = html;
    const JSON_LD: &str = r#"<script type="application/ld+json">"#;
    while let Some(start) = rest.find(JSON_LD) {
        executable.push_str(&rest[..start]);
        match rest[start..].find("</script>") {
            Some(end) => rest = &rest[start + end + "</script>".len()..],
            None => {
                rest = "";
            }
        }
    }
    executable.push_str(rest);
    (
        ContentSecurityPolicy::hashes_for_inline_scripts(&executable),
        ContentSecurityPolicy::hashes_for_inline_styles(&executable),
    )
}

/// The policy, allowing the given inline script and style hashes.
pub fn policy(scripts: Vec<String>, styles: Vec<String>) -> ContentSecurityPolicy {
    let script_src: Vec<String> = [src::SELF, src::WASM_UNSAFE_EVAL]
        .into_iter()
        .map(String::from)
        .chain(scripts)
        .collect();
    let style_src: Vec<String> = std::iter::once(src::SELF.to_string())
        .chain(styles)
        .collect();
    ContentSecurityPolicy::new()
        .default_src([src::SELF])
        .script_src(script_src)
        .style_src(style_src)
        // Animations set CSS variables through style attributes.
        .style_src_attr([src::UNSAFE_INLINE])
        .img_src([src::SELF, src::DATA])
        .font_src([src::SELF])
        .connect_src([src::SELF])
        // The service worker and the web app manifest.
        .worker_src([src::SELF])
        .manifest_src([src::SELF])
        .object_src([src::NONE])
        .base_uri([src::SELF])
        .form_action([src::SELF])
}

/// The `<meta>` tags replacing the security headers on a static host, inserted right
/// after `<meta charset>` so that they apply to every script and style sheet.
pub fn with_meta_policy(html: &str) -> String {
    let (scripts, styles) = inline_hashes(html);
    // frame-ancestors is ignored in a <meta> policy (browsers warn about it): left out.
    let csp = policy(scripts, styles)
        .upgrade_insecure_requests()
        .to_string();
    let metas = format!(
        r#"<meta http-equiv="Content-Security-Policy" content="{}"/><meta name="referrer" content="strict-origin-when-cross-origin"/>"#,
        csp.replace('&', "&amp;").replace('"', "&quot;")
    );
    const CHARSET: &str = r#"<meta charset="utf-8"/>"#;
    match html.find(CHARSET) {
        Some(i) => {
            let at = i + CHARSET.len();
            format!("{}{metas}{}", &html[..at], &html[at..])
        }
        None => html.replacen("<head>", &format!("<head>{metas}"), 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_ld_is_not_hashed() {
        let html = r#"<head><script type="application/ld+json">{"a":1}</script><script>x()</script><style>a{}</style></head>"#;
        let (scripts, styles) = inline_hashes(html);
        assert_eq!(scripts.len(), 1);
        assert_eq!(styles.len(), 1);
    }

    #[test]
    fn the_meta_policy_comes_first() {
        let html = with_meta_policy(r#"<head><meta charset="utf-8"/><script>x()</script></head>"#);
        assert!(html.starts_with(
            r#"<head><meta charset="utf-8"/><meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-"#
        ));
        assert!(html.contains("upgrade-insecure-requests"));
        assert!(!html.contains("frame-ancestors"));
        assert!(html.contains(r#"<meta name="referrer""#));
    }
}
