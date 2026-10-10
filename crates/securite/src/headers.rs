//! Security response headers (Helmet-like) and Content-Security-Policy builder.
//!
//! Defaults follow the [OWASP Secure Headers Project] recommendations.
//!
//! [OWASP Secure Headers Project]: https://owasp.org/www-project-secure-headers/

use std::time::Duration;

use http::header::{self, HeaderName, HeaderValue};
use http::{request, response};
use sha2::{Digest, Sha256};

use crate::guard::impl_layer;
use crate::util::{b64std, b64url, secure_random};
use crate::{Context, Guard, Rejection, priority};

/// The per-request CSP nonce, inserted in the request extensions when
/// [`ContentSecurityPolicy::with_nonce`] is enabled.
///
/// Use it in your templates: `<script nonce="{{ nonce }}">`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CspNonce(pub String);

/// Well-known CSP source expressions.
pub mod src {
    /// `'self'`
    pub const SELF: &str = "'self'";
    /// `'none'`
    pub const NONE: &str = "'none'";
    /// `'unsafe-inline'` (avoid for scripts)
    pub const UNSAFE_INLINE: &str = "'unsafe-inline'";
    /// `'unsafe-eval'` (avoid)
    pub const UNSAFE_EVAL: &str = "'unsafe-eval'";
    /// `'wasm-unsafe-eval'` – required to instantiate WebAssembly.
    pub const WASM_UNSAFE_EVAL: &str = "'wasm-unsafe-eval'";
    /// `'strict-dynamic'`
    pub const STRICT_DYNAMIC: &str = "'strict-dynamic'";
    /// `'unsafe-hashes'`
    pub const UNSAFE_HASHES: &str = "'unsafe-hashes'";
    /// `data:`
    pub const DATA: &str = "data:";
    /// `blob:`
    pub const BLOB: &str = "blob:";
    /// `https:`
    pub const HTTPS: &str = "https:";
}

/// Builder for a `Content-Security-Policy`.
///
/// ```
/// use securite::headers::{ContentSecurityPolicy, src};
///
/// let csp = ContentSecurityPolicy::strict()
///     .script_src([src::SELF, src::WASM_UNSAFE_EVAL])
///     .img_src([src::SELF, src::DATA, "https://images.example.com"])
///     .with_nonce();
/// assert!(csp.to_string().contains("script-src 'self' 'wasm-unsafe-eval' 'nonce-{nonce}'"));
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentSecurityPolicy {
    directives: Vec<(String, Vec<String>)>,
    nonce: bool,
    report_only: bool,
}

/// Short alias.
pub type Csp = ContentSecurityPolicy;

macro_rules! directive_methods {
    ($($fn:ident => $name:literal),* $(,)?) => {$(
        #[doc = concat!("Sets the `", $name, "` directive.")]
        pub fn $fn<I, S>(self, sources: I) -> Self
        where
            I: IntoIterator<Item = S>,
            S: Into<String>,
        {
            self.directive($name, sources)
        }
    )*};
}

impl ContentSecurityPolicy {
    /// An empty policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// A strict, same-origin policy suitable for most server-rendered apps
    /// and SPAs:
    ///
    /// `default-src 'self'; script-src 'self'; style-src 'self';
    /// img-src 'self' data:; font-src 'self'; connect-src 'self';
    /// object-src 'none'; base-uri 'self'; form-action 'self';
    /// frame-ancestors 'none'; upgrade-insecure-requests`
    pub fn strict() -> Self {
        Self::new()
            .default_src([src::SELF])
            .script_src([src::SELF])
            .style_src([src::SELF])
            .img_src([src::SELF, src::DATA])
            .font_src([src::SELF])
            .connect_src([src::SELF])
            .object_src([src::NONE])
            .base_uri([src::SELF])
            .form_action([src::SELF])
            .frame_ancestors([src::NONE])
            .upgrade_insecure_requests()
    }

    /// A locked-down policy for JSON APIs: `default-src 'none';
    /// frame-ancestors 'none'; base-uri 'none'; form-action 'none'`.
    pub fn api() -> Self {
        Self::new()
            .default_src([src::NONE])
            .frame_ancestors([src::NONE])
            .base_uri([src::NONE])
            .form_action([src::NONE])
    }

    /// Sets (or replaces) any directive.
    ///
    /// # Panics
    ///
    /// If a source contains `;`, `,` or control characters (header injection).
    pub fn directive<I, S>(mut self, name: &str, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let name = name.trim().to_ascii_lowercase();
        assert!(
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid CSP directive name: {name:?}"
        );
        let sources: Vec<String> = sources
            .into_iter()
            .map(|s| {
                let s = s.into();
                assert!(
                    !s.contains([';', ',']) && !s.chars().any(char::is_control),
                    "invalid CSP source expression: {s:?}"
                );
                s
            })
            .collect();
        match self.directives.iter_mut().find(|(n, _)| *n == name) {
            Some((_, existing)) => *existing = sources,
            None => self.directives.push((name, sources)),
        }
        self
    }

    /// Removes a directive (e.g. `upgrade-insecure-requests` for local
    /// development over plain HTTP).
    pub fn remove_directive(mut self, name: &str) -> Self {
        let name = name.trim().to_ascii_lowercase();
        self.directives.retain(|(n, _)| *n != name);
        self
    }

    /// Appends sources to an existing directive (creating it if needed).
    pub fn add_sources<I, S>(mut self, name: &str, sources: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let name = name.trim().to_ascii_lowercase();
        let name = name.as_str();
        let current = self
            .directives
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.clone())
            .unwrap_or_default();
        let mut all = current;
        for s in sources {
            let s = s.into();
            if !all.contains(&s) {
                all.push(s);
            }
        }
        self = self.directive(name, all);
        self
    }

    directive_methods! {
        default_src => "default-src",
        script_src => "script-src",
        script_src_elem => "script-src-elem",
        script_src_attr => "script-src-attr",
        style_src => "style-src",
        style_src_elem => "style-src-elem",
        style_src_attr => "style-src-attr",
        img_src => "img-src",
        font_src => "font-src",
        connect_src => "connect-src",
        media_src => "media-src",
        object_src => "object-src",
        frame_src => "frame-src",
        child_src => "child-src",
        worker_src => "worker-src",
        manifest_src => "manifest-src",
        frame_ancestors => "frame-ancestors",
        base_uri => "base-uri",
        form_action => "form-action",
        sandbox => "sandbox",
        report_to => "report-to",
        report_uri => "report-uri",
    }

    /// Adds `upgrade-insecure-requests`.
    pub fn upgrade_insecure_requests(self) -> Self {
        self.directive("upgrade-insecure-requests", Vec::<String>::new())
    }

    /// Adds `require-trusted-types-for 'script'` (DOM XSS protection).
    pub fn require_trusted_types(self) -> Self {
        self.directive("require-trusted-types-for", ["'script'"])
    }

    /// Generates a fresh nonce for every request and appends
    /// `'nonce-…'` to `script-src` (and `style-src` when present).
    /// The nonce is available as the [`CspNonce`] request extension.
    pub fn with_nonce(mut self) -> Self {
        self.nonce = true;
        self
    }

    /// Sends `Content-Security-Policy-Report-Only` instead (monitoring).
    pub fn report_only(mut self) -> Self {
        self.report_only = true;
        self
    }

    /// Computes `'sha256-…'` sources for every inline `<script>` in `html`.
    ///
    /// Perfect for SPAs whose bundler injects an inline bootstrap script
    /// (Vite …) or a server-rendered WebAssembly loader: hash them at startup and
    /// keep a strict `script-src`.
    pub fn hashes_for_inline_scripts(html: &str) -> Vec<String> {
        inline_tag_contents(html, "script")
            .into_iter()
            .map(|content| format!("'sha256-{}'", b64std(&Sha256::digest(content.as_bytes()))))
            .collect()
    }

    /// Computes `'sha256-…'` sources for every inline `<style>` in `html`.
    pub fn hashes_for_inline_styles(html: &str) -> Vec<String> {
        inline_tag_contents(html, "style")
            .into_iter()
            .map(|content| format!("'sha256-{}'", b64std(&Sha256::digest(content.as_bytes()))))
            .collect()
    }

    fn render(&self) -> String {
        self.render_with(self.nonce)
    }

    fn render_with(&self, nonce: bool) -> String {
        let mut out = String::new();
        for (name, sources) in &self.directives {
            if !out.is_empty() {
                out.push_str("; ");
            }
            out.push_str(name);
            for s in sources {
                out.push(' ');
                out.push_str(s);
            }
            if nonce && (name == "script-src" || name == "style-src" || name == "script-src-elem") {
                out.push_str(" 'nonce-{nonce}'");
            }
        }
        if nonce && !self.directives.iter().any(|(n, _)| n == "script-src") {
            if !out.is_empty() {
                out.push_str("; ");
            }
            // A new script-src overrides default-src: keep its sources.
            out.push_str("script-src");
            if let Some((_, sources)) = self.directives.iter().find(|(n, _)| n == "default-src") {
                for s in sources.iter().filter(|s| *s != "'none'") {
                    out.push(' ');
                    out.push_str(s);
                }
            }
            out.push_str(" 'nonce-{nonce}'");
        }
        out
    }
}

impl std::fmt::Display for ContentSecurityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// Extracts the contents of inline `<tag>` elements (without `src`).
fn inline_tag_contents<'a>(html: &'a str, tag: &str) -> Vec<&'a str> {
    let lower = html.to_ascii_lowercase();
    let open = format!("<{tag}");
    let close = format!("</{tag}");
    let mut out = Vec::new();
    let mut pos = 0;
    while let Some(start) = lower[pos..].find(&open).map(|i| i + pos) {
        let after_name = start + open.len();
        // Make sure we matched the full tag name (`<script>` not `<scripts>`).
        match lower.as_bytes().get(after_name) {
            Some(b'>' | b' ' | b'\t' | b'\n' | b'\r' | b'/') => {}
            _ => {
                pos = after_name;
                continue;
            }
        }
        let Some(tag_end) = lower[after_name..].find('>').map(|i| i + after_name) else {
            break;
        };
        let attrs = &lower[after_name..tag_end];
        let Some(end) = lower[tag_end..].find(&close).map(|i| i + tag_end) else {
            break;
        };
        if !has_attr(attrs, "src") {
            out.push(&html[tag_end + 1..end]);
        }
        pos = end + close.len();
    }
    out
}

fn has_attr(attrs: &str, name: &str) -> bool {
    attrs
        .split(|c: char| c.is_whitespace())
        .any(|a| a == name || a.starts_with(&format!("{name}=")))
}

/// Value of the `Strict-Transport-Security` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hsts {
    /// `max-age`.
    pub max_age: Duration,
    /// `includeSubDomains`.
    pub include_subdomains: bool,
    /// `preload` (only if you submitted your domain to hstspreload.org).
    pub preload: bool,
}

impl Default for Hsts {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(63_072_000), // 2 years
            include_subdomains: true,
            preload: false,
        }
    }
}

impl Hsts {
    fn value(&self) -> HeaderValue {
        let mut v = format!("max-age={}", self.max_age.as_secs());
        if self.include_subdomains {
            v.push_str("; includeSubDomains");
        }
        if self.preload {
            v.push_str("; preload");
        }
        HeaderValue::from_str(&v).expect("valid hsts")
    }
}

const DEFAULT_PERMISSIONS_POLICY: &str = "accelerometer=(), autoplay=(), camera=(), \
display-capture=(), encrypted-media=(), geolocation=(), gyroscope=(), magnetometer=(), \
microphone=(), midi=(), payment=(), picture-in-picture=(), screen-wake-lock=(), usb=(), \
xr-spatial-tracking=()";

const REMOVED: [&str; 5] = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-runtime",
];

/// Adds security headers to every response (Helmet for Rust).
///
/// | Header | Default |
/// |---|---|
/// | `Content-Security-Policy` | [`ContentSecurityPolicy::strict`] |
/// | `Strict-Transport-Security` | `max-age=63072000; includeSubDomains` |
/// | `X-Content-Type-Options` | `nosniff` |
/// | `X-Frame-Options` | `DENY` |
/// | `Referrer-Policy` | `strict-origin-when-cross-origin` |
/// | `Permissions-Policy` | disables camera, mic, geolocation, payment … |
/// | `Cross-Origin-Opener-Policy` | `same-origin` |
/// | `Cross-Origin-Resource-Policy` | `same-origin` |
/// | `Origin-Agent-Cluster` | `?1` |
/// | `X-DNS-Prefetch-Control` | `off` |
/// | `X-Download-Options` | `noopen` |
/// | `X-Permitted-Cross-Domain-Policies` | `none` |
/// | `X-XSS-Protection` | `0` (the legacy auditor is harmful) |
///
/// It also strips `Server`, `X-Powered-By` and friends (fingerprinting).
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    csp: Option<ContentSecurityPolicy>,
    /// (before nonce, after nonce, report-only, policy without nonce)
    csp_parts: Option<(String, String, bool, HeaderValue)>,
    static_headers: Vec<(HeaderName, HeaderValue)>,
    remove: Vec<HeaderName>,
    overwrite: bool,
}

impl Default for SecurityHeaders {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityHeaders {
    /// Recommended defaults (see the table above).
    pub fn new() -> Self {
        let mut s = Self {
            csp: None,
            csp_parts: None,
            static_headers: Vec::new(),
            remove: REMOVED.iter().map(|h| HeaderName::from_static(h)).collect(),
            overwrite: false,
        };
        s = s
            .content_security_policy(ContentSecurityPolicy::strict())
            .hsts(Some(Hsts::default()))
            .set("x-content-type-options", "nosniff")
            .set("x-frame-options", "DENY")
            .set("referrer-policy", "strict-origin-when-cross-origin")
            .set("permissions-policy", DEFAULT_PERMISSIONS_POLICY)
            .set("cross-origin-opener-policy", "same-origin")
            .set("cross-origin-resource-policy", "same-origin")
            .set("origin-agent-cluster", "?1")
            .set("x-dns-prefetch-control", "off")
            .set("x-download-options", "noopen")
            .set("x-permitted-cross-domain-policies", "none")
            .set("x-xss-protection", "0");
        s
    }

    /// Maximum hardening: [`new`](Self::new) plus
    /// `Cross-Origin-Embedder-Policy: require-corp` and
    /// `Referrer-Policy: no-referrer`.
    ///
    /// HSTS `preload` is deliberately **not** enabled: opt in with
    /// `.hsts(Some(Hsts { preload: true, ..Hsts::default() }))` once your
    /// whole domain (and every sub-domain) is HTTPS only.
    pub fn strict() -> Self {
        Self::new()
            .set("cross-origin-embedder-policy", "require-corp")
            .set("referrer-policy", "no-referrer")
    }

    /// For JSON APIs: locked CSP, `Cache-Control: no-store`, `no-referrer`.
    pub fn api() -> Self {
        Self::new()
            .content_security_policy(ContentSecurityPolicy::api())
            .set("referrer-policy", "no-referrer")
            .set("cache-control", "no-store")
    }

    /// Sets (or replaces) a header. Use it for any header not covered by a
    /// dedicated method.
    ///
    /// # Panics
    ///
    /// On an invalid header name or value.
    pub fn set(mut self, name: &str, value: &str) -> Self {
        let name = HeaderName::from_bytes(name.as_bytes()).expect("invalid header name");
        let value = HeaderValue::from_str(value).expect("invalid header value");
        self.static_headers.retain(|(n, _)| *n != name);
        self.static_headers.push((name, value));
        self
    }

    /// Removes a header previously set (e.g. `"x-frame-options"`).
    pub fn unset(mut self, name: &str) -> Self {
        self.static_headers
            .retain(|(n, _)| !n.as_str().eq_ignore_ascii_case(name));
        if name.eq_ignore_ascii_case("content-security-policy") {
            self.csp = None;
            self.csp_parts = None;
        }
        self
    }

    /// Sets the Content-Security-Policy (`None` disables it).
    pub fn content_security_policy(
        mut self,
        csp: impl Into<Option<ContentSecurityPolicy>>,
    ) -> Self {
        self.csp = csp.into();
        self.csp_parts = self.csp.as_ref().map(|csp| {
            let rendered = csp.render();
            let (before, after) = match rendered.split_once("{nonce}") {
                Some((b, a)) => (b.to_owned(), a.to_owned()),
                None => (rendered, String::new()),
            };
            // Used when no nonce was generated (request rejected before the
            // headers guard ran): never send a truncated policy.
            let plain = HeaderValue::from_str(&csp.render_with(false)).expect("invalid CSP");
            (before, after, csp.report_only, plain)
        });
        if let Some((b, a, _, _)) = &self.csp_parts {
            // Validate eagerly so a bad policy panics at startup, not per request.
            HeaderValue::from_str(&format!("{b}{a}")).expect("invalid CSP");
        }
        self
    }

    /// Alias of [`content_security_policy`](Self::content_security_policy).
    pub fn csp(self, csp: impl Into<Option<ContentSecurityPolicy>>) -> Self {
        self.content_security_policy(csp)
    }

    /// Configures HSTS (`None` disables it, e.g. for plain-HTTP local dev).
    pub fn hsts(self, hsts: Option<Hsts>) -> Self {
        match hsts {
            Some(h) => {
                let v = h.value();
                self.set("strict-transport-security", v.to_str().unwrap_or_default())
            }
            None => self.unset("strict-transport-security"),
        }
    }

    /// `X-Frame-Options` value (`DENY` or `SAMEORIGIN`).
    pub fn frame_options(self, value: &str) -> Self {
        self.set("x-frame-options", value)
    }

    /// `Referrer-Policy` value.
    pub fn referrer_policy(self, value: &str) -> Self {
        self.set("referrer-policy", value)
    }

    /// `Permissions-Policy` value.
    pub fn permissions_policy(self, value: &str) -> Self {
        self.set("permissions-policy", value)
    }

    /// `Cross-Origin-Embedder-Policy` value (`require-corp`, `credentialless`).
    pub fn cross_origin_embedder_policy(self, value: &str) -> Self {
        self.set("cross-origin-embedder-policy", value)
    }

    /// `Cross-Origin-Opener-Policy` value.
    pub fn cross_origin_opener_policy(self, value: &str) -> Self {
        self.set("cross-origin-opener-policy", value)
    }

    /// `Cross-Origin-Resource-Policy` value (`same-origin`, `same-site`,
    /// `cross-origin`).
    pub fn cross_origin_resource_policy(self, value: &str) -> Self {
        self.set("cross-origin-resource-policy", value)
    }

    /// `Cache-Control` value.
    pub fn cache_control(self, value: &str) -> Self {
        self.set("cache-control", value)
    }

    /// Overwrite headers already set by your handlers (default: `false`, a
    /// handler can always relax a header for a specific route).
    pub fn overwrite(mut self, overwrite: bool) -> Self {
        self.overwrite = overwrite;
        self
    }

    /// Keep the `Server` / `X-Powered-By` headers.
    pub fn keep_fingerprinting_headers(mut self) -> Self {
        self.remove.clear();
        self
    }

    /// The configured CSP, if any.
    pub fn policy(&self) -> Option<&ContentSecurityPolicy> {
        self.csp.as_ref()
    }

    fn put(&self, headers: &mut http::HeaderMap, name: HeaderName, value: HeaderValue) {
        if self.overwrite {
            headers.insert(name, value);
        } else if let header::Entry::Vacant(e) = headers.entry(name) {
            e.insert(value);
        }
    }
}

impl Guard for SecurityHeaders {
    fn name(&self) -> &'static str {
        "security_headers"
    }

    fn priority(&self) -> u16 {
        priority::HEADERS
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        if self.csp.as_ref().is_some_and(|c| c.nonce) {
            let mut raw = [0u8; 16];
            secure_random(&mut raw);
            let nonce = b64url(&raw);
            req.extensions.insert(CspNonce(nonce.clone()));
            ctx.csp_nonce = Some(nonce);
        }
        Ok(())
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        for name in &self.remove {
            res.headers.remove(name);
        }
        for (name, value) in &self.static_headers {
            self.put(&mut res.headers, name.clone(), value.clone());
        }
        if let Some((before, after, report_only, plain)) = &self.csp_parts {
            let name = if *report_only {
                HeaderName::from_static("content-security-policy-report-only")
            } else {
                header::CONTENT_SECURITY_POLICY
            };
            let value = match (&ctx.csp_nonce, after.is_empty()) {
                (Some(nonce), false) => {
                    let full = format!("{before}{nonce}{}", after.replace("{nonce}", nonce));
                    HeaderValue::from_str(&full).ok()
                }
                (_, true) => HeaderValue::from_str(before).ok(),
                (None, false) => Some(plain.clone()),
            };
            if let Some(v) = value {
                self.put(&mut res.headers, name, v);
            }
        }
    }
}

impl_layer!(SecurityHeaders);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csp_render() {
        let csp = Csp::strict();
        let s = csp.to_string();
        assert!(s.starts_with("default-src 'self'; script-src 'self'"));
        assert!(s.ends_with("upgrade-insecure-requests"));
        let s = Csp::new().script_src([src::SELF]).with_nonce().to_string();
        assert_eq!(s, "script-src 'self' 'nonce-{nonce}'");
    }

    #[test]
    fn csp_without_nonce_is_complete() {
        let h = SecurityHeaders::new().csp(Csp::strict().with_nonce());
        let (mut res, ()) = http::Response::new(()).into_parts();
        let ctx = Context::new(http::Method::GET, http::Uri::from_static("/"), None);
        h.on_response(&mut res, &ctx);
        let v = res.headers["content-security-policy"].to_str().unwrap();
        assert!(!v.contains("nonce"), "{v}");
        assert!(v.ends_with("upgrade-insecure-requests"), "{v}");
        let s = Csp::new().default_src([src::SELF]).with_nonce().to_string();
        assert_eq!(s, "default-src 'self'; script-src 'self' 'nonce-{nonce}'");
        let s = Csp::strict()
            .remove_directive("Upgrade-Insecure-Requests")
            .to_string();
        assert!(!s.contains("upgrade"));
    }

    #[test]
    fn csp_replace_and_add() {
        let csp = Csp::strict()
            .script_src(["'self'", "https://cdn.example.com"])
            .add_sources("img-src", ["blob:"]);
        let s = csp.to_string();
        assert!(s.contains("script-src 'self' https://cdn.example.com;"));
        assert!(s.contains("img-src 'self' data: blob:"));
    }

    #[test]
    #[should_panic(expected = "invalid CSP source")]
    fn csp_injection_rejected() {
        let _ = Csp::new().script_src(["'self'; report-uri https://evil"]);
    }

    #[test]
    fn inline_script_hashes() {
        let html = r#"<html><head><script type="module">import init from '/app.js';init();</script>
        <script src="/x.js"></script><scripts>no</scripts><style>body{}</style></head></html>"#;
        let hashes = Csp::hashes_for_inline_scripts(html);
        assert_eq!(hashes.len(), 1);
        let expected = format!(
            "'sha256-{}'",
            b64std(&Sha256::digest(b"import init from '/app.js';init();"))
        );
        assert_eq!(hashes[0], expected);
        assert_eq!(Csp::hashes_for_inline_styles(html).len(), 1);
    }
}
