//! The application: pages rendered by `securite-site`, static files, the web app manifest,
//! the service worker and the live attack playground API, all behind a `securite` shield.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use securite::headers::Hsts;
use securite::prelude::*;
use securite_site::i18n::Lang;
use securite_site::render::Site;
use securite_site::routes::{Page, Route};
use tower_http::compression::CompressionLayer;

#[derive(Clone)]
pub struct AppState {
    shield: Shield,
    site: Arc<Site>,
    manifest: Arc<str>,
    worker: Arc<str>,
}

/// Builds the shield protecting this very website.
pub fn shield(production: bool, scripts: Vec<String>, styles: Vec<String>) -> Shield {
    let mut csp = crate::csp::policy(scripts, styles).frame_ancestors(["'none'"]);
    if production {
        // Would break plain http://localhost during development.
        csp = csp.upgrade_insecure_requests();
    }
    let headers = SecurityHeaders::new()
        .cross_origin_embedder_policy("require-corp")
        .hsts(production.then(Hsts::default))
        .csp(csp);

    let mut builder = Shield::builder()
        .client_ip(if production {
            ClientIpSource::heroku()
        } else {
            ClientIpSource::Peer
        })
        .guard(RequestId::new())
        .guard(Hygiene::new())
        .guard(MethodFilter::only([
            axum::http::Method::GET,
            axum::http::Method::HEAD,
            axum::http::Method::OPTIONS,
        ]))
        .guard(BodyLimit::new(16 * 1024))
        .guard(
            RateLimit::new(Quota::per_second(30).burst(150))
                .route("/api/demo", Quota::per_minute(60).burst(20)),
        )
        .guard(ConcurrencyLimit::per_ip(64))
        .guard(AutoBan::new().max_strikes(30).ignore_paths(["/api/demo"]))
        .guard(BotBlocker::new())
        .guard(Waf::new())
        .guard(Csrf::new())
        .guard(headers)
        .guard(CookieHardening::new());
    if production {
        builder = builder.guard(HttpsRedirect::new().exempt("/api/health"));
    }
    builder.build()
}

/// The whole application (routes + shield).
pub fn app(site: Arc<Site>, production: bool) -> Router {
    // Every page has the same inline scripts (WebAssembly loader, service worker
    // registration) and style: hash them once.
    let sample = site.page(&Route::new(Lang::En, Page::Home), "http://localhost");
    let (scripts, styles) = crate::csp::inline_hashes(&sample);
    tracing::info!(
        inline_scripts = scripts.len(),
        inline_styles = styles.len(),
        production,
        bundle = site.has_bundle(),
        "CSP hashes computed"
    );
    let shield = shield(production, scripts, styles);
    tracing::info!(guards = ?shield.guard_names(), "shield ready");
    routes(site, shield.clone())
        .layer(CompressionLayer::new())
        .layer(shield)
}

/// The routes, without the shield.
pub fn routes(site: Arc<Site>, shield: Shield) -> Router {
    let state = AppState {
        shield,
        manifest: site.manifest().to_json().into(),
        worker: site.service_worker().to_js().into(),
        site,
    };
    Router::new()
        .route("/", get(root))
        .route("/index.html", get(root))
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/stats", get(stats))
        .route("/api/demo", get(demo))
        .route("/manifest.webmanifest", get(manifest))
        .route("/sw.js", get(service_worker))
        .route("/sitemap.xml", get(sitemap))
        .route("/robots.txt", get(robots))
        .route("/favicon.svg", get(favicon))
        .route("/static/{*path}", get(file))
        .route("/pkg/{*path}", get(file))
        .fallback(get(page))
        .with_state(state)
}

/// Preferred supported language from `Accept-Language`, English by default.
pub fn pick_lang(headers: &HeaderMap) -> Lang {
    let header = headers
        .get(header::ACCEPT_LANGUAGE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let mut ranked: Vec<(Lang, f32)> = header
        .split(',')
        .filter_map(|part| {
            let mut pieces = part.trim().split(";q=");
            let lang = Lang::from_code(pieces.next()?)?;
            let q = pieces
                .next()
                .and_then(|q| q.trim().parse().ok())
                .unwrap_or(1.0);
            Some((lang, q))
        })
        .filter(|(_, q)| *q > 0.0)
        .collect();
    ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
    ranked.first().map_or(Lang::En, |r| r.0)
}

fn public_url(site: &Site, headers: &HeaderMap) -> String {
    let get = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
    };
    let host = get("x-forwarded-host").or_else(|| get("host"));
    let https = get("x-forwarded-proto").as_deref() == Some("https");
    site.public_url(host.as_deref(), https)
}

fn redirect(status: StatusCode, location: String) -> Response {
    let mut res = (status, [(header::LOCATION, location)]).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    res
}

/// `/`: the home page in the visitor's language.
async fn root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let lang = pick_lang(&headers);
    let mut res = redirect(
        StatusCode::FOUND,
        Route::new(lang, Page::Home).href(&state.site.base),
    );
    res.headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Accept-Language"));
    res
}

fn html(status: StatusCode, body: String) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

/// Every page: `/{lang}/`, `/{lang}/docs/`, `/{lang}/docs/{slug}/`, `/{lang}/playground/`,
/// the addresses of the previous version of the site (redirected), or a 404.
async fn page(State(state): State<AppState>, uri: Uri, headers: HeaderMap) -> Response {
    let site = &state.site;
    let path = uri.path();
    let query = uri.query().map(|q| format!("?{q}")).unwrap_or_default();
    let route = match site.route(path) {
        Some(route) => route,
        None => {
            let lang = pick_lang(&headers);
            // Links to the previous single-page app: /docs, /docs/waf, /playground.
            let legacy = path == "/docs"
                || path.starts_with("/docs/")
                || path.trim_end_matches('/') == "/playground";
            if legacy {
                let path = path.trim_end_matches('/');
                return redirect(
                    StatusCode::MOVED_PERMANENTLY,
                    format!("{}/{}{path}/{query}", site.base, lang.code()),
                );
            }
            Route::new(lang, Page::NotFound)
        }
    };
    if route.page != Page::NotFound && !path.ends_with('/') {
        return redirect(
            StatusCode::MOVED_PERMANENTLY,
            format!("{}{path}/{query}", site.base),
        );
    }
    let status = if route.page == Page::NotFound {
        StatusCode::NOT_FOUND
    } else {
        StatusCode::OK
    };
    html(status, site.page(&route, &public_url(site, &headers)))
}

fn asset(site: &Site, url: &str, uri: &Uri) -> Response {
    match site.assets.get(url) {
        Some(a) => {
            let cache = if uri.query().is_some_and(|q| q.starts_with("v=")) {
                "public, max-age=31536000, immutable"
            } else {
                "public, max-age=3600"
            };
            (
                [
                    (header::CONTENT_TYPE, a.content_type),
                    (header::CACHE_CONTROL, cache),
                ],
                a.bytes.clone(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn file(State(state): State<AppState>, uri: Uri) -> Response {
    asset(&state.site, uri.path(), &uri)
}

async fn favicon(State(state): State<AppState>, uri: Uri) -> Response {
    asset(&state.site, "/static/favicon.svg", &uri)
}

async fn manifest(State(state): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        state.manifest.to_string(),
    )
        .into_response()
}

async fn service_worker(State(state): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        state.worker.to_string(),
    )
        .into_response()
}

async fn sitemap(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let public = public_url(&state.site, &headers);
    (
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        state.site.sitemap(&public),
    )
        .into_response()
}

async fn robots(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let public = public_url(&state.site, &headers);
    (
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        state.site.robots(&public),
    )
        .into_response()
}

async fn stats(State(state): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        state.shield.stats().to_json(),
    )
        .into_response()
}

/// Playground endpoint: if the WAF lets the payload through, echo it back.
async fn demo(Query(params): Query<std::collections::HashMap<String, String>>) -> Response {
    let payload = params.get("payload").cloned().unwrap_or_default();
    let body = serde_json::json!({
        "status": "allowed",
        "message": "No attack detected: the request reached the application.",
        "payload": payload,
    });
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        body.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use securite_site::render::site_dir;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn test_app(production: bool) -> Router {
        app(
            Arc::new(Site::load(&site_dir(), "", None, true)),
            production,
        )
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let mut req = req;
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [203, 0, 113, 7],
                4000,
            ))));
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8_lossy(&body).into_owned())
    }

    async fn get(app: &Router, uri: &str) -> (StatusCode, HeaderMap, String) {
        send(
            app,
            Request::builder().uri(uri).body(Body::empty()).unwrap(),
        )
        .await
    }

    #[tokio::test]
    async fn pages_have_a_strict_csp_allowing_their_inline_scripts() {
        let app = test_app(false);
        let (status, h, body) = get(&app, "/fr/docs/waf/").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["content-type"], "text/html; charset=utf-8");
        assert!(body.contains("<h1>Pare-feu applicatif (WAF)</h1>"));
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("'wasm-unsafe-eval'"), "{csp}");
        assert!(!csp.contains("'unsafe-inline' "), "{csp}");
        assert!(csp.contains("worker-src 'self'"), "{csp}");
        assert!(csp.contains("manifest-src 'self'"), "{csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        // Every script and style the browser runs on this page is allowed by hash.
        let (scripts, styles) = crate::csp::inline_hashes(&body);
        assert!(!scripts.is_empty() && !styles.is_empty());
        for hash in scripts.iter().chain(&styles) {
            assert!(csp.contains(hash.as_str()), "{hash} missing from {csp}");
        }
        assert!(
            !csp.contains("upgrade-insecure-requests"),
            "dev mode: {csp}"
        );
        assert!(
            !h.contains_key("strict-transport-security"),
            "no HSTS in dev"
        );
        assert_eq!(h["cross-origin-embedder-policy"], "require-corp");
    }

    #[tokio::test]
    async fn every_page_passes_the_shield() {
        let site = Arc::new(Site::load(&site_dir(), "", None, true));
        let app = app(site.clone(), false);
        for route in site.routes() {
            let (status, _, body) = get(&app, &route.path()).await;
            assert_eq!(status, StatusCode::OK, "{}", route.path());
            assert!(body.contains("</html>"), "{}", route.path());
        }
        let (status, _, body) = get(&app, "/es/nope/").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.contains(r#"<html lang="es">"#));
    }

    #[tokio::test]
    async fn redirects_to_the_language_and_the_canonical_address() {
        let app = test_app(false);
        let req = Request::builder()
            .uri("/")
            .header("accept-language", "de-DE, fr;q=0.9, en;q=0.8")
            .body(Body::empty())
            .unwrap();
        let (status, h, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::FOUND);
        assert_eq!(h["location"], "/fr/");
        let (status, h, _) = get(&app, "/en/docs/waf").await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(h["location"], "/en/docs/waf/");
        // Addresses of the previous single-page app.
        let (status, h, _) = get(&app, "/docs/rate-limit").await;
        assert_eq!(status, StatusCode::MOVED_PERMANENTLY);
        assert_eq!(h["location"], "/en/docs/rate-limit/");
        let (_, h, _) = get(&app, "/playground").await;
        assert_eq!(h["location"], "/en/playground/");
    }

    #[tokio::test]
    async fn serves_the_manifest_the_worker_and_the_files() {
        let app = test_app(false);
        let (status, h, body) = get(&app, "/manifest.webmanifest").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["content-type"], "application/manifest+json");
        assert!(body.starts_with(r#"{"name":"securite""#));
        let (status, h, body) = get(&app, "/sw.js").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["content-type"], "text/javascript; charset=utf-8");
        assert_eq!(h["cache-control"], "no-cache");
        assert!(body.contains(r#"const NETWORK_ONLY = ["/api/"];"#));
        let (status, h, _) = get(&app, "/static/icon-192.png?v=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["content-type"], "image/png");
        assert_eq!(h["cache-control"], "public, max-age=31536000, immutable");
        let (status, h, _) = get(&app, "/static/main.css").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(h["content-type"], "text/css; charset=utf-8");
        assert_eq!(get(&app, "/favicon.svg").await.0, StatusCode::OK);
        assert_eq!(get(&app, "/static/nope.css").await.0, StatusCode::NOT_FOUND);
        let (_, _, robots) = get(&app, "/robots.txt").await;
        assert!(robots.contains("Sitemap: http://localhost/sitemap.xml"));
        let (_, h, xml) = get(&app, "/sitemap.xml").await;
        assert_eq!(h["content-type"], "application/xml; charset=utf-8");
        assert!(xml.contains("<loc>http://localhost/fr/playground/</loc>"));
    }

    #[tokio::test]
    async fn demo_blocks_attacks_and_counts_them() {
        let app = test_app(false);
        let (status, _, body) = get(&app, "/api/demo?payload=hello").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("\"allowed\""));
        let (status, h, body) =
            get(&app, "/api/demo?payload=%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(h["content-type"], "application/problem+json");
        assert!(body.contains("waf_blocked"));
        let (_, _, stats) = get(&app, "/api/stats").await;
        assert!(stats.contains("\"blocked\":1"), "{stats}");
    }

    #[tokio::test]
    async fn production_mode_redirects_and_sets_hsts() {
        let app = test_app(true);
        let req = Request::builder()
            .uri("/en/docs/")
            .header("host", "securite.example")
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-for", "198.51.100.4")
            .body(Body::empty())
            .unwrap();
        let (status, h, _) = send(&app, req).await;
        assert_eq!(status, StatusCode::PERMANENT_REDIRECT);
        assert_eq!(h["location"], "https://securite.example/en/docs/");
        let req = Request::builder()
            .uri("/en/")
            .header("host", "securite.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "198.51.100.4")
            .body(Body::empty())
            .unwrap();
        let (status, h, body) = send(&app, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            h["strict-transport-security"]
                .to_str()
                .unwrap()
                .contains("max-age")
        );
        assert!(
            h["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("upgrade-insecure-requests")
        );
        assert!(body.contains(r#"<link rel="canonical" href="https://securite.example/en/"/>"#));
    }
}
