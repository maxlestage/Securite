//! The application: pages rendered by `securite-site`, static files, the web app manifest,
//! the service worker and the live attack playground API, all behind a `securite` shield.

use std::sync::Arc;

use securite::headers::Hsts;
use securite::prelude::*;
use securite_site::i18n::Lang;
use securite_site::render::Site;
use securite_site::routes::{Page, Route};
use vitesse::prelude::*;

/// What every handler needs.
pub struct AppState {
    shield: Shield,
    site: Arc<Site>,
    manifest: String,
    worker: String,
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
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
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

/// Adds the shield (outermost), the compression and the routes to `app`.
pub fn install(app: &mut App, site: Arc<Site>, production: bool) {
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
    // The shield sees every request first, and decorates every response last.
    app.middleware(shield.clone());
    app.middleware(middleware::compress());
    routes(app, site, shield);
}

/// The routes, without the shield.
pub fn routes(app: &mut App, site: Arc<Site>, shield: Shield) {
    let state = Arc::new(AppState {
        shield,
        manifest: site.manifest().to_json(),
        worker: site.service_worker().to_js(),
        site,
    });
    route(app, "/", &state, root);
    route(app, "/index.html", &state, root);
    app.get("/api/health", |_req: Request| async { "ok" });
    route(app, "/api/stats", &state, stats);
    app.get("/api/demo", demo);
    route(app, "/manifest.webmanifest", &state, manifest);
    route(app, "/sw.js", &state, service_worker);
    route(app, "/sitemap.xml", &state, sitemap);
    route(app, "/robots.txt", &state, robots);
    route(app, "/favicon.svg", &state, favicon);
    route(app, "/static/*path", &state, file);
    route(app, "/pkg/*path", &state, file);
    app.fallback(move |req: Request| {
        let state = state.clone();
        async move { page(&state, &req) }
    });
}

/// Routes a handler that only needs the state and the request.
fn route(
    app: &mut App,
    path: &str,
    state: &Arc<AppState>,
    handler: fn(&AppState, &Request) -> Response,
) {
    let state = state.clone();
    app.get(path, move |req: Request| {
        let state = state.clone();
        async move { handler(&state, &req) }
    });
}

/// Preferred supported language from `Accept-Language`, English by default.
pub fn pick_lang(req: &Request) -> Lang {
    let header = req.header("accept-language").unwrap_or("");
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

fn public_url(site: &Site, req: &Request) -> String {
    let get = |name: &str| {
        req.header(name)
            .map(|v| v.split(',').next().unwrap_or("").trim().to_string())
    };
    let host = get("x-forwarded-host").or_else(|| get("host"));
    let https = get("x-forwarded-proto").as_deref() == Some("https");
    site.public_url(host.as_deref(), https)
}

fn redirect(status: u16, location: String) -> Response {
    res::status(status)
        .header("location", location)
        .header("cache-control", "no-cache")
}

/// `/`: the home page in the visitor's language.
fn root(state: &AppState, req: &Request) -> Response {
    let lang = pick_lang(req);
    redirect(302, Route::new(lang, Page::Home).href(&state.site.base))
        .header("vary", "Accept-Language")
}

fn html(status: u16, body: String) -> Response {
    res::status(status)
        .header("cache-control", "no-cache")
        .html(body)
}

/// Every page: `/{lang}/`, `/{lang}/docs/`, `/{lang}/docs/{slug}/`, `/{lang}/playground/`,
/// the addresses of the previous version of the site (redirected), or a 404.
fn page(state: &AppState, req: &Request) -> Response {
    let site = &state.site;
    let path = req.path();
    let query = req
        .query_string()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let route = match site.route(path) {
        Some(route) => route,
        None => {
            let lang = pick_lang(req);
            // Links to the previous single-page app: /docs, /docs/waf, /playground.
            let legacy = path == "/docs"
                || path.starts_with("/docs/")
                || path.trim_end_matches('/') == "/playground";
            if legacy {
                let path = path.trim_end_matches('/');
                return redirect(301, format!("{}/{}{path}/{query}", site.base, lang.code()));
            }
            Route::new(lang, Page::NotFound)
        }
    };
    if route.page != Page::NotFound && !path.ends_with('/') {
        return redirect(301, format!("{}{path}/{query}", site.base));
    }
    let status = if route.page == Page::NotFound {
        404
    } else {
        200
    };
    html(status, site.page(&route, &public_url(site, req)))
}

/// A static file by its URL. Versioned URLs (`?v=`) never change: browsers keep them a year.
fn asset(site: &Site, url: &str, req: &Request) -> Response {
    match site.assets.get(url) {
        Some(a) => {
            let cache = if req.query_string().is_some_and(|q| q.starts_with("v=")) {
                "public, max-age=31536000, immutable"
            } else {
                "public, max-age=3600"
            };
            res::send(a.bytes.clone())
                .header("content-type", a.content_type)
                .header("cache-control", cache)
        }
        None => res::status(404),
    }
}

fn file(state: &AppState, req: &Request) -> Response {
    asset(&state.site, req.path(), req)
}

fn favicon(state: &AppState, req: &Request) -> Response {
    asset(&state.site, "/static/favicon.svg", req)
}

fn manifest(state: &AppState, _req: &Request) -> Response {
    res::send(state.manifest.clone())
        .header("content-type", "application/manifest+json")
        .header("cache-control", "no-cache")
}

fn service_worker(state: &AppState, _req: &Request) -> Response {
    res::send(state.worker.clone())
        .header("content-type", "text/javascript; charset=utf-8")
        .header("cache-control", "no-cache")
}

fn sitemap(state: &AppState, req: &Request) -> Response {
    let public = public_url(&state.site, req);
    res::send(state.site.sitemap(&public)).header("content-type", "application/xml; charset=utf-8")
}

fn robots(state: &AppState, req: &Request) -> Response {
    let public = public_url(&state.site, req);
    res::text(state.site.robots(&public))
}

/// `/api/stats`: the live counters of the shield.
fn stats(state: &AppState, _req: &Request) -> Response {
    res::send(state.shield.stats().to_json())
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
}

/// Playground endpoint: if the WAF lets the payload through, echo it back.
async fn demo(req: Request) -> Response {
    let payload = req
        .query("payload")
        .map(|p| p.into_owned())
        .unwrap_or_default();
    let body = serde_json::json!({
        "status": "allowed",
        "message": "No attack detected: the request reached the application.",
        "payload": payload,
    });
    res::json(body).header("cache-control", "no-store")
}

#[cfg(test)]
mod tests {
    use super::*;
    use securite_site::render::site_dir;
    use vitesse::test::{TestClient, TestResponse};

    fn client_for(site: Arc<Site>, production: bool) -> TestClient {
        let mut app = App::new();
        install(&mut app, site, production);
        TestClient::new(app)
    }

    fn test_app(production: bool) -> TestClient {
        client_for(
            Arc::new(Site::load(&site_dir(), "", None, true)),
            production,
        )
    }

    fn h<'a>(res: &'a TestResponse, name: &str) -> &'a str {
        res.header(name).unwrap_or("")
    }

    async fn get(client: &TestClient, uri: &str) -> TestResponse {
        client.get(uri).await
    }

    #[tokio::test]
    async fn pages_have_a_strict_csp_allowing_their_inline_scripts() {
        let client = test_app(false);
        let res = get(&client, "/fr/docs/waf/").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(h(&res, "content-type"), "text/html; charset=utf-8");
        let body = res.text();
        assert!(body.contains("<h1>Pare-feu applicatif (WAF)</h1>"));
        let csp = h(&res, "content-security-policy");
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
            res.header("strict-transport-security").is_none(),
            "no HSTS in dev"
        );
        assert_eq!(h(&res, "cross-origin-embedder-policy"), "require-corp");
        assert!(res.header("x-request-id").is_some());
    }

    #[tokio::test]
    async fn pages_are_compressed_for_browsers_that_accept_it() {
        let client = test_app(false);
        let res = client
            .get("/en/")
            .header("accept-encoding", "gzip, br")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(h(&res, "content-encoding"), "br");
        assert!(
            h(&res, "vary").contains("accept-encoding"),
            "{}",
            h(&res, "vary")
        );
        // Still decorated by the shield.
        assert_eq!(h(&res, "x-frame-options"), "DENY");
    }

    #[tokio::test]
    async fn every_page_ends_with_the_signature_footer() {
        let client = test_app(false);
        for (lang, rights, here) in [
            ("fr", "Tous droits réservés", "Vous êtes ici"),
            ("en", "All rights reserved", "You are here"),
            ("es", "Todos los derechos reservados", "Estás aquí"),
        ] {
            let res = get(&client, &format!("/{lang}/")).await;
            assert_eq!(res.status(), StatusCode::OK, "{lang}");
            let body = res.text();
            let footer = body.split("<footer").nth(1).expect("a footer");
            // The author's signature, the legal line and the license.
            assert!(footer.contains(r#"class="credits-name""#), "{lang}");
            assert!(footer.contains("Maxime Nathan Lestage"), "{lang}");
            assert!(footer.contains(rights), "{lang}");
            assert!(footer.contains(r#"href="/static/LICENSE.txt""#), "{lang}");
            // No link to GitHub anywhere: the project is not open source.
            assert!(!body.contains("github.com"), "{lang}");
            assert!(!footer.contains("MIT"), "{lang}");
            // The install command and the version of the crate.
            assert!(footer.contains("cargo add securite"), "{lang}");
            assert!(
                footer.contains(&format!("v{}", securite::VERSION)),
                "{lang}"
            );
            // The six projects of the ecosystem, this one marked as the current page.
            for project in [
                "Active",
                "Vitesse",
                "Securite",
                "Memoire",
                "Paquets",
                "FerroSwift",
            ] {
                assert!(
                    footer.contains(&format!(
                        r#"href="https://maxlestage.github.io/{project}/""#
                    )),
                    "{lang} {project}"
                );
            }
            assert!(footer.contains(r#"aria-current="page""#), "{lang}");
            assert!(footer.contains(here), "{lang}");
            // The author is named in the metadata too.
            assert!(
                body.contains(r#"content="Maxime Nathan Lestage""#),
                "{lang}"
            );
        }
        // The license is served by the site, identical to the repository's.
        let res = get(&client, "/static/LICENSE.txt").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.text(), include_str!("../../LICENSE"));
    }

    #[tokio::test]
    async fn every_page_passes_the_shield() {
        let site = Arc::new(Site::load(&site_dir(), "", None, true));
        let client = client_for(site.clone(), false);
        for route in site.routes() {
            let res = get(&client, &route.path()).await;
            assert_eq!(res.status(), StatusCode::OK, "{}", route.path());
            assert!(res.text().contains("</html>"), "{}", route.path());
        }
        let res = get(&client, "/es/nope/").await;
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
        assert!(res.text().contains(r#"<html lang="es">"#));
    }

    #[tokio::test]
    async fn redirects_to_the_language_and_the_canonical_address() {
        let client = test_app(false);
        let res = client
            .get("/")
            .header("accept-language", "de-DE, fr;q=0.9, en;q=0.8")
            .await;
        assert_eq!(res.status(), StatusCode::FOUND);
        assert_eq!(h(&res, "location"), "/fr/");
        let res = get(&client, "/en/docs/waf").await;
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(h(&res, "location"), "/en/docs/waf/");
        // Addresses of the previous single-page app.
        let res = get(&client, "/docs/rate-limit").await;
        assert_eq!(res.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(h(&res, "location"), "/en/docs/rate-limit/");
        let res = get(&client, "/playground").await;
        assert_eq!(h(&res, "location"), "/en/playground/");
    }

    #[tokio::test]
    async fn serves_the_manifest_the_worker_and_the_files() {
        let client = test_app(false);
        let res = get(&client, "/manifest.webmanifest").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(h(&res, "content-type"), "application/manifest+json");
        assert!(res.text().starts_with(r#"{"name":"Securite""#));
        let res = get(&client, "/sw.js").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(h(&res, "content-type"), "text/javascript; charset=utf-8");
        assert_eq!(h(&res, "cache-control"), "no-cache");
        assert!(res.text().contains(r#"const NETWORK_ONLY = ["/api/"];"#));
        let res = get(&client, "/static/icon-192.png?v=1").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(h(&res, "content-type"), "image/png");
        assert_eq!(
            h(&res, "cache-control"),
            "public, max-age=31536000, immutable"
        );
        let res = get(&client, "/static/main.css").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(h(&res, "content-type"), "text/css; charset=utf-8");
        assert_eq!(get(&client, "/favicon.svg").await.status(), StatusCode::OK);
        assert_eq!(
            get(&client, "/static/nope.css").await.status(),
            StatusCode::NOT_FOUND
        );
        let robots = get(&client, "/robots.txt").await.text();
        assert!(robots.contains("Sitemap: http://localhost/sitemap.xml"));
        let res = get(&client, "/sitemap.xml").await;
        assert_eq!(h(&res, "content-type"), "application/xml; charset=utf-8");
        assert!(
            res.text()
                .contains("<loc>http://localhost/fr/playground/</loc>")
        );
    }

    #[tokio::test]
    async fn demo_blocks_attacks_and_counts_them() {
        let client = test_app(false);
        let res = get(&client, "/api/demo?payload=hello").await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.text().contains("\"allowed\""));
        let res = get(
            &client,
            "/api/demo?payload=%24%7Bjndi%3Aldap%3A%2F%2Fx%2Fa%7D",
        )
        .await;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
        assert_eq!(h(&res, "content-type"), "application/problem+json");
        assert!(res.text().contains("waf_blocked"));
        let stats = get(&client, "/api/stats").await.text();
        assert!(stats.contains("\"blocked\":1"), "{stats}");
    }

    #[tokio::test]
    async fn production_mode_redirects_and_sets_hsts() {
        let client = test_app(true);
        let res = client
            .get("/en/docs/")
            .header("host", "securite.example")
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-for", "198.51.100.4")
            .await;
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(h(&res, "location"), "https://securite.example/en/docs/");
        let res = client
            .get("/en/")
            .header("host", "securite.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-for", "198.51.100.4")
            .await;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(h(&res, "strict-transport-security").contains("max-age"));
        assert!(h(&res, "content-security-policy").contains("upgrade-insecure-requests"));
        assert!(
            res.text()
                .contains(r#"<link rel="canonical" href="https://securite.example/en/"/>"#)
        );
    }
}
