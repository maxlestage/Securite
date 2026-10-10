//! Web server of the securite website.
//!
//! It serves the Yew/WebAssembly site and protects itself with the
//! `securite` crate (dogfooding). Configuration comes from the environment:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PORT` | `8080` | Listening port (set by Heroku) |
//! | `DIST_DIR` | `./dist` | Folder produced by `trunk build` |
//! | `SECURITE_ENV` | `production` when `DYNO` is set, else `development` | Enables HTTPS redirect, HSTS … |
//! | `RUST_LOG` | `info` | Log filter |

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use securite::headers::{ContentSecurityPolicy, Hsts, src};
use securite::prelude::*;
use tower_http::compression::CompressionLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;

#[derive(Clone)]
struct AppState {
    shield: Shield,
    index: Arc<str>,
}

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

/// Builds the shield protecting this very website.
fn shield(production: bool, inline_script_hashes: Vec<String>) -> Shield {
    // Trunk injects one inline bootstrap script: allow it by hash, never
    // with 'unsafe-inline'. WebAssembly needs 'wasm-unsafe-eval'.
    let script_src: Vec<String> = [src::SELF, src::WASM_UNSAFE_EVAL]
        .into_iter()
        .map(String::from)
        .chain(inline_script_hashes)
        .collect();
    let mut csp = ContentSecurityPolicy::new()
        .default_src([src::SELF])
        .script_src(script_src)
        .style_src([src::SELF])
        // Animations set CSS variables through style attributes.
        .style_src_attr([src::UNSAFE_INLINE])
        .img_src([src::SELF, src::DATA])
        .font_src([src::SELF])
        .connect_src([src::SELF])
        .object_src([src::NONE])
        .base_uri([src::SELF])
        .form_action([src::SELF])
        .frame_ancestors([src::NONE]);
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

/// Builds the whole application (routes + shield).
fn app(dist: &std::path::Path, index: String, production: bool) -> Router {
    let hashes = ContentSecurityPolicy::hashes_for_inline_scripts(&index);
    tracing::info!(
        inline_scripts = hashes.len(),
        production,
        "CSP hashes computed"
    );

    let shield = shield(production, hashes);
    tracing::info!(guards = ?shield.guard_names(), "shield ready");

    let state = AppState {
        shield: shield.clone(),
        index: Arc::from(index),
    };

    // Hashed assets produced by trunk are immutable.
    let assets = Router::new()
        .fallback_service(ServeDir::new(dist).fallback(get(spa).with_state(state.clone())))
        .layer(SetResponseHeaderLayer::if_not_present(
            header::CACHE_CONTROL,
            HeaderValue::from_static("public, max-age=31536000, immutable"),
        ));

    Router::new()
        .route("/", get(spa))
        .route("/index.html", get(spa))
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/stats", get(stats))
        .route("/api/demo", get(demo))
        .with_state(state)
        .merge(assets)
        .layer(CompressionLayer::new())
        .layer(shield)
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let production = match std::env::var("SECURITE_ENV") {
        Ok(v) => v == "production",
        Err(_) => std::env::var("DYNO").is_ok(),
    };
    let dist = PathBuf::from(env_or("DIST_DIR", "dist"));
    let index = std::fs::read_to_string(dist.join("index.html")).unwrap_or_else(|_| {
        tracing::warn!(path = %dist.display(), "index.html not found, run `trunk build` in site/");
        "<!doctype html><title>securite</title><h1>Build the site with trunk</h1>".into()
    });
    let app = app(&dist, index, production);

    let port: u16 = env_or("PORT", "8080")
        .parse()
        .expect("PORT must be a number");
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    tracing::info!(%addr, "securite website listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await
    .expect("server error");
}

/// Single page app: every unknown route renders index.html.
async fn spa(State(state): State<AppState>) -> Response {
    let mut res = Html(state.index.to_string()).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    res
}

async fn stats(State(state): State<AppState>) -> Response {
    let mut res = state.shield.stats().to_json().into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
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

async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const INDEX: &str = "<!doctype html><script type=\"module\">init()</script><h1>ok</h1>";

    async fn get(app: &Router, uri: &str) -> (StatusCode, axum::http::HeaderMap, String) {
        let mut req = Request::builder().uri(uri).body(Body::empty()).unwrap();
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

    #[tokio::test]
    async fn index_has_strict_csp_with_script_hash() {
        let app = app(std::path::Path::new("/nonexistent"), INDEX.into(), false);
        let (status, h, body) = get(&app, "/").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("<h1>ok</h1>"));
        let csp = h["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("'sha256-"), "{csp}");
        assert!(csp.contains("'wasm-unsafe-eval'"), "{csp}");
        assert!(
            !csp.contains("upgrade-insecure-requests"),
            "dev mode: {csp}"
        );
        assert!(
            !h.contains_key("strict-transport-security"),
            "no HSTS in dev"
        );
        assert_eq!(h["cross-origin-embedder-policy"], "require-corp");
        // SPA routes render index.html.
        assert_eq!(get(&app, "/docs/waf").await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn demo_blocks_attacks_and_counts_them() {
        let app = app(std::path::Path::new("/nonexistent"), INDEX.into(), false);
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
        let app = app(std::path::Path::new("/nonexistent"), INDEX.into(), true);
        let mut req = Request::builder()
            .uri("/docs")
            .header("host", "securite.example")
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-for", "198.51.100.4")
            .body(Body::empty())
            .unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(SocketAddr::from((
                [10, 0, 0, 1],
                4000,
            ))));
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(res.headers()["location"], "https://securite.example/docs");
        let (_, h, _) = get(&app, "/api/health").await;
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
    }
}
