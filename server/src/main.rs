//! Web server of the securite website.
//!
//! It renders the pages written with active (`securite-site`), serves the browser bundle,
//! the web app manifest and the service worker, hosts the live attack playground API, and
//! protects itself with the `securite` crate (dogfooding). Configuration comes from the
//! environment:
//!
//! | Variable | Default | Meaning |
//! |---|---|---|
//! | `PORT` | `8080` | Listening port (set by Heroku) |
//! | `SITE_DIR` | the `site/` folder | Holds `static/` and `pkg/` (the browser bundle) |
//! | `BASE_PATH` | empty | Path the site lives under, e.g. `/Securite` |
//! | `SITE_URL` | from each request | Public address, for canonical URLs and the sitemap |
//! | `SECURITE_ENV` | `production` when `DYNO` is set, else `development` | Enables HTTPS redirect, HSTS … |
//! | `RUST_LOG` | `info` | Log filter |
//!
//! `securite-server export <dir>` writes the whole site as static files instead (GitHub
//! Pages): see [`export`].

mod app;
mod csp;
mod export;

use std::net::SocketAddr;
use std::sync::Arc;

use securite_site::render::{Site, site_dir};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_owned())
}

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        None => serve().await,
        Some("export") => {
            let dir = args.next().unwrap_or_else(|| "dist".into());
            let base = env_or("BASE_PATH", "");
            let site_url = std::env::var("SITE_URL").ok();
            match export::export(std::path::Path::new(&dir), &base, site_url) {
                Ok(files) => println!("{files} files written to {dir}"),
                Err(error) => {
                    eprintln!("export failed: {error}");
                    std::process::exit(1);
                }
            }
        }
        Some(other) => {
            eprintln!("unknown command {other:?}: run without arguments, or `export <dir>`");
            std::process::exit(2);
        }
    }
}

async fn serve() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let production = match std::env::var("SECURITE_ENV") {
        Ok(v) => v == "production",
        Err(_) => std::env::var("DYNO").is_ok(),
    };
    let dir = site_dir();
    let site = Site::load(
        &dir,
        &env_or("BASE_PATH", ""),
        std::env::var("SITE_URL").ok(),
        true,
    );
    if !site.has_bundle() {
        tracing::warn!(
            path = %dir.join("pkg").display(),
            "browser bundle not found: the pages work but are not interactive (see CONTRIBUTING.md)"
        );
    }
    let app = app::app(Arc::new(site), production);

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
