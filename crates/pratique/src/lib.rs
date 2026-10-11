//! # Pratique
//!
//! **Everyday middlewares for [Vitesse](https://maxlestage.github.io/Vitesse/)
//! that have nothing to do with security**: caching, observability, URLs,
//! operations and internationalisation. Each one is a single line:
//!
//! ```no_run
//! use pratique::prelude::*;
//! use vitesse::prelude::*;
//! use std::time::Duration;
//!
//! fn main() -> std::io::Result<()> {
//!     let mut app = App::new();
//!     app.middleware(AccessLog::json().skip("/health"));
//!     app.middleware(Metrics::new());
//!     app.middleware(Health::new().version(env!("CARGO_PKG_VERSION")));
//!     app.middleware(ResponseTime::new());
//!     app.middleware(TrailingSlash::trim());
//!     app.middleware(ETag::new());
//!     app.middleware(CacheControl::new().fallback(CacheControl::NO_CACHE));
//!     app.middleware(Locale::new(["en", "fr", "es"]));
//!     app.get("/", |_req: Request| async { "Hello!" });
//!     app.run(3000)
//! }
//! ```
//!
//! ## Middlewares
//!
//! | Category        | Middleware                                       | What it does |
//! |-----------------|--------------------------------------------------|--------------|
//! | Caching         | [`ETag`](etag::ETag)                             | `ETag` from the body, `304 Not Modified` on `If-None-Match` |
//! |                 | [`CacheControl`](cache_control::CacheControl)    | `Cache-Control` by path prefix and content type |
//! |                 | [`ResponseCache`](cache::ResponseCache)          | In-memory cache of whole `GET` responses, with TTL and purge |
//! | Observability   | [`AccessLog`](access_log::AccessLog)             | JSON lines or Apache combined access logs |
//! |                 | [`Metrics`](metrics::Metrics)                    | Prometheus `/metrics`: counts, latency histogram, in-flight |
//! |                 | [`ResponseTime`](timing::ResponseTime)           | `X-Response-Time` and `Server-Timing` |
//! | URLs            | [`TrailingSlash`](trailing_slash::TrailingSlash) | One address per page, with or without the final `/` |
//! |                 | [`Redirects`](redirect::Redirects)               | Moved pages, renamed sections, canonical domain |
//! | Operations      | [`Health`](health::Health)                       | `/health` probe with named checks (`application/health+json`) |
//! |                 | [`Maintenance`](maintenance::Maintenance)        | `503` + `Retry-After`, switched on and off at runtime |
//! | Responses & API | [`SetHeaders`](headers::SetHeaders)              | Add, replace or remove headers on every response |
//! |                 | [`Locale`](locale::Locale)                       | Language from `?lang=`, a cookie or `Accept-Language` |
//! |                 | [`Deprecation`](deprecation::Deprecation)        | `Deprecation`, `Sunset` and `Link` headers (RFC 9745, RFC 8594) |
//!
//! ## Order
//!
//! Vitesse runs middlewares in the order they are added, the first one being
//! the outermost. Put the ones that observe everything first (`AccessLog`,
//! `Metrics`), then the ones that answer by themselves (`Health`,
//! `Maintenance`, `Redirects`, `TrailingSlash`), then the ones that work on
//! the response of your routes (`ETag`, `CacheControl`, `ResponseCache`).
//! With [Securite](https://docs.rs/securite), add the `Shield` before the
//! endpoints you want to protect (`/metrics`).
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// The version of this crate, e.g. `"0.1.0"`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod access_log;
pub mod cache;
pub mod cache_control;
pub mod deprecation;
pub mod etag;
pub mod headers;
pub mod health;
pub mod locale;
pub mod maintenance;
pub mod metrics;
pub mod redirect;
pub mod timing;
pub mod trailing_slash;
mod util;

/// Every middleware, in one import.
pub mod prelude {
    pub use crate::access_log::AccessLog;
    pub use crate::cache::{CacheHandle, ResponseCache};
    pub use crate::cache_control::CacheControl;
    pub use crate::deprecation::Deprecation;
    pub use crate::etag::ETag;
    pub use crate::headers::SetHeaders;
    pub use crate::health::Health;
    pub use crate::locale::{Lang, Locale};
    pub use crate::maintenance::{Maintenance, MaintenanceSwitch};
    pub use crate::metrics::{Metrics, MetricsHandle};
    pub use crate::redirect::Redirects;
    pub use crate::timing::ResponseTime;
    pub use crate::trailing_slash::TrailingSlash;
}
