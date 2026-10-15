//! # Securite
//!
//! **Fast, easy, batteries-included security middlewares for Rust web services.**
//!
//! `securite` protects a [Vitesse](https://vitesse-f16135654c3d.herokuapp.com/) application
//! with one line, and any [`tower`](https://docs.rs/tower) based stack (hyper, tonic,
//! Poem, Salvo …) with one layer: the [`Shield`].
//!
//! A `Shield` runs a pipeline of synchronous, allocation-light [`Guard`]s on
//! every request (in a fixed, sensible order) and decorates every response
//! (security headers, rate-limit headers, CORS, hardened cookies …).
//!
//! ```no_run
//! use securite::prelude::*;
//! use vitesse::prelude::*;
//!
//! fn main() -> std::io::Result<()> {
//!     let mut app = App::new();
//!     // Security headers, WAF, rate limiting, CSRF, request ids …
//!     app.middleware(Shield::recommended());
//!     app.get("/", |_req: Request| async { "Hello, secure world!" });
//!     app.run(3000)
//! }
//! ```
//!
//! ## Middlewares
//!
//! | Category            | Guard                                   | What it does |
//! |---------------------|-----------------------------------------|--------------|
//! | Browser hardening   | [`SecurityHeaders`](headers::SecurityHeaders) | CSP (nonces, hashes), HSTS, COOP/CORP (+ COEP in strict), Permissions-Policy … |
//! |                     | [`Cors`](cors::Cors)                    | Strict, allow-list based CORS |
//! |                     | [`CookieHardening`](cookies::CookieHardening) | Adds `Secure`, `HttpOnly`, `SameSite` to every cookie |
//! |                     | [`HttpsRedirect`](https::HttpsRedirect) | Redirects plain HTTP to HTTPS (proxy aware) |
//! | Traffic control     | [`RateLimit`](rate_limit::RateLimit)    | GCRA rate limiting per IP / key / route |
//! |                     | [`ConcurrencyLimit`](concurrency::ConcurrencyLimit) | Max in-flight requests per IP |
//! |                     | [`AutoBan`](ban::AutoBan)               | fail2ban-like automatic banning |
//! |                     | [`BodyLimit`](body_limit::BodyLimit)    | Rejects oversized bodies early |
//! |                     | [`Hygiene`](hygiene::Hygiene)           | Anti request-smuggling and protocol sanity checks |
//! |                     | [`MethodFilter`](method::MethodFilter)  | Allowed HTTP methods, blocks method override |
//! | Access control      | [`IpFilter`](ip_filter::IpFilter)       | CIDR allow / deny lists, updatable at runtime |
//! |                     | [`HostFilter`](host::HostFilter)        | Host header allow-list (anti DNS-rebinding) |
//! |                     | [`Auth`](auth::Auth)                    | Bearer / API key / Basic / JWT (JWKS) auth, constant-time |
//! |                     | [`AccessControl`](access::AccessControl) | Symfony-style `access_control`: roles by URL, role hierarchy |
//! |                     | [`Sessions`](session::Sessions)         | Server-side sessions: rotation on login, idle/absolute timeouts |
//! |                     | [`Csrf`](csrf::Csrf)                    | Fetch-Metadata + signed double-submit tokens |
//! |                     | [`ContentTypeGuard`](content_type::ContentTypeGuard) | Allowed request media types |
//! |                     | [`SignedUrls`](signing::SignedUrls)     | Laravel-style signed, expiring URLs |
//! | Threat detection    | [`Waf`](waf::Waf)                       | SQLi, XSS, traversal, RCE, Log4Shell, SSRF … |
//! |                     | [`BotBlocker`](user_agent::BotBlocker)  | Blocks scanners and attack tools |
//! | Integrity & tracing | [`RequestId`](request_id::RequestId)    | Validated request IDs |
//! |                     | [`SignatureLayer`](signature::SignatureLayer) | HMAC webhook verification (GitHub, Stripe, Slack …) |
//! |                     | [`Stats`](event::StatsSnapshot) / [events](event::SecurityEvent) | Metrics and audit trail |
//! |                     | [`ClearSiteData`](clear_site_data::ClearSiteData) | Wipes cache, cookies and storage on logout |
//!
//! ## Building blocks for handlers
//!
//! | Module | What it does |
//! |--------|--------------|
//! | [`password`] | Argon2id password hashing (OWASP parameters), rehash on login, anti user enumeration |
//! | [`throttle`] | [`LoginThrottle`](throttle::LoginThrottle): brute-force lockout per account, IP or both |
//! | [`authz`] | [`Gate`](authz::Gate): abilities, policies and voters, deny by default |
//! | [`signing`] | [`Signer`](signing::Signer): signed, expiring, purpose-bound tokens and URLs |
//! | [`totp`] | [`Totp`](totp::Totp): RFC 6238 two-factor codes, replay protection, recovery codes |
//! | `crypt` | `Encrypter`: XChaCha20-Poly1305 encryption, key rotation, encrypted cookies (feature `crypt`) |
//! | `jwt` | `JwtValidator`: JWT / JWKS validation, algorithm allow-list, key rotation (feature `jwt`) |
//! | [`session`] | [`SessionManager`](session::SessionManager): sessions, fixation protection, logout with `Clear-Site-Data` |
//! | [`password_policy`] | [`PasswordPolicy`](password_policy::PasswordPolicy): NIST SP 800-63B rules, Have I Been Pwned k-anonymity |
//! | [`counter`] | [`CounterStore`](counter::CounterStore): counters shared by every instance (Redis …) |
//! | `report` | CSP violation report collector (feature `reports`) |
//! | [`security_txt`] | [`SecurityTxt`](security_txt::SecurityTxt): RFC 9116 `security.txt` |
//!
//! Every guard can also be used on its own, as a one-guard shield (with tower,
//! a guard is a layer by itself):
//!
//! ```no_run
//! use securite::prelude::*;
//! use vitesse::prelude::*;
//!
//! let mut app = App::new();
//! app.middleware(Shield::from(SecurityHeaders::strict()));
//! app.middleware(Shield::from(RateLimit::per_minute(120)));
//! ```
//!
//! ## Client IP
//!
//! IP aware guards need to know who the client is. By default the shield uses
//! the TCP peer address, which Vitesse hands it (see [`ClientIpSource`]; with
//! hyper, insert a [`PeerAddr`] in the request extensions). Behind a reverse
//! proxy (Heroku, Fly.io, Cloudflare, Nginx …) configure the right source with
//! [`ShieldBuilder::client_ip`].
//!
//! ## Cargo features
//!
//! * `vitesse` (default): the [`Shield`] and the
//!   [`SignatureLayer`](signature::SignatureLayer) are Vitesse middlewares.
//!   Without it the crate only depends on `http` and `tower`.
//! * `password` (default): the [`password`] module (Argon2id, through the
//!   RustCrypto `argon2` crate).
//! * `crypt` (default): the `crypt` module (XChaCha20-Poly1305, through the
//!   RustCrypto `chacha20poly1305` crate).
//! * `jwt`: the `jwt` module and `Auth::jwt` (through the `jsonwebtoken`
//!   crate and its RustCrypto backend).
//! * `reports`: the `report` module (CSP violation reports, `serde_json`).
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unreachable_pub)]
#![cfg_attr(docsrs, feature(doc_cfg))]

/// The version of this crate, e.g. `"0.2.0"`: handy for a footer or a `Server` header.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod access;
pub mod auth;
pub mod authz;
pub mod ban;
pub mod body;
pub mod body_limit;
pub mod clear_site_data;
pub mod concurrency;
pub mod content_type;
mod context;
pub mod cookies;
pub mod cors;
pub mod counter;
#[cfg(feature = "crypt")]
#[cfg_attr(docsrs, doc(cfg(feature = "crypt")))]
pub mod crypt;
pub mod csrf;
pub mod event;
mod guard;
pub mod headers;
pub mod host;
pub mod https;
pub mod hygiene;
pub mod ip;
pub mod ip_filter;
#[cfg(feature = "jwt")]
#[cfg_attr(docsrs, doc(cfg(feature = "jwt")))]
pub mod jwt;
pub mod method;
#[cfg(feature = "password")]
#[cfg_attr(docsrs, doc(cfg(feature = "password")))]
pub mod password;
pub mod password_policy;
pub mod rate_limit;
mod rejection;
#[cfg(feature = "reports")]
#[cfg_attr(docsrs, doc(cfg(feature = "reports")))]
pub mod report;
pub mod request_id;
pub mod security_txt;
pub mod session;
mod shield;
pub mod signature;
pub mod signing;
mod store;
pub mod throttle;
pub mod totp;
pub mod user_agent;
mod util;
pub mod waf;

/// Re-export of the `http` crate used in the public API.
pub use http;

pub use context::Context;
pub use guard::{Guard, Mode, priority};
pub use ip::{ClientIp, ClientIpSource, PeerAddr};
pub use rejection::{ErrorFormat, Rejection};
pub use shield::{ResponseFuture, Shield, ShieldBuilder, ShieldService};

/// Everything you usually need, in one import.
pub mod prelude {
    pub use crate::access::{Access, AccessControl, RoleHierarchy, Roles};
    pub use crate::auth::{Auth, Principal};
    pub use crate::authz::{Gate, Vote, Voter};
    pub use crate::ban::AutoBan;
    pub use crate::body_limit::{BodyLimit, BodyLimitLayer};
    pub use crate::concurrency::ConcurrencyLimit;
    pub use crate::content_type::ContentTypeGuard;
    pub use crate::cookies::{CookieHardening, SameSite};
    pub use crate::cors::Cors;
    pub use crate::csrf::{Csrf, CsrfToken};
    pub use crate::event::{SecurityEvent, StatsSnapshot};
    pub use crate::headers::{ContentSecurityPolicy, CspNonce, SecurityHeaders};
    pub use crate::host::HostFilter;
    pub use crate::https::HttpsRedirect;
    pub use crate::hygiene::Hygiene;
    pub use crate::ip_filter::{InvalidNetwork, IpFilter, IpSet};
    pub use crate::method::MethodFilter;
    #[cfg(feature = "password")]
    pub use crate::password::{PasswordCheck, PasswordHasher};
    pub use crate::rate_limit::{HeaderStyle, Quota, RateLimit, RateLimitKey};
    pub use crate::request_id::{RequestId, RequestIdValue};
    pub use crate::signature::{SignatureLayer, SignatureVerifier};
    pub use crate::signing::{SignedUrls, Signer};
    pub use crate::throttle::LoginThrottle;
    pub use crate::user_agent::BotBlocker;
    pub use crate::waf::{Paranoia, Waf};
    pub use crate::{
        ClientIp, ClientIpSource, Context, ErrorFormat, Guard, Mode, PeerAddr, Rejection, Shield,
        ShieldBuilder,
    };
}
