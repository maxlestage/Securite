use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context as TaskContext, Poll, ready};

use bytes::Bytes;
use http::{Request, Response, request, response};
use http_body::Body;
use pin_project_lite::pin_project;
use tower_layer::Layer;
use tower_service::Service;

use crate::body::SecureBody;
use crate::event::{SecurityEvent, Stats, StatsSnapshot};
use crate::prelude::*;
use crate::{ClientIp, ClientIpSource, Context, ErrorFormat, Guard, Mode, Rejection};

type EventHook = dyn Fn(&SecurityEvent<'_>) + Send + Sync;

/// The all-in-one security layer.
///
/// A `Shield` is cheap to clone (it is an `Arc`) and implements
/// [`tower::Layer`](tower_layer::Layer), so it can be used with
/// `axum::Router::layer`, `tower::ServiceBuilder`, tonic, hyper …
///
/// ```
/// use securite::prelude::*;
/// use std::time::Duration;
///
/// let shield = Shield::builder()
///     .client_ip(ClientIpSource::heroku())
///     .guard(SecurityHeaders::strict())
///     .guard(RateLimit::per_second(10).burst(30))
///     .guard(Waf::new())
///     .guard(AutoBan::new().max_strikes(10).ban_for(Duration::from_secs(600)))
///     .build();
///
/// assert_eq!(shield.guard_names(), ["ban", "rate_limit", "waf", "security_headers"]);
/// ```
#[derive(Clone)]
pub struct Shield {
    inner: Arc<ShieldInner>,
}

struct ShieldInner {
    guards: Vec<Box<dyn Guard>>,
    ip_source: ClientIpSource,
    error_format: ErrorFormat,
    on_event: Option<Arc<EventHook>>,
    log_events: bool,
    stats: Stats,
}

impl Shield {
    /// Starts an empty builder.
    pub fn builder() -> ShieldBuilder {
        ShieldBuilder::new()
    }

    /// Sensible protection for web apps and APIs. See
    /// [`ShieldBuilder::recommended`].
    pub fn recommended() -> Self {
        ShieldBuilder::recommended().build()
    }

    /// Maximum protection. See [`ShieldBuilder::strict`].
    pub fn strict() -> Self {
        ShieldBuilder::strict().build()
    }

    /// Tuned for JSON APIs. See [`ShieldBuilder::api`].
    pub fn api() -> Self {
        ShieldBuilder::api().build()
    }

    /// Live counters.
    pub fn stats(&self) -> StatsSnapshot {
        self.inner.stats.snapshot()
    }

    /// Names of the active guards, in execution order.
    pub fn guard_names(&self) -> Vec<&'static str> {
        self.inner.guards.iter().map(|g| g.name()).collect()
    }
}

impl fmt::Debug for Shield {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Shield")
            .field("guards", &self.guard_names())
            .field("client_ip", &self.inner.ip_source)
            .field("error_format", &self.inner.error_format)
            .finish()
    }
}

impl<S> Layer<S> for Shield {
    type Service = ShieldService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ShieldService {
            inner,
            shield: self.inner.clone(),
        }
    }
}

/// Builder for [`Shield`].
#[must_use]
pub struct ShieldBuilder {
    guards: Vec<Box<dyn Guard>>,
    ip_source: ClientIpSource,
    error_format: ErrorFormat,
    on_event: Option<Arc<EventHook>>,
    log_events: bool,
}

impl Default for ShieldBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ShieldBuilder {
    /// An empty builder (no guard).
    pub fn new() -> Self {
        Self {
            guards: Vec::new(),
            ip_source: ClientIpSource::Peer,
            error_format: ErrorFormat::ProblemJson,
            on_event: None,
            log_events: true,
        }
    }

    /// Recommended preset for most web applications:
    ///
    /// request id · hygiene · method filter · 2 MiB body limit ·
    /// rate limit (20 req/s, burst 100 per IP) · bot blocker · WAF
    /// (paranoia 1) · Fetch-Metadata CSRF · security headers · cookie
    /// hardening.
    pub fn recommended() -> Self {
        Self::new()
            .guard(RequestId::new())
            .guard(Hygiene::new())
            .guard(MethodFilter::new())
            .guard(BodyLimit::new(2 * 1024 * 1024))
            .guard(RateLimit::new(Quota::per_second(20).burst(100)))
            .guard(BotBlocker::new())
            .guard(Waf::new())
            .guard(Csrf::new())
            .guard(SecurityHeaders::new())
            .guard(CookieHardening::new())
    }

    /// Strict preset: everything in [`recommended`](Self::recommended) with
    /// tighter limits, plus HTTPS redirect, auto-ban, per-IP concurrency
    /// limit, content-type allow-list, strict headers and WAF paranoia 2.
    pub fn strict() -> Self {
        Self::recommended()
            .guard(HttpsRedirect::new())
            .guard(AutoBan::new())
            .guard(BodyLimit::new(1024 * 1024))
            .guard(RateLimit::new(Quota::per_second(10).burst(40)))
            .guard(ConcurrencyLimit::per_ip(32))
            .guard(Waf::new().paranoia(Paranoia::Medium))
            .guard(ContentTypeGuard::new())
            .guard(SecurityHeaders::strict())
            .guard(CookieHardening::new().same_site(SameSite::Strict))
    }

    /// API preset: JSON only, `no-store` caching, locked-down CSP, no CSRF
    /// (APIs authenticate with tokens, not ambient cookies).
    pub fn api() -> Self {
        Self::new()
            .guard(RequestId::new())
            .guard(Hygiene::new())
            .guard(MethodFilter::new())
            .guard(BodyLimit::new(1024 * 1024))
            .guard(RateLimit::new(Quota::per_second(20).burst(50)))
            .guard(BotBlocker::new())
            .guard(Waf::new())
            .guard(ContentTypeGuard::json())
            .guard(SecurityHeaders::api())
            .guard(CookieHardening::new())
    }

    /// Adds a guard. A guard with the same [`name`](Guard::name) is
    /// replaced, which makes presets easy to customise:
    ///
    /// ```
    /// use securite::prelude::*;
    /// let shield = ShieldBuilder::recommended()
    ///     .guard(RateLimit::per_minute(600)) // replaces the preset limiter
    ///     .build();
    /// ```
    pub fn guard(mut self, guard: impl Guard) -> Self {
        let name = guard.name();
        self.guards.retain(|g| g.name() != name);
        self.guards.push(Box::new(guard));
        self
    }

    /// Removes the guard named `name` (e.g. `"csrf"`).
    pub fn without(mut self, name: &str) -> Self {
        self.guards.retain(|g| g.name() != name);
        self
    }

    /// Where to read the client IP from (default: TCP peer).
    pub fn client_ip(mut self, source: ClientIpSource) -> Self {
        self.ip_source = source;
        self
    }

    /// How rejections are rendered (default: `application/problem+json`).
    pub fn error_format(mut self, format: ErrorFormat) -> Self {
        self.error_format = format;
        self
    }

    /// Called for every security event (block or monitor). Plug your
    /// metrics, SIEM or alerting here.
    pub fn on_event<F>(mut self, f: F) -> Self
    where
        F: Fn(&SecurityEvent<'_>) + Send + Sync + 'static,
    {
        self.on_event = Some(Arc::new(f));
        self
    }

    /// Writes events with `tracing` (default: `true`).
    pub fn log_events(mut self, enabled: bool) -> Self {
        self.log_events = enabled;
        self
    }

    /// Builds the shield.
    pub fn build(mut self) -> Shield {
        // Stable sort: guards with equal priority keep insertion order.
        self.guards.sort_by_key(|g| g.priority());
        let stats = Stats::new(self.guards.iter().map(|g| g.name()));
        Shield {
            inner: Arc::new(ShieldInner {
                guards: self.guards,
                ip_source: self.ip_source,
                error_format: self.error_format,
                on_event: self.on_event,
                log_events: self.log_events,
                stats,
            }),
        }
    }
}

fn warn_unknown_ip() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::warn!(
            target: "securite",
            "client IP unknown: IP based guards fall back to a shared bucket. \
             With axum use `into_make_service_with_connect_info::<SocketAddr>()`, \
             with hyper insert `securite::PeerAddr` in the request extensions."
        );
    });
}

impl ShieldInner {
    fn run_request(&self, parts: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        for (idx, guard) in self.guards.iter().enumerate() {
            let Err(rejection) = guard.on_request(parts, ctx) else {
                continue;
            };
            if rejection.benign {
                ctx.rejected_by = Some(guard.name());
                return Err(rejection);
            }
            let enforced = guard.mode() == Mode::Enforce;
            self.stats.per_guard[idx].1.fetch_add(1, Ordering::Relaxed);
            self.emit(guard.name(), &rejection, ctx, enforced);
            if enforced {
                self.stats.blocked.fetch_add(1, Ordering::Relaxed);
                ctx.rejected_by = Some(guard.name());
                ctx.blocked = true;
                return Err(rejection);
            }
            self.stats.monitored.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    fn run_response(&self, parts: &mut response::Parts, ctx: &Context) {
        for cookie in &ctx.set_cookies {
            parts
                .headers
                .append(http::header::SET_COOKIE, cookie.clone());
        }
        for guard in &self.guards {
            guard.on_response(parts, ctx);
        }
    }

    fn emit(&self, guard: &'static str, r: &Rejection, ctx: &Context, enforced: bool) {
        let event = SecurityEvent {
            guard,
            code: r.code,
            status: r.status,
            enforced,
            client_ip: ctx.client_ip,
            method: &ctx.method,
            path: ctx.uri.path(),
            request_id: ctx.request_id(),
            message: &r.message,
            details: r.details.as_deref(),
        };
        if self.log_events {
            if enforced {
                tracing::warn!(
                    target: "securite",
                    guard,
                    code = r.code,
                    status = r.status.as_u16(),
                    ip = ?event.client_ip,
                    method = %event.method,
                    path = event.path,
                    request_id = event.request_id,
                    details = event.details,
                    "request blocked"
                );
            } else {
                tracing::info!(
                    target: "securite",
                    guard,
                    code = r.code,
                    status = r.status.as_u16(),
                    ip = ?event.client_ip,
                    method = %event.method,
                    path = event.path,
                    request_id = event.request_id,
                    details = event.details,
                    "violation (monitor mode)"
                );
            }
        }
        if let Some(hook) = &self.on_event {
            hook(&event);
        }
    }
}

/// The service produced by [`Shield`].
pub struct ShieldService<S> {
    inner: S,
    shield: Arc<ShieldInner>,
}

impl<S: Clone> Clone for ShieldService<S> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shield: self.shield.clone(),
        }
    }
}

impl<S: fmt::Debug> fmt::Debug for ShieldService<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShieldService")
            .field("inner", &self.inner)
            .finish_non_exhaustive()
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ShieldService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    ResBody: Body<Data = Bytes>,
{
    type Response = Response<SecureBody<ResBody>>;
    type Error = S::Error;
    type Future = ResponseFuture<S::Future>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let shield = &self.shield;
        shield.stats.total.fetch_add(1, Ordering::Relaxed);

        let (mut parts, body) = req.into_parts();
        // An outer shield (e.g. configured for a proxy) already resolved
        // the client: reuse its answer so stacked layers agree.
        let ip = match parts.extensions.get::<ClientIp>() {
            Some(ClientIp(ip)) => Some(*ip),
            None => {
                let ip = shield.ip_source.resolve(&parts);
                match ip {
                    Some(ip) => {
                        parts.extensions.insert(ClientIp(ip));
                    }
                    None => warn_unknown_ip(),
                }
                ip
            }
        };
        let mut ctx = Context::new(parts.method.clone(), parts.uri.clone(), ip);

        let state = match shield.run_request(&mut parts, &mut ctx) {
            Ok(()) => State::Inner {
                fut: self.inner.call(Request::from_parts(parts, body)),
            },
            Err(rejection) => State::Rejected {
                res: Some(shield.error_format.render(&rejection, &ctx)),
            },
        };
        ResponseFuture {
            state,
            ctx: Some(ctx),
            shield: shield.clone(),
        }
    }
}

pin_project! {
    /// Response future of [`ShieldService`].
    pub struct ResponseFuture<F> {
        #[pin]
        state: State<F>,
        ctx: Option<Context>,
        shield: Arc<ShieldInner>,
    }
}

pin_project! {
    #[project = StateProj]
    enum State<F> {
        Inner { #[pin] fut: F },
        Rejected { res: Option<(response::Parts, Bytes)> },
    }
}

impl<F, B, E> Future for ResponseFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body<Data = Bytes>,
{
    type Output = Result<Response<SecureBody<B>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let (mut parts, body) = match this.state.project() {
            StateProj::Inner { fut } => {
                let res = ready!(fut.poll(cx))?;
                let (parts, body) = res.into_parts();
                (parts, SecureBody::inner(body))
            }
            StateProj::Rejected { res } => {
                let (parts, bytes) = res.take().expect("ResponseFuture polled after completion");
                (parts, SecureBody::full(bytes))
            }
        };
        let ctx = this
            .ctx
            .take()
            .expect("ResponseFuture polled after completion");
        this.shield.run_response(&mut parts, &ctx);
        drop(ctx);
        Poll::Ready(Ok(Response::from_parts(parts, body)))
    }
}
