use http::{request, response};

use crate::{Context, Rejection};

/// Whether a guard blocks requests or only reports what it would have blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    /// Violations are rejected (default).
    #[default]
    Enforce,
    /// Violations are logged and counted but the request goes through.
    ///
    /// Perfect to roll out a WAF or a CSP without breaking production.
    Monitor,
}

/// Default priorities of the built-in guards. Lower runs first.
///
/// Custom guards default to [`priority::CUSTOM`].
pub mod priority {
    /// [`RequestId`](crate::request_id::RequestId)
    pub const REQUEST_ID: u16 = 10;
    /// [`HttpsRedirect`](crate::https::HttpsRedirect) — after
    /// [`HOST`] so the `Location` is built from a validated host.
    pub const HTTPS_REDIRECT: u16 = 75;
    /// [`AutoBan`](crate::ban::AutoBan)
    pub const BAN: u16 = 30;
    /// [`IpFilter`](crate::ip_filter::IpFilter)
    pub const IP_FILTER: u16 = 40;
    /// [`Hygiene`](crate::hygiene::Hygiene)
    pub const HYGIENE: u16 = 50;
    /// [`MethodFilter`](crate::method::MethodFilter)
    pub const METHOD: u16 = 60;
    /// [`HostFilter`](crate::host::HostFilter)
    pub const HOST: u16 = 70;
    /// [`BodyLimit`](crate::body_limit::BodyLimit)
    pub const BODY_LIMIT: u16 = 80;
    /// [`Cors`](crate::cors::Cors)
    pub const CORS: u16 = 90;
    /// [`RateLimit`](crate::rate_limit::RateLimit)
    pub const RATE_LIMIT: u16 = 100;
    /// [`ConcurrencyLimit`](crate::concurrency::ConcurrencyLimit)
    pub const CONCURRENCY: u16 = 105;
    /// [`BotBlocker`](crate::user_agent::BotBlocker)
    pub const USER_AGENT: u16 = 110;
    /// [`Waf`](crate::waf::Waf)
    pub const WAF: u16 = 120;
    /// [`Csrf`](crate::csrf::Csrf)
    pub const CSRF: u16 = 130;
    /// [`SignedUrls`](crate::signing::SignedUrls)
    pub const SIGNED_URL: u16 = 135;
    /// [`Sessions`](crate::session::Sessions) — before [`AUTH`] and
    /// [`ACCESS_CONTROL`], which read the session's user.
    pub const SESSIONS: u16 = 138;
    /// [`Auth`](crate::auth::Auth)
    pub const AUTH: u16 = 140;
    /// [`AccessControl`](crate::access::AccessControl) — right after [`AUTH`].
    pub const ACCESS_CONTROL: u16 = 145;
    /// [`ContentTypeGuard`](crate::content_type::ContentTypeGuard)
    pub const CONTENT_TYPE: u16 = 150;
    /// Default for user defined guards.
    pub const CUSTOM: u16 = 500;
    /// [`SecurityHeaders`](crate::headers::SecurityHeaders)
    pub const HEADERS: u16 = 900;
    /// [`CookieHardening`](crate::cookies::CookieHardening)
    pub const COOKIES: u16 = 910;
    /// [`ClearSiteData`](crate::clear_site_data::ClearSiteData)
    pub const CLEAR_SITE_DATA: u16 = 920;
}

/// A security check executed by the [`Shield`](crate::Shield).
///
/// Guards are synchronous and only see the request *head* (method, URI,
/// headers, extensions), which keeps them extremely fast. They run in
/// ascending [`priority`](Guard::priority) order and the first rejection wins.
///
/// After the inner service produced a response (or after a rejection), every
/// guard gets a chance to decorate the response head in
/// [`on_response`](Guard::on_response).
///
/// # Example: a custom guard
///
/// ```
/// use securite::{Context, Guard, Rejection, Shield};
/// use http::{request::Parts, StatusCode};
///
/// struct DenyAdminOnSundays;
///
/// impl Guard for DenyAdminOnSundays {
///     fn name(&self) -> &'static str { "no_admin_sunday" }
///
///     fn on_request(&self, req: &mut Parts, _ctx: &mut Context) -> Result<(), Rejection> {
///         if req.uri.path().starts_with("/admin") && is_sunday() {
///             return Err(Rejection::new(StatusCode::FORBIDDEN, "closed", "Admin is closed on Sundays"));
///         }
///         Ok(())
///     }
/// }
/// # fn is_sunday() -> bool { false }
///
/// let shield = Shield::builder().guard(DenyAdminOnSundays).build();
/// ```
pub trait Guard: Send + Sync + 'static {
    /// Stable, machine readable name (used in logs, events and stats).
    fn name(&self) -> &'static str;

    /// Execution order. Lower runs first. See [`priority`].
    fn priority(&self) -> u16 {
        priority::CUSTOM
    }

    /// Enforce or monitor-only.
    fn mode(&self) -> Mode {
        Mode::Enforce
    }

    /// Inspects (and may modify) the request head.
    ///
    /// Returning `Err` stops the pipeline and answers with the rejection.
    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let _ = (req, ctx);
        Ok(())
    }

    /// Decorates the response head. Called for successful responses *and*
    /// for rejections produced by any guard.
    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        let _ = (res, ctx);
    }
}

impl<G: Guard + ?Sized> Guard for std::sync::Arc<G> {
    fn name(&self) -> &'static str {
        (**self).name()
    }
    fn priority(&self) -> u16 {
        (**self).priority()
    }
    fn mode(&self) -> Mode {
        (**self).mode()
    }
    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        (**self).on_request(req, ctx)
    }
    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        (**self).on_response(res, ctx)
    }
}

/// Implements `tower::Layer` and `From<guard> for Shield` so a guard can be
/// used standalone: `app.middleware(Shield::from(RateLimit::per_second(10)))`
/// with Vitesse, `ServiceBuilder::new().layer(RateLimit::per_second(10))`
/// with tower.
macro_rules! impl_layer {
    ($($ty:ty),* $(,)?) => {$(
        impl<S> tower_layer::Layer<S> for $ty {
            type Service = $crate::ShieldService<S>;

            fn layer(&self, inner: S) -> Self::Service {
                $crate::Shield::builder().guard(self.clone()).build().layer(inner)
            }
        }

        impl From<$ty> for $crate::Shield {
            fn from(guard: $ty) -> Self {
                $crate::Shield::builder().guard(guard).build()
            }
        }
    )*};
}
pub(crate) use impl_layer;
