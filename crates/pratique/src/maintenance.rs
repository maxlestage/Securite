//! Maintenance mode, switched on and off while the app runs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response, StatusCode, json};

use crate::util::{normalize_prefix, path_matches};

/// Turns maintenance mode on and off from anywhere (an admin route, a signal
/// handler, a deploy script …). Cheap to clone.
#[derive(Debug, Clone, Default)]
pub struct MaintenanceSwitch(Arc<AtomicBool>);

impl MaintenanceSwitch {
    /// Starts answering `503`.
    pub fn on(&self) {
        self.set(true);
    }

    /// Back to normal.
    pub fn off(&self) {
        self.set(false);
    }

    /// Sets the mode.
    pub fn set(&self, enabled: bool) {
        self.0.store(enabled, Ordering::Relaxed);
    }

    /// Whether maintenance mode is on.
    pub fn is_on(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// While its [switch](Maintenance::switch) is on, answers every request with
/// `503 Service Unavailable`, `Retry-After` and `Cache-Control: no-store`:
/// an HTML page for browsers (when [`html`](Maintenance::html) is set), JSON
/// for clients that accept it, text otherwise. Some paths (health checks,
/// the admin) can stay [open](Maintenance::allow).
///
/// ```
/// use pratique::prelude::*;
/// use std::time::Duration;
/// use vitesse::prelude::*;
///
/// let maintenance = Maintenance::new()
///     .allow("/health")
///     .retry_after(Duration::from_secs(600));
/// let switch = maintenance.switch();
///
/// let mut app = App::new();
/// app.middleware(maintenance);
/// app.post("/admin/maintenance/on", move |_req: Request| {
///     let switch = switch.clone();
///     async move { switch.on(); "maintenance on" }
/// });
/// ```
#[derive(Debug, Clone)]
pub struct Maintenance {
    switch: MaintenanceSwitch,
    allow: Vec<String>,
    retry_after: Option<u64>,
    message: String,
    html: Option<String>,
}

impl Default for Maintenance {
    fn default() -> Self {
        Self::new()
    }
}

impl Maintenance {
    /// Off, until [`switch`](Maintenance::switch)`().on()`.
    pub fn new() -> Self {
        Self {
            switch: MaintenanceSwitch::default(),
            allow: Vec::new(),
            retry_after: None,
            message: "The service is down for maintenance. Please try again later.".into(),
            html: None,
        }
    }

    /// Starts on (or off).
    pub fn enabled(self, enabled: bool) -> Self {
        self.switch.set(enabled);
        self
    }

    /// The switch, to keep before handing the middleware to the app.
    pub fn switch(&self) -> MaintenanceSwitch {
        self.switch.clone()
    }

    /// Path prefix still served during maintenance (can be called several times).
    pub fn allow(mut self, prefix: impl Into<String>) -> Self {
        self.allow.push(normalize_prefix(prefix));
        self
    }

    /// `Retry-After`, in whole seconds.
    pub fn retry_after(mut self, after: Duration) -> Self {
        self.retry_after = Some(after.as_secs());
        self
    }

    /// The message (text and JSON answers).
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// The page shown to browsers.
    pub fn html(mut self, page: impl Into<String>) -> Self {
        self.html = Some(page.into());
        self
    }

    fn response(&self, accept: &str) -> Response {
        let res = Response::new().status(StatusCode::SERVICE_UNAVAILABLE);
        let mut res = match &self.html {
            Some(page) if accept.contains("text/html") => res.html(page.clone()),
            _ if accept.contains("json") => res.json(json!({
                "error": "maintenance",
                "message": self.message,
            })),
            _ => res.text(self.message.clone()),
        };
        let headers = res.headers_mut();
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if let Some(secs) = self.retry_after {
            headers.insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        res
    }
}

impl Middleware for Maintenance {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if !self.switch.is_on() || self.allow.iter().any(|p| path_matches(req.path(), p)) {
            return next.run(req);
        }
        let res = self.response(req.header(header::ACCEPT).unwrap_or(""));
        Box::pin(std::future::ready(res))
    }
}
