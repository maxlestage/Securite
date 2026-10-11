//! A health check endpoint for load balancers and orchestrators.

use std::sync::Arc;
use std::time::Instant;

use vitesse::http::header::{self, HeaderValue};
use vitesse::serde_json::{Map, Value};
use vitesse::{BoxFuture, Method, Middleware, Next, Request, Response, StatusCode, json};

type Check = Arc<dyn Fn() -> bool + Send + Sync>;

/// Answers `GET /health` itself (before the routes, without logging noise
/// in your handlers), in the `application/health+json` format:
///
/// ```json
/// {
///   "checks": {
///     "database": [{ "status": "pass" }],
///     "uptime": [{ "componentType": "system", "observedUnit": "s", "observedValue": 3600, "status": "pass" }]
///   },
///   "status": "pass",
///   "version": "1.4.0"
/// }
/// ```
///
/// Every [`check`](Health::check) must pass for a `200`; otherwise the answer
/// is `503` with `"status":"fail"`, so the load balancer stops sending
/// traffic. Checks run on every probe: keep them cheap (read a flag kept up
/// to date by a background task rather than querying the database).
///
/// ```
/// use pratique::prelude::*;
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicBool, Ordering};
/// use vitesse::prelude::*;
///
/// let db_up = Arc::new(AtomicBool::new(true));
/// let probe = db_up.clone();
///
/// let mut app = App::new();
/// app.middleware(
///     Health::new()
///         .version(env!("CARGO_PKG_VERSION"))
///         .check("database", move || probe.load(Ordering::Relaxed)),
/// );
/// ```
#[derive(Clone)]
pub struct Health {
    path: String,
    version: Option<String>,
    checks: Vec<(String, Check)>,
    started: Instant,
}

impl std::fmt::Debug for Health {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Health")
            .field("path", &self.path)
            .field("version", &self.version)
            .field(
                "checks",
                &self.checks.iter().map(|(n, _)| n).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl Default for Health {
    fn default() -> Self {
        Self::new()
    }
}

impl Health {
    /// `GET /health`, no check.
    pub fn new() -> Self {
        Self {
            path: "/health".into(),
            version: None,
            checks: Vec::new(),
            started: Instant::now(),
        }
    }

    /// Another path (`/healthz`, `/_health` …).
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = crate::util::normalize_prefix(path);
        self
    }

    /// Version shown in the answer.
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// A named check; `false` fails the probe.
    pub fn check<F>(mut self, name: impl Into<String>, check: F) -> Self
    where
        F: Fn() -> bool + Send + Sync + 'static,
    {
        self.checks.push((name.into(), Arc::new(check)));
        self
    }

    fn response(&self) -> Response {
        // `application/health+json`: every check is a list of measurements.
        let mut checks = Map::new();
        checks.insert(
            "uptime".into(),
            json!([{
                "componentType": "system",
                "observedValue": self.started.elapsed().as_secs(),
                "observedUnit": "s",
                "status": "pass",
            }]),
        );
        let mut healthy = true;
        for (name, check) in &self.checks {
            let pass = check();
            healthy &= pass;
            let status = if pass { "pass" } else { "fail" };
            checks.insert(name.clone(), json!([{ "status": status }]));
        }
        let mut body = json!({
            "status": if healthy { "pass" } else { "fail" },
            "checks": checks,
        });
        if let Some(version) = &self.version {
            body["version"] = Value::from(version.as_str());
        }
        let status = if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let mut res = Response::new().status(status).json(body);
        let headers = res.headers_mut();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/health+json"),
        );
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        res
    }
}

impl Middleware for Health {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        // `/health` and `/health/`, like the routes of Vitesse.
        let path = req.path();
        let on_path = path == self.path || path.strip_suffix('/') == Some(self.path.as_str());
        if !on_path || !matches!(*req.method(), Method::GET | Method::HEAD) {
            return next.run(req);
        }
        Box::pin(std::future::ready(self.response()))
    }
}
