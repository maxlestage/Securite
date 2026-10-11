//! Prometheus metrics: request counts, latency histogram, in-flight requests.

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

use vitesse::http::header::{self, HeaderValue};
use vitesse::{BoxFuture, Method, Middleware, Next, Request, Response};

const METHODS: [&str; 8] = [
    "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "OTHER",
];
const CLASSES: [&str; 5] = ["1xx", "2xx", "3xx", "4xx", "5xx"];
/// Upper bounds of the latency buckets, in seconds.
const BUCKETS: [f64; 12] = [
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

struct Registry {
    requests: [[AtomicU64; CLASSES.len()]; METHODS.len()],
    /// Per bucket (not cumulative), plus `+Inf` at the end.
    buckets: [AtomicU64; BUCKETS.len() + 1],
    sum_micros: AtomicU64,
    in_flight: AtomicI64,
    started: Instant,
}

impl Registry {
    fn new() -> Self {
        Self {
            requests: Default::default(),
            buckets: Default::default(),
            sum_micros: AtomicU64::new(0),
            in_flight: AtomicI64::new(0),
            started: Instant::now(),
        }
    }

    fn method_index(method: &Method) -> usize {
        METHODS
            .iter()
            .position(|m| *m == method.as_str())
            .unwrap_or(METHODS.len() - 1)
    }

    fn record(&self, method: usize, status: u16, seconds: f64) {
        let class = usize::from(status / 100).clamp(1, 5) - 1;
        self.requests[method][class].fetch_add(1, Ordering::Relaxed);
        let bucket = BUCKETS
            .iter()
            .position(|le| seconds <= *le)
            .unwrap_or(BUCKETS.len());
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.sum_micros
            .fetch_add((seconds * 1e6) as u64, Ordering::Relaxed);
    }

    fn total(&self) -> u64 {
        self.buckets.iter().map(|b| b.load(Ordering::Relaxed)).sum()
    }

    fn render(&self, prefix: &str) -> String {
        let mut out = String::with_capacity(2048);
        let _ = writeln!(
            out,
            "# HELP {prefix}_requests_total Requests answered, by method and status class.\n\
             # TYPE {prefix}_requests_total counter"
        );
        for (m, method) in METHODS.iter().enumerate() {
            for (c, class) in CLASSES.iter().enumerate() {
                let n = self.requests[m][c].load(Ordering::Relaxed);
                if n > 0 {
                    let _ = writeln!(
                        out,
                        "{prefix}_requests_total{{method=\"{method}\",status=\"{class}\"}} {n}"
                    );
                }
            }
        }
        let _ = writeln!(
            out,
            "# HELP {prefix}_request_duration_seconds Time to produce the response head.\n\
             # TYPE {prefix}_request_duration_seconds histogram"
        );
        let mut cumulative = 0;
        for (i, le) in BUCKETS.iter().enumerate() {
            cumulative += self.buckets[i].load(Ordering::Relaxed);
            let _ = writeln!(
                out,
                "{prefix}_request_duration_seconds_bucket{{le=\"{le}\"}} {cumulative}"
            );
        }
        cumulative += self.buckets[BUCKETS.len()].load(Ordering::Relaxed);
        let sum = self.sum_micros.load(Ordering::Relaxed) as f64 / 1e6;
        let _ = writeln!(
            out,
            "{prefix}_request_duration_seconds_bucket{{le=\"+Inf\"}} {cumulative}\n\
             {prefix}_request_duration_seconds_sum {sum}\n\
             {prefix}_request_duration_seconds_count {cumulative}"
        );
        let _ = writeln!(
            out,
            "# HELP {prefix}_requests_in_flight Requests being processed.\n\
             # TYPE {prefix}_requests_in_flight gauge\n\
             {prefix}_requests_in_flight {}",
            self.in_flight.load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP process_uptime_seconds Seconds since the app started.\n\
             # TYPE process_uptime_seconds gauge\n\
             process_uptime_seconds {}",
            self.started.elapsed().as_secs()
        );
        out
    }
}

/// Decrements the in-flight gauge, even when the request is cancelled.
struct InFlight<'a>(&'a AtomicI64);

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counts every request and serves the numbers at `GET /metrics`, in the
/// Prometheus text format (scraped by Prometheus, Grafana Agent, Datadog,
/// VictoriaMetrics …):
///
/// * `http_requests_total{method, status}`: by method and status class
///   (`2xx`, `4xx` …), a bounded set of series, whatever the paths;
/// * `http_request_duration_seconds`: latency histogram;
/// * `http_requests_in_flight` and `process_uptime_seconds`.
///
/// The metrics endpoint does not count itself. To keep it private, put an
/// authentication middleware (e.g. Securite's `Auth`) or an IP allow-list
/// before it.
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let metrics = Metrics::new();
/// let handle = metrics.handle(); // `handle.total()` from your own code
///
/// let mut app = App::new();
/// app.middleware(metrics);
/// ```
#[derive(Clone)]
pub struct Metrics {
    path: String,
    prefix: String,
    registry: Arc<Registry>,
}

impl std::fmt::Debug for Metrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Metrics")
            .field("path", &self.path)
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// `GET /metrics`, metric names starting with `http_`.
    pub fn new() -> Self {
        Self {
            path: "/metrics".into(),
            prefix: "http".into(),
            registry: Arc::new(Registry::new()),
        }
    }

    /// Another path for the endpoint.
    pub fn path(mut self, path: impl Into<String>) -> Self {
        self.path = crate::util::normalize_prefix(path);
        self
    }

    /// Prefix of the metric names (default `http`, e.g. `myapp_http`).
    ///
    /// # Panics
    /// If `prefix` is not a valid Prometheus metric name.
    pub fn prefix(mut self, prefix: impl Into<String>) -> Self {
        let prefix = prefix.into();
        let valid = prefix
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()));
        assert!(
            valid && !prefix.is_empty(),
            "invalid metric prefix {prefix:?}"
        );
        self.prefix = prefix;
        self
    }

    /// A handle to read the numbers from your own code.
    pub fn handle(&self) -> MetricsHandle {
        MetricsHandle {
            prefix: self.prefix.clone(),
            registry: self.registry.clone(),
        }
    }
}

impl Middleware for Metrics {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if req.path() == self.path && *req.method() == Method::GET {
            let mut res = Response::new().send(self.registry.render(&self.prefix));
            let headers = res.headers_mut();
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            return Box::pin(std::future::ready(res));
        }
        let registry = &self.registry;
        let method = Registry::method_index(req.method());
        let start = Instant::now();
        registry.in_flight.fetch_add(1, Ordering::Relaxed);
        let guard = InFlight(&registry.in_flight);
        Box::pin(async move {
            let res = next.run(req).await;
            registry.record(
                method,
                res.status_code().as_u16(),
                start.elapsed().as_secs_f64(),
            );
            drop(guard);
            res
        })
    }
}

/// Reads the numbers of a [`Metrics`] middleware.
#[derive(Clone)]
pub struct MetricsHandle {
    prefix: String,
    registry: Arc<Registry>,
}

impl std::fmt::Debug for MetricsHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsHandle")
            .field("total", &self.total())
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

impl MetricsHandle {
    /// Requests answered so far.
    pub fn total(&self) -> u64 {
        self.registry.total()
    }

    /// Requests answered with this status class (`2` for `2xx` …).
    pub fn by_class(&self, class: u8) -> u64 {
        let Some(c) = usize::from(class)
            .checked_sub(1)
            .filter(|c| *c < CLASSES.len())
        else {
            return 0;
        };
        self.registry
            .requests
            .iter()
            .map(|m| m[c].load(Ordering::Relaxed))
            .sum()
    }

    /// Requests being processed right now.
    pub fn in_flight(&self) -> i64 {
        self.registry.in_flight.load(Ordering::Relaxed)
    }

    /// The Prometheus text, as served by the endpoint.
    pub fn render(&self) -> String {
        self.registry.render(&self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposition_format() {
        let r = Registry::new();
        r.record(Registry::method_index(&Method::GET), 200, 0.003);
        r.record(Registry::method_index(&Method::POST), 503, 20.0);
        r.record(
            Registry::method_index(&Method::from_bytes(b"PURGE").unwrap()),
            404,
            0.0,
        );
        let text = r.render("http");
        assert!(text.contains("http_requests_total{method=\"GET\",status=\"2xx\"} 1\n"));
        assert!(text.contains("http_requests_total{method=\"POST\",status=\"5xx\"} 1\n"));
        assert!(text.contains("http_requests_total{method=\"OTHER\",status=\"4xx\"} 1\n"));
        assert!(text.contains("http_request_duration_seconds_bucket{le=\"0.001\"} 1\n"));
        assert!(text.contains("http_request_duration_seconds_bucket{le=\"0.005\"} 2\n"));
        assert!(text.contains("http_request_duration_seconds_bucket{le=\"10\"} 2\n"));
        assert!(text.contains("http_request_duration_seconds_bucket{le=\"+Inf\"} 3\n"));
        assert!(text.contains("http_request_duration_seconds_count 3\n"));
        assert_eq!(r.total(), 3);
    }

    #[test]
    #[should_panic(expected = "invalid metric prefix")]
    fn prefixes_are_validated() {
        let _ = Metrics::new().prefix("my-app");
    }
}
