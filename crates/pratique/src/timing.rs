//! How long the app took to answer.

use std::time::Instant;

use vitesse::http::header::{HeaderName, HeaderValue};
use vitesse::{BoxFuture, Middleware, Next, Request, Response};

/// Adds the time spent producing the response head: `X-Response-Time: 1.234ms`
/// and `Server-Timing: app;dur=1.234`, which browsers show in their developer
/// tools (Network → Timing).
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(ResponseTime::new());
/// ```
#[derive(Debug, Clone)]
pub struct ResponseTime {
    header: Option<HeaderName>,
    server_timing: Option<String>,
    digits: usize,
}

impl Default for ResponseTime {
    fn default() -> Self {
        Self::new()
    }
}

impl ResponseTime {
    /// `X-Response-Time` and `Server-Timing: app;dur=…`, 3 decimals.
    pub fn new() -> Self {
        Self {
            header: Some(HeaderName::from_static("x-response-time")),
            server_timing: Some("app".into()),
            digits: 3,
        }
    }

    /// Custom header name, or `None` to only send `Server-Timing`.
    ///
    /// # Panics
    /// If `name` is not a valid header name.
    pub fn header(mut self, name: Option<&str>) -> Self {
        self.header =
            name.map(|n| HeaderName::from_bytes(n.as_bytes()).expect("invalid header name"));
        self
    }

    /// Metric name in `Server-Timing` (default `app`), or `None` to leave it out.
    pub fn server_timing(mut self, metric: Option<&str>) -> Self {
        self.server_timing = metric.map(str::to_owned);
        self
    }

    /// Decimals of the milliseconds (default 3).
    pub fn digits(mut self, digits: usize) -> Self {
        self.digits = digits;
        self
    }
}

impl Middleware for ResponseTime {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        let start = Instant::now();
        Box::pin(async move {
            let mut res = next.run(req).await;
            let ms = start.elapsed().as_secs_f64() * 1000.0;
            let digits = self.digits;
            if let Some(name) = &self.header {
                if let Ok(value) = HeaderValue::from_str(&format!("{ms:.digits$}ms")) {
                    res.headers_mut().insert(name.clone(), value);
                }
            }
            if let Some(metric) = &self.server_timing {
                if let Ok(value) = HeaderValue::from_str(&format!("{metric};dur={ms:.digits$}")) {
                    res.headers_mut().append("server-timing", value);
                }
            }
            res
        })
    }
}
