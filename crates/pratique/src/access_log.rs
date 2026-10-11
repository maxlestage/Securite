//! Access logs for log pipelines: JSON lines or the Apache combined format.

use std::io::Write as _;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use vitesse::http::header;
use vitesse::{BoxFuture, Middleware, Next, Request, Response};

use crate::util::{json_escape, normalize_prefix, path_matches, unix_secs};

type Sink = Arc<dyn Fn(&str) + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Json,
    Combined,
}

/// What is known about a request once it is answered.
struct Line {
    time: SystemTime,
    ip: Option<std::net::IpAddr>,
    method: String,
    target: String,
    version: vitesse::http::Version,
    status: u16,
    bytes: Option<u64>,
    duration_ms: f64,
    referer: Option<String>,
    user_agent: Option<String>,
    request_id: Option<String>,
}

/// Writes one line per request, for Loki, Elasticsearch, CloudWatch,
/// GoAccess … (Vitesse's `middleware::logger()` is made for humans; this one
/// is made for machines).
///
/// * [`json`](AccessLog::json): one JSON object per line
///   (`{"time":"2026-10-11T08:49:37.042Z","ip":"203.0.113.9","method":"GET","path":"/","status":200,…}`);
/// * [`combined`](AccessLog::combined): the Apache / Nginx "combined" format,
///   understood by every log analyzer.
///
/// Lines go to standard output, or anywhere with [`to`](AccessLog::to).
///
/// ```
/// use pratique::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(AccessLog::json().skip("/health"));
/// ```
#[derive(Clone)]
pub struct AccessLog {
    format: Format,
    sink: Sink,
    skip: Vec<String>,
}

impl std::fmt::Debug for AccessLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessLog")
            .field("format", &self.format)
            .field("skip", &self.skip)
            .finish_non_exhaustive()
    }
}

fn stdout(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
}

impl AccessLog {
    /// JSON lines on standard output.
    pub fn json() -> Self {
        Self::with(Format::Json)
    }

    /// Apache "combined" lines on standard output.
    pub fn combined() -> Self {
        Self::with(Format::Combined)
    }

    fn with(format: Format) -> Self {
        Self {
            format,
            sink: Arc::new(stdout),
            skip: Vec::new(),
        }
    }

    /// Sends every line (without the newline) to `sink`: a file, `tracing`,
    /// a channel …
    pub fn to<F>(mut self, sink: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        self.sink = Arc::new(sink);
        self
    }

    /// Doesn't log requests under this path prefix (health checks, metrics …).
    pub fn skip(mut self, prefix: impl Into<String>) -> Self {
        self.skip.push(normalize_prefix(prefix));
        self
    }

    fn format(&self, line: &Line) -> String {
        match self.format {
            Format::Json => json_line(line),
            Format::Combined => combined_line(line),
        }
    }
}

fn json_line(l: &Line) -> String {
    let mut s = String::with_capacity(256);
    s.push_str("{\"time\":\"");
    s.push_str(&crate::util::rfc3339(l.time));
    s.push('"');
    let mut field = |name: &str, value: Option<&str>| {
        if let Some(value) = value {
            s.push_str(",\"");
            s.push_str(name);
            s.push_str("\":\"");
            json_escape(&mut s, value);
            s.push('"');
        }
    };
    field("ip", l.ip.map(|ip| ip.to_string()).as_deref());
    field("method", Some(&l.method));
    field("path", Some(&l.target));
    field("version", Some(&format!("{:?}", l.version)));
    field("referer", l.referer.as_deref());
    field("user_agent", l.user_agent.as_deref());
    field("request_id", l.request_id.as_deref());
    s.push_str(&format!(",\"status\":{}", l.status));
    if let Some(bytes) = l.bytes {
        s.push_str(&format!(",\"bytes\":{bytes}"));
    }
    s.push_str(&format!(",\"duration_ms\":{:.3}}}", l.duration_ms));
    s
}

/// Quoted field of the combined format: `"` `\` and control characters are
/// escaped, so a crafted `User-Agent` cannot forge another log line.
fn quoted(out: &mut String, value: Option<&str>) {
    let Some(value) = value else {
        out.push_str("\"-\"");
        return;
    };
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `10/Oct/2000:13:55:36 +0000`
fn clf_date(time: SystemTime) -> String {
    // `Tue, 10 Oct 2000 13:55:36 GMT` → `10/Oct/2000:13:55:36 +0000`
    let http = crate::util::http_date(time);
    let parts: Vec<&str> = http.split(' ').collect();
    match parts.as_slice() {
        [_, day, month, year, clock, _] => format!("{day}/{month}/{year}:{clock} +0000"),
        _ => unix_secs(time).to_string(),
    }
}

fn combined_line(l: &Line) -> String {
    let mut s = String::with_capacity(256);
    match l.ip {
        Some(ip) => s.push_str(&ip.to_string()),
        None => s.push('-'),
    }
    s.push_str(" - - [");
    s.push_str(&clf_date(l.time));
    s.push_str("] ");
    let request = format!("{} {} {:?}", l.method, l.target, l.version);
    quoted(&mut s, Some(&request));
    s.push_str(&format!(" {} ", l.status));
    match l.bytes {
        Some(bytes) => s.push_str(&bytes.to_string()),
        None => s.push('-'),
    }
    s.push(' ');
    quoted(&mut s, l.referer.as_deref());
    s.push(' ');
    quoted(&mut s, l.user_agent.as_deref());
    s
}

impl Middleware for AccessLog {
    fn handle(&'static self, req: Request, next: Next) -> BoxFuture<Response> {
        if self.skip.iter().any(|p| path_matches(req.path(), p)) {
            return next.run(req);
        }
        let start = Instant::now();
        let time = SystemTime::now();
        let header = |name| req.header(name).map(str::to_owned);
        let mut line = Line {
            time,
            ip: req.ip(),
            method: req.method().to_string(),
            target: req
                .uri()
                .path_and_query()
                .map_or_else(|| req.path().to_owned(), |pq| pq.as_str().to_owned()),
            version: req.version(),
            status: 0,
            bytes: None,
            duration_ms: 0.0,
            referer: header(header::REFERER),
            user_agent: header(header::USER_AGENT),
            request_id: header(vitesse::http::HeaderName::from_static("x-request-id")),
        };
        Box::pin(async move {
            let res = next.run(req).await;
            line.status = res.status_code().as_u16();
            line.bytes = res.body().size();
            line.duration_ms = start.elapsed().as_secs_f64() * 1000.0;
            if line.request_id.is_none() {
                line.request_id = res.get_header("x-request-id").map(str::to_owned);
            }
            (self.sink)(&self.format(&line));
            res
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    fn line() -> Line {
        Line {
            time: UNIX_EPOCH + Duration::from_secs(971_186_136),
            ip: Some("203.0.113.9".parse().unwrap()),
            method: "GET".into(),
            target: "/a?b=1".into(),
            version: vitesse::http::Version::HTTP_11,
            status: 200,
            bytes: Some(2326),
            duration_ms: 1.5,
            referer: None,
            user_agent: Some("curl/8 \"evil\"\nGET / HTTP/1.1".into()),
            request_id: Some("abc".into()),
        }
    }

    #[test]
    fn combined_format() {
        assert_eq!(
            combined_line(&line()),
            "203.0.113.9 - - [10/Oct/2000:13:55:36 +0000] \"GET /a?b=1 HTTP/1.1\" 200 2326 \"-\" \
             \"curl/8 \\\"evil\\\"\\x0aGET / HTTP/1.1\""
        );
    }

    #[test]
    fn json_format() {
        assert_eq!(
            json_line(&line()),
            "{\"time\":\"2000-10-10T13:55:36.000Z\",\"ip\":\"203.0.113.9\",\"method\":\"GET\",\
             \"path\":\"/a?b=1\",\"version\":\"HTTP/1.1\",\
             \"user_agent\":\"curl/8 \\\"evil\\\"\\nGET / HTTP/1.1\",\"request_id\":\"abc\",\
             \"status\":200,\"bytes\":2326,\"duration_ms\":1.500}"
        );
    }
}
