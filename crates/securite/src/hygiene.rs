//! HTTP hygiene: request-smuggling defences and protocol sanity checks.

use http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::{StatusCode, request};

use crate::guard::impl_layer;
use crate::util::{has_invalid_percent, percent_decode};
use crate::{Context, Guard, Rejection, priority};

/// Rejects malformed or ambiguous requests that are commonly used for
/// request smuggling, cache poisoning, path traversal or resource
/// exhaustion.
///
/// | Check | Default |
/// |---|---|
/// | Both `Content-Length` and `Transfer-Encoding` | rejected |
/// | Conflicting / invalid `Content-Length` values | rejected |
/// | `Transfer-Encoding` other than `chunked` | rejected |
/// | Several `Host` headers | rejected |
/// | URI length | 8 KiB |
/// | Number of headers | 100 |
/// | Size of all headers | 32 KiB |
/// | Number of query parameters | 256 |
/// | NUL / control characters in path (raw or `%00`) | rejected |
/// | `..` and `.` path segments (raw or encoded) | rejected |
/// | Malformed percent-encoding in path | rejected |
#[derive(Debug, Clone)]
pub struct Hygiene {
    max_uri: usize,
    max_headers: usize,
    max_header_bytes: usize,
    max_query_params: usize,
    reject_traversal: bool,
    reject_bad_encoding: bool,
}

impl Default for Hygiene {
    fn default() -> Self {
        Self::new()
    }
}

fn bad(code: &'static str, msg: &'static str) -> Rejection {
    Rejection::new(StatusCode::BAD_REQUEST, code, msg)
}

impl Hygiene {
    /// Defaults from the table above.
    pub fn new() -> Self {
        Self {
            max_uri: 8 * 1024,
            max_headers: 100,
            max_header_bytes: 32 * 1024,
            max_query_params: 256,
            reject_traversal: true,
            reject_bad_encoding: true,
        }
    }

    /// Maximum URI length in bytes (`414 URI Too Long`).
    pub fn max_uri_length(mut self, max: usize) -> Self {
        self.max_uri = max;
        self
    }

    /// Maximum number of request headers (`431`).
    pub fn max_headers(mut self, max: usize) -> Self {
        self.max_headers = max;
        self
    }

    /// Maximum cumulated size of header names and values (`431`).
    pub fn max_header_bytes(mut self, max: usize) -> Self {
        self.max_header_bytes = max;
        self
    }

    /// Maximum number of query parameters (HashDoS / parser exhaustion).
    pub fn max_query_params(mut self, max: usize) -> Self {
        self.max_query_params = max;
        self
    }

    /// Allow `..` segments in paths (not recommended).
    pub fn allow_dot_segments(mut self) -> Self {
        self.reject_traversal = false;
        self
    }

    /// Allow malformed percent-encoding in paths.
    pub fn allow_bad_encoding(mut self) -> Self {
        self.reject_bad_encoding = false;
        self
    }

    fn check_framing(req: &request::Parts) -> Result<(), Rejection> {
        let te: Vec<_> = req.headers.get_all(TRANSFER_ENCODING).iter().collect();
        let cl: Vec<_> = req.headers.get_all(CONTENT_LENGTH).iter().collect();
        if !te.is_empty() && !cl.is_empty() {
            return Err(bad(
                "ambiguous_framing",
                "Both Content-Length and Transfer-Encoding.",
            ));
        }
        if te.len() > 1
            || te.iter().any(|v| {
                !v.to_str()
                    .is_ok_and(|s| s.trim().eq_ignore_ascii_case("chunked"))
            })
        {
            return Err(bad(
                "bad_transfer_encoding",
                "Unsupported Transfer-Encoding.",
            ));
        }
        let mut seen: Option<u64> = None;
        for v in cl {
            for part in v.to_str().unwrap_or("x").split(',') {
                let part = part.trim();
                if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad("bad_content_length", "Invalid Content-Length."));
                }
                let n: u64 = part
                    .parse()
                    .map_err(|_| bad("bad_content_length", "Invalid Content-Length."))?;
                if seen.is_some_and(|s| s != n) {
                    return Err(bad("bad_content_length", "Conflicting Content-Length."));
                }
                seen = Some(n);
            }
        }
        if req.headers.get_all(HOST).iter().count() > 1 {
            return Err(bad("duplicate_host", "Several Host headers."));
        }
        Ok(())
    }

    fn check_path(&self, path: &str) -> Result<(), Rejection> {
        if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(bad("bad_path", "Invalid characters in path."));
        }
        if self.reject_bad_encoding && has_invalid_percent(path) {
            return Err(bad("bad_path_encoding", "Malformed percent-encoding."));
        }
        let decoded = percent_decode(path, false);
        // Double encoding (`%252e`) is decoded twice.
        let decoded = if decoded.contains('%') {
            percent_decode(&decoded, false).into_owned()
        } else {
            decoded.into_owned()
        };
        if decoded.chars().any(|c| c == '\0' || c == '\r' || c == '\n') {
            return Err(bad("bad_path", "Invalid characters in path."));
        }
        if self.reject_traversal
            && decoded
                .split(['/', '\\'])
                .any(|seg| seg == ".." || seg == ".")
        {
            return Err(bad("path_traversal", "Dot segments are not allowed."));
        }
        Ok(())
    }
}

impl Guard for Hygiene {
    fn name(&self) -> &'static str {
        "hygiene"
    }

    fn priority(&self) -> u16 {
        priority::HYGIENE
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let uri_len = req.uri.path_and_query().map_or(0, |pq| pq.as_str().len());
        if uri_len > self.max_uri {
            return Err(Rejection::new(
                StatusCode::URI_TOO_LONG,
                "uri_too_long",
                "URI too long.",
            ));
        }
        if req.headers.len() > self.max_headers {
            return Err(Rejection::new(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "too_many_headers",
                "Too many headers.",
            ));
        }
        let header_bytes: usize = req
            .headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len())
            .sum();
        if header_bytes > self.max_header_bytes {
            return Err(Rejection::new(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "headers_too_large",
                "Headers too large.",
            ));
        }
        Self::check_framing(req)?;
        self.check_path(req.uri.path())?;
        if let Some(q) = req.uri.query() {
            if q.split('&').count() > self.max_query_params {
                return Err(bad("too_many_params", "Too many query parameters."));
            }
            if q.contains("%00") {
                return Err(bad("bad_query", "NUL byte in query."));
            }
        }
        Ok(())
    }
}

impl_layer!(Hygiene);

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn run(uri: &str, headers: &[(&str, &str)]) -> Result<(), Rejection> {
        let mut b = Request::builder().method("POST").uri(uri);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut p = b.body(()).unwrap().into_parts().0;
        let mut ctx = Context::new(p.method.clone(), p.uri.clone(), None);
        Hygiene::new().on_request(&mut p, &mut ctx)
    }

    #[test]
    fn smuggling() {
        assert!(
            run(
                "/",
                &[("content-length", "5"), ("transfer-encoding", "chunked")]
            )
            .is_err()
        );
        assert!(run("/", &[("transfer-encoding", "gzip, chunked")]).is_err());
        assert!(run("/", &[("transfer-encoding", "chunked")]).is_ok());
        assert!(run("/", &[("content-length", "5"), ("content-length", "6")]).is_err());
        assert!(run("/", &[("content-length", "5, 5")]).is_ok());
        assert!(run("/", &[("content-length", "+5")]).is_err());
        assert!(run("/", &[("host", "a"), ("host", "b")]).is_err());
    }

    #[test]
    fn paths() {
        assert!(run("/ok/path", &[]).is_ok());
        assert!(run("/a/../etc/passwd", &[]).is_err());
        assert!(run("/a/%2e%2e/etc", &[]).is_err());
        assert!(run("/a/%252e%252e/etc", &[]).is_err());
        assert!(run("/a/..%5c..%5cwin.ini", &[]).is_err());
        assert!(run("/a%00b", &[]).is_err());
        assert!(run("/a%0d%0aSet-Cookie:x", &[]).is_err());
        assert!(run("/a%zz", &[]).is_err());
        assert!(run("/files/report..pdf", &[]).is_ok());
    }

    #[test]
    fn limits() {
        let long = format!("/{}", "a".repeat(9000));
        assert_eq!(
            run(&long, &[]).unwrap_err().status(),
            StatusCode::URI_TOO_LONG
        );
        let q = format!("/?{}", vec!["a=1"; 300].join("&"));
        assert!(run(&q, &[]).is_err());
        assert!(run("/?x=%00", &[]).is_err());
    }
}
