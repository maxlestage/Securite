//! Host header allow-list (Host header injection, DNS rebinding).

use http::header::HOST;
use http::{StatusCode, request};

use crate::guard::impl_layer;
use crate::{Context, Guard, Mode, Rejection, priority};

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostRule {
    Exact(String),
    /// `*.example.com` → `.example.com`
    Suffix(String),
}

/// Only answers requests addressed to your domains.
///
/// Prevents Host header poisoning (password-reset links, cache poisoning)
/// and DNS-rebinding attacks against services listening on localhost.
///
/// ```
/// use securite::prelude::*;
///
/// let hosts = HostFilter::new(["example.com", "*.example.com"]).allow_localhost();
/// ```
#[derive(Debug, Clone)]
pub struct HostFilter {
    rules: Vec<HostRule>,
    mode: Mode,
}

impl HostFilter {
    /// Allowed host names (port-insensitive). `*.example.com` matches every
    /// sub-domain (but not `example.com` itself).
    pub fn new<I, S>(hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self {
            rules: Vec::new(),
            mode: Mode::Enforce,
        }
        .allow(hosts)
    }

    /// Adds allowed hosts.
    pub fn allow<I, S>(mut self, hosts: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for h in hosts {
            let h = h.as_ref().trim().to_ascii_lowercase();
            let rule = match h.strip_prefix("*.") {
                Some(rest) => HostRule::Suffix(format!(".{rest}")),
                None => HostRule::Exact(h),
            };
            self.rules.push(rule);
        }
        self
    }

    /// Also accept `localhost`, `127.0.0.1` and `[::1]` (local development).
    pub fn allow_localhost(self) -> Self {
        self.allow(["localhost", "127.0.0.1", "[::1]"])
    }

    /// Monitor-only mode.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    /// Whether `host` (with or without port) is allowed.
    pub fn is_allowed(&self, host: &str) -> bool {
        let host = strip_port(host).to_ascii_lowercase();
        let host = host.trim_end_matches('.');
        self.rules.iter().any(|r| match r {
            HostRule::Exact(h) => h == host,
            HostRule::Suffix(s) => host.len() > s.len() && host.ends_with(s.as_str()),
        })
    }
}

fn strip_port(host: &str) -> &str {
    if host.starts_with('[') {
        // [::1]:8080
        return host.find(']').map_or(host, |i| &host[..=i]);
    }
    match host.rsplit_once(':') {
        Some((h, port)) if port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host,
    }
}

impl Guard for HostFilter {
    fn name(&self) -> &'static str {
        "host"
    }

    fn priority(&self) -> u16 {
        priority::HOST
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let host = req.uri.host().map(str::to_owned).or_else(|| {
            req.headers
                .get(HOST)
                .and_then(|h| h.to_str().ok())
                .map(str::to_owned)
        });
        match host {
            Some(h) if self.is_allowed(&h) => Ok(()),
            Some(h) => Err(Rejection::new(
                StatusCode::MISDIRECTED_REQUEST,
                "invalid_host",
                "Unknown host.",
            )
            .with_details(format!("host={}", h.escape_debug()))),
            None => Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "missing_host",
                "Missing Host header.",
            )),
        }
    }
}

impl_layer!(HostFilter);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let f = HostFilter::new(["example.com", "*.example.org"]).allow_localhost();
        assert!(f.is_allowed("example.com"));
        assert!(f.is_allowed("EXAMPLE.com:443"));
        assert!(f.is_allowed("example.com."));
        assert!(!f.is_allowed("evil.com"));
        assert!(!f.is_allowed("example.com.evil.com"));
        assert!(f.is_allowed("api.example.org"));
        assert!(!f.is_allowed("example.org"));
        assert!(!f.is_allowed("evilexample.org"));
        assert!(f.is_allowed("localhost:3000"));
        assert!(f.is_allowed("[::1]:8080"));
    }
}
