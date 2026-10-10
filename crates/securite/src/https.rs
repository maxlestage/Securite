//! Redirect plain HTTP to HTTPS (TLS-terminating proxy aware).

use http::header::{HOST, HeaderValue, LOCATION};
use http::{StatusCode, request};

use crate::guard::impl_layer;
use crate::util::{any_path_matches, normalize_prefix};
use crate::{Context, Guard, Rejection, priority};

/// Redirects `http://` requests to `https://` with `308 Permanent Redirect`
/// (method and body preserved).
///
/// The scheme is read from the request URI or, behind a proxy (Heroku,
/// Render, AWS ALB, Cloudflare …), from `X-Forwarded-Proto` / `Forwarded:
/// proto=`. When the scheme is unknown (local development) nothing happens.
///
/// `/.well-known/acme-challenge/` is exempt so Let's Encrypt keeps working.
#[derive(Debug, Clone)]
pub struct HttpsRedirect {
    trust_forwarded: bool,
    exempt: Vec<String>,
}

impl Default for HttpsRedirect {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpsRedirect {
    /// Trusts `X-Forwarded-Proto` (set it to `false` if you are not behind
    /// a proxy).
    pub fn new() -> Self {
        Self {
            trust_forwarded: true,
            exempt: vec!["/.well-known/acme-challenge/".into()],
        }
    }

    /// Whether to trust `X-Forwarded-Proto` / `Forwarded`.
    pub fn trust_forwarded_proto(mut self, trust: bool) -> Self {
        self.trust_forwarded = trust;
        self
    }

    /// Paths never redirected (health checks …).
    pub fn exempt(mut self, prefix: impl Into<String>) -> Self {
        self.exempt.push(normalize_prefix(prefix));
        self
    }

    fn is_plain_http(&self, req: &request::Parts) -> bool {
        if let Some(scheme) = req.uri.scheme_str() {
            return scheme.eq_ignore_ascii_case("http");
        }
        if !self.trust_forwarded {
            return false;
        }
        if let Some(proto) = req
            .headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
        {
            // Right-most value was set by the closest (trusted) proxy, the
            // same trust model as `ClientIpSource::XForwardedFor`.
            let last = proto.rsplit(',').next().unwrap_or("").trim();
            return last.eq_ignore_ascii_case("http");
        }
        req.headers
            .get("forwarded")
            .and_then(|v| v.to_str().ok())
            .and_then(|f| {
                f.split([';', ',']).find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    k.trim()
                        .eq_ignore_ascii_case("proto")
                        .then(|| v.trim().trim_matches('"').eq_ignore_ascii_case("http"))
                })
            })
            .unwrap_or(false)
    }
}

impl Guard for HttpsRedirect {
    fn name(&self) -> &'static str {
        "https_redirect"
    }

    fn priority(&self) -> u16 {
        priority::HTTPS_REDIRECT
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        if !self.is_plain_http(req) || any_path_matches(req.uri.path(), &self.exempt) {
            return Ok(());
        }
        let host = req
            .uri
            .authority()
            .map(|a| a.host().to_owned())
            .or_else(|| {
                req.headers
                    .get(HOST)
                    .and_then(|h| h.to_str().ok())
                    .map(|h| {
                        // Drop the port: the HTTPS port is the default one.
                        match h.rsplit_once(':') {
                            Some((host, port))
                                if !h.ends_with(']')
                                    && port.bytes().all(|b| b.is_ascii_digit()) =>
                            {
                                host.to_owned()
                            }
                            _ => h.to_owned(),
                        }
                    })
            });
        let Some(host) = host.filter(|h| {
            !h.is_empty()
                && h.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-.[]:".contains(&b))
        }) else {
            return Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "https_required",
                "HTTPS is required.",
            ));
        };
        let pq = req.uri.path_and_query().map_or("/", |pq| pq.as_str());
        let location = format!("https://{host}{pq}");
        match HeaderValue::from_str(&location) {
            Ok(v) => Err(
                Rejection::respond(StatusCode::PERMANENT_REDIRECT, "https_redirect")
                    .with_header(LOCATION, v),
            ),
            Err(_) => Err(Rejection::new(
                StatusCode::BAD_REQUEST,
                "https_required",
                "HTTPS is required.",
            )),
        }
    }
}

impl_layer!(HttpsRedirect);
