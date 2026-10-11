//! HMAC-SHA256 webhook signature verification (GitHub, Stripe, Slack,
//! Shopify or your own format), with replay protection.
//!
//! Unlike the other guards this layer needs the request **body**, so it is a
//! separate tower layer: [`SignatureLayer`]. It buffers the body (up to
//! `max_body`), verifies it in constant time, and hands an identical body to
//! your handler.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http::header::{HeaderMap, HeaderName};
use http::{Request, Response, StatusCode};
use http_body::Body;
use http_body_util::{BodyExt, Limited};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use tower_layer::Layer;
use tower_service::Service;

use crate::body::SecureBody;
use crate::util::{b64std_decode, hex_decode, normalize_prefix, path_matches};
use crate::{Context, ErrorFormat, Rejection};

/// Why a signature was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureError {
    /// Signature header absent.
    Missing,
    /// Header present but unparsable.
    Malformed,
    /// Timestamp outside the tolerance window (replay).
    Expired,
    /// The MAC does not match.
    Mismatch,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignatureError::Missing => "missing signature",
            SignatureError::Malformed => "malformed signature",
            SignatureError::Expired => "timestamp outside tolerance",
            SignatureError::Mismatch => "signature mismatch",
        })
    }
}

impl std::error::Error for SignatureError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Encoding {
    Hex,
    Base64,
}

#[derive(Debug, Clone)]
enum Scheme {
    /// MAC(body) in one header, optional prefix (`sha256=`).
    Simple {
        header: HeaderName,
        prefix: String,
        encoding: Encoding,
    },
    /// MAC("{ts}.{body}") with a separate timestamp header.
    Timestamped {
        header: HeaderName,
        ts_header: HeaderName,
        prefix: String,
        encoding: Encoding,
    },
    Stripe,
    Slack,
}

/// Verifies HMAC-SHA256 signatures. See the constructors for the supported
/// providers.
///
/// ```
/// use securite::signature::SignatureVerifier;
///
/// let github = SignatureVerifier::github("webhook-secret");
/// let mac = github.sign(b"{}");
/// let mut headers = http::HeaderMap::new();
/// headers.insert("x-hub-signature-256", format!("sha256={mac}").parse().unwrap());
/// assert!(github.verify(&headers, b"{}").is_ok());
/// assert!(github.verify(&headers, b"{\"tampered\":true}").is_err());
/// ```
#[derive(Clone)]
pub struct SignatureVerifier {
    secret: Arc<[u8]>,
    scheme: Scheme,
    tolerance: Duration,
    max_body: usize,
}

impl fmt::Debug for SignatureVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureVerifier")
            .field("scheme", &self.scheme)
            .field("tolerance", &self.tolerance)
            .field("max_body", &self.max_body)
            .finish_non_exhaustive()
    }
}

impl SignatureVerifier {
    fn new(secret: impl AsRef<[u8]>, scheme: Scheme) -> Self {
        Self {
            secret: Arc::from(secret.as_ref()),
            scheme,
            tolerance: Duration::from_secs(300),
            max_body: 1024 * 1024,
        }
    }

    /// GitHub: `X-Hub-Signature-256: sha256=<hex>`.
    pub fn github(secret: impl AsRef<[u8]>) -> Self {
        Self::new(
            secret,
            Scheme::Simple {
                header: HeaderName::from_static("x-hub-signature-256"),
                prefix: "sha256=".into(),
                encoding: Encoding::Hex,
            },
        )
    }

    /// Stripe: `Stripe-Signature: t=<ts>,v1=<hex>` over `"{t}.{body}"`.
    pub fn stripe(secret: impl AsRef<[u8]>) -> Self {
        Self::new(secret, Scheme::Stripe)
    }

    /// Slack: `X-Slack-Signature: v0=<hex>` over `"v0:{ts}:{body}"` with
    /// `X-Slack-Request-Timestamp`.
    pub fn slack(secret: impl AsRef<[u8]>) -> Self {
        Self::new(secret, Scheme::Slack)
    }

    /// Shopify: `X-Shopify-Hmac-Sha256: <base64>`.
    pub fn shopify(secret: impl AsRef<[u8]>) -> Self {
        Self::new(
            secret,
            Scheme::Simple {
                header: HeaderName::from_static("x-shopify-hmac-sha256"),
                prefix: String::new(),
                encoding: Encoding::Base64,
            },
        )
    }

    /// Generic: `<header>: <prefix><hex(HMAC(body))>`.
    pub fn hmac_hex(secret: impl AsRef<[u8]>, header: &str, prefix: &str) -> Self {
        Self::new(
            secret,
            Scheme::Simple {
                header: HeaderName::from_bytes(header.as_bytes()).expect("invalid header"),
                prefix: prefix.into(),
                encoding: Encoding::Hex,
            },
        )
    }

    /// Generic: `<header>: <prefix><base64(HMAC(body))>`.
    pub fn hmac_base64(secret: impl AsRef<[u8]>, header: &str, prefix: &str) -> Self {
        Self::new(
            secret,
            Scheme::Simple {
                header: HeaderName::from_bytes(header.as_bytes()).expect("invalid header"),
                prefix: prefix.into(),
                encoding: Encoding::Base64,
            },
        )
    }

    /// Generic with replay protection: `<header>: <prefix><hex>` computed
    /// over `"{timestamp}.{body}"`, timestamp (Unix seconds) in `ts_header`.
    pub fn hmac_hex_timestamped(
        secret: impl AsRef<[u8]>,
        header: &str,
        ts_header: &str,
        prefix: &str,
    ) -> Self {
        Self::new(
            secret,
            Scheme::Timestamped {
                header: HeaderName::from_bytes(header.as_bytes()).expect("invalid header"),
                ts_header: HeaderName::from_bytes(ts_header.as_bytes()).expect("invalid header"),
                prefix: prefix.into(),
                encoding: Encoding::Hex,
            },
        )
    }

    /// Maximum accepted clock skew / age for timestamped schemes
    /// (default 5 minutes).
    pub fn tolerance(mut self, tolerance: Duration) -> Self {
        self.tolerance = tolerance;
        self
    }

    /// Maximum body size buffered for verification (default 1 MiB).
    pub fn max_body(mut self, bytes: usize) -> Self {
        self.max_body = bytes;
        self
    }

    fn mac(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut mac =
            <Hmac<Sha256> as KeyInit>::new_from_slice(&self.secret).expect("hmac accepts any key");
        for p in parts {
            mac.update(p);
        }
        mac.finalize().into_bytes().to_vec()
    }

    /// Hex HMAC-SHA256 of `payload` (handy in tests and to sign outgoing
    /// webhooks).
    pub fn sign(&self, payload: &[u8]) -> String {
        crate::util::hex_encode(&self.mac(&[payload]))
    }

    fn fresh(&self, ts: &str) -> Result<(), SignatureError> {
        let ts: u64 = ts.trim().parse().map_err(|_| SignatureError::Malformed)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if now.abs_diff(ts) > self.tolerance.as_secs() {
            return Err(SignatureError::Expired);
        }
        Ok(())
    }

    /// Verifies `body` against the signature headers.
    pub fn verify(&self, headers: &HeaderMap, body: &[u8]) -> Result<(), SignatureError> {
        let get = |name: &HeaderName| -> Result<&str, SignatureError> {
            headers
                .get(name)
                .ok_or(SignatureError::Missing)?
                .to_str()
                .map_err(|_| SignatureError::Malformed)
        };
        let decode = |enc: Encoding, s: &str| -> Result<Vec<u8>, SignatureError> {
            match enc {
                Encoding::Hex => hex_decode(s.trim()),
                Encoding::Base64 => b64std_decode(s.trim()),
            }
            .ok_or(SignatureError::Malformed)
        };
        let check = |expected: &[u8], provided: &[u8]| {
            if bool::from(expected.ct_eq(provided)) {
                Ok(())
            } else {
                Err(SignatureError::Mismatch)
            }
        };
        match &self.scheme {
            Scheme::Simple {
                header,
                prefix,
                encoding,
            } => {
                let v = get(header)?;
                let sig = v
                    .strip_prefix(prefix.as_str())
                    .ok_or(SignatureError::Malformed)?;
                check(&self.mac(&[body]), &decode(*encoding, sig)?)
            }
            Scheme::Timestamped {
                header,
                ts_header,
                prefix,
                encoding,
            } => {
                let ts = get(ts_header)?;
                self.fresh(ts)?;
                let v = get(header)?;
                let sig = v
                    .strip_prefix(prefix.as_str())
                    .ok_or(SignatureError::Malformed)?;
                check(
                    &self.mac(&[ts.trim().as_bytes(), b".", body]),
                    &decode(*encoding, sig)?,
                )
            }
            Scheme::Slack => {
                let ts = get(&HeaderName::from_static("x-slack-request-timestamp"))?;
                self.fresh(ts)?;
                let v = get(&HeaderName::from_static("x-slack-signature"))?;
                let sig = v.strip_prefix("v0=").ok_or(SignatureError::Malformed)?;
                check(
                    &self.mac(&[b"v0:", ts.trim().as_bytes(), b":", body]),
                    &decode(Encoding::Hex, sig)?,
                )
            }
            Scheme::Stripe => {
                let v = get(&HeaderName::from_static("stripe-signature"))?;
                let mut ts = None;
                let mut sigs = Vec::new();
                for item in v.split(',') {
                    match item.trim().split_once('=') {
                        Some(("t", t)) => ts = Some(t),
                        Some(("v1", s)) => sigs.push(s),
                        _ => {}
                    }
                }
                let ts = ts.ok_or(SignatureError::Malformed)?;
                self.fresh(ts)?;
                let expected = self.mac(&[ts.as_bytes(), b".", body]);
                let mut ok = false;
                for s in sigs {
                    if let Ok(raw) = decode(Encoding::Hex, s) {
                        ok |= bool::from(expected.ct_eq(&raw));
                    }
                }
                if ok {
                    Ok(())
                } else {
                    Err(SignatureError::Mismatch)
                }
            }
        }
    }
}

/// Verifies webhook signatures on some paths: a Vitesse middleware (feature
/// `vitesse`) and a tower layer.
///
/// The body is read in full (at most [`max_body`](SignatureVerifier::max_body)
/// bytes), checked, and handed over to the handler as it was.
///
/// ```no_run
/// use securite::prelude::*;
/// use vitesse::prelude::*;
///
/// let mut app = App::new();
/// app.middleware(
///     SignatureLayer::new(SignatureVerifier::github(std::env::var("GH_SECRET").unwrap()))
///         .paths(["/webhooks/github"]),
/// );
/// app.post("/webhooks/github", |req: Request| async move {
///     let body = req.text().await?;
///     Ok::<_, Error>(body.len().to_string())
/// });
/// ```
#[derive(Debug, Clone)]
pub struct SignatureLayer {
    verifier: Arc<SignatureVerifier>,
    paths: Arc<[String]>,
}

impl SignatureLayer {
    /// Verifies every request (restrict with [`paths`](Self::paths)).
    pub fn new(verifier: SignatureVerifier) -> Self {
        Self {
            verifier: Arc::new(verifier),
            paths: Arc::from(Vec::new()),
        }
    }

    /// Only verify these path prefixes (cumulative).
    pub fn paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.paths = self
            .paths
            .iter()
            .cloned()
            .chain(prefixes.into_iter().map(normalize_prefix))
            .collect();
        self
    }
}

impl<S> Layer<S> for SignatureLayer {
    type Service = SignatureService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SignatureService {
            inner,
            verifier: self.verifier.clone(),
            paths: self.paths.clone(),
        }
    }
}

/// Service produced by [`SignatureLayer`].
#[derive(Debug, Clone)]
pub struct SignatureService<S> {
    inner: S,
    verifier: Arc<SignatureVerifier>,
    paths: Arc<[String]>,
}

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn reject<B>(
    rejection: &Rejection,
    method: http::Method,
    uri: http::Uri,
) -> Response<SecureBody<B>> {
    let ctx = Context::new(method, uri, None);
    let (parts, body) = ErrorFormat::ProblemJson.render(rejection, &ctx);
    Response::from_parts(parts, SecureBody::full(body))
}

fn body_too_large() -> Rejection {
    Rejection::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "body_too_large",
        "Webhook body too large.",
    )
}

fn invalid_signature(path: &str, error: &SignatureError) -> Rejection {
    tracing::warn!(target: "securite", guard = "signature", path, error = %error, "webhook signature rejected");
    Rejection::new(
        StatusCode::UNAUTHORIZED,
        "invalid_signature",
        "Invalid webhook signature.",
    )
}

/// Whether the layer checks requests to `path`.
fn applies(paths: &[String], path: &str) -> bool {
    paths.is_empty() || paths.iter().any(|p| path_matches(path, p))
}

#[cfg(feature = "vitesse")]
impl vitesse::Middleware for SignatureLayer {
    fn handle(
        &'static self,
        req: vitesse::Request,
        next: vitesse::Next,
    ) -> vitesse::BoxFuture<vitesse::Response> {
        use vitesse::IntoResponse;

        Box::pin(async move {
            if !applies(&self.paths, req.path()) {
                return next.run(req).await;
            }
            let mut req = req;
            let reject = |rejection: Rejection, req: &vitesse::Request| {
                let ctx = Context::new(req.method().clone(), req.uri().clone(), None);
                crate::shield::vitesse_middleware::render(
                    &ErrorFormat::ProblemJson,
                    &rejection,
                    &ctx,
                )
            };
            // A declared size above the limit is refused before reading anything.
            let declared = req
                .header("content-length")
                .and_then(|v| v.trim().parse::<usize>().ok());
            if declared.is_some_and(|n| n > self.verifier.max_body) {
                return reject(body_too_large(), &req);
            }
            let bytes = match req.bytes().await {
                Ok(bytes) if bytes.len() <= self.verifier.max_body => bytes,
                Ok(_) => return reject(body_too_large(), &req),
                Err(error) => return error.into_response(),
            };
            if let Err(error) = self.verifier.verify(req.headers(), &bytes) {
                return reject(invalid_signature(req.path(), &error), &req);
            }
            // The handler reads the body as usual.
            req.set_body(bytes);
            next.run(req).await
        })
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SignatureService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Body + From<Bytes> + Send + 'static,
    ReqBody::Data: Send,
    ReqBody::Error: Into<BoxError>,
    ResBody: Body<Data = Bytes> + Send + 'static,
{
    type Response = Response<SecureBody<ResBody>>;
    type Error = S::Error;
    type Future = BoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        if !applies(&self.paths, req.uri().path()) {
            return Box::pin(async move { Ok(inner.call(req).await?.map(SecureBody::inner)) });
        }
        let verifier = self.verifier.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let bytes = match Limited::new(body, verifier.max_body).collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => return Ok(reject(&body_too_large(), parts.method, parts.uri)),
            };
            if let Err(e) = verifier.verify(&parts.headers, &bytes) {
                let r = invalid_signature(parts.uri.path(), &e);
                return Ok(reject(&r, parts.method, parts.uri));
            }
            let req = Request::from_parts(parts, ReqBody::from(bytes));
            Ok(inner.call(req).await?.map(SecureBody::inner))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn github() {
        let v = SignatureVerifier::github("It's a Secret to Everybody");
        // Test vector from GitHub's documentation.
        let mut h = HeaderMap::new();
        h.insert(
            "x-hub-signature-256",
            "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17"
                .parse()
                .unwrap(),
        );
        assert_eq!(v.verify(&h, b"Hello, World!"), Ok(()));
        assert_eq!(
            v.verify(&h, b"Hello, World?"),
            Err(SignatureError::Mismatch)
        );
        assert_eq!(
            v.verify(&HeaderMap::new(), b""),
            Err(SignatureError::Missing)
        );
    }

    #[test]
    fn stripe_and_replay() {
        let v = SignatureVerifier::stripe("whsec_test");
        let ts = now().to_string();
        let sig = crate::util::hex_encode(&v.mac(&[ts.as_bytes(), b".", b"{}"]));
        let mut h = HeaderMap::new();
        h.insert(
            "stripe-signature",
            format!("t={ts},v1=deadbeef,v1={sig}").parse().unwrap(),
        );
        assert_eq!(v.verify(&h, b"{}"), Ok(()));
        let old = (now() - 3600).to_string();
        h.insert(
            "stripe-signature",
            format!("t={old},v1={sig}").parse().unwrap(),
        );
        assert_eq!(v.verify(&h, b"{}"), Err(SignatureError::Expired));
    }

    #[test]
    fn slack_and_shopify() {
        let v = SignatureVerifier::slack("8f742231b10e8888abcd99yyyzzz85a5");
        let ts = now().to_string();
        let sig = crate::util::hex_encode(&v.mac(&[b"v0:", ts.as_bytes(), b":", b"payload"]));
        let mut h = HeaderMap::new();
        h.insert("x-slack-request-timestamp", ts.parse().unwrap());
        h.insert("x-slack-signature", format!("v0={sig}").parse().unwrap());
        assert_eq!(v.verify(&h, b"payload"), Ok(()));

        let s = SignatureVerifier::shopify("shpss");
        let mac = crate::util::b64std(&s.mac(&[b"order"]));
        let mut h = HeaderMap::new();
        h.insert("x-shopify-hmac-sha256", mac.parse().unwrap());
        assert_eq!(s.verify(&h, b"order"), Ok(()));
    }
}
