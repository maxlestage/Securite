//! Request IDs for tracing and incident response.

use http::header::{HeaderName, HeaderValue};
use http::{request, response};

use crate::guard::impl_layer;
use crate::util::{fast_u64, hex_encode};
use crate::{Context, Guard, Rejection, priority};

/// The request id, inserted in the request extensions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestIdValue(pub HeaderValue);

impl RequestIdValue {
    /// The id as a string.
    pub fn as_str(&self) -> &str {
        self.0.to_str().unwrap_or_default()
    }
}

/// Assigns every request a unique id (UUID v4 format), forwards it to your
/// handlers (`X-Request-Id` header + [`RequestIdValue`] extension), echoes
/// it in the response and adds it to every security event.
///
/// Incoming ids (e.g. set by Heroku's router or your load balancer) are
/// reused **only** if they are short and made of safe characters, which
/// prevents log injection.
#[derive(Debug, Clone)]
pub struct RequestId {
    header: HeaderName,
    trust_incoming: bool,
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestId {
    /// Uses `x-request-id` and accepts safe incoming ids.
    pub fn new() -> Self {
        Self {
            header: HeaderName::from_static("x-request-id"),
            trust_incoming: true,
        }
    }

    /// Custom header name (e.g. `x-correlation-id`).
    pub fn header(mut self, name: &str) -> Self {
        self.header = HeaderName::from_bytes(name.as_bytes()).expect("invalid header name");
        self
    }

    /// Always generate a fresh id, ignoring incoming ones.
    pub fn always_generate(mut self) -> Self {
        self.trust_incoming = false;
        self
    }

    /// Generates a random UUID v4 string.
    pub fn generate() -> String {
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&fast_u64().to_le_bytes());
        b[8..].copy_from_slice(&fast_u64().to_le_bytes());
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let h = hex_encode(&b);
        format!(
            "{}-{}-{}-{}-{}",
            &h[..8],
            &h[8..12],
            &h[12..16],
            &h[16..20],
            &h[20..]
        )
    }

    fn valid(v: &HeaderValue) -> bool {
        let b = v.as_bytes();
        !b.is_empty()
            && b.len() <= 128
            && b.iter()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(c))
    }
}

impl Guard for RequestId {
    fn name(&self) -> &'static str {
        "request_id"
    }

    fn priority(&self) -> u16 {
        priority::REQUEST_ID
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let id = match req.headers.get(&self.header) {
            Some(v) if self.trust_incoming && Self::valid(v) => v.clone(),
            _ => HeaderValue::from_str(&Self::generate()).expect("uuid is a valid header"),
        };
        req.headers.insert(self.header.clone(), id.clone());
        req.extensions.insert(RequestIdValue(id.clone()));
        ctx.request_id = Some(id);
        Ok(())
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        if let Some(id) = &ctx.request_id {
            res.headers.insert(self.header.clone(), id.clone());
        }
    }
}

impl_layer!(RequestId);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_format() {
        let id = RequestId::generate();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert_ne!(id, RequestId::generate());
    }

    #[test]
    fn validation() {
        assert!(RequestId::valid(&HeaderValue::from_static("abc-123_x.y:z")));
        assert!(!RequestId::valid(&HeaderValue::from_static("a b")));
        assert!(!RequestId::valid(&HeaderValue::from_static("x\"><script>")));
        assert!(!RequestId::valid(
            &HeaderValue::from_str(&"a".repeat(129)).unwrap()
        ));
    }
}
