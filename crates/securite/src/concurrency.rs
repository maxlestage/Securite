//! Maximum in-flight requests per client IP.

use std::net::IpAddr;
use std::sync::Arc;

use http::{StatusCode, request};

use crate::guard::impl_layer;
use crate::ip::mask;
use crate::store::ShardedMap;
use crate::{Context, Guard, Mode, Rejection, priority};

/// Limits how many requests a single client can have in flight.
///
/// Rate limiting counts requests over time; this guard caps *simultaneous*
/// requests, which stops slow / expensive request floods from one client
/// from exhausting your workers, DB pool or memory.
///
/// The permit is released when the response head is produced (or when the
/// request is cancelled).
///
/// ```
/// use securite::prelude::*;
/// let limit = ConcurrencyLimit::per_ip(16);
/// ```
#[derive(Clone)]
pub struct ConcurrencyLimit {
    max: u32,
    state: Arc<ShardedMap<IpAddr, u32>>,
    ipv6_prefix: u8,
    mode: Mode,
}

impl std::fmt::Debug for ConcurrencyLimit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConcurrencyLimit")
            .field("max", &self.max)
            .finish_non_exhaustive()
    }
}

impl ConcurrencyLimit {
    /// At most `max` concurrent requests per client IP.
    pub fn per_ip(max: u32) -> Self {
        Self {
            max: max.max(1),
            state: Arc::new(ShardedMap::new(500_000)),
            ipv6_prefix: 64,
            mode: Mode::Enforce,
        }
    }

    /// Monitor-only mode.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    /// Requests currently in flight for `ip`.
    pub fn in_flight(&self, ip: IpAddr) -> u32 {
        self.state
            .get(&mask(ip, self.ipv6_prefix), |v| v.map_or(0, |v| *v))
    }
}

struct Permit {
    key: IpAddr,
    state: Arc<ShardedMap<IpAddr, u32>>,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let _ = self.state.update(
            self.key,
            |_| false,
            |entry| {
                if let std::collections::hash_map::Entry::Occupied(mut o) = entry {
                    let n = o.get_mut();
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        o.remove();
                    }
                }
            },
        );
    }
}

impl Guard for ConcurrencyLimit {
    fn name(&self) -> &'static str {
        "concurrency"
    }

    fn priority(&self) -> u16 {
        priority::CONCURRENCY
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, _req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let Some(ip) = ctx.client_ip else {
            return Ok(());
        };
        let key = mask(ip, self.ipv6_prefix);
        let acquired = self
            .state
            .update(
                key,
                |n| *n == 0,
                |entry| {
                    let n = entry.or_insert(0);
                    if *n >= self.max {
                        false
                    } else {
                        *n += 1;
                        true
                    }
                },
            )
            .unwrap_or(false);
        if !acquired {
            return Err(Rejection::new(
                StatusCode::TOO_MANY_REQUESTS,
                "too_many_concurrent",
                "Too many concurrent requests.",
            ));
        }
        ctx.hold(Permit {
            key,
            state: self.state.clone(),
        });
        Ok(())
    }
}

impl_layer!(ConcurrencyLimit);

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    #[test]
    fn permits_are_released() {
        let limit = ConcurrencyLimit::per_ip(2);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let mut parts = Request::new(()).into_parts().0;
        let mut c1 = Context::new(parts.method.clone(), parts.uri.clone(), Some(ip));
        let mut c2 = Context::new(parts.method.clone(), parts.uri.clone(), Some(ip));
        let mut c3 = Context::new(parts.method.clone(), parts.uri.clone(), Some(ip));
        assert!(limit.on_request(&mut parts, &mut c1).is_ok());
        assert!(limit.on_request(&mut parts, &mut c2).is_ok());
        assert!(limit.on_request(&mut parts, &mut c3).is_err());
        assert_eq!(limit.in_flight(ip), 2);
        drop(c1);
        assert_eq!(limit.in_flight(ip), 1);
        assert!(limit.on_request(&mut parts, &mut c3).is_ok());
        drop(c2);
        drop(c3);
        assert_eq!(limit.in_flight(ip), 0);
        assert_eq!(limit.state.len(), 0);
    }
}
