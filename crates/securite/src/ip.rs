//! Client IP resolution (proxy aware).

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use http::request::Parts;
use http::{HeaderMap, HeaderName};

use crate::ip_filter::IpSet;

/// The resolved client IP, inserted in the request extensions by the shield.
///
/// With Vitesse: `req.get::<ClientIp>()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientIp(pub IpAddr);

/// Insert this in the request extensions when you run a raw hyper server, so
/// the shield knows the TCP peer address (Vitesse inserts it for you).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerAddr(pub SocketAddr);

/// Where to read the client IP from.
///
/// ⚠️ Only trust forwarding headers when your app is **only** reachable
/// through the proxy that sets them; otherwise clients can spoof them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ClientIpSource {
    /// TCP peer address (given by Vitesse, else a [`PeerAddr`] or a raw
    /// `SocketAddr` extension). Safe default for directly exposed apps.
    #[default]
    Peer,
    /// The right-most `X-Forwarded-For` entry, skipping `trusted_hops`
    /// additional proxies. Use `trusted_hops: 0` on Heroku, Render, Fly.io
    /// (`X-Forwarded-For`), AWS ALB, a single Nginx …
    XForwardedFor {
        /// Number of *additional* trusted proxies appending to the header.
        trusted_hops: usize,
    },
    /// RFC 7239 `Forwarded: for=…` header, right-most entry, skipping
    /// `trusted_hops` additional proxies.
    Forwarded {
        /// Number of *additional* trusted proxies appending to the header.
        trusted_hops: usize,
    },
    /// A single-IP header set by your edge, e.g. `CF-Connecting-IP`
    /// (Cloudflare), `True-Client-IP` (Akamai), `Fly-Client-IP`, `X-Real-IP`.
    Header(HeaderName),
}

impl ClientIpSource {
    /// Heroku: the router appends the client IP to `X-Forwarded-For`.
    pub fn heroku() -> Self {
        Self::XForwardedFor { trusted_hops: 0 }
    }

    /// Cloudflare: `CF-Connecting-IP`.
    pub fn cloudflare() -> Self {
        Self::Header(HeaderName::from_static("cf-connecting-ip"))
    }

    /// Fly.io: `Fly-Client-IP`.
    pub fn fly() -> Self {
        Self::Header(HeaderName::from_static("fly-client-ip"))
    }

    /// Nginx with `proxy_set_header X-Real-IP $remote_addr;`.
    pub fn x_real_ip() -> Self {
        Self::Header(HeaderName::from_static("x-real-ip"))
    }

    /// Resolves the client IP. Falls back to the peer address when the
    /// configured header is missing or invalid.
    pub fn resolve(&self, parts: &Parts) -> Option<IpAddr> {
        let from_header = match self {
            ClientIpSource::Peer => None,
            ClientIpSource::XForwardedFor { trusted_hops } => nth_from_right(
                &parts.headers,
                "x-forwarded-for",
                *trusted_hops,
                parse_plain,
            ),
            ClientIpSource::Forwarded { trusted_hops } => nth_from_right(
                &parts.headers,
                "forwarded",
                *trusted_hops,
                parse_forwarded_element,
            ),
            ClientIpSource::Header(name) => parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_plain(v.trim())),
        };
        from_header.or_else(|| peer_ip(parts)).map(canonical)
    }
}

impl ClientIpSource {
    /// Like [`resolve`](Self::resolve), but forwarding headers are only
    /// believed when the TCP peer is one of the `trusted` proxies (Express'
    /// `trust proxy`, Laravel's `TrustProxies`, Django's
    /// `SECURE_PROXY_SSL_HEADER` caveat). A client that reaches the app
    /// directly cannot spoof its address with a forged header.
    ///
    /// With `X-Forwarded-For` and `Forwarded`, entries are read from the
    /// right and every trusted proxy is skipped: the client is the first
    /// untrusted address (`trusted_hops` is then ignored). With a single-IP
    /// header, the header is used only when the peer is trusted.
    ///
    /// Without a known peer address, headers are ignored and `None` is
    /// returned.
    ///
    /// ```
    /// use securite::{ClientIpSource, PeerAddr};
    /// use securite::ip_filter::IpSet;
    ///
    /// let trusted: IpSet = "10.0.0.0/8".parse().unwrap();
    /// let mut req = http::Request::get("/")
    ///     .header("x-forwarded-for", "6.6.6.6, 203.0.113.9, 10.1.2.3")
    ///     .body(())
    ///     .unwrap()
    ///     .into_parts()
    ///     .0;
    /// req.extensions.insert(PeerAddr("10.0.0.1:443".parse().unwrap()));
    /// let ip = ClientIpSource::heroku().resolve_trusted(&req, &trusted);
    /// assert_eq!(ip, Some("203.0.113.9".parse().unwrap()));
    /// ```
    pub fn resolve_trusted(&self, parts: &Parts, trusted: &IpSet) -> Option<IpAddr> {
        let peer = peer_ip(parts).map(canonical)?;
        if matches!(self, ClientIpSource::Peer) || !trusted.contains(peer) {
            return Some(peer);
        }
        let from_header = match self {
            ClientIpSource::Peer => None,
            ClientIpSource::XForwardedFor { .. } => {
                first_untrusted(&parts.headers, "x-forwarded-for", trusted, parse_plain)
            }
            ClientIpSource::Forwarded { .. } => first_untrusted(
                &parts.headers,
                "forwarded",
                trusted,
                parse_forwarded_element,
            ),
            ClientIpSource::Header(name) => parts
                .headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| parse_plain(v.trim())),
        };
        Some(from_header.map_or(peer, canonical))
    }
}

/// Walks a forwarding list from the right, skipping trusted proxies.
fn first_untrusted(
    headers: &HeaderMap,
    name: &str,
    trusted: &IpSet,
    parse: fn(&str) -> Option<IpAddr>,
) -> Option<IpAddr> {
    let mut items: Vec<&str> = Vec::new();
    for value in headers.get_all(name) {
        let s = value.to_str().ok()?;
        items.extend(s.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    let mut last_trusted = None;
    for item in items.iter().rev() {
        // An unparsable entry was written by the hop before it: stop there.
        let Some(ip) = parse(item).map(canonical) else {
            return last_trusted;
        };
        if !trusted.contains(ip) {
            return Some(ip);
        }
        last_trusted = Some(ip);
    }
    // Every hop is trusted: the furthest one is the client.
    last_trusted
}

/// Reads the TCP peer address from the request extensions.
pub fn peer_ip(parts: &Parts) -> Option<IpAddr> {
    if let Some(peer) = parts.extensions.get::<PeerAddr>() {
        return Some(peer.0.ip());
    }
    if let Some(addr) = parts.extensions.get::<SocketAddr>() {
        return Some(addr.ip());
    }
    parts.extensions.get::<ClientIp>().map(|c| c.0)
}

fn nth_from_right(
    headers: &HeaderMap,
    name: &str,
    skip: usize,
    parse: fn(&str) -> Option<IpAddr>,
) -> Option<IpAddr> {
    // Multiple header lines are equivalent to a comma separated list.
    let mut items: Vec<&str> = Vec::new();
    for value in headers.get_all(name) {
        let s = value.to_str().ok()?;
        items.extend(s.split(',').map(str::trim).filter(|s| !s.is_empty()));
    }
    let idx = items.len().checked_sub(1 + skip)?;
    parse(items[idx])
}

fn parse_plain(s: &str) -> Option<IpAddr> {
    let s = s.trim();
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(ip);
    }
    // "1.2.3.4:5678" or "[::1]:443"
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    s.strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .and_then(|r| r.parse().ok())
}

fn parse_forwarded_element(element: &str) -> Option<IpAddr> {
    element.split(';').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if !k.trim().eq_ignore_ascii_case("for") {
            return None;
        }
        let v = v.trim().trim_matches('"');
        parse_plain(v)
    })
}

/// Maps IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) to IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    }
}

/// Masks an IPv6 address to `prefix` bits (IPv4 is returned unchanged).
///
/// Rate limiting and banning per `/64` prevents an attacker from rotating
/// through the 2^64 addresses most ISPs hand out.
pub fn mask(ip: IpAddr, ipv6_prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let prefix = u32::from(ipv6_prefix.min(128));
            let masked = if prefix == 0 {
                0
            } else {
                bits & (u128::MAX << (128 - prefix))
            };
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn parts(headers: &[(&str, &str)]) -> Parts {
        let mut b = Request::builder();
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        let mut p = b.body(()).unwrap().into_parts().0;
        p.extensions
            .insert(PeerAddr("10.0.0.1:1234".parse().unwrap()));
        p
    }

    #[test]
    fn peer_default() {
        let p = parts(&[("x-forwarded-for", "1.1.1.1")]);
        assert_eq!(
            ClientIpSource::Peer.resolve(&p),
            Some("10.0.0.1".parse().unwrap())
        );
    }

    #[test]
    fn xff_rightmost() {
        let p = parts(&[("x-forwarded-for", "6.6.6.6, 1.2.3.4, 5.6.7.8")]);
        let ip = ClientIpSource::XForwardedFor { trusted_hops: 0 }.resolve(&p);
        assert_eq!(ip, Some("5.6.7.8".parse().unwrap()));
        let ip = ClientIpSource::XForwardedFor { trusted_hops: 1 }.resolve(&p);
        assert_eq!(ip, Some("1.2.3.4".parse().unwrap()));
        let ip = ClientIpSource::XForwardedFor { trusted_hops: 5 }.resolve(&p);
        assert_eq!(ip, Some("10.0.0.1".parse().unwrap()), "falls back to peer");
    }

    #[test]
    fn xff_multiple_lines() {
        let p = parts(&[
            ("x-forwarded-for", "9.9.9.9"),
            ("x-forwarded-for", "8.8.8.8"),
        ]);
        let ip = ClientIpSource::heroku().resolve(&p);
        assert_eq!(ip, Some("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn forwarded_header() {
        let p = parts(&[(
            "forwarded",
            "for=192.0.2.43, for=\"[2001:db8:cafe::17]:4711\";proto=https",
        )]);
        let ip = ClientIpSource::Forwarded { trusted_hops: 0 }.resolve(&p);
        assert_eq!(ip, Some("2001:db8:cafe::17".parse().unwrap()));
    }

    #[test]
    fn single_header() {
        let p = parts(&[("cf-connecting-ip", " 203.0.113.9 ")]);
        assert_eq!(
            ClientIpSource::cloudflare().resolve(&p),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn trusted_proxies_only() {
        let trusted: IpSet = "10.0.0.0/8, 192.168.0.0/16".parse().unwrap();
        let xff = ClientIpSource::heroku();
        // The peer (10.0.0.1) is trusted: walk past every trusted hop.
        let p = parts(&[(
            "x-forwarded-for",
            "6.6.6.6, 203.0.113.9, 192.168.1.1, 10.9.9.9",
        )]);
        assert_eq!(
            xff.resolve_trusted(&p, &trusted),
            Some("203.0.113.9".parse().unwrap())
        );
        // A client-supplied left part cannot win.
        let p = parts(&[("x-forwarded-for", "10.6.6.6, 203.0.113.9")]);
        assert_eq!(
            xff.resolve_trusted(&p, &trusted),
            Some("203.0.113.9".parse().unwrap())
        );
        // Every hop trusted: the furthest one.
        let p = parts(&[("x-forwarded-for", "10.1.1.1, 10.2.2.2")]);
        assert_eq!(
            xff.resolve_trusted(&p, &trusted),
            Some("10.1.1.1".parse().unwrap())
        );
        // Garbage stops the walk at the last trusted hop.
        let p = parts(&[("x-forwarded-for", "1.1.1.1, garbage, 10.2.2.2")]);
        assert_eq!(
            xff.resolve_trusted(&p, &trusted),
            Some("10.2.2.2".parse().unwrap())
        );
        // No header: the peer.
        let p = parts(&[]);
        assert_eq!(
            xff.resolve_trusted(&p, &trusted),
            Some("10.0.0.1".parse().unwrap())
        );
        // Forwarded and single headers.
        let p = parts(&[("forwarded", "for=198.51.100.1, for=10.0.0.5")]);
        assert_eq!(
            ClientIpSource::Forwarded { trusted_hops: 0 }.resolve_trusted(&p, &trusted),
            Some("198.51.100.1".parse().unwrap())
        );
        let p = parts(&[("cf-connecting-ip", "203.0.113.50")]);
        assert_eq!(
            ClientIpSource::cloudflare().resolve_trusted(&p, &trusted),
            Some("203.0.113.50".parse().unwrap())
        );
    }

    #[test]
    fn untrusted_peers_cannot_spoof() {
        let trusted: IpSet = "192.168.0.0/16".parse().unwrap();
        // The peer 10.0.0.1 is not a trusted proxy: headers are ignored.
        for (h, v) in [
            ("x-forwarded-for", "1.2.3.4"),
            ("cf-connecting-ip", "1.2.3.4"),
            ("forwarded", "for=1.2.3.4"),
        ] {
            let p = parts(&[(h, v)]);
            for src in [
                ClientIpSource::heroku(),
                ClientIpSource::cloudflare(),
                ClientIpSource::Forwarded { trusted_hops: 0 },
            ] {
                assert_eq!(
                    src.resolve_trusted(&p, &trusted),
                    Some("10.0.0.1".parse().unwrap()),
                    "{h}"
                );
            }
        }
        // Unknown peer: nothing is believed.
        let p = Request::builder()
            .header("x-forwarded-for", "1.2.3.4")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        assert_eq!(ClientIpSource::heroku().resolve_trusted(&p, &trusted), None);
    }

    #[test]
    fn mapped_and_mask() {
        let ip: IpAddr = "::ffff:1.2.3.4".parse().unwrap();
        assert_eq!(canonical(ip), "1.2.3.4".parse::<IpAddr>().unwrap());
        let v6: IpAddr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        assert_eq!(mask(v6, 64), "2001:db8:1:2::".parse::<IpAddr>().unwrap());
        assert_eq!(mask(v6, 0), "::".parse::<IpAddr>().unwrap());
        assert_eq!(mask(v6, 128), v6);
    }
}
