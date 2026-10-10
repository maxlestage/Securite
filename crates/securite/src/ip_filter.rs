//! IP allow / deny lists with CIDR support and runtime updates.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, RwLock};

use http::{StatusCode, request};

use crate::guard::impl_layer;
use crate::ip::canonical;
use crate::util::{any_path_matches, normalize_prefix};
use crate::{Context, Guard, Mode, Rejection, priority};

/// Error returned when an IP or CIDR cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidNetwork(pub String);

impl fmt::Display for InvalidNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid IP network: {:?}", self.0)
    }
}

impl std::error::Error for InvalidNetwork {}

/// An immutable, sorted set of IP ranges with `O(log n)` lookups.
///
/// IPv4 and IPv6 live in the same 128-bit space (IPv4 is mapped to
/// `::ffff:0:0/96`), overlapping ranges are merged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpSet {
    ranges: Vec<(u128, u128)>,
}

fn to_u128(ip: IpAddr) -> u128 {
    match canonical(ip) {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn parse_network(s: &str) -> Result<(u128, u128), InvalidNetwork> {
    let err = || InvalidNetwork(s.to_owned());
    let s = s.trim();
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().map_err(|_| err())?)),
        None => (s, None),
    };
    let ip = IpAddr::from_str(addr).map_err(|_| err())?;
    let (bits, max) = match ip {
        IpAddr::V4(v4) => (u128::from(v4.to_ipv6_mapped()), 32u8),
        IpAddr::V6(v6) => (u128::from(v6), 128u8),
    };
    let prefix = prefix.unwrap_or(max);
    if prefix > max {
        return Err(err());
    }
    // Host bits in the 128-bit space.
    let host_bits = u32::from(max - prefix);
    let mask = if host_bits >= 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let start = bits & !mask;
    Ok((start, start | mask))
}

impl IpSet {
    /// Parses a list of IPs / CIDRs (`"10.0.0.0/8"`, `"2001:db8::/32"`,
    /// `"192.0.2.7"`).
    pub fn parse<I, S>(items: I) -> Result<Self, InvalidNetwork>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut ranges = items
            .into_iter()
            .map(|s| parse_network(s.as_ref()))
            .collect::<Result<Vec<_>, _>>()?;
        ranges.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Ok(Self { ranges: merged })
    }

    /// Whether `ip` belongs to the set.
    ///
    /// IPv4 addresses live in the IPv4-mapped range, so `::/0` contains every
    /// IPv4 address too.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let x = to_u128(ip);
        let idx = self.ranges.partition_point(|&(start, _)| start <= x);
        idx > 0 && self.ranges[idx - 1].1 >= x
    }

    /// Number of (merged) ranges.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Private, loopback and link-local networks (RFC 1918, RFC 4193 …).
    pub fn private_networks() -> Self {
        Self::parse([
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "100.64.0.0/10",
            "::1/128",
            "fc00::/7",
            "fe80::/10",
        ])
        .expect("valid networks")
    }

    pub(crate) fn union(&self, other: &IpSet) -> IpSet {
        let mut ranges: Vec<(u128, u128)> = self
            .ranges
            .iter()
            .chain(other.ranges.iter())
            .copied()
            .collect();
        ranges.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        IpSet { ranges: merged }
    }
}

impl FromStr for IpSet {
    type Err = InvalidNetwork;

    /// Comma / whitespace separated list.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(
            s.split([',', ' ', '\n', '\t'])
                .filter(|x| !x.trim().is_empty()),
        )
    }
}

#[derive(Debug, Default, Clone)]
struct Lists {
    allow: IpSet,
    deny: IpSet,
}

/// Blocks or allows clients by IP / CIDR.
///
/// * `deny` always wins.
/// * If the allow-list is not empty, only listed clients get through.
/// * Unknown client IPs are rejected when an allow-list is configured.
///
/// Lists can be changed at runtime through a clone of the filter
/// (all clones share the same lists):
///
/// ```
/// use securite::prelude::*;
///
/// let filter = IpFilter::new()
///     .deny(["203.0.113.0/24", "2001:db8:bad::/48"])
///     .only_paths(["/admin"]);
/// let handle = filter.clone();
/// // later, from an admin endpoint:
/// handle.deny_now("198.51.100.7").unwrap();
/// ```
#[derive(Clone)]
pub struct IpFilter {
    lists: Arc<RwLock<Lists>>,
    paths: Vec<String>,
    mode: Mode,
}

impl fmt::Debug for IpFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let l = self.lists.read().unwrap_or_else(|p| p.into_inner());
        f.debug_struct("IpFilter")
            .field("allow_ranges", &l.allow.len())
            .field("deny_ranges", &l.deny.len())
            .field("paths", &self.paths)
            .finish()
    }
}

impl Default for IpFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl IpFilter {
    /// Empty filter (lets everybody through).
    pub fn new() -> Self {
        Self {
            lists: Arc::new(RwLock::new(Lists::default())),
            paths: Vec::new(),
            mode: Mode::Enforce,
        }
    }

    /// Adds networks to the allow-list.
    ///
    /// # Panics
    ///
    /// On an invalid IP / CIDR. Use [`try_allow`](Self::try_allow) for
    /// dynamic input.
    pub fn allow<I, S>(self, networks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.try_allow(networks).expect("invalid IP network")
    }

    /// Adds networks to the deny-list.
    ///
    /// # Panics
    ///
    /// On an invalid IP / CIDR. Use [`try_deny`](Self::try_deny).
    pub fn deny<I, S>(self, networks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        self.try_deny(networks).expect("invalid IP network")
    }

    /// Fallible [`allow`](Self::allow).
    pub fn try_allow<I, S>(self, networks: I) -> Result<Self, InvalidNetwork>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let set = IpSet::parse(networks)?;
        Ok(self.with_lists(|l| l.allow = l.allow.union(&set)))
    }

    /// Fallible [`deny`](Self::deny).
    pub fn try_deny<I, S>(self, networks: I) -> Result<Self, InvalidNetwork>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let set = IpSet::parse(networks)?;
        Ok(self.with_lists(|l| l.deny = l.deny.union(&set)))
    }

    /// Allow private / loopback networks (internal tools, admin panels).
    pub fn allow_private(self) -> Self {
        self.with_lists(|l| l.allow = l.allow.union(&IpSet::private_networks()))
    }

    /// Builder methods are copy-on-write: configuring a clone never changes
    /// the original. Only the `*_now` / `replace_*` methods act on the
    /// shared, live lists.
    fn with_lists(mut self, f: impl FnOnce(&mut Lists)) -> Self {
        let mut lists = self.lists.read().unwrap_or_else(|p| p.into_inner()).clone();
        f(&mut lists);
        self.lists = Arc::new(RwLock::new(lists));
        self
    }

    /// Only apply the filter to these path prefixes (e.g. `/admin`).
    pub fn only_paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.paths
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Monitor-only mode.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    /// Denies a network immediately (shared by every clone).
    pub fn deny_now(&self, network: &str) -> Result<(), InvalidNetwork> {
        let set = IpSet::parse([network])?;
        let mut l = self.lists.write().unwrap_or_else(|p| p.into_inner());
        l.deny = l.deny.union(&set);
        Ok(())
    }

    /// Allows a network immediately (shared by every clone).
    pub fn allow_now(&self, network: &str) -> Result<(), InvalidNetwork> {
        let set = IpSet::parse([network])?;
        let mut l = self.lists.write().unwrap_or_else(|p| p.into_inner());
        l.allow = l.allow.union(&set);
        Ok(())
    }

    /// Replaces the whole deny-list (e.g. from a threat-intel feed).
    pub fn replace_deny_list(&self, set: IpSet) {
        self.lists.write().unwrap_or_else(|p| p.into_inner()).deny = set;
    }

    /// Replaces the whole allow-list.
    pub fn replace_allow_list(&self, set: IpSet) {
        self.lists.write().unwrap_or_else(|p| p.into_inner()).allow = set;
    }

    /// Evaluates the lists for `ip`.
    pub fn is_allowed(&self, ip: Option<IpAddr>) -> bool {
        let l = self.lists.read().unwrap_or_else(|p| p.into_inner());
        match ip {
            Some(ip) if l.deny.contains(ip) => false,
            Some(ip) => l.allow.is_empty() || l.allow.contains(ip),
            None => l.allow.is_empty(),
        }
    }
}

impl Guard for IpFilter {
    fn name(&self) -> &'static str {
        "ip_filter"
    }

    fn priority(&self) -> u16 {
        priority::IP_FILTER
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        if !self.paths.is_empty() && !any_path_matches(req.uri.path(), &self.paths) {
            return Ok(());
        }
        if self.is_allowed(ctx.client_ip) {
            return Ok(());
        }
        Err(
            Rejection::new(StatusCode::FORBIDDEN, "ip_blocked", "Access denied.").with_details(
                format!(
                    "ip={}",
                    ctx.client_ip
                        .map_or_else(|| "unknown".to_owned(), |i| i.to_string())
                ),
            ),
        )
    }
}

impl_layer!(IpFilter);

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidr_v4() {
        let set = IpSet::parse(["10.0.0.0/8", "192.168.1.7"]).unwrap();
        assert!(set.contains(ip("10.1.2.3")));
        assert!(set.contains(ip("10.255.255.255")));
        assert!(!set.contains(ip("11.0.0.0")));
        assert!(set.contains(ip("192.168.1.7")));
        assert!(!set.contains(ip("192.168.1.8")));
        assert!(set.contains(ip("::ffff:10.0.0.1")), "mapped v6");
    }

    #[test]
    fn cidr_v6_and_merge() {
        let set = IpSet::parse(["2001:db8::/32", "2001:db8:1::/48", "::1"]).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(ip("2001:db8:ffff::1")));
        assert!(!set.contains(ip("2001:db9::1")));
        assert!(set.contains(ip("::1")));
        assert!(!set.contains(ip("1.2.3.4")));
    }

    #[test]
    fn whole_spaces() {
        let set = IpSet::parse(["0.0.0.0/0"]).unwrap();
        assert!(set.contains(ip("8.8.8.8")));
        assert!(!set.contains(ip("2001:db8::1")));
        let set = IpSet::parse(["::/0"]).unwrap();
        assert!(set.contains(ip("2001:db8::1")));
        assert!(set.contains(ip("8.8.8.8")));
    }

    #[test]
    fn invalid() {
        assert!(IpSet::parse(["10.0.0.0/33"]).is_err());
        assert!(IpSet::parse(["nope"]).is_err());
        assert!("10.0.0.1, 10.0.0.2".parse::<IpSet>().is_ok());
    }

    #[test]
    fn filter_logic() {
        let f = IpFilter::new().allow(["10.0.0.0/8"]).deny(["10.6.6.6"]);
        assert!(f.is_allowed(Some(ip("10.1.1.1"))));
        assert!(!f.is_allowed(Some(ip("10.6.6.6"))));
        assert!(!f.is_allowed(Some(ip("8.8.8.8"))));
        assert!(!f.is_allowed(None));
        let f = IpFilter::new().deny(["1.2.3.4"]);
        assert!(f.is_allowed(None));
        let clone = f.clone();
        clone.deny_now("5.5.5.5").unwrap();
        assert!(!f.is_allowed(Some(ip("5.5.5.5"))), "shared lists");
        let other = f.clone().deny(["6.6.6.6"]);
        assert!(!other.is_allowed(Some(ip("6.6.6.6"))));
        assert!(
            f.is_allowed(Some(ip("6.6.6.6"))),
            "builders are copy-on-write"
        );
    }
}
