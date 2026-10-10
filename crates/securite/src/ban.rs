//! fail2ban-like automatic banning.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderValue, RETRY_AFTER};
use http::{StatusCode, request, response};

use crate::guard::impl_layer;
use crate::ip::mask;
use crate::ip_filter::IpSet;
use crate::store::ShardedMap;
use crate::util::{any_path_matches, ceil_secs, normalize_prefix};
use crate::{Context, Guard, Mode, Rejection, priority};

#[derive(Debug, Clone, Copy)]
struct Entry {
    strikes: u32,
    window_start: u64,
    banned_until: u64,
    bans: u32,
    last_seen: u64,
}

/// Automatically bans clients that keep triggering errors.
///
/// Every request blocked by another guard of the shield (WAF, rate limit,
/// hygiene, bot blocker …) and every response whose status is a *strike
/// status* (default: `401`, `403`, `429`, e.g. failed logins in your own
/// handlers) adds a strike to the client. After `max_strikes` within `window` the client
/// is banned for `ban_for`; repeat offenders get exponentially longer bans
/// (up to `max_ban`).
///
/// ```
/// use securite::prelude::*;
/// use std::time::Duration;
///
/// let ban = AutoBan::new()
///     .max_strikes(10)
///     .window(Duration::from_secs(60))
///     .ban_for(Duration::from_secs(15 * 60))
///     .count_status(404)            // scanners hammer unknown URLs
///     .never_ban(["10.0.0.0/8"]);   // internal network
/// let handle = ban.clone();         // shares the same state
/// assert!(!handle.is_banned("1.2.3.4".parse().unwrap()));
/// ```
#[derive(Clone)]
pub struct AutoBan {
    state: Arc<ShardedMap<IpAddr, Entry>>,
    max_strikes: u32,
    window: Duration,
    ban_for: Duration,
    max_ban: Duration,
    statuses: Vec<u16>,
    never: IpSet,
    ignore_paths: Vec<String>,
    ipv6_prefix: u8,
    mode: Mode,
}

impl std::fmt::Debug for AutoBan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoBan")
            .field("max_strikes", &self.max_strikes)
            .field("window", &self.window)
            .field("ban_for", &self.ban_for)
            .field("statuses", &self.statuses)
            .finish_non_exhaustive()
    }
}

impl Default for AutoBan {
    fn default() -> Self {
        Self::new()
    }
}

impl AutoBan {
    /// 20 strikes per minute → 15 minutes ban, doubling up to 24 hours.
    pub fn new() -> Self {
        Self {
            state: Arc::new(ShardedMap::new(500_000)),
            max_strikes: 20,
            window: Duration::from_secs(60),
            ban_for: Duration::from_secs(15 * 60),
            max_ban: Duration::from_secs(24 * 3600),
            statuses: vec![401, 403, 429],
            never: IpSet::default(),
            ignore_paths: Vec::new(),
            ipv6_prefix: 64,
            mode: Mode::Enforce,
        }
    }

    /// Strikes before a ban.
    pub fn max_strikes(mut self, n: u32) -> Self {
        self.max_strikes = n.max(1);
        self
    }

    /// Window in which strikes are counted.
    pub fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// First ban duration.
    pub fn ban_for(mut self, duration: Duration) -> Self {
        self.ban_for = duration;
        self
    }

    /// Upper bound for escalating bans.
    pub fn max_ban(mut self, duration: Duration) -> Self {
        self.max_ban = duration;
        self
    }

    /// Adds a status counted as a strike (e.g. `404`, `400`).
    pub fn count_status(mut self, status: u16) -> Self {
        if !self.statuses.contains(&status) {
            self.statuses.push(status);
        }
        self
    }

    /// Replaces the strike statuses.
    pub fn statuses(mut self, statuses: impl IntoIterator<Item = u16>) -> Self {
        self.statuses = statuses.into_iter().collect();
        self
    }

    /// Networks that are never banned (monitoring, office …).
    ///
    /// # Panics
    ///
    /// On an invalid network.
    pub fn never_ban<I, S>(mut self, networks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let extra = IpSet::parse(networks).expect("invalid IP network");
        self.never = self.never.union(&extra);
        self
    }

    /// Paths whose responses never count as strikes.
    pub fn ignore_paths<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.ignore_paths
            .extend(prefixes.into_iter().map(normalize_prefix));
        self
    }

    /// Monitor-only mode (logs who *would* be banned).
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    fn key(&self, ip: IpAddr) -> IpAddr {
        mask(ip, self.ipv6_prefix)
    }

    /// Whether `ip` is currently banned.
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        self.remaining_ban(ip).is_some()
    }

    fn remaining_ban(&self, ip: IpAddr) -> Option<u64> {
        let now = self.state.now();
        self.state.get(&self.key(ip), |e| {
            e.and_then(|e| (e.banned_until > now).then(|| e.banned_until - now))
        })
    }

    /// Bans `ip` manually.
    pub fn ban(&self, ip: IpAddr, duration: Duration) {
        let now = self.state.now();
        let until = now.saturating_add(duration.as_nanos() as u64);
        let _ = self.state.update(
            self.key(ip),
            |_| false,
            |entry| {
                let e = entry.or_insert(Entry {
                    strikes: 0,
                    window_start: now,
                    banned_until: 0,
                    bans: 0,
                    last_seen: now,
                });
                e.banned_until = until;
                e.bans += 1;
            },
        );
    }

    /// Lifts a ban.
    pub fn unban(&self, ip: IpAddr) {
        self.state.remove(&self.key(ip));
    }

    /// Currently banned clients with the remaining ban time.
    pub fn banned(&self) -> Vec<(IpAddr, Duration)> {
        let now = self.state.now();
        let mut out = Vec::new();
        self.state.for_each(|ip, e| {
            if e.banned_until > now {
                out.push((*ip, Duration::from_nanos(e.banned_until - now)));
            }
        });
        out
    }

    fn strike(&self, ip: IpAddr) {
        let now = self.state.now();
        let window = self.window.as_nanos() as u64;
        let keep = self.window.max(self.max_ban).as_nanos() as u64;
        let _ = self.state.update(
            self.key(ip),
            // Clients never banned are forgotten after `window`; repeat
            // offenders are remembered longer to escalate their bans.
            |e| {
                e.banned_until <= now
                    && now.saturating_sub(e.last_seen) > if e.bans > 0 { keep } else { window }
            },
            |entry| {
                let e = entry.or_insert(Entry {
                    strikes: 0,
                    window_start: now,
                    banned_until: 0,
                    bans: 0,
                    last_seen: now,
                });
                e.last_seen = now;
                if now.saturating_sub(e.window_start) > window {
                    e.strikes = 0;
                    e.window_start = now;
                }
                e.strikes += 1;
                if e.strikes >= self.max_strikes && e.banned_until <= now {
                    let factor = 1u64 << e.bans.min(16);
                    let dur = (self.ban_for.as_nanos() as u64)
                        .saturating_mul(factor)
                        .min(self.max_ban.as_nanos() as u64);
                    e.banned_until = now.saturating_add(dur);
                    e.bans += 1;
                    e.strikes = 0;
                    tracing::warn!(
                        target: "securite",
                        guard = "ban",
                        %ip,
                        seconds = dur / 1_000_000_000,
                        "client banned"
                    );
                }
            },
        );
    }
}

impl Guard for AutoBan {
    fn name(&self) -> &'static str {
        "ban"
    }

    fn priority(&self) -> u16 {
        priority::BAN
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, _req: &mut request::Parts, ctx: &mut Context) -> Result<(), Rejection> {
        let Some(ip) = ctx.client_ip else {
            return Ok(());
        };
        match self.remaining_ban(ip) {
            Some(remaining) => Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "banned",
                "Your address is temporarily banned.",
            )
            .with_header(RETRY_AFTER, HeaderValue::from(ceil_secs(remaining)))),
            None => Ok(()),
        }
    }

    fn on_response(&self, res: &mut response::Parts, ctx: &Context) {
        if ctx.rejected_by == Some("ban") {
            return;
        }
        let Some(ip) = ctx.client_ip else { return };
        if !ctx.blocked && !self.statuses.contains(&res.status.as_u16()) {
            return;
        }
        if self.never.contains(ip) || any_path_matches(ctx.path(), &self.ignore_paths) {
            return;
        }
        self.strike(ip);
    }
}

impl_layer!(AutoBan);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bans_after_strikes_and_escalates() {
        let ban = AutoBan::new()
            .max_strikes(3)
            .ban_for(Duration::from_secs(60));
        let ip: IpAddr = "203.0.113.5".parse().unwrap();
        ban.strike(ip);
        ban.strike(ip);
        assert!(!ban.is_banned(ip));
        ban.strike(ip);
        assert!(ban.is_banned(ip));
        let (_, remaining) = ban.banned()[0];
        assert!(remaining <= Duration::from_secs(60));
        ban.unban(ip);
        assert!(!ban.is_banned(ip));
    }

    #[test]
    fn ipv6_grouped() {
        let ban = AutoBan::new();
        ban.ban("2001:db8::1".parse().unwrap(), Duration::from_secs(10));
        assert!(ban.is_banned("2001:db8::ffff".parse().unwrap()));
        assert!(!ban.is_banned("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn never_ban() {
        let ban = AutoBan::new().max_strikes(1).never_ban(["10.0.0.0/8"]);
        assert!(ban.never.contains("10.1.1.1".parse().unwrap()));
    }
}
