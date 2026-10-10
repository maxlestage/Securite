//! Security events (audit trail) and live statistics.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use http::{Method, StatusCode};

/// Emitted every time a guard rejects (or, in monitor mode, would reject) a
/// request. Also written to [`tracing`] under the `securite` target.
#[derive(Debug, Clone)]
pub struct SecurityEvent<'a> {
    /// Guard name (`waf`, `rate_limit` …).
    pub guard: &'static str,
    /// Machine readable rejection code.
    pub code: &'static str,
    /// Status that was (or would have been) returned.
    pub status: StatusCode,
    /// `false` when the guard runs in [`Mode::Monitor`](crate::Mode::Monitor).
    pub enforced: bool,
    /// Client IP, if known.
    pub client_ip: Option<IpAddr>,
    /// Request method.
    pub method: &'a Method,
    /// Request path.
    pub path: &'a str,
    /// Request id, if a [`RequestId`](crate::request_id::RequestId) guard runs.
    pub request_id: Option<&'a str>,
    /// Message sent to the client.
    pub message: &'a str,
    /// Audit-only details (matched rules …).
    pub details: Option<&'a str>,
}

#[derive(Debug)]
pub(crate) struct Stats {
    pub(crate) total: AtomicU64,
    pub(crate) blocked: AtomicU64,
    pub(crate) monitored: AtomicU64,
    pub(crate) per_guard: Vec<(&'static str, AtomicU64)>,
}

impl Stats {
    pub(crate) fn new(names: impl Iterator<Item = &'static str>) -> Self {
        Self {
            total: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            monitored: AtomicU64::new(0),
            per_guard: names.map(|n| (n, AtomicU64::new(0))).collect(),
        }
    }

    pub(crate) fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            monitored: self.monitored.load(Ordering::Relaxed),
            by_guard: self
                .per_guard
                .iter()
                .map(|(n, c)| (*n, c.load(Ordering::Relaxed)))
                .collect(),
        }
    }
}

/// A point-in-time copy of the shield counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
    /// Requests seen.
    pub total: u64,
    /// Requests rejected.
    pub blocked: u64,
    /// Violations reported by guards in monitor mode.
    pub monitored: u64,
    /// Violations per guard (blocked + monitored).
    pub by_guard: Vec<(&'static str, u64)>,
}

impl StatsSnapshot {
    /// Requests that went through.
    pub fn allowed(&self) -> u64 {
        self.total.saturating_sub(self.blocked)
    }

    /// Renders the snapshot as a compact JSON object.
    pub fn to_json(&self) -> String {
        let mut s = format!(
            "{{\"total\":{},\"allowed\":{},\"blocked\":{},\"monitored\":{},\"by_guard\":{{",
            self.total,
            self.allowed(),
            self.blocked,
            self.monitored
        );
        for (i, (name, count)) in self.by_guard.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push('"');
            s.push_str(name);
            s.push_str("\":");
            s.push_str(&count.to_string());
        }
        s.push_str("}}");
        s
    }
}
