//! Blocks vulnerability scanners and attack tools by User-Agent.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use http::header::USER_AGENT;
use http::{StatusCode, request};
use std::sync::Arc;

use crate::guard::impl_layer;
use crate::{Context, Guard, Mode, Rejection, priority};

/// User-Agent fragments of well-known offensive tools.
pub const DEFAULT_DENY: &[&str] = &[
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "zgrab",
    "nuclei",
    "acunetix",
    "netsparker",
    "wpscan",
    "joomscan",
    "dirbuster",
    "gobuster",
    "dirb/",
    "feroxbuster",
    "ffuf",
    "wfuzz",
    "hydra",
    "havij",
    "w3af",
    "openvas",
    "arachni",
    "skipfish",
    "commix",
    "xsstrike",
    "jaeles",
    "whatweb",
    "zmeu",
    "morfeus",
    "fimap",
    "nessus",
    "qualys",
    "burpcollaborator",
    "interactsh",
    "censysinspect",
    "httpx - open-source",
    "go-http-client/1.1 (scanner",
];

/// Blocks requests whose `User-Agent` matches known scanners.
///
/// Matching is case-insensitive and uses a single Aho-Corasick automaton,
/// so the cost is independent of the number of patterns.
///
/// Remember that the User-Agent is attacker controlled: this is a cheap
/// noise filter, not a security boundary.
///
/// ```
/// use securite::prelude::*;
///
/// let bots = BotBlocker::new()
///     .deny(["python-requests", "curl/"])   // add yours
///     .allow(["nuclei-internal-audit"])     // your own scanner
///     .block_empty(true);
/// ```
#[derive(Clone)]
pub struct BotBlocker {
    deny: Vec<String>,
    allow: Vec<String>,
    block_empty: bool,
    deny_ac: Option<Arc<AhoCorasick>>,
    allow_ac: Option<Arc<AhoCorasick>>,
    mode: Mode,
}

impl std::fmt::Debug for BotBlocker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BotBlocker")
            .field("deny", &self.deny.len())
            .field("allow", &self.allow)
            .field("block_empty", &self.block_empty)
            .finish()
    }
}

impl Default for BotBlocker {
    fn default() -> Self {
        Self::new()
    }
}

fn build(patterns: &[String]) -> Option<Arc<AhoCorasick>> {
    if patterns.is_empty() {
        return None;
    }
    Some(Arc::new(
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(patterns)
            .expect("valid patterns"),
    ))
}

impl BotBlocker {
    /// Blocks [`DEFAULT_DENY`].
    pub fn new() -> Self {
        let mut s = Self {
            deny: DEFAULT_DENY.iter().map(|s| (*s).to_owned()).collect(),
            allow: Vec::new(),
            block_empty: false,
            deny_ac: None,
            allow_ac: None,
            mode: Mode::Enforce,
        };
        s.rebuild();
        s
    }

    /// An empty blocker (only your own patterns).
    pub fn empty() -> Self {
        let mut s = Self::new();
        s.deny.clear();
        s.rebuild();
        s
    }

    /// Adds deny patterns (case-insensitive substrings).
    pub fn deny<I, S>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.deny.extend(patterns.into_iter().map(Into::into));
        self.rebuild();
        self
    }

    /// Patterns that are always allowed (checked first).
    pub fn allow<I, S>(mut self, patterns: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allow.extend(patterns.into_iter().map(Into::into));
        self.rebuild();
        self
    }

    /// Rejects requests without a User-Agent.
    pub fn block_empty(mut self, block: bool) -> Self {
        self.block_empty = block;
        self
    }

    /// Monitor-only mode.
    pub fn monitor(mut self) -> Self {
        self.mode = Mode::Monitor;
        self
    }

    fn rebuild(&mut self) {
        self.deny_ac = build(&self.deny);
        self.allow_ac = build(&self.allow);
    }

    /// Returns the matched deny pattern, if any.
    pub fn check(&self, user_agent: &str) -> Option<&str> {
        if self
            .allow_ac
            .as_ref()
            .is_some_and(|ac| ac.is_match(user_agent))
        {
            return None;
        }
        let m = self.deny_ac.as_ref()?.find(user_agent)?;
        Some(&self.deny[m.pattern().as_usize()])
    }
}

impl Guard for BotBlocker {
    fn name(&self) -> &'static str {
        "bot_blocker"
    }

    fn priority(&self) -> u16 {
        priority::USER_AGENT
    }

    fn mode(&self) -> Mode {
        self.mode
    }

    fn on_request(&self, req: &mut request::Parts, _ctx: &mut Context) -> Result<(), Rejection> {
        let ua = req
            .headers
            .get(USER_AGENT)
            .filter(|v| !v.as_bytes().iter().all(u8::is_ascii_whitespace))
            .map(|v| String::from_utf8_lossy(v.as_bytes()));
        match ua {
            None if self.block_empty => Err(Rejection::new(
                StatusCode::FORBIDDEN,
                "bot_blocked",
                "Automated clients are not allowed.",
            )
            .with_details("empty user-agent")),
            None => Ok(()),
            Some(ua) => match self.check(&ua) {
                Some(pattern) => Err(Rejection::new(
                    StatusCode::FORBIDDEN,
                    "bot_blocked",
                    "Automated clients are not allowed.",
                )
                .with_details(format!("user-agent matched {pattern:?}"))),
                None => Ok(()),
            },
        }
    }
}

impl_layer!(BotBlocker);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_scanners() {
        let b = BotBlocker::new();
        assert_eq!(
            b.check("sqlmap/1.7.2#stable (https://sqlmap.org)"),
            Some("sqlmap")
        );
        assert_eq!(
            b.check("Mozilla/5.0 (compatible; Nmap Scripting Engine)"),
            Some("nmap")
        );
        assert!(
            b.check("Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0")
                .is_none()
        );
        let b = b.allow(["nuclei-internal"]);
        assert!(b.check("Nuclei-Internal v3").is_none());
        let b = BotBlocker::empty().deny(["curl/"]);
        assert!(b.check("curl/8.5.0").is_some());
        assert!(b.check("sqlmap").is_none());
    }
}
