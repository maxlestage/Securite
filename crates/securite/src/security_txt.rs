//! `/.well-known/security.txt` (RFC 9116): how security researchers reach
//! you.
//!
//! [`SecurityTxt`] builds a valid file and refuses the common mistakes: no
//! `Contact`, no `Expires`, an expiry in the past or more than a year ahead
//! (the RFC's recommendation), `http://` links, or values that would inject
//! extra fields.
//!
//! ```
//! use std::time::Duration;
//! use securite::security_txt::SecurityTxt;
//!
//! let txt = SecurityTxt::new()
//!     .contact("mailto:security@example.com")
//!     .contact("https://example.com/security")
//!     .expires_in(Duration::from_secs(180 * 24 * 3600))
//!     .preferred_languages(["en", "fr"])
//!     .canonical("https://example.com/.well-known/security.txt")
//!     .policy("https://example.com/disclosure-policy")
//!     .render()
//!     .unwrap();
//! assert!(txt.starts_with("Contact: mailto:security@example.com\n"));
//! assert!(txt.contains("\nExpires: "));
//! ```
//!
//! Serve it with your framework at [`PATH`] (and, optionally, at
//! `/security.txt`), with the content type [`CONTENT_TYPE`]. With Vitesse:
//!
//! ```ignore
//! let body = txt.clone();
//! app.get(securite::security_txt::PATH, move |_req: Request| {
//!     let body = body.clone();
//!     async move { ([("content-type", securite::security_txt::CONTENT_TYPE)], body) }
//! });
//! ```

use std::fmt::{self, Write as _};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the file is served.
pub const PATH: &str = "/.well-known/security.txt";
/// Its content type.
pub const CONTENT_TYPE: &str = "text/plain; charset=utf-8";

const ONE_YEAR: u64 = 366 * 24 * 3600;

/// Why a file was not rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SecurityTxtError {
    /// No `Contact` field (required).
    MissingContact,
    /// No `Expires` field (required).
    MissingExpires,
    /// `Expires` is in the past, or more than a year ahead.
    BadExpires,
    /// A value is not an allowed URI for its field (e.g. `http://`), or
    /// contains a line break.
    InvalidValue(String),
}

impl fmt::Display for SecurityTxtError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityTxtError::MissingContact => f.write_str("security.txt needs a Contact"),
            SecurityTxtError::MissingExpires => f.write_str("security.txt needs an Expires"),
            SecurityTxtError::BadExpires => {
                f.write_str("Expires must be in the future and less than a year ahead")
            }
            SecurityTxtError::InvalidValue(v) => write!(f, "invalid security.txt value `{v}`"),
        }
    }
}

impl std::error::Error for SecurityTxtError {}

/// A `security.txt` builder. See the [module docs](self).
#[derive(Debug, Clone, Default)]
pub struct SecurityTxt {
    fields: Vec<(&'static str, String)>,
    expires: Option<u64>,
}

/// `2026-10-15T08:00:00Z` from Unix seconds.
fn rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl SecurityTxt {
    /// An empty file (add at least a contact and an expiry).
    pub fn new() -> Self {
        Self::default()
    }

    fn push(mut self, field: &'static str, value: impl Into<String>) -> Self {
        self.fields.push((field, value.into()));
        self
    }

    /// `Contact:` a `mailto:`, `tel:` or `https://` URI (repeatable, in
    /// order of preference).
    pub fn contact(self, uri: impl Into<String>) -> Self {
        self.push("Contact", uri)
    }

    /// `Expires:` at this time.
    pub fn expires_at(mut self, at: SystemTime) -> Self {
        self.expires = Some(at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs()));
        self
    }

    /// `Expires:` after `ttl` (keep it under a year, and regenerate it on
    /// every deploy).
    pub fn expires_in(mut self, ttl: Duration) -> Self {
        self.expires = Some(now_unix().saturating_add(ttl.as_secs()));
        self
    }

    /// `Encryption:` your OpenPGP key (`https://`, `openpgp4fpr:` or `dns:`).
    pub fn encryption(self, uri: impl Into<String>) -> Self {
        self.push("Encryption", uri)
    }

    /// `Acknowledgments:` your hall of fame.
    pub fn acknowledgments(self, uri: impl Into<String>) -> Self {
        self.push("Acknowledgments", uri)
    }

    /// `Preferred-Languages:` (once).
    pub fn preferred_languages<I, S>(self, langs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let list: Vec<String> = langs.into_iter().map(|l| l.as_ref().to_owned()).collect();
        self.push("Preferred-Languages", list.join(", "))
    }

    /// `Canonical:` where this file lives.
    pub fn canonical(self, uri: impl Into<String>) -> Self {
        self.push("Canonical", uri)
    }

    /// `Policy:` your vulnerability disclosure policy.
    pub fn policy(self, uri: impl Into<String>) -> Self {
        self.push("Policy", uri)
    }

    /// `Hiring:` your security jobs.
    pub fn hiring(self, uri: impl Into<String>) -> Self {
        self.push("Hiring", uri)
    }

    /// `CSAF:` your provider-metadata.json (RFC 9116 extension).
    pub fn csaf(self, uri: impl Into<String>) -> Self {
        self.push("CSAF", uri)
    }

    /// The file, or the first problem found.
    pub fn render(&self) -> Result<String, SecurityTxtError> {
        self.render_at(now_unix())
    }

    fn render_at(&self, now: u64) -> Result<String, SecurityTxtError> {
        if !self.fields.iter().any(|(f, _)| *f == "Contact") {
            return Err(SecurityTxtError::MissingContact);
        }
        let expires = self.expires.ok_or(SecurityTxtError::MissingExpires)?;
        if expires <= now || expires - now > ONE_YEAR {
            return Err(SecurityTxtError::BadExpires);
        }
        let mut out = String::new();
        for (field, value) in &self.fields {
            let v = value.trim();
            let bad = v.is_empty()
                || v.chars().any(char::is_control)
                || match *field {
                    "Contact" => !["mailto:", "tel:", "https://"]
                        .iter()
                        .any(|s| v.starts_with(s)),
                    "Encryption" => !["https://", "openpgp4fpr:", "dns:"]
                        .iter()
                        .any(|s| v.starts_with(s)),
                    "Preferred-Languages" => !v.split(", ").all(|l| {
                        !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    }),
                    _ => !v.starts_with("https://"),
                };
            if bad {
                return Err(SecurityTxtError::InvalidValue(value.clone()));
            }
            let _ = writeln!(out, "{field}: {v}");
        }
        let _ = writeln!(out, "Expires: {}", rfc3339(expires));
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_792_000_000; // 2026-10-14

    fn base() -> SecurityTxt {
        SecurityTxt {
            expires: Some(NOW + 86_400 * 30),
            ..SecurityTxt::new().contact("mailto:sec@example.com")
        }
    }

    #[test]
    fn dates() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_792_000_000), "2026-10-14T17:46:40Z");
    }

    #[test]
    fn renders_a_valid_file() {
        let t = base()
            .encryption("openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f")
            .preferred_languages(["en", "fr-CA"])
            .render_at(NOW)
            .unwrap();
        assert_eq!(
            t,
            "Contact: mailto:sec@example.com\nEncryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f\nPreferred-Languages: en, fr-CA\nExpires: 2026-11-13T17:46:40Z\n"
        );
    }

    #[test]
    fn refuses_mistakes() {
        assert_eq!(
            SecurityTxt::new()
                .expires_in(Duration::from_secs(60))
                .render(),
            Err(SecurityTxtError::MissingContact)
        );
        assert_eq!(
            SecurityTxt::new().contact("mailto:a@b.c").render(),
            Err(SecurityTxtError::MissingExpires)
        );
        let past = SecurityTxt {
            expires: Some(NOW - 1),
            ..base()
        };
        assert_eq!(past.render_at(NOW), Err(SecurityTxtError::BadExpires));
        let far = SecurityTxt {
            expires: Some(NOW + 2 * ONE_YEAR),
            ..base()
        };
        assert_eq!(far.render_at(NOW), Err(SecurityTxtError::BadExpires));
        for bad in [
            base().contact("http://example.com"),
            base().contact("javascript:alert(1)"),
            base().policy("https://a.test/\nContact: mailto:attacker@evil.test"),
            base().canonical("ftp://a.test"),
            base().preferred_languages(["en\r\nHiring: x"]),
        ] {
            assert!(
                matches!(bad.render_at(NOW), Err(SecurityTxtError::InvalidValue(_))),
                "{bad:?}"
            );
        }
    }
}
