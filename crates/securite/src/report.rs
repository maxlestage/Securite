//! A collector for Content-Security-Policy violation reports (feature
//! `reports`).
//!
//! Browsers send a report each time the CSP blocks something: either the
//! legacy `report-uri` format (`application/csp-report`), or the Reporting
//! API format of `report-to` + `Reporting-Endpoints`
//! (`application/reports+json`). [`parse_csp_reports`] reads both into
//! [`CspViolation`]s, defensively, since anybody can post to the endpoint:
//!
//! * bodies over 64 KiB and more than 100 reports per request are refused;
//! * every string is truncated to 1024 characters and stripped of control
//!   characters (no log injection);
//! * noise from browser extensions can be filtered with
//!   [`CspViolation::is_extension_noise`].
//!
//! Pair it with [`SecurityHeaders::reporting_endpoint`](crate::headers::SecurityHeaders::reporting_endpoint),
//! a CSP in report-only mode while you roll it out, and a [`RateLimit`](crate::rate_limit::RateLimit)
//! on the endpoint:
//!
//! ```
//! use securite::headers::{ContentSecurityPolicy, SecurityHeaders};
//! use securite::report::parse_csp_reports;
//!
//! let headers = SecurityHeaders::new()
//!     .reporting_endpoint("csp", "https://example.com/csp-reports")
//!     .content_security_policy(
//!         ContentSecurityPolicy::strict()
//!             .report_to(["csp"])
//!             .report_uri(["/csp-reports"]),
//!     );
//!
//! // In the `POST /csp-reports` handler:
//! let body = br#"{"csp-report":{"document-uri":"https://example.com/","blocked-uri":"https://evil.example/x.js","effective-directive":"script-src-elem"}}"#;
//! for v in parse_csp_reports(Some("application/csp-report"), body).unwrap() {
//!     if !v.is_extension_noise() {
//!         v.log(); // a `tracing` warning, target `securite::csp`
//!     }
//! }
//! ```

use std::fmt;

use serde_json::Value;

/// Largest accepted body, in bytes.
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Most reports read from one body.
pub const MAX_REPORTS: usize = 100;
const MAX_FIELD_CHARS: usize = 1024;

/// Why a body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReportError {
    /// Larger than [`MAX_BODY_BYTES`] (answer `413`).
    TooLarge,
    /// Neither `application/csp-report`, `application/reports+json` nor
    /// `application/json` (answer `415`).
    UnsupportedMediaType,
    /// Not a report (answer `400`).
    Malformed,
}

impl fmt::Display for ReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ReportError::TooLarge => "report body too large",
            ReportError::UnsupportedMediaType => "unsupported report media type",
            ReportError::Malformed => "malformed report",
        })
    }
}

impl std::error::Error for ReportError {}

/// One CSP violation, whatever format it came in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CspViolation {
    /// The page where the violation happened.
    pub document_uri: Option<String>,
    /// What was blocked (a URL, `inline`, `eval` …).
    pub blocked_uri: Option<String>,
    /// The directive that blocked it (`script-src-elem` …).
    pub effective_directive: Option<String>,
    /// `enforce` or `report`.
    pub disposition: Option<String>,
    /// The script or style file where it happened.
    pub source_file: Option<String>,
    /// Line in `source_file`.
    pub line: Option<u64>,
    /// Column in `source_file`.
    pub column: Option<u64>,
    /// The first characters of the blocked inline code, when the policy has
    /// `'report-sample'`.
    pub sample: Option<String>,
    /// The referrer of the page.
    pub referrer: Option<String>,
    /// HTTP status of the page.
    pub status_code: Option<u64>,
}

fn clean(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    let out: String = s
        .chars()
        .filter(|c| !c.is_control())
        .take(MAX_FIELD_CHARS)
        .collect();
    (!out.is_empty()).then_some(out)
}

fn number(v: Option<&Value>) -> Option<u64> {
    let v = v?;
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

impl CspViolation {
    fn legacy(r: &Value) -> Self {
        CspViolation {
            document_uri: clean(r.get("document-uri")),
            blocked_uri: clean(r.get("blocked-uri")),
            effective_directive: clean(r.get("effective-directive"))
                .or_else(|| clean(r.get("violated-directive"))),
            disposition: clean(r.get("disposition")),
            source_file: clean(r.get("source-file")),
            line: number(r.get("line-number")),
            column: number(r.get("column-number")),
            sample: clean(r.get("script-sample")),
            referrer: clean(r.get("referrer")),
            status_code: number(r.get("status-code")),
        }
    }

    fn reporting_api(b: &Value) -> Self {
        CspViolation {
            document_uri: clean(b.get("documentURL")),
            blocked_uri: clean(b.get("blockedURL")),
            effective_directive: clean(b.get("effectiveDirective")),
            disposition: clean(b.get("disposition")),
            source_file: clean(b.get("sourceFile")),
            line: number(b.get("lineNumber")),
            column: number(b.get("columnNumber")),
            sample: clean(b.get("sample")),
            referrer: clean(b.get("referrer")),
            status_code: number(b.get("statusCode")),
        }
    }

    /// Whether the violation comes from a browser extension or the browser
    /// itself (`chrome-extension:`, `moz-extension:` …): usually noise.
    pub fn is_extension_noise(&self) -> bool {
        const SCHEMES: [&str; 6] = [
            "chrome-extension:",
            "moz-extension:",
            "safari-extension:",
            "safari-web-extension:",
            "ms-browser-extension:",
            "webkit-masked-url:",
        ];
        [&self.blocked_uri, &self.source_file]
            .into_iter()
            .flatten()
            .any(|u| SCHEMES.iter().any(|s| u.starts_with(s)))
    }

    /// Writes the violation as a `tracing` warning (target `securite::csp`).
    pub fn log(&self) {
        tracing::warn!(
            target: "securite::csp",
            document_uri = self.document_uri.as_deref().unwrap_or(""),
            blocked_uri = self.blocked_uri.as_deref().unwrap_or(""),
            directive = self.effective_directive.as_deref().unwrap_or(""),
            disposition = self.disposition.as_deref().unwrap_or(""),
            source_file = self.source_file.as_deref().unwrap_or(""),
            line = self.line.unwrap_or(0),
            "CSP violation"
        );
    }
}

/// Parses the body of a CSP report request. `content_type` is the request's
/// `Content-Type` header. See the [module docs](self).
pub fn parse_csp_reports(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<CspViolation>, ReportError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ReportError::TooLarge);
    }
    let media = content_type
        .and_then(|c| c.split(';').next())
        .map(|m| m.trim().to_ascii_lowercase())
        .ok_or(ReportError::UnsupportedMediaType)?;
    if !matches!(
        media.as_str(),
        "application/csp-report" | "application/reports+json" | "application/json"
    ) {
        return Err(ReportError::UnsupportedMediaType);
    }
    let value: Value = serde_json::from_slice(body).map_err(|_| ReportError::Malformed)?;
    match value {
        Value::Object(ref o) => {
            let r = o.get("csp-report").ok_or(ReportError::Malformed)?;
            if !r.is_object() {
                return Err(ReportError::Malformed);
            }
            Ok(vec![CspViolation::legacy(r)])
        }
        Value::Array(items) => Ok(items
            .iter()
            .take(MAX_REPORTS)
            .filter(|r| r.get("type").and_then(Value::as_str) == Some("csp-violation"))
            .filter_map(|r| r.get("body").filter(|b| b.is_object()))
            .map(CspViolation::reporting_api)
            .collect()),
        _ => Err(ReportError::Malformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_format() {
        let body = br#"{"csp-report":{"document-uri":"https://a.test/p","referrer":"","violated-directive":"script-src","blocked-uri":"inline","line-number":"12","column-number":3,"source-file":"https://a.test/app.js","status-code":200,"script-sample":"alert(1)"}}"#;
        let v = parse_csp_reports(Some("application/csp-report; charset=utf-8"), body).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].effective_directive.as_deref(), Some("script-src"));
        assert_eq!(v[0].line, Some(12));
        assert_eq!(v[0].column, Some(3));
        assert_eq!(v[0].referrer, None);
        assert_eq!(v[0].sample.as_deref(), Some("alert(1)"));
        v[0].log();
    }

    #[test]
    fn reporting_api_format() {
        let body = br#"[
          {"type":"csp-violation","age":10,"url":"https://a.test/","body":{"documentURL":"https://a.test/","blockedURL":"https://cdn.evil/x.js","effectiveDirective":"script-src-elem","disposition":"enforce","statusCode":200}},
          {"type":"deprecation","body":{"id":"x"}},
          {"type":"csp-violation","body":"not an object"}
        ]"#;
        let v = parse_csp_reports(Some("application/reports+json"), body).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].blocked_uri.as_deref(), Some("https://cdn.evil/x.js"));
        assert_eq!(v[0].disposition.as_deref(), Some("enforce"));
    }

    #[test]
    fn hostile_bodies() {
        let ct = Some("application/csp-report");
        assert_eq!(
            parse_csp_reports(ct, &vec![b' '; MAX_BODY_BYTES + 1]),
            Err(ReportError::TooLarge)
        );
        assert_eq!(
            parse_csp_reports(Some("text/plain"), b"{}"),
            Err(ReportError::UnsupportedMediaType)
        );
        assert_eq!(
            parse_csp_reports(None, b"{}"),
            Err(ReportError::UnsupportedMediaType)
        );
        for bad in [&b"nope"[..], b"{}", b"42", br#"{"csp-report":"x"}"#] {
            assert_eq!(parse_csp_reports(ct, bad), Err(ReportError::Malformed));
        }
        // Log injection and huge fields.
        let long = "a".repeat(5000);
        let body = format!(
            r#"{{"csp-report":{{"document-uri":"https://a.test/\n[INFO] admin logged in\u001b[0m","blocked-uri":"{long}"}}}}"#
        );
        let v = parse_csp_reports(ct, body.as_bytes()).unwrap();
        assert!(!v[0].document_uri.as_ref().unwrap().contains('\n'));
        assert!(!v[0].document_uri.as_ref().unwrap().contains('\u{1b}'));
        assert_eq!(v[0].blocked_uri.as_ref().unwrap().len(), MAX_FIELD_CHARS);
        // At most MAX_REPORTS reports.
        let one = r#"{"type":"csp-violation","body":{"blockedURL":"x"}}"#;
        let many = format!("[{}]", vec![one; 300].join(","));
        assert!(many.len() < MAX_BODY_BYTES);
        let v = parse_csp_reports(Some("application/reports+json"), many.as_bytes()).unwrap();
        assert_eq!(v.len(), MAX_REPORTS);
    }

    #[test]
    fn extension_noise() {
        let v = CspViolation {
            blocked_uri: Some("chrome-extension://abc/inject.js".into()),
            ..CspViolation::default()
        };
        assert!(v.is_extension_noise());
        assert!(!CspViolation::default().is_extension_noise());
    }
}
