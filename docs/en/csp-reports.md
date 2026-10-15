---
title: CSP reports
summary: Collects Content-Security-Policy violation reports in both browser formats, with Reporting-Endpoints, size limits, log-injection-safe fields and extension noise filtering.
category: browser
order: 5
---

A Content-Security-Policy is only rolled out safely when you see what it blocks. Browsers send a report for each violation, to the `report-uri` of the policy (format `application/csp-report`) or to a `report-to` endpoint declared by `Reporting-Endpoints` (format `application/reports+json`). `parse_csp_reports` reads both (feature `reports`).

```toml
securite = { version = "0.1", features = ["reports"] }
```

## Threats mitigated

- **A05:2021 Security Misconfiguration**: a CSP that breaks the site gets disabled; reports let you fix it in report-only mode first.
- **XSS detection**: injected scripts show up as violations in production.
- **A hostile endpoint**: anybody can post to it. Bodies over 64 KiB and more than 100 reports are refused, every field is truncated to 1024 characters and stripped of control characters (no log injection).

## Quick start

```rust
use securite::headers::{ContentSecurityPolicy, SecurityHeaders};

let headers = SecurityHeaders::new()
    .reporting_endpoint("csp", "https://example.com/csp-reports")
    .content_security_policy(
        ContentSecurityPolicy::strict()
            .report_to(["csp"])            // Reporting API (Chrome, Edge, Safari)
            .report_uri(["/csp-reports"])  // legacy format (Firefox)
            .report_only(),                // observe first, enforce later
    );
```

The endpoint:

```rust
use securite::report::{parse_csp_reports, ReportError};

app.post("/csp-reports", |req: Request| async move {
    let ct = req.headers().get("content-type").and_then(|v| v.to_str().ok()).map(str::to_owned);
    match parse_csp_reports(ct.as_deref(), &req.body_bytes()) {
        Ok(reports) => {
            for v in reports.iter().filter(|v| !v.is_extension_noise()) {
                v.log(); // tracing warning, target `securite::csp`
            }
            StatusCode::NO_CONTENT
        }
        Err(ReportError::TooLarge) => StatusCode::PAYLOAD_TOO_LARGE,
        Err(ReportError::UnsupportedMediaType) => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        Err(_) => StatusCode::BAD_REQUEST,
    }
});
```

## What a violation contains

`CspViolation` has `document_uri`, `blocked_uri`, `effective_directive`, `disposition` (`enforce` / `report`), `source_file`, `line`, `column`, `sample` (with `'report-sample'`), `referrer` and `status_code`, all optional.

`is_extension_noise()` spots violations caused by browser extensions (`chrome-extension:`, `moz-extension:` …), which are usually most of the reports.

## Pitfalls and tips

- Put a [rate limit](/docs/rate-limit) and a [body limit](/docs/body-limit) on the endpoint, and exclude it from [CSRF protection](/docs/csrf) (browsers post it without a token).
- `reporting_endpoint` only accepts `https://` URLs (and `http://localhost`): browsers ignore the others.
- Reports are hints, not evidence: they can be forged.

## Related pages

- [Security headers and CSP](/docs/security-headers)
- [Monitor mode](/docs/monitor-mode)
