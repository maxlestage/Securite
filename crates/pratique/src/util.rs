//! Small helpers shared by the middlewares.

use std::time::{SystemTime, UNIX_EPOCH};

use vitesse::Response;
use vitesse::http::header::{self, HeaderValue};

/// Normalises a user provided path prefix (`api` -> `/api`).
pub(crate) fn normalize_prefix(p: impl Into<String>) -> String {
    let p = p.into();
    if p.starts_with('/') {
        p
    } else {
        format!("/{p}")
    }
}

/// `path` is `prefix` or below it, segment by segment: `/api` covers `/api`
/// and `/api/x`, not `/apix`.
pub(crate) fn path_matches(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('/') || prefix.ends_with('/'),
        None => false,
    }
}

/// The value for the longest prefix of `routes` that covers `path`.
pub(crate) fn longest_match<'a, T>(routes: &'a [(String, T)], path: &str) -> Option<&'a T> {
    routes
        .iter()
        .filter(|(p, _)| path_matches(path, p))
        .max_by_key(|(p, _)| p.len())
        .map(|(_, v)| v)
}

/// Adds `token` to the `Vary` header of `res` (once).
pub(crate) fn add_vary(res: &mut Response, token: &str) {
    let headers = res.headers_mut();
    let present = headers
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|v| v.trim() == "*" || v.trim().eq_ignore_ascii_case(token));
    if !present {
        if let Ok(value) = HeaderValue::from_str(token) {
            headers.append(header::VARY, value);
        }
    }
}

/// 64-bit FNV-1a: stable across builds and platforms (unlike `DefaultHasher`),
/// which keeps `ETag`s valid after a restart.
pub(crate) fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Seconds since the Unix epoch.
pub(crate) fn unix_secs(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// `(year, month, day)` of a day number counted from 1970-01-01
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

/// An HTTP date (RFC 9110 IMF-fixdate): `Sun, 06 Nov 1994 08:49:37 GMT`.
pub(crate) fn http_date(time: SystemTime) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let secs = unix_secs(time) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}, {day:02} {} {year:04} {:02}:{:02}:{:02} GMT",
        DAYS[days.rem_euclid(7) as usize],
        MONTHS[month as usize - 1],
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
    )
}

/// An RFC 3339 UTC timestamp with milliseconds: `2026-10-11T08:49:37.042Z`.
pub(crate) fn rfc3339(time: SystemTime) -> String {
    let since = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = since.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis(),
    )
}

/// Escapes `s` for a JSON string (without the quotes).
pub(crate) fn json_escape(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn prefixes_match_whole_segments() {
        assert!(path_matches("/api", "/api"));
        assert!(path_matches("/api/users", "/api"));
        assert!(!path_matches("/apix", "/api"));
        assert!(path_matches("/anything", "/"));
        let routes = vec![("/".to_string(), 1), ("/api".to_string(), 2)];
        assert_eq!(longest_match(&routes, "/api/x"), Some(&2));
        assert_eq!(longest_match(&routes, "/home"), Some(&1));
    }

    #[test]
    fn dates() {
        let t = UNIX_EPOCH + Duration::from_secs(784_111_777);
        assert_eq!(http_date(t), "Sun, 06 Nov 1994 08:49:37 GMT");
        let t = UNIX_EPOCH + Duration::from_millis(1_791_708_577_042);
        assert_eq!(rfc3339(t), "2026-10-11T08:49:37.042Z");
        assert_eq!(http_date(UNIX_EPOCH), "Thu, 01 Jan 1970 00:00:00 GMT");
        let leap = UNIX_EPOCH + Duration::from_secs(951_782_400);
        assert_eq!(http_date(leap), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn fnv_is_stable() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn json_strings_are_escaped() {
        let mut s = String::new();
        json_escape(&mut s, "a\"b\\c\nd\u{1}");
        assert_eq!(s, "a\\\"b\\\\c\\nd\\u0001");
    }
}
