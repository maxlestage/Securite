//! Small internal helpers (randomness, encodings, parsing).

use std::borrow::Cow;
use std::cell::Cell;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

/// Fills `buf` with cryptographically secure random bytes.
///
/// Falls back to the (non cryptographic) thread-local generator only if the
/// operating system RNG is unavailable, which never happens on supported
/// platforms.
pub(crate) fn secure_random(buf: &mut [u8]) {
    if getrandom::fill(buf).is_err() {
        for chunk in buf.chunks_mut(8) {
            let r = fast_u64().to_le_bytes();
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
    }
}

thread_local! {
    static RNG: Cell<u64> = Cell::new({
        let mut seed = [0u8; 8];
        let _ = getrandom::fill(&mut seed);
        u64::from_le_bytes(seed) | 1
    });
}

/// Fast thread-local wyrand generator (NOT for secrets).
pub(crate) fn fast_u64() -> u64 {
    RNG.with(|state| {
        let s = state.get().wrapping_add(0xa076_1d64_78bd_642f);
        state.set(s);
        let t = u128::from(s) * u128::from(s ^ 0xe703_7ed1_a0b4_28db);
        ((t >> 64) as u64) ^ (t as u64)
    })
}

/// Encodes bytes as URL-safe base64 without padding.
pub(crate) fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Encodes bytes as standard base64 (with padding).
pub(crate) fn b64std(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

pub(crate) fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

pub(crate) fn b64std_decode(s: &str) -> Option<Vec<u8>> {
    STANDARD.decode(s).ok()
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return None;
    }
    s.chunks(2)
        .map(|pair| Some((hex_val(pair[0])? << 4) | hex_val(pair[1])?))
        .collect()
}

#[inline]
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes `input`. Invalid escapes are kept verbatim.
/// When `plus_as_space` is set, `+` is decoded as a space (query strings).
pub(crate) fn percent_decode(input: &str, plus_as_space: bool) -> Cow<'_, str> {
    let bytes = input.as_bytes();
    if !bytes
        .iter()
        .any(|&b| b == b'%' || (plus_as_space && b == b'+'))
    {
        return Cow::Borrowed(input);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' if plus_as_space => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    Cow::Owned(String::from_utf8_lossy(&out).into_owned())
}

/// Returns true if `input` contains a malformed percent escape.
pub(crate) fn has_invalid_percent(input: &str) -> bool {
    let b = input.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return true;
            }
            if hex_val(b[i + 1]).is_none() || hex_val(b[i + 2]).is_none() {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// Iterates over `name=value` pairs of a `Cookie` request header.
pub(crate) fn cookie_pairs(header: &str) -> impl Iterator<Item = (&str, &str)> {
    header.split(';').filter_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .unwrap_or(value);
        Some((name.trim(), value))
    })
}

/// Escapes a string for inclusion inside a JSON string literal.
pub(crate) fn json_escape(s: &str, out: &mut String) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
}

/// Path prefix matching on segment boundaries: `/api` matches `/api`,
/// `/api/` and `/api/users` but not `/apiary`.
#[inline]
pub(crate) fn path_matches(path: &str, prefix: &str) -> bool {
    if prefix.is_empty() || prefix == "/" {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some(rest) => rest.is_empty() || rest.starts_with('/') || prefix.ends_with('/'),
        None => false,
    }
}

pub(crate) fn any_path_matches(path: &str, prefixes: &[String]) -> bool {
    prefixes.iter().any(|p| path_matches(path, p))
}

/// Normalises a user provided path prefix (`api` -> `/api`).
pub(crate) fn normalize_prefix(p: impl Into<String>) -> String {
    let p = p.into();
    if p.starts_with('/') {
        p
    } else {
        format!("/{p}")
    }
}

/// Seconds (rounded up) in a nanosecond duration.
#[inline]
pub(crate) fn ceil_secs(nanos: u64) -> u64 {
    nanos.div_ceil(1_000_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b", false), "a b");
        assert_eq!(percent_decode("a+b", true), "a b");
        assert_eq!(percent_decode("a+b", false), "a+b");
        assert_eq!(percent_decode("%2e%2E%2f", false), "../");
        assert_eq!(percent_decode("100%", false), "100%");
        assert_eq!(percent_decode("%zz", false), "%zz");
        assert_eq!(percent_decode("%4", false), "%4");
        assert_eq!(percent_decode("x%41", false), "xA");
    }

    #[test]
    fn invalid_percent() {
        assert!(!has_invalid_percent("/a%20b"));
        assert!(has_invalid_percent("/a%2"));
        assert!(has_invalid_percent("/a%zz"));
        assert!(has_invalid_percent("%"));
        assert!(!has_invalid_percent("/plain"));
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 0xab, 0xff];
        assert_eq!(hex_encode(&data), "0001abff");
        assert_eq!(hex_decode("0001ABff").unwrap(), data);
        assert!(hex_decode("abc").is_none());
        assert!(hex_decode("zz").is_none());
    }

    #[test]
    fn prefixes() {
        assert!(path_matches("/api", "/api"));
        assert!(path_matches("/api/users", "/api"));
        assert!(!path_matches("/apiary", "/api"));
        assert!(path_matches("/anything", "/"));
        assert!(path_matches("/static/x.css", "/static/"));
    }

    #[test]
    fn cookies() {
        let pairs: Vec<_> = cookie_pairs("a=1; b=\"two\";c=3").collect();
        assert_eq!(pairs, vec![("a", "1"), ("b", "two"), ("c", "3")]);
    }

    #[test]
    fn json() {
        let mut s = String::new();
        json_escape("a\"b<\n", &mut s);
        assert_eq!(s, "a\\\"b\\u003c\\n");
    }
}
