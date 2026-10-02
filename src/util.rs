//! Small helpers used throughout.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rand::RngCore;

/// Now, in epoch seconds.
pub fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// `n` random bytes as hex.
pub fn random_hex(n: usize) -> String {
    let mut bytes = vec![0u8; n];
    rand::rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Percent-decode a URL path the way `decodeURIComponent` does, or `None` when
/// an escape is malformed or decodes to invalid UTF-8.
pub fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Checked by hand: `from_str_radix` also accepts a leading `+`,
            // which `decodeURIComponent` rejects.
            let hex = bytes.get(i + 1..i + 3).filter(|hex| hex.iter().all(u8::is_ascii_hexdigit))?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// A request path percent-decoded, tolerating malformed escapes.
pub fn decode_path(path: &str) -> String {
    decode_uri_component(path).unwrap_or_else(|| path.to_string())
}

/// The extension of the last path segment, dot included, as `path.extname`
/// finds it: empty for none, and for a name that only starts with a dot.
pub fn extname(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(0) | None => "",
        Some(index) => &name[index..],
    }
}

/// [`extname`] in lowercase, which is how extensions are compared. Borrowed
/// unless the path spells it otherwise, so the usual case allocates nothing.
pub fn lowercase_extname(path: &str) -> std::borrow::Cow<'_, str> {
    let extension = extname(path);
    if extension.bytes().any(|b| b.is_ascii_uppercase()) {
        extension.to_ascii_lowercase().into()
    } else {
        extension.into()
    }
}

/// Format epoch seconds as an HTTP date.
pub fn http_date(epoch: i64) -> String {
    httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(epoch.max(0) as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extnames() {
        assert_eq!(extname("/a/b.html"), ".html");
        assert_eq!(extname("/a/b"), "");
        assert_eq!(extname("/a/.htaccess"), "");
        assert_eq!(extname("/a.b/c"), "");
        assert_eq!(extname("/a/b.tar.gz"), ".gz");
    }

    #[test]
    fn decodes_paths() {
        assert_eq!(decode_path("/a%20b"), "/a b");
        assert_eq!(decode_path("/%E2%9C%93"), "/✓");
        assert_eq!(decode_path("/100%"), "/100%");
        assert_eq!(decode_path("/%ff"), "/%ff");
        assert_eq!(decode_path("/%+1"), "/%+1");
        assert_eq!(decode_path("/%é"), "/%é");
    }

    #[test]
    fn dates() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }
}
