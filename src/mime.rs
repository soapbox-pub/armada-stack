//! Content types for the file extensions that appear in web sites.
//!
//! A small table beats a dependency here: nsites are static sites, so the long
//! tail of media types never shows up, and anything unknown streams fine as
//! `application/octet-stream`.

use crate::util::lowercase_extname;

fn lookup(extension: &str) -> Option<&'static str> {
    Some(match extension {
        ".html" | ".htm" => "text/html; charset=utf-8",
        ".css" => "text/css; charset=utf-8",
        ".js" | ".mjs" | ".cjs" => "text/javascript; charset=utf-8",
        ".json" | ".map" => "application/json; charset=utf-8",
        ".jsonld" => "application/ld+json",
        ".txt" | ".toml" => "text/plain; charset=utf-8",
        ".md" => "text/markdown; charset=utf-8",
        ".xml" => "application/xml; charset=utf-8",
        ".xhtml" => "application/xhtml+xml",
        ".rss" => "application/rss+xml",
        ".atom" => "application/atom+xml",
        ".csv" => "text/csv; charset=utf-8",
        ".svg" => "image/svg+xml",
        ".png" => "image/png",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".avif" => "image/avif",
        ".ico" => "image/x-icon",
        ".bmp" => "image/bmp",
        ".tiff" => "image/tiff",
        ".woff" => "font/woff",
        ".woff2" => "font/woff2",
        ".ttf" => "font/ttf",
        ".otf" => "font/otf",
        ".eot" => "application/vnd.ms-fontobject",
        ".mp3" => "audio/mpeg",
        ".ogg" | ".oga" => "audio/ogg",
        ".wav" => "audio/wav",
        ".flac" => "audio/flac",
        ".m4a" => "audio/mp4",
        ".mp4" => "video/mp4",
        ".webm" => "video/webm",
        ".mov" => "video/quicktime",
        ".m3u8" => "application/vnd.apple.mpegurl",
        ".ts" => "video/mp2t",
        ".pdf" => "application/pdf",
        ".zip" => "application/zip",
        ".gz" => "application/gzip",
        ".br" => "application/x-brotli",
        ".tar" => "application/x-tar",
        ".wasm" => "application/wasm",
        ".webmanifest" => "application/manifest+json",
        ".manifest" | ".appcache" => "text/cache-manifest",
        ".epub" => "application/epub+zip",
        ".apk" => "application/vnd.android.package-archive",
        ".yaml" | ".yml" => "text/yaml; charset=utf-8",
        _ => return None,
    })
}

/// Well-known URIs (RFC 8615) whose names carry no extension, but whose
/// formats are fixed by the spec that registered them. Apple in particular
/// rejects an `apple-app-site-association` served as anything but JSON, and
/// that file is what lets Armada's iOS app open armada links. URI paths are
/// case-sensitive, and these are registered in lowercase, so they match
/// exactly.
fn well_known(path: &str) -> Option<&'static str> {
    let name = path.strip_prefix("/.well-known/")?;
    Some(match name {
        "apple-app-site-association"
        | "com.apple.remotemanagement"
        | "nodeinfo"
        | "openid-configuration"
        | "oauth-authorization-server"
        | "oauth-protected-resource"
        | "web-app-origin-association"
        | "passkey-endpoints"
        | "matrix/server"
        | "matrix/client"
        | "matrix/support" => "application/json; charset=utf-8",
        "webfinger" | "host-meta.json" => "application/jrd+json",
        "host-meta" => "application/xrd+xml",
        "traffic-advice" => "application/trafficadvice+json",
        "apple-developer-merchantid-domain-association" | "atproto-did" => "text/plain; charset=utf-8",
        // Lightning addresses: one document per name, and a name may
        // contain a dot that would otherwise read as an extension.
        _ if name.strip_prefix("lnurlp/").is_some_and(|user| !user.is_empty() && !user.contains('/')) => {
            "application/json; charset=utf-8"
        }
        _ => return None,
    })
}

/// Types that are text underneath, without saying so in their name. Fonts
/// are here in their uncompressed forms only — `woff` and `woff2` carry their
/// own compression. Structured-syntax suffixes (`+json`, `+xml`) are caught
/// separately, so they aren't listed.
const COMPRESSIBLE_TYPES: [&str; 5] = ["application/json", "application/xml", "application/wasm", "font/ttf", "font/otf"];

/// Content type for a site path, defaulting to a safe binary type.
pub fn content_type(path: &str) -> &'static str {
    well_known(path).or_else(|| lookup(&lowercase_extname(path))).unwrap_or("application/octet-stream")
}

/// Whether a file is worth storing compressed copies of.
///
/// Decided from the content type rather than a second list of extensions, so
/// this can't drift from the table above.
pub fn is_compressible(path: &str) -> bool {
    let kind = content_type(path).split(';').next().unwrap_or("").trim();
    kind.starts_with("text/") || kind.ends_with("+json") || kind.ends_with("+xml") || COMPRESSIBLE_TYPES.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        assert_eq!(content_type("/index.HTML"), "text/html; charset=utf-8");
        assert_eq!(content_type("/x"), "application/octet-stream");
        assert!(is_compressible("/a.js"));
        assert!(is_compressible("/a.svg"));
        assert!(!is_compressible("/a.png"));
        assert!(!is_compressible("/a.woff2"));
        assert!(!is_compressible("/a"));
    }

    #[test]
    fn well_known_paths() {
        let json = "application/json; charset=utf-8";
        assert_eq!(content_type("/.well-known/apple-app-site-association"), json);
        assert_eq!(content_type("/.well-known/matrix/server"), json);
        assert_eq!(content_type("/.well-known/lnurlp/alex.g"), json);
        assert_eq!(content_type("/.well-known/webfinger"), "application/jrd+json");
        assert_eq!(content_type("/.well-known/host-meta"), "application/xrd+xml");
        assert_eq!(content_type("/.well-known/atproto-did"), "text/plain; charset=utf-8");
        assert!(is_compressible("/.well-known/apple-app-site-association"));
        assert!(is_compressible("/.well-known/webfinger"));

        // Only the registered spelling, and only at the root.
        assert_eq!(content_type("/.well-known/Apple-App-Site-Association"), "application/octet-stream");
        assert_eq!(content_type("/docs/.well-known/apple-app-site-association"), "application/octet-stream");
        assert_eq!(content_type("/.well-known/lnurlp/"), "application/octet-stream");
        assert_eq!(content_type("/.well-known/lnurlp/a/b"), "application/octet-stream");

        // Anything with an extension still goes by it.
        assert_eq!(content_type("/.well-known/assetlinks.json"), json);
        assert_eq!(content_type("/.well-known/security.txt"), "text/plain; charset=utf-8");
        assert_eq!(content_type("/.well-known/openpgpkey/hu/abc"), "application/octet-stream");
    }
}
