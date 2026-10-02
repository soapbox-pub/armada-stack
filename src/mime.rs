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

/// Types that are text underneath, without saying so in their name. Fonts
/// are here in their uncompressed forms only — `woff` and `woff2` carry their
/// own compression.
const COMPRESSIBLE_TYPES: [&str; 11] = [
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/manifest+json",
    "application/wasm",
    "image/svg+xml",
    "font/ttf",
    "font/otf",
];

/// Content type for a site path, defaulting to a safe binary type.
pub fn content_type(path: &str) -> &'static str {
    // Extensionless by Apple's rule, and only honoured when served as JSON:
    // it is what lets Armada's iOS app open armada links.
    if path == "/.well-known/apple-app-site-association" {
        return "application/json";
    }
    lookup(&lowercase_extname(path)).unwrap_or("application/octet-stream")
}

/// Whether a file is worth storing compressed copies of.
///
/// Decided from the content type rather than a second list of extensions, so
/// this can't drift from the table above.
pub fn is_compressible(path: &str) -> bool {
    let kind = content_type(path).split(';').next().unwrap_or("").trim();
    kind.starts_with("text/") || COMPRESSIBLE_TYPES.contains(&kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn types() {
        assert_eq!(content_type("/index.HTML"), "text/html; charset=utf-8");
        assert_eq!(content_type("/x"), "application/octet-stream");
        assert_eq!(content_type("/.well-known/apple-app-site-association"), "application/json");
        assert!(is_compressible("/a.js"));
        assert!(is_compressible("/a.svg"));
        assert!(!is_compressible("/a.png"));
        assert!(!is_compressible("/a.woff2"));
        assert!(!is_compressible("/a"));
    }
}
