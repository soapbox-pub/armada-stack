//! Serving a request for the site.
//!
//! Everything is read from local storage — nothing is proxied from a Blossom
//! server at request time — so the site keeps working with every relay and
//! Blossom server it came from offline. A warm request touches neither the
//! database nor the filesystem: the live version's file map is in memory, and
//! the blob itself is a kept memory mapping.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use axum::body::Body;
use bytes::Bytes;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Request, Response, StatusCode};

use super::csp::{DEFAULT_CSP, denies_framing};
use super::env::{ClientEnv, ENV_PATH};
use super::site::{ASSETS, Site};
use crate::blobs::{BlobStore, Encoding, Variants};
use crate::hash::BlobHash;
use crate::mime::content_type;
use crate::util::lowercase_extname;

/// Documents revalidate every time, which the `ETag` makes cheap; assets are
/// only ever fetched by a document that revalidated first, so they get an
/// hour. What's under [`ASSETS`] is named by its content, so never changes.
const CACHE_CONTROL: &str = "public, no-cache";
const ASSET_CACHE_CONTROL: &str = "public, max-age=3600, must-revalidate";
const HASHED_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// How long a browser may reuse a preflight result, in seconds.
const PREFLIGHT_MAX_AGE: &str = "86400";

pub struct SiteServer {
    pub live: Arc<ArcSwapOption<Site>>,
    pub blobs: BlobStore,
    /// The site's `X-Nsite-Addr`.
    pub naddr: HeaderValue,
    /// What [`ENV_PATH`] says.
    pub env: ClientEnv,
}

type Reply = Response<Body>;

impl SiteServer {
    pub async fn serve(&self, request: Request<Body>) -> Reply {
        if request.method() == Method::OPTIONS && request.headers().contains_key(header::ACCESS_CONTROL_REQUEST_METHOD) {
            return preflight(request.headers());
        }

        let (parts, _) = request.into_parts();
        let site = self.live.load_full();
        let mut response = self.respond(site.as_deref(), &parts.method, parts.uri.path(), &parts.headers).await;
        let headers = response.headers_mut();
        // On every answer, not only documents: the policy is the site's, and a
        // 404 or a 503 is the site answering too.
        let csp = site.map_or(HeaderValue::from_static(DEFAULT_CSP), |site| site.csp.clone());
        if csp.to_str().is_ok_and(denies_framing) {
            headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
        }
        headers.insert(header::CONTENT_SECURITY_POLICY, csp);
        // Every file is served as the type its name says, never another.
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        // Set on everything rather than only on what varied, because a cache
        // has to be told before it stores the first response.
        headers.append(header::VARY, HeaderValue::from_static("accept-encoding"));
        // A site is public files with no credential attached, so the
        // same-origin policy protects nothing here.
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("*"));
        response
    }

    async fn respond(&self, site: Option<&Site>, method: &Method, path: &str, request: &HeaderMap) -> Reply {
        if method != Method::GET && method != Method::HEAD {
            // An nsite is a pile of files. There is nothing to POST to.
            return Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .header(header::ALLOW, "GET, HEAD")
                .body(Body::from("This site only serves GET and HEAD requests."))
                .expect("response");
        }

        // Before the site: it's armada's, and the app wants it even while
        // there's no site to load it.
        if path == ENV_PATH {
            return self.env_script(method, request);
        }

        let Some(site) = site else {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                .header(header::RETRY_AFTER, "30")
                .body(Body::from("The site has not finished downloading yet. Try again in a moment."))
                .expect("response");
        };

        let Some((resolved, file)) = site.resolve(path) else {
            return text(StatusCode::NOT_FOUND, "Not found.");
        };

        // Everything below is about the representation this picks, not the
        // blob: its size, its `ETag`, and the bytes a `Range` counts from.
        let encoding = negotiate_encoding(header_str(request, header::ACCEPT_ENCODING), &file.variants);
        let etag = etag_for(file.sha256, encoding);

        let mut builder = Response::builder()
            .header(header::CONTENT_TYPE, content_type(resolved.path))
            .header(header::CACHE_CONTROL, cache_control(resolved.path))
            .header(header::ETAG, &etag)
            .header(header::LAST_MODIFIED, site.last_modified.clone())
            .header(header::ACCEPT_RANGES, "bytes")
            .header("x-nsite-addr", self.naddr.clone());
        if let Some(encoding) = encoding {
            builder = builder.header(header::CONTENT_ENCODING, encoding.as_str());
        }

        if matches_etag(header_str(request, header::IF_NONE_MATCH), &etag) {
            return builder.status(StatusCode::NOT_MODIFIED).body(Body::empty()).expect("response");
        }

        // A GET is measured by the bytes it sends. The recorded size describes
        // the same file, but if the two ever disagreed, a `Content-Length` the
        // body doesn't match is a response hyper aborts, and a range past the
        // body's end a slice that panics.
        let bytes = if method == Method::HEAD {
            None
        } else {
            match self.open(file.sha256, encoding).await {
                Ok(bytes) => Some(bytes),
                Err(error) => {
                    tracing::error!(path = resolved.path, sha256 = %file.sha256, %error, "blob missing from storage");
                    return text(StatusCode::INTERNAL_SERVER_ERROR, "This file is missing from local storage.");
                }
            }
        };
        let size = bytes.as_ref().map_or(file.variants.size(encoding), |bytes| bytes.len() as u64);

        // A range is of this representation only: not of the shell standing
        // in for what was asked, and not of a version the client
        // didn't name in `If-Range`.
        let ranged = !resolved.shell && header_str(request, header::IF_RANGE).is_none_or(|tag| tag == etag);
        let requested = if ranged { header_str(request, header::RANGE) } else { None };
        let range = match parse_range(requested, size) {
            Range::Unsatisfiable => {
                return builder
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                    .body(Body::empty())
                    .expect("response");
            }
            Range::Whole => None,
            Range::Part(start, end) => Some((start, end)),
        };

        let status = if range.is_some() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        };

        builder = match range {
            Some((start, end)) => builder
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
                .header(header::CONTENT_LENGTH, end - start + 1),
            None => builder.header(header::CONTENT_LENGTH, size),
        };

        let Some(bytes) = bytes else {
            return builder.status(status).body(Body::empty()).expect("response");
        };
        // `parse_range` keeps both ends within `size`, which is this length.
        let body = match range {
            Some((start, end)) => bytes.slice(start as usize..=end as usize),
            None => bytes,
        };
        builder.status(status).body(Body::from(body)).expect("response")
    }

    /// [`ENV_PATH`]: written per request, so it's revalidated every time,
    /// which its `ETag` makes cheap.
    fn env_script(&self, method: &Method, request: &HeaderMap) -> Reply {
        let script = self.env.script(request);
        let etag = format!("\"{}\"", BlobHash::of(script.as_bytes()));
        let builder = Response::builder()
            .header(header::CONTENT_TYPE, "text/javascript; charset=utf-8")
            .header(header::CACHE_CONTROL, "no-cache")
            .header(header::ETAG, &etag);
        if matches_etag(header_str(request, header::IF_NONE_MATCH), &etag) {
            return builder.status(StatusCode::NOT_MODIFIED).body(Body::empty()).expect("response");
        }
        let builder = builder.status(StatusCode::OK).header(header::CONTENT_LENGTH, script.len());
        builder.body(if method == Method::HEAD { Body::empty() } else { Body::from(script) }).expect("response")
    }

    /// A blob's bytes for a response body. A kept mapping answers right
    /// here, with no system call; a new one is opened off the runtime threads.
    async fn open(&self, sha256: BlobHash, encoding: Option<Encoding>) -> anyhow::Result<Bytes> {
        if let Some(bytes) = self.blobs.mapped(sha256, encoding) {
            return Ok(bytes);
        }
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.open(sha256, encoding)).await?
    }
}

/// Answer a CORS preflight. The requested headers are echoed back because a
/// static file server has no request header it needs to refuse.
fn preflight(request: &HeaderMap) -> Reply {
    let mut builder = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, OPTIONS")
        .header(header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE);
    if let Some(requested) = request.get(header::ACCESS_CONTROL_REQUEST_HEADERS) {
        builder = builder.header(header::ACCESS_CONTROL_ALLOW_HEADERS, requested.clone());
    }
    builder.body(Body::empty()).expect("response")
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn text(status: StatusCode, body: &'static str) -> Reply {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .expect("response")
}

/// Pick which stored copy of a blob to serve.
///
/// `q` is honored as the ranking the header defines — zero is a refusal — but
/// ties are broken by size, which is the case that actually happens: browsers
/// send their encodings at equal quality. `None` means the blob itself; a
/// client that accepts nothing stored gets it anyway rather than a 406.
pub fn negotiate_encoding(header: Option<&str>, variants: &Variants) -> Option<Encoding> {
    let header = header.filter(|h| !h.is_empty())?;
    let accepted = parse_accept_encoding(header);

    // The best quality, then the smallest; the first listed if both tie.
    let (encoding, size, _) = Encoding::ALL
        .into_iter()
        .filter_map(|encoding| {
            let size = variants.get(encoding)?;
            let q = accepted.quality(encoding).unwrap_or(0.0);
            (q > 0.0).then_some((encoding, size, q))
        })
        .min_by(|a, b| b.2.total_cmp(&a.2).then(a.1.cmp(&b.1)))?;

    // A copy is only stored when it beat the blob, but serving one that
    // doesn't would be worse than pointless.
    (size < variants.identity).then_some(encoding)
}

/// The quality an `Accept-Encoding` gives each stored encoding, and `*`,
/// where it names them.
#[derive(Default)]
struct Accepted {
    br: Option<f64>,
    gzip: Option<f64>,
    any: Option<f64>,
}

impl Accepted {
    fn quality(&self, encoding: Encoding) -> Option<f64> {
        let named = match encoding {
            Encoding::Br => self.br,
            Encoding::Gzip => self.gzip,
        };
        named.or(self.any)
    }
}

fn parse_accept_encoding(header: &str) -> Accepted {
    let mut accepted = Accepted::default();

    for entry in header.split(',') {
        let mut parts = entry.split(';');
        let name = parts.next().unwrap_or("").trim();
        let q = parts.map(str::trim).find_map(|p| p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")));
        // A malformed q is treated as absent, as the header's grammar says.
        let value = match q {
            None => 1.0,
            Some(q) => q.trim().parse::<f64>().ok().filter(|n| n.is_finite()).unwrap_or(1.0).clamp(0.0, 1.0),
        };
        let slot = if name.eq_ignore_ascii_case("br") {
            &mut accepted.br
        } else if name.eq_ignore_ascii_case("gzip") {
            &mut accepted.gzip
        } else if name == "*" {
            &mut accepted.any
        } else {
            continue;
        };
        *slot = Some(value);
    }

    accepted
}

/// The `ETag` for one representation of a blob. Encodings need tags of their
/// own, or a shared cache holding the brotli copy would hand it to a client
/// whose `If-None-Match` matched, however little brotli that client speaks.
pub fn etag_for(sha256: BlobHash, encoding: Option<Encoding>) -> String {
    match encoding {
        Some(encoding) => format!("\"{sha256}-{}\"", encoding.as_str()),
        None => format!("\"{sha256}\""),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Range {
    Whole,
    Part(u64, u64),
    Unsatisfiable,
}

/// Parse a single-range `Range` header. Multi-range requests are ignored.
pub fn parse_range(header: Option<&str>, size: u64) -> Range {
    let Some(spec) = header.and_then(|h| h.strip_prefix("bytes=")) else {
        return Range::Whole;
    };
    let Some((raw_start, raw_end)) = spec.split_once('-') else {
        return Range::Whole;
    };
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if !digits(raw_start) || !digits(raw_end) || (raw_start.is_empty() && raw_end.is_empty()) {
        return Range::Whole;
    }

    let parse = |s: &str| s.parse::<u64>().unwrap_or(u64::MAX);

    let (start, end) = if raw_start.is_empty() {
        // Suffix range: the last N bytes.
        let suffix = parse(raw_end);
        if suffix == 0 {
            return Range::Unsatisfiable;
        }
        (size.saturating_sub(suffix), size.wrapping_sub(1))
    } else {
        let start = parse(raw_start);
        let end = if raw_end.is_empty() { size.wrapping_sub(1) } else { parse(raw_end).min(size.wrapping_sub(1)) };
        (start, end)
    };

    if size == 0 || start > end || start >= size {
        return Range::Unsatisfiable;
    }
    Range::Part(start, end)
}

/// How long a file may be cached, by what kind of file it is.
pub fn cache_control(path: &str) -> &'static str {
    if path.starts_with(ASSETS) {
        return HASHED_CACHE_CONTROL;
    }
    match &*lowercase_extname(path) {
        ".html" | ".htm" | ".xhtml" | ".json" | ".webmanifest" | ".xml" | ".txt" | ".md" | "" => CACHE_CONTROL,
        _ => ASSET_CACHE_CONTROL,
    }
}

/// Whether an `If-None-Match` header matches the current ETag.
pub fn matches_etag(header: Option<&str>, etag: &str) -> bool {
    let Some(header) = header else { return false };
    if header.trim() == "*" {
        return true;
    }
    header.split(',').map(|value| value.trim()).map(|value| value.strip_prefix("W/").unwrap_or(value)).any(|value| value == etag)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variants(br: Option<u64>, gzip: Option<u64>) -> Variants {
        Variants { identity: 1000, br, gzip }
    }

    #[test]
    fn negotiates() {
        let both = variants(Some(200), Some(300));
        assert_eq!(negotiate_encoding(Some("gzip, deflate, br"), &both), Some(Encoding::Br));
        assert_eq!(negotiate_encoding(Some("gzip"), &both), Some(Encoding::Gzip));
        assert_eq!(negotiate_encoding(Some("br;q=0.5, gzip"), &both), Some(Encoding::Gzip));
        assert_eq!(negotiate_encoding(Some("br;q=0, gzip;q=0"), &both), None);
        assert_eq!(negotiate_encoding(Some("*"), &both), Some(Encoding::Br));
        assert_eq!(negotiate_encoding(Some("identity"), &both), None);
        assert_eq!(negotiate_encoding(None, &both), None);
        assert_eq!(negotiate_encoding(Some("br"), &variants(None, Some(10))), None);
        assert_eq!(negotiate_encoding(Some("br;q=abc"), &both), Some(Encoding::Br));
        assert_eq!(negotiate_encoding(Some("GZIP;Q=1, BR;q=0.1"), &both), Some(Encoding::Gzip));
        assert_eq!(negotiate_encoding(Some("br, gzip"), &variants(Some(200), Some(200))), Some(Encoding::Br));
    }

    #[test]
    fn ranges() {
        assert_eq!(parse_range(None, 100), Range::Whole);
        assert_eq!(parse_range(Some("bytes=0-9"), 100), Range::Part(0, 9));
        assert_eq!(parse_range(Some("bytes=90-"), 100), Range::Part(90, 99));
        assert_eq!(parse_range(Some("bytes=-10"), 100), Range::Part(90, 99));
        assert_eq!(parse_range(Some("bytes=-1000"), 100), Range::Part(0, 99));
        assert_eq!(parse_range(Some("bytes=50-1000"), 100), Range::Part(50, 99));
        assert_eq!(parse_range(Some("bytes=100-"), 100), Range::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=-0"), 100), Range::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=5-1"), 100), Range::Unsatisfiable);
        assert_eq!(parse_range(Some("bytes=0-1,5-6"), 100), Range::Whole);
        assert_eq!(parse_range(Some("items=0-1"), 100), Range::Whole);
        assert_eq!(parse_range(Some("bytes=0-0"), 0), Range::Unsatisfiable);
    }

    #[test]
    fn etags() {
        assert!(matches_etag(Some("W/\"abc\", \"def\""), "\"abc\""));
        assert!(matches_etag(Some("*"), "\"x\""));
        assert!(!matches_etag(Some("\"abc-br\""), "\"abc\""));
        let hash = BlobHash::of(b"abc");
        assert_eq!(etag_for(hash, Some(Encoding::Gzip)), format!("\"{hash}-gzip\""));
    }

    #[test]
    fn caches() {
        assert_eq!(cache_control("/index.html"), CACHE_CONTROL);
        assert_eq!(cache_control("/.well-known/apple-app-site-association"), CACHE_CONTROL);
        assert_eq!(cache_control("/assets/app-1234.js"), HASHED_CACHE_CONTROL);
        assert_eq!(cache_control("/assets/logo.svg"), HASHED_CACHE_CONTROL);
        assert_eq!(cache_control("/sw.js"), ASSET_CACHE_CONTROL);
    }
}
