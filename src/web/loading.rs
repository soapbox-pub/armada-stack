//! The page a browser gets while there's no site to serve yet: Armada's
//! crest and sea, and how far the download has got, until the site is live
//! and the page reloads into it. It's armada's own, built in, like the
//! [`super::brand`] images.
//!
//! The default policy allows no inline script, so the page's is a file of
//! its own, at [`SCRIPT_PATH`]. It asks [`STATUS_PATH`] how things stand.

use axum::body::Body;
use http::header::{self, HeaderMap};
use http::{Method, Response, StatusCode};

use super::progress::Stage;
use super::serve::matches_etag;
use crate::hash::BlobHash;

pub const SCRIPT_PATH: &str = "/_armada/loading.js";
pub const STATUS_PATH: &str = "/_armada/status.json";

const PAGE: &str = include_str!("../../assets/loading.html");
const SCRIPT: &str = include_str!("../../assets/loading.js");

/// Seconds a client without the script should wait before trying again.
pub const RETRY_AFTER: &str = "30";

/// Whether a request is a browser's for a page, which gets [`page`] rather
/// than a line of text.
pub fn wants_page(request: &HeaderMap) -> bool {
    request.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|accept| accept.contains("text/html"))
}

/// The page, as a 503: the site it stands in for isn't there.
pub fn page(method: &Method) -> Response<Body> {
    let body = if *method == Method::HEAD { Body::empty() } else { Body::from(PAGE) };
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CONTENT_LENGTH, PAGE.len())
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::RETRY_AFTER, RETRY_AFTER)
        .body(body)
        .expect("response")
}

/// The page's script, if that's what `path` is.
pub fn script(method: &Method, path: &str, request: &HeaderMap) -> Option<Response<Body>> {
    if path != SCRIPT_PATH {
        return None;
    }
    let etag = format!("\"{}\"", BlobHash::of(SCRIPT.as_bytes()));
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, "text/javascript; charset=utf-8")
        .header(header::CACHE_CONTROL, "public, no-cache")
        .header(header::ETAG, &etag);
    if matches_etag(request.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()), &etag) {
        return Some(builder.status(StatusCode::NOT_MODIFIED).body(Body::empty()).expect("response"));
    }
    let body = if *method == Method::HEAD { Body::empty() } else { Body::from(SCRIPT) };
    Some(builder.status(StatusCode::OK).header(header::CONTENT_LENGTH, SCRIPT.len()).body(body).expect("response"))
}

/// [`STATUS_PATH`]: the worker's stage, or `live` once there's a site.
pub fn status(method: &Method, live: bool, stage: Stage) -> Response<Body> {
    let json = if live { r#"{"state":"live"}"#.to_string() } else { serde_json::to_string(&stage).expect("a stage serializes") };
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONTENT_LENGTH, json.len());
    builder.body(if *method == Method::HEAD { Body::empty() } else { Body::from(json) }).expect("response")
}
