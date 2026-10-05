//! Armada's icon and banner, built into the binary, for the relay's NIP-11
//! document to point at. They're armada's own, not the site's: the site
//! may be any nsite, or not downloaded yet.

use axum::body::Body;
use http::header::{self, HeaderMap};
use http::{Method, Response, StatusCode};

use super::serve::matches_etag;
use crate::hash::BlobHash;

pub const ICON_PATH: &str = "/_armada/icon.png";
pub const BANNER_PATH: &str = "/_armada/banner.png";

const ICON: &[u8] = include_bytes!("../../assets/icon.png");
const BANNER: &[u8] = include_bytes!("../../assets/banner.png");

/// The image at `path`, if it's one of these.
pub fn serve(method: &Method, path: &str, request: &HeaderMap) -> Option<Response<Body>> {
    let bytes = match path {
        ICON_PATH => ICON,
        BANNER_PATH => BANNER,
        _ => return None,
    };
    let etag = format!("\"{}\"", BlobHash::of(bytes));
    let builder = Response::builder()
        .header(header::CONTENT_TYPE, "image/png")
        .header(header::CACHE_CONTROL, "public, max-age=86400")
        .header(header::ETAG, &etag);
    if matches_etag(request.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()), &etag) {
        return Some(builder.status(StatusCode::NOT_MODIFIED).body(Body::empty()).expect("response"));
    }
    let body = if method == Method::HEAD { Body::empty() } else { Body::from(bytes) };
    Some(builder.status(StatusCode::OK).header(header::CONTENT_LENGTH, bytes.len()).body(body).expect("response"))
}
