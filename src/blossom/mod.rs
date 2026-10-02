//! The Blossom server: a store for encrypted blobs, and nothing else.
//!
//! Implements BUD-01 (retrieval), BUD-02 (upload), BUD-04 (mirror), BUD-06
//! (upload preflight), BUD-11 (authorization), and the delete half of
//! BUD-12. Built around privacy:
//!
//! - Uploads and mirrors that don't look encrypted are refused (see
//!   [`sniff`]). Whatever type a client declares is ignored.
//! - Blobs are only ever served as `application/octet-stream`, as an
//!   attachment, sandboxed, whatever extension the URL asks for.
//! - The server keeps a blob's size, the day it arrived, and who uploaded it
//!   (which deleting needs) — never its declared type, the name a token
//!   mentions, or anything about the request. There is no `/list`.
//! - Nothing is logged per request.
//!
//! Its blobs live in a store of their own, apart from the site's.

pub mod auth;
mod db;
pub mod sniff;

use std::sync::Arc;

use anyhow::Result;
use axum::body::Body;
use axum::extract::Request;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Response, StatusCode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use crate::blobs::{BlobStore, DownloadError, DownloadReason, Staged};
use crate::config::BlossomConfig;
use crate::hash::BlobHash;
use crate::storage::Storage;
use crate::util::now;
use crate::web::serve::{Range, matches_etag, parse_range};
use auth::{Token, authorize};
use db::{BlossomDb, Record, Removal};
use sniff::Sniffer;

/// The only type a blob is ever served or described as.
const BINARY: &str = "application/octet-stream";

/// A blob is content-addressed, so it never changes, but a day rather than
/// forever: a deleted blob shouldn't linger in shared caches for long.
const CACHE_CONTROL: &str = "public, max-age=86400";

/// Nothing a blob is may run, render, or be sniffed into something that
/// does, even if it's opened directly.
const BLOB_CSP: &str = "default-src 'none'; sandbox";

/// How long a browser may reuse a preflight result, in seconds.
const PREFLIGHT_MAX_AGE: &str = "86400";

/// The most a `/mirror` request body may be. It's one URL.
const MAX_MIRROR_REQUEST: usize = 16 * 1024;

type Reply = Response<Body>;

#[derive(Clone)]
pub struct Blossom {
    server: Arc<Server>,
}

struct Server {
    db: BlossomDb,
    blobs: BlobStore,
    public_url: Option<url::Url>,
    max_blob_size: u64,
    /// Held while a blob goes into the store and the index, and while one
    /// comes out of both, so a delete racing an upload of the same blob
    /// can't leave a record without its bytes.
    commit: Arc<Mutex<()>>,
    /// Fires on shutdown, abandoning mirrors in progress.
    cancel: CancellationToken,
}

impl Blossom {
    /// Open the server's index and store. `public_url` is the origin clients
    /// reach it at, if configured; mirrors in progress are abandoned once
    /// `cancel` fires.
    pub fn open(config: &BlossomConfig, public_url: Option<url::Url>, storage: &Storage, cancel: &CancellationToken) -> Result<Blossom> {
        let db = BlossomDb::open(storage)?;
        let blobs = storage.blob_store("blossom/blobs");
        blobs.clear_temp();
        Ok(Blossom {
            server: Arc::new(Server {
                db,
                blobs,
                public_url,
                max_blob_size: config.max_blob_size,
                commit: Arc::new(Mutex::new(())),
                cancel: cancel.child_token(),
            }),
        })
    }

    #[cfg(test)]
    pub fn router(&self) -> axum::Router {
        let blossom = self.clone();
        axum::Router::new().fallback(move |request: Request| async move { blossom.handle(request).await })
    }

    pub async fn handle(&self, request: Request) -> Reply {
        self.server.handle(request).await
    }
}

/// Whether a path is one of the Blossom server's endpoints, whatever the
/// method. It shares an origin with the web app, whose shell would
/// otherwise answer every one of these.
pub fn wants(path: &str) -> bool {
    matches!(path, "/upload" | "/mirror" | "/media" | "/report") || path.starts_with("/list/") || blob_path(path).is_some()
}

/// A blob descriptor (BUD-02).
#[derive(Debug, Serialize, Deserialize)]
struct Descriptor {
    url: String,
    sha256: String,
    size: u64,
    #[serde(rename = "type")]
    kind: String,
    uploaded: i64,
}

#[derive(Deserialize)]
struct MirrorRequest {
    url: String,
}

/// Where the request reached this server: the origin blob URLs are built on,
/// and the domain `server` tags must name.
struct Origin {
    base: String,
    host: Option<String>,
}

impl Server {
    async fn handle(&self, request: Request) -> Reply {
        let mut response = self.route(request).await;
        let headers = response.headers_mut();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        headers.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, HeaderValue::from_static("*"));
        headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
        headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
        response
    }

    async fn route(&self, request: Request) -> Reply {
        let method = request.method().clone();
        if method == Method::OPTIONS {
            return preflight();
        }

        let path = request.uri().path().to_string();
        match path.as_str() {
            "/upload" => match method {
                Method::PUT => self.upload(request).await,
                Method::HEAD => self.check_upload(request.headers()),
                _ => not_allowed("HEAD, PUT"),
            },
            "/mirror" => match method {
                Method::PUT => self.mirror(request).await,
                _ => not_allowed("PUT"),
            },
            _ if path.starts_with("/list/") => error(StatusCode::NOT_FOUND, "This server doesn't list blobs."),
            "/media" | "/report" => error(StatusCode::NOT_FOUND, "This server doesn't support that."),
            _ => {
                let Some(sha256) = blob_path(&path) else {
                    return error(StatusCode::NOT_FOUND, "Not found.");
                };
                match method {
                    Method::GET | Method::HEAD => self.get(sha256, &method, request.headers()).await,
                    Method::DELETE => self.delete(sha256, request.headers()).await,
                    _ => not_allowed("GET, HEAD, DELETE"),
                }
            }
        }
    }

    /// `GET` and `HEAD /<sha256>` (BUD-01). Only blobs this server accepted:
    /// never anything else that happens to be on disk.
    async fn get(&self, sha256: BlobHash, method: &Method, request: &HeaderMap) -> Reply {
        let record = match self.db.get(sha256) {
            Ok(Some(record)) => record,
            Ok(None) => return error(StatusCode::NOT_FOUND, "Blob not found."),
            Err(error) => return internal(error),
        };

        let etag = format!("\"{sha256}\"");
        let builder = Response::builder()
            .header(header::CONTENT_TYPE, BINARY)
            .header(header::CONTENT_DISPOSITION, "attachment")
            .header(header::CONTENT_SECURITY_POLICY, BLOB_CSP)
            .header(header::CACHE_CONTROL, CACHE_CONTROL)
            .header(header::ETAG, &etag)
            .header(header::ACCEPT_RANGES, "bytes");

        if matches_etag(header_str(request, header::IF_NONE_MATCH), &etag) {
            return builder.status(StatusCode::NOT_MODIFIED).body(Body::empty()).expect("response");
        }

        let bytes = if method == Method::HEAD {
            None
        } else {
            match self.open(sha256).await {
                Ok(bytes) => Some(bytes),
                Err(failure) => {
                    tracing::error!(error = %failure, "blossom: an indexed blob is missing from storage");
                    return error(StatusCode::NOT_FOUND, "Blob not found.");
                }
            }
        };
        let size = bytes.as_ref().map_or(record.size, |bytes| bytes.len() as u64);

        let ranged = header_str(request, header::IF_RANGE).is_none_or(|tag| tag == etag);
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

        let (status, builder) = match range {
            Some((start, end)) => (
                StatusCode::PARTIAL_CONTENT,
                builder
                    .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{size}"))
                    .header(header::CONTENT_LENGTH, end - start + 1),
            ),
            None => (StatusCode::OK, builder.header(header::CONTENT_LENGTH, size)),
        };
        let body = match (bytes, range) {
            (None, _) => Body::empty(),
            // `parse_range` keeps both ends within `size`, which is this length.
            (Some(bytes), Some((start, end))) => Body::from(bytes.slice(start as usize..=end as usize)),
            (Some(bytes), None) => Body::from(bytes),
        };
        builder.status(status).body(body).expect("response")
    }

    async fn open(&self, sha256: BlobHash) -> Result<bytes::Bytes> {
        if let Some(bytes) = self.blobs.mapped(sha256, None) {
            return Ok(bytes);
        }
        let blobs = self.blobs.clone();
        tokio::task::spawn_blocking(move || blobs.open(sha256, None)).await?
    }

    /// `PUT /upload` (BUD-02).
    async fn upload(&self, request: Request) -> Reply {
        let (parts, body) = request.into_parts();
        let origin = self.origin(&parts.headers);
        let token = match authorize(&parts.headers, "upload", origin.host.as_deref(), now()) {
            Ok(token) => token,
            Err(error) => return unauthorized(error.reason()),
        };

        let declared = match header_str(&parts.headers, "x-sha-256") {
            None => None,
            Some(value) => match BlobHash::parse(value.trim()) {
                Some(sha256) => Some(sha256),
                None => return error(StatusCode::BAD_REQUEST, "X-SHA-256 is not a sha256 hash."),
            },
        };
        if let Some(sha256) = declared
            && !token.covers(sha256)
        {
            return unauthorized("Authorization has no x tag for this blob.");
        }
        if let Some(length) = header_str(&parts.headers, header::CONTENT_LENGTH).and_then(|v| v.parse::<u64>().ok())
            && let Some(refusal) = self.check_size(length)
        {
            return refusal;
        }

        let mut sniffer = Sniffer::default();
        let staged = match self.blobs.ingest(body.into_data_stream(), declared, self.max_blob_size, &mut sniffer).await {
            Ok(staged) => staged,
            Err(failure) if failure.reason == DownloadReason::Network => {
                return error(StatusCode::BAD_REQUEST, "The upload broke off.");
            }
            Err(failure) => return transfer_error(&failure, self.max_blob_size),
        };
        // Without X-SHA-256 the hash is only known now.
        if !token.covers(staged.sha256) {
            return unauthorized("Authorization has no x tag for this blob.");
        }
        self.keep(staged, &token, &origin).await
    }

    /// `HEAD /upload` (BUD-06): whether an upload would be accepted, from its
    /// headers. A token is checked if one is sent, but not required: clients
    /// preflight before they've signed anything.
    fn check_upload(&self, headers: &HeaderMap) -> Reply {
        let declared = match header_str(headers, "x-sha-256") {
            None => None,
            Some(value) => match BlobHash::parse(value.trim()) {
                Some(sha256) => Some(sha256),
                None => return error(StatusCode::BAD_REQUEST, "X-SHA-256 is not a sha256 hash."),
            },
        };
        let Some(length) = header_str(headers, "x-content-length") else {
            return error(StatusCode::LENGTH_REQUIRED, "X-Content-Length is required.");
        };
        let Ok(length) = length.trim().parse::<u64>() else {
            return error(StatusCode::BAD_REQUEST, "X-Content-Length is not a number.");
        };

        if headers.contains_key(header::AUTHORIZATION) {
            let token = match authorize(headers, "upload", self.origin(headers).host.as_deref(), now()) {
                Ok(token) => token,
                Err(error) => return unauthorized(error.reason()),
            };
            if let Some(sha256) = declared
                && !token.covers(sha256)
            {
                return unauthorized("Authorization has no x tag for this blob.");
            }
        }

        self.check_size(length).unwrap_or_else(|| Response::builder().status(StatusCode::OK).body(Body::empty()).expect("response"))
    }

    fn check_size(&self, length: u64) -> Option<Reply> {
        if length > self.max_blob_size {
            return Some(error(StatusCode::PAYLOAD_TOO_LARGE, &format!("Blobs may be at most {} bytes.", self.max_blob_size)));
        }
        if length < sniff::MIN_SIZE {
            return Some(error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Only encrypted blobs are accepted, and this is too short to be one."));
        }
        None
    }

    /// `PUT /mirror` (BUD-04): fetch a blob from another server, under the
    /// same rules as an upload.
    async fn mirror(&self, request: Request) -> Reply {
        let (parts, body) = request.into_parts();
        let origin = self.origin(&parts.headers);
        let token = match authorize(&parts.headers, "upload", origin.host.as_deref(), now()) {
            Ok(token) => token,
            Err(error) => return unauthorized(error.reason()),
        };

        let Ok(body) = axum::body::to_bytes(body, MAX_MIRROR_REQUEST).await else {
            return error(StatusCode::BAD_REQUEST, "The request body is too large.");
        };
        let Ok(MirrorRequest { url }) = serde_json::from_slice(&body) else {
            return error(StatusCode::BAD_REQUEST, "The request body must be JSON with a url.");
        };
        let Some(sha256) = blob_url(&url) else {
            return error(StatusCode::BAD_REQUEST, "The url must name a blob by its sha256.");
        };
        if !token.covers(sha256) {
            return unauthorized("Authorization has no x tag for this blob.");
        }

        // Already here: nothing to fetch, but they become an owner as an
        // upload would make them.
        if matches!(self.db.get(sha256), Ok(Some(_))) && self.blobs.size(sha256).is_some() {
            let pubkey = token.pubkey.clone();
            return match self.locked(move |db, _| db.add(sha256, 0, &pubkey, now())).await {
                Ok((record, _)) => descriptor(StatusCode::OK, sha256, record, &origin),
                Err(error) => internal(error),
            };
        }

        let mut sniffer = Sniffer::default();
        let staged = match self.blobs.download_staged(&url, sha256, self.max_blob_size, &mut sniffer, &self.cancel).await {
            Ok(staged) => staged,
            Err(error) => return transfer_error(&error, self.max_blob_size),
        };
        self.keep(staged, &token, &origin).await
    }

    /// Commit a staged blob, record its uploader, and describe it.
    async fn keep(&self, staged: Staged, token: &Token, origin: &Origin) -> Reply {
        let sha256 = staged.sha256;
        let pubkey = token.pubkey.clone();
        let result = self
            .locked(move |db, _| {
                let size = staged.size;
                staged.commit()?;
                db.add(sha256, size, &pubkey, now())
            })
            .await;
        match result {
            Ok((record, new)) => descriptor(if new { StatusCode::CREATED } else { StatusCode::OK }, sha256, record, origin),
            Err(error) => internal(error),
        }
    }

    /// Run `work` off the runtime threads, holding the commit lock.
    async fn locked<T: Send + 'static>(
        &self,
        work: impl FnOnce(&BlossomDb, &BlobStore) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let (db, blobs, lock) = (self.db.clone(), self.blobs.clone(), self.commit.clone());
        tokio::task::spawn_blocking(move || {
            let _guard = lock.lock();
            work(&db, &blobs)
        })
        .await?
    }

    /// `DELETE /<sha256>` (BUD-12). Removes the requester as an owner, and
    /// the blob itself with its last owner.
    async fn delete(&self, sha256: BlobHash, headers: &HeaderMap) -> Reply {
        let token = match authorize(headers, "delete", self.origin(headers).host.as_deref(), now()) {
            Ok(token) => token,
            Err(error) => return unauthorized(error.reason()),
        };
        if !token.covers(sha256) {
            return unauthorized("Authorization has no x tag for this blob.");
        }

        let pubkey = token.pubkey;
        let result = self
            .locked(move |db, blobs| {
                let removal = db.remove_owner(sha256, &pubkey)?;
                if removal == Removal::Gone {
                    blobs.remove(sha256)?;
                }
                Ok(removal)
            })
            .await;
        match result {
            Ok(Removal::NotOwner) => error(StatusCode::NOT_FOUND, "No blob of yours to delete."),
            Ok(_) => Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty()).expect("response"),
            Err(error) => internal(error),
        }
    }

    fn origin(&self, headers: &HeaderMap) -> Origin {
        if let Some(url) = &self.public_url {
            return Origin { base: url.origin().ascii_serialization(), host: url.host_str().map(str::to_string) };
        }
        let host = header_str(headers, header::HOST)
            .map(str::trim)
            .filter(|host| !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)));
        let Some(host) = host else {
            return Origin { base: "http://localhost".into(), host: None };
        };
        let scheme = match header_str(headers, "x-forwarded-proto").and_then(|v| v.split(',').next()).map(str::trim) {
            Some("https") => "https",
            _ => "http",
        };
        Origin { base: format!("{scheme}://{host}"), host: Some(domain(host).to_ascii_lowercase()) }
    }
}

/// A `Host` without its port.
fn domain(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// The blob a request path names: `/<sha256>`, with any extension.
fn blob_path(path: &str) -> Option<BlobHash> {
    path.strip_prefix('/').filter(|name| !name.contains('/')).and_then(blob_name)
}

/// The blob another server's URL names. It may sit under a path of its
/// own, so only the last segment counts.
fn blob_url(url: &str) -> Option<BlobHash> {
    let url = url::Url::parse(url).ok()?;
    blob_name(url.path_segments()?.next_back()?)
}

/// `<sha256>`, with any extension.
fn blob_name(name: &str) -> Option<BlobHash> {
    let (hash, extension) = name.split_at_checked(64)?;
    if !(extension.is_empty() || extension.starts_with('.')) {
        return None;
    }
    BlobHash::parse(hash)
}

fn descriptor(status: StatusCode, sha256: BlobHash, record: Record, origin: &Origin) -> Reply {
    let descriptor = Descriptor {
        url: format!("{}/{sha256}.bin", origin.base),
        sha256: sha256.to_string(),
        size: record.size,
        kind: BINARY.into(),
        uploaded: record.uploaded,
    };
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&descriptor).expect("JSON")))
        .expect("response")
}

fn transfer_error(failure: &DownloadError, max_size: u64) -> Reply {
    let message = failure.message.clone();
    match failure.reason {
        DownloadReason::TooLarge => error_owned(StatusCode::PAYLOAD_TOO_LARGE, format!("Blobs may be at most {max_size} bytes.")),
        DownloadReason::HashMismatch => error(StatusCode::CONFLICT, "The blob's sha256 doesn't match."),
        DownloadReason::Rejected => error_owned(StatusCode::UNSUPPORTED_MEDIA_TYPE, message),
        DownloadReason::Blocked => error_owned(StatusCode::BAD_REQUEST, message),
        DownloadReason::Http => error_owned(StatusCode::BAD_GATEWAY, format!("The origin answered {message}")),
        // An upload's body that broke off, or a mirror's origin that did.
        DownloadReason::Network => error_owned(StatusCode::BAD_GATEWAY, message),
        DownloadReason::Storage => internal(anyhow::anyhow!(message)),
    }
}

fn preflight() -> Reply {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_HEADERS, "Authorization, *")
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, HEAD, PUT, DELETE")
        .header(header::ACCESS_CONTROL_MAX_AGE, PREFLIGHT_MAX_AGE)
        .body(Body::empty())
        .expect("response")
}

fn header_str(headers: &HeaderMap, name: impl header::AsHeaderName) -> Option<&str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// An error, with its reason in `X-Reason` (BUD-01) and the body both.
fn error(status: StatusCode, reason: &str) -> Reply {
    error_owned(status, reason.to_string())
}

fn error_owned(status: StatusCode, reason: String) -> Reply {
    // A header value can't hold everything a message might.
    let printable: String = reason.chars().map(|c| if c == ' ' || c.is_ascii_graphic() { c } else { '?' }).collect();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header("x-reason", HeaderValue::from_str(&printable).unwrap_or(HeaderValue::from_static("Error")))
        .body(Body::from(reason))
        .expect("response")
}

fn unauthorized(reason: &str) -> Reply {
    error(StatusCode::UNAUTHORIZED, reason)
}

fn not_allowed(allow: &'static str) -> Reply {
    let mut response = error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed.");
    response.headers_mut().insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}

fn internal(error: anyhow::Error) -> Reply {
    tracing::error!(%error, "blossom: storage failed");
    self::error(StatusCode::INTERNAL_SERVER_ERROR, "The server failed to store or read the blob.")
}

#[cfg(test)]
mod tests;
