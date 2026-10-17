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
//! - The server keeps a blob's size, the day it arrived, who uploaded it
//!   (which deleting needs), and the day each uploader's claim expires, if
//!   it does — never its declared type, the name a token mentions, or
//!   anything about the request. There is no `/list`.
//! - Nothing is logged per request. Each client's address is held in
//!   memory while it's rate limited, and no longer.
//!
//! Uploads and mirrors are limited per client address, in number, in bytes,
//! and in how many may run at once: tokens are free to sign, so they bound
//! nothing alone. Every byte received counts, whether or not the blob is
//! kept. An upload has [`UPLOAD_TIMEOUT`] in all, and is dropped if its
//! body stalls for [`UPLOAD_IDLE`]. None is taken that would leave the disk
//! with less than `min_free_space`.
//!
//! An uploader may ask for a blob to expire, with `X-Expiration: <unix
//! time>` on an upload or mirror (blossom#115): an attachment to a
//! disappearing message needn't outlive it. It's rounded up to the end of
//! its day, so the server learns no more of when the message was sent than
//! it does of when the blob arrived. A blob goes once every uploader's claim
//! on it has expired, never while any keeps it for good, and says when with
//! `Sunset` (BUD-01).
//!
//! Its blobs live in a store of their own, apart from the site's.

pub mod auth;
mod db;
pub mod sniff;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::body::Body;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use axum::extract::Request;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Response, StatusCode};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio_util::sync::CancellationToken;

use crate::blobs::{BlobStore, DownloadError, DownloadReason, Staged};
use crate::config::BlossomConfig;
use crate::hash::BlobHash;
use crate::origin::{Names, Origin, request_origin};
use crate::ratelimit::{self, RateLimiter, Trust};
use crate::storage::Storage;
use crate::util::{http_date, now};
use crate::web::serve::{Range, matches_etag, parse_range};
use auth::{Token, authorize};
use db::{BlossomDb, DAY, Record, Removal};
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

/// The most clients counted at once, by each limit.
const MAX_RATE_LIMITED: usize = 100_000;

/// How long an upload may take in all: a full-size blob at about a
/// megabit a second.
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How long an upload's body may go without sending anything.
const UPLOAD_IDLE: Duration = Duration::from_secs(30);

/// Uploads and mirrors running at once, in all and from one client. Each
/// holds a temp file, a buffer, and a connection while it runs.
const MAX_TRANSFERS: usize = 64;
const MAX_TRANSFERS_PER_CLIENT: usize = 4;

/// Deletes one client may make a minute. Each costs a signature check.
const DELETES_PER_MINUTE: u64 = 120;

/// The latest expiration taken: the start of the last day an HTTP date,
/// as `Sunset` gives it, can name.
const MAX_EXPIRATION: i64 = 253_402_214_400;

/// How often blobs past their expiration are deleted, and how many claims
/// one step of that takes on, holding the commit lock. Until they're
/// deleted they're already not served.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);
const SWEEP_BATCH: usize = 1000;

type Reply = Response<Body>;

#[derive(Clone)]
pub struct Blossom {
    server: Arc<Server>,
}

/// See [`Blossom::open_for_removal`].
pub struct Removals {
    db: BlossomDb,
    blobs: BlobStore,
}

impl Removals {
    /// Whether this server holds a blob `pubkey` uploaded.
    pub fn uploaded_by(&self, sha256: BlobHash, pubkey: &str) -> Result<bool> {
        self.db.owns(sha256, pubkey)
    }

    /// Remove a blob, whoever uploaded it.
    pub fn remove(&self, sha256: BlobHash) -> Result<()> {
        self.db.remove_blob(sha256)?;
        self.blobs.remove(sha256)
    }
}

struct Server {
    db: BlossomDb,
    blobs: BlobStore,
    names: Names,
    max_blob_size: u64,
    /// Whose word on a client's address to take; see [`crate::config::Config::trust`].
    trust: Trust,
    /// Uploads and mirrors each client may start a minute, and bytes it may
    /// send an hour. `None` for no limit.
    uploads: Option<Mutex<RateLimiter>>,
    bytes: Option<Mutex<RateLimiter>>,
    deletes: Mutex<RateLimiter>,
    /// Uploads and mirrors running.
    transfers: Transfers,
    /// Bytes to leave free on the disk.
    min_free_space: u64,
    /// Held while a blob goes into the store and the index, and while one
    /// comes out of both, so a delete racing an upload of the same blob
    /// can't leave a record without its bytes.
    commit: Arc<Mutex<()>>,
    /// Fires on shutdown, abandoning mirrors in progress.
    cancel: CancellationToken,
}

impl Blossom {
    /// Open the server's index and store. `names` are the origins clients
    /// reach it at, where known; mirrors in progress are abandoned once
    /// `cancel` fires.
    pub fn open(config: &BlossomConfig, names: Names, trust: Trust, storage: &Storage, cancel: &CancellationToken) -> Result<Blossom> {
        let db = BlossomDb::open(storage)?;
        let blobs = storage.blob_store("blossom/blobs");
        blobs.clear_temp();
        Ok(Blossom {
            server: Arc::new(Server {
                db,
                blobs,
                names,
                max_blob_size: config.max_blob_size,
                trust,
                uploads: limiter(config.uploads_per_minute.into(), Duration::from_secs(60)),
                bytes: limiter(config.upload_bytes_per_hour, Duration::from_secs(60 * 60)),
                deletes: Mutex::new(RateLimiter::new(DELETES_PER_MINUTE, Duration::from_secs(60), MAX_RATE_LIMITED)),
                transfers: Transfers::new(MAX_TRANSFERS, MAX_TRANSFERS_PER_CLIENT),
                min_free_space: config.min_free_space,
                commit: Arc::new(Mutex::new(())),
                cancel: cancel.child_token(),
            }),
        })
    }

    /// The index and store alone, for `armada ban` to remove blobs from in a
    /// process of its own. A running server stops serving a blob as soon as
    /// its record goes.
    pub fn open_for_removal(storage: &Storage) -> Result<Removals> {
        Ok(Removals { db: BlossomDb::open(storage)?, blobs: storage.blob_store("blossom/blobs") })
    }

    #[cfg(test)]
    pub fn router(&self) -> axum::Router {
        let blossom = self.clone();
        axum::Router::new().fallback(move |request: Request| async move { blossom.handle(request).await })
    }

    pub async fn handle(&self, request: Request) -> Reply {
        self.server.handle(request).await
    }

    /// Delete blobs once they expire, until shutdown.
    pub fn start(&self) {
        let server = self.server.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SWEEP_INTERVAL);
            loop {
                tokio::select! {
                    _ = server.cancel.cancelled() => break,
                    _ = interval.tick() => {}
                }
                match server.sweep().await {
                    Ok(0) => {}
                    Ok(gone) => tracing::info!(gone, "blossom: deleted expired blobs"),
                    Err(error) => tracing::error!(%error, "blossom: deleting expired blobs failed"),
                }
            }
        });
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
    /// When it's due to go, if it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expiration: Option<i64>,
}

#[derive(Deserialize)]
struct MirrorRequest {
    url: String,
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
                    Method::DELETE => self.delete(sha256, request).await,
                    _ => not_allowed("GET, HEAD, DELETE"),
                }
            }
        }
    }

    /// `GET` and `HEAD /<sha256>` (BUD-01). Only blobs this server accepted:
    /// never anything else that happens to be on disk.
    async fn get(&self, sha256: BlobHash, method: &Method, request: &HeaderMap) -> Reply {
        let record = match self.db.get(sha256) {
            // Past its expiration it's gone, whether or not it's been swept.
            Ok(Some(record)) if !record.expired(now()) => record,
            Ok(_) => return error(StatusCode::NOT_FOUND, "Blob not found."),
            Err(error) => return internal(error),
        };

        let etag = format!("\"{sha256}\"");
        let mut builder = Response::builder()
            .header(header::CONTENT_TYPE, BINARY)
            .header(header::CONTENT_DISPOSITION, "attachment")
            .header(header::CONTENT_SECURITY_POLICY, BLOB_CSP)
            .header(header::CACHE_CONTROL, CACHE_CONTROL)
            .header(header::ETAG, &etag)
            .header(header::ACCEPT_RANGES, "bytes");
        if let Some(expires) = record.expires {
            builder = builder.header("sunset", http_date(expires));
        }

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
        let Some(client) = self.client(&parts) else {
            // Without one there's nothing to limit by, and a shared count
            // would let any such client exhaust it for the rest.
            return error(StatusCode::BAD_REQUEST, "Cannot determine the client's address.");
        };
        if let Some(refusal) = self.admit(&client) {
            return refusal;
        }
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
        let expires = match expiration(&parts.headers, now()) {
            Ok(expires) => expires,
            Err(reason) => return error(StatusCode::BAD_REQUEST, reason),
        };
        let length = header_str(&parts.headers, header::CONTENT_LENGTH).and_then(|v| v.parse::<u64>().ok());
        if let Some(length) = length {
            if let Some(refusal) = self.check_size(length) {
                return refusal;
            }
            if let Some(refusal) = self.check_bytes(&client, length) {
                return refusal;
            }
        }
        if let Some(refusal) = self.check_space(length.unwrap_or(self.max_blob_size)) {
            return refusal;
        }
        let Some(_transfer) = self.transfers.start(&client) else {
            return rate_limited("Too many uploads at once; try again shortly.", 1);
        };

        // What it says it'll send is held against its budget from the start,
        // so uploads started together can't all fit in what's left of it.
        let reserved = length.unwrap_or(0);
        self.charge_bytes(&client, reserved);
        let received = Arc::new(AtomicU64::new(0));
        let mut sniffer = Sniffer::default();
        let ingest = self.blobs.ingest(watched(body, received.clone()), declared, self.max_blob_size, &mut sniffer);
        let result = tokio::time::timeout(UPLOAD_TIMEOUT, ingest).await;
        self.settle_bytes(&client, reserved, received.load(Ordering::Relaxed));
        let staged = match result {
            Ok(Ok(staged)) => staged,
            Ok(Err(failure)) if failure.reason == DownloadReason::Network => {
                return error(StatusCode::BAD_REQUEST, "The upload broke off, or stalled.");
            }
            Ok(Err(failure)) => return transfer_error(&failure, self.max_blob_size),
            Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "The upload took too long."),
        };
        // Without X-SHA-256 the hash is only known now.
        if !token.covers(staged.sha256) {
            return unauthorized("Authorization has no x tag for this blob.");
        }
        self.keep(staged, &token, expires, &origin).await
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

    /// Whether a blob of `length` would leave the disk at least
    /// `min_free_space`. If it can't be told, it's let through.
    fn check_space(&self, length: u64) -> Option<Reply> {
        if self.min_free_space == 0 {
            return None;
        }
        let free = self.blobs.free_space()?;
        (free < self.min_free_space.saturating_add(length)).then(|| error(StatusCode::INSUFFICIENT_STORAGE, "This server is out of space for blobs."))
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
        let Some(client) = self.client(&parts) else {
            // Without one there's nothing to limit by, and a shared count
            // would let any such client exhaust it for the rest.
            return error(StatusCode::BAD_REQUEST, "Cannot determine the client's address.");
        };
        if let Some(refusal) = self.admit(&client) {
            return refusal;
        }
        let origin = self.origin(&parts.headers);
        let token = match authorize(&parts.headers, "upload", origin.host.as_deref(), now()) {
            Ok(token) => token,
            Err(error) => return unauthorized(error.reason()),
        };
        let expires = match expiration(&parts.headers, now()) {
            Ok(expires) => expires,
            Err(reason) => return error(StatusCode::BAD_REQUEST, reason),
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
        // upload would make them. Looked at under the commit lock, so a
        // delete can't take the blob between the look and the record.
        let pubkey = token.pubkey.clone();
        let existing = self
            .locked(move |db, blobs| match db.get(sha256)? {
                Some(_) if blobs.size(sha256).is_some() => db.add(sha256, 0, &pubkey, expires, now()).map(|(record, _)| Some(record)),
                _ => Ok(None),
            })
            .await;
        match existing {
            Ok(Some(record)) => return descriptor(StatusCode::OK, sha256, record, &origin),
            Ok(None) => {}
            Err(error) => return internal(error),
        }

        if let Some(refusal) = self.check_space(self.max_blob_size) {
            return refusal;
        }
        let Some(_transfer) = self.transfers.start(&client) else {
            return rate_limited("Too many uploads at once; try again shortly.", 1);
        };
        let mut sniffer = Sniffer::default();
        let staged = match self.blobs.download_staged(&url, sha256, self.max_blob_size, &mut sniffer, &self.cancel).await {
            Ok(staged) => staged,
            Err(error) => {
                self.charge_bytes(&client, error.received);
                return transfer_error(&error, self.max_blob_size);
            }
        };
        self.charge_bytes(&client, staged.size);
        self.keep(staged, &token, expires, &origin).await
    }

    /// The key a request's client is limited under.
    fn client(&self, parts: &http::request::Parts) -> Option<String> {
        ratelimit::client_key(&parts.headers, &parts.extensions, self.trust)
    }

    /// Count an upload or mirror against its client, before its token is
    /// checked: that's work too.
    fn admit(&self, client: &str) -> Option<Reply> {
        if let Some(uploads) = &self.uploads
            && let Err(retry_after) = uploads.lock().admit(client, Instant::now())
        {
            return Some(rate_limited("Too many uploads; try again later.", retry_after));
        }
        self.check_bytes(client, 1)
    }

    /// Whether `client` may send `length` more bytes this hour.
    fn check_bytes(&self, client: &str, length: u64) -> Option<Reply> {
        let retry_after = self.bytes.as_ref()?.lock().check(client, length, Instant::now()).err()?;
        Some(rate_limited("Too many bytes uploaded; try again later.", retry_after))
    }

    /// Spend what a blob took to receive, whether or not it was kept.
    fn charge_bytes(&self, client: &str, size: u64) {
        if let Some(bytes) = &self.bytes {
            bytes.lock().charge(client, size, Instant::now());
        }
    }

    /// Settle what an upload `reserved` against what it turned out to send.
    fn settle_bytes(&self, client: &str, reserved: u64, received: u64) {
        let Some(bytes) = &self.bytes else { return };
        let mut bytes = bytes.lock();
        match received.cmp(&reserved) {
            std::cmp::Ordering::Greater => bytes.charge(client, received - reserved, Instant::now()),
            std::cmp::Ordering::Less => bytes.refund(client, reserved - received, Instant::now()),
            std::cmp::Ordering::Equal => {}
        }
    }

    /// Commit a staged blob, record its uploader's claim on it until
    /// `expires`, and describe it.
    async fn keep(&self, staged: Staged, token: &Token, expires: Option<i64>, origin: &Origin) -> Reply {
        let sha256 = staged.sha256;
        let pubkey = token.pubkey.clone();
        let result = self
            .locked(move |db, _| {
                let size = staged.size;
                staged.commit()?;
                db.add(sha256, size, &pubkey, expires, now())
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
    async fn delete(&self, sha256: BlobHash, request: Request) -> Reply {
        let (parts, _) = request.into_parts();
        let Some(client) = self.client(&parts) else {
            return error(StatusCode::BAD_REQUEST, "Cannot determine the client's address.");
        };
        if let Err(retry_after) = self.deletes.lock().admit(&client, Instant::now()) {
            return rate_limited("Too many deletes; try again later.", retry_after);
        }
        let headers = &parts.headers;
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

    /// Delete what's expired, a step at a time, so uploads and deletes
    /// waiting on the commit lock get their turn. Returns how many blobs went.
    async fn sweep(&self) -> Result<usize> {
        let mut total = 0;
        loop {
            let now = now();
            let (gone, more) = self
                .locked(move |db, blobs| {
                    let (gone, more) = db.sweep(now, SWEEP_BATCH)?;
                    for &sha256 in &gone {
                        if let Err(error) = blobs.remove(sha256) {
                            tracing::error!(%error, "blossom: an expired blob's bytes couldn't be deleted");
                        }
                    }
                    Ok((gone.len(), more))
                })
                .await?;
            total += gone;
            if !more || self.cancel.is_cancelled() {
                return Ok(total);
            }
        }
    }

    /// Where the request reached this server: the origin blob URLs are built
    /// on, and the domain `server` tags must name.
    fn origin(&self, headers: &HeaderMap) -> Origin {
        request_origin(&self.names, headers)
    }
}

/// A request body that fails once it goes [`UPLOAD_IDLE`] without sending
/// anything, counting into `received` every byte that passes.
fn watched(body: Body, received: Arc<AtomicU64>) -> impl Stream<Item = Result<Bytes, std::io::Error>> {
    futures_util::stream::unfold(Some(body.into_data_stream()), move |stream| {
        let received = received.clone();
        async move {
            let mut stream = stream?;
            match tokio::time::timeout(UPLOAD_IDLE, stream.next()).await {
                Ok(Some(Ok(chunk))) => {
                    received.fetch_add(chunk.len() as u64, Ordering::Relaxed);
                    Some((Ok(chunk), Some(stream)))
                }
                Ok(Some(Err(error))) => Some((Err(std::io::Error::other(error)), None)),
                Ok(None) => None,
                Err(_) => Some((Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "the upload stalled")), None)),
            }
        }
    })
}

/// Uploads and mirrors running, in all and by client.
struct Transfers {
    total: Semaphore,
    per_client: usize,
    running: Mutex<HashMap<String, usize>>,
}

/// One transfer, counted until it's dropped.
struct Transfer<'a> {
    transfers: &'a Transfers,
    client: String,
    _permit: SemaphorePermit<'a>,
}

impl Transfers {
    fn new(total: usize, per_client: usize) -> Transfers {
        Transfers { total: Semaphore::new(total), per_client, running: Mutex::new(HashMap::new()) }
    }

    /// Count one from `client`, or `None` if there are already as many as
    /// may be, from it or in all.
    fn start(&self, client: &str) -> Option<Transfer<'_>> {
        let permit = self.total.try_acquire().ok()?;
        let mut running = self.running.lock();
        let count = running.entry(client.to_string()).or_default();
        if *count >= self.per_client {
            if *count == 0 {
                running.remove(client);
            }
            return None;
        }
        *count += 1;
        Some(Transfer { transfers: self, client: client.to_string(), _permit: permit })
    }
}

impl Drop for Transfer<'_> {
    fn drop(&mut self) {
        let mut running = self.transfers.running.lock();
        if let Some(count) = running.get_mut(&self.client) {
            *count -= 1;
            if *count == 0 {
                running.remove(&self.client);
            }
        }
    }
}

/// When an upload's uploader asks for its claim to expire, from
/// `X-Expiration`, rounded up to the end of its day: `None` for never.
fn expiration(headers: &HeaderMap, now: i64) -> Result<Option<i64>, &'static str> {
    let Some(value) = header_str(headers, "x-expiration") else { return Ok(None) };
    let Ok(at) = value.trim().parse::<i64>() else {
        return Err("X-Expiration is not a unix time.");
    };
    if at <= now {
        return Err("X-Expiration is in the past.");
    }
    if at > MAX_EXPIRATION {
        return Err("X-Expiration is too far off.");
    }
    Ok(Some(at + (DAY - at.rem_euclid(DAY)) % DAY))
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
        expiration: record.expires,
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

fn rate_limited(reason: &str, retry_after: u64) -> Reply {
    let mut response = error(StatusCode::TOO_MANY_REQUESTS, reason);
    response.headers_mut().insert(header::RETRY_AFTER, retry_after.into());
    response
}

/// A limit of `limit` a `window`, or none for 0.
fn limiter(limit: u64, window: Duration) -> Option<Mutex<RateLimiter>> {
    (limit != 0).then(|| Mutex::new(RateLimiter::new(limit, window, MAX_RATE_LIMITED)))
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
