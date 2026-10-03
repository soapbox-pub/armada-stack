//! The content-addressed filesystem store every service shares.
//!
//! Blobs live at `<dir>/<ab>/<cd>/<sha256>` — a two-level fanout keeps any one
//! directory small. Downloads are hashed while they stream into a temp file
//! and renamed into place only once the hash matches, so a truncated transfer
//! or a lying server can never leave a bad blob behind, and the rename is
//! atomic so readers never see a partial file.
//!
//! Compressed copies sit beside their blob as `<sha256>.br` and `<sha256>.gz`.
//! They are an attribute of a blob rather than blobs themselves: nothing
//! references them by name, and their names aren't hashes.

use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::hash::BlobHash;
use crate::net::{is_public_address, PublicResolver};

/// Compressed copies stored alongside a blob.
///
/// Both, rather than only the better one: Firefox only offers `br` on HTTPS,
/// and a self-hosted site may well be reached over plain HTTP.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Encoding {
    Br,
    Gzip,
}

impl Encoding {
    pub const ALL: [Encoding; 2] = [Encoding::Br, Encoding::Gzip];

    pub fn as_str(self) -> &'static str {
        match self {
            Encoding::Br => "br",
            Encoding::Gzip => "gzip",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Encoding::Br => ".br",
            Encoding::Gzip => ".gz",
        }
    }
}

/// Blobs too small to bother compressing: anything under a TCP segment arrives
/// in one packet either way.
const MIN_VARIANT_SIZE: u64 = 512;

/// How much smaller a variant has to be before it's worth keeping.
const MIN_SAVING: f64 = 0.05;

/// Size above which brotli drops from its slowest setting. Quality 11 runs
/// around a megabyte a second: fine once for a page or a bundle, not for a
/// large dump that would hold up every other blob in the deploy.
const BROTLI_SLOW_ABOVE: u64 = 4 * 1024 * 1024;

/// Redirects followed before giving up on a blob.
const MAX_REDIRECTS: usize = 3;

/// How long one download may take, start to finish.
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30);

/// Mapped blobs kept for serving.
const MAPPED_BLOBS: usize = 4096;

/// Sizes of a stored blob and whatever compressed copies it has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Variants {
    /// Size of the blob itself, which is always the one that exists.
    pub identity: u64,
    pub br: Option<u64>,
    pub gzip: Option<u64>,
}

impl Variants {
    pub fn size(&self, encoding: Option<Encoding>) -> u64 {
        match encoding {
            None => self.identity,
            Some(Encoding::Br) => self.br.unwrap_or(self.identity),
            Some(Encoding::Gzip) => self.gzip.unwrap_or(self.identity),
        }
    }

    pub fn get(&self, encoding: Encoding) -> Option<u64> {
        match encoding {
            Encoding::Br => self.br,
            Encoding::Gzip => self.gzip,
        }
    }
}

/// Why a download failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DownloadReason {
    Http,
    TooLarge,
    HashMismatch,
    Network,
    Blocked,
    /// An [`Inspector`] refused the bytes.
    Rejected,
    /// The store itself failed: a temp file couldn't be written or renamed.
    Storage,
}

impl DownloadReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DownloadReason::Http => "http",
            DownloadReason::TooLarge => "too_large",
            DownloadReason::HashMismatch => "hash_mismatch",
            DownloadReason::Network => "network",
            DownloadReason::Blocked => "blocked",
            DownloadReason::Rejected => "rejected",
            DownloadReason::Storage => "storage",
        }
    }
}

/// Looks at a blob's bytes as they stream into the store, and may refuse
/// them. A refusal stops the transfer and leaves nothing behind.
pub trait Inspector: Send {
    /// Each chunk, in order, before it is written.
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), String>;
    /// Called once every byte has arrived, before the blob is committed.
    fn finish(&mut self) -> Result<(), String>;
}

/// The inspector that accepts everything.
struct AcceptAll;

impl Inspector for AcceptAll {
    fn chunk(&mut self, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    fn finish(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// A blob written, hashed, and inspected, but not yet in the store. Dropping
/// it discards the bytes; [`Staged::commit`] moves them into place.
pub struct Staged {
    store: BlobStore,
    tmp: TempFile,
    pub sha256: BlobHash,
    pub size: u64,
}

impl Staged {
    pub fn commit(self) -> Result<()> {
        self.store.commit(self.tmp, self.sha256)
    }
}

/// A download that failed, and why.
#[derive(Debug)]
pub struct DownloadError {
    pub message: String,
    pub reason: DownloadReason,
    pub status: Option<u16>,
}

impl std::fmt::Display for DownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DownloadError {}

fn fail(message: impl Into<String>, reason: DownloadReason, status: Option<u16>) -> DownloadError {
    DownloadError { message: message.into(), reason, status }
}

#[derive(Clone)]
pub struct BlobStore {
    inner: Arc<Inner>,
}

struct Inner {
    dir: PathBuf,
    tmp: PathBuf,
    http: reqwest::Client,
    /// Only tests turn this off: their Blossom servers listen on loopback,
    /// which is exactly what the real check refuses.
    public_only: bool,
    mapped: Mutex<lru::LruCache<(BlobHash, Option<Encoding>), Bytes>>,
}

impl BlobStore {
    pub fn new(dir: &Path) -> BlobStore {
        Self::build(dir, true)
    }

    /// A store whose downloads may reach private addresses. For tests.
    #[cfg(test)]
    pub fn allowing_private(dir: &Path) -> BlobStore {
        Self::build(dir, false)
    }

    fn build(dir: &Path, public_only: bool) -> BlobStore {
        let mut http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("armada/", env!("CARGO_PKG_VERSION")))
            .connect_timeout(Duration::from_secs(10));
        if public_only {
            http = http.dns_resolver(Arc::new(PublicResolver));
        }

        BlobStore {
            inner: Arc::new(Inner {
                dir: dir.to_path_buf(),
                tmp: dir.join("tmp"),
                http: http.build().expect("an HTTP client"),
                public_only,
                mapped: Mutex::new(lru::LruCache::new(NonZeroUsize::new(MAPPED_BLOBS).unwrap())),
            }),
        }
    }

    /// Filesystem path a blob occupies, whether or not it exists.
    pub fn path(&self, sha256: BlobHash) -> PathBuf {
        let hex = sha256.hex();
        let name = hex.as_str();
        self.inner.dir.join(&name[..2]).join(&name[2..4]).join(name)
    }

    /// Filesystem path one of a blob's compressed copies occupies.
    pub fn variant_path(&self, sha256: BlobHash, encoding: Encoding) -> PathBuf {
        let mut path = self.path(sha256).into_os_string();
        path.push(encoding.suffix());
        path.into()
    }

    fn file_path(&self, sha256: BlobHash, encoding: Option<Encoding>) -> PathBuf {
        match encoding {
            Some(encoding) => self.variant_path(sha256, encoding),
            None => self.path(sha256),
        }
    }

    /// Size in bytes, or `None` when the blob isn't stored.
    pub fn size(&self, sha256: BlobHash) -> Option<u64> {
        size_of(&self.path(sha256))
    }

    /// The first `max_bytes` of a blob, decoded as UTF-8 with anything invalid
    /// replaced. The cap is the point: a site may publish a file of any size
    /// at any name.
    pub fn read_text(&self, sha256: BlobHash, max_bytes: u64) -> String {
        use std::io::Read;
        let Ok(file) = std::fs::File::open(self.path(sha256)) else {
            return String::new();
        };
        let mut bytes = Vec::new();
        let _ = file.take(max_bytes).read_to_end(&mut bytes);
        String::from_utf8_lossy(&bytes).into_owned()
    }

    /// Sizes of a blob and every compressed copy it has, or `None` when the
    /// blob isn't stored.
    pub fn variants(&self, sha256: BlobHash) -> Option<Variants> {
        let identity = self.size(sha256)?;
        Some(Variants {
            identity,
            br: size_of(&self.variant_path(sha256, Encoding::Br)),
            gzip: size_of(&self.variant_path(sha256, Encoding::Gzip)),
        })
    }

    /// A blob or copy an earlier [`BlobStore::open`] mapped and kept, found
    /// without touching the disk — so without leaving a runtime thread.
    pub fn mapped(&self, sha256: BlobHash, encoding: Option<Encoding>) -> Option<Bytes> {
        self.inner.mapped.lock().get(&(sha256, encoding)).cloned()
    }

    /// A blob, or one of its compressed copies, for a response body.
    ///
    /// Mapped rather than read: the bytes are the kernel's page cache, a
    /// response is a slice of the mapping, and the mapping is kept, so a warm
    /// file costs no system call at all to send again. Stored files are only
    /// ever replaced by rename, never rewritten, so a mapping can't change
    /// under a reader.
    pub fn open(&self, sha256: BlobHash, encoding: Option<Encoding>) -> Result<Bytes> {
        if let Some(bytes) = self.mapped(sha256, encoding) {
            return Ok(bytes);
        }
        let key = (sha256, encoding);

        let file = std::fs::File::open(self.file_path(sha256, encoding))?;
        let len = file.metadata()?.len();
        let bytes = if len == 0 {
            Bytes::new()
        } else {
            // SAFETY: stored files are written once, through a temp file and a
            // rename, and never truncated or modified in place.
            let map = unsafe { memmap2::Mmap::map(&file)? };
            Bytes::from_owner(map)
        };

        self.inner.mapped.lock().put(key, bytes.clone());
        Ok(bytes)
    }

    /// Compress a stored blob, if it isn't already and it's worth doing.
    ///
    /// Returns the encodings written by this call. CPU-bound, so callers on a
    /// runtime run it on the blocking pool.
    pub fn ensure_variants(&self, sha256: BlobHash) -> Result<Vec<Encoding>> {
        let Some(size) = self.size(sha256) else {
            return Ok(Vec::new());
        };
        if size < MIN_VARIANT_SIZE {
            return Ok(Vec::new());
        }

        let mut written = Vec::new();
        // One encoding at a time: a deploy already compresses several blobs at
        // once, and doubling that again would just contend for the same cores.
        for encoding in Encoding::ALL {
            if size_of(&self.variant_path(sha256, encoding)).is_some() {
                continue;
            }
            if self.write_variant(sha256, encoding, size)? {
                written.push(encoding);
            }
        }

        Ok(written)
    }

    /// Store bytes already in memory, verifying them against `sha256`.
    pub fn put(&self, sha256: BlobHash, bytes: &[u8]) -> Result<u64> {
        let digest = BlobHash::of(bytes);
        if digest != sha256 {
            anyhow::bail!(fail(format!("Expected {sha256}, got {digest}"), DownloadReason::HashMismatch, None));
        }

        let tmp = self.temp_file()?;
        std::fs::write(&tmp, bytes)?;
        self.commit(tmp, sha256)?;
        Ok(bytes.len() as u64)
    }

    /// Download a blob from `url`, verifying it hashes to `sha256`.
    ///
    /// The target — and every redirect it leads to — must be a public address,
    /// because the URL ultimately comes from a manifest anyone can publish.
    /// Returns the size in bytes, leaving the store untouched on failure.
    pub async fn download(
        &self,
        url: &str,
        sha256: BlobHash,
        max_size: u64,
        cancel: &CancellationToken,
    ) -> Result<u64, DownloadError> {
        let staged = self.download_staged(url, sha256, max_size, &mut AcceptAll, cancel).await?;
        let size = staged.size;
        staged.commit().map_err(|e| fail(e.to_string(), DownloadReason::Storage, None))?;
        Ok(size)
    }

    /// [`BlobStore::download`], with every byte shown to `inspector`, and
    /// the blob left staged for the caller to commit.
    pub async fn download_staged(
        &self,
        url: &str,
        sha256: BlobHash,
        max_size: u64,
        inspector: &mut dyn Inspector,
        cancel: &CancellationToken,
    ) -> Result<Staged, DownloadError> {
        let work = self.download_inner(url, sha256, max_size, inspector);
        tokio::select! {
            result = tokio::time::timeout(DOWNLOAD_TIMEOUT, work) => match result {
                Ok(result) => result,
                Err(_) => Err(fail("The operation timed out.", DownloadReason::Network, None)),
            },
            _ = cancel.cancelled() => Err(fail("The operation was aborted.", DownloadReason::Network, None)),
        }
    }

    async fn download_inner(
        &self,
        url: &str,
        sha256: BlobHash,
        max_size: u64,
        inspector: &mut dyn Inspector,
    ) -> Result<Staged, DownloadError> {
        let response = self.request(url).await?;

        let status = response.status().as_u16();
        if !response.status().is_success() {
            return Err(fail(format!("HTTP {status}"), DownloadReason::Http, Some(status)));
        }

        // Reject oversized blobs before reading a single byte, when possible.
        if let Some(declared) = response.content_length()
            && declared > max_size
        {
            return Err(fail(format!("{declared} bytes exceeds the {max_size} byte limit"), DownloadReason::TooLarge, None));
        }

        self.ingest(response.bytes_stream(), Some(sha256), max_size, inspector).await
    }

    /// Stream a blob into a staged temp file: hashed, capped at `max_size`,
    /// shown to `inspector`, and checked against `expected` when given.
    pub async fn ingest<E: std::error::Error>(
        &self,
        body: impl Stream<Item = Result<Bytes, E>>,
        expected: Option<BlobHash>,
        max_size: u64,
        inspector: &mut dyn Inspector,
    ) -> Result<Staged, DownloadError> {
        let storage = |e: std::io::Error| fail(e.to_string(), DownloadReason::Storage, None);
        let tmp = self.temp_file().map_err(|e| fail(e.to_string(), DownloadReason::Storage, None))?;
        let mut file = tokio::io::BufWriter::with_capacity(256 * 1024, tokio::fs::File::create(&tmp).await.map_err(storage)?);
        let mut hash = Sha256::new();
        let mut size: u64 = 0;

        let mut body = std::pin::pin!(body);
        while let Some(chunk) = body.next().await {
            let chunk = chunk.map_err(|e| fail(error_chain(&e), DownloadReason::Network, None))?;
            size += chunk.len() as u64;
            // Senders may omit content-length, so enforce the cap mid-stream too.
            if size > max_size {
                return Err(fail(format!("Body exceeds the {max_size} byte limit"), DownloadReason::TooLarge, None));
            }
            inspector.chunk(&chunk).map_err(|reason| fail(reason, DownloadReason::Rejected, None))?;
            hash.update(&chunk);
            file.write_all(&chunk).await.map_err(storage)?;
        }
        file.flush().await.map_err(storage)?;
        inspector.finish().map_err(|reason| fail(reason, DownloadReason::Rejected, None))?;

        let digest = BlobHash::from_bytes(hash.finalize().into());
        if let Some(expected) = expected
            && digest != expected
        {
            return Err(fail(format!("Expected {expected}, got {digest}"), DownloadReason::HashMismatch, None));
        }
        Ok(Staged { store: self.clone(), tmp, sha256: digest, size })
    }

    /// Delete a blob and its compressed copies, and forget any mapping of
    /// them, so nothing serves them again.
    pub fn remove(&self, sha256: BlobHash) -> Result<()> {
        {
            let mut mapped = self.inner.mapped.lock();
            mapped.pop(&(sha256, None));
            for encoding in Encoding::ALL {
                mapped.pop(&(sha256, Some(encoding)));
                let _ = std::fs::remove_file(self.variant_path(sha256, encoding));
            }
        }
        match std::fs::remove_file(self.path(sha256)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.into()),
            _ => Ok(()),
        }
    }

    /// Every blob stored, with when it was written. Compressed copies go with
    /// their blob, so aren't listed; nor is anything else in the directory.
    pub fn list(&self) -> Result<Vec<(BlobHash, SystemTime)>> {
        let mut blobs = Vec::new();
        let entries = |dir: &Path| -> Result<Vec<std::fs::DirEntry>> {
            match std::fs::read_dir(dir) {
                Ok(entries) => Ok(entries.collect::<std::io::Result<_>>()?),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
                Err(error) => Err(error.into()),
            }
        };
        let fanned = |entry: &std::fs::DirEntry| entry.file_type().is_ok_and(|kind| kind.is_dir()) && entry.file_name().len() == 2;
        for first in entries(&self.inner.dir)?.iter().filter(|entry| fanned(entry)) {
            for second in entries(&first.path())?.iter().filter(|entry| fanned(entry)) {
                for file in entries(&second.path())? {
                    let Some(sha256) = file.file_name().to_str().and_then(BlobHash::parse) else { continue };
                    if file.path() != self.path(sha256) {
                        continue;
                    }
                    let metadata = file.metadata()?;
                    if metadata.is_file() {
                        blobs.push((sha256, metadata.modified()?));
                    }
                }
            }
        }
        Ok(blobs)
    }

    /// Fetch a URL, following redirects one at a time, so each hop is vetted
    /// before it is requested.
    async fn request(&self, url: &str) -> Result<reqwest::Response, DownloadError> {
        let mut target =
            url::Url::parse(url).map_err(|_| fail(format!("Not a valid URL: {url}"), DownloadReason::Blocked, None))?;

        for hop in 0.. {
            if target.scheme() != "http" && target.scheme() != "https" {
                return Err(fail(format!("Refusing to fetch a {}: URL", target.scheme()), DownloadReason::Blocked, None));
            }
            self.assert_public(&target).await?;

            let response = self
                .inner
                .http
                .get(target.clone())
                .send()
                .await
                .map_err(|e| fail(error_chain(&e), DownloadReason::Network, None))?;

            let status = response.status().as_u16();
            if ![301, 302, 303, 307, 308].contains(&status) {
                return Ok(response);
            }

            let location = response.headers().get("location").and_then(|v| v.to_str().ok()).map(str::to_string);
            let Some(location) = location else {
                return Err(fail(format!("HTTP {status} without a Location header"), DownloadReason::Http, Some(status)));
            };
            if hop >= MAX_REDIRECTS {
                return Err(fail(format!("More than {MAX_REDIRECTS} redirects"), DownloadReason::Http, Some(status)));
            }
            target = target.join(&location).map_err(|_| {
                fail(format!("Redirected to an invalid URL: {location}"), DownloadReason::Blocked, None)
            })?;
        }

        unreachable!()
    }

    /// Refuse to fetch anything that isn't on the public internet. The
    /// resolver the client connects through enforces the same rule; this is
    /// what gives the log a sentence rather than a connection error.
    async fn assert_public(&self, url: &url::Url) -> Result<(), DownloadError> {
        if !self.inner.public_only {
            return Ok(());
        }

        let host = url.host_str().unwrap_or("");
        let addresses =
            crate::net::resolve_all(host).await.map_err(|e| fail(e.to_string(), DownloadReason::Network, None))?;
        if addresses.into_iter().all(is_public_address) {
            return Ok(());
        }

        Err(fail(
            format!(
                "{host} is not a public address. Publish this site's blobs to a Blossom server reachable on the public internet."
            ),
            DownloadReason::Blocked,
            None,
        ))
    }

    /// Delete any temp files left behind by an interrupted download.
    pub fn clear_temp(&self) {
        let _ = std::fs::remove_dir_all(&self.inner.tmp);
    }

    fn temp_file(&self) -> Result<TempFile> {
        std::fs::create_dir_all(&self.inner.tmp)?;
        Ok(TempFile { path: self.inner.tmp.join(crate::util::random_hex(16)), kept: false })
    }

    fn commit(&self, tmp: TempFile, sha256: BlobHash) -> Result<()> {
        let target = self.path(sha256);
        if let Some(dir) = target.parent() {
            std::fs::create_dir_all(dir)?;
        }
        tmp.keep_as(&target)?;
        Ok(())
    }

    /// Compress one blob into one encoding. Returns whether the result was
    /// worth keeping. Streamed through a temp file, for the same reason
    /// downloads are: an interrupted pass must not leave a truncated variant.
    fn write_variant(&self, sha256: BlobHash, encoding: Encoding, size: u64) -> Result<bool> {
        let tmp = self.temp_file()?;

        (|| -> Result<bool> {
            let mut input = std::io::BufReader::with_capacity(256 * 1024, std::fs::File::open(self.path(sha256))?);
            let output = std::io::BufWriter::with_capacity(256 * 1024, std::fs::File::create(&tmp)?);

            match encoding {
                Encoding::Gzip => {
                    let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::new(9));
                    std::io::copy(&mut input, &mut encoder)?;
                    encoder.finish()?.flush()?;
                }
                Encoding::Br => {
                    let params = brotli::enc::BrotliEncoderParams {
                        quality: if size > BROTLI_SLOW_ABOVE { 5 } else { 11 },
                        // A window as large as the input, capped at what every
                        // decoder handles without the large-window extension.
                        lgwin: 24,
                        size_hint: size as usize,
                        ..Default::default()
                    };
                    let mut output = output;
                    brotli::BrotliCompress(&mut input, &mut output, &params)?;
                    output.flush()?;
                }
            }

            let compressed = size_of(&tmp).unwrap_or(u64::MAX);
            if compressed as f64 > size as f64 * (1.0 - MIN_SAVING) {
                return Ok(false);
            }
            tmp.keep_as(&self.variant_path(sha256, encoding))?;
            Ok(true)
        })()
    }
}

/// A file in the store's `tmp`, removed when dropped unless it was renamed
/// into place. A download is a future, and one dropped by a timeout or a
/// cancel never reaches cleanup of its own, so the cleanup can't be code that
/// runs after it.
struct TempFile {
    path: PathBuf,
    kept: bool,
}

impl TempFile {
    fn keep_as(mut self, target: &Path) -> std::io::Result<()> {
        std::fs::rename(&self.path, target)?;
        self.kept = true;
        Ok(())
    }
}

impl std::ops::Deref for TempFile {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for TempFile {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if !self.kept {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Size of a file, or `None` when it isn't there.
fn size_of(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().filter(|m| m.is_file()).map(|m| m.len())
}

/// An error with its causes, which is where reqwest keeps the useful part.
fn error_chain(error: &dyn std::error::Error) -> String {
    let mut message = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use super::*;

    #[test]
    fn stores_and_compresses() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path());
        let text = "hello world ".repeat(200);
        let sha = BlobHash::of(text.as_bytes());

        assert!(store.put(BlobHash::from_bytes([0; 32]), text.as_bytes()).is_err());
        assert_eq!(store.put(sha, text.as_bytes()).unwrap(), text.len() as u64);
        assert_eq!(store.size(sha), Some(text.len() as u64));

        let written = store.ensure_variants(sha).unwrap();
        assert_eq!(written, [Encoding::Br, Encoding::Gzip]);
        assert!(store.ensure_variants(sha).unwrap().is_empty());

        let variants = store.variants(sha).unwrap();
        assert!(variants.br.unwrap() < variants.identity);
        assert!(variants.gzip.unwrap() < variants.identity);

        let mut decoded = String::new();
        flate2::read::GzDecoder::new(&store.open(sha, Some(Encoding::Gzip)).unwrap()[..]).read_to_string(&mut decoded).unwrap();
        assert_eq!(decoded, text);
        let mut decoded = Vec::new();
        brotli::BrotliDecompress(&mut &store.open(sha, Some(Encoding::Br)).unwrap()[..], &mut decoded).unwrap();
        assert_eq!(decoded, text.as_bytes());

        assert_eq!(&store.open(sha, None).unwrap()[..], text.as_bytes());
    }

    #[test]
    fn skips_small_and_incompressible() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path());
        let small = b"tiny";
        let sha = BlobHash::of(small);
        store.put(sha, small).unwrap();
        assert!(store.ensure_variants(sha).unwrap().is_empty());

        let noise: Vec<u8> = (0..4096u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        let sha = BlobHash::of(&noise);
        store.put(sha, &noise).unwrap();
        store.ensure_variants(sha).unwrap();
        let variants = store.variants(sha).unwrap();
        assert!(variants.br.is_none_or(|br| (br as f64) <= 4096.0 * 0.95));
    }

    #[tokio::test]
    async fn refuses_private_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path());
        let cancel = CancellationToken::new();
        let hash = BlobHash::from_bytes([0xaa; 32]);
        let error = store.download("http://127.0.0.1:1/x", hash, 1000, &cancel).await.unwrap_err();
        assert_eq!(error.reason, DownloadReason::Blocked);
        let error = store.download("ftp://example.com/x", hash, 1000, &cancel).await.unwrap_err();
        assert_eq!(error.reason, DownloadReason::Blocked);
    }

    /// A server that sends part of a body and stalls leaves nothing behind
    /// once the download is abandoned.
    #[tokio::test]
    async fn abandoned_downloads_leave_no_temp_file() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n").await.unwrap();
            stream.write_all(&[b'x'; 50_000]).await.unwrap();
            std::future::pending::<()>().await;
        });

        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::allowing_private(dir.path());
        let cancel = CancellationToken::new();
        let url = format!("http://127.0.0.1:{port}/x");
        let hash = BlobHash::from_bytes([0xaa; 32]);
        let download = store.download(&url, hash, 1_000_000, &cancel);
        let stop = async {
            // Long enough for the partial body to reach the temp file.
            tokio::time::sleep(Duration::from_millis(300)).await;
            cancel.cancel();
        };
        let (result, ()) = tokio::join!(download, stop);
        assert!(result.is_err());
        let left: Vec<_> = std::fs::read_dir(dir.path().join("tmp")).unwrap().collect();
        assert!(left.is_empty());
    }
}
