//! The sync worker: find the site's newest version, download it, put it live.
//!
//! Three things bring a version in:
//!
//! 1. A fetch at startup, and again every `resync_interval`, which catches
//!    anything the subscription missed while a relay was down.
//! 2. A live subscription to the site's manifest, while `auto_update` is on.
//! 3. A retry, with backoff, of a version whose deploy failed.
//!
//! A version goes live only once every one of its blobs is on disk, and then
//! all at once, so the site is never served half-updated. It goes live with
//! the versions kept before it merged beneath (see [`super::site`]). With `auto_update`
//! off the worker stops as soon as anything is live.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwapOption;
use futures_util::StreamExt;
use futures_util::stream::FuturesUnordered;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::db::{Status, Version, WebDb};
use super::site::Site;
use crate::blobs::BlobStore;
use crate::hash::BlobHash;
use crate::mime::is_compressible;
use crate::nostr::Event;
use crate::nostr::service::{NostrSource, blob_url, dedupe};
use crate::nsite::{NsiteAddress, manifest_paths};

/// Blobs downloaded in parallel.
const BLOB_CONCURRENCY: usize = 4;

/// Blobs in a row no server could supply before a deploy stops trying the
/// rest. Every attempt at a server that doesn't answer can take the download
/// timeout, so a version whose servers are all dead would otherwise take hours
/// to fail.
const MAX_FAILURES_IN_A_ROW: usize = 16;

/// Attempts at one version before waiting for the next resync.
const DEPLOY_ATTEMPTS: u32 = 3;

/// Most files one version may list.
const MAX_SITE_FILES: usize = 50_000;

pub struct SyncSettings {
    pub auto_update: bool,
    pub resync_interval: Duration,
    pub max_file_size: u64,
    pub max_site_size: u64,
    /// Versions kept, the served one included, and merged beneath it.
    pub keep_versions: usize,
    /// Wait before a second attempt at a failed deploy. It doubles after that.
    pub retry_backoff: Duration,
}

pub struct SyncWorker {
    pub address: NsiteAddress,
    pub db: WebDb,
    pub blobs: BlobStore,
    pub nostr: Arc<dyn NostrSource>,
    pub settings: SyncSettings,
    /// What the web service serves; swapped when a version goes live.
    pub live: Arc<ArcSwapOption<Site>>,
}

impl SyncWorker {
    /// Sync until `cancel` fires — or, with `auto_update` off, until a
    /// version is live.
    pub async fn run(self, cancel: CancellationToken) {
        let blobs = self.blobs.clone();
        // Temp files can only be leftovers from a download a crash interrupted.
        let _ = tokio::task::spawn_blocking(move || blobs.clear_temp()).await;

        let mut updates = if self.settings.auto_update {
            Some(self.nostr.subscribe(&self.address, cancel.clone()).await)
        } else {
            None
        };

        // The first tick is immediate: every start is a reason to look.
        let mut resync = tokio::time::interval(self.settings.resync_interval);
        resync.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut retry: Option<(Instant, u32)> = None;

        loop {
            if !self.settings.auto_update && self.live.load().is_some() {
                tracing::info!("auto_update is off, so the live version is kept");
                return;
            }

            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = resync.tick() => {
                    match self.nostr.fetch_manifest(&self.address, &cancel).await {
                        Some(event) => self.ingest(event).await,
                        None => tracing::warn!(naddr = self.address.naddr(), "no relay has the site's manifest"),
                    }
                    // A fresh run of attempts: whatever failed before may work now.
                    retry = None;
                }
                Some(event) = next_update(&mut updates) => {
                    self.ingest(event).await;
                    retry = None;
                }
                _ = sleep_until(retry.map(|(at, _)| at)) => {}
            }
            if cancel.is_cancelled() {
                return;
            }

            let attempt = retry.map_or(1, |(_, attempt)| attempt + 1);
            retry = match self.deploy_newest(&cancel).await {
                Ok(()) => None,
                Err(error) if cancel.is_cancelled() => {
                    tracing::info!(%error, "deploy interrupted by shutdown; it resumes on the next start");
                    return;
                }
                Err(error) if attempt < DEPLOY_ATTEMPTS => {
                    let wait = self.settings.retry_backoff * 2u32.pow(attempt - 1);
                    tracing::warn!(%error, attempt, wait_secs = wait.as_secs(), "deploy failed; retrying");
                    Some((Instant::now() + wait, attempt))
                }
                Err(error) => {
                    tracing::error!(%error, attempt, "deploy failed; the next resync tries again");
                    None
                }
            };
        }
    }

    async fn db<T: Send + 'static>(&self, f: impl FnOnce(&WebDb) -> Result<T> + Send + 'static) -> Result<T> {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db)).await?
    }

    /// Store a version of the site if it's one not seen before and newer
    /// than what's live.
    async fn ingest(&self, event: Event) {
        if !self.address.matches(&event) {
            return;
        }
        let live = self.db(|db| db.current()).await.ok().flatten();
        if live.is_some_and(|live| live.event.created_at >= event.created_at) {
            return;
        }

        let (id, created_at) = (event.id.clone(), event.created_at);
        match self.db(move |db| db.insert(&event)).await {
            Ok(true) => tracing::info!(event_id = id, created_at, "new version of the site"),
            Ok(false) => {}
            Err(error) => tracing::error!(%error, event_id = id, "could not store a version of the site"),
        }
    }

    /// Bring the newest known version live, if it isn't already.
    async fn deploy_newest(&self, cancel: &CancellationToken) -> Result<()> {
        let Some(newest) = self.db(|db| db.newest()).await? else { return Ok(()) };
        if self.live.load().as_ref().is_some_and(|site| site.event_id == newest.event.id) {
            return Ok(());
        }

        let id = newest.event.id.clone();
        match self.deploy(&newest, cancel).await {
            Ok(()) => Ok(()),
            Err(error) if cancel.is_cancelled() => Err(error),
            Err(error) => {
                let message = error.to_string();
                self.db(move |db| db.set_status(&id, Status::Failed, Some(&message))).await?;
                Err(error)
            }
        }
    }

    async fn deploy(&self, version: &Version, cancel: &CancellationToken) -> Result<()> {
        let event = &version.event;
        let files = manifest_paths(event);
        if files.len() > MAX_SITE_FILES {
            anyhow::bail!("This version lists {} files, more than the {MAX_SITE_FILES} a site may have.", files.len());
        }

        // Whether a blob is worth compressing is a question about the file it
        // is served as, which the store, keyed by hash, can't answer.
        let compressible: HashSet<BlobHash> = files.iter().filter(|(path, _)| is_compressible(path)).map(|(_, sha)| *sha).collect();
        let hashes = dedupe(files.values().copied());

        let blobs = self.blobs.clone();
        let all = hashes.clone();
        let (present, stored) = tokio::task::spawn_blocking(move || {
            let sizes: Vec<(BlobHash, Option<u64>)> = all.into_iter().map(|sha| (sha, blobs.size(sha))).collect();
            let stored: u64 = sizes.iter().filter_map(|(_, size)| *size).sum();
            (sizes, stored)
        })
        .await?;
        let missing: Vec<BlobHash> = present.iter().filter(|(_, size)| size.is_none()).map(|(sha, _)| *sha).collect();

        tracing::info!(event_id = event.id, files = files.len(), blobs = hashes.len(), missing = missing.len(), "deploying");

        // Already on disk, perhaps from an interrupted deploy, but not
        // necessarily compressed.
        for (sha256, _) in present.iter().filter(|(sha, size)| size.is_some() && compressible.contains(sha)) {
            self.compress(*sha256).await;
        }

        let max_size = self.settings.max_site_size;
        if stored > max_size {
            anyhow::bail!(oversized(max_size));
        }

        if !missing.is_empty() {
            let servers = self.nostr.blob_sources(event, cancel).await;
            if servers.is_empty() {
                anyhow::bail!("No Blossom servers to download from: the manifest names none, and its author has no kind 10063 list.");
            }
            self.download_all(missing, &servers, &compressible, max_size - stored, cancel).await?;
        }

        let (id, keep) = (event.id.clone(), self.settings.keep_versions);
        let earlier: Vec<Event> = self.db(move |db| db.chain(&id, keep)).await?.into_iter().skip(1).map(|version| version.event).collect();
        let blobs = self.blobs.clone();
        let manifest = event.clone();
        let site = tokio::task::spawn_blocking(move || Site::load(&manifest, &earlier, &blobs))
            .await?
            .map_err(|sha| anyhow::anyhow!("Blob {sha} went missing from storage during the deploy."))?;

        let id = event.id.clone();
        self.db(move |db| db.promote(&id, keep)).await?;
        self.live.store(Some(Arc::new(site)));
        tracing::info!(event_id = event.id, created_at = event.created_at, "version live");
        Ok(())
    }

    /// Download missing blobs with bounded concurrency. Nothing new starts
    /// once the downloads pass `budget` bytes — a manifest doesn't say how big
    /// its blobs are, so the limit is found by crossing it — nor once
    /// [`MAX_FAILURES_IN_A_ROW`] blobs have failed with none succeeding.
    async fn download_all(
        &self,
        missing: Vec<BlobHash>,
        servers: &[String],
        compressible: &HashSet<BlobHash>,
        budget: u64,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let total = missing.len();
        let mut queue = missing.into_iter();
        let mut downloading = FuturesUnordered::new();
        let (mut failed, mut bytes, mut done, mut in_a_row) = (Vec::new(), 0u64, 0usize, 0usize);

        loop {
            while downloading.len() < BLOB_CONCURRENCY && !cancel.is_cancelled() && bytes <= budget && in_a_row < MAX_FAILURES_IN_A_ROW {
                let Some(sha256) = queue.next() else { break };
                let compress = compressible.contains(&sha256);
                downloading.push(async move { (sha256, self.download_blob(sha256, servers, compress, cancel).await) });
            }
            let Some((sha256, size)) = downloading.next().await else { break };
            match size {
                Some(size) => {
                    bytes += size;
                    done += 1;
                    in_a_row = 0;
                    if done % 50 == 0 {
                        tracing::info!(done, total, "downloading blobs");
                    }
                }
                None => {
                    in_a_row += 1;
                    failed.push(sha256);
                }
            }
        }

        if cancel.is_cancelled() {
            anyhow::bail!("Interrupted with {} blobs still to download.", total - done);
        }
        if bytes > budget {
            anyhow::bail!(oversized(self.settings.max_site_size));
        }
        if !failed.is_empty() {
            let sample = failed.iter().take(3).map(BlobHash::to_string).collect::<Vec<_>>().join(", ");
            anyhow::bail!(
                "{} of {total} blobs could not be downloaded from {} server(s): {sample}{}",
                failed.len() + queue.count(),
                servers.len(),
                if failed.len() > 3 { ", …" } else { "" }
            );
        }
        Ok(())
    }

    /// Try each server in turn for one blob. Returns its size, or `None` if no
    /// server had it.
    async fn download_blob(&self, sha256: BlobHash, servers: &[String], compress: bool, cancel: &CancellationToken) -> Option<u64> {
        for server in servers {
            let url = blob_url(server, sha256.hex().as_str());
            match self.blobs.download(&url, sha256, self.settings.max_file_size, cancel).await {
                Ok(size) => {
                    tracing::debug!(%sha256, server, size, "blob downloaded");
                    if compress {
                        self.compress(sha256).await;
                    }
                    return Some(size);
                }
                Err(error) => {
                    tracing::debug!(%sha256, server, reason = error.reason.as_str(), status = error.status, %error, "blob download failed");
                }
            }
        }
        tracing::warn!(%sha256, servers = servers.len(), "no server had the blob");
        None
    }

    /// Store compressed copies of a blob. Never fatal: a site served
    /// uncompressed is a slower site rather than a broken one.
    async fn compress(&self, sha256: BlobHash) {
        let blobs = self.blobs.clone();
        match tokio::task::spawn_blocking(move || blobs.ensure_variants(sha256)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(%sha256, %error, "could not compress a blob"),
            Err(error) => tracing::warn!(%sha256, %error, "could not compress a blob"),
        }
    }
}

fn oversized(limit: u64) -> String {
    format!("This version is larger than web.max_site_size ({} MiB).", limit >> 20)
}

async fn next_update(updates: &mut Option<mpsc::Receiver<Event>>) -> Option<Event> {
    match updates {
        Some(updates) => updates.recv().await,
        None => std::future::pending().await,
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}
