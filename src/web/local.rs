//! The web app from a directory on this machine, `web.dir`, in place of the
//! nsite: a build of Armada's own, say, or one being worked on.
//!
//! The directory's files are copied into the site's blob store and served
//! from there like any version from Nostr, with the env script added to
//! its pages and compressed copies made of what compresses. With
//! `auto_update` on, the directory is looked at every [`POLL`], and a change
//! goes live once it has held still for a look, so a build caught halfway
//! isn't served. What the previous load used is pruned as a deploy's would be.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use arc_swap::ArcSwapOption;
use tokio_util::sync::CancellationToken;

use super::db::WebDb;
use super::progress::{Progress, Stage};
use super::prune::prune;
use super::site::{File, Site};
use crate::blobs::BlobStore;
use crate::hash::BlobHash;
use crate::mime::is_compressible;

/// How often the directory is looked at for changes.
pub const POLL: Duration = Duration::from_secs(2);

/// Most files the directory may hold, as for a version from Nostr.
const MAX_SITE_FILES: usize = 50_000;

/// How deep directories are followed, so a link back up can't go on forever.
const MAX_DEPTH: usize = 32;

/// One file in the directory, as a look at its metadata finds it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Entry {
    /// Where the site serves it.
    path: String,
    source: PathBuf,
    len: u64,
    modified: SystemTime,
}

pub struct Limits {
    pub max_file_size: u64,
    pub max_site_size: u64,
}

pub struct LocalWorker {
    pub dir: PathBuf,
    pub watch: bool,
    /// How often it's looked at: [`POLL`], but for tests.
    pub poll: Duration,
    pub limits: Limits,
    pub db: WebDb,
    pub blobs: BlobStore,
    pub live: Arc<ArcSwapOption<Site>>,
    pub progress: Arc<Progress>,
}

impl LocalWorker {
    /// Load the directory, then, while watching, again each time it changes,
    /// until `cancel` fires.
    pub async fn run(self, cancel: CancellationToken) {
        let blobs = self.blobs.clone();
        let _ = tokio::task::spawn_blocking(move || blobs.clear_temp()).await;

        // What each file was found to be, by where it is and how it looked,
        // so a reload reads only what changed.
        let mut known: HashMap<Entry, File> = HashMap::new();
        let mut loaded: Option<Vec<Entry>> = None;
        let mut settling: Option<Vec<Entry>> = None;
        let mut failing = false;

        loop {
            let found = self.scan().await;
            match found {
                Err(error) => {
                    if !failing {
                        tracing::warn!(dir = %self.dir.display(), "web.dir: {error:#}");
                        failing = true;
                    }
                    if self.live.load().is_none() {
                        self.progress.set(Stage::Failed);
                    }
                }
                Ok(entries) if loaded.as_ref() == Some(&entries) => {
                    failing = false;
                    settling = None;
                }
                // Changed since the last look: wait for it to hold still,
                // except the first time, when there's nothing else to serve.
                Ok(entries) if loaded.is_some() && settling.as_ref() != Some(&entries) => {
                    failing = false;
                    settling = Some(entries);
                }
                Ok(entries) => {
                    failing = false;
                    settling = None;
                    match self.load(&entries, &mut known).await {
                        Ok(()) => {}
                        Err(error) => tracing::error!(dir = %self.dir.display(), "web.dir: could not load the site: {error:#}"),
                    }
                    // Not tried again until it changes, whether or not it loaded.
                    loaded = Some(entries);
                }
            }

            if !self.watch && self.live.load().is_some() {
                tracing::info!("auto_update is off, so web.dir isn't watched for changes");
                return;
            }
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(self.poll) => {}
            }
        }
    }

    async fn scan(&self) -> Result<Vec<Entry>> {
        let dir = self.dir.clone();
        let entries = tokio::task::spawn_blocking(move || scan(&dir)).await??;
        if entries.is_empty() {
            bail!("{} has no files in it.", self.dir.display());
        }
        if entries.len() > MAX_SITE_FILES {
            bail!("{} has {} files, more than the {MAX_SITE_FILES} a site may have.", self.dir.display(), entries.len());
        }
        if let Some(entry) = entries.iter().find(|entry| entry.len > self.limits.max_file_size) {
            bail!("{} is larger than web.max_file_size ({} MiB).", entry.source.display(), self.limits.max_file_size >> 20);
        }
        if entries.iter().map(|entry| entry.len).sum::<u64>() > self.limits.max_site_size {
            bail!("{} is larger than web.max_site_size ({} MiB).", self.dir.display(), self.limits.max_site_size >> 20);
        }
        Ok(entries)
    }

    /// Put `entries` live: stored, then served, then served compressed.
    async fn load(&self, entries: &[Entry], known: &mut HashMap<Entry, File>) -> Result<()> {
        if self.live.load().is_none() {
            self.progress.set(Stage::Downloading { done: 0, total: entries.len() });
        }
        let (blobs, list, mut cache, progress) = (self.blobs.clone(), entries.to_vec(), std::mem::take(known), self.progress.clone());
        let stored = tokio::task::spawn_blocking(move || {
            let result = store(&blobs, &list, &mut cache, &progress);
            (result, cache)
        })
        .await?;
        let (result, cache) = stored;
        // Only what's in the directory now is worth remembering.
        let present: HashSet<&Entry> = entries.iter().collect();
        *known = cache.into_iter().filter(|(entry, _)| present.contains(entry)).collect();
        let files = result?;

        let id = version_id(&files);
        let created_at = entries.iter().map(|entry| entry.modified).max().and_then(|time| time.duration_since(UNIX_EPOCH).ok()).map_or(0, |since| since.as_secs() as i64);
        let site = self.assemble(id.clone(), files.clone(), created_at).await?;
        self.live.store(Some(site.clone()));
        tracing::info!(dir = %self.dir.display(), version = id, files = files.len(), "web.dir live");

        // Compressed copies after, so a change shows up right away.
        let blobs = self.blobs.clone();
        let paths: Vec<(String, File)> = files.iter().map(|(path, file)| (path.clone(), *file)).collect();
        let compressed = tokio::task::spawn_blocking(move || {
            let mut any = false;
            let mut files = HashMap::new();
            for (path, mut file) in paths {
                if is_compressible(&path) {
                    match blobs.ensure_variants(file.sha256) {
                        Ok(written) => any |= !written.is_empty(),
                        Err(error) => tracing::warn!(%path, %error, "could not compress a file"),
                    }
                    file.variants = blobs.variants(file.sha256).unwrap_or(file.variants);
                }
                files.insert(path, file);
            }
            (any, files)
        })
        .await?;
        let (any, compressed) = compressed;
        for (entry, file) in known.iter_mut() {
            if let Some(updated) = compressed.get(&entry.path) {
                *file = *updated;
            }
        }
        let mut site = site;
        if any {
            site = self.assemble(id, compressed, created_at).await?;
            self.live.store(Some(site.clone()));
        }

        let (db, blobs) = (self.db.clone(), self.blobs.clone());
        match tokio::task::spawn_blocking(move || prune(&db, &blobs, &site, SystemTime::now())).await? {
            Ok(pruned) if pruned.blobs > 0 => tracing::info!(blobs = pruned.blobs, bytes = pruned.bytes, "pruned blobs nothing uses"),
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "could not prune blobs"),
        }
        Ok(())
    }

    async fn assemble(&self, id: String, files: HashMap<String, File>, created_at: i64) -> Result<Arc<Site>> {
        let blobs = self.blobs.clone();
        Ok(Arc::new(tokio::task::spawn_blocking(move || Site::assemble(id, files, created_at, &blobs)).await?))
    }
}

/// Every file beneath `dir`, by site path. Links are followed, to files and
/// to directories, [`MAX_DEPTH`] deep at most. Blocking.
fn scan(dir: &Path) -> Result<Vec<Entry>> {
    let metadata = std::fs::metadata(dir).with_context(|| format!("Could not read {}", dir.display()))?;
    if !metadata.is_dir() {
        bail!("{} isn't a directory.", dir.display());
    }
    let mut entries = Vec::new();
    walk(dir, "", 0, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn walk(dir: &Path, prefix: &str, depth: usize, entries: &mut Vec<Entry>) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("{} is more than {MAX_DEPTH} directories deep; is there a link to a directory above it?", dir.display());
    }
    for item in std::fs::read_dir(dir).with_context(|| format!("Could not read {}", dir.display()))? {
        let item = item?;
        let source = item.path();
        let Some(name) = item.file_name().to_str().map(str::to_string) else {
            tracing::warn!(path = %source.display(), "web.dir: skipping a file whose name isn't UTF-8");
            continue;
        };
        // Followed through links; one that leads nowhere is skipped.
        let Ok(metadata) = std::fs::metadata(&source) else { continue };
        let path = format!("{prefix}/{name}");
        if metadata.is_dir() {
            walk(&source, &path, depth + 1, entries)?;
        } else if metadata.is_file() {
            entries.push(Entry { path, source, len: metadata.len(), modified: metadata.modified()? });
        }
    }
    Ok(())
}

/// Store every file `entries` lists, reading only those `known` hasn't seen
/// as they are now. Blocking.
fn store(blobs: &BlobStore, entries: &[Entry], known: &mut HashMap<Entry, File>, progress: &Progress) -> Result<HashMap<String, File>> {
    let mut files = HashMap::with_capacity(entries.len());
    for entry in entries {
        let file = match known.get(entry).filter(|file| blobs.size(file.sha256).is_some()) {
            Some(file) => *file,
            None => {
                let bytes = std::fs::read(&entry.source).with_context(|| format!("Could not read {}", entry.source.display()))?;
                let sha256 = BlobHash::of(&bytes);
                if blobs.size(sha256).is_none() {
                    blobs.put(sha256, &bytes)?;
                }
                let variants = blobs.variants(sha256).context("a file went missing from the store as it was stored")?;
                let file = File { sha256, variants };
                known.insert(entry.clone(), file);
                file
            }
        };
        progress.downloaded_one();
        files.insert(entry.path.clone(), file);
    }
    Ok(files)
}

/// A short name for one load of the directory, the same for the same files.
fn version_id(files: &HashMap<String, File>) -> String {
    let mut listing: Vec<(&String, BlobHash)> = files.iter().map(|(path, file)| (path, file.sha256)).collect();
    listing.sort();
    let text: String = listing.iter().map(|(path, sha256)| format!("{path}\0{sha256}\n")).collect();
    BlobHash::of(text.as_bytes()).to_string()[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_beneath_the_root() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("assets/deep")).unwrap();
        std::fs::write(dir.path().join("index.html"), "<html></html>").unwrap();
        std::fs::write(dir.path().join("assets/deep/a.js"), "1").unwrap();
        std::fs::write(dir.path().join(".nojekyll"), "").unwrap();
        let paths: Vec<String> = scan(dir.path()).unwrap().into_iter().map(|entry| entry.path).collect();
        assert_eq!(paths, ["/.nojekyll", "/assets/deep/a.js", "/index.html"]);
        assert!(scan(&dir.path().join("index.html")).is_err());
        assert!(scan(&dir.path().join("missing")).is_err());
    }
}
