//! Deleting the site's blobs that nothing kept uses any more.
//!
//! Run by the sync worker once a version goes live, so it never runs beside
//! a deploy: the worker does one thing at a time. A blob is in use while any
//! version still in the database names it, whatever that version's state —
//! a failed deploy keeps what it got, for its next attempt — or while the
//! live site serves it, which covers the pages with the env script added,
//! stored under hashes of their own.
//!
//! Blobs written within [`GRACE`] are left alone whatever, which is what
//! keeps a request still answering from the site just replaced from losing
//! its page, and makes the rule safe to change without thinking about
//! everything that writes to the store.

use std::collections::HashSet;
use std::time::{Duration, SystemTime};

use anyhow::Result;

use super::db::WebDb;
use super::site::Site;
use crate::blobs::BlobStore;
use crate::hash::BlobHash;
use crate::nsite::manifest_paths;

/// How old an unused blob has to be to go.
pub const GRACE: Duration = Duration::from_secs(60 * 60);

/// What a prune deleted.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub blobs: usize,
    pub bytes: u64,
}

/// Delete every blob nothing kept uses and older than [`GRACE`] at `now`.
/// Blocking.
pub fn prune(db: &WebDb, blobs: &BlobStore, live: &Site, now: SystemTime) -> Result<Pruned> {
    let mut used: HashSet<BlobHash> = live.files.values().map(|file| file.sha256).collect();
    for version in db.all()? {
        used.extend(manifest_paths(&version.event).into_values());
    }

    let mut pruned = Pruned::default();
    for (sha256, written) in blobs.list()? {
        if used.contains(&sha256) || now.duration_since(written).unwrap_or_default() < GRACE {
            continue;
        }
        let size = blobs.variants(sha256).map_or(0, |variants| variants.identity + variants.br.unwrap_or(0) + variants.gzip.unwrap_or(0));
        blobs.remove(sha256)?;
        pruned.blobs += 1;
        pruned.bytes += size;
    }
    Ok(pruned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Event;
    use crate::storage::Storage;

    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn deletes_only_old_blobs_nothing_uses() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::allowing_private(dir.path());
        let (db, blobs) = (WebDb::open(&storage).unwrap(), storage.blobs.clone());
        let put = |content: &str| {
            let sha256 = BlobHash::of(content.as_bytes());
            blobs.put(sha256, content.as_bytes()).unwrap();
            sha256
        };
        let manifest = |created_at, paths: &[(&str, BlobHash)]| {
            let tags = paths.iter().map(|(path, sha256)| vec!["path".to_string(), path.to_string(), sha256.to_string()]).collect();
            Event::sign(SECRET, created_at, 15128, tags, "")
        };

        let (gone, old, kept, page, stray) = (put("gone"), put("old"), put("kept"), put("<html><head></head></html>"), put("stray"));
        blobs.ensure_variants(gone).unwrap();
        let first = manifest(100, &[("/assets/gone.js", gone)]);
        let second = manifest(200, &[("/assets/old.js", old)]);
        let third = manifest(300, &[("/index.html", page), ("/assets/kept.js", kept)]);
        for version in [&first, &second, &third] {
            db.insert(version).unwrap();
            db.promote(&version.id, 2).unwrap();
        }
        let live = Site::load(&third, &[second.clone()], &blobs).unwrap();
        let injected = live.files["/index.html"].sha256;
        assert_ne!(injected, page);

        // Nothing is old enough yet.
        assert_eq!(prune(&db, &blobs, &live, SystemTime::now()).unwrap(), Pruned::default());

        let later = SystemTime::now() + GRACE + Duration::from_secs(1);
        let pruned = prune(&db, &blobs, &live, later).unwrap();
        assert_eq!(pruned.blobs, 2, "the first version's blob and the one nothing named");
        assert!(blobs.size(gone).is_none());
        assert!(blobs.size(stray).is_none());
        for sha256 in [old, kept, page, injected] {
            assert!(blobs.size(sha256).is_some(), "{sha256}");
        }
        assert_eq!(pruned.bytes, 9);
    }
}
