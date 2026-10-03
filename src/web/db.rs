//! The web service's LMDB: the versions of the site it keeps, and which one
//! it serves.
//!
//! Tiny by design. The served version's file map, with the earlier versions
//! merged beneath it, is rebuilt from their manifests at startup and held in
//! memory, so a request never reads the database.

use anyhow::Result;
use heed::types::{SerdeJson, Str};
use heed::{Database, Env, WithoutTls};
use serde::{Deserialize, Serialize};

use crate::nostr::Event;
use crate::storage::Storage;

/// Address space reserved for the database. A version is one manifest event,
/// and only `keep_versions` of them are kept.
const MAP_SIZE: usize = 1 << 30;

/// The `meta` key naming the served version's event id.
const CURRENT: &str = "current";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Stored, and not yet (fully) downloaded.
    Pending,
    /// Every blob is on disk.
    Ready,
    /// The last attempt failed; `error` says why.
    Failed,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Version {
    pub event: Event,
    pub status: Status,
    pub error: Option<String>,
    pub fetched_at: i64,
    pub ready_at: Option<i64>,
}

#[derive(Clone)]
pub struct WebDb {
    env: Env<WithoutTls>,
    /// Event id → version.
    versions: Database<Str, SerdeJson<Version>>,
    meta: Database<Str, Str>,
}

impl WebDb {
    pub fn open(storage: &Storage) -> Result<WebDb> {
        let env = storage.env("web", MAP_SIZE, 4)?;
        let mut txn = env.write_txn()?;
        let versions = env.create_database(&mut txn, Some("versions"))?;
        let meta = env.create_database(&mut txn, Some("meta"))?;
        txn.commit()?;
        Ok(WebDb { env, versions, meta })
    }

    #[cfg(test)]
    pub fn get(&self, event_id: &str) -> Result<Option<Version>> {
        let txn = self.env.read_txn()?;
        Ok(self.versions.get(&txn, event_id)?)
    }

    /// The version being served, if one has gone live.
    pub fn current(&self) -> Result<Option<Version>> {
        let txn = self.env.read_txn()?;
        let Some(id) = self.meta.get(&txn, CURRENT)? else { return Ok(None) };
        Ok(self.versions.get(&txn, id)?)
    }

    /// The newest version known, whatever its status. The first stored wins
    /// a tie, as relays settle one.
    pub fn newest(&self) -> Result<Option<Version>> {
        let txn = self.env.read_txn()?;
        let mut newest: Option<Version> = None;
        for entry in self.versions.iter(&txn)? {
            let (_, version) = entry?;
            if newest.as_ref().is_none_or(|n| (version.event.created_at, version.fetched_at) > (n.event.created_at, n.fetched_at)) {
                newest = Some(version);
            }
        }
        Ok(newest)
    }

    /// Store a version not seen before. Returns whether it was new.
    pub fn insert(&self, event: &Event) -> Result<bool> {
        let mut txn = self.env.write_txn()?;
        if self.versions.get(&txn, &event.id)?.is_some() {
            return Ok(false);
        }
        let version = Version { event: event.clone(), status: Status::Pending, error: None, fetched_at: crate::util::now(), ready_at: None };
        self.versions.put(&mut txn, &event.id, &version)?;
        txn.commit()?;
        Ok(true)
    }

    pub fn set_status(&self, event_id: &str, status: Status, error: Option<&str>) -> Result<()> {
        let mut txn = self.env.write_txn()?;
        if let Some(mut version) = self.versions.get(&txn, event_id)? {
            version.status = status;
            version.error = error.map(str::to_string);
            self.versions.put(&mut txn, event_id, &version)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// A version and up to `keep - 1` ready versions before it, newest
    /// first: the order a path is looked for in when it's served. Nothing
    /// newer, and nothing not ready, whose blobs may not all be on disk.
    pub fn chain(&self, event_id: &str, keep: usize) -> Result<Vec<Version>> {
        let txn = self.env.read_txn()?;
        let Some(current) = self.versions.get(&txn, event_id)? else { return Ok(Vec::new()) };
        let mut older: Vec<Version> = self
            .versions
            .iter(&txn)?
            .filter_map(|entry| entry.ok())
            .map(|(_, version)| version)
            .filter(|version| version.status == Status::Ready && version.event.id != current.event.id && version.event.created_at <= current.event.created_at)
            .collect();
        older.sort_by(newest_first);
        older.truncate(keep.saturating_sub(1));
        Ok(std::iter::once(current).chain(older).collect())
    }

    /// Every version kept, in any state.
    pub fn all(&self) -> Result<Vec<Version>> {
        let txn = self.env.read_txn()?;
        Ok(self.versions.iter(&txn)?.filter_map(|entry| entry.ok()).map(|(_, version)| version).collect())
    }

    /// Make a version the one served, keeping it and the `keep - 1` ready
    /// versions before it. Older ready versions go, and so does anything
    /// older that never got ready: only the newest is ever deployed, so it
    /// never will be. Anything newer may still be deploying, and stays.
    pub fn promote(&self, event_id: &str, keep: usize) -> Result<()> {
        let mut txn = self.env.write_txn()?;
        let Some(mut version) = self.versions.get(&txn, event_id)? else { return Ok(()) };
        version.status = Status::Ready;
        version.error = None;
        version.ready_at = Some(crate::util::now());
        self.versions.put(&mut txn, event_id, &version)?;
        self.meta.put(&mut txn, CURRENT, event_id)?;

        let mut older: Vec<Version> = self
            .versions
            .iter(&txn)?
            .filter_map(|entry| entry.ok())
            .map(|(_, other)| other)
            .filter(|other| other.event.id != version.event.id && other.event.created_at <= version.event.created_at)
            .collect();
        older.sort_by(newest_first);
        let mut ready = 1;
        let mut forget = Vec::new();
        for other in older {
            if other.status == Status::Ready && ready < keep {
                ready += 1;
            } else {
                forget.push(other.event.id);
            }
        }
        for id in forget {
            self.versions.delete(&mut txn, &id)?;
        }

        txn.commit()?;
        Ok(())
    }
}

/// Newest first, by when the author published it, then by when it was seen,
/// as [`WebDb::newest`] settles a tie.
fn newest_first(a: &Version, b: &Version) -> std::cmp::Ordering {
    (b.event.created_at, b.fetched_at).cmp(&(a.event.created_at, a.fetched_at))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn keeps_versions_until_a_newer_one_goes_live() {
        let dir = tempfile::tempdir().unwrap();
        let db = WebDb::open(&Storage::allowing_private(dir.path())).unwrap();
        let old = Event::sign(SECRET, 100, 15128, vec![], "");
        let new = Event::sign(SECRET, 200, 15128, vec![], "");

        assert!(db.current().unwrap().is_none());
        assert!(db.insert(&old).unwrap());
        assert!(!db.insert(&old).unwrap());
        db.promote(&old.id, 1).unwrap();
        assert_eq!(db.current().unwrap().unwrap().event.id, old.id);

        assert!(db.insert(&new).unwrap());
        assert_eq!(db.newest().unwrap().unwrap().event.id, new.id);
        db.set_status(&new.id, Status::Failed, Some("nope")).unwrap();
        assert_eq!(db.get(&new.id).unwrap().unwrap().error.as_deref(), Some("nope"));
        assert_eq!(db.current().unwrap().unwrap().event.id, old.id);

        db.promote(&new.id, 1).unwrap();
        let current = db.current().unwrap().unwrap();
        assert_eq!((current.event.id.as_str(), current.status, current.error), (new.id.as_str(), Status::Ready, None));
        assert!(db.get(&old.id).unwrap().is_none());
    }

    #[test]
    fn keeps_the_newest_ready_versions() {
        let dir = tempfile::tempdir().unwrap();
        let db = WebDb::open(&Storage::allowing_private(dir.path())).unwrap();
        let at = |created_at| Event::sign(SECRET, created_at, 15128, vec![], "");
        let (a, b, c, d, e) = (at(100), at(200), at(300), at(400), at(500));
        assert!(db.chain(&a.id, 3).unwrap().is_empty());

        for version in [&a, &b] {
            db.insert(version).unwrap();
            db.promote(&version.id, 3).unwrap();
        }
        // Never ready, and older than what goes live next: it never will be.
        db.insert(&c).unwrap();
        db.set_status(&c.id, Status::Failed, Some("nope")).unwrap();
        db.insert(&d).unwrap();
        // Newer than what goes live, so perhaps still deploying.
        db.insert(&e).unwrap();
        db.promote(&d.id, 3).unwrap();

        let ids = |versions: Vec<Version>| versions.into_iter().map(|version| version.event.id).collect::<Vec<_>>();
        assert_eq!(ids(db.chain(&d.id, 3).unwrap()), [d.id.clone(), b.id.clone(), a.id.clone()]);
        assert_eq!(ids(db.chain(&d.id, 2).unwrap()), [d.id.clone(), b.id.clone()]);
        assert!(db.get(&c.id).unwrap().is_none());
        assert!(db.get(&e.id).unwrap().is_some());
        assert_eq!(db.all().unwrap().len(), 4);

        // A tighter cap forgets the oldest.
        db.promote(&d.id, 2).unwrap();
        assert!(db.get(&a.id).unwrap().is_none());
        assert_eq!(ids(db.chain(&d.id, 60).unwrap()), [d.id.clone(), b.id.clone()]);
    }
}
