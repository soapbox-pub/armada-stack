//! The web service's LMDB: every version of the site it knows of, and which
//! one it serves.
//!
//! Tiny by design. The served version's file map is rebuilt from its manifest
//! at startup and held in memory, so a request never reads the database.

use anyhow::Result;
use heed::types::{SerdeJson, Str};
use heed::{Database, Env, WithoutTls};
use serde::{Deserialize, Serialize};

use crate::nostr::Event;
use crate::storage::Storage;

/// Address space reserved for the database. A version is one manifest event,
/// and old ones are dropped as new ones go live.
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

    /// Make a version the one served, and forget every older one: nothing
    /// will ever serve them again.
    pub fn promote(&self, event_id: &str) -> Result<()> {
        let mut txn = self.env.write_txn()?;
        let Some(mut version) = self.versions.get(&txn, event_id)? else { return Ok(()) };
        version.status = Status::Ready;
        version.error = None;
        version.ready_at = Some(crate::util::now());
        self.versions.put(&mut txn, event_id, &version)?;
        self.meta.put(&mut txn, CURRENT, event_id)?;

        let older: Vec<String> = self
            .versions
            .iter(&txn)?
            .filter_map(|entry| entry.ok())
            .filter(|(_, other)| other.event.created_at < version.event.created_at)
            .map(|(id, _)| id.to_string())
            .collect();
        for id in older {
            self.versions.delete(&mut txn, &id)?;
        }

        txn.commit()?;
        Ok(())
    }
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
        db.promote(&old.id).unwrap();
        assert_eq!(db.current().unwrap().unwrap().event.id, old.id);

        assert!(db.insert(&new).unwrap());
        assert_eq!(db.newest().unwrap().unwrap().event.id, new.id);
        db.set_status(&new.id, Status::Failed, Some("nope")).unwrap();
        assert_eq!(db.get(&new.id).unwrap().unwrap().error.as_deref(), Some("nope"));
        assert_eq!(db.current().unwrap().unwrap().event.id, old.id);

        db.promote(&new.id).unwrap();
        let current = db.current().unwrap().unwrap();
        assert_eq!((current.event.id.as_str(), current.status, current.error), (new.id.as_str(), Status::Ready, None));
        assert!(db.get(&old.id).unwrap().is_none());
    }
}
