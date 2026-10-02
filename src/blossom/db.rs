//! The Blossom server's LMDB: which blobs it holds, and who uploaded each.
//!
//! Deliberately little. A blob's record is its size and the day it was
//! first uploaded — not the hour, not a type, not a name. Owners are kept
//! only because deleting needs them, as bare (blob, pubkey) pairs.

use anyhow::Result;
use heed::types::{Bytes, SerdeJson, Unit};
use heed::{Database, Env, WithoutTls};
use serde::{Deserialize, Serialize};

use crate::hash::BlobHash;
use crate::storage::Storage;

/// Address space reserved for the database. A blob is a few dozen bytes
/// here, so this is room for tens of millions.
const MAP_SIZE: usize = 4 << 30;

const DAY: i64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub size: u64,
    /// The start of the day, UTC, it was first uploaded.
    pub uploaded: i64,
}

/// What removing an owner left behind.
#[derive(Debug, PartialEq, Eq)]
pub enum Removal {
    /// They didn't own it, or it isn't here.
    NotOwner,
    /// Others still own it.
    Kept,
    /// That was the last owner: the record is gone, and the bytes should go.
    Gone,
}

#[derive(Clone)]
pub struct BlossomDb {
    env: Env<WithoutTls>,
    /// Blob hash → record.
    blobs: Database<Bytes, SerdeJson<Record>>,
    /// Blob hash ‖ owner pubkey, both raw → nothing.
    owners: Database<Bytes, Unit>,
}

impl BlossomDb {
    pub fn open(storage: &Storage) -> Result<BlossomDb> {
        let env = storage.env("blossom", MAP_SIZE, 4)?;
        let mut txn = env.write_txn()?;
        let blobs = env.create_database(&mut txn, Some("blobs"))?;
        let owners = env.create_database(&mut txn, Some("owners"))?;
        txn.commit()?;
        Ok(BlossomDb { env, blobs, owners })
    }

    pub fn get(&self, sha256: BlobHash) -> Result<Option<Record>> {
        let txn = self.env.read_txn()?;
        Ok(self.blobs.get(&txn, sha256.as_bytes())?)
    }

    /// Record that `pubkey` uploaded a blob. Returns its record, and whether
    /// the blob is new to the server.
    pub fn add(&self, sha256: BlobHash, size: u64, pubkey: &str, now: i64) -> Result<(Record, bool)> {
        let owner = owner_key(sha256, pubkey)?;
        let mut txn = self.env.write_txn()?;
        let (record, new) = match self.blobs.get(&txn, sha256.as_bytes())? {
            Some(record) => (record, false),
            None => {
                let record = Record { size, uploaded: now - now.rem_euclid(DAY) };
                self.blobs.put(&mut txn, sha256.as_bytes(), &record)?;
                (record, true)
            }
        };
        self.owners.put(&mut txn, &owner, &())?;
        txn.commit()?;
        Ok((record, new))
    }

    /// Remove `pubkey` as an owner of a blob, and the blob's record with its
    /// last owner.
    pub fn remove_owner(&self, sha256: BlobHash, pubkey: &str) -> Result<Removal> {
        let Ok(owner) = owner_key(sha256, pubkey) else { return Ok(Removal::NotOwner) };
        let mut txn = self.env.write_txn()?;
        if !self.owners.delete(&mut txn, &owner)? {
            return Ok(Removal::NotOwner);
        }
        let others = self.owners.prefix_iter(&txn, sha256.as_bytes())?.next().is_some();
        if !others {
            self.blobs.delete(&mut txn, sha256.as_bytes())?;
        }
        txn.commit()?;
        Ok(if others { Removal::Kept } else { Removal::Gone })
    }
}

fn owner_key(sha256: BlobHash, pubkey: &str) -> Result<[u8; 64]> {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(sha256.as_bytes());
    hex::decode_to_slice(pubkey, &mut key[32..])?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "aa00000000000000000000000000000000000000000000000000000000000000";
    const BOB: &str = "bb00000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn tracks_owners_until_the_last_one_goes() {
        let dir = tempfile::tempdir().unwrap();
        let db = BlossomDb::open(&Storage::allowing_private(dir.path())).unwrap();
        let sha = BlobHash::of(b"one");
        let other = BlobHash::of(b"two");

        assert_eq!(db.get(sha).unwrap(), None);
        let (record, new) = db.add(sha, 10, ALICE, DAY * 3 + 5000).unwrap();
        assert!(new);
        assert_eq!(record, Record { size: 10, uploaded: DAY * 3 });
        assert!(!db.add(sha, 10, BOB, DAY * 9).unwrap().1);
        assert_eq!(db.get(sha).unwrap().unwrap().uploaded, DAY * 3);
        db.add(other, 5, ALICE, 0).unwrap();

        assert_eq!(db.remove_owner(sha, "not hex").unwrap(), Removal::NotOwner);
        assert_eq!(db.remove_owner(other, BOB).unwrap(), Removal::NotOwner);
        assert_eq!(db.remove_owner(sha, ALICE).unwrap(), Removal::Kept);
        assert_eq!(db.remove_owner(sha, ALICE).unwrap(), Removal::NotOwner);
        assert!(db.get(sha).unwrap().is_some());
        assert_eq!(db.remove_owner(sha, BOB).unwrap(), Removal::Gone);
        assert_eq!(db.get(sha).unwrap(), None);
        // The neighbor is untouched.
        assert!(db.get(other).unwrap().is_some());
    }
}
