//! The Blossom server's LMDB: which blobs it holds, and who uploaded each.
//!
//! Deliberately little. A blob's record is its size, the day it was first
//! uploaded, and the day it's due to expire, if it is — not the hour, not a
//! type, not a name. Owners are kept only because deleting needs them, as
//! (blob, pubkey) pairs, each with the day its claim runs out, if it does.
//!
//! An owner may ask for its claim to expire. A blob expires only once every
//! owner's has: when the latest of them passes, or never if any owner's
//! claim is for good. So one owner's disappearing attachment can't take the
//! same bytes from another who keeps them as an avatar.

use anyhow::Result;
use heed::types::{Bytes, SerdeJson, Unit};
use heed::{Database, Env, RwTxn, WithoutTls};
use serde::{Deserialize, Serialize};

use crate::hash::BlobHash;
use crate::storage::Storage;

/// Address space reserved for the database. A blob is a few dozen bytes
/// here, so this is room for tens of millions.
const MAP_SIZE: usize = 4 << 30;

pub const DAY: i64 = 86_400;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub size: u64,
    /// The start of the day, UTC, it was first uploaded.
    pub uploaded: i64,
    /// When it's due to go: the latest of its owners' expirations, or
    /// `None` if any owner keeps it for good.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<i64>,
}

impl Record {
    pub fn expired(&self, now: i64) -> bool {
        self.expires.is_some_and(|expires| expires <= now)
    }
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
    /// Blob hash ‖ owner pubkey, both raw → when the claim expires, as
    /// big-endian seconds, or nothing if it doesn't.
    owners: Database<Bytes, Bytes>,
    /// Expiration, big-endian seconds ‖ blob hash ‖ owner pubkey → nothing:
    /// the claims that expire, soonest first.
    expiring: Database<Bytes, Unit>,
}

impl BlossomDb {
    pub fn open(storage: &Storage) -> Result<BlossomDb> {
        let env = storage.env("blossom", MAP_SIZE, 4)?;
        let mut txn = env.write_txn()?;
        let blobs = env.create_database(&mut txn, Some("blobs"))?;
        let owners = env.create_database(&mut txn, Some("owners"))?;
        let expiring = env.create_database(&mut txn, Some("expiring"))?;
        txn.commit()?;
        Ok(BlossomDb { env, blobs, owners, expiring })
    }

    pub fn get(&self, sha256: BlobHash) -> Result<Option<Record>> {
        let txn = self.env.read_txn()?;
        Ok(self.blobs.get(&txn, sha256.as_bytes())?)
    }

    /// Record that `pubkey` uploaded a blob, to keep until `expires`, or for
    /// good if `None`. Returns its record, and whether the blob is new to
    /// the server.
    ///
    /// An owner's claim only ever grows: uploading again extends it, or
    /// makes it for good, but never cuts it short.
    pub fn add(&self, sha256: BlobHash, size: u64, pubkey: &str, expires: Option<i64>, now: i64) -> Result<(Record, bool)> {
        let owner = owner_key(sha256, pubkey)?;
        let mut txn = self.env.write_txn()?;
        let (mut record, new) = match self.blobs.get(&txn, sha256.as_bytes())? {
            Some(record) => (record, false),
            None => (Record { size, uploaded: now - now.rem_euclid(DAY), expires: None }, true),
        };
        let claim = match self.owners.get(&txn, &owner)? {
            None => expires,
            Some(held) => {
                let held = decode_claim(held);
                let claim = later(held, expires);
                if let Some(held) = held.filter(|held| claim != Some(*held)) {
                    self.expiring.delete(&mut txn, &expiring_key(held, &owner))?;
                }
                claim
            }
        };
        self.owners.put(&mut txn, &owner, &encode_claim(claim))?;
        if let Some(claim) = claim {
            self.expiring.put(&mut txn, &expiring_key(claim, &owner), &())?;
        }
        record.expires = self.latest_claim(&txn, sha256)?;
        self.blobs.put(&mut txn, sha256.as_bytes(), &record)?;
        txn.commit()?;
        Ok((record, new))
    }

    /// Remove `pubkey` as an owner of a blob, and the blob's record with its
    /// last owner.
    pub fn remove_owner(&self, sha256: BlobHash, pubkey: &str) -> Result<Removal> {
        let Ok(owner) = owner_key(sha256, pubkey) else { return Ok(Removal::NotOwner) };
        let mut txn = self.env.write_txn()?;
        let removal = self.remove(&mut txn, &owner)?;
        txn.commit()?;
        Ok(removal)
    }

    /// Remove up to `limit` owners whose claims expired by `now`, and the
    /// records of the blobs they were the last owners of. Returns those
    /// blobs, whose bytes should go, and whether there may be more to do.
    pub fn sweep(&self, now: i64, limit: usize) -> Result<(Vec<BlobHash>, bool)> {
        let mut txn = self.env.write_txn()?;
        let mut due = Vec::new();
        for entry in self.expiring.iter(&txn)? {
            let (key, ()) = entry?;
            let Some((at, owner)) = key.split_first_chunk::<8>() else { continue };
            if i64::from_be_bytes(*at) > now || due.len() == limit {
                break;
            }
            due.push(owner.to_vec());
        }
        let more = due.len() == limit;
        let mut gone = Vec::new();
        for owner in due {
            // Removing the owner takes its entry here too.
            if self.remove(&mut txn, &owner)? == Removal::Gone {
                gone.push(blob_of(&owner));
            }
        }
        txn.commit()?;
        Ok((gone, more))
    }

    fn remove(&self, txn: &mut RwTxn, owner: &[u8]) -> Result<Removal> {
        let Some(held) = self.owners.get(txn, owner)? else { return Ok(Removal::NotOwner) };
        if let Some(held) = decode_claim(held) {
            self.expiring.delete(txn, &expiring_key(held, owner))?;
        }
        self.owners.delete(txn, owner)?;
        let sha256 = &owner[..32];
        let others = self.owners.prefix_iter(txn, sha256)?.next().is_some();
        if others {
            if let Some(mut record) = self.blobs.get(txn, sha256)? {
                record.expires = self.latest_claim(txn, blob_of(owner))?;
                self.blobs.put(txn, sha256, &record)?;
            }
            Ok(Removal::Kept)
        } else {
            self.blobs.delete(txn, sha256)?;
            Ok(Removal::Gone)
        }
    }

    /// The latest of a blob's owners' claims, or `None` if any is for good.
    fn latest_claim(&self, txn: &heed::RoTxn<WithoutTls>, sha256: BlobHash) -> Result<Option<i64>> {
        let mut latest = Some(i64::MIN);
        for entry in self.owners.prefix_iter(txn, sha256.as_bytes())? {
            let (_, claim) = entry?;
            latest = later(latest, decode_claim(claim));
            if latest.is_none() {
                break;
            }
        }
        Ok(latest)
    }
}

/// The later of two claims, where `None` is for good.
fn later(a: Option<i64>, b: Option<i64>) -> Option<i64> {
    Some(a?.max(b?))
}

fn encode_claim(claim: Option<i64>) -> Vec<u8> {
    claim.map(|at| at.to_be_bytes().to_vec()).unwrap_or_default()
}

/// What an owner's value says. Owners recorded before claims could expire
/// have an empty one, which is for good.
fn decode_claim(value: &[u8]) -> Option<i64> {
    value.try_into().ok().map(i64::from_be_bytes)
}

fn expiring_key(at: i64, owner: &[u8]) -> Vec<u8> {
    let mut key = at.to_be_bytes().to_vec();
    key.extend_from_slice(owner);
    key
}

/// The blob an owner key is for.
fn blob_of(owner: &[u8]) -> BlobHash {
    BlobHash::from_bytes(owner[..32].try_into().expect("an owner key starts with a blob hash"))
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

    fn open() -> (tempfile::TempDir, BlossomDb) {
        let dir = tempfile::tempdir().unwrap();
        let db = BlossomDb::open(&Storage::allowing_private(dir.path())).unwrap();
        (dir, db)
    }

    #[test]
    fn tracks_owners_until_the_last_one_goes() {
        let (_dir, db) = open();
        let sha = BlobHash::of(b"one");
        let other = BlobHash::of(b"two");

        assert_eq!(db.get(sha).unwrap(), None);
        let (record, new) = db.add(sha, 10, ALICE, None, DAY * 3 + 5000).unwrap();
        assert!(new);
        assert_eq!(record, Record { size: 10, uploaded: DAY * 3, expires: None });
        assert!(!db.add(sha, 10, BOB, None, DAY * 9).unwrap().1);
        assert_eq!(db.get(sha).unwrap().unwrap().uploaded, DAY * 3);
        db.add(other, 5, ALICE, None, 0).unwrap();

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

    #[test]
    fn a_blob_expires_with_its_last_claim() {
        let (_dir, db) = open();
        let sha = BlobHash::of(b"one");

        assert_eq!(db.add(sha, 10, ALICE, Some(DAY * 5), 0).unwrap().0.expires, Some(DAY * 5));
        assert_eq!(db.add(sha, 10, BOB, Some(DAY * 7), 0).unwrap().0.expires, Some(DAY * 7));
        // Never cut short.
        assert_eq!(db.add(sha, 10, BOB, Some(DAY * 6), 0).unwrap().0.expires, Some(DAY * 7));

        assert_eq!(db.sweep(DAY * 4, 100).unwrap(), (vec![], false));
        // Alice's claim goes; Bob's holds it.
        assert_eq!(db.sweep(DAY * 5, 100).unwrap(), (vec![], false));
        assert_eq!(db.remove_owner(sha, ALICE).unwrap(), Removal::NotOwner);
        assert_eq!(db.get(sha).unwrap().unwrap().expires, Some(DAY * 7));
        assert_eq!(db.sweep(DAY * 7, 100).unwrap(), (vec![sha], false));
        assert_eq!(db.get(sha).unwrap(), None);
    }

    #[test]
    fn a_claim_for_good_keeps_a_blob() {
        let (_dir, db) = open();
        let sha = BlobHash::of(b"avatar");

        db.add(sha, 10, ALICE, None, 0).unwrap();
        assert_eq!(db.add(sha, 10, BOB, Some(DAY), 0).unwrap().0.expires, None);
        assert_eq!(db.sweep(DAY * 2, 100).unwrap(), (vec![], false));
        assert_eq!(db.remove_owner(sha, BOB).unwrap(), Removal::NotOwner);

        // An expiring claim made for good, by uploading again.
        let other = BlobHash::of(b"attachment");
        db.add(other, 10, BOB, Some(DAY), 0).unwrap();
        assert_eq!(db.add(other, 10, BOB, None, 0).unwrap().0.expires, None);
        assert_eq!(db.sweep(DAY * 2, 100).unwrap(), (vec![], false));

        // And once the claim for good is deleted, the rest decide.
        let third = BlobHash::of(b"shared");
        db.add(third, 10, ALICE, None, 0).unwrap();
        db.add(third, 10, BOB, Some(DAY * 3), 0).unwrap();
        assert_eq!(db.remove_owner(third, ALICE).unwrap(), Removal::Kept);
        assert_eq!(db.get(third).unwrap().unwrap().expires, Some(DAY * 3));
    }

    #[test]
    fn sweeps_a_bounded_step_at_a_time() {
        let (_dir, db) = open();
        let shas: Vec<_> = (0..5u8).map(|n| BlobHash::of(&[n])).collect();
        for (n, sha) in shas.iter().enumerate() {
            db.add(*sha, 10, ALICE, Some(DAY * (n as i64 + 1)), 0).unwrap();
        }
        let (gone, more) = db.sweep(DAY * 10, 2).unwrap();
        assert_eq!((gone, more), (shas[..2].to_vec(), true));
        let (gone, more) = db.sweep(DAY * 10, 2).unwrap();
        assert_eq!((gone, more), (shas[2..4].to_vec(), true));
        assert_eq!(db.sweep(DAY * 10, 2).unwrap(), (shas[4..].to_vec(), false));
    }

    /// Owners recorded before claims could expire hold an empty value.
    #[test]
    fn reads_owners_recorded_before_expiration() {
        let (_dir, db) = open();
        let sha = BlobHash::of(b"old");
        let owner = owner_key(sha, ALICE).unwrap();
        let mut txn = db.env.write_txn().unwrap();
        let old: Database<Bytes, Unit> = db.owners.remap_data_type();
        old.put(&mut txn, &owner, &()).unwrap();
        // Records then had no expiration either.
        let raw: Database<Bytes, Bytes> = db.blobs.remap_data_type();
        raw.put(&mut txn, sha.as_bytes(), br#"{"size":10,"uploaded":0}"#).unwrap();
        txn.commit().unwrap();

        assert_eq!(db.get(sha).unwrap(), Some(Record { size: 10, uploaded: 0, expires: None }));
        assert_eq!(db.add(sha, 10, BOB, Some(DAY), 0).unwrap().0.expires, None);
        assert_eq!(db.remove_owner(sha, ALICE).unwrap(), Removal::Kept);
        assert_eq!(db.get(sha).unwrap().unwrap().expires, Some(DAY));
    }
}
