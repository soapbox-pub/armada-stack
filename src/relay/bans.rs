//! The relay's store as `armada ban` uses it, from a process of its own.
//!
//! LMDB takes writers from more than one process, one at a time, so this
//! works while armada runs: a running relay refuses a banned pubkey's
//! events from the moment the ban commits. What was stored before goes a
//! batch per transaction, so the relay's writer never waits long behind it.

use anyhow::Result;

use super::store::{SWEEP_BATCH, Store};
pub use super::store::Outcome;
use crate::config::RelayConfig;
use crate::nostr::Event;
use crate::storage::Storage;

pub use super::store::Ban;

pub struct Bans {
    store: Store,
}

impl Bans {
    pub fn open(config: &RelayConfig, storage: &Storage) -> Result<Bans> {
        Ok(Bans { store: Store::open(&storage.service_dir("relay")?, config.map_size as usize)? })
    }

    #[cfg(test)]
    pub fn insert(&self, event: &Event) -> Outcome {
        self.publish(event).unwrap()
    }

    /// Store an event of armada's own, such as a blocklist entry. Clients
    /// find it when they next ask; those subscribed to the running relay
    /// aren't told of it.
    pub fn publish(&self, event: &Event) -> Result<Outcome> {
        let mut txn = self.store.write()?;
        let outcome = self.store.insert(&mut txn, &super::record::encode_expiring(event, super::record::expiration(event)))?;
        txn.commit()?;
        Ok(outcome)
    }

    /// Every event `pubkey` signed that's stored here.
    pub fn events_by(&self, pubkey: &[u8; 32]) -> Result<Vec<Event>> {
        let txn = self.store.read()?;
        let mut events = Vec::new();
        for seq in self.store.authored(&txn, pubkey)? {
            if let Some(view) = self.store.load(&txn, seq)? {
                events.push(serde_json::from_str(&view.to_json())?);
            }
        }
        Ok(events)
    }

    /// How many events `pubkey` signed that are stored here.
    pub fn count_by(&self, pubkey: &[u8; 32]) -> Result<usize> {
        let txn = self.store.read()?;
        Ok(self.store.authored(&txn, pubkey)?.len())
    }

    /// The kinds of the events `pubkey` signed that are stored here.
    pub fn kinds_by(&self, pubkey: &[u8; 32]) -> Result<Vec<u16>> {
        let txn = self.store.read()?;
        let mut kinds = Vec::new();
        for seq in self.store.authored(&txn, pubkey)? {
            kinds.extend(self.store.load(&txn, seq)?.map(|view| view.kind()));
        }
        Ok(kinds)
    }

    /// How many stored Discover announcements announce links signed by
    /// `signers`.
    pub fn count_announcements(&self, signers: &[[u8; 32]]) -> Result<usize> {
        let txn = self.store.read()?;
        Ok(self.store.announcements_of(&txn, signers)?.len())
    }

    /// Ban `pubkeys` together, as `community`'s.
    pub fn ban(&self, pubkeys: &[[u8; 32]], community: &[u8; 32]) -> Result<()> {
        let at = u32::try_from(crate::util::now()).unwrap_or(u32::MAX);
        let mut txn = self.store.write()?;
        for &pubkey in pubkeys {
            self.store.ban(&mut txn, &Ban { pubkey, community: *community, at })?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Remove every stored event `pubkey` signed. Returns how many went.
    pub fn remove_by(&self, pubkey: &[u8; 32]) -> Result<usize> {
        let mut removed = 0;
        loop {
            let mut txn = self.store.write()?;
            let batch = self.store.remove_authored(&mut txn, pubkey, SWEEP_BATCH)?;
            txn.commit()?;
            removed += batch;
            if batch < SWEEP_BATCH {
                return Ok(removed);
            }
        }
    }

    /// Remove the stored Discover announcements of links signed by
    /// `signers`. Returns how many went.
    pub fn remove_announcements(&self, signers: &[[u8; 32]]) -> Result<usize> {
        let seqs = {
            let txn = self.store.read()?;
            self.store.announcements_of(&txn, signers)?
        };
        for batch in seqs.chunks(SWEEP_BATCH) {
            let mut txn = self.store.write()?;
            for &seq in batch {
                self.store.remove(&mut txn, seq)?;
            }
            txn.commit()?;
        }
        Ok(seqs.len())
    }

    pub fn list(&self) -> Result<Vec<Ban>> {
        let txn = self.store.read()?;
        Ok(self.store.bans(&txn)?)
    }

    /// Lift the bans on `pubkeys`. Returns how many there were.
    pub fn unban(&self, pubkeys: &[[u8; 32]]) -> Result<usize> {
        let mut txn = self.store.write()?;
        let mut lifted = 0;
        for pubkey in pubkeys {
            lifted += usize::from(self.store.unban(&mut txn, pubkey)?);
        }
        txn.commit()?;
        Ok(lifted)
    }
}
