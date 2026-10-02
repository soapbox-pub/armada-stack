//! The relay's LMDB: events, their indexes, and what NIP-01, NIP-09, and
//! NIP-40 say about which events to keep.
//!
//! Each stored event gets a sequence number, never reused, under which its
//! [record](super::record) is kept. The indexes point at events by a 10-byte
//! *stamp*: `created_at` (u32) then the sequence number (48 bits), both
//! big-endian, so a key's stamps sort oldest to newest. Most indexes are
//! `DUPSORT | DUPFIXED` tables — the key once, then its stamps packed
//! together — so an index entry costs 10 bytes rather than a key, a value,
//! and a node header.
//!
//! | table           | key                          | value                  |
//! |-----------------|------------------------------|------------------------|
//! | `events`        | seq (native u64)             | record                 |
//! | `ids`           | id                           | seq (u64 BE)           |
//! | `created`       | stamp                        | —                      |
//! | `kinds`         | kind (u16 BE)                | stamps                 |
//! | `authors`       | pubkey                       | stamps                 |
//! | `author_kinds`  | pubkey ‖ kind                | stamps                 |
//! | `tags`          | letter ‖ value               | stamps                 |
//! | `replaceable`   | address                      | seq (u64 BE)           |
//! | `deleted`       | id ‖ pubkey                  | —                      |
//! | `deleted_addrs` | address                      | created_at (u32 BE)    |
//! | `expirations`   | expiration (u32 BE) ‖ seq    | —                      |
//! | `meta`          | name                         | value                  |
//!
//! Tag values are indexed in [`record::tag_value`] form; an *address* is
//! pubkey ‖ kind ‖ the `d` tag in that form (always empty for replaceable
//! kinds).

use std::path::Path;

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

use super::lmdb::{Db, DbFlags, Env, Result, RoTxn, RwTxn, Txn};
use super::record::{self, DELETION, Element, EventView, GIFT_WRAP};

/// Bumped when the layout changes incompatibly.
const VERSION: u32 = 1;

pub const STAMP_LEN: usize = 10;
pub type Stamp = [u8; STAMP_LEN];

/// The largest sequence number a stamp holds.
pub const MAX_SEQ: u64 = (1 << 48) - 1;

/// Tag values longer than this, encoded, aren't indexed: LMDB keys top out
/// at 511 bytes, and nobody filters by an essay.
pub const MAX_INDEXED_TAG: usize = 256;

/// Longer `d` tags are hashed in addresses, to fit in a key.
const MAX_ADDRESS_D: usize = 256;

/// How many expired events one sweep removes, so it never holds the writer
/// long.
const SWEEP_BATCH: usize = 1000;

pub fn stamp(created_at: u32, seq: u64) -> Stamp {
    let mut out = [0; STAMP_LEN];
    out[..4].copy_from_slice(&created_at.to_be_bytes());
    out[4..].copy_from_slice(&seq.to_be_bytes()[2..]);
    out
}

pub fn stamp_created_at(stamp: &[u8]) -> u32 {
    u32::from_be_bytes(stamp[..4].try_into().unwrap())
}

pub fn stamp_seq(stamp: &[u8]) -> u64 {
    let mut seq = [0; 8];
    seq[2..].copy_from_slice(&stamp[4..STAMP_LEN]);
    u64::from_be_bytes(seq)
}

/// What became of an event offered to the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Stored, under this sequence number.
    Stored(u64),
    /// Already here.
    Duplicate,
    /// A newer version of it is already here.
    Replaced,
    /// Its author asked for it to be deleted.
    Deleted,
}

#[derive(Clone, Copy)]
pub struct Tables {
    pub events: Db,
    pub ids: Db,
    pub created: Db,
    pub kinds: Db,
    pub authors: Db,
    pub author_kinds: Db,
    pub tags: Db,
    pub replaceable: Db,
    pub deleted: Db,
    pub deleted_addrs: Db,
    pub expirations: Db,
    pub meta: Db,
}

pub struct Store {
    env: Env,
    pub tables: Tables,
}

impl Store {
    pub fn open(dir: &Path, map_size: usize) -> anyhow::Result<Store> {
        let env = Env::open(dir, map_size, 16, 1024).with_context(|| format!("Could not open the relay database at {}", dir.display()))?;
        let tables = Tables {
            events: env.create_db("events", DbFlags::INTEGER_KEY)?,
            ids: env.create_db("ids", DbFlags::PLAIN)?,
            created: env.create_db("created", DbFlags::PLAIN)?,
            kinds: env.create_db("kinds", DbFlags::DUP_FIXED)?,
            authors: env.create_db("authors", DbFlags::DUP_FIXED)?,
            author_kinds: env.create_db("author_kinds", DbFlags::DUP_FIXED)?,
            tags: env.create_db("tags", DbFlags::DUP_FIXED)?,
            replaceable: env.create_db("replaceable", DbFlags::PLAIN)?,
            deleted: env.create_db("deleted", DbFlags::PLAIN)?,
            deleted_addrs: env.create_db("deleted_addrs", DbFlags::PLAIN)?,
            expirations: env.create_db("expirations", DbFlags::PLAIN)?,
            meta: env.create_db("meta", DbFlags::PLAIN)?,
        };

        let mut txn = env.write_txn()?;
        match txn.get(tables.meta, b"version")? {
            None => {
                txn.put(tables.meta, b"version", &VERSION.to_be_bytes())?;
            }
            Some(version) if version == VERSION.to_be_bytes() => {}
            Some(version) => bail!("The relay database at {} is format {version:?}, not {VERSION}.", dir.display()),
        }
        txn.commit()?;
        Ok(Store { env, tables })
    }

    pub fn read(&self) -> Result<RoTxn<'_>> {
        self.env.read_txn()
    }

    pub fn write(&self) -> Result<RwTxn<'_>> {
        self.env.write_txn()
    }

    /// The sequence number the next stored event will get. Everything a
    /// transaction can see is below the one it reads.
    pub fn next_seq(&self, txn: &Txn) -> Result<u64> {
        Ok(txn.get(self.tables.meta, b"next_seq")?.map_or(1, |v| u64::from_be_bytes(v.try_into().unwrap_or_default())))
    }

    pub fn contains(&self, txn: &Txn, id: &[u8; 32]) -> Result<bool> {
        Ok(txn.get(self.tables.ids, id)?.is_some())
    }

    pub fn seq_of(&self, txn: &Txn, id: &[u8; 32]) -> Result<Option<u64>> {
        Ok(txn.get(self.tables.ids, id)?.map(|v| u64::from_be_bytes(v.try_into().unwrap_or_default())))
    }

    pub fn load<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<EventView<'t>>> {
        Ok(txn.get(self.tables.events, &seq.to_ne_bytes())?.and_then(EventView::new))
    }

    /// How many events are stored.
    pub fn len(&self, txn: &Txn) -> Result<usize> {
        txn.len(self.tables.events)
    }

    /// Offer an encoded event to the store, applying replacement and
    /// deletion. The caller has checked it's valid and not ephemeral.
    pub fn insert(&self, txn: &mut RwTxn, record: &[u8]) -> Result<Outcome> {
        let view = EventView::new(record).expect("an encoded record");
        let t = self.tables;
        let (id, kind, created_at) = (view.id(), view.kind(), view.created_at());

        if self.contains(txn, id)? {
            return Ok(Outcome::Duplicate);
        }
        if self.tombstoned(txn, &view)? {
            return Ok(Outcome::Deleted);
        }

        // Older versions this one replaces, and events it deletes.
        let mut remove = Vec::new();

        let address = address_of(&view);
        if let Some(address) = &address {
            if let Some(deleted) = txn.get(t.deleted_addrs, address)? {
                if created_at <= u32::from_be_bytes(deleted.try_into().unwrap_or_default()) {
                    return Ok(Outcome::Deleted);
                }
            }
            if let Some(seq) = self.replaceable_seq(txn, address)? {
                if let Some(old) = self.load(txn, seq)? {
                    if (old.created_at(), std::cmp::Reverse(old.id())) >= (created_at, std::cmp::Reverse(id)) {
                        return Ok(Outcome::Replaced);
                    }
                }
                remove.push(seq);
            }
        }

        if kind == DELETION {
            self.collect_deletions(txn, &view, &mut remove)?;
            self.record_tombstones(txn, &view)?;
        }

        let seq = self.next_seq(txn)?;
        assert!(seq <= MAX_SEQ, "the relay has run out of sequence numbers");
        let stamp = stamp(created_at, seq);
        txn.put(t.events, &seq.to_ne_bytes(), record)?;
        txn.put(t.ids, id, &seq.to_be_bytes())?;
        txn.put(t.created, &stamp, &[])?;
        for (db, key) in self.index_keys(&view) {
            txn.put_dup(db, &key, &stamp)?;
        }
        if let Some(address) = &address {
            txn.put(t.replaceable, address, &seq.to_be_bytes())?;
        }
        if let Some(expiration) = view.expiration() {
            txn.put(t.expirations, &expiration_key(expiration, seq), &[])?;
        }
        txn.put(t.meta, b"next_seq", &(seq + 1).to_be_bytes())?;

        for old in remove {
            self.remove(txn, old)?;
        }
        Ok(Outcome::Stored(seq))
    }

    /// Whether the event's author (or for a gift wrap, its recipient) has
    /// already asked for it to be deleted.
    fn tombstoned(&self, txn: &Txn, view: &EventView) -> Result<bool> {
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(view.id());
        key[32..].copy_from_slice(view.pubkey());
        if txn.get(self.tables.deleted, &key)?.is_some() {
            return Ok(true);
        }
        if view.kind() == GIFT_WRAP {
            for (letter, value) in view.indexed_tags() {
                if let (b'p', Element::Hex(recipient)) = (letter, value) {
                    key[32..].copy_from_slice(recipient);
                    if txn.get(self.tables.deleted, &key)?.is_some() {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    }

    /// The stored events a deletion request may delete (NIP-09): its
    /// author's own, by id or by address up to the request's time, and gift
    /// wraps addressed to them. Never other deletion requests.
    fn collect_deletions(&self, txn: &Txn, deletion: &EventView, out: &mut Vec<u64>) -> Result<()> {
        let author = deletion.pubkey();
        for (letter, value) in deletion.indexed_tags() {
            match (letter, value) {
                (b'e', Element::Hex(id)) => {
                    let Some(seq) = self.seq_of(txn, id)? else { continue };
                    let Some(target) = self.load(txn, seq)? else { continue };
                    let recipient = || {
                        target.kind() == GIFT_WRAP && target.indexed_tags().any(|(l, v)| l == b'p' && v == Element::Hex(author))
                    };
                    if target.kind() != DELETION && (target.pubkey() == author || recipient()) {
                        out.push(seq);
                    }
                }
                (b'a', Element::Text(value)) => {
                    let Some(address) = parse_address(value, author) else { continue };
                    let Some(seq) = self.replaceable_seq(txn, &address)? else { continue };
                    if self.load(txn, seq)?.is_some_and(|target| target.created_at() <= deletion.created_at()) {
                        out.push(seq);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Remember what a deletion request asked for, so the events it names
    /// can't come back later.
    fn record_tombstones(&self, txn: &mut RwTxn, deletion: &EventView) -> Result<()> {
        let author = deletion.pubkey();
        let mut key = [0u8; 64];
        key[32..].copy_from_slice(author);
        for (letter, value) in deletion.indexed_tags() {
            match (letter, value) {
                (b'e', Element::Hex(id)) => {
                    key[..32].copy_from_slice(id);
                    txn.put(self.tables.deleted, &key, &[])?;
                }
                (b'a', Element::Text(value)) => {
                    let Some(address) = parse_address(value, author) else { continue };
                    let previous = txn.get(self.tables.deleted_addrs, &address)?.map_or(0, |v| u32::from_be_bytes(v.try_into().unwrap_or_default()));
                    if deletion.created_at() > previous {
                        txn.put(self.tables.deleted_addrs, &address, &deletion.created_at().to_be_bytes())?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn replaceable_seq(&self, txn: &Txn, address: &[u8]) -> Result<Option<u64>> {
        Ok(txn.get(self.tables.replaceable, address)?.map(|v| u64::from_be_bytes(v.try_into().unwrap_or_default())))
    }

    /// Every (index, key) an event is filed under, besides `ids` and
    /// `created`. Each at most once, since a stamp is only stored once per
    /// key anyway.
    fn index_keys(&self, view: &EventView) -> Vec<(Db, Vec<u8>)> {
        let t = self.tables;
        let kind = view.kind().to_be_bytes();
        let mut keys = vec![(t.kinds, kind.to_vec()), (t.authors, view.pubkey().to_vec()), (t.author_kinds, [&view.pubkey()[..], &kind].concat())];
        let mut tags: Vec<Vec<u8>> = Vec::new();
        for (letter, value) in view.indexed_tags() {
            if value.encoded_len() > MAX_INDEXED_TAG {
                continue;
            }
            let mut key = vec![letter];
            value.encode(&mut key);
            tags.push(key);
        }
        tags.sort_unstable();
        tags.dedup();
        keys.extend(tags.into_iter().map(|key| (t.tags, key)));
        keys
    }

    /// Delete a stored event and every index entry pointing at it.
    pub fn remove(&self, txn: &mut RwTxn, seq: u64) -> Result<bool> {
        let t = self.tables;
        let Some(record) = txn.get(t.events, &seq.to_ne_bytes())?.map(<[u8]>::to_vec) else { return Ok(false) };
        let view = EventView::new(&record).expect("a stored record");
        let stamp = stamp(view.created_at(), seq);

        for (db, key) in self.index_keys(&view) {
            txn.del(db, &key, Some(&stamp))?;
        }
        if let Some(address) = address_of(&view) {
            if self.replaceable_seq(txn, &address)? == Some(seq) {
                txn.del(t.replaceable, &address, None)?;
            }
        }
        if let Some(expiration) = view.expiration() {
            txn.del(t.expirations, &expiration_key(expiration, seq), None)?;
        }
        txn.del(t.created, &stamp, None)?;
        txn.del(t.ids, view.id(), None)?;
        txn.del(t.events, &seq.to_ne_bytes(), None)?;
        Ok(true)
    }

    /// Delete events whose NIP-40 expiration has passed, a batch at a time.
    /// Returns how many went.
    pub fn sweep_expired(&self, txn: &mut RwTxn, now: i64) -> Result<usize> {
        let mut expired = Vec::new();
        {
            let mut cursor = txn.cursor(self.tables.expirations)?;
            let mut entry = cursor.first()?;
            while let Some((key, _)) = entry {
                let expiration = u32::from_be_bytes(key[..4].try_into().unwrap());
                if i64::from(expiration) > now || expired.len() == SWEEP_BATCH {
                    break;
                }
                expired.push(u64::from_be_bytes(key[4..12].try_into().unwrap()));
                entry = cursor.next()?;
            }
        }
        for &seq in &expired {
            self.remove(txn, seq)?;
        }
        Ok(expired.len())
    }
}

fn expiration_key(expiration: u32, seq: u64) -> [u8; 12] {
    let mut key = [0; 12];
    key[..4].copy_from_slice(&expiration.to_be_bytes());
    key[4..].copy_from_slice(&seq.to_be_bytes());
    key
}

/// The address a replaceable or addressable event is kept under.
fn address_of(view: &EventView) -> Option<Vec<u8>> {
    let kind = view.kind();
    let mut d = Vec::new();
    if record::is_addressable(kind) {
        view.tag("d").unwrap_or(Element::Text("")).encode(&mut d);
    } else if record::is_replaceable(kind) {
        Element::Text("").encode(&mut d);
    } else {
        return None;
    }
    Some(address(view.pubkey(), kind, &d))
}

fn address(pubkey: &[u8; 32], kind: u16, d: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 2 + 33);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(&kind.to_be_bytes());
    if d.len() > MAX_ADDRESS_D {
        // Can't collide with a short one: those start with 0 or 1.
        out.push(2);
        out.extend_from_slice(&Sha256::digest(d));
    } else {
        out.extend_from_slice(d);
    }
    out
}

/// The address an `a` tag (`kind:pubkey:d`) names, if it's one `author` may
/// delete: their own, of a replaceable or addressable kind.
fn parse_address(value: &str, author: &[u8; 32]) -> Option<Vec<u8>> {
    let mut parts = value.splitn(3, ':');
    let kind: u16 = parts.next()?.parse().ok()?;
    let pubkey = parts.next()?;
    let d = parts.next().unwrap_or("");
    let mut key = [0u8; 32];
    hex::decode_to_slice(pubkey, &mut key).ok()?;
    if &key != author {
        return None;
    }
    let d = if record::is_addressable(kind) {
        record::tag_value(d)
    } else if record::is_replaceable(kind) {
        record::tag_value("")
    } else {
        return None;
    };
    Some(address(author, kind, &d))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::nostr::Event;
    use crate::nostr::event::public_key;

    pub const ALICE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    pub const BOB: &str = "0000000000000000000000000000000000000000000000000000000000000002";

    pub fn open() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), 1 << 26).unwrap();
        (dir, store)
    }

    pub fn tags(tags: &[&[&str]]) -> Vec<Vec<String>> {
        tags.iter().map(|tag| tag.iter().map(|s| s.to_string()).collect()).collect()
    }

    pub fn put(store: &Store, event: &Event) -> Outcome {
        let mut txn = store.write().unwrap();
        let outcome = store.insert(&mut txn, &record::encode(event)).unwrap();
        txn.commit().unwrap();
        outcome
    }

    fn has(store: &Store, event: &Event) -> bool {
        let txn = store.read().unwrap();
        let id: [u8; 32] = hex::decode(&event.id).unwrap().try_into().unwrap();
        store.contains(&txn, &id).unwrap()
    }

    /// Every index entry of every table, to check removals leave nothing.
    fn entries(store: &Store) -> usize {
        let t = store.tables;
        let txn = store.read().unwrap();
        [t.events, t.ids, t.created, t.kinds, t.authors, t.author_kinds, t.tags, t.replaceable, t.expirations]
            .iter()
            .map(|&db| txn.len(db).unwrap())
            .sum()
    }

    #[test]
    fn stores_once_and_removes_cleanly() {
        let (_dir, store) = open();
        let event = Event::sign(ALICE, 100, 1, tags(&[&["t", "x"], &["t", "x"], &["p", &"ab".repeat(32)]]), "hi");
        assert!(matches!(put(&store, &event), Outcome::Stored(1)));
        assert_eq!(put(&store, &event), Outcome::Duplicate);
        // events, ids, created, kinds, authors, author_kinds, two tags.
        assert_eq!(entries(&store), 8);

        let mut txn = store.write().unwrap();
        assert!(store.remove(&mut txn, 1).unwrap());
        txn.commit().unwrap();
        assert_eq!(entries(&store), 0);

        // Sequence numbers aren't reused.
        let other = Event::sign(ALICE, 100, 1, vec![], "again");
        assert_eq!(put(&store, &other), Outcome::Stored(2));
    }

    #[test]
    fn keeps_the_newest_replaceable() {
        let (_dir, store) = open();
        let old = Event::sign(ALICE, 100, 0, vec![], "old");
        let new = Event::sign(ALICE, 200, 0, vec![], "new");
        put(&store, &old);
        assert!(matches!(put(&store, &new), Outcome::Stored(_)));
        assert!(!has(&store, &old));
        assert_eq!(put(&store, &old), Outcome::Replaced);
        // Another author's is separate.
        assert!(matches!(put(&store, &Event::sign(BOB, 50, 0, vec![], "")), Outcome::Stored(_)));

        // On a tie, the lower id wins.
        let a = Event::sign(ALICE, 300, 3, vec![], "a");
        let b = Event::sign(ALICE, 300, 3, vec![], "b");
        let (low, high) = if a.id < b.id { (a, b) } else { (b, a) };
        put(&store, &high);
        assert!(matches!(put(&store, &low), Outcome::Stored(_)));
        assert_eq!(put(&store, &high), Outcome::Replaced);
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 3);
    }

    #[test]
    fn keeps_the_newest_addressable_per_d_tag() {
        let (_dir, store) = open();
        let one = Event::sign(ALICE, 100, 30_000, tags(&[&["d", "one"]]), "");
        let two = Event::sign(ALICE, 100, 30_000, tags(&[&["d", "two"]]), "");
        let none = Event::sign(ALICE, 100, 30_000, vec![], "");
        let empty = Event::sign(ALICE, 200, 30_000, tags(&[&["d", ""]]), "");
        for event in [&one, &two, &none] {
            assert!(matches!(put(&store, event), Outcome::Stored(_)));
        }
        // No d tag and an empty one are the same address.
        put(&store, &empty);
        assert!(!has(&store, &none) && has(&store, &one) && has(&store, &two));
    }

    #[test]
    fn deletes_by_id_and_remembers() {
        let (_dir, store) = open();
        let note = Event::sign(ALICE, 100, 1, vec![], "oops");
        let bobs = Event::sign(BOB, 100, 1, vec![], "mine");
        put(&store, &note);
        put(&store, &bobs);
        let deletion = Event::sign(ALICE, 200, 5, tags(&[&["e", &note.id], &["e", &bobs.id]]), "");
        put(&store, &deletion);
        assert!(!has(&store, &note));
        assert!(has(&store, &bobs), "only the author's own");
        assert!(has(&store, &deletion));
        assert_eq!(put(&store, &note), Outcome::Deleted);

        // Deleting before the event arrives works too.
        let later = Event::sign(ALICE, 300, 1, vec![], "later");
        put(&store, &Event::sign(ALICE, 250, 5, tags(&[&["e", &later.id]]), ""));
        assert_eq!(put(&store, &later), Outcome::Deleted);

        // Deletion requests can't be deleted.
        put(&store, &Event::sign(ALICE, 400, 5, tags(&[&["e", &deletion.id]]), ""));
        assert!(has(&store, &deletion));
    }

    #[test]
    fn deletes_by_address_up_to_its_time() {
        let (_dir, store) = open();
        let alice = public_key(ALICE);
        let article = Event::sign(ALICE, 100, 30_023, tags(&[&["d", "post"]]), "v1");
        put(&store, &article);
        let address = format!("30023:{alice}:post");
        put(&store, &Event::sign(ALICE, 150, 5, tags(&[&["a", &address]]), ""));
        assert!(!has(&store, &article));

        // Older versions can't come back; newer ones can.
        assert_eq!(put(&store, &Event::sign(ALICE, 120, 30_023, tags(&[&["d", "post"]]), "v0")), Outcome::Deleted);
        assert!(matches!(put(&store, &Event::sign(ALICE, 200, 30_023, tags(&[&["d", "post"]]), "v2")), Outcome::Stored(_)));

        // Nobody else can delete it.
        let bobs = format!("30023:{alice}:post");
        put(&store, &Event::sign(BOB, 300, 5, tags(&[&["a", &bobs]]), ""));
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 3);
    }

    #[test]
    fn lets_recipients_delete_gift_wraps() {
        let (_dir, store) = open();
        let alice = public_key(ALICE);
        let wrap = Event::sign(BOB, 100, GIFT_WRAP.into(), tags(&[&["p", &alice]]), "sealed");
        put(&store, &wrap);
        put(&store, &Event::sign(ALICE, 200, 5, tags(&[&["e", &wrap.id]]), ""));
        assert!(!has(&store, &wrap));
        assert_eq!(put(&store, &wrap), Outcome::Deleted);
    }

    #[test]
    fn sweeps_expired_events() {
        let (_dir, store) = open();
        let soon = Event::sign(ALICE, 100, 1, tags(&[&["expiration", "1000"]]), "");
        let later = Event::sign(ALICE, 100, 1, tags(&[&["expiration", "2000"]]), "");
        let never = Event::sign(ALICE, 100, 1, vec![], "");
        for event in [&soon, &later, &never] {
            put(&store, event);
        }
        let mut txn = store.write().unwrap();
        assert_eq!(store.sweep_expired(&mut txn, 999).unwrap(), 0);
        assert_eq!(store.sweep_expired(&mut txn, 1000).unwrap(), 1);
        txn.commit().unwrap();
        assert!(!has(&store, &soon) && has(&store, &later) && has(&store, &never));
    }

    #[test]
    fn stamps_sort_by_time_then_sequence() {
        assert!(stamp(1, MAX_SEQ) < stamp(2, 0));
        assert!(stamp(5, 1) < stamp(5, 2));
        assert_eq!(stamp_seq(&stamp(7, MAX_SEQ)), MAX_SEQ);
        assert_eq!(stamp_created_at(&stamp(u32::MAX, 3)), u32::MAX);
    }
}
