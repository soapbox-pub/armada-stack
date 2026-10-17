//! The relay's LMDB: events, their indexes, and what NIP-01, NIP-09,
//! NIP-40, and NIP-62 say about which events to keep.
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
//! | `ids`           | id prefix (8 bytes)          | seqs (u64 BE)          |
//! | `created`       | `CREATED`                    | stamps                 |
//! | `kinds`         | kind (u16 BE)                | stamps                 |
//! | `authors`       | pubkey                       | stamps                 |
//! | `author_kinds`  | pubkey ‖ kind                | stamps                 |
//! | `tags`          | letter ‖ value               | stamps                 |
//! | `replaceable`   | address                      | seq (u64 BE)           |
//! | `deleted`       | id ‖ pubkey                  | —                      |
//! | `deleted_addrs` | address                      | created_at (u32 BE)    |
//! | `vanished`      | pubkey                       | created_at (u32 BE)    |
//! | `vanishing`     | pubkey                       | [`Vanishing`]          |
//! | `banned`        | pubkey                       | community id ‖ time    |
//! | `expirations`   | expiration (u32 BE) ‖ seq    | —                      |
//! | `meta`          | name                         | value                  |
//!
//! `ids` is keyed by a prefix of the id, a quarter its size; the record has
//! the whole id, so a lookup checks there, and the rare prefix shared by two
//! ids just means reading both records. `created` files every stamp under
//! one key, packed like the other indexes.
//!
//! Tag values are indexed in [`record::tag_value`] form; an *address* is
//! pubkey ‖ kind ‖ the `d` tag in that form (always empty for replaceable
//! kinds).
//!
//! Gift wraps belong to their `p` recipient, not their author (see
//! [`policy::is_gift_wrap`]): only the recipient may delete one, by NIP-09
//! or by vanishing.
//!
//! A request to vanish is recorded in `vanished` at once, which keeps
//! anything older out from then on, but what it removes may be far more
//! than one transaction should do. So it's queued in `vanishing`, and
//! carried out [`SWEEP_BATCH`] index entries at a time, resuming where the
//! last step left off, by [`Store::sweep`] alongside expired events.
//!
//! The operator bans pubkeys with `armada ban`, a Concord Community's
//! addresses and invite links (see [`crate::ban`]). Nothing a banned pubkey
//! signs is taken, gift wraps included, nor any Discover announcement of a
//! banned invite link.

use std::path::Path;

use anyhow::{Context, bail};
use sha2::{Digest, Sha256};

use super::lmdb::{Db, DbFlags, Env, Result, RoTxn, RwTxn, Txn};
use super::policy::{self, ANNOUNCEMENT, DELETION, NIP46, VANISH};
use super::record::{self, Content, Element, EventView};

/// Bumped when the layout changes incompatibly.
const VERSION: u32 = 2;

pub const STAMP_LEN: usize = 10;
pub type Stamp = [u8; STAMP_LEN];

/// The largest sequence number a stamp holds.
pub const MAX_SEQ: u64 = (1 << 48) - 1;

/// Tag values longer than this, encoded, aren't indexed: LMDB keys top out
/// at 511 bytes, and nobody filters by an essay.
pub const MAX_INDEXED_TAG: usize = 256;

/// Longer `d` tags are hashed in addresses, to fit in a key.
const MAX_ADDRESS_D: usize = 256;

/// The one key of the `created` table.
pub const CREATED: &[u8] = &[0];

/// The bytes of an id the `ids` table is keyed by.
const ID_PREFIX: usize = 8;

/// How many expired events one sweep removes, so it never holds the writer
/// long.
pub const SWEEP_BATCH: usize = 1000;

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
    /// Its owner asked for it to be deleted.
    Deleted,
    /// A request to vanish, carried out. Never stored.
    Vanished,
    /// Signed by a banned pubkey, or announcing a banned invite link.
    Banned,
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
    pub vanished: Db,
    pub vanishing: Db,
    pub banned: Db,
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
            ids: env.create_db("ids", DbFlags::DUP_FIXED)?,
            created: env.create_db("created", DbFlags::DUP_FIXED)?,
            kinds: env.create_db("kinds", DbFlags::DUP_FIXED)?,
            authors: env.create_db("authors", DbFlags::DUP_FIXED)?,
            author_kinds: env.create_db("author_kinds", DbFlags::DUP_FIXED)?,
            tags: env.create_db("tags", DbFlags::DUP_FIXED)?,
            replaceable: env.create_db("replaceable", DbFlags::PLAIN)?,
            deleted: env.create_db("deleted", DbFlags::PLAIN)?,
            deleted_addrs: env.create_db("deleted_addrs", DbFlags::PLAIN)?,
            vanished: env.create_db("vanished", DbFlags::PLAIN)?,
            vanishing: env.create_db("vanishing", DbFlags::PLAIN)?,
            banned: env.create_db("banned", DbFlags::PLAIN)?,
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

    #[cfg(test)]
    pub fn copy_compact(&self, path: &Path) -> Result<()> {
        self.env.copy_compact(path)
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
        Ok(self.seq_of(txn, id)?.is_some())
    }

    pub fn seq_of(&self, txn: &Txn, id: &[u8; 32]) -> Result<Option<u64>> {
        let mut cursor = txn.cursor(self.tables.ids)?;
        let mut entry = cursor.set(&id[..ID_PREFIX])?;
        while let Some((_, value)) = entry {
            let seq = u64::from_be_bytes(value.try_into().unwrap_or_default());
            if self.load(txn, seq)?.is_some_and(|view| view.id() == id) {
                return Ok(Some(seq));
            }
            entry = cursor.next_dup()?;
        }
        Ok(None)
    }

    pub fn load<'t>(&self, txn: &'t Txn, seq: u64) -> Result<Option<EventView<'t>>> {
        Ok(txn.get(self.tables.events, &seq.to_ne_bytes())?.and_then(EventView::new))
    }

    /// How many events are stored.
    #[cfg(test)]
    pub fn len(&self, txn: &Txn) -> Result<usize> {
        txn.len(self.tables.events)
    }

    /// Offer an encoded event to the store, applying replacement, deletion,
    /// and requests to vanish. The caller has checked it's valid.
    pub fn insert(&self, txn: &mut RwTxn, record: &[u8]) -> Result<Outcome> {
        let view = EventView::new(record).expect("an encoded record");
        let t = self.tables;
        let (id, kind, created_at) = (view.id(), view.kind(), view.created_at());

        if self.is_banned(txn, &view)? {
            return Ok(Outcome::Banned);
        }
        if kind == VANISH {
            self.vanish(txn, &view)?;
            return Ok(Outcome::Vanished);
        }
        if self.contains(txn, id)? {
            return Ok(Outcome::Duplicate);
        }
        if self.tombstoned(txn, &view)? || self.owners_vanished(txn, &view)? {
            return Ok(Outcome::Deleted);
        }

        // Older versions this one replaces, and events it deletes.
        let mut remove = Vec::new();

        let address = address_of(&view);
        if let Some(address) = &address {
            if let Some(deleted) = txn.get(t.deleted_addrs, address)?
                && created_at <= u32::from_be_bytes(deleted.try_into().unwrap_or_default())
            {
                return Ok(Outcome::Deleted);
            }
            if let Some(seq) = self.replaceable_seq(txn, address)? {
                if let Some(old) = self.load(txn, seq)?
                    && (old.created_at(), std::cmp::Reverse(old.id())) >= (created_at, std::cmp::Reverse(id))
                {
                    return Ok(Outcome::Replaced);
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
        txn.put_dup(t.ids, &id[..ID_PREFIX], &seq.to_be_bytes())?;
        txn.put_dup(t.created, CREATED, &stamp)?;
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

    /// Whether an event is one a ban keeps out: signed by a banned pubkey,
    /// or announcing an invite link whose bundle's signer is banned.
    fn is_banned(&self, txn: &Txn, view: &EventView) -> Result<bool> {
        if self.ban_of(txn, view.pubkey())?.is_some() {
            return Ok(true);
        }
        if view.kind() == ANNOUNCEMENT
            && let Content::Text(content) = view.content()
            && let Some(signer) = crate::concord::link_signer(content).and_then(|signer| crate::concord::bytes32(&signer))
        {
            return Ok(self.ban_of(txn, &signer)?.is_some());
        }
        Ok(false)
    }

    /// The Community a pubkey was banned with, and when, if it was.
    pub fn ban_of(&self, txn: &Txn, pubkey: &[u8; 32]) -> Result<Option<Ban>> {
        Ok(txn.get(self.tables.banned, pubkey)?.and_then(|value| Ban::decode(*pubkey, value)))
    }

    /// Ban a pubkey. Its events already stored stay until
    /// [`Store::remove_authored`] removes them.
    pub fn ban(&self, txn: &mut RwTxn, ban: &Ban) -> Result<()> {
        txn.put(self.tables.banned, &ban.pubkey, &ban.encode())?;
        Ok(())
    }

    /// Lift a ban. Whether there was one.
    pub fn unban(&self, txn: &mut RwTxn, pubkey: &[u8; 32]) -> Result<bool> {
        txn.del(self.tables.banned, pubkey, None)
    }

    /// Every ban.
    pub fn bans(&self, txn: &Txn) -> Result<Vec<Ban>> {
        let mut bans = Vec::new();
        let mut cursor = txn.cursor(self.tables.banned)?;
        let mut entry = cursor.first()?;
        while let Some((key, value)) = entry {
            if let Some(ban) = key.try_into().ok().and_then(|pubkey| Ban::decode(pubkey, value)) {
                bans.push(ban);
            }
            entry = cursor.next()?;
        }
        Ok(bans)
    }

    /// The sequence numbers of an author's stored events, oldest first.
    pub fn authored(&self, txn: &Txn, author: &[u8; 32]) -> Result<Vec<u64>> {
        let mut seqs = Vec::new();
        let mut cursor = txn.cursor(self.tables.authors)?;
        let mut entry = cursor.set(author)?;
        while let Some((_, stamp)) = entry {
            seqs.push(stamp_seq(stamp));
            entry = cursor.next_dup()?;
        }
        Ok(seqs)
    }

    /// Remove up to `budget` of an author's events, whoever they belong to.
    /// Returns how many went: fewer than `budget` once there are no more.
    pub fn remove_authored(&self, txn: &mut RwTxn, author: &[u8; 32], budget: usize) -> Result<usize> {
        let mut doomed = Vec::new();
        {
            let mut cursor = txn.cursor(self.tables.authors)?;
            let mut entry = cursor.set(author)?;
            while let Some((_, stamp)) = entry {
                if doomed.len() == budget {
                    break;
                }
                doomed.push(stamp_seq(stamp));
                entry = cursor.next_dup()?;
            }
        }
        for &seq in &doomed {
            self.remove(txn, seq)?;
        }
        Ok(doomed.len())
    }

    /// The sequence numbers of stored Discover announcements of invite
    /// links whose bundles' signers are `signers`.
    pub fn announcements_of(&self, txn: &Txn, signers: &[[u8; 32]]) -> Result<Vec<u64>> {
        let mut seqs = Vec::new();
        let mut cursor = txn.cursor(self.tables.kinds)?;
        let mut entry = cursor.set(&ANNOUNCEMENT.to_be_bytes())?;
        while let Some((_, stamp)) = entry {
            let seq = stamp_seq(stamp);
            if let Some(view) = self.load(txn, seq)?
                && let Content::Text(content) = view.content()
                && crate::concord::link_signer(content).and_then(|signer| crate::concord::bytes32(&signer)).is_some_and(|signer| signers.contains(&signer))
            {
                seqs.push(seq);
            }
            entry = cursor.next_dup()?;
        }
        Ok(seqs)
    }

    /// Whether the event's owner has already asked for it to be deleted.
    fn tombstoned(&self, txn: &Txn, view: &EventView) -> Result<bool> {
        let Some(owner) = owner(view) else { return Ok(false) };
        let mut key = [0u8; 64];
        key[..32].copy_from_slice(view.id());
        key[32..].copy_from_slice(owner);
        Ok(txn.get(self.tables.deleted, &key)?.is_some())
    }

    /// Whether someone the event belongs to vanished after it was made: its
    /// owner, or the other party to a NIP-46 message.
    fn owners_vanished(&self, txn: &Txn, view: &EventView) -> Result<bool> {
        let mut parties: Vec<&[u8; 32]> = owner(view).into_iter().collect();
        if view.kind() == NIP46 {
            parties.extend(recipient(view));
        }
        for party in parties {
            if let Some(at) = txn.get(self.tables.vanished, party)?
                && view.created_at() <= u32::from_be_bytes(at.try_into().unwrap_or_default())
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Take a request to vanish (NIP-62): delete everything its author made
    /// up to its time, other than gift wraps they sent, along with the gift
    /// wraps and NIP-46 messages addressed to them, and keep any of those
    /// from coming back. Only the first [`SWEEP_BATCH`] index entries are
    /// gone through now; [`Store::sweep_vanishing`] does the rest.
    ///
    /// One no newer than a request already taken asks for nothing more, so
    /// costs nothing: it can be sent again by anyone, as often as they like.
    fn vanish(&self, txn: &mut RwTxn, request: &EventView) -> Result<()> {
        let t = self.tables;
        let (author, until) = (request.pubkey(), request.created_at());
        let previous = txn.get(t.vanished, author)?.map_or(0, |v| u32::from_be_bytes(v.try_into().unwrap_or_default()));
        if until <= previous {
            return Ok(());
        }
        txn.put(t.vanished, author, &until.to_be_bytes())?;
        txn.put(t.vanishing, author, &Vanishing { until, phase: 0, after: None }.encode())?;
        self.vanish_step(txn, author, SWEEP_BATCH)?;
        Ok(())
    }

    /// Go through up to `budget` index entries of one author's pending
    /// request to vanish, removing what's theirs. Returns how many it went
    /// through.
    fn vanish_step(&self, txn: &mut RwTxn, author: &[u8; 32], budget: usize) -> Result<usize> {
        let t = self.tables;
        let Some(mut job) = txn.get(t.vanishing, author)?.and_then(Vanishing::decode) else {
            txn.del(t.vanishing, author, None)?;
            return Ok(0);
        };
        let mut p = vec![b'p'];
        Element::Hex(author).encode(&mut p);
        let mut doomed = Vec::new();
        let mut examined = 0;
        while job.phase < 2 && examined < budget {
            let (db, key) = if job.phase == 0 { (t.authors, &author[..]) } else { (t.tags, &p[..]) };
            let mut cursor = txn.cursor(db)?;
            let mut entry = match &job.after {
                Some(after) => cursor.get_both_range(key, after)?,
                None => cursor.set(key)?,
            };
            // Where the last step stopped, unless that entry has gone since.
            if let (Some(after), Some((_, stamp))) = (&job.after, entry)
                && stamp == &after[..]
            {
                entry = cursor.next_dup()?;
            }
            let mut finished = true;
            while let Some((_, stamp)) = entry {
                if stamp_created_at(stamp) > job.until {
                    break;
                }
                if examined == budget {
                    finished = false;
                    break;
                }
                examined += 1;
                doomed.push(stamp_seq(stamp));
                job.after = stamp.try_into().ok();
                entry = cursor.next_dup()?;
            }
            if finished {
                job.phase += 1;
                job.after = None;
            }
        }
        doomed.sort_unstable();
        doomed.dedup();
        for seq in doomed {
            let Some(view) = self.load(txn, seq)? else { continue };
            let theirs = owner(&view) == Some(author) || (view.kind() == NIP46 && recipient(&view) == Some(author));
            if theirs {
                self.remove(txn, seq)?;
            }
        }
        if job.phase >= 2 {
            txn.del(t.vanishing, author, None)?;
        } else {
            txn.put(t.vanishing, author, &job.encode())?;
        }
        Ok(examined)
    }

    /// Carry pending requests to vanish on, through at most `budget` index
    /// entries between them. Returns how many it went through.
    pub fn sweep_vanishing(&self, txn: &mut RwTxn, budget: usize) -> Result<usize> {
        let mut examined = 0;
        while examined < budget {
            let Some(author) = txn.cursor(self.tables.vanishing)?.first()?.and_then(|(key, _)| <[u8; 32]>::try_from(key).ok()) else { break };
            examined += self.vanish_step(txn, &author, budget - examined)?;
        }
        Ok(examined)
    }

    /// The stored events a deletion request may delete (NIP-09): those it
    /// owns, by id or by address up to the request's time. Never other
    /// deletion requests.
    fn collect_deletions(&self, txn: &Txn, deletion: &EventView, out: &mut Vec<u64>) -> Result<()> {
        let author = deletion.pubkey();
        for (letter, value) in deletion.indexed_tags() {
            match (letter, value) {
                (b'e', Element::Hex(id)) => {
                    let Some(seq) = self.seq_of(txn, id)? else { continue };
                    let Some(target) = self.load(txn, seq)? else { continue };
                    if target.kind() != DELETION && owner(&target) == Some(author) {
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

    /// Every (index, key) an event's stamp is filed under, besides
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
        if let Some(address) = address_of(&view)
            && self.replaceable_seq(txn, &address)? == Some(seq)
        {
            txn.del(t.replaceable, &address, None)?;
        }
        if let Some(expiration) = view.expiration() {
            txn.del(t.expirations, &expiration_key(expiration, seq), None)?;
        }
        txn.del(t.created, CREATED, Some(&stamp))?;
        txn.del(t.ids, &view.id()[..ID_PREFIX], Some(&seq.to_be_bytes()))?;
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

/// A banned pubkey, and the Community it was banned with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ban {
    pub pubkey: [u8; 32],
    pub community: [u8; 32],
    pub at: u32,
}

impl Ban {
    fn encode(&self) -> Vec<u8> {
        [&self.community[..], &self.at.to_be_bytes()].concat()
    }

    fn decode(pubkey: [u8; 32], value: &[u8]) -> Option<Ban> {
        let (community, at) = value.split_first_chunk::<32>()?;
        Some(Ban { pubkey, community: *community, at: u32::from_be_bytes(at.try_into().ok()?) })
    }
}

/// A request to vanish not yet carried out: its time, which index it's
/// going through (0 for the author's own events, 1 for those `p`-tagging
/// them), and the last entry gone through there.
struct Vanishing {
    until: u32,
    phase: u8,
    after: Option<Stamp>,
}

impl Vanishing {
    fn encode(&self) -> Vec<u8> {
        let mut out = self.until.to_be_bytes().to_vec();
        out.push(self.phase);
        out.extend_from_slice(self.after.as_ref().map_or(&[][..], |after| &after[..]));
        out
    }

    fn decode(bytes: &[u8]) -> Option<Vanishing> {
        let (until, rest) = bytes.split_first_chunk::<4>()?;
        let (&phase, after) = rest.split_first()?;
        let after = if after.is_empty() { None } else { Some(after.try_into().ok()?) };
        Some(Vanishing { until: u32::from_be_bytes(*until), phase, after })
    }
}

/// Who an event belongs to: a gift wrap's recipient, or anything else's
/// author.
fn owner<'a>(view: &EventView<'a>) -> Option<&'a [u8; 32]> {
    if policy::is_gift_wrap(view.kind()) { recipient(view) } else { Some(view.pubkey()) }
}

/// An envelope's `p` recipient. Envelopes have exactly one.
fn recipient<'a>(view: &EventView<'a>) -> Option<&'a [u8; 32]> {
    view.indexed_tags().find_map(|tag| match tag {
        (b'p', Element::Hex(recipient)) => Some(recipient),
        _ => None,
    })
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
    fn lets_only_recipients_delete_gift_wraps() {
        let (_dir, store) = open();
        let alice = public_key(ALICE);
        let wrap = Event::sign(BOB, 100, policy::GIFT_WRAP.into(), tags(&[&["p", &alice]]), "sealed");
        put(&store, &wrap);
        // Its author can't, nor keep it from arriving again.
        put(&store, &Event::sign(BOB, 200, 5, tags(&[&["e", &wrap.id]]), ""));
        assert!(has(&store, &wrap));
        put(&store, &Event::sign(ALICE, 200, 5, tags(&[&["e", &wrap.id]]), ""));
        assert!(!has(&store, &wrap));
        assert_eq!(put(&store, &wrap), Outcome::Deleted);

        // An author's deletion before it arrives doesn't count either.
        let early = Event::sign(BOB, 100, policy::GIFT_WRAP.into(), tags(&[&["p", &alice]]), "early");
        put(&store, &Event::sign(BOB, 200, 5, tags(&[&["e", &early.id]]), ""));
        assert!(matches!(put(&store, &early), Outcome::Stored(_)));
    }

    #[test]
    fn vanishes() {
        let (_dir, store) = open();
        let (alice, bob) = (public_key(ALICE), public_key(BOB));
        let wrap = |secret, to: &str, at| Event::sign(secret, at, policy::GIFT_WRAP.into(), tags(&[&["p", to]]), &at.to_string());
        let profile = Event::sign(ALICE, 100, 0, vec![], "{}");
        let sent = wrap(ALICE, &bob, 100);
        let received = wrap(BOB, &alice, 100);
        let to_her_signer = Event::sign(BOB, 100, NIP46.into(), tags(&[&["p", &alice]]), "rpc");
        let bobs = Event::sign(BOB, 100, 0, tags(&[&["p", &alice]]), "{}");
        let later = Event::sign(ALICE, 300, 3, vec![], "");
        for event in [&profile, &sent, &received, &to_her_signer, &bobs, &later] {
            assert!(matches!(put(&store, event), Outcome::Stored(_)));
        }

        let request = Event::sign(ALICE, 200, VANISH.into(), tags(&[&["relay", "ALL_RELAYS"]]), "");
        assert_eq!(put(&store, &request), Outcome::Vanished);
        assert!(!has(&store, &request), "never stored");
        assert!(!has(&store, &profile) && !has(&store, &received) && !has(&store, &to_her_signer));
        // The wrap she sent is Bob's; Bob's events are his; and hers since are hers.
        assert!(has(&store, &sent) && has(&store, &bobs) && has(&store, &later));

        // Nothing from before comes back.
        assert_eq!(put(&store, &profile), Outcome::Deleted);
        assert_eq!(put(&store, &wrap(BOB, &alice, 150)), Outcome::Deleted);
        assert!(matches!(put(&store, &wrap(BOB, &alice, 250)), Outcome::Stored(_)));
        assert!(matches!(put(&store, &Event::sign(ALICE, 250, 0, vec![], "{}")), Outcome::Stored(_)));
    }

    /// A request to vanish no newer than one already taken does nothing at
    /// all, so resending it costs nothing.
    #[test]
    fn takes_each_request_to_vanish_once() {
        let (_dir, store) = open();
        let request = Event::sign(ALICE, 200, VANISH.into(), tags(&[&["relay", "ALL_RELAYS"]]), "");
        assert_eq!(put(&store, &request), Outcome::Vanished);
        let note = Event::sign(ALICE, 100, 1, vec![], "");
        assert_eq!(put(&store, &note), Outcome::Deleted);

        // Something of hers from before slips in another way: the replay
        // doesn't look for it, since it can't have been let in by `insert`.
        let mut txn = store.write().unwrap();
        let seq = store.next_seq(&txn).unwrap();
        txn.put(store.tables.events, &seq.to_ne_bytes(), &record::encode(&note)).unwrap();
        txn.put(store.tables.meta, b"next_seq", &(seq + 1).to_be_bytes()).unwrap();
        txn.put_dup(store.tables.ids, &hex::decode(&note.id).unwrap()[..ID_PREFIX], &seq.to_be_bytes()).unwrap();
        for (db, key) in store.index_keys(&EventView::new(&record::encode(&note)).unwrap()) {
            txn.put_dup(db, &key, &stamp(100, seq)).unwrap();
        }
        txn.commit().unwrap();
        assert_eq!(put(&store, &request), Outcome::Vanished);
        assert_eq!(put(&store, &Event::sign(ALICE, 150, VANISH.into(), tags(&[&["relay", "ALL_RELAYS"]]), "")), Outcome::Vanished);
        assert!(has(&store, &note));
        assert_eq!(store.read().unwrap().len(store.tables.vanishing).unwrap(), 0);
    }

    /// However much there is to remove, each step goes through a bounded
    /// number of entries, and the steps together get everything.
    #[test]
    fn vanishes_in_steps() {
        let (_dir, store) = open();
        let alice = public_key(ALICE);
        let mut txn = store.write().unwrap();
        // Hers, and Bob's mentioning her, which stay but are gone through.
        for i in 0..SWEEP_BATCH * 2 + 5 {
            store.insert(&mut txn, &record::encode(&Event::sign(ALICE, 100, 1, vec![], &i.to_string()))).unwrap();
            store.insert(&mut txn, &record::encode(&Event::sign(BOB, 100, 1, tags(&[&["p", &alice]]), &i.to_string()))).unwrap();
        }
        txn.commit().unwrap();
        let theirs = |store: &Store| {
            let txn = store.read().unwrap();
            let mut cursor = txn.cursor(store.tables.authors).unwrap();
            if cursor.set(&hex::decode(&alice).unwrap()).unwrap().is_some() { cursor.count().unwrap() } else { 0 }
        };

        put(&store, &Event::sign(ALICE, 200, VANISH.into(), tags(&[&["relay", "ALL_RELAYS"]]), ""));
        assert_eq!(theirs(&store), SWEEP_BATCH + 5);
        let mut steps = 0;
        loop {
            let mut txn = store.write().unwrap();
            let examined = store.sweep_vanishing(&mut txn, SWEEP_BATCH).unwrap();
            txn.commit().unwrap();
            assert!(examined <= SWEEP_BATCH);
            if examined == 0 {
                break;
            }
            steps += 1;
        }
        // 1,005 more of hers, then 2,005 of Bob's.
        assert_eq!(steps, 4);
        assert_eq!(theirs(&store), 0);
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), SWEEP_BATCH * 2 + 5);
        assert_eq!(store.read().unwrap().len(store.tables.vanishing).unwrap(), 0);
    }

    #[test]
    fn bans_authors_and_their_links() {
        let (_dir, store) = open();
        let (alice, bob) = (public_key(ALICE), public_key(BOB));
        let alice_key: [u8; 32] = hex::decode(&alice).unwrap().try_into().unwrap();
        // Alice stands for a stream's address: its wraps are hers to ban,
        // though they belong to their recipients.
        let wrap = Event::sign(ALICE, 100, policy::GIFT_WRAP.into(), tags(&[&["p", &bob]]), "sealed");
        let bundle = Event::sign(ALICE, 100, 33301, tags(&[&["d", ""], &["vsk", "9"]]), "");
        let link = format!("https://armada.example/invite/{}#BAGZmZmZmZmZmZmZmZmZmZmZ", crate::nostr::nip19::naddr_encode(&alice, 33301, "", &[]));
        let announcement = Event::sign(BOB, 100, ANNOUNCEMENT.into(), vec![], &link);
        let other = Event::sign(BOB, 100, ANNOUNCEMENT.into(), vec![], "https://armada.example/invite/naddr1other#x");
        for event in [&wrap, &bundle, &announcement, &other] {
            assert!(matches!(put(&store, event), Outcome::Stored(_)));
        }
        {
            let txn = store.read().unwrap();
            assert_eq!(store.authored(&txn, &alice_key).unwrap().len(), 2);
            assert_eq!(store.announcements_of(&txn, &[alice_key]).unwrap().len(), 1);
        }

        let ban = Ban { pubkey: alice_key, community: [7; 32], at: 50 };
        let mut txn = store.write().unwrap();
        store.ban(&mut txn, &ban).unwrap();
        assert_eq!(store.remove_authored(&mut txn, &alice_key, 1).unwrap(), 1);
        assert_eq!(store.remove_authored(&mut txn, &alice_key, 1).unwrap(), 1);
        assert_eq!(store.remove_authored(&mut txn, &alice_key, 1).unwrap(), 0);
        txn.commit().unwrap();
        assert!(!has(&store, &wrap) && !has(&store, &bundle));
        assert_eq!(store.bans(&store.read().unwrap()).unwrap(), [ban]);

        // Nothing of hers comes back, nor any new announcement of her link.
        assert_eq!(put(&store, &wrap), Outcome::Banned);
        assert_eq!(put(&store, &Event::sign(ALICE, 200, 0, vec![], "{}")), Outcome::Banned);
        assert_eq!(put(&store, &Event::sign(BOB, 200, ANNOUNCEMENT.into(), vec![], &link)), Outcome::Banned);
        assert!(matches!(put(&store, &Event::sign(BOB, 200, 0, vec![], "{}")), Outcome::Stored(_)));

        let mut txn = store.write().unwrap();
        assert!(store.unban(&mut txn, &alice_key).unwrap());
        txn.commit().unwrap();
        assert!(matches!(put(&store, &wrap), Outcome::Stored(_)));
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

    /// How big the database is, compacted, against the events' JSON. Slow,
    /// so run by hand: `cargo test --release disk_usage -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn disk_usage() {
        use rand::rngs::StdRng;
        use rand::{Rng, SeedableRng};

        let (_dir, store) = open_sized(1 << 32);
        let mut rng = StdRng::seed_from_u64(1);
        let secrets: Vec<String> = (1..=500u32).map(|n| format!("{n:064x}")).collect();
        let people: Vec<String> = secrets.iter().map(|s| public_key(s)).collect();
        let mut ids: Vec<String> = Vec::new();
        let (mut json, mut count) = (0usize, 0usize);
        let mut txn = store.write().unwrap();
        for i in 0..100_000u32 {
            // A typical feed: notes, replies, and reactions, mentioning people.
            let mut event_tags = Vec::new();
            let kind = if i % 3 == 0 && !ids.is_empty() { 7 } else { 1 };
            if !ids.is_empty() && (kind == 7 || rng.random_bool(0.4)) {
                event_tags.push(vec!["e".into(), ids[rng.random_range(0..ids.len())].clone()]);
            }
            for _ in 0..rng.random_range(0..3) {
                event_tags.push(vec!["p".into(), people[rng.random_range(0..people.len())].clone()]);
            }
            let content: String = if kind == 7 { "+".into() } else { (0..rng.random_range(20..280)).map(|_| rng.random_range('a'..='z')).collect() };
            let event = Event::sign(&secrets[rng.random_range(0..secrets.len())], 1_700_000_000 + i64::from(i), kind, event_tags, &content);
            json += serde_json::to_string(&event).unwrap().len();
            store.insert(&mut txn, &record::encode(&event)).unwrap();
            ids.push(event.id);
            count += 1;
            if count % 10_000 == 0 {
                txn.commit().unwrap();
                txn = store.write().unwrap();
            }
        }
        txn.commit().unwrap();
        let compact = tempfile::tempdir().unwrap();
        store.copy_compact(compact.path()).unwrap();
        let disk = std::fs::metadata(compact.path().join("data.mdb")).unwrap().len() as usize;
        println!("{count} events: {json} bytes of JSON, {disk} bytes on disk ({:.2}x), {} per event", disk as f64 / json as f64, disk / count);
    }

    fn open_sized(map_size: usize) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path(), map_size).unwrap();
        (dir, store)
    }

    #[test]
    fn stamps_sort_by_time_then_sequence() {
        assert!(stamp(1, MAX_SEQ) < stamp(2, 0));
        assert!(stamp(5, 1) < stamp(5, 2));
        assert_eq!(stamp_seq(&stamp(7, MAX_SEQ)), MAX_SEQ);
        assert_eq!(stamp_created_at(&stamp(u32::MAX, 3)), u32::MAX);
    }
}
