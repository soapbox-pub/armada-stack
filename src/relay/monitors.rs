//! Live subscriptions, and which of them each new event goes to.
//!
//! Every open filter is filed in a reverse index under one of its fields:
//! its ids if it has them, else its authors, else the values of its
//! narrowest tag, else its kinds. A new event then only has to be checked
//! against the filters filed under its own id, author, tags, and kind (plus
//! the few with none of those) rather than against every subscription.
//!
//! The writer hands committed events straight here, so they go out as soon
//! as they're durable, with no database polling or re-reading, and each
//! event's JSON is written once however many subscriptions get it.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::filter::Filter;
use super::record::EventView;
use super::store::MAX_INDEXED_TAG;

pub type ConnId = u64;

/// What the rest of the relay sends a connection.
#[derive(Debug)]
pub enum Outbound {
    /// A new event for one of its subscriptions. `seq` is `None` for
    /// ephemeral events, which are never stored.
    Event { sub: Arc<str>, seq: Option<u64>, json: Arc<str> },
    /// A message ready to send as is.
    Text(String),
}

/// The way to a connection. Its queue is bounded: a connection that falls
/// so far behind that it fills up is told to go, rather than buffering
/// without end.
#[derive(Clone)]
pub struct Link {
    tx: mpsc::Sender<Outbound>,
    overflow: CancellationToken,
}

impl Link {
    pub fn new(capacity: usize) -> (Link, mpsc::Receiver<Outbound>, CancellationToken) {
        let (tx, rx) = mpsc::channel(capacity);
        let overflow = CancellationToken::new();
        (Link { tx, overflow: overflow.clone() }, rx, overflow)
    }

    pub fn send(&self, message: Outbound) {
        if self.tx.try_send(message).is_err() {
            self.overflow.cancel();
        }
    }
}

struct Installed {
    /// Unique to the subscription, so an event matching several of its
    /// filters is sent once.
    sub_key: u64,
    conn: ConnId,
    sub: Arc<str>,
    filter: Filter,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Bucket {
    Id([u8; 32]),
    Author([u8; 32]),
    Kind(u16),
    Other,
}

struct Connection {
    link: Link,
    /// Subscription id → the keys of its installed filters.
    subs: HashMap<Arc<str>, Vec<u64>>,
}

#[derive(Default)]
pub struct Monitors {
    conns: HashMap<ConnId, Connection>,
    filters: HashMap<u64, Installed>,
    next_key: u64,
    buckets: HashMap<Bucket, HashSet<u64>>,
    /// Keyed by letter ‖ value, in `tag_value` form.
    tags: HashMap<Vec<u8>, HashSet<u64>>,
}

impl Monitors {
    pub fn connect(&mut self, conn: ConnId, link: Link) {
        self.conns.insert(conn, Connection { link, subs: HashMap::new() });
    }

    pub fn disconnect(&mut self, conn: ConnId) {
        if let Some(connection) = self.conns.remove(&conn) {
            for keys in connection.subs.into_values() {
                self.uninstall(keys);
            }
        }
    }

    /// Open a subscription, replacing any of the same id.
    pub fn subscribe(&mut self, conn: ConnId, sub: Arc<str>, filters: Vec<Filter>) {
        self.unsubscribe(conn, &sub);
        if !self.conns.contains_key(&conn) {
            return;
        }
        self.next_key += 1;
        let sub_key = self.next_key;
        let mut keys = Vec::new();
        for filter in filters.into_iter().filter(|f| !f.never) {
            self.next_key += 1;
            let key = self.next_key;
            match &filter {
                Filter { ids: Some(ids), .. } => self.file(ids.iter().map(|id| Bucket::Id(*id)), key),
                Filter { authors: Some(authors), .. } => self.file(authors.iter().map(|a| Bucket::Author(*a)), key),
                Filter { tags, .. } if !tags.is_empty() => {
                    let (letter, values) = tags.iter().min_by_key(|(_, values)| values.len()).unwrap();
                    for value in values {
                        self.tags.entry([&[*letter][..], value].concat()).or_default().insert(key);
                    }
                }
                Filter { kinds: Some(kinds), .. } => self.file(kinds.iter().map(|k| Bucket::Kind(*k)), key),
                _ => self.file([Bucket::Other], key),
            }
            self.filters.insert(key, Installed { sub_key, conn, sub: sub.clone(), filter });
            keys.push(key);
        }
        self.conns.get_mut(&conn).unwrap().subs.insert(sub, keys);
    }

    pub fn unsubscribe(&mut self, conn: ConnId, sub: &str) {
        if let Some(keys) = self.conns.get_mut(&conn).and_then(|c| c.subs.remove(sub)) {
            self.uninstall(keys);
        }
    }

    fn file(&mut self, buckets: impl IntoIterator<Item = Bucket>, key: u64) {
        for bucket in buckets {
            self.buckets.entry(bucket).or_default().insert(key);
        }
    }

    fn uninstall(&mut self, keys: Vec<u64>) {
        for key in keys {
            let Some(installed) = self.filters.remove(&key) else { continue };
            let f = &installed.filter;
            let mut unfile = |bucket| {
                if let Some(set) = self.buckets.get_mut(&bucket) {
                    set.remove(&key);
                    if set.is_empty() {
                        self.buckets.remove(&bucket);
                    }
                }
            };
            if let Some(ids) = &f.ids {
                ids.iter().for_each(|id| unfile(Bucket::Id(*id)));
            } else if let Some(authors) = &f.authors {
                authors.iter().for_each(|a| unfile(Bucket::Author(*a)));
            } else if !f.tags.is_empty() {
                let (letter, values) = f.tags.iter().min_by_key(|(_, values)| values.len()).unwrap();
                for value in values {
                    let tag = [&[*letter][..], value].concat();
                    if let Some(set) = self.tags.get_mut(&tag) {
                        set.remove(&key);
                        if set.is_empty() {
                            self.tags.remove(&tag);
                        }
                    }
                }
            } else if let Some(kinds) = &f.kinds {
                kinds.iter().for_each(|k| unfile(Bucket::Kind(*k)));
            } else {
                unfile(Bucket::Other);
            }
        }
    }

    /// Send a new event to every subscription it matches. Returns how many.
    pub fn broadcast(&self, event: &EventView, seq: Option<u64>) -> usize {
        let mut candidates: Vec<u64> = Vec::new();
        for bucket in [Bucket::Id(*event.id()), Bucket::Author(*event.pubkey()), Bucket::Kind(event.kind()), Bucket::Other] {
            if let Some(set) = self.buckets.get(&bucket) {
                candidates.extend(set);
            }
        }
        if !self.tags.is_empty() {
            let mut tag = Vec::new();
            for (letter, value) in event.indexed_tags() {
                if value.encoded_len() > MAX_INDEXED_TAG {
                    continue;
                }
                tag.clear();
                tag.push(letter);
                value.encode(&mut tag);
                if let Some(set) = self.tags.get(&tag) {
                    candidates.extend(set);
                }
            }
        }
        if candidates.is_empty() {
            return 0;
        }
        candidates.sort_unstable();
        candidates.dedup();

        let mut json: Option<Arc<str>> = None;
        let mut sent = HashSet::new();
        for key in candidates {
            let Some(installed) = self.filters.get(&key) else { continue };
            if sent.contains(&installed.sub_key) || !installed.filter.matches(event) {
                continue;
            }
            sent.insert(installed.sub_key);
            let json = json.get_or_insert_with(|| event.to_json().into()).clone();
            if let Some(connection) = self.conns.get(&installed.conn) {
                connection.link.send(Outbound::Event { sub: installed.sub.clone(), seq, json });
            }
        }
        sent.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Event;
    use crate::relay::record::encode;
    use crate::relay::store::tests::{ALICE, BOB, tags};
    use serde_json::json;

    fn filters(values: &[serde_json::Value]) -> Vec<Filter> {
        values.iter().map(|v| Filter::parse(v).unwrap()).collect()
    }

    fn deliver(monitors: &Monitors, event: &Event) -> usize {
        let record = encode(event);
        monitors.broadcast(&EventView::new(&record).unwrap(), Some(1))
    }

    fn received(rx: &mut mpsc::Receiver<Outbound>) -> Vec<String> {
        let mut subs = Vec::new();
        while let Ok(Outbound::Event { sub, .. }) = rx.try_recv() {
            subs.push(sub.to_string());
        }
        subs
    }

    #[test]
    fn sends_each_subscription_an_event_once() {
        let mut monitors = Monitors::default();
        let (link, mut rx, _) = Link::new(16);
        monitors.connect(1, link);

        let note = Event::sign(ALICE, 100, 1, tags(&[&["t", "a"], &["t", "b"]]), "");
        let alice = &note.pubkey;
        monitors.subscribe(1, "everything".into(), filters(&[json!({})]));
        monitors.subscribe(1, "twice".into(), filters(&[json!({"#t": ["a", "b"]}), json!({"authors": [alice]})]));
        monitors.subscribe(1, "kinds".into(), filters(&[json!({"kinds": [1], "since": 50})]));
        monitors.subscribe(1, "other".into(), filters(&[json!({"kinds": [7]}), json!({"ids": ["ab".repeat(32)]})]));
        monitors.subscribe(1, "never".into(), filters(&[json!({"authors": []})]));

        assert_eq!(deliver(&monitors, &note), 3);
        let mut subs = received(&mut rx);
        subs.sort();
        assert_eq!(subs, ["everything", "kinds", "twice"]);

        // Closing and replacing take effect.
        monitors.unsubscribe(1, "everything");
        monitors.subscribe(1, "kinds".into(), filters(&[json!({"kinds": [1], "since": 500})]));
        assert_eq!(deliver(&monitors, &note), 1);
        assert_eq!(received(&mut rx), ["twice"]);
        assert_eq!(monitors.conns[&1].subs.len(), 4);

        monitors.disconnect(1);
        assert_eq!(deliver(&monitors, &Event::sign(BOB, 100, 7, vec![], "")), 0);
        assert!(monitors.filters.is_empty() && monitors.buckets.is_empty() && monitors.tags.is_empty());
    }

    #[test]
    fn signals_a_connection_that_falls_behind() {
        let mut monitors = Monitors::default();
        let (link, _rx, overflow) = Link::new(1);
        monitors.connect(1, link);
        monitors.subscribe(1, "s".into(), filters(&[json!({})]));
        deliver(&monitors, &Event::sign(ALICE, 1, 1, vec![], ""));
        assert!(!overflow.is_cancelled());
        deliver(&monitors, &Event::sign(ALICE, 2, 1, vec![], ""));
        assert!(overflow.is_cancelled());
    }
}
