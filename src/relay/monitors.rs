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
//!
//! The matching runs on a few shard threads, each owning the subscriptions
//! of its share of the connections, so the writer only queues a batch and
//! gets on with the next commit. Everything a shard does — connections
//! coming and going, subscriptions opening and closing, new events — arrives
//! on one queue, in order, so there's nothing to lock.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::filter::Filter;
use super::policy::{self, Access};
use super::record::EventView;
use super::store::MAX_INDEXED_TAG;

pub type ConnId = u64;

/// What the rest of the relay sends a connection.
#[derive(Debug)]
pub enum Outbound {
    /// A new event for one of its subscriptions.
    Event { sub: Arc<str>, seq: u64, json: Arc<str> },
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

/// Commands a shard may fall behind by before whoever sends the next one
/// waits. The writer waiting is the point: fan-out that can't keep up slows
/// writing rather than queueing without end.
const SHARD_QUEUE: usize = 256;

/// A committed event on its way to live subscriptions.
pub struct Live {
    pub record: Vec<u8>,
    pub seq: u64,
    /// Its JSON, written by whichever shard needs it first.
    json: OnceLock<Arc<str>>,
}

impl Live {
    pub fn new(record: Vec<u8>, seq: u64) -> Live {
        Live { record, seq, json: OnceLock::new() }
    }
}

enum Command {
    Connect(ConnId, Link),
    Disconnect(ConnId),
    Subscribe { conn: ConnId, sub: Arc<str>, filters: Vec<Filter>, installed: oneshot::Sender<()> },
    Unsubscribe(ConnId, String),
    Events(Arc<Vec<Live>>),
}

/// The way to the shards. A connection always goes to the same one.
#[derive(Clone)]
pub struct Hub {
    shards: Arc<[mpsc::Sender<Command>]>,
}

impl Hub {
    /// Start `shards` threads. They run until every `Hub` is dropped.
    pub fn spawn(shards: usize) -> Hub {
        let shards = (0..shards.max(1))
            .map(|i| {
                let (tx, mut rx) = mpsc::channel(SHARD_QUEUE);
                std::thread::Builder::new()
                    .name(format!("relay-monitor-{i}"))
                    .spawn(move || {
                        let mut monitors = Monitors::default();
                        while let Some(command) = rx.blocking_recv() {
                            monitors.handle(command);
                        }
                    })
                    .expect("a thread for the relay's monitors");
                tx
            })
            .collect();
        Hub { shards }
    }

    fn shard(&self, conn: ConnId) -> &mpsc::Sender<Command> {
        &self.shards[(conn % self.shards.len() as u64) as usize]
    }

    pub async fn connect(&self, conn: ConnId, link: Link) {
        let _ = self.shard(conn).send(Command::Connect(conn, link)).await;
    }

    pub async fn disconnect(&self, conn: ConnId) {
        let _ = self.shard(conn).send(Command::Disconnect(conn)).await;
    }

    /// Open a subscription, replacing any of the same id. The receiver
    /// fires once it's live: every event committed after that reaches it.
    pub async fn subscribe(&self, conn: ConnId, sub: Arc<str>, filters: Vec<Filter>) -> oneshot::Receiver<()> {
        let (installed, done) = oneshot::channel();
        let _ = self.shard(conn).send(Command::Subscribe { conn, sub, filters, installed }).await;
        done
    }

    pub async fn unsubscribe(&self, conn: ConnId, sub: &str) {
        let _ = self.shard(conn).send(Command::Unsubscribe(conn, sub.to_string())).await;
    }

    /// Hand events to every shard, waiting if one is behind. Not for async
    /// code: the writer calls it from its own thread.
    pub fn broadcast(&self, events: Vec<Live>) {
        if events.is_empty() {
            return;
        }
        let events = Arc::new(events);
        for shard in self.shards.iter() {
            let _ = shard.blocking_send(Command::Events(events.clone()));
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

/// One shard's subscriptions.
#[derive(Default)]
struct Monitors {
    conns: HashMap<ConnId, Connection>,
    filters: HashMap<u64, Installed>,
    next_key: u64,
    buckets: HashMap<Bucket, HashSet<u64>>,
    /// Keyed by letter ‖ value, in `tag_value` form.
    tags: HashMap<Vec<u8>, HashSet<u64>>,
}

impl Monitors {
    fn handle(&mut self, command: Command) {
        match command {
            Command::Connect(conn, link) => self.connect(conn, link),
            Command::Disconnect(conn) => self.disconnect(conn),
            Command::Subscribe { conn, sub, filters, installed } => {
                self.subscribe(conn, sub, filters);
                let _ = installed.send(());
            }
            Command::Unsubscribe(conn, sub) => self.unsubscribe(conn, &sub),
            Command::Events(events) => {
                for live in events.iter() {
                    let view = EventView::new(&live.record).expect("a record");
                    self.broadcast(&view, live.seq, &live.json);
                }
            }
        }
    }

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

    /// Send a new event to every subscription it matches, writing its JSON
    /// into `json` if no one has yet. Returns how many.
    fn broadcast(&self, event: &EventView, seq: u64, json: &OnceLock<Arc<str>>) -> usize {
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

        let private = policy::access(event.kind()) != Access::Anyone;
        let mut sent = HashSet::new();
        for key in candidates {
            let Some(installed) = self.filters.get(&key) else { continue };
            if sent.contains(&installed.sub_key) || !installed.filter.matches(event) {
                continue;
            }
            if private && !policy::visible(event, &installed.filter) {
                continue;
            }
            let Some(connection) = self.conns.get(&installed.conn) else { continue };
            sent.insert(installed.sub_key);
            let json = json.get_or_init(|| event.to_json().into()).clone();
            connection.link.send(Outbound::Event { sub: installed.sub.clone(), seq, json });
        }
        sent.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Event;
    use crate::relay::record::encode;
    use crate::nostr::event::public_key;
    use crate::relay::store::tests::{ALICE, BOB, tags};
    use serde_json::json;

    const CAROL: &str = "0000000000000000000000000000000000000000000000000000000000000003";

    fn filters(values: &[serde_json::Value]) -> Vec<Filter> {
        values.iter().map(|v| Filter::parse(v).unwrap()).collect()
    }

    fn deliver(monitors: &Monitors, event: &Event) -> usize {
        let record = encode(event);
        monitors.broadcast(&EventView::new(&record).unwrap(), 1, &OnceLock::new())
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
    fn sends_private_events_only_to_filters_that_name_them() {
        let mut monitors = Monitors::default();
        let (alice, bob, carol) = (public_key(ALICE), public_key(BOB), public_key(CAROL));
        let mut receivers = Vec::new();
        let asks = [json!({}), json!({"#p": [bob]}), json!({"authors": [alice]}), json!({"#p": [carol]}), json!({"authors": [carol], "#p": [bob]})];
        for (conn, filter) in (1..).zip(asks) {
            let (link, rx, _) = Link::new(16);
            monitors.connect(conn, link);
            monitors.subscribe(conn, "s".into(), filters(&[filter]));
            receivers.push(rx);
        }
        let wrap = Event::sign(ALICE, 100, 1059, tags(&[&["p", &bob]]), "");
        assert_eq!(deliver(&monitors, &wrap), 2);
        let got: Vec<usize> = receivers.iter_mut().map(|rx| received(rx).len()).collect();
        assert_eq!(got, [0, 1, 1, 0, 0]);
    }

    #[tokio::test]
    async fn routes_through_shards() {
        let hub = Hub::spawn(2);
        let mut receivers = Vec::new();
        for conn in 1..=3 {
            let (link, rx, _) = Link::new(16);
            hub.connect(conn, link).await;
            hub.subscribe(conn, "s".into(), filters(&[json!({"kinds": [1]})])).await.await.unwrap();
            receivers.push(rx);
        }
        hub.unsubscribe(3, "s").await;

        let note = Event::sign(ALICE, 100, 1, vec![], "");
        let events = vec![Live::new(encode(&note), 1), Live::new(encode(&Event::sign(BOB, 100, 7, vec![], "")), 2)];
        let broadcaster = hub.clone();
        tokio::task::spawn_blocking(move || broadcaster.broadcast(events)).await.unwrap();

        for rx in &mut receivers[..2] {
            match rx.recv().await.unwrap() {
                Outbound::Event { sub, seq, json } => {
                    assert_eq!((&*sub, seq), ("s", 1));
                    assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), note);
                }
                other => panic!("unexpected {other:?}"),
            }
        }
        // Once the shards have caught up, nothing else came.
        for conn in 1..=3 {
            hub.subscribe(conn, "sync".into(), vec![]).await.await.unwrap();
        }
        assert!(receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
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
