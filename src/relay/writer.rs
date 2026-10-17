//! The one thread that writes to the store.
//!
//! LMDB allows a single writer anyway, so rather than have connections take
//! turns, they queue verified events here and this thread commits whatever
//! has piled up in one transaction: under load, one fsync covers many
//! events. Once a batch is durable it answers each event's `OK` and queues
//! the batch for the [monitors](super::monitors), whose threads match it
//! against live subscriptions while this one moves on to the next commit.
//!
//! Ephemeral events are stored too, briefly, so a client that reconnects can
//! catch up on them.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use super::monitors::{Hub, Link, Live, Outbound};
use super::record::EventView;
use super::store::{Outcome, SWEEP_BATCH, Store};
use crate::util::now;

/// Events that may wait for the writer. Past this, publishers are told the
/// relay is busy rather than queued without end.
const QUEUE: usize = 8192;

/// The most events committed together.
const MAX_BATCH: usize = 1024;

/// How often expired events are swept out. A sweep that finds more than it
/// may remove at once goes again after the next batch of writes instead,
/// until it catches up: ephemeral wraps all expire within minutes, and a
/// busy relay makes plenty.
const SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// A verified event, encoded, and where to send its `OK`.
pub struct Submission {
    pub record: Vec<u8>,
    pub reply: Link,
}

#[derive(Clone)]
pub struct Writer {
    tx: SyncSender<Submission>,
}

impl Writer {
    /// Start the thread. It runs until every `Writer` is dropped.
    pub fn spawn(store: Arc<Store>, hub: Hub) -> Writer {
        let (tx, rx) = sync_channel(QUEUE);
        std::thread::Builder::new()
            .name("relay-writer".into())
            .spawn(move || run(&store, &hub, rx))
            .expect("a thread for the relay's writer");
        Writer { tx }
    }

    /// Queue an event. Gives it back if the queue is full.
    pub fn submit(&self, submission: Submission) -> Result<(), Submission> {
        self.tx.try_send(submission).map_err(|error| match error {
            TrySendError::Full(s) | TrySendError::Disconnected(s) => s,
        })
    }
}

fn run(store: &Store, hub: &Hub, rx: Receiver<Submission>) {
    let mut next_sweep = Instant::now();
    loop {
        if Instant::now() >= next_sweep {
            let behind = sweep(store);
            next_sweep = if behind { Instant::now() } else { Instant::now() + SWEEP_INTERVAL };
        }
        let first = match rx.recv_timeout(next_sweep.saturating_duration_since(Instant::now())) {
            Ok(submission) => submission,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let mut batch = vec![first];
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(submission) => batch.push(submission),
                Err(_) => break,
            }
        }
        write(store, hub, batch);
    }
}

fn write(store: &Store, hub: &Hub, batch: Vec<Submission>) {
    let outcomes = match store_batch(store, &batch) {
        Ok(outcomes) => outcomes.into_iter().map(Ok).collect(),
        // One event's failure fails the transaction, and with it everyone
        // else's in the batch. So each goes again in one of its own, and
        // only the one that can't be stored is refused.
        Err(error) if batch.len() > 1 => {
            tracing::warn!(%error, events = batch.len(), "could not store a batch; storing its events one at a time");
            batch.iter().map(|submission| store_batch(store, std::slice::from_ref(submission)).map(|mut outcome| outcome.remove(0))).collect()
        }
        Err(error) => vec![Err(error)],
    };

    let mut live = Vec::new();
    for (submission, outcome) in batch.into_iter().zip(outcomes) {
        let id = hex::encode(EventView::new(&submission.record).expect("a record").id());
        let (accepted, message) = match outcome {
            Ok(Outcome::Stored(_) | Outcome::Vanished) => (true, ""),
            Ok(Outcome::Duplicate) => (true, "duplicate: already have this event"),
            Ok(Outcome::Replaced) => (false, "duplicate: already have a newer version of this event"),
            Ok(Outcome::Deleted) => (false, "blocked: this event has been deleted"),
            Ok(Outcome::Banned) => (false, "blocked: banned by this relay's operator"),
            Err(error) => {
                tracing::error!(%error, %id, "could not store an event");
                (false, "error: could not store the event")
            }
        };
        submission.reply.send(Outbound::Text(ok(&id, accepted, message)));
        if let Ok(Outcome::Stored(seq)) = outcome {
            live.push(Live::new(submission.record, seq));
        }
    }
    hub.broadcast(live);
}

/// Store a batch in one transaction.
fn store_batch(store: &Store, batch: &[Submission]) -> super::lmdb::Result<Vec<Outcome>> {
    let mut txn = store.write()?;
    let outcomes = batch.iter().map(|submission| store.insert(&mut txn, &submission.record)).collect::<Result<Vec<_>, _>>()?;
    txn.commit()?;
    Ok(outcomes)
}

/// Remove a batch of expired events, and carry requests to vanish on by
/// another step. Returns whether there may be more of either.
fn sweep(store: &Store) -> bool {
    let result = (|| {
        let mut txn = store.write()?;
        let removed = store.sweep_expired(&mut txn, now())?;
        let vanishing = store.sweep_vanishing(&mut txn, SWEEP_BATCH)?;
        if removed > 0 || vanishing > 0 {
            txn.commit()?;
        }
        Ok::<_, super::lmdb::Error>((removed, vanishing))
    })();
    match result {
        Ok((0, 0)) => false,
        Ok((removed, vanishing)) => {
            tracing::debug!(removed, vanishing, "swept expired events and requests to vanish");
            removed == SWEEP_BATCH || vanishing == SWEEP_BATCH
        }
        Err(error) => {
            tracing::error!(%error, "could not sweep expired events");
            false
        }
    }
}

/// An `OK` message.
pub fn ok(id: &str, accepted: bool, message: &str) -> String {
    serde_json::json!(["OK", id, accepted, message]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::Event;
    use crate::relay::filter::Filter;
    use crate::relay::record;
    use crate::relay::store::tests::{ALICE, open, tags};

    #[tokio::test]
    async fn stores_then_answers_and_broadcasts() {
        let (_dir, store) = open();
        let store = Arc::new(store);
        let hub = Hub::spawn(1);
        let writer = Writer::spawn(store.clone(), hub.clone());

        let (link, mut rx, _) = Link::new(16);
        hub.connect(1, link.clone()).await;
        hub.subscribe(1, "s".into(), vec![Filter::parse(&serde_json::json!({})).unwrap()]).await.await.unwrap();

        let note = Event::sign(ALICE, 100, 1, vec![], "hi");
        let vanish = Event::sign(ALICE, 50, 62, tags(&[&["relay", "ALL_RELAYS"]]), "");
        let ephemeral = Event::sign(ALICE, 100, 20_001, vec![], "typing");
        for event in [&note, &note, &vanish, &ephemeral] {
            assert!(writer.submit(Submission { record: record::encode(event), reply: link.clone() }).is_ok());
        }

        let mut messages = Vec::new();
        while messages.len() < 6 {
            messages.push(rx.recv().await.unwrap());
        }
        let oks: Vec<_> = messages.iter().filter_map(|m| if let Outbound::Text(t) = m { Some(t.as_str()) } else { None }).collect();
        assert_eq!(oks[0], ok(&note.id, true, ""));
        assert_eq!(oks[1], ok(&note.id, true, "duplicate: already have this event"));
        assert_eq!(oks[2], ok(&vanish.id, true, ""));
        assert_eq!(oks[3], ok(&ephemeral.id, true, ""));
        // Requests to vanish are carried out, but neither kept nor relayed.
        let seqs: Vec<_> = messages.iter().filter_map(|m| if let Outbound::Event { seq, .. } = m { Some(*seq) } else { None }).collect();
        assert_eq!(seqs, [1, 2]);

        let txn = store.read().unwrap();
        assert_eq!(store.len(&txn).unwrap(), 2);
    }

    /// An event that can't be stored is refused alone, not with the rest
    /// of its batch.
    #[tokio::test]
    async fn one_failure_fails_only_its_own_event() {
        let dir = tempfile::tempdir().unwrap();
        // Room for small events, not for a big one.
        let store = Arc::new(Store::open(dir.path(), 1 << 20).unwrap());
        let hub = Hub::spawn(1);
        let (link, mut rx, _) = Link::new(16);
        let batch: Vec<Event> = vec![
            Event::sign(ALICE, 100, 1, vec![], "small"),
            Event::sign(ALICE, 100, 1, vec![], &"x".repeat(2 << 20)),
            Event::sign(ALICE, 100, 1, vec![], "also small"),
        ];
        let submissions = batch.iter().map(|event| Submission { record: record::encode(event), reply: link.clone() }).collect();
        let (writing, written) = (store.clone(), hub.clone());
        // As on the writer's own thread: broadcasting blocks.
        tokio::task::spawn_blocking(move || write(&writing, &written, submissions)).await.unwrap();
        let mut oks = Vec::new();
        while oks.len() < 3 {
            if let Outbound::Text(text) = rx.recv().await.unwrap() {
                oks.push(text);
            }
        }
        assert_eq!(oks[0], ok(&batch[0].id, true, ""));
        assert_eq!(oks[1], ok(&batch[1].id, false, "error: could not store the event"));
        assert_eq!(oks[2], ok(&batch[2].id, true, ""));
        assert_eq!(store.len(&store.read().unwrap()).unwrap(), 2);
    }

    /// A backlog of more than one sweep's worth goes in one go, not one
    /// batch per interval.
    #[tokio::test]
    async fn sweeps_a_backlog_without_waiting() {
        let (_dir, store) = open();
        let mut txn = store.write().unwrap();
        for i in 0..SWEEP_BATCH * 2 + 10 {
            let event = Event::sign(ALICE, 100, 1, tags(&[&["expiration", "1000"]]), &i.to_string());
            store.insert(&mut txn, &record::encode(&event)).unwrap();
        }
        txn.commit().unwrap();
        let store = Arc::new(store);
        let _writer = Writer::spawn(store.clone(), Hub::spawn(1));

        let deadline = Instant::now() + Duration::from_secs(5);
        while store.len(&store.read().unwrap()).unwrap() > 0 {
            assert!(Instant::now() < deadline, "the backlog wasn't swept in time");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
