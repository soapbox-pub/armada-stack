//! The one thread that writes to the store.
//!
//! LMDB allows a single writer anyway, so rather than have connections take
//! turns, they queue verified events here and this thread commits whatever
//! has piled up in one transaction: under load, one fsync covers many
//! events. Once a batch is durable it answers each event's `OK` and queues
//! the batch for the [monitors](super::monitors), whose threads match it
//! against live subscriptions while this one moves on to the next commit.
//!
//! Ephemeral events take the same path, minus the store, so they're relayed
//! in the order they arrived relative to stored ones.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TrySendError, sync_channel};
use std::time::{Duration, Instant};

use super::monitors::{Hub, Link, Live, Outbound};
use super::record::{self, EventView};
use super::store::{Outcome, Store};
use crate::util::now;

/// Events that may wait for the writer. Past this, publishers are told the
/// relay is busy rather than queued without end.
const QUEUE: usize = 8192;

/// The most events committed together.
const MAX_BATCH: usize = 1024;

/// How often expired events are swept out.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

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
            sweep(store);
            next_sweep = Instant::now() + SWEEP_INTERVAL;
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
        Ok(outcomes) => outcomes,
        Err(error) => {
            tracing::error!(%error, events = batch.len(), "could not store events");
            for submission in &batch {
                let id = hex::encode(EventView::new(&submission.record).expect("a record").id());
                submission.reply.send(Outbound::Text(ok(&id, false, "error: could not store the event")));
            }
            return;
        }
    };

    let mut live = Vec::new();
    for (submission, outcome) in batch.into_iter().zip(outcomes) {
        let id = hex::encode(EventView::new(&submission.record).expect("a record").id());
        let (accepted, message, seq) = match outcome {
            None => (true, "", None),
            Some(Outcome::Stored(seq)) => (true, "", Some(seq)),
            Some(Outcome::Duplicate) => (true, "duplicate: already have this event", None),
            Some(Outcome::Replaced) => (false, "duplicate: already have a newer version of this event", None),
            Some(Outcome::Deleted) => (false, "blocked: this event has been deleted", None),
        };
        submission.reply.send(Outbound::Text(ok(&id, accepted, message)));
        if outcome.is_none() || seq.is_some() {
            live.push(Live::new(submission.record, seq));
        }
    }
    hub.broadcast(live);
}

/// Store a batch in one transaction. `None` for ephemeral events, which
/// aren't stored.
fn store_batch(store: &Store, batch: &[Submission]) -> super::lmdb::Result<Vec<Option<Outcome>>> {
    let mut txn = store.write()?;
    let mut outcomes = Vec::with_capacity(batch.len());
    for submission in batch {
        let kind = EventView::new(&submission.record).expect("a record").kind();
        outcomes.push(if record::is_ephemeral(kind) { None } else { Some(store.insert(&mut txn, &submission.record)?) });
    }
    if outcomes.iter().any(Option::is_some) {
        txn.commit()?;
    }
    Ok(outcomes)
}

fn sweep(store: &Store) {
    let result = (|| {
        let mut txn = store.write()?;
        let removed = store.sweep_expired(&mut txn, now())?;
        if removed > 0 {
            txn.commit()?;
        }
        Ok::<_, super::lmdb::Error>(removed)
    })();
    match result {
        Ok(0) => {}
        Ok(removed) => tracing::debug!(removed, "swept expired events"),
        Err(error) => tracing::error!(%error, "could not sweep expired events"),
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
    use crate::relay::store::tests::{ALICE, open};

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
        let ephemeral = Event::sign(ALICE, 100, 20_001, vec![], "typing");
        for event in [&note, &note, &ephemeral] {
            assert!(writer.submit(Submission { record: record::encode(event), reply: link.clone() }).is_ok());
        }

        let mut messages = Vec::new();
        while messages.len() < 5 {
            messages.push(rx.recv().await.unwrap());
        }
        let oks: Vec<_> = messages.iter().filter_map(|m| if let Outbound::Text(t) = m { Some(t.as_str()) } else { None }).collect();
        assert_eq!(oks[0], ok(&note.id, true, ""));
        assert_eq!(oks[1], ok(&note.id, true, "duplicate: already have this event"));
        assert_eq!(oks[2], ok(&ephemeral.id, true, ""));
        let seqs: Vec<_> = messages.iter().filter_map(|m| if let Outbound::Event { seq, .. } = m { Some(*seq) } else { None }).collect();
        assert_eq!(seqs, [Some(1), None]);

        let txn = store.read().unwrap();
        assert_eq!(store.len(&txn).unwrap(), 1);
    }
}
