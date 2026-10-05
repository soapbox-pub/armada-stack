//! One client's WebSocket: NIP-01's EVENT, REQ, and CLOSE.
//!
//! There's no NIP-42 AUTH. A relay that has readers sign in ties each one's
//! key to the address it connects from, which plain REQs and EVENTs never
//! do: anyone may ask for anything, or send any signed event, so neither
//! says whose it is. What may be read is up to the filter alone
//! ([`policy::scope`]).
//!
//! Events get their cheap checks here, on the connection's own task. The
//! rest — the duplicate lookup, which reads the map and can stall on disk,
//! and the signature — runs on the blocking pool, a few at a time, so the
//! writer only ever sees valid events and no async thread waits on either.
//! Queries run there too.
//!
//! A REQ's subscription goes live *before* its query reads the store: the
//! query waits until its monitor shard confirms it's installed, so every
//! event committed after the query's snapshot reaches the subscription. The
//! events that arrive for it meanwhile wait until the query's EOSE. Live
//! events the query already saw (by sequence number) are dropped, then and
//! after — a shard can deliver an event committed just before the snapshot
//! well after EOSE — so nothing is missed between the two and nothing is
//! sent twice.
//!
//! A query stops as soon as nobody wants its results: when its subscription
//! is closed or replaced, or the connection goes. Until it does it holds one
//! of its client's few query places ([`Slot::queries`]) and a core.
//!
//! A client that stops reading is dropped, rather than left holding what's
//! waiting for it: every write has [`WRITE_TIMEOUT`] to go out. One that
//! goes silent altogether, without closing, is pinged every
//! [`PING_INTERVAL`] and dropped if it doesn't answer.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, StreamExt};
use futures_util::SinkExt;
use serde_json::Value;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::Shared;
use super::clients::Slot;
use super::filter::Filter;
use super::monitors::{ConnId, Link, Outbound};
use super::policy;
use super::query::{self, Results};
use super::record;
use super::writer::{Submission, ok};
use crate::nostr::Event;
use crate::nostr::event::is_hex64;
use crate::ratelimit::TokenBucket;
use crate::util::now;

/// Messages waiting to go out to one client, beyond which it's dropped.
const OUTBOUND: usize = 4096;

/// The longest subscription id NIP-01 allows.
const MAX_SUB_ID: usize = 64;

/// How long one write to the socket may take — one message, or a query's
/// results all together — before the client is taken to have stopped
/// reading.
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);

/// How often a client is pinged. One not heard from in two of these, pong
/// or otherwise, is gone.
const PING_INTERVAL: Duration = Duration::from_secs(60);

/// Messages of any sort one connection may send a minute, in bursts of as
/// many: each costs a parse, whatever it turns out to be, and not every
/// sort has a budget of its own.
const MESSAGES_PER_MINUTE: u32 = 3000;

/// The most live events held for one subscription while its query runs.
/// Past this the subscription is closed: its client can ask again.
const MAX_PENDING: usize = OUTBOUND;

/// A connection's side of the socket has gone; stop.
struct Gone;

type Sink = SplitSink<WebSocket, Message>;

struct Sub {
    /// This REQ's own name: a later REQ of the same id gets a new one, so
    /// events and results meant for the old can be told apart.
    name: Arc<str>,
    /// The id as JSON, ready to splice into messages.
    json: String,
    /// Live events held until the query's EOSE.
    pending: Option<Vec<(u64, Arc<str>)>>,
    /// The query's snapshot: stored events below this were sent with it.
    floor: u64,
    /// Stops its query.
    cancel: CancellationToken,
    /// Filter values it holds of its client's ([`Slot::hold_values`]).
    values: usize,
}

struct Session {
    shared: Arc<Shared>,
    id: ConnId,
    link: Link,
    sink: Sink,
    subs: HashMap<String, Sub>,
    /// Its events.
    tokens: TokenBucket,
    /// Its messages of every sort.
    messages: TokenBucket,
    /// This connection, counted against its client's address, whose event
    /// budget it shares.
    slot: Slot,
    /// Stops every query of this connection's, once it goes.
    cancel: CancellationToken,
}

type QueryDone = (Arc<str>, anyhow::Result<Results>);

pub async fn serve(shared: Arc<Shared>, socket: WebSocket, slot: Slot) {
    let id = shared.next_conn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (link, mut rx, overflow) = Link::new(OUTBOUND);
    let (sink, mut stream) = socket.split();
    shared.hub.connect(id, link.clone()).await;
    let tokens = TokenBucket::new(shared.config.events_per_minute, Instant::now());
    let messages = TokenBucket::new(MESSAGES_PER_MINUTE, Instant::now());
    let cancel = shared.cancel.clone();
    let mut session = Session { shared, id, link, sink, subs: HashMap::new(), tokens, messages, slot, cancel: CancellationToken::new() };
    let mut queries: JoinSet<QueryDone> = JoinSet::new();
    let mut ping = tokio::time::interval_at(tokio::time::Instant::now() + PING_INTERVAL, PING_INTERVAL);
    let mut heard = Instant::now();

    loop {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            _ = overflow.cancelled() => {
                tracing::debug!(conn = id, "dropping a client that fell too far behind");
                break;
            }
            _ = ping.tick() => {
                if heard.elapsed() > 2 * PING_INTERVAL {
                    tracing::debug!(conn = id, "dropping a client that went silent");
                    break;
                }
                write_within(session.sink.send(Message::Ping(Default::default()))).await
            }
            message = stream.next() => {
                heard = Instant::now();
                match message {
                    Some(Ok(Message::Text(text))) => session.on_text(&text, &mut queries).await,
                    Some(Ok(Message::Binary(_))) => session.notice("invalid: messages must be text").await,
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(()),
                    Some(Ok(Message::Close(_)) | Err(_)) | None => break,
                }
            }
            Some(outbound) = rx.recv() => session.on_outbound(outbound).await,
            Some(done) = queries.join_next(), if !queries.is_empty() => match done {
                Ok((name, results)) => session.on_results(name, results).await,
                Err(_) => Ok(()),
            },
        };
        if result.is_err() {
            break;
        }
    }

    // Dropping `queries` drops their tasks, but not what they left running
    // on the blocking pool.
    session.cancel.cancel();
    session.shared.hub.disconnect(id).await;
    let _ = tokio::time::timeout(WRITE_TIMEOUT, session.sink.close()).await;
}

/// A write to the socket, within [`WRITE_TIMEOUT`].
async fn write_within<T, E>(write: impl Future<Output = Result<T, E>>) -> Result<T, Gone> {
    match tokio::time::timeout(WRITE_TIMEOUT, write).await {
        Ok(Ok(written)) => Ok(written),
        _ => Err(Gone),
    }
}

impl Session {
    async fn send(&mut self, text: String) -> Result<(), Gone> {
        write_within(self.sink.send(Message::Text(text.into()))).await
    }

    async fn notice(&mut self, message: &str) -> Result<(), Gone> {
        self.send(serde_json::json!(["NOTICE", message]).to_string()).await
    }

    async fn closed(&mut self, sub: &str, message: &str) -> Result<(), Gone> {
        self.send(serde_json::json!(["CLOSED", sub, message]).to_string()).await
    }

    async fn on_text(&mut self, text: &str, queries: &mut JoinSet<QueryDone>) -> Result<(), Gone> {
        if !self.messages.take(Instant::now()) {
            return self.notice("rate-limited: too many messages; slow down").await;
        }
        let Ok(Value::Array(message)) = serde_json::from_str::<Value>(text) else {
            return self.notice("invalid: a message must be a JSON array").await;
        };
        match message.first().and_then(Value::as_str) {
            Some("EVENT") => self.on_event(message.get(1)).await,
            Some("REQ") => self.on_req(&message, queries).await,
            Some("COUNT") => match message.get(1).and_then(Value::as_str) {
                Some(sub) => self.closed(sub, "unsupported: COUNT isn't supported").await,
                None => self.notice("invalid: COUNT needs a subscription id").await,
            },
            Some("CLOSE") => {
                if let Some(sub) = message.get(1).and_then(Value::as_str) {
                    self.end(sub).await;
                }
                Ok(())
            }
            Some(other) => self.notice(&format!("unsupported: {other} messages")).await,
            None => self.notice("invalid: a message must start with its type").await,
        }
    }

    /// Close a subscription, and stop its query. One the connection doesn't
    /// have costs nothing, so a flood of them can't crowd the shards' queues.
    async fn end(&mut self, sub: &str) {
        if self.forget(sub) {
            self.shared.hub.unsubscribe(self.id, sub).await;
        }
    }

    /// Stop a subscription's query and give back its values, leaving the
    /// shard to whoever replaces or unsubscribes it. Returns whether there
    /// was one.
    fn forget(&mut self, sub: &str) -> bool {
        let Some(sub) = self.subs.remove(sub) else { return false };
        sub.cancel.cancel();
        self.slot.release_values(sub.values);
        true
    }

    async fn on_event(&mut self, event: Option<&Value>) -> Result<(), Gone> {
        let event = match event.map(|e| serde_json::from_value::<Event>(e.clone())) {
            Some(Ok(event)) => event,
            _ => {
                let id = event.and_then(|e| e.get("id")).and_then(Value::as_str).filter(|id| is_hex64(id));
                return match id {
                    Some(id) => self.send(ok(id, false, "invalid: not a well-formed event")).await,
                    None => self.notice("invalid: not a well-formed event").await,
                };
            }
        };

        if let Err(message) = self.screen(&event) {
            return self.send(ok(&event.id, false, &message)).await;
        }
        // Waiting here slows only this client when verifiers are scarce.
        let Ok(permit) = self.shared.verifiers.clone().acquire_owned().await else { return Ok(()) };
        let (shared, link) = (self.shared.clone(), self.link.clone());
        tokio::task::spawn_blocking(move || {
            admit(&shared, event, link);
            drop(permit);
        });
        Ok(())
    }

    /// Every check short of the signature, and the rate limit. Errors are
    /// the `OK` message to refuse with.
    fn screen(&mut self, event: &Event) -> Result<(), String> {
        let config = &self.shared.config;
        let now = now();
        if !well_formed(event) {
            return Err("invalid: id, pubkey, and sig must be lowercase hex".into());
        }
        if !(0..=i64::from(u32::MAX)).contains(&event.created_at) {
            return Err("invalid: created_at is out of range".into());
        }
        if event.created_at > now.saturating_add(config.created_at_upper_limit as i64) {
            return Err("invalid: created_at is too far in the future".into());
        }
        if event.tags.len() > config.max_event_tags {
            return Err("invalid: too many tags".into());
        }
        if event.content.len() > config.max_content_length {
            return Err("invalid: content is too long".into());
        }
        // Never the request's `Host`: anyone can send any, and with it
        // replay a request to vanish meant for another relay.
        policy::validate(event, now, &self.shared.authorities)?;
        if record::expiration(event).is_some_and(|expiration| i64::from(expiration) <= now) {
            return Err("invalid: event has expired".into());
        }
        let instant = Instant::now();
        if !self.tokens.take(instant) || !self.slot.take_event(event_bytes(event), instant) {
            return Err("rate-limited: slow down".into());
        }
        Ok(())
    }

    async fn on_req(&mut self, message: &[Value], queries: &mut JoinSet<QueryDone>) -> Result<(), Gone> {
        let config = &self.shared.config;
        let Some(sub) = message.get(1).and_then(Value::as_str) else {
            return self.notice("invalid: REQ needs a subscription id").await;
        };
        if sub.is_empty() || sub.chars().count() > MAX_SUB_ID {
            return self.notice("invalid: subscription ids are 1 to 64 characters").await;
        }
        let sub = sub.to_string();
        if message.len() - 2 > config.max_filters {
            return self.closed(&sub, "invalid: too many filters").await;
        }
        // Before parsing, which is most of what a refused one would cost.
        if !self.slot.take_req(Instant::now()) {
            self.end(&sub).await;
            return self.closed(&sub, "rate-limited: slow down").await;
        }
        let scoped = |value| {
            let mut filter = Filter::parse(value)?;
            policy::scope(&mut filter)?;
            Ok::<_, String>(filter)
        };
        let filters = match message[2..].iter().map(scoped).collect::<Result<Vec<_>, _>>() {
            Ok(filters) => filters,
            Err(error) => {
                self.end(&sub).await;
                return self.closed(&sub, &error).await;
            }
        };
        let values = filters.iter().map(Filter::values).sum();
        if values > config.max_filter_values {
            let message = format!("invalid: filters list more than {} values", config.max_filter_values);
            self.end(&sub).await;
            return self.closed(&sub, &message).await;
        }
        if !self.subs.contains_key(&sub) && self.subs.len() >= config.max_subscriptions {
            return self.closed(&sub, "rate-limited: too many open subscriptions").await;
        }
        // What it replaces gives its values back first.
        self.forget(&sub);
        if !self.slot.hold_values(values) {
            self.end(&sub).await;
            return self.closed(&sub, "rate-limited: too many filter values in open subscriptions; close some").await;
        }

        let name: Arc<str> = sub.as_str().into();
        let json = serde_json::to_string(&sub).expect("strings serialize");
        let cancel = self.cancel.child_token();
        self.subs.insert(sub, Sub { name: name.clone(), json, pending: Some(Vec::new()), floor: 0, cancel: cancel.clone(), values });
        // Live first, then the query: see the module docs. Queued from here
        // rather than the query's task, so a later CLOSE or REQ of the same id
        // reaches the shard after it.
        let installed = self.shared.hub.subscribe(self.id, name.clone(), filters.clone()).await;

        let shared = self.shared.clone();
        let place = self.slot.queries.clone();
        queries.spawn(async move {
            let query = async {
                installed.await?;
                // One of the client's own places first, then a core.
                let place = match place {
                    Some(places) => Some(places.acquire_owned().await?),
                    None => None,
                };
                let core = shared.queries.clone().acquire_owned().await?;
                let (store, max_limit, cancel) = (shared.store.clone(), shared.config.max_limit, cancel.clone());
                Ok(tokio::task::spawn_blocking(move || {
                    // Held until the query stops, which may be a moment
                    // after it's cancelled.
                    let _held = (place, core);
                    query::run(&store, &filters, max_limit, now(), &cancel)
                })
                .await??)
            };
            let results = cancel.run_until_cancelled(query).await.unwrap_or_else(|| Err(anyhow::anyhow!("cancelled")));
            (name, results)
        });
        Ok(())
    }

    async fn on_results(&mut self, name: Arc<str>, results: anyhow::Result<Results>) -> Result<(), Gone> {
        // Closed or replaced while it ran.
        let Some(sub) = self.subs.get_mut(&*name).filter(|sub| Arc::ptr_eq(&sub.name, &name)) else { return Ok(()) };
        let results = match results {
            Ok(results) => results,
            Err(error) => {
                tracing::error!(%error, "a query failed");
                self.end(&name).await;
                return self.closed(&name, "error: could not run the query").await;
            }
        };
        let pending = sub.pending.take().unwrap_or_default();
        sub.floor = results.next_seq;
        let sub_json = sub.json.clone();

        let sink = &mut self.sink;
        // All of it within one timeout, so a client reading just fast enough
        // to keep each message from timing out can't hold its results for long.
        write_within(async move {
            for json in &results.events {
                sink.feed(Message::Text(event_message(&sub_json, json).into())).await?;
            }
            sink.feed(Message::Text(format!("[\"EOSE\",{sub_json}]").into())).await?;
            for (seq, json) in pending {
                // Stored events the query could see were sent with it.
                if seq >= results.next_seq {
                    sink.feed(Message::Text(event_message(&sub_json, &json).into())).await?;
                }
            }
            sink.flush().await
        })
        .await
    }

    async fn on_outbound(&mut self, outbound: Outbound) -> Result<(), Gone> {
        match outbound {
            Outbound::Text(text) => self.send(text).await,
            Outbound::Event { sub, seq, json } => {
                let Some(state) = self.subs.get_mut(&*sub).filter(|state| Arc::ptr_eq(&state.name, &sub)) else { return Ok(()) };
                match &mut state.pending {
                    Some(pending) if pending.len() >= MAX_PENDING => {
                        self.end(&sub).await;
                        self.closed(&sub, "error: too many new events arrived while the query ran; ask again").await
                    }
                    Some(pending) => {
                        pending.push((seq, json));
                        Ok(())
                    }
                    None if seq < state.floor => Ok(()),
                    None => {
                        let message = event_message(&state.json, &json);
                        self.send(message).await
                    }
                }
            }
        }
    }
}

/// Look for an event, verify it, and queue it for the writer, answering
/// through `link` if it goes no further. Blocks: run it off the async
/// threads.
fn admit(shared: &Shared, event: Event, link: Link) {
    let refuse = |accepted, message| link.send(Outbound::Text(ok(&event.id, accepted, message)));
    let mut id = [0; 32];
    hex::decode_to_slice(&event.id, &mut id).expect("screened hex");
    // Resent events are common and cost a signature check each, so look
    // first: one with the stored copy's signature is that event, already
    // verified. A forgery of a stored id is checked like any other event,
    // so the answer doesn't say what's stored, which for gift wraps and
    // the like a filter alone may not.
    let store = &shared.store;
    let stored_sig = store.read().and_then(|txn| Ok(store.seq_of(&txn, &id)?.and_then(|seq| store.load(&txn, seq).ok().flatten()).map(|view| *view.sig())));
    let mut sig = [0; 64];
    hex::decode_to_slice(&event.sig, &mut sig).expect("screened hex");
    if stored_sig.ok().flatten() == Some(sig) {
        return refuse(true, "duplicate: already have this event");
    }
    if !event.verify() {
        return refuse(false, "invalid: bad id or signature");
    }
    let record = record::encode_expiring(&event, policy::expiration(&event, now()));
    let submission = Submission { record, reply: link.clone() };
    if shared.writer.submit(submission).is_err() {
        refuse(false, "rate-limited: the relay is busy, try again shortly");
    }
}

/// Whether an event's id, pubkey, and signature are lowercase hex of the
/// right lengths, as a record holds them.
pub fn well_formed(event: &Event) -> bool {
    is_hex64(&event.id) && is_hex64(&event.pubkey) && event.sig.len() == 128 && event.sig.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// About how many bytes an event takes to keep: its strings, and what its
/// fixed fields and JSON cost besides, without serializing it again.
fn event_bytes(event: &Event) -> u64 {
    let tags: usize = event.tags.iter().map(|tag| tag.iter().map(|value| value.len() + 3).sum::<usize>() + 2).sum();
    (event.content.len() + tags + 400) as u64
}

fn event_message(sub_json: &str, event_json: &str) -> String {
    let mut out = String::with_capacity(12 + sub_json.len() + event_json.len());
    out.push_str("[\"EVENT\",");
    out.push_str(sub_json);
    out.push(',');
    out.push_str(event_json);
    out.push(']');
    out
}
