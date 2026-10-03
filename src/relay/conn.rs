//! One client's WebSocket: NIP-01's EVENT, REQ, and CLOSE, and NIP-42's
//! AUTH.
//!
//! The AUTH challenge goes out as soon as the client connects, so it can
//! authenticate before it asks for anything, rather than learning it has
//! to from a refusal. A connection may authenticate as many keys as it
//! likes, up to a limit: Armada authenticates as every Concord stream key
//! it reads, besides its user. Each AUTH is checked in turn, on the
//! connection's own task, so a REQ sent after it is answered knowing it.
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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::ws::{Message, WebSocket};
use futures_util::stream::{SplitSink, StreamExt};
use futures_util::SinkExt;
use serde_json::Value;
use tokio::task::JoinSet;

use super::Shared;
use super::filter::Filter;
use super::monitors::{ConnId, Link, Outbound, SharedKeys};
use super::policy::{self, Keys};
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

/// Seconds an AUTH event's `created_at` may be from now.
const AUTH_WINDOW: i64 = 600;

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
}

struct Session {
    shared: Arc<Shared>,
    id: ConnId,
    link: Link,
    sink: Sink,
    subs: HashMap<String, Sub>,
    tokens: TokenBucket,
    /// What this relay is called, as [`policy::authority`] puts it.
    authority: Arc<str>,
    challenge: String,
    keys: SharedKeys,
}

type QueryDone = (Arc<str>, anyhow::Result<Results>);

pub async fn serve(shared: Arc<Shared>, socket: WebSocket, authority: Arc<str>) {
    let id = shared.next_conn.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let (link, mut rx, overflow) = Link::new(OUTBOUND);
    let (sink, mut stream) = socket.split();
    let keys = SharedKeys::default();
    shared.hub.connect(id, link.clone(), keys.clone()).await;
    let tokens = TokenBucket::new(shared.config.events_per_minute, Instant::now());
    let cancel = shared.cancel.clone();
    let challenge = hex::encode(rand::random::<[u8; 16]>());
    let mut session = Session { shared, id, link, sink, subs: HashMap::new(), tokens, authority, challenge, keys };
    let mut queries: JoinSet<QueryDone> = JoinSet::new();

    // The challenge, before anything else: see the module docs.
    let challenge = serde_json::json!(["AUTH", session.challenge]).to_string();
    let mut alive = session.send(challenge).await.is_ok();
    while alive {
        let result = tokio::select! {
            _ = cancel.cancelled() => break,
            _ = overflow.cancelled() => {
                tracing::debug!(conn = id, "dropping a client that fell too far behind");
                break;
            }
            message = stream.next() => match message {
                Some(Ok(Message::Text(text))) => session.on_text(&text, &mut queries).await,
                Some(Ok(Message::Binary(_))) => session.notice("invalid: messages must be text").await,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(()),
                Some(Ok(Message::Close(_)) | Err(_)) | None => break,
            },
            Some(outbound) = rx.recv() => session.on_outbound(outbound).await,
            Some(done) = queries.join_next(), if !queries.is_empty() => match done {
                Ok((name, results)) => session.on_results(name, results).await,
                Err(_) => Ok(()),
            },
        };
        alive = result.is_ok();
    }

    session.shared.hub.disconnect(id).await;
    let _ = session.sink.close().await;
}

impl Session {
    async fn send(&mut self, text: String) -> Result<(), Gone> {
        self.sink.send(Message::Text(text.into())).await.map_err(|_| Gone)
    }

    async fn notice(&mut self, message: &str) -> Result<(), Gone> {
        self.send(serde_json::json!(["NOTICE", message]).to_string()).await
    }

    async fn closed(&mut self, sub: &str, message: &str) -> Result<(), Gone> {
        self.send(serde_json::json!(["CLOSED", sub, message]).to_string()).await
    }

    async fn on_text(&mut self, text: &str, queries: &mut JoinSet<QueryDone>) -> Result<(), Gone> {
        let Ok(Value::Array(message)) = serde_json::from_str::<Value>(text) else {
            return self.notice("invalid: a message must be a JSON array").await;
        };
        match message.first().and_then(Value::as_str) {
            Some("EVENT") => self.on_event(message.get(1)).await,
            Some("REQ") => self.on_req(&message, queries).await,
            Some("AUTH") => self.on_auth(message.get(1)).await,
            Some("COUNT") => match message.get(1).and_then(Value::as_str) {
                Some(sub) => self.closed(sub, "unsupported: COUNT isn't supported").await,
                None => self.notice("invalid: COUNT needs a subscription id").await,
            },
            Some("CLOSE") => {
                if let Some(sub) = message.get(1).and_then(Value::as_str) {
                    self.subs.remove(sub);
                    self.shared.hub.unsubscribe(self.id, sub).await;
                }
                Ok(())
            }
            Some(other) => self.notice(&format!("unsupported: {other} messages")).await,
            None => self.notice("invalid: a message must start with its type").await,
        }
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
        if !is_hex64(&event.id) || !is_hex64(&event.pubkey) || event.sig.len() != 128 || hex::decode(&event.sig).is_err() {
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
        policy::validate(event, now, &self.authority)?;
        if record::expiration(event).is_some_and(|expiration| i64::from(expiration) <= now) {
            return Err("invalid: event has expired".into());
        }
        // NIP-70.
        if event.tags.iter().any(|tag| tag.len() == 1 && tag[0] == "-") && !self.keys().contains(&key(&event.pubkey)) {
            return Err("auth-required: only its author may publish this event".into());
        }
        if !self.tokens.take(Instant::now()) {
            return Err("rate-limited: slow down".into());
        }
        Ok(())
    }

    fn keys(&self) -> std::sync::RwLockReadGuard<'_, Keys> {
        self.keys.read().expect("the keys lock")
    }

    /// Authenticate as the key that signed `event` (NIP-42).
    async fn on_auth(&mut self, event: Option<&Value>) -> Result<(), Gone> {
        let Some(Ok(event)) = event.map(|e| serde_json::from_value::<Event>(e.clone())) else {
            return self.notice("invalid: AUTH takes an event").await;
        };
        let reply = match self.check_auth(&event) {
            Ok(()) => {
                let max = self.shared.config.max_authed_keys;
                let mut keys = self.keys.write().expect("the keys lock");
                let pubkey = key(&event.pubkey);
                if keys.len() >= max && !keys.contains(&pubkey) {
                    ok(&event.id, false, "restricted: this connection has authenticated as too many keys")
                } else {
                    keys.insert(pubkey);
                    ok(&event.id, true, "")
                }
            }
            Err(message) => ok(&event.id, false, message),
        };
        self.send(reply).await
    }

    fn check_auth(&self, event: &Event) -> Result<(), &'static str> {
        if !is_hex64(&event.id) || !is_hex64(&event.pubkey) {
            return Err("invalid: id and pubkey must be lowercase hex");
        }
        if event.kind != i64::from(policy::AUTH) {
            return Err("invalid: AUTH takes a kind 22242 event");
        }
        if (event.created_at - now()).abs() > AUTH_WINDOW {
            return Err("invalid: created_at is too far from now");
        }
        if event.tag("challenge") != Some(self.challenge.as_str()) {
            return Err("invalid: that's not this connection's challenge");
        }
        if event.tag("relay").and_then(policy::authority).as_deref() != Some(&*self.authority) {
            return Err("invalid: that's not this relay");
        }
        if !event.verify() {
            return Err("invalid: bad id or signature");
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
        let keys = self.keys().clone();
        let scoped = |value| {
            let mut filter = Filter::parse(value)?;
            policy::scope(&mut filter, &keys)?;
            Ok::<_, String>(filter)
        };
        let filters = match message[2..].iter().map(scoped).collect::<Result<Vec<_>, _>>() {
            Ok(filters) => filters,
            Err(error) => {
                self.subs.remove(&sub);
                self.shared.hub.unsubscribe(self.id, &sub).await;
                return self.closed(&sub, &error).await;
            }
        };
        if !self.subs.contains_key(&sub) && self.subs.len() >= config.max_subscriptions {
            return self.closed(&sub, "rate-limited: too many open subscriptions").await;
        }

        let name: Arc<str> = sub.as_str().into();
        let json = serde_json::to_string(&sub).expect("strings serialize");
        self.subs.insert(sub, Sub { name: name.clone(), json, pending: Some(Vec::new()), floor: 0 });
        // Live first, then the query: see the module docs. Queued from here
        // rather than the query's task, so a later CLOSE or REQ of the same id
        // reaches the shard after it.
        let installed = self.shared.hub.subscribe(self.id, name.clone(), filters.clone()).await;

        let shared = self.shared.clone();
        queries.spawn(async move {
            let results = async {
                installed.await?;
                let _permit = shared.queries.clone().acquire_owned().await?;
                let store = shared.store.clone();
                let max_limit = shared.config.max_limit;
                Ok(tokio::task::spawn_blocking(move || query::run(&store, &filters, &keys, max_limit, now())).await??)
            };
            (name, results.await)
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
                self.subs.remove(&*name);
                self.shared.hub.unsubscribe(self.id, &name).await;
                return self.closed(&name, "error: could not run the query").await;
            }
        };
        let pending = sub.pending.take().unwrap_or_default();
        sub.floor = results.next_seq;
        let sub_json = sub.json.clone();

        for json in &results.events {
            self.sink.feed(Message::Text(event_message(&sub_json, json).into())).await.map_err(|_| Gone)?;
        }
        self.sink.feed(Message::Text(format!("[\"EOSE\",{sub_json}]").into())).await.map_err(|_| Gone)?;
        for (seq, json) in pending {
            // Stored events the query could see were sent with it.
            if seq >= results.next_seq {
                self.sink.feed(Message::Text(event_message(&sub_json, &json).into())).await.map_err(|_| Gone)?;
            }
        }
        self.sink.flush().await.map_err(|_| Gone)
    }

    async fn on_outbound(&mut self, outbound: Outbound) -> Result<(), Gone> {
        match outbound {
            Outbound::Text(text) => self.send(text).await,
            Outbound::Event { sub, seq, json } => {
                let Some(state) = self.subs.get_mut(&*sub).filter(|state| Arc::ptr_eq(&state.name, &sub)) else { return Ok(()) };
                match &mut state.pending {
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
    // first. A forgery of a stored id is answered the same way, and stores
    // nothing.
    let store = &shared.store;
    if store.read().and_then(|txn| store.contains(&txn, &id)).unwrap_or(false) {
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

/// A checked hex key's bytes.
fn key(hex: &str) -> [u8; 32] {
    let mut key = [0; 32];
    hex::decode_to_slice(hex, &mut key).expect("checked hex");
    key
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
