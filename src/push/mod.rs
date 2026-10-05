//! A Web Push service for Armada, speaking nostr-push2's protocol so a
//! client can't tell the two apart, but living inside the relay.
//!
//! Clients talk to it as to nostr-push2: NIP-44 encrypted kind 25742
//! requests to its pubkey, in NIP-46's shape, answered the same way, with
//! `create`, `set`, `get`, `delete` and `ping`. Only Web Push connections
//! are taken. Each client brings its own VAPID key, so the only key here is
//! the service's Nostr key, made on first start ([`key`]); the web app is
//! pointed at it through `NOSTR_PUSH2_PUBKEY` and `NOSTR_PUSH2_RELAYS`
//! (see [`crate::web::env`]).
//!
//! Being inside the relay makes most of nostr-push2 unnecessary. Requests
//! and new events both come from the relay's own live subscriptions
//! ([`crate::relay::Internal`]), already verified and deduplicated, and
//! matched by its index; each client is one subscription there, under its
//! pubkey. So there's no firehose, no websocket client, and no matcher of
//! our own. The flip side: only events this relay stores are pushed. The
//! relays a subscription names are kept and handed back, and otherwise
//! ignored, as nostr-push2 does with its own relays.
//!
//! Everything that changes a client happens on one task, in order: requests,
//! deliveries that find a subscription gone, and the sweep of clients not
//! seen in a month. Deliveries run beside it.

mod connection;
mod db;
mod key;
mod subscriptions;
mod webpush;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, mpsc};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::nostr::{Event, nip44};
use crate::ratelimit::TokenBucket;
use crate::relay::{ConnId, Internal, Outbound};
use crate::storage::Storage;
use crate::util::now;
use connection::Connection;
use db::{Client, PushDb};
use key::Keys;
use webpush::{Outcome, Sender};

/// Requests and their answers.
pub const KIND: i64 = 25742;

/// How far a request's `created_at` may be from now.
const MAX_CLOCK_SKEW: i64 = 600;
/// Clients unseen for this long are forgotten. Apps `create` or `ping` on
/// launch.
const CLIENT_TTL: i64 = 30 * 86_400;
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);
/// The most clients kept, so `create` can't fill the disk.
const MAX_CLIENTS: usize = 100_000;
/// Pushes one client may get a minute, in bursts of as many. More are
/// dropped, not queued.
const PUSHES_PER_MINUTE: u32 = 30;
/// Pushes waiting to go out, and how many go at once. Past the queue, new
/// ones are dropped.
const DELIVERY_QUEUE: usize = 10_000;
const DELIVERY_CONCURRENCY: usize = 32;
/// The most a push's plaintext may be before its event is left out, and the
/// client fetches it by id instead.
const PAYLOAD_BUDGET: usize = 3900;
const _: () = assert!(PAYLOAD_BUDGET <= webpush::MAX_PLAINTEXT);
/// How far the relay's subscriptions may fall behind before they're
/// dropped and made again.
const REQUEST_BACKLOG: usize = 1024;
const MATCH_BACKLOG: usize = 8192;

pub struct Push {
    keys: Keys,
    db: PushDb,
}

/// What [`Push::start`] needs from the rest of armada.
pub struct Options {
    /// This relay's URL, for pushes to say where their event is.
    pub relay_url: Option<String>,
    /// The VAPID `sub`: a `mailto:` or `https:` URL for push services to
    /// contact.
    pub subject: String,
    /// Refuse push endpoints on private networks. Only tests turn it off.
    pub public_only: bool,
}

impl Push {
    /// Load the service's key and clients, making the key if need be.
    pub fn open(storage: &Storage) -> Result<Push> {
        let keys = Keys::load_or_create(&storage.service_dir("push")?.join("key"))?;
        Ok(Push { keys, db: PushDb::open(storage)? })
    }

    /// The service's pubkey, in hex: where clients send requests.
    pub fn pubkey(&self) -> &str {
        &self.keys.pubkey
    }

    /// Serve until `cancel` fires.
    pub fn start(self, relay: Internal, options: Options, cancel: CancellationToken) -> Result<JoinHandle<()>> {
        let clients: HashMap<String, Client> = self.db.all()?.into_iter().collect();
        tracing::info!(pubkey = %self.keys.pubkey, clients = clients.len(), "push service ready");
        let (deliveries, queue) = mpsc::channel(DELIVERY_QUEUE);
        let (gone_tx, gone) = mpsc::channel(1024);
        tokio::spawn(deliver(Sender::new(&options.subject, options.public_only), queue, gone_tx));
        let service = Service { keys: self.keys, db: self.db, relay, options, clients, buckets: HashMap::new(), matches: 0, deliveries };
        Ok(tokio::spawn(service.run(gone, cancel)))
    }
}

struct Service {
    keys: Keys,
    db: PushDb,
    relay: Internal,
    options: Options,
    clients: HashMap<String, Client>,
    buckets: HashMap<String, TokenBucket>,
    /// The relay connection clients' subscriptions are on.
    matches: ConnId,
    deliveries: mpsc::Sender<Delivery>,
}

struct Delivery {
    pubkey: String,
    connection: Connection,
    payload: String,
}

/// A decrypted request.
#[derive(Deserialize)]
struct Request {
    id: String,
    method: String,
    #[serde(default)]
    params: Option<Value>,
}

impl Service {
    async fn run(mut self, mut gone: mpsc::Receiver<(String, Connection)>, cancel: CancellationToken) {
        let (mut requests_conn, mut requests, mut requests_overflow) = self.listen().await;
        let (mut matches, mut matches_overflow) = self.watch().await;
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                Some(message) = requests.recv() => {
                    if let Outbound::Event { json, .. } = message {
                        self.on_request(&json).await;
                    }
                }
                Some(message) = matches.recv() => {
                    if let Outbound::Event { sub, json, .. } = message {
                        self.on_match(&sub, &json);
                    }
                }
                Some((pubkey, connection)) = gone.recv() => self.on_gone(&pubkey, &connection).await,
                () = requests_overflow.cancelled() => {
                    tracing::warn!("push requests fell behind; some were dropped");
                    self.relay.disconnect(requests_conn).await;
                    (requests_conn, requests, requests_overflow) = self.listen().await;
                }
                () = matches_overflow.cancelled() => {
                    tracing::warn!("push matching fell behind; some pushes were dropped");
                    (matches, matches_overflow) = self.watch().await;
                }
                _ = sweep.tick() => self.sweep().await,
            }
        }
    }

    /// A relay connection for requests to this service.
    async fn listen(&self) -> (ConnId, mpsc::Receiver<Outbound>, CancellationToken) {
        let (conn, rx, overflow) = self.relay.connect(REQUEST_BACKLOG).await;
        let filter = json!({"kinds": [KIND], "#p": [self.keys.pubkey]});
        self.relay.subscribe(conn, "requests", &[filter]).await.expect("a valid filter");
        (conn, rx, overflow)
    }

    /// A relay connection with every client's subscription on it, replacing
    /// any before it.
    async fn watch(&mut self) -> (mpsc::Receiver<Outbound>, CancellationToken) {
        if self.matches != 0 {
            self.relay.disconnect(self.matches).await;
        }
        let (conn, rx, overflow) = self.relay.connect(MATCH_BACKLOG).await;
        self.matches = conn;
        for (pubkey, client) in &self.clients {
            self.install(pubkey, client).await;
        }
        (rx, overflow)
    }

    async fn install(&self, pubkey: &str, client: &Client) {
        let filters: Vec<Value> = client.subscriptions.iter().flat_map(|s| s.live_filters()).collect();
        if let Err(error) = self.relay.subscribe(self.matches, pubkey, &filters).await {
            tracing::warn!(%pubkey, %error, "could not watch a client's subscriptions");
        }
    }

    async fn on_request(&mut self, json: &str) {
        let Ok(event) = serde_json::from_str::<Event>(json) else { return };
        if (event.created_at - now()).abs() > MAX_CLOCK_SKEW {
            return;
        }
        let Ok(author) = event.pubkey.parse() else { return };
        let key = nip44::conversation_key(&self.keys.secret, &author);
        let Some(request) = nip44::decrypt(&key, &event.content).and_then(|plaintext| parse_request(&plaintext)) else {
            tracing::debug!(client = %event.pubkey, "an unreadable push request");
            return;
        };
        let response = match self.dispatch(&event.pubkey, &request.method, request.params).await {
            Ok(result) => json!({"id": request.id, "result": result}),
            Err(error) => json!({"id": request.id, "error": error}),
        };
        // `set` keeps what `get` hands back small enough to encrypt, but
        // clients saved before it did may not be.
        let too_large = || json!({"id": request.id, "error": "the response is too large; set fewer subscriptions"});
        let Some(content) = nip44::encrypt(&key, &response.to_string()).or_else(|| nip44::encrypt(&key, &too_large().to_string())) else {
            tracing::warn!(client = %event.pubkey, "a push response too large to send");
            return;
        };
        let answer = Event::sign(&self.keys.secret_hex, now(), KIND, vec![vec!["p".into(), event.pubkey]], &content);
        if !self.relay.publish(&answer) {
            tracing::warn!("the relay had no room for a push response");
        }
    }

    async fn dispatch(&mut self, pubkey: &str, method: &str, params: Option<Value>) -> Result<Value, String> {
        let now = now();
        match method {
            "create" => {
                let connection = Connection::parse(params.as_ref().unwrap_or(&Value::Null), self.options.public_only)?;
                let client = match self.clients.get(pubkey) {
                    // Its subscriptions are kept, and already installed.
                    Some(existing) => Client { connection, last_seen: now, ..existing.clone() },
                    None if self.clients.len() >= MAX_CLIENTS => return Err("this service has no room for more clients".into()),
                    None => Client { connection, subscriptions: Vec::new(), created_at: now, last_seen: now },
                };
                self.save(pubkey, client).await?;
            }
            "delete" => self.remove(vec![pubkey.to_string()]).await?,
            "set" => {
                let Some(params) = params.as_ref().and_then(Value::as_object) else { return Err("params.subscriptions is required".into()) };
                let subscriptions = subscriptions::normalize(params.get("subscriptions").unwrap_or(&Value::Null), now)?;
                for filter in subscriptions.iter().flat_map(|s| s.live_filters()) {
                    crate::relay::check_filter(&filter)?;
                }
                let existing = self.clients.get(pubkey).ok_or(UNKNOWN)?;
                let client = Client { subscriptions, last_seen: now, ..existing.clone() };
                self.save(pubkey, client.clone()).await?;
                self.install(pubkey, &client).await;
            }
            "get" => {
                let existing = self.clients.get(pubkey).ok_or(UNKNOWN)?;
                let result = json!({"subscriptions": existing.subscriptions});
                self.save(pubkey, Client { last_seen: now, ..existing.clone() }).await?;
                return Ok(result);
            }
            "ping" => {
                let existing = self.clients.get(pubkey).ok_or(UNKNOWN)?;
                self.save(pubkey, Client { last_seen: now, ..existing.clone() }).await?;
            }
            _ => return Err(format!("unknown method {method}")),
        }
        Ok(json!({}))
    }

    async fn save(&mut self, pubkey: &str, client: Client) -> Result<(), String> {
        let (db, key, record) = (self.db.clone(), pubkey.to_string(), client.clone());
        match tokio::task::spawn_blocking(move || db.put(&key, &record)).await {
            Ok(Ok(())) => {
                self.clients.insert(pubkey.to_string(), client);
                Ok(())
            }
            Ok(Err(error)) => {
                tracing::error!(%error, "could not save a push client");
                Err("could not save; try again".into())
            }
            Err(error) => panic!("saving a push client: {error}"),
        }
    }

    async fn remove(&mut self, pubkeys: Vec<String>) -> Result<(), String> {
        let db = self.db.clone();
        let removed = pubkeys.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || db.delete(&removed)).await.expect("deleting push clients") {
            tracing::error!(%error, "could not delete push clients");
            return Err("could not delete; try again".into());
        }
        for pubkey in pubkeys {
            if self.clients.remove(&pubkey).is_some() {
                self.relay.unsubscribe(self.matches, &pubkey).await;
            }
            self.buckets.remove(&pubkey);
        }
        Ok(())
    }

    fn on_match(&mut self, pubkey: &str, json: &str) {
        let Some(client) = self.clients.get(pubkey) else { return };
        let now = Instant::now();
        if !self.buckets.entry(pubkey.to_string()).or_insert_with(|| TokenBucket::new(PUSHES_PER_MINUTE, now)).take(now) {
            tracing::debug!(%pubkey, "a push client is over its rate");
            return;
        }
        let Ok(Id { id }) = serde_json::from_str(json) else { return };
        let delivery = Delivery { pubkey: pubkey.to_string(), connection: client.connection.clone(), payload: payload(&id, json, self.options.relay_url.as_deref()) };
        if self.deliveries.try_send(delivery).is_err() {
            tracing::warn!("too many pushes waiting; dropped one");
        }
    }

    /// A push service says a client's subscription is gone. Unless the
    /// client has made a new one since, it goes too.
    async fn on_gone(&mut self, pubkey: &str, connection: &Connection) {
        if self.clients.get(pubkey).is_some_and(|client| client.connection == *connection) {
            tracing::debug!(%pubkey, "a push subscription is gone");
            let _ = self.remove(vec![pubkey.to_string()]).await;
        }
    }

    async fn sweep(&mut self) {
        let cutoff = now() - CLIENT_TTL;
        let stale: Vec<String> = self.clients.iter().filter(|(_, client)| client.last_seen < cutoff).map(|(pubkey, _)| pubkey.clone()).collect();
        if !stale.is_empty() {
            tracing::info!(clients = stale.len(), "forgetting push clients not seen in a month");
            let _ = self.remove(stale).await;
        }
        let now = Instant::now();
        self.buckets.retain(|_, bucket| !bucket.is_full(now));
    }
}

const UNKNOWN: &str = "unknown client; call create first";

#[derive(Deserialize)]
struct Id {
    id: String,
}

/// A decrypted request, or `None` for anything that isn't one: those go
/// unanswered, as nostr-push2 leaves them.
fn parse_request(plaintext: &str) -> Option<Request> {
    let request: Request = serde_json::from_str(plaintext).ok()?;
    let fits = |value: &str, max: usize| (1..=max).contains(&value.chars().count());
    (fits(&request.id, 64) && fits(&request.method, 32)).then_some(request)
}

/// Tenna's `napp.push.payload`: the event's id, where it is, and the event
/// itself if it fits.
fn payload(id: &str, event_json: &str, relay: Option<&str>) -> String {
    let head = format!(r#"{{"$type":"napp.push.payload","event_id":{},"relays":{}"#, json!(id), json!(relay.into_iter().collect::<Vec<_>>()));
    let with_event = format!(r#"{head},"event":{event_json}}}"#);
    if with_event.len() <= PAYLOAD_BUDGET { with_event } else { format!("{head}}}") }
}

/// Send pushes as they're queued, a few at once, and report subscriptions
/// that are gone.
async fn deliver(sender: Sender, mut queue: mpsc::Receiver<Delivery>, gone: mpsc::Sender<(String, Connection)>) {
    let permits = Arc::new(Semaphore::new(DELIVERY_CONCURRENCY));
    while let Some(delivery) = queue.recv().await {
        let permit = permits.clone().acquire_owned().await.expect("never closed");
        let (sender, gone) = (sender.clone(), gone.clone());
        tokio::spawn(async move {
            match sender.send(&delivery.connection, delivery.payload.as_bytes(), now()).await {
                Outcome::Sent => {}
                Outcome::Gone => {
                    let _ = gone.send((delivery.pubkey, delivery.connection)).await;
                }
                Outcome::Failed(error) => tracing::info!(pubkey = %delivery.pubkey, %error, "a push failed"),
            }
            drop(permit);
        });
    }
}

#[cfg(test)]
mod tests;
