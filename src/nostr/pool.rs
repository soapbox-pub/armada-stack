//! A pool of relay connections.
//!
//! One task per relay URL owns its WebSocket. It connects when something is
//! asked of it, resends every open subscription after a reconnect, backs off
//! when the relay is down, and closes itself once nothing has been asked of it
//! for a while.
//!
//! A relay the operator didn't configure is one an author named, and is held
//! to the rule blob downloads follow: public addresses only. The check is made on
//! the addresses the connection is then opened to, not on a lookup of its own
//! that a rebinding name could answer differently.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

use super::Event;

/// How long a relay with nothing asked of it stays connected.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);

/// The largest message taken from a relay: room for a manifest listing tens
/// of thousands of files.
const MAX_MESSAGE: usize = 16 << 20;

/// Bytes of events received and not yet handled, per query or subscription.
/// Any relay an author names can send as many events of theirs as it likes,
/// each signed and each matching, so what waits is bounded by size rather
/// than count; past this, events are dropped until the reader catches up.
const MAX_QUEUED_KIB: usize = 32 << 10;

/// How far ahead of this clock an event may be dated. Anything later would
/// stand as an address's newest version until that date came.
const MAX_FUTURE: i64 = 15 * 60;

/// A NIP-01 filter, as the subset this sends.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Filter {
    pub ids: Vec<String>,
    pub kinds: Vec<i64>,
    pub authors: Vec<String>,
    /// `#d` values.
    pub d: Vec<String>,
    /// `#i` values.
    pub i: Vec<String>,
    pub since: Option<i64>,
    pub limit: Option<u64>,
}

impl Filter {
    pub fn to_json(&self) -> Value {
        let mut filter = serde_json::Map::new();
        if !self.ids.is_empty() {
            filter.insert("ids".into(), json!(self.ids));
        }
        filter.insert("kinds".into(), json!(self.kinds));
        filter.insert("authors".into(), json!(self.authors));
        if !self.d.is_empty() {
            filter.insert("#d".into(), json!(self.d));
        }
        if !self.i.is_empty() {
            filter.insert("#i".into(), json!(self.i));
        }
        if let Some(since) = self.since {
            filter.insert("since".into(), json!(since));
        }
        if let Some(limit) = self.limit {
            filter.insert("limit".into(), json!(limit));
        }
        Value::Object(filter)
    }

    /// Whether an event is one this filter asked for. Relays are not trusted
    /// to have applied it.
    pub fn matches(&self, event: &Event) -> bool {
        (self.ids.is_empty() || self.ids.contains(&event.id))
            && (self.kinds.is_empty() || self.kinds.contains(&event.kind))
            && (self.authors.is_empty() || self.authors.contains(&event.pubkey))
            && (self.d.is_empty() || event.tag("d").is_some_and(|d| self.d.iter().any(|want| want == d)))
            && (self.i.is_empty() || has_tag_value(event, "i", &self.i))
            && self.since.is_none_or(|since| event.created_at >= since)
    }
}

/// Whether any of the event's `name` tags has one of `values`, as a relay
/// matches a `#name` filter.
fn has_tag_value(event: &Event, name: &str, values: &[String]) -> bool {
    event.tags.iter().any(|tag| tag.first().map(String::as_str) == Some(name) && tag.get(1).is_some_and(|value| values.contains(value)))
}

/// What a relay said about one subscription.
#[derive(Debug)]
enum Reply {
    /// With its share of the queued-bytes budget, given back when dropped.
    Event(Event, OwnedSemaphorePermit),
    /// Stored events are done, or the relay gave up on the subscription, or
    /// never connected: either way nothing more is coming for a query.
    Done,
}

enum Command {
    Subscribe { id: String, filters: Arc<Vec<Filter>>, replies: mpsc::Sender<Reply>, budget: Arc<Semaphore> },
    Close { id: String },
}

#[derive(Clone)]
pub struct Pool {
    inner: Arc<PoolInner>,
}

/// Whether a relay URL is one the operator configured, and so may be on any
/// address.
pub type Trusted = Arc<dyn Fn(&str) -> bool + Send + Sync>;

struct PoolInner {
    relays: Mutex<HashMap<String, mpsc::UnboundedSender<Command>>>,
    trusted: Trusted,
}

impl Pool {
    pub fn new(trusted: Trusted) -> Pool {
        Pool { inner: Arc::new(PoolInner { relays: Mutex::new(HashMap::new()), trusted }) }
    }

    fn relay(&self, url: &str) -> mpsc::UnboundedSender<Command> {
        let mut relays = self.inner.relays.lock();
        if let Some(tx) = relays.get(url).filter(|tx| !tx.is_closed()) {
            return tx.clone();
        }
        let (tx, rx) = mpsc::unbounded_channel();
        relays.insert(url.to_string(), tx.clone());
        tokio::spawn(run_relay(url.to_string(), rx, self.inner.trusted.clone()));
        tx
    }

    /// Collect the newest stored event for each address matching `filters`
    /// from `relays`, until each relay is done or `timeout` passes.
    ///
    /// Only the newest per address is kept as they arrive, since that is all
    /// anything asks for, and an author can otherwise have a relay of theirs
    /// send every version they ever signed.
    pub async fn query(&self, filters: Vec<Filter>, relays: &[String], timeout: Duration, cancel: &CancellationToken) -> Vec<Event> {
        let filters = Arc::new(filters);
        let budget = Arc::new(Semaphore::new(MAX_QUEUED_KIB));
        let (tx, mut rx) = mpsc::channel(1024);
        let id = crate::util::random_hex(8);

        let mut handles = Vec::new();
        for (index, url) in relays.iter().enumerate() {
            let relay = self.relay(url);
            let (relay_tx, mut relay_rx) = mpsc::channel(4096);
            let _ = relay.send(Command::Subscribe {
                id: format!("{id}{index}"),
                filters: filters.clone(),
                replies: relay_tx,
                budget: budget.clone(),
            });
            let tx = tx.clone();
            handles.push((relay, format!("{id}{index}")));
            tokio::spawn(async move {
                while let Some(reply) = relay_rx.recv().await {
                    let done = matches!(reply, Reply::Done);
                    if tx.send(reply).await.is_err() || done {
                        break;
                    }
                }
            });
        }
        drop(tx);

        let mut events: HashMap<(i64, String, String), Event> = HashMap::new();
        let mut done = 0;
        let deadline = Instant::now() + timeout;

        while done < relays.len() {
            tokio::select! {
                reply = rx.recv() => match reply {
                    Some(Reply::Event(event, _)) => {
                        if filters.iter().any(|f| f.matches(&event)) {
                            let address = (event.kind, event.pubkey.clone(), address_identifier(&event));
                            // The first seen wins a tie.
                            match events.get(&address) {
                                Some(kept) if kept.created_at >= event.created_at => {}
                                _ => {
                                    events.insert(address, event);
                                }
                            }
                        }
                    }
                    Some(Reply::Done) => done += 1,
                    None => break,
                },
                _ = tokio::time::sleep_until(deadline) => break,
                _ = cancel.cancelled() => break,
            }
        }

        for (relay, sub) in handles {
            let _ = relay.send(Command::Close { id: sub });
        }

        events.into_values().collect()
    }

    /// Stream events matching `filters` from `relays` until `cancel` fires,
    /// deduplicated across relays. Relays that drop are reconnected to, and
    /// asked again.
    pub fn subscribe(&self, filters: Vec<Filter>, relays: &[String], cancel: CancellationToken) -> mpsc::Receiver<Event> {
        let filters = Arc::new(filters);
        // One at a time: what waits for the reader waits in `replies`, where
        // the budget counts it.
        let (out, rx) = mpsc::channel(1);
        let (tx, mut replies) = mpsc::channel::<Reply>(4096);
        let budget = Arc::new(Semaphore::new(MAX_QUEUED_KIB));
        let id = crate::util::random_hex(8);

        let mut handles = Vec::new();
        for (index, url) in relays.iter().enumerate() {
            let relay = self.relay(url);
            let sub = format!("{id}{index}");
            let _ = relay.send(Command::Subscribe { id: sub.clone(), filters: filters.clone(), replies: tx.clone(), budget: budget.clone() });
            handles.push((relay, sub));
        }
        drop(tx);

        tokio::spawn(async move {
            let mut seen: HashSet<String> = HashSet::new();
            loop {
                tokio::select! {
                    reply = replies.recv() => match reply {
                        Some(Reply::Event(event, _permit)) => {
                            if !filters.iter().any(|f| f.matches(&event)) || !seen.insert(event.id.clone()) {
                                continue;
                            }
                            // Bounded, since a long-running subscription must not grow forever.
                            if seen.len() > 100_000 {
                                seen.clear();
                            }
                            if out.send(event).await.is_err() {
                                break;
                            }
                        }
                        Some(Reply::Done) => {}
                        None => break,
                    },
                    _ = cancel.cancelled() => break,
                }
            }
            for (relay, sub) in handles {
                let _ = relay.send(Command::Close { id: sub });
            }
        });

        rx
    }
}

struct Subscription {
    filters: Arc<Vec<Filter>>,
    replies: mpsc::Sender<Reply>,
    budget: Arc<Semaphore>,
    /// Whether it has been answered with EOSE on this connection, so a query
    /// isn't told it is done twice.
    done: bool,
}

type Socket = tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// One relay's connection, for as long as anything is asked of it.
async fn run_relay(url: String, mut commands: mpsc::UnboundedReceiver<Command>, trusted: Trusted) {
    let mut subs: HashMap<String, Subscription> = HashMap::new();
    let mut socket: Option<Socket> = None;
    let mut backoff = BACKOFF_MIN;
    let mut retry_at: Option<Instant> = None;
    let mut idle_since = Instant::now();

    loop {
        // Connect when there is something to ask and no wait in force.
        if socket.is_none() && !subs.is_empty() && retry_at.is_none_or(|at| Instant::now() >= at) {
            match connect(&url, !trusted(&url)).await {
                Ok(mut ws) => {
                    backoff = BACKOFF_MIN;
                    retry_at = None;
                    let mut ok = true;
                    for (id, sub) in subs.iter_mut() {
                        sub.done = false;
                        ok &= send_req(&mut ws, id, &sub.filters).await;
                    }
                    if ok {
                        tracing::debug!(relay = url.as_str(), "relay connected");
                        socket = Some(ws);
                    }
                }
                Err(error) => {
                    tracing::debug!(relay = url.as_str(), %error, "relay connect failed");
                    // Nothing is coming from this relay for now, so a query
                    // waiting on it should stop waiting.
                    for sub in subs.values_mut() {
                        if !sub.done {
                            sub.done = true;
                            let _ = sub.replies.try_send(Reply::Done);
                        }
                    }
                    retry_at = Some(Instant::now() + backoff);
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                }
            }
        }

        let idle_deadline = idle_since + IDLE_TIMEOUT;
        let retry = retry_at.unwrap_or(Instant::now() + Duration::from_secs(3600));

        tokio::select! {
            command = commands.recv() => {
                let Some(command) = command else { break };
                match command {
                    Command::Subscribe { id, filters, replies, budget } => {
                        if let Some(ws) = socket.as_mut() {
                            if !send_req(ws, &id, &filters).await {
                                socket = None;
                            }
                        } else if retry_at.is_some() {
                            // Down and waiting to retry: a query shouldn't wait too.
                            let _ = replies.try_send(Reply::Done);
                        }
                        subs.insert(id, Subscription { filters, replies, budget, done: retry_at.is_some() && socket.is_none() });
                    }
                    Command::Close { id } => {
                        if subs.remove(&id).is_some()
                            && let Some(ws) = socket.as_mut()
                        {
                            let _ = ws.send(Message::Text(json!(["CLOSE", id]).to_string().into())).await;
                        }
                        if subs.is_empty() {
                            idle_since = Instant::now();
                        }
                    }
                }
            }
            message = next_message(&mut socket) => match message {
                Some(Ok(Message::Text(text))) => handle_message(&text, &mut subs),
                Some(Ok(Message::Ping(payload))) => {
                    if let Some(ws) = socket.as_mut() {
                        let _ = ws.send(Message::Pong(payload)).await;
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => {
                    tracing::debug!(relay = url.as_str(), "relay disconnected");
                    socket = None;
                    retry_at = Some(Instant::now() + backoff);
                    backoff = (backoff * 2).min(BACKOFF_MAX);
                    for sub in subs.values_mut() {
                        if !sub.done {
                            sub.done = true;
                            let _ = sub.replies.try_send(Reply::Done);
                        }
                    }
                }
                Some(Ok(_)) => {}
            },
            _ = sleep_until_opt(retry_at.map(|_| retry)) => {}
            _ = tokio::time::sleep_until(idle_deadline), if subs.is_empty() => {
                if let Some(mut ws) = socket.take() {
                    let _ = ws.close(None).await;
                }
                return;
            }
        }

        // Subscriptions whose reader went away are as good as closed.
        let before = subs.len();
        subs.retain(|_, sub| !sub.replies.is_closed());
        if before > 0 && subs.is_empty() {
            idle_since = Instant::now();
        }
    }

    if let Some(mut ws) = socket.take() {
        let _ = ws.close(None).await;
    }
}

async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

async fn next_message(socket: &mut Option<Socket>) -> Option<Result<Message, tokio_tungstenite::tungstenite::Error>> {
    match socket.as_mut() {
        Some(ws) => ws.next().await,
        None => std::future::pending().await,
    }
}

async fn connect(url: &str, public_only: bool) -> Result<Socket, String> {
    match tokio::time::timeout(CONNECT_TIMEOUT, open(url, public_only)).await {
        Ok(result) => result,
        Err(_) => Err("timed out".into()),
    }
}

/// Resolve a relay's name, connect to one of its addresses, and speak
/// WebSocket over that. The resolving is done here rather than left to the
/// WebSocket client so that the addresses checked are the ones dialed.
async fn open(url: &str, public_only: bool) -> Result<Socket, String> {
    let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().ok_or("no host")?;
    let port = parsed.port_or_known_default().ok_or("no port")?;

    let addresses = crate::net::resolve_all(host).await.map_err(|e| e.to_string())?;
    if public_only && !addresses.iter().copied().all(crate::net::is_public_address) {
        return Err(format!("{host} is not a public address"));
    }

    let mut last_error = String::from("no addresses");
    let mut stream = None;
    for address in addresses {
        match tokio::net::TcpStream::connect((address, port)).await {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = error.to_string(),
        }
    }
    let stream = stream.ok_or(last_error)?;

    let config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    let (ws, _) = tokio_tungstenite::client_async_tls_with_config(url, stream, Some(config), None).await.map_err(|e| e.to_string())?;
    Ok(ws)
}

async fn send_req(ws: &mut Socket, id: &str, filters: &[Filter]) -> bool {
    let mut req = vec![json!("REQ"), json!(id)];
    req.extend(filters.iter().map(Filter::to_json));
    ws.send(Message::Text(Value::Array(req).to_string().into())).await.is_ok()
}

fn handle_message(text: &str, subs: &mut HashMap<String, Subscription>) {
    let Ok(Value::Array(message)) = serde_json::from_str::<Value>(text) else {
        return;
    };
    let kind = message.first().and_then(Value::as_str);
    let Some(sub_id) = message.get(1).and_then(Value::as_str) else {
        return;
    };
    let Some(sub) = subs.get_mut(sub_id) else {
        return;
    };

    match kind {
        Some("EVENT") => {
            let Some(event) = message.get(2).and_then(|e| serde_json::from_value::<Event>(e.clone()).ok()) else {
                return;
            };
            if event.created_at > crate::util::now() + MAX_FUTURE || !sub.filters.iter().any(|f| f.matches(&event)) || !event.verify() {
                return;
            }
            let kib = u32::try_from(text.len().div_ceil(1024)).unwrap_or(u32::MAX);
            let Ok(permit) = sub.budget.clone().try_acquire_many_owned(kib) else {
                return;
            };
            let _ = sub.replies.try_send(Reply::Event(event, permit));
        }
        Some("EOSE") if !sub.done => {
            sub.done = true;
            let _ = sub.replies.try_send(Reply::Done);
        }
        Some("CLOSED") => {
            if !sub.done {
                let _ = sub.replies.try_send(Reply::Done);
            }
            subs.remove(sub_id);
        }
        _ => {}
    }
}

/// What tells apart the versions of one address: a `d` tag for an
/// addressable kind, and nothing for a replaceable one, which has one per
/// author. Anything else is its own address.
fn address_identifier(event: &Event) -> String {
    match event.kind {
        30000..40000 => event.tag("d").unwrap_or("").to_string(),
        0 | 3 | 10000..20000 => String::new(),
        _ => event.id.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let event = Event::sign(secret, 100, 35128, vec![vec!["d".into(), "docs".into()]], "");
        let filter = Filter { kinds: vec![35128], authors: vec![event.pubkey.clone()], d: vec!["docs".into()], since: Some(50), ..Default::default() };
        assert!(filter.matches(&event));
        assert!(!Filter { d: vec!["blog".into()], ..filter.clone() }.matches(&event));
        assert!(!Filter { since: Some(200), ..filter.clone() }.matches(&event));
        assert_eq!(filter.to_json(), json!({ "kinds": [35128], "authors": [event.pubkey], "#d": ["docs"], "since": 50 }));

        let tagged = Event::sign(secret, 100, 30063, vec![vec!["i".into(), "other".into()], vec!["i".into(), "app".into()]], "");
        let by_tag = Filter { i: vec!["app".into()], ..Default::default() };
        assert!(by_tag.matches(&tagged));
        assert!(!by_tag.matches(&event));
        let by_id = Filter { ids: vec![tagged.id.clone()], ..Default::default() };
        assert!(by_id.matches(&tagged));
        assert!(!by_id.matches(&event));
        assert_eq!(
            Filter { ids: vec!["a".into()], kinds: vec![3063], authors: vec!["p".into()], i: vec!["app".into()], ..Default::default() }.to_json(),
            json!({ "ids": ["a"], "kinds": [3063], "authors": ["p"], "#i": ["app"] })
        );
    }

    #[test]
    fn refuses_future_events_and_spends_a_budget() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let (tx, mut rx) = mpsc::channel(16);
        let budget = Arc::new(Semaphore::new(1));
        let filters = Arc::new(vec![Filter::default()]);
        let mut subs = HashMap::from([("s".to_string(), Subscription { filters, replies: tx, budget: budget.clone(), done: false })]);
        let message = |event: &Event| json!(["EVENT", "s", event]).to_string();

        let future = Event::sign(secret, crate::util::now() + 3600, 15128, vec![], "");
        handle_message(&message(&future), &mut subs);
        assert!(rx.try_recv().is_err());

        let now = Event::sign(secret, crate::util::now(), 15128, vec![], "");
        handle_message(&message(&now), &mut subs);
        let received = rx.try_recv().unwrap();
        // The budget is spent until the event is handled.
        handle_message(&message(&Event::sign(secret, crate::util::now(), 10002, vec![], "")), &mut subs);
        assert!(rx.try_recv().is_err());
        drop(received);
        assert_eq!(budget.available_permits(), 1);
    }

    #[test]
    fn addresses() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let named = Event::sign(secret, 1, 35128, vec![vec!["d".into(), "docs".into()]], "");
        assert_eq!(address_identifier(&named), "docs");
        assert_eq!(address_identifier(&Event::sign(secret, 1, 10002, vec![], "")), "");
        let note = Event::sign(secret, 1, 1, vec![], "");
        assert_eq!(address_identifier(&note), note.id);
    }

    #[tokio::test]
    async fn a_dead_relay_does_not_hold_up_a_query() {
        let pool = Pool::new(Arc::new(|_: &str| true));
        let started = std::time::Instant::now();
        let events = pool
            .query(vec![Filter::default()], &["wss://127.0.0.1:1".into()], Duration::from_secs(10), &CancellationToken::new())
            .await;
        assert!(events.is_empty());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn an_untrusted_relay_must_be_public() {
        assert!(open("wss://127.0.0.1:1", true).await.unwrap_err().contains("not a public address"));
        assert!(open("wss://localhost:1", true).await.unwrap_err().contains("not a public address"));
    }
}
