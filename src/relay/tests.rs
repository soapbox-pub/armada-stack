//! The relay end to end, over real WebSockets.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tower::ServiceExt;

use super::*;
use crate::nostr::Event;
use crate::util::now;
use store::tests::{ALICE, BOB, tags};

struct Harness {
    _dir: tempfile::TempDir,
    url: String,
    relay: Router,
    _cancel: tokio_util::sync::DropGuard,
}

impl Harness {
    async fn new(config: RelayConfig) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let relay = Relay::open(&config, &Storage::allowing_private(dir.path())).unwrap();
        let router = relay.router();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let cancel = CancellationToken::new();
        tokio::spawn(relay.run(listener, cancel.clone()));
        Harness { _dir: dir, url, relay: router, _cancel: cancel.drop_guard() }
    }

    async fn client(&self) -> Client {
        let (socket, _) = tokio_tungstenite::connect_async(&self.url).await.unwrap();
        Client { socket }
    }
}

struct Client {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl Client {
    async fn send(&mut self, message: Value) {
        self.socket.send(Message::Text(message.to_string().into())).await.unwrap();
    }

    async fn recv(&mut self) -> Value {
        let message = tokio::time::timeout(Duration::from_secs(5), self.socket.next()).await.expect("a message in time");
        match message.unwrap().unwrap() {
            Message::Text(text) => serde_json::from_str(&text).unwrap(),
            other => panic!("unexpected {other:?}"),
        }
    }

    /// Nothing more arrives for a moment.
    async fn quiet(&mut self) {
        let next = tokio::time::timeout(Duration::from_millis(200), self.socket.next()).await;
        assert!(next.is_err(), "unexpected {next:?}");
    }

    async fn publish(&mut self, event: &Event) -> Value {
        self.send(json!(["EVENT", event])).await;
        self.recv().await
    }

    /// The events a REQ returns before its EOSE.
    async fn query(&mut self, sub: &str, filters: &[Value]) -> Vec<Event> {
        let mut message = vec![json!("REQ"), json!(sub)];
        message.extend(filters.iter().cloned());
        self.send(Value::Array(message)).await;
        let mut events = Vec::new();
        loop {
            let message = self.recv().await;
            match message[0].as_str().unwrap() {
                "EVENT" => {
                    assert_eq!(message[1], sub);
                    events.push(serde_json::from_value(message[2].clone()).unwrap());
                }
                "EOSE" => return events,
                _ => panic!("unexpected {message}"),
            }
        }
    }
}

fn note(secret: &str, content: &str) -> Event {
    Event::sign(secret, now(), 1, vec![], content)
}

#[tokio::test]
async fn stores_queries_and_streams() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut alice = harness.client().await;
    let mut bob = harness.client().await;

    let first = note(ALICE, "first");
    assert_eq!(alice.publish(&first).await, json!(["OK", first.id, true, ""]));
    assert_eq!(alice.publish(&first).await, json!(["OK", first.id, true, "duplicate: already have this event"]));

    // Stored events, then EOSE, then live ones.
    assert_eq!(bob.query("feed", &[json!({"kinds": [1]})]).await, [first]);
    let second = note(ALICE, "second");
    alice.publish(&second).await;
    let live = bob.recv().await;
    assert_eq!(live[0], "EVENT");
    assert_eq!(live[1], "feed");
    assert_eq!(serde_json::from_value::<Event>(live[2].clone()).unwrap(), second);

    // Others' filters don't see it.
    assert!(bob.query("other", &[json!({"kinds": [7]})]).await.is_empty());

    // Closed subscriptions stop.
    bob.send(json!(["CLOSE", "feed"])).await;
    bob.send(json!(["CLOSE", "other"])).await;
    alice.publish(&note(ALICE, "third")).await;
    bob.quiet().await;
    assert_eq!(bob.query("again", &[json!({"limit": 2})]).await.len(), 2);
}

/// Subscriptions opened while events stream in each get every event exactly
/// once, whether from their query or live.
#[tokio::test]
async fn hands_off_from_query_to_live_without_gaps_or_repeats() {
    const EVENTS: usize = 300;
    const SUBS: usize = 20;
    let harness = Harness::new(RelayConfig { events_per_minute: 0, ..RelayConfig::default() }).await;
    let mut alice = harness.client().await;
    let bob = harness.client().await;

    let publisher = tokio::spawn(async move {
        let mut ids = Vec::new();
        for i in 0..EVENTS {
            let event = note(ALICE, &i.to_string());
            assert_eq!(alice.publish(&event).await[2], true);
            ids.push(event.id);
        }
        ids
    });

    let (mut tx, mut rx) = bob.socket.split();
    let opener = tokio::spawn(async move {
        for i in 0..SUBS {
            let req = json!(["REQ", format!("s{i}"), {"kinds": [1]}]);
            tx.send(Message::Text(req.to_string().into())).await.unwrap();
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
        tx
    });

    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    let complete = |seen: &HashMap<String, Vec<String>>| seen.len() == SUBS && seen.values().all(|ids| ids.len() >= EVENTS);
    while !complete(&seen) {
        let message = tokio::time::timeout(Duration::from_secs(10), rx.next()).await.expect("every event in time");
        let Message::Text(text) = message.unwrap().unwrap() else { continue };
        let message: Value = serde_json::from_str(&text).unwrap();
        let sub = message[1].as_str().unwrap().to_string();
        let ids = seen.entry(sub).or_default();
        if message[0] == "EVENT" {
            ids.push(message[2]["id"].as_str().unwrap().to_string());
        }
    }
    let _tx = opener.await.unwrap();
    let mut published = publisher.await.unwrap();
    published.sort();
    for (sub, mut ids) in seen {
        ids.sort();
        assert_eq!(ids, published, "{sub}");
    }
    let extra = tokio::time::timeout(Duration::from_millis(200), rx.next()).await;
    assert!(extra.is_err(), "unexpected {extra:?}");
}

#[tokio::test]
async fn relays_ephemeral_events_without_storing_them() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut alice = harness.client().await;
    let mut bob = harness.client().await;
    bob.query("live", &[json!({"kinds": [20001]})]).await;

    let typing = Event::sign(ALICE, now(), 20_001, vec![], "typing");
    assert_eq!(alice.publish(&typing).await[2], true);
    assert_eq!(bob.recv().await[2]["id"], typing.id);
    assert!(bob.query("stored", &[json!({"kinds": [20001]})]).await.is_empty());
}

#[tokio::test]
async fn honors_deletion_and_replacement() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut alice = harness.client().await;
    let at = now();

    let profile = Event::sign(ALICE, at - 10, 0, vec![], "old");
    let newer = Event::sign(ALICE, at, 0, vec![], "new");
    alice.publish(&profile).await;
    alice.publish(&newer).await;
    let reply = alice.publish(&profile).await;
    assert_eq!(reply[2], false);
    assert!(reply[3].as_str().unwrap().starts_with("duplicate:"));
    assert_eq!(alice.query("p", &[json!({"kinds": [0]})]).await, [newer]);

    let oops = note(ALICE, "oops");
    alice.publish(&oops).await;
    alice.publish(&Event::sign(ALICE, at, 5, tags(&[&["e", &oops.id]]), "")).await;
    assert!(alice.query("o", &[json!({"ids": [oops.id]})]).await.is_empty());
    let reply = alice.publish(&oops).await;
    assert_eq!(reply[2], false);
    assert!(reply[3].as_str().unwrap().starts_with("blocked:"));
}

#[tokio::test]
async fn refuses_what_it_should() {
    let config = RelayConfig { max_filters: 2, max_subscriptions: 2, events_per_minute: 2, ..RelayConfig::default() };
    let harness = Harness::new(config).await;
    let mut client = harness.client().await;

    let mut forged = note(ALICE, "real");
    forged.content = "forged".into();
    assert_eq!(client.publish(&forged).await, json!(["OK", forged.id, false, "invalid: bad id or signature"]));

    let future = Event::sign(ALICE, now() + 3600, 1, vec![], "");
    assert_eq!(client.publish(&future).await[3], "invalid: created_at is too far in the future");

    let expired = Event::sign(ALICE, now(), 1, tags(&[&["expiration", "1000"]]), "");
    assert_eq!(client.publish(&expired).await[3], "invalid: event has expired");

    // Only events that pass the cheap checks count. The third in a minute
    // is one too many.
    assert_eq!(client.publish(&note(BOB, "x")).await[2], true);
    assert_eq!(client.publish(&note(BOB, "y")).await[3], "rate-limited: slow down");

    client.send(json!(["REQ", "s", {}, {}, {}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "s", "invalid: too many filters"]));
    client.send(json!(["REQ", "s", {"search": "x"}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "s", "unsupported: filter field search"]));

    client.query("a", &[json!({"kinds": [1]})]).await;
    client.query("b", &[json!({"kinds": [1]})]).await;
    // Replacing an open one is fine; a third isn't.
    client.query("b", &[json!({"kinds": [1]})]).await;
    client.send(json!(["REQ", "c", {}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "c", "rate-limited: too many open subscriptions"]));

    client.send(json!({"not": "an array"})).await;
    assert_eq!(client.recv().await[0], "NOTICE");
    client.send(json!(["AUTH", "x"])).await;
    assert_eq!(client.recv().await, json!(["NOTICE", "unsupported: AUTH messages"]));
}

#[tokio::test]
async fn describes_itself() {
    let harness = Harness::new(RelayConfig::default()).await;
    let request = Request::builder().uri("/").header("accept", "application/nostr+json").body(axum::body::Body::empty()).unwrap();
    let response = harness.relay.clone().oneshot(request).await.unwrap();
    assert_eq!(response.headers()["content-type"], "application/nostr+json");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let info: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(info["software"], "armada-stack");
    assert_eq!(info["supported_nips"], json!([1, 9, 11, 40]));
    assert_eq!(info["limitation"]["max_limit"], 500);
}
