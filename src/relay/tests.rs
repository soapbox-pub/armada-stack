//! The relay end to end, over real WebSockets.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use axum::Router;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use tower::ServiceExt;

use super::*;
use crate::nostr::Event;
use crate::util::now;
use store::tests::{ALICE, BOB, tags};

const CAROL: &str = "0000000000000000000000000000000000000000000000000000000000000003";

struct Harness {
    _dir: tempfile::TempDir,
    url: String,
    relay: Router,
    handle: Relay,
    _cancel: tokio_util::sync::DropGuard,
}

impl Harness {
    async fn new(config: RelayConfig) -> Harness {
        Self::trusting(config, false).await
    }

    /// One whose relay believes `X-Forwarded-For` if `trust_proxy`.
    async fn trusting(config: RelayConfig, trust_proxy: bool) -> Harness {
        Self::open(config, trust_proxy, None).await
    }

    /// One that knows it's reached at `public_url`.
    async fn at(config: RelayConfig, public_url: &str) -> Harness {
        Self::open(config, false, Some(url::Url::parse(public_url).unwrap())).await
    }

    async fn open(config: RelayConfig, trust_proxy: bool, public_url: Option<url::Url>) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let cancel = CancellationToken::new();
        let relay = Relay::open(&config, public_url, trust_proxy, &Storage::allowing_private(dir.path()), &cancel).unwrap();
        let router = relay.router();
        let handle = relay.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let served = router.clone();
        tokio::spawn(async move { axum::serve(listener, served.into_make_service_with_connect_info::<std::net::SocketAddr>()).await });
        Harness { _dir: dir, url, relay: router, handle, _cancel: cancel.drop_guard() }
    }

    async fn client(&self) -> Client {
        self.client_via(None).await.unwrap()
    }

    /// A client whose request says it was forwarded for `forwarded`, or
    /// the status it was refused with.
    async fn client_via(&self, forwarded: Option<&str>) -> Result<Client, http::StatusCode> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Error;
        let mut request = self.url.as_str().into_client_request().unwrap();
        if let Some(forwarded) = forwarded {
            request.headers_mut().insert("x-forwarded-for", forwarded.parse().unwrap());
        }
        let socket = match tokio_tungstenite::connect_async(request).await {
            Ok((socket, _)) => socket,
            Err(Error::Http(response)) => return Err(response.status()),
            Err(error) => panic!("{error}"),
        };
        Ok(Client { socket, url: self.url.clone() })
    }
}

struct Client {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    url: String,
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

/// A user status: public, free text, and addressed by its content here, so
/// each is its own.
fn note(secret: &str, content: &str) -> Event {
    Event::sign(secret, now(), STATUS.into(), tags(&[&["d", content]]), content)
}

const STATUS: u16 = 30315;

#[tokio::test]
async fn stores_queries_and_streams() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut alice = harness.client().await;
    let mut bob = harness.client().await;

    let first = note(ALICE, "first");
    assert_eq!(alice.publish(&first).await, json!(["OK", first.id, true, ""]));
    assert_eq!(alice.publish(&first).await, json!(["OK", first.id, true, "duplicate: already have this event"]));

    // Stored events, then EOSE, then live ones.
    assert_eq!(bob.query("feed", &[json!({"kinds": [STATUS]})]).await, [first]);
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

/// NIP-50 isn't done here, but a search beside plain filters doesn't stop
/// them being answered: it just finds nothing.
#[tokio::test]
async fn answers_the_rest_of_a_req_with_a_search() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut client = harness.client().await;
    let status = note(ALICE, "searchable");
    client.publish(&status).await;

    let filters = [json!({"kinds": [STATUS]}), json!({"kinds": [STATUS], "search": "searchable"})];
    assert_eq!(client.query("both", &filters).await, std::slice::from_ref(&status));
    assert!(client.query("alone", &[json!({"search": "searchable"})]).await.is_empty());
    client.send(json!(["CLOSE", "both"])).await;
    client.send(json!(["CLOSE", "alone"])).await;
    client.send(json!(["REQ", "s", {"search": 1}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "s", "invalid: search must be a string"]));

    // Nor does it see live events.
    client.query("live", &[json!({"search": "later"})]).await;
    client.publish(&note(ALICE, "later")).await;
    client.quiet().await;
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
            let req = json!(["REQ", format!("s{i}"), {"kinds": [STATUS]}]);
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
async fn honors_deletion_and_replacement() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut alice = harness.client().await;
    let at = now();

    let profile = Event::sign(ALICE, at - 10, 0, vec![], r#"{"name":"old"}"#);
    let newer = Event::sign(ALICE, at, 0, vec![], r#"{"name":"new"}"#);
    alice.publish(&profile).await;
    alice.publish(&newer).await;
    let reply = alice.publish(&profile).await;
    assert_eq!(reply[2], false);
    assert!(reply[3].as_str().unwrap().starts_with("duplicate:"));
    assert_eq!(alice.query("p", &[json!({"kinds": [0]})]).await, [newer]);

    let oops = note(ALICE, "oops");
    alice.publish(&oops).await;
    let deletion = Event::sign(ALICE, at, 5, tags(&[&["e", &oops.id]]), "");
    alice.publish(&deletion).await;
    assert!(alice.query("o", &[json!({"ids": [oops.id]})]).await.is_empty());
    let reply = alice.publish(&oops).await;
    assert_eq!(reply[2], false);
    assert!(reply[3].as_str().unwrap().starts_with("blocked:"));

    // Deletion requests are anyone's to read.
    let author = crate::nostr::event::public_key(ALICE);
    let mut bob = harness.client().await;
    assert_eq!(bob.query("d", &[json!({"kinds": [5], "#e": [oops.id]})]).await, std::slice::from_ref(&deletion));
    assert_eq!(bob.query("d", &[json!({"kinds": [5], "authors": [author]})]).await, [deletion]);
}

#[tokio::test]
async fn refuses_what_it_should() {
    let config = RelayConfig { max_filters: 2, max_subscriptions: 2, events_per_minute: 2, ..RelayConfig::default() };
    let harness = Harness::new(config).await;
    let mut client = harness.client().await;

    let mut forged = note(ALICE, "real");
    forged.content = "forged".into();
    assert_eq!(client.publish(&forged).await, json!(["OK", forged.id, false, "invalid: bad id or signature"]));

    let future = Event::sign(ALICE, now() + 3600, STATUS.into(), tags(&[&["d", ""]]), "");
    assert_eq!(client.publish(&future).await[3], "invalid: created_at is too far in the future");

    let expired = Event::sign(ALICE, now(), STATUS.into(), tags(&[&["d", ""], &["expiration", "1000"]]), "");
    assert_eq!(client.publish(&expired).await[3], "invalid: event has expired");

    // Only the kinds Armada uses, in the shape it gives them.
    let text_note = Event::sign(ALICE, now(), 1, vec![], "hello");
    assert_eq!(client.publish(&text_note).await[3], "blocked: kind 1 is not accepted by this relay");
    let profile = Event::sign(ALICE, now(), 0, vec![], "not json");
    assert_eq!(client.publish(&profile).await[3], "invalid: content must be a JSON object");

    // Only events that pass the cheap checks count. The third in a minute
    // is one too many.
    assert_eq!(client.publish(&note(BOB, "x")).await[2], true);
    assert_eq!(client.publish(&note(BOB, "y")).await[3], "rate-limited: slow down");

    client.send(json!(["REQ", "s", {}, {}, {}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "s", "invalid: too many filters"]));
    client.send(json!(["REQ", "s", {"#title": ["x"]}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "s", "unsupported: filter field #title"]));

    client.query("a", &[json!({"kinds": [STATUS]})]).await;
    client.query("b", &[json!({"kinds": [STATUS]})]).await;
    // Replacing an open one is fine; a third isn't.
    client.query("b", &[json!({"kinds": [STATUS]})]).await;
    client.send(json!(["REQ", "c", {}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "c", "rate-limited: too many open subscriptions"]));

    client.send(json!({"not": "an array"})).await;
    assert_eq!(client.recv().await[0], "NOTICE");
    client.send(json!(["AUTH", "x"])).await;
    assert_eq!(client.recv().await, json!(["NOTICE", "unsupported: AUTH messages"]));
    client.send(json!(["COUNT", "x", {}])).await;
    assert_eq!(client.recv().await, json!(["CLOSED", "x", "unsupported: COUNT isn't supported"]));
    client.send(json!(["NEG-OPEN", "x", {}, ""])).await;
    assert_eq!(client.recv().await, json!(["NOTICE", "unsupported: NEG-OPEN messages"]));
}

#[tokio::test]
async fn caps_each_addresss_connections() {
    let harness = Harness::new(RelayConfig { max_connections_per_ip: 2, ..RelayConfig::default() }).await;
    let first = harness.client().await;
    let _second = harness.client().await;
    assert_eq!(harness.client_via(None).await.err(), Some(http::StatusCode::TOO_MANY_REQUESTS));
    // A client's own X-Forwarded-For isn't believed, with no proxy in front.
    assert_eq!(harness.client_via(Some("203.0.113.9")).await.err(), Some(http::StatusCode::TOO_MANY_REQUESTS));

    // Closing one frees its place, once the relay notices.
    drop(first);
    let mut third = None;
    for _ in 0..50 {
        if let Ok(client) = harness.client_via(None).await {
            third = Some(client);
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(third.is_some(), "the closed connection's place was never freed");
}

#[tokio::test]
async fn caps_each_client_behind_a_proxy() {
    let harness = Harness::trusting(RelayConfig { max_connections_per_ip: 1, ..RelayConfig::default() }, true).await;
    let _one = harness.client_via(Some("203.0.113.9")).await.unwrap();
    assert_eq!(harness.client_via(Some("203.0.113.9")).await.err(), Some(http::StatusCode::TOO_MANY_REQUESTS));
    // Only the entry the proxy appended counts.
    assert_eq!(harness.client_via(Some("6.6.6.6, 203.0.113.9")).await.err(), Some(http::StatusCode::TOO_MANY_REQUESTS));
    let _other = harness.client_via(Some("198.51.100.1")).await.unwrap();
    // One IPv6 /64 is one client.
    let _v6 = harness.client_via(Some("2001:db8::1")).await.unwrap();
    assert_eq!(harness.client_via(Some("2001:db8::2")).await.err(), Some(http::StatusCode::TOO_MANY_REQUESTS));
}

#[tokio::test]
async fn shares_an_event_budget_across_an_addresss_connections() {
    let harness = Harness::new(RelayConfig { events_per_minute: 0, events_per_minute_per_ip: 3, ..RelayConfig::default() }).await;
    let mut a = harness.client().await;
    let mut b = harness.client().await;
    assert_eq!(a.publish(&note(ALICE, "1")).await[2], true);
    assert_eq!(a.publish(&note(ALICE, "2")).await[2], true);
    assert_eq!(b.publish(&note(ALICE, "3")).await[2], true);
    assert_eq!(b.publish(&note(ALICE, "4")).await[3], "rate-limited: slow down");
    // A new connection doesn't bring a new budget.
    let mut c = harness.client().await;
    assert_eq!(c.publish(&note(ALICE, "5")).await[3], "rate-limited: slow down");
}

#[tokio::test]
async fn limits_the_bytes_an_address_publishes() {
    let config = RelayConfig { max_content_length: 4000, event_bytes_per_hour_per_ip: 10_000, ..RelayConfig::default() };
    let harness = Harness::new(config).await;
    let mut a = harness.client().await;
    let mut b = harness.client().await;
    // About 3,100 bytes each, as counted: three fit in the hour's 10,000.
    let big = |n: &str| Event::sign(ALICE, now(), STATUS.into(), tags(&[&["d", n]]), &"x".repeat(2700));
    assert_eq!(a.publish(&big("1")).await[2], true);
    assert_eq!(b.publish(&big("2")).await[2], true);
    assert_eq!(a.publish(&big("3")).await[2], true);
    assert_eq!(b.publish(&big("4")).await[3], "rate-limited: slow down");
    // Small ones still fit in what's left.
    assert_eq!(a.publish(&note(ALICE, "small")).await[2], true);
}

#[tokio::test]
async fn shares_a_req_budget_across_an_addresss_connections() {
    let harness = Harness::new(RelayConfig { reqs_per_minute_per_ip: 3, ..RelayConfig::default() }).await;
    let mut a = harness.client().await;
    let mut b = harness.client().await;
    let filter = json!({"kinds": [STATUS]});
    a.query("1", std::slice::from_ref(&filter)).await;
    a.query("2", std::slice::from_ref(&filter)).await;
    b.query("3", std::slice::from_ref(&filter)).await;
    b.send(json!(["REQ", "3", filter])).await;
    assert_eq!(b.recv().await, json!(["CLOSED", "3", "rate-limited: slow down"]));
    // Which closes the subscription it would have replaced.
    let mut c = harness.client().await;
    assert_eq!(c.publish(&note(ALICE, "x")).await[2], true);
    b.quiet().await;
}

/// Filters' values are held in memory while their subscription is open, so
/// there's a ceiling on them, in one REQ and across an address's.
#[tokio::test]
async fn limits_filter_values() {
    let config = RelayConfig { max_filter_values: 4, max_filter_values_per_ip: 6, ..RelayConfig::default() };
    let harness = Harness::new(config).await;
    let mut a = harness.client().await;
    let mut b = harness.client().await;
    // A kind and so many topics.
    let topics = |n: usize| json!({"kinds": [STATUS], "#t": (0..n).map(|i| i.to_string()).collect::<Vec<_>>()});

    a.send(json!(["REQ", "big", topics(4)])).await;
    assert_eq!(a.recv().await, json!(["CLOSED", "big", "invalid: filters list more than 4 values"]));
    a.send(json!(["REQ", "big", topics(2), topics(2)])).await;
    assert_eq!(a.recv().await, json!(["CLOSED", "big", "invalid: filters list more than 4 values"]));

    a.query("four", &[topics(3)]).await;
    // Replacing it counts only the new one.
    a.query("four", &[topics(3)]).await;
    let full = "rate-limited: too many filter values in open subscriptions; close some";
    b.send(json!(["REQ", "three", topics(2)])).await;
    assert_eq!(b.recv().await, json!(["CLOSED", "three", full]));
    b.query("two", &[topics(1)]).await;

    // Closing one gives its back, and so does going away.
    a.send(json!(["CLOSE", "four"])).await;
    // An answer means the CLOSE before it was read.
    a.send(json!(["REQ", "big", topics(4)])).await;
    assert_eq!(a.recv().await[0], "CLOSED");
    b.query("three", &[topics(2)]).await;
    b.send(json!(["REQ", "more", topics(2)])).await;
    assert_eq!(b.recv().await, json!(["CLOSED", "more", full]));
    drop(b);
    let mut c = harness.client().await;
    for _ in 0..50 {
        c.send(json!(["REQ", "after", topics(3)])).await;
        if c.recv().await == json!(["EOSE", "after"]) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the closed connection's values were never given back");
}

/// Queries replaced, closed, or left behind by a closed connection give
/// back their client's place, so the next one runs.
#[tokio::test]
async fn gives_back_query_places() {
    let harness = Harness::new(RelayConfig { max_queries_per_ip: 1, ..RelayConfig::default() }).await;
    let mut a = harness.client().await;
    a.publish(&note(ALICE, "x")).await;
    let filter = json!({"kinds": [STATUS]});
    for _ in 0..50 {
        a.send(json!(["REQ", "same", filter])).await;
    }
    for n in 0..50 {
        a.send(json!(["REQ", n.to_string(), filter])).await;
        a.send(json!(["CLOSE", n.to_string()])).await;
    }
    let mut gone = harness.client().await;
    for n in 0..20 {
        gone.send(json!(["REQ", n.to_string(), filter])).await;
    }
    drop(gone);

    let mut b = harness.client().await;
    assert_eq!(b.query("last", &[filter]).await.len(), 1);
    // The last of the replaced ones still answers. (The closed ones may
    // have too, if they finished before their CLOSE was read.)
    while a.recv().await != json!(["EOSE", "same"]) {}
}

#[tokio::test]
async fn refuses_a_client_with_no_address() {
    let harness = Harness::new(RelayConfig::default()).await;
    // Served without the peer's address, unlike any real server.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}", listener.local_addr().unwrap());
    let router = harness.relay.clone();
    tokio::spawn(async move { axum::serve(listener, router).await });
    match tokio_tungstenite::connect_async(&url).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => assert_eq!(response.status(), http::StatusCode::BAD_REQUEST),
        other => panic!("unexpected {other:?}"),
    }
}

/// A gift wrap from `secret` to `recipient`'s key, backdated `ago` seconds
/// as NIP-59 says, which tells apart ones made in the same second.
fn wrap(secret: &str, kind: u16, recipient: &str, ago: i64) -> Event {
    let recipient = crate::nostr::event::public_key(recipient);
    Event::sign(secret, now() - ago, kind.into(), tags(&[&["p", &recipient]]), &nip44::payload(200))
}

#[tokio::test]
async fn shows_gift_wraps_only_to_filters_naming_their_author_or_recipient() {
    let harness = Harness::new(RelayConfig::default()).await;
    let (alice, bob) = (crate::nostr::event::public_key(ALICE), crate::nostr::event::public_key(BOB));
    let mut sender = harness.client().await;
    let mut recipient = harness.client().await;
    let mut stranger = harness.client().await;

    // Anyone may publish one.
    let first = wrap(BOB, policy::GIFT_WRAP, ALICE, 100);
    assert_eq!(sender.publish(&first).await, json!(["OK", first.id, true, ""]));

    // Nobody may ask for everyone's.
    stranger.send(json!(["REQ", "s", {"kinds": [1059]}])).await;
    let closed = stranger.recv().await;
    assert_eq!((&closed[0], &closed[1]), (&json!("CLOSED"), &json!("s")));
    assert!(closed[2].as_str().unwrap().starts_with("restricted:"), "{closed}");
    // Filters without kinds, and lookups by id, just don't find it, even
    // beside a filter that names its author.
    assert!(stranger.query("all", &[json!({}), json!({"kinds": [1059], "authors": [crate::nostr::event::public_key(CAROL)]})]).await.is_empty());
    assert!(stranger.query("all", &[json!({"authors": [bob]})]).await.is_empty());
    assert!(stranger.query("id", &[json!({"ids": [first.id]})]).await.is_empty());
    assert!(stranger.query("id", &[json!({"ids": [first.id]}), json!({"kinds": [1059], "authors": [alice]})]).await.is_empty());
    assert!(stranger.query("p", &[json!({"kinds": [1059], "authors": [alice], "#p": [alice]})]).await.is_empty());

    // Its recipient, by #p, and its author, by authors, whoever asks.
    assert_eq!(recipient.query("inbox", &[json!({"kinds": [1059], "#p": [alice]})]).await, std::slice::from_ref(&first));
    assert_eq!(sender.query("outbox", &[json!({"kinds": [1059], "authors": [bob]})]).await, std::slice::from_ref(&first));

    // Live, likewise.
    let second = wrap(BOB, policy::GIFT_WRAP, ALICE, 50);
    sender.publish(&second).await;
    assert_eq!(sender.recv().await[2]["id"], second.id);
    assert_eq!(recipient.recv().await[2]["id"], second.id);
    stranger.quiet().await;

    // Big ones too, up to the content limit.
    let big = Event::sign(BOB, now() - 25, 1059, tags(&[&["p", &alice]]), &nip44::payload(600_000));
    assert_eq!(sender.publish(&big).await, json!(["OK", big.id, true, ""]));
    assert_eq!(sender.recv().await[2]["id"], big.id);
    assert_eq!(recipient.recv().await[2]["id"], big.id);

    // Ephemeral wraps are kept a while, for clients catching up.
    let typing = wrap(BOB, policy::EPHEMERAL_GIFT_WRAP, ALICE, 0);
    assert_eq!(sender.publish(&typing).await[2], true);
    assert_eq!(recipient.query("typing", &[json!({"kinds": [21059], "#p": [alice]})]).await, [typing]);
}

/// A gift wrap's author is a throwaway key or a Concord stream address, so
/// naming it is enough to read its wraps: that's how a Concord member reads
/// a Control Plane only staff can sign.
#[tokio::test]
async fn shows_gift_wraps_to_filters_naming_their_author() {
    let harness = Harness::new(RelayConfig::default()).await;
    let (alice, bob) = (crate::nostr::event::public_key(ALICE), crate::nostr::event::public_key(BOB));
    let mut sender = harness.client().await;
    let mut reader = harness.client().await;
    let mut other = harness.client().await;

    let first = wrap(BOB, policy::GIFT_WRAP, ALICE, 100);
    sender.publish(&first).await;
    let typing = wrap(BOB, policy::EPHEMERAL_GIFT_WRAP, ALICE, 0);
    sender.publish(&typing).await;

    assert_eq!(reader.query("plane", &[json!({"kinds": [1059], "authors": [bob]})]).await, std::slice::from_ref(&first));
    assert_eq!(reader.query("both", &[json!({"kinds": [1059, 21059], "authors": [bob]})]).await, [typing.clone(), first.clone()]);
    assert_eq!(reader.query("id", &[json!({"ids": [first.id], "authors": [bob]})]).await, std::slice::from_ref(&first));
    // Alongside kinds anyone may read.
    assert_eq!(reader.query("mixed", &[json!({"kinds": [1059, 30078], "authors": [bob]})]).await, std::slice::from_ref(&first));

    // Live, only to the filter that named it: another subscription of the
    // same connection, and others' subscriptions, get nothing.
    for sub in ["plane", "both", "id", "mixed"] {
        reader.send(json!(["CLOSE", sub])).await;
    }
    reader.send(json!(["REQ", "live", {"kinds": [1059], "authors": [bob], "since": now()}, {"kinds": [0]}])).await;
    assert_eq!(reader.recv().await, json!(["EOSE", "live"]));
    reader.send(json!(["REQ", "everything", {}])).await;
    assert_eq!(reader.recv().await[0], "EOSE");
    other.send(json!(["REQ", "elsewhere", {"kinds": [1059], "authors": [alice]}])).await;
    assert_eq!(other.recv().await, json!(["EOSE", "elsewhere"]));
    let second = wrap(BOB, policy::GIFT_WRAP, ALICE, 0);
    sender.publish(&second).await;
    let delivered = reader.recv().await;
    assert_eq!((&delivered[1], &delivered[2]["id"]), (&json!("live"), &json!(second.id)));
    reader.quiet().await;
    other.quiet().await;
}

#[tokio::test]
async fn shows_app_data_to_anyone() {
    let harness = Harness::new(RelayConfig::default()).await;
    let alice = crate::nostr::event::public_key(ALICE);
    let mut client = harness.client().await;
    let settings = Event::sign(ALICE, now(), policy::APP_DATA.into(), tags(&[&["d", "armada/metadata"]]), &nip44::payload(100));
    assert_eq!(client.publish(&settings).await[2], true);
    let mut stranger = harness.client().await;
    assert_eq!(stranger.query("s", &[json!({"kinds": [30078], "authors": [alice]})]).await, [settings]);
}

/// NIP-70 has a relay take a protected event only from a connection
/// authenticated as its author, and there's no authenticating here.
#[tokio::test]
async fn refuses_protected_events() {
    let harness = Harness::new(RelayConfig::default()).await;
    let mut client = harness.client().await;
    let status = Event::sign(ALICE, now(), STATUS.into(), tags(&[&["d", ""], &["-"]]), "mine");
    assert!(client.publish(&status).await[3].as_str().unwrap().starts_with("blocked:"));
}

#[tokio::test]
async fn vanishes_on_request() {
    let harness = Harness::at(RelayConfig::default(), "https://armada.example.com").await;
    let mut client = harness.client().await;
    let status = note(ALICE, "here");
    client.publish(&status).await;
    let elsewhere = Event::sign(ALICE, now(), 62, tags(&[&["relay", "wss://elsewhere.example.com"]]), "");
    assert_eq!(client.publish(&elsewhere).await[2], false);
    let request = Event::sign(ALICE, now(), 62, tags(&[&["relay", "wss://armada.example.com"]]), "");
    assert_eq!(client.publish(&request).await, json!(["OK", request.id, true, ""]));
    assert!(client.query("s", &[json!({})]).await.is_empty());
    assert_eq!(client.publish(&status).await[3], "blocked: this event has been deleted");
}

/// Without `public_url` the relay doesn't know its name, and won't take
/// one from `Host`: a request meant for another relay could be replayed
/// here under that relay's name.
#[tokio::test]
async fn takes_no_name_from_the_host_header() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let harness = Harness::new(RelayConfig::default()).await;
    let mut request = harness.url.as_str().into_client_request().unwrap();
    request.headers_mut().insert("host", "elsewhere.example.com".parse().unwrap());
    let (socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    let mut client = Client { socket, url: harness.url.clone() };
    let status = note(ALICE, "here");
    client.publish(&status).await;

    let meant_for_elsewhere = Event::sign(ALICE, now(), 62, tags(&[&["relay", "wss://elsewhere.example.com"]]), "");
    assert_eq!(client.publish(&meant_for_elsewhere).await[2], false);
    let own_url = client.url.clone();
    assert_eq!(client.publish(&Event::sign(ALICE, now(), 62, tags(&[&["relay", &own_url]]), "")).await[2], false);
    assert_eq!(client.query("s", &[json!({})]).await.len(), 1);

    let everywhere = Event::sign(ALICE, now(), 62, tags(&[&["relay", "ALL_RELAYS"]]), "");
    assert_eq!(client.publish(&everywhere).await[2], true);
    assert!(client.query("s", &[json!({})]).await.is_empty());
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
    assert_eq!(info["supported_nips"], json!([1, 9, 11, 40, 62]));
    assert_eq!(info["limitation"]["restricted_writes"], true);
    assert_eq!(info["limitation"]["max_limit"], 500);
}

/// NIP-46 runs between a client's throwaway key and a remote signer: each
/// finds what's meant for it by naming itself.
#[tokio::test]
async fn carries_nip46_between_parties_that_name_themselves() {
    let harness = Harness::new(RelayConfig::default()).await;
    let (app, signer) = (crate::nostr::event::public_key(ALICE), crate::nostr::event::public_key(BOB));
    let mut client = harness.client().await;
    let mut bunker = harness.client().await;
    let mut stranger = harness.client().await;

    client.send(json!(["REQ", "replies", {"kinds": [24133], "#p": [app]}])).await;
    assert_eq!(client.recv().await, json!(["EOSE", "replies"]));
    bunker.send(json!(["REQ", "requests", {"kinds": [24133], "#p": [signer]}])).await;
    assert_eq!(bunker.recv().await, json!(["EOSE", "requests"]));
    // Someone watching the signer's outbox, by its author.
    stranger.send(json!(["REQ", "outbox", {"kinds": [24133], "authors": [signer]}])).await;
    assert_eq!(stranger.recv().await, json!(["EOSE", "outbox"]));
    // Asking for everyone's is refused, and without kinds finds none.
    stranger.send(json!(["REQ", "all", {"kinds": [24133]}])).await;
    assert!(stranger.recv().await[2].as_str().unwrap().starts_with("restricted:"));
    stranger.send(json!(["REQ", "any", {}])).await;
    assert_eq!(stranger.recv().await, json!(["EOSE", "any"]));

    let request = wrap(ALICE, policy::NIP46, BOB, 0);
    assert_eq!(client.publish(&request).await[2], true);
    assert_eq!(bunker.recv().await[2]["id"], request.id);
    let reply = wrap(BOB, policy::NIP46, ALICE, 0);
    assert_eq!(bunker.publish(&reply).await[2], true);
    assert_eq!(client.recv().await[2]["id"], reply.id);
    let seen = stranger.recv().await;
    assert_eq!((&seen[1], &seen[2]["id"]), (&json!("outbox"), &json!(reply.id)));
    client.quiet().await;
    bunker.quiet().await;
    stranger.quiet().await;

    // Kept briefly, for a party that reconnects.
    assert_eq!(stranger.query("late", &[json!({"kinds": [24133], "#p": [signer]})]).await, [request]);
}

/// A service inside armada sees new events under a client's rules, and
/// publishes its own.
#[tokio::test]
async fn serves_internal_connections() {
    let harness = Harness::new(RelayConfig::default()).await;
    let internal = harness.handle.internal();
    let (conn, mut rx, _) = internal.connect(16).await;
    let bob = crate::nostr::event::public_key(BOB);
    assert!(internal.subscribe(conn, "s", &[json!({"kinds": [1059]})]).await.unwrap_err().starts_with("restricted:"));
    internal.subscribe(conn, "s", &[json!({"kinds": [1059], "#p": [bob]})]).await.unwrap();

    let mut alice = harness.client().await;
    let wrap = Event::sign(ALICE, now(), 1059, tags(&[&["p", &bob]]), &nip44::payload(100));
    alice.publish(&wrap).await;
    match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap() {
        Outbound::Event { sub, json, .. } => {
            assert_eq!(&*sub, "s");
            assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), wrap);
        }
        other => panic!("unexpected {other:?}"),
    }

    // What it publishes reaches clients.
    let mut carol = harness.client().await;
    assert!(carol.query("mine", &[json!({"kinds": [1059], "#p": [bob]})]).await.len() == 1);
    let reply = Event::sign(CAROL, now(), 1059, tags(&[&["p", &bob]]), &nip44::payload(100));
    assert!(internal.publish(&reply));
    assert_eq!(carol.recv().await, json!(["EVENT", "mine", reply]));
    internal.disconnect(conn).await;
}
