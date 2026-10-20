//! The push service end to end: a client talking to it over the relay's
//! WebSocket, and a push service of its own on loopback receiving what it
//! sends.

use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::routing::post;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, StatusCode};
use p256::SecretKey;
use secp256k1::XOnlyPublicKey;
use serde_json::{Value, json};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use super::*;
use crate::config::RelayConfig;
use crate::nostr::event::public_key;
use crate::relay::Relay;
use crate::relay::nip44::payload as wrap_content;

const CLIENT: &str = "00000000000000000000000000000000000000000000000000000000000000c1";
const ALICE: &str = "00000000000000000000000000000000000000000000000000000000000000a1";
const BOB: &str = "00000000000000000000000000000000000000000000000000000000000000b1";
const RELAY_URL: &str = "wss://armada.example.com";

struct Harness {
    _dir: tempfile::TempDir,
    url: String,
    service: String,
    /// What the fake push service was sent.
    pushes: mpsc::UnboundedReceiver<(HeaderMap, Bytes)>,
    endpoint: String,
    /// What it answers with.
    status: Arc<AtomicU16>,
    _cancel: tokio_util::sync::DropGuard,
}

impl Harness {
    async fn new() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::allowing_private(dir.path());
        let cancel = CancellationToken::new();
        let relay = Relay::open(&RelayConfig::default(), Default::default(), Default::default(), None, &storage, &cancel).unwrap();
        let push = Push::open(&storage).unwrap();
        let service = push.pubkey().to_string();
        let options = Options { relay_url: Some(RELAY_URL.into()), subject: "https://armada.example.com".into(), public_only: false };
        push.start(relay.internal(), options, cancel.clone()).unwrap();
        let url = serve(relay.router()).await.replace("http://", "ws://");

        let (tx, pushes) = mpsc::unbounded_channel();
        let status = Arc::new(AtomicU16::new(201));
        let answer = status.clone();
        let fake = Router::new().route(
            "/push/abc",
            post(move |headers: HeaderMap, body: Bytes| async move {
                let _ = tx.send((headers, body));
                StatusCode::from_u16(answer.load(Ordering::Relaxed)).unwrap()
            }),
        );
        let endpoint = format!("{}/push/abc", serve(fake).await);
        Harness { _dir: dir, url, service, pushes, endpoint, status, _cancel: cancel.drop_guard() }
    }

    async fn socket(&self) -> WebSocketStream<MaybeTlsStream<TcpStream>> {
        tokio_tungstenite::connect_async(self.url.as_str()).await.unwrap().0
    }

    async fn client(&self) -> Client {
        let mut socket = self.socket().await;
        let service: XOnlyPublicKey = self.service.parse().unwrap();
        let key = nip44::conversation_key(&secp256k1::SecretKey::from_slice(&hex::decode(CLIENT).unwrap()).unwrap(), &service);
        let filter = json!({"kinds": [KIND], "authors": [self.service], "#p": [public_key(CLIENT)]});
        send(&mut socket, json!(["REQ", "answers", filter])).await;
        assert_eq!(recv(&mut socket).await[0], "EOSE");
        Client { socket, service: self.service.clone(), key, next: 0 }
    }

    async fn push(&mut self) -> (HeaderMap, Value) {
        let (headers, body) = tokio::time::timeout(Duration::from_secs(5), self.pushes.recv()).await.expect("a push in time").unwrap();
        let plaintext = webpush::tests::decrypt(&SecretKey::from_slice(&[7; 32]).unwrap(), &[1; 16], &body);
        (headers, serde_json::from_slice(&plaintext).unwrap())
    }

    async fn no_push(&mut self) {
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(self.pushes.try_recv().is_err(), "an unexpected push");
    }
}

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await });
    url
}

async fn send(socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>, message: Value) {
    socket.send(Message::Text(message.to_string().into())).await.unwrap();
}

async fn recv(socket: &mut WebSocketStream<MaybeTlsStream<TcpStream>>) -> Value {
    let message = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.expect("a message in time");
    match message.unwrap().unwrap() {
        Message::Text(text) => serde_json::from_str(&text).unwrap(),
        other => panic!("unexpected {other:?}"),
    }
}

struct Client {
    socket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    service: String,
    key: [u8; 32],
    next: u32,
}

impl Client {
    /// Make a request and wait for its answer: its `result`, or its `error`.
    async fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next += 1;
        let id = self.next.to_string();
        let content = nip44::encrypt(&self.key, &json!({"id": id, "method": method, "params": params}).to_string()).unwrap();
        let request = Event::sign(CLIENT, now(), KIND, vec![vec!["p".into(), self.service.clone()]], &content);
        send(&mut self.socket, json!(["EVENT", request])).await;
        loop {
            let message = recv(&mut self.socket).await;
            match message[0].as_str().unwrap() {
                "OK" => assert_eq!(message[2], true, "{message}"),
                "EVENT" => {
                    let answer: Event = serde_json::from_value(message[2].clone()).unwrap();
                    assert!(answer.verify());
                    let answer: Value = serde_json::from_str(&nip44::decrypt(&self.key, &answer.content).unwrap()).unwrap();
                    assert_eq!(answer["id"], id);
                    return match answer.get("error") {
                        Some(error) => Err(error.as_str().unwrap().to_string()),
                        None => Ok(answer["result"].clone()),
                    };
                }
                _ => panic!("unexpected {message}"),
            }
        }
    }
}

fn wrap_for(recipient: &str) -> Event {
    Event::sign(ALICE, now() - 3600, 1059, vec![vec!["p".into(), public_key(recipient)]], &wrap_content(200))
}

#[tokio::test]
async fn registers_and_pushes() {
    let mut harness = Harness::new().await;
    let mut client = harness.client().await;
    let bob = public_key(BOB);

    assert_eq!(client.call("get", json!(null)).await.unwrap_err(), UNKNOWN);
    assert_eq!(client.call("set", json!({"subscriptions": []})).await.unwrap_err(), UNKNOWN);
    assert_eq!(client.call("create", connection::tests::web(&harness.endpoint)).await, Ok(json!({})));
    assert_eq!(client.call("create", json!({"method": "apn"})).await.unwrap_err(), "method apn is not available on this service");
    assert_eq!(client.call("frob", json!(null)).await.unwrap_err(), "unknown method frob");
    assert_eq!(client.call("set", json!(null)).await.unwrap_err(), "params.subscriptions is required");
    assert_eq!(client.call("set", json!({"subscriptions": [{"filters": [{}], "relays": ["wss://a.example"]}]})).await.unwrap_err(), "A filter in subscription 0 matches everything; name ids, authors, kinds or a tag");
    // Only the filters Armada makes.
    let everyone = json!({"subscriptions": [{"filters": [{"kinds": [1059]}], "relays": ["wss://a.example"]}]});
    assert_eq!(client.call("set", everyone).await.unwrap_err(), "A filter in subscription 0 has to name either authors or #p");
    let profiles = json!({"subscriptions": [{"filters": [{"kinds": [0], "authors": [bob]}], "relays": ["wss://a.example"]}]});
    assert_eq!(client.call("set", profiles).await.unwrap_err(), "A filter in subscription 0 may only ask for gift wraps (kind 1059)");

    // Armada's group filters come along, and are dropped: this relay has
    // no group messages.
    let subscriptions = json!([
        {"filters": [{"kinds": [1059], "#p": [bob]}], "relays": ["wss://a.example"]},
        {"filters": [{"kinds": [9], "#h": ["g"]}], "relays": ["wss://groups.example"]},
    ]);
    assert_eq!(client.call("set", json!({"subscriptions": subscriptions})).await, Ok(json!({})));
    let got = client.call("get", json!(null)).await.unwrap();
    assert_eq!(got["subscriptions"].as_array().unwrap().len(), 1);
    assert_eq!(got["subscriptions"][0]["filters"][0]["#p"], json!([bob]));
    assert!(got["subscriptions"][0]["filters"][0]["since"].as_i64().unwrap() >= now() - 5);
    assert_eq!(client.call("ping", json!(null)).await, Ok(json!({})));

    // A wrap for Bob, dated back as NIP-59 dates them, is pushed.
    let mut alice = harness.socket().await;
    let wrap = wrap_for(BOB);
    send(&mut alice, json!(["EVENT", wrap])).await;
    assert_eq!(recv(&mut alice).await[2], true);
    let (headers, payload) = harness.push().await;
    assert_eq!(payload, json!({"$type": "napp.push.payload", "event_id": wrap.id, "relays": [RELAY_URL], "event": wrap}));
    assert_eq!(headers["ttl"], "86400");
    assert_eq!(headers["urgency"], "high");
    assert_eq!(headers["content-encoding"], "aes128gcm");
    assert!(headers["authorization"].to_str().unwrap().starts_with("vapid t="));

    // One for someone else isn't.
    send(&mut alice, json!(["EVENT", wrap_for(ALICE)])).await;
    recv(&mut alice).await;
    harness.no_push().await;

    // A wrap too big to carry is pointed at instead.
    let big = Event::sign(ALICE, now(), 1059, vec![vec!["p".into(), bob.clone()]], &wrap_content(4000));
    send(&mut alice, json!(["EVENT", big])).await;
    recv(&mut alice).await;
    assert_eq!(harness.push().await.1, json!({"$type": "napp.push.payload", "event_id": big.id, "relays": [RELAY_URL]}));

    // Re-creating keeps the subscriptions; deleting drops them.
    assert_eq!(client.call("create", connection::tests::web(&harness.endpoint)).await, Ok(json!({})));
    assert_eq!(client.call("get", json!(null)).await.unwrap()["subscriptions"], got["subscriptions"]);
    assert_eq!(client.call("delete", json!(null)).await, Ok(json!({})));
    assert_eq!(client.call("delete", json!(null)).await, Ok(json!({})));
    send(&mut alice, json!(["EVENT", wrap_for(BOB)])).await;
    recv(&mut alice).await;
    harness.no_push().await;
}

/// Subscriptions grow when tidied. Ones that would grow past what `get` can
/// send back are refused, rather than taking the service down when it tries.
#[tokio::test]
async fn refuses_subscriptions_too_large_to_hand_back() {
    let harness = Harness::new().await;
    let mut client = harness.client().await;
    client.call("create", connection::tests::web(&harness.endpoint)).await.unwrap();
    let subscription = json!({"filters": vec![json!({"kinds": [1059], "#p": [public_key(BOB)]}); subscriptions::MAX_FILTERS], "relays": ["ws://a"]});
    // The request fits in one message; its answer to `get` wouldn't have.
    let subscriptions = json!(vec![subscription; 60]);
    assert_eq!(client.call("set", json!({"subscriptions": subscriptions})).await.unwrap_err(), format!("Subscriptions come to more than {} bytes", subscriptions::MAX_SIZE));
    assert_eq!(client.call("get", json!(null)).await.unwrap(), json!({"subscriptions": []}));
}

#[tokio::test]
async fn forgets_subscriptions_that_are_gone() {
    let mut harness = Harness::new().await;
    let mut client = harness.client().await;
    client.call("create", connection::tests::web(&harness.endpoint)).await.unwrap();
    let subscriptions = json!([{"filters": [{"kinds": [1059], "#p": [public_key(BOB)]}], "relays": ["wss://a.example"]}]);
    client.call("set", json!({"subscriptions": subscriptions})).await.unwrap();

    harness.status.store(410, Ordering::Relaxed);
    let mut alice = harness.socket().await;
    send(&mut alice, json!(["EVENT", wrap_for(BOB)])).await;
    recv(&mut alice).await;
    harness.push().await;
    for _ in 0..50 {
        if client.call("ping", json!(null)).await.is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the client outlived its subscription");
}

#[test]
fn payloads_carry_the_event_if_it_fits() {
    let event = r#"{"id":"ab"}"#;
    assert_eq!(payload("ab", event, Some("wss://r.example")), r#"{"$type":"napp.push.payload","event_id":"ab","relays":["wss://r.example"],"event":{"id":"ab"}}"#);
    assert_eq!(payload("ab", event, None), r#"{"$type":"napp.push.payload","event_id":"ab","relays":[],"event":{"id":"ab"}}"#);
    let big = format!(r#"{{"id":"ab","content":"{}"}}"#, "x".repeat(PAYLOAD_BUDGET));
    assert_eq!(payload("ab", &big, None), r#"{"$type":"napp.push.payload","event_id":"ab","relays":[]}"#);
}

#[test]
fn parses_requests_as_nostr_push2_does() {
    assert_eq!(parse_request(r#"{"id":"1","method":"ping"}"#).unwrap().method, "ping");
    assert!(parse_request(r#"{"id":"1","method":"set","params":{"subscriptions":[]}}"#).unwrap().params.is_some());
    for bad in ["nope", r#"{"id":"","method":"ping"}"#, r#"{"id":1,"method":"ping"}"#, r#"{"method":"ping"}"#] {
        assert!(parse_request(bad).is_none(), "{bad}");
    }
    assert!(parse_request(&json!({"id": "x".repeat(65), "method": "ping"}).to_string()).is_none());
    assert!(parse_request(&json!({"id": "1", "method": "x".repeat(33)}).to_string()).is_none());
}

/// One site's push endpoints can only be signed up so fast, however many
/// keypairs ask: they're free to make.
#[tokio::test]
async fn limits_creates_by_site() {
    let harness = Harness::new().await;
    let mut client = harness.client().await;
    for _ in 0..CREATES_PER_SITE_PER_HOUR {
        client.call("create", connection::tests::web(&harness.endpoint)).await.unwrap();
    }
    let refused = client.call("create", connection::tests::web(&harness.endpoint)).await.unwrap_err();
    assert_eq!(refused, "too many clients for this push service; try again later");
    // Its existing registration is untouched.
    assert_eq!(client.call("ping", json!(null)).await, Ok(json!({})));
}

#[test]
fn tells_endpoints_sites() {
    assert_eq!(site("https://fcm.googleapis.com/fcm/send/abc"), "googleapis.com");
    assert_eq!(site("https://a.b.evil.example./x"), "evil.example");
    assert_eq!(site("https://localhost:8443/x"), "localhost");
    assert_eq!(site("https://203.0.113.9/x"), "203.0.113.9");
    assert_eq!(site("https://[2001:db8::1]/x"), "[2001:db8::1]");
    assert_eq!(host("https://Push.Example.com:8443/x"), "push.example.com");
}

#[test]
fn counts_a_clients_filter_values() {
    let hex = "ab".repeat(32);
    let subscriptions = subscriptions::normalize(&json!([{"filters": [{"kinds": [1059], "#p": [hex]}, {"kinds": [1059], "authors": [hex, hex, hex]}], "relays": ["wss://a.example"]}]), now()).unwrap();
    let client = db::Client { connection: Connection::parse(&connection::tests::web("https://push.example.com/x"), true).unwrap(), subscriptions, created_at: 0, last_seen: 0 };
    // Kinds, #p; kinds, authors.
    assert_eq!(client.filter_values(), 2 + 4);
}
