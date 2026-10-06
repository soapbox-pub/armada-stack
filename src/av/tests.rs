//! The broker end to end, through its router, without a network: tokens
//! are signed locally, and health checks never run.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::{Method, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use tower::ServiceExt;

use super::*;
use crate::nostr::Event;
use crate::nostr::event::public_key;

const ORIGIN: &str = "https://armada.example.com";

fn config(extra: &str) -> Config {
    Config::parse(&format!(
        "public_url = \"{ORIGIN}/\"\n[av]\n{extra}\n[[av.nodes]]\nurl = \"wss://sfu.example.com\"\napi_key = \"devkey\"\napi_secret = \"devsecret\"\n"
    ))
    .unwrap()
}

fn broker(extra: &str) -> Av {
    Av::new(&config(extra)).unwrap().unwrap()
}

fn secret() -> String {
    random_hex(32)
}

/// A grant, as Armada builds one.
fn grant(secret: &str) -> (String, String) {
    let room = public_key(secret);
    let tags = vec![
        vec!["u".into(), format!("{ORIGIN}{PATH}/{room}")],
        vec!["method".into(), "GET".into()],
        vec!["nonce".into(), random_hex(32)],
    ];
    let event = Event::sign(secret, now(), grant::KIND, tags, "");
    (room, format!("Concord {}", STANDARD.encode(serde_json::to_vec(&event).unwrap())))
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: Value,
}

async fn send(av: &Av, method: Method, path: &str, headers: &[(&str, &str)], peer: &str) -> Reply {
    let mut request = Request::builder().method(method).uri(path);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let mut request = request.body(Body::empty()).unwrap();
    let ip: std::net::IpAddr = peer.parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 4000)));
    let response = av.router().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() { Value::Null } else { serde_json::from_slice(&bytes).unwrap() };
    Reply { status: parts.status, headers: parts.headers, body }
}

async fn get(av: &Av, path: &str, authorization: Option<&str>, peer: &str) -> Reply {
    let headers: Vec<(&str, &str)> = authorization.map(|value| ("authorization", value)).into_iter().collect();
    send(av, Method::GET, path, &headers, peer).await
}

fn room_path(room: &str) -> String {
    format!("{PATH}/{room}")
}

#[test]
fn claims_only_its_paths() {
    assert!(wants(PATH));
    assert!(wants(&format!("{PATH}/")));
    assert!(wants(&room_path("abc")));
    assert!(!wants("/.well-known/concord/avatar"));
    assert!(!wants("/.well-known/concord"));
    assert!(Av::new(&Config::default()).unwrap().is_none());
}

#[tokio::test]
async fn answers_the_capability_probe() {
    let av = broker("");
    for path in [PATH, &format!("{PATH}/")] {
        let reply = get(&av, path, None, "1.2.3.4").await;
        assert_eq!(reply.status, StatusCode::NO_CONTENT);
        assert_eq!(reply.headers["access-control-allow-origin"], "*");
    }

    // And reports failure only when no node is up.
    av.broker.fleet.observe(0, Err(anyhow::anyhow!("down")));
    assert_eq!(get(&av, PATH, None, "1.2.3.4").await.status, StatusCode::NO_CONTENT);
    av.broker.fleet.observe(0, Err(anyhow::anyhow!("down")));
    assert_eq!(get(&av, PATH, None, "1.2.3.4").await.status, StatusCode::SERVICE_UNAVAILABLE);
    let secret = secret();
    let (room, header) = grant(&secret);
    let reply = get(&av, &room_path(&room), Some(&header), "1.2.3.4").await;
    assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn answers_the_preflight_the_authorization_header_forces() {
    let reply = send(&broker(""), Method::OPTIONS, &room_path("x"), &[], "1.2.3.4").await;
    assert_eq!(reply.status, StatusCode::NO_CONTENT);
    assert!(reply.headers["access-control-allow-headers"].to_str().unwrap().contains("Authorization"));
    assert!(reply.headers["access-control-allow-methods"].to_str().unwrap().contains("GET"));
}

#[tokio::test]
async fn mints_a_token_for_the_room_under_a_fresh_identity() {
    let av = broker("");
    let (room, header) = grant(&secret());
    let reply = get(&av, &room_path(&room), Some(&header), "1.2.3.4").await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.body["url"], "wss://sfu.example.com");
    let identity = reply.body["identity"].as_str().unwrap();
    assert!(identity.len() == 32 && identity.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(reply.headers["cache-control"], "no-store");
    assert_eq!(reply.headers["x-content-type-options"], "nosniff");

    let token = reply.body["token"].as_str().unwrap();
    let payload = token.split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["sub"], identity);
    assert_eq!(claims["iss"], "devkey");
    assert_eq!(claims["video"]["room"], room.as_str());
    assert_eq!(claims["video"]["roomJoin"], true);
    assert_eq!(claims["exp"].as_i64().unwrap() - claims["nbf"].as_i64().unwrap(), 6 * 60 * 60);
}

#[tokio::test]
async fn gives_two_joiners_of_one_room_distinct_identities() {
    // One Channel key signs both; only the nonce tells them apart.
    let av = broker("");
    let secret = secret();
    let (room, first) = grant(&secret);
    let (_, second) = grant(&secret);
    let a = get(&av, &room_path(&room), Some(&first), "1.2.3.4").await;
    let b = get(&av, &room_path(&room), Some(&second), "5.6.7.8").await;
    assert_eq!((a.status, b.status), (StatusCode::OK, StatusCode::OK));
    assert_ne!(a.body["identity"], b.body["identity"]);
}

#[tokio::test]
async fn refuses_a_replayed_grant() {
    let av = broker("");
    let (room, header) = grant(&secret());
    assert_eq!(get(&av, &room_path(&room), Some(&header), "1.2.3.4").await.status, StatusCode::OK);
    let replay = get(&av, &room_path(&room), Some(&header), "1.2.3.4").await;
    assert_eq!(replay.status, StatusCode::UNAUTHORIZED);
    assert_eq!(replay.body["error"], "grant already used");
}

#[tokio::test]
async fn refuses_grants_for_other_rooms_and_malformed_requests() {
    let av = broker("");
    let (room, header) = grant(&secret());
    let other = public_key(&secret());
    assert_eq!(get(&av, &room_path(&other), Some(&header), "1.2.3.4").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&av, &room_path(&room), None, "1.2.3.4").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&av, &room_path("not-a-room"), None, "1.2.3.4").await.status, StatusCode::NOT_FOUND);
    assert_eq!(get(&av, &room_path(&room.to_uppercase()), None, "1.2.3.4").await.status, StatusCode::NOT_FOUND);
    assert_eq!(get(&av, &format!("{}/x", room_path(&room)), None, "1.2.3.4").await.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn refuses_other_methods_and_names_what_is_allowed() {
    let reply = send(&broker(""), Method::POST, &room_path("x"), &[], "1.2.3.4").await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(reply.headers["allow"], "GET, OPTIONS");
    assert_eq!(reply.headers["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn rate_limits_each_client_before_checking_grants() {
    let av = broker("rate_limit_per_minute = 3");
    let room = public_key(&secret());
    for _ in 0..3 {
        assert_eq!(get(&av, &room_path(&room), None, "9.9.9.9").await.status, StatusCode::UNAUTHORIZED);
    }
    let limited = get(&av, &room_path(&room), None, "9.9.9.9").await;
    assert_eq!(limited.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(limited.headers.contains_key("retry-after"));
    assert_eq!(get(&av, &room_path(&room), None, "8.8.8.8").await.status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn rate_limits_an_ipv6_client_by_its_64() {
    let av = broker("rate_limit_per_minute = 3");
    let room = public_key(&secret());
    let mut limited = 0;
    for i in 0..10 {
        let status = get(&av, &room_path(&room), None, &format!("2001:db8:1:1::{i:x}")).await.status;
        limited += usize::from(status == StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(limited, 7);
    assert_eq!(get(&av, &room_path(&room), None, "2001:db8:1:2::1").await.status, StatusCode::UNAUTHORIZED);

    // An IPv4 peer seen through a dual-stack socket is that IPv4 address,
    // not one of everyone's shared /64.
    assert_eq!(get(&av, &room_path(&room), None, "::ffff:203.0.113.9").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&av, &room_path(&room), None, "203.0.113.9").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&av, &room_path(&room), None, "::ffff:198.51.100.4").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&av, &room_path(&room), None, "203.0.113.9").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(get(&av, &room_path(&room), None, "::ffff:203.0.113.9").await.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn behind_a_proxy_trusts_only_the_entry_it_appended() {
    // The default listen address is loopback, so a proxy is trusted.
    let av = broker("rate_limit_per_minute = 1");
    let room = public_key(&secret());
    let path = room_path(&room);
    let via = |forwarded: &'static str| [("x-forwarded-for", forwarded)];
    assert_eq!(send(&av, Method::GET, &path, &via("9.9.9.1, 203.0.113.9"), "127.0.0.1").await.status, StatusCode::UNAUTHORIZED);
    // Stuffing the left of the header doesn't make a new client.
    let stuffed = send(&av, Method::GET, &path, &via("9.9.9.2, 203.0.113.9"), "127.0.0.1").await;
    assert_eq!(stuffed.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(send(&av, Method::GET, &path, &via("203.0.113.10"), "127.0.0.1").await.status, StatusCode::UNAUTHORIZED);
    // With no header, the peer itself.
    assert_eq!(send(&av, Method::GET, &path, &[], "127.0.0.1").await.status, StatusCode::UNAUTHORIZED);

    // Not trusted, the header is the client's own and is ignored.
    let config = Config::parse(&format!(
        "public_url = \"{ORIGIN}\"\nlisten = \"0.0.0.0:8080\"\n[av]\nrate_limit_per_minute = 1\n[[av.nodes]]\nurl = \"wss://sfu.example.com\"\napi_key = \"k\"\napi_secret = \"s\"\n"
    ))
    .unwrap();
    let av = Av::new(&config).unwrap().unwrap();
    assert_eq!(send(&av, Method::GET, &path, &via("1.1.1.1"), "203.0.113.9").await.status, StatusCode::UNAUTHORIZED);
    assert_eq!(send(&av, Method::GET, &path, &via("2.2.2.2"), "203.0.113.9").await.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn refuses_a_request_with_no_peer_rather_than_sharing_a_bucket() {
    let av = broker("");
    let request = Request::builder().uri(room_path(&public_key(&secret()))).body(Body::empty()).unwrap();
    let response = av.router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn checks_grants_against_the_public_url_not_the_host() {
    let av = broker("");
    let secret = secret();
    let room = public_key(&secret);
    let tags = vec![vec!["u".into(), format!("https://evil.example.com{PATH}/{room}")], vec!["method".into(), "GET".into()]];
    let event = Event::sign(&secret, now(), grant::KIND, tags, "");
    let header = format!("Concord {}", STANDARD.encode(serde_json::to_vec(&event).unwrap()));
    let headers = [("authorization", header.as_str()), ("host", "evil.example.com")];
    let reply = send(&av, Method::GET, &room_path(&room), &headers, "1.2.3.4").await;
    assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
    assert_eq!(reply.body["error"], "grant `u` tag does not match this request");
}

/// A stand-in for a LiveKit node's HTTP server: `/rtc` a WebSocket that
/// first says what it was asked with, then echoes; `/rtc/validate` the same
/// as text; anything else a mark that it was reached.
async fn fake_node() -> SocketAddr {
    use axum::extract::ws::{Message, WebSocketUpgrade};

    fn described(request: &http::request::Parts) -> String {
        let header = |name: &str| request.headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("-").to_string();
        format!("{} {} {}", request.uri, header("x-forwarded-for"), header("host"))
    }

    let router = axum::Router::new()
        .route(
            "/rtc",
            axum::routing::get(|upgrade: WebSocketUpgrade, request: http::request::Parts| async move {
                let description = described(&request);
                upgrade.protocols(["livekit"]).on_upgrade(move |mut socket| async move {
                    socket.send(Message::Text(description.into())).await.unwrap();
                    while let Some(Ok(message)) = socket.recv().await {
                        if socket.send(message).await.is_err() {
                            break;
                        }
                    }
                })
            }),
        )
        .route("/rtc/validate", axum::routing::get(|request: http::request::Parts| async move { described(&request) }))
        .fallback(|| async { (StatusCode::IM_A_TEAPOT, "reached") });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    address
}

/// armada, with an AV node on its own origin.
async fn armada_with_local_node(node: SocketAddr, extra: &str) -> SocketAddr {
    let config = Config::parse(&format!(
        "public_url = \"{ORIGIN}\"\n{extra}\n[[av.nodes]]\nurl = \"wss://armada.example.com\"\napi_url = \"http://{node}\"\napi_key = \"k\"\napi_secret = \"s\"\n"
    ))
    .unwrap();
    let av = Av::new(&config).unwrap().unwrap();
    let router = axum::Router::new().fallback(move |request: Request| {
        let av = av.clone();
        async move {
            match av.signaling().filter(|_| signaling::wants(request.uri().path())) {
                Some(signaling) => signaling.handle(request).await,
                None => empty(StatusCode::NOT_FOUND),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await });
    address
}

#[test]
fn forwards_only_signaling() {
    assert!(signaling::wants("/rtc"));
    assert!(signaling::wants("/rtc/validate"));
    assert!(signaling::wants("/rtc/v1"));
    assert!(!signaling::wants("/rtcx"));
    assert!(!signaling::wants("/twirp/livekit.RoomService/ListRooms"));
    // Only a node on armada's own origin is forwarded to.
    assert!(broker("").signaling().is_none());
}

#[tokio::test]
async fn forwards_signaling_to_the_node_on_its_own_origin() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

    let node = fake_node().await;
    let armada = armada_with_local_node(node, "trust_proxy = false").await;

    // The WebSocket, joined byte for byte: the node picks the subprotocol.
    let mut request = format!("ws://{armada}/rtc?access_token=abc").into_client_request().unwrap();
    request.headers_mut().insert("sec-websocket-protocol", HeaderValue::from_static("livekit"));
    request.headers_mut().insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
    let (mut socket, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.headers()["sec-websocket-protocol"], "livekit");
    let first = socket.next().await.unwrap().unwrap().into_text().unwrap();
    // A client's own X-Forwarded-For isn't believed, with no proxy in front.
    assert_eq!(first.as_str(), format!("/rtc?access_token=abc 127.0.0.1 {armada}"));
    socket.send(Message::Binary(vec![1, 2, 3].into())).await.unwrap();
    assert_eq!(socket.next().await.unwrap().unwrap(), Message::Binary(vec![1, 2, 3].into()));
    socket.close(None).await.unwrap();

    // Plain requests too. Behind a trusted proxy, what it forwarded is kept.
    let http = reqwest::Client::new();
    let armada = armada_with_local_node(node, "").await;
    let reply = http.get(format!("http://{armada}/rtc/validate?access_token=abc")).header("x-forwarded-for", "6.6.6.6").send().await.unwrap();
    assert_eq!(reply.status(), StatusCode::OK);
    assert_eq!(reply.text().await.unwrap(), format!("/rtc/validate?access_token=abc 6.6.6.6, 127.0.0.1 {armada}"));

    // Never the server API.
    let reply = http.get(format!("http://{armada}/twirp/livekit.RoomService/ListRooms")).send().await.unwrap();
    assert_eq!(reply.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reports_a_node_that_is_down() {
    let closed = {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let armada = armada_with_local_node(closed, "").await;
    let reply = reqwest::get(format!("http://{armada}/rtc/validate")).await.unwrap();
    assert_eq!(reply.status(), StatusCode::BAD_GATEWAY);
}

/// The LiveKit built into this build, run for real, as armada runs it: it
/// unpacks and starts with its keys, passes the health check, takes the
/// broker's tokens, and seats two callers in one room through `/rtc`.
/// Only builds with `ARMADA_LIVEKIT` have one, and it takes LiveKit's
/// fixed ports, so 7880-7882 have to be free. It's given its node IP, so it
/// needs no STUN server, nor any network but loopback. Media isn't
/// exchanged: that needs a WebRTC peer.
#[cfg(armada_livekit)]
#[tokio::test]
async fn places_a_call_on_the_built_in_livekit() {
    use std::time::Duration;

    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    assert!(
        std::net::TcpListener::bind("127.0.0.1:7880").is_ok(),
        "127.0.0.1:7880 is taken, which the built-in LiveKit needs; is another LiveKit running?"
    );
    let storage_dir = tempfile::tempdir().unwrap();
    let storage = crate::storage::Storage::open(storage_dir.path()).unwrap();
    let mut config = Config::parse(&format!("public_url = \"{ORIGIN}\"\n[av]\nnode_ip = \"127.0.0.1\"\n")).unwrap();
    let livekit = builtin::LiveKit::prepare(&config, &storage).unwrap().expect("this build has LiveKit built in");
    config.av.nodes.push(livekit.node(&config.public_url().unwrap().unwrap()));
    config.validate_av().unwrap();
    let cancel = CancellationToken::new();
    let running = livekit.start(cancel.clone());

    // Up, and its keys are the ones armada signs with.
    let node = Node::from_config(&config.av.nodes[0]).unwrap();
    let http = reqwest::Client::new();
    let started = Instant::now();
    while let Err(error) = livekit::probe(&http, &node, Duration::from_secs(2), now()).await {
        assert!(started.elapsed() < Duration::from_secs(30), "the built-in LiveKit didn't come up: {error:#}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // armada's broker and /rtc, as routes.rs serves them.
    let av = Av::new(&config).unwrap().unwrap();
    let router = axum::Router::new().fallback(move |request: Request| {
        let av = av.clone();
        async move {
            match av.signaling().filter(|_| signaling::wants(request.uri().path())) {
                Some(signaling) => signaling.handle(request).await,
                None => av.handle(request),
            }
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let armada = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await });

    // Two members of one Channel join its room.
    let secret = secret();
    let mut callers = Vec::new();
    for _ in 0..2 {
        let (room, header) = grant(&secret);
        let reply = http.get(format!("http://{armada}{}", room_path(&room))).header("authorization", header).send().await.unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let seat: Value = serde_json::from_slice(&reply.bytes().await.unwrap()).unwrap();
        assert_eq!(seat["url"], "wss://armada.example.com");
        let token = seat["token"].as_str().unwrap();
        let url = format!("ws://{armada}/rtc?access_token={token}&protocol=16&sdk=js&version=2.15.0&auto_subscribe=1");
        let (mut socket, _) = tokio_tungstenite::connect_async(url).await.expect("LiveKit refused the broker's token");
        let first = tokio::time::timeout(Duration::from_secs(10), socket.next()).await.expect("LiveKit said nothing").unwrap().unwrap();
        let Message::Binary(signal) = first else { panic!("LiveKit's first message wasn't a signal: {first:?}") };
        // SignalResponse.join: JoinResponse.
        let join = protobuf::field(&signal, 1).expect("LiveKit's first signal wasn't a JoinResponse");
        let room_name = protobuf::field(protobuf::field(join, 1).unwrap(), 2).unwrap();
        assert_eq!(room_name, room.as_bytes());
        let me = protobuf::field(protobuf::field(join, 2).unwrap(), 2).unwrap();
        assert_eq!(me, seat["identity"].as_str().unwrap().as_bytes());
        let others: Vec<String> = protobuf::fields(join, 3).map(|other| String::from_utf8_lossy(protobuf::field(other, 2).unwrap()).into_owned()).collect();
        callers.push((seat["identity"].as_str().unwrap().to_string(), others, socket));
    }
    // The first found the room empty; the second, the first in it.
    assert!(callers[0].1.is_empty());
    assert_eq!(callers[1].1, vec![callers[0].0.clone()]);

    drop(callers);
    cancel.cancel();
    tokio::time::timeout(Duration::from_secs(15), running).await.expect("the built-in LiveKit didn't stop").unwrap();
}

/// Just enough protobuf to read LiveKit's signals.
#[cfg(armada_livekit)]
mod protobuf {
    /// Every length-delimited value of field `number` in `message`.
    pub fn fields(mut message: &[u8], number: u64) -> impl Iterator<Item = &[u8]> {
        std::iter::from_fn(move || {
            while !message.is_empty() {
                let key = varint(&mut message)?;
                let value: &[u8] = match key & 7 {
                    0 => {
                        varint(&mut message)?;
                        continue;
                    }
                    1 => take(&mut message, 8)?,
                    2 => {
                        let length = varint(&mut message)? as usize;
                        take(&mut message, length)?
                    }
                    5 => take(&mut message, 4)?,
                    _ => return None,
                };
                if key >> 3 == number && key & 7 == 2 {
                    return Some(value);
                }
            }
            None
        })
    }

    /// The first length-delimited value of field `number` in `message`.
    pub fn field(message: &[u8], number: u64) -> Option<&[u8]> {
        fields(message, number).next()
    }

    fn varint(bytes: &mut &[u8]) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = bytes.split_first()?;
            *bytes = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Option<&'a [u8]> {
        let (taken, rest) = bytes.split_at_checked(length)?;
        *bytes = rest;
        Some(taken)
    }
}
