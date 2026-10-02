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
