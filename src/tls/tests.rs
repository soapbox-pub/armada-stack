use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use futures_util::{SinkExt, StreamExt};
use http::{Method, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use parking_lot::Mutex;
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpListener;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use super::acme::alpn_challenge_certificate;
use super::store::{Certificate, Store};
use super::*;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A CA, and a certificate for `localhost` from it: the chain and key as a
/// CA would hand them over, PEM.
struct Issued {
    ca: CertificateDer<'static>,
    chain: String,
    key: String,
}

fn issue(validity: Option<(i64, i64)>) -> Issued {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = CertifiedIssuer::self_signed(ca_params, KeyPair::generate().unwrap()).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    if let Some((not_before, not_after)) = validity {
        params.not_before = time::OffsetDateTime::from_unix_timestamp(not_before).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(not_after).unwrap();
    }
    let key = KeyPair::generate().unwrap();
    let leaf = params.signed_by(&key, &ca).unwrap();
    Issued { ca: ca.as_ref().der().clone(), chain: format!("{}{}", leaf.pem(), ca.as_ref().pem()), key: key.serialize_pem() }
}

/// HTTPS on a port of its own, serving `router` with the certificate in
/// `state`.
async fn serve_tls(state: Arc<State>, router: Router) -> (SocketAddr, tokio_util::sync::DropGuard) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let cancel = CancellationToken::new();
    tokio::spawn(serve(listener, Some(server_config(state)), router, super::Limits::new(false), cancel.clone()));
    (address, cancel.drop_guard())
}

async fn connect(address: SocketAddr, config: rustls::ClientConfig) -> TlsStream<tokio::net::TcpStream> {
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    TlsConnector::from(Arc::new(config)).connect(ServerName::try_from("localhost").unwrap(), tcp).await.unwrap()
}

fn trusting(ca: &CertificateDer<'static>, alpn: &[&[u8]]) -> rustls::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(ca.clone()).unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    config
}

/// Accepts any certificate, and remembers it. Signatures go unchecked too:
/// webpki won't parse a challenge certificate, whose critical extension it
/// doesn't know.
#[derive(Debug, Default)]
struct Recording(Mutex<Option<CertificateDer<'static>>>);

impl ServerCertVerifier for Recording {
    fn verify_server_cert(&self, end_entity: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock() = Some(end_entity.clone().into_owned());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(&self, _: &[u8], _: &CertificateDer<'_>, _: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider().signature_verification_algorithms.supported_schemes()
    }
}

fn with_certificate(issued: &Issued) -> Arc<State> {
    let state = Arc::new(State::default());
    let pem = format!("{}{}", issued.chain, issued.key);
    state.certificate.store(Some(Certificate::from_pem(pem.as_bytes()).unwrap().key));
    state
}

/// The whole stack, with no site downloaded yet, so the web app answers
/// 503 to everything.
fn stack(dir: &std::path::Path, cancel: &CancellationToken) -> Router {
    let storage = crate::storage::Storage::allowing_private(dir);
    let config = crate::config::Config::default();
    let web = Arc::new(crate::web::serve::SiteServer {
        live: Default::default(),
        blobs: storage.blobs.clone(),
        naddr: http::HeaderValue::from_static("naddr"),
        env: Default::default(),
    });
    let relay = crate::relay::Relay::open(&config.relay, Default::default(), false, &storage, cancel).unwrap();
    let blossom = crate::blossom::Blossom::open(&config.blossom, Default::default(), false, &storage, cancel).unwrap();
    crate::routes::router(crate::routes::Services { web, relay, blossom, av: None })
}

#[tokio::test]
async fn serves_the_stack_over_https_and_wss() {
    let issued = issue(None);
    let dir = tempfile::tempdir().unwrap();
    let cancel = CancellationToken::new();
    let (address, _guard) = serve_tls(with_certificate(&issued), stack(dir.path(), &cancel)).await;

    // HTTP/1.1, verified against the CA: the chain is served whole.
    let stream = connect(address, trusting(&issued.ca, &[b"http/1.1"])).await;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::get("/").header("host", "localhost").header("accept", "application/nostr+json").body(Empty::<bytes::Bytes>::new()).unwrap();
    let response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("supported_nips"));

    // HTTP/2, when the client asks for it.
    let stream = connect(address, trusting(&issued.ca, &[b"h2", b"http/1.1"])).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, connection) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::get("https://localhost/").body(Empty::<bytes::Bytes>::new()).unwrap();
    assert_eq!(sender.send_request(request).await.unwrap().status(), StatusCode::SERVICE_UNAVAILABLE);

    // The relay, over wss://.
    let stream = connect(address, trusting(&issued.ca, &[b"http/1.1"])).await;
    let (mut socket, _) = tokio_tungstenite::client_async("wss://localhost/", stream).await.unwrap();
    socket.send(Message::Text(r#"["REQ","s",{"limit":1}]"#.into())).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.unwrap().unwrap().unwrap();
    assert_eq!(reply.into_text().unwrap().as_str(), r#"["EOSE","s"]"#);
    cancel.cancel();
}

#[tokio::test]
async fn requests_know_who_sent_them() {
    let issued = issue(None);
    let router = Router::new().fallback(|ConnectInfo(peer): ConnectInfo<SocketAddr>| async move { peer.to_string() });
    let (address, _guard) = serve_tls(with_certificate(&issued), router).await;

    let stream = connect(address, trusting(&issued.ca, &[])).await;
    let local = stream.get_ref().0.local_addr().unwrap();
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(connection);
    let request = http::Request::get("/").header("host", "localhost").body(Empty::<bytes::Bytes>::new()).unwrap();
    let body = sender.send_request(request).await.unwrap().into_body().collect().await.unwrap().to_bytes();
    assert_eq!(String::from_utf8_lossy(&body), local.to_string());
}

#[tokio::test]
async fn a_validating_ca_gets_the_challenge_certificate() {
    let issued = issue(None);
    let state = with_certificate(&issued);
    let (address, _guard) = serve_tls(state.clone(), Router::new()).await;
    let recording = Arc::new(Recording::default());
    let config = |alpn: &[u8]| {
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(recording.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        config
    };

    // No challenge pending: the CA's handshake fails.
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    let refused = TlsConnector::from(Arc::new(config(ACME_TLS_ALPN))).connect(ServerName::try_from("localhost").unwrap(), tcp).await;
    assert!(refused.is_err());

    let challenge = alpn_challenge_certificate("localhost", &[7; 32]).unwrap();
    let challenge_der = challenge.cert[0].clone();
    state.alpn_challenge.store(Some(Arc::new(challenge)));
    let stream = connect(address, config(ACME_TLS_ALPN)).await;
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(ACME_TLS_ALPN));
    assert_eq!(recording.0.lock().take(), Some(challenge_der.clone()));
    // It carries the digest, in the critical id-pe-acmeIdentifier extension.
    let (_, parsed) = x509_parser::parse_x509_certificate(&challenge_der).unwrap();
    let extension = parsed.extensions().iter().find(|extension| extension.oid.to_id_string() == "1.3.6.1.5.5.7.1.31").unwrap();
    assert!(extension.critical);
    assert!(extension.value.ends_with(&[7; 32]));

    // Everyone else still gets the real one.
    let stream = connect(address, config(b"http/1.1")).await;
    drop(stream);
    assert_eq!(recording.0.lock().take().as_deref(), Some(state.certificate.load().as_ref().unwrap().cert[0].as_ref()));
}

#[tokio::test]
async fn port_80_redirects_and_answers_challenges() {
    let state = Arc::new(State::default());
    state.http_challenges.lock().insert("tok".into(), "tok.thumb".into());
    let router = redirect::router("armada.example.com".into(), state);
    let send = |method: Method, uri: &str| {
        let request = Request::builder().method(method).uri(uri).header("host", "evil.example").body(Body::empty()).unwrap();
        router.clone().oneshot(request)
    };

    let response = send(Method::GET, "/.well-known/acme-challenge/tok").await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(&response.into_body().collect().await.unwrap().to_bytes()[..], b"tok.thumb");
    let response = send(Method::GET, "/.well-known/acme-challenge/other").await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let response = send(Method::POST, "/upload?x=1").await.unwrap();
    assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
    assert_eq!(response.headers()["location"], "https://armada.example.com/upload?x=1");
    let response = send(Method::GET, "/").await.unwrap();
    assert_eq!(response.headers()["location"], "https://armada.example.com/");
}

#[test]
fn keeps_certificates_privately_per_ca() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path(), "https://acme-staging-v02.api.letsencrypt.org/directory").unwrap();
    assert!(store.load_certificate("localhost").unwrap().is_none());
    assert!(store.load_account().unwrap().is_none());

    let issued = issue(Some((1_800_000_000, 1_800_000_000 + 90 * 86400)));
    let saved = store.save_certificate("localhost", &issued.chain, &issued.key).unwrap();
    let path = dir.path().join("acme-staging-v02.api.letsencrypt.org/localhost.pem");
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    let loaded = store.load_certificate("localhost").unwrap().unwrap();
    assert_eq!(loaded.key.cert, saved.key.cert);
    assert_eq!(loaded.key.cert.len(), 2);
    // A month before a 90-day certificate expires.
    assert_eq!(loaded.renew_at(), 1_800_000_000 + 60 * 86400);

    // Another CA's certificates are its own.
    let other = Store::open(dir.path(), "https://localhost:14000/dir").unwrap();
    assert!(other.load_certificate("localhost").unwrap().is_none());
    assert!(dir.path().join("localhost_14000").is_dir());

    // A key that isn't the certificate's is refused before it's kept.
    let stranger = issue(None);
    assert!(store.save_certificate("localhost", &issued.chain, &stranger.key).is_err());
    assert!(Certificate::from_pem(issued.chain.as_bytes()).is_err());
}

/// Gets real certificates from Pebble, Let's Encrypt's test CA, by both
/// challenges. Pebble validates against 127.0.0.1, so armada listens where
/// it looks: 5001 for TLS-ALPN-01 and 5002 for HTTP-01, its defaults.
///
/// ```text
/// docker run -d --name challtestsrv --network host ghcr.io/letsencrypt/pebble-challtestsrv -defaultIPv4 127.0.0.1 -defaultIPv6 ""
/// docker run -d --name pebble --network host -e PEBBLE_VA_NOSLEEP=1 ghcr.io/letsencrypt/pebble -dnsserver 127.0.0.1:8053
/// docker cp pebble:/test/certs/pebble.minica.pem /tmp/pebble.minica.pem
/// PEBBLE_ROOT=/tmp/pebble.minica.pem cargo test pebble -- --ignored
/// ```
#[tokio::test]
#[ignore = "needs a Pebble ACME server"]
async fn pebble() {
    let root = std::env::var("PEBBLE_ROOT").expect("PEBBLE_ROOT: Pebble's CA certificate");
    let directory = std::env::var("PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".into());
    let dir = tempfile::tempdir().unwrap();
    let state = Arc::new(State::default());
    let acme = acme::Acme {
        domain: "armada.test".into(),
        directory: directory.clone(),
        email: Some("ops@armada.test".into()),
        http01: true,
        root: Some(root.into()),
        store: Store::open(dir.path(), &directory).unwrap(),
        state: state.clone(),
    };

    let cancel = CancellationToken::new();
    let _guard = cancel.clone().drop_guard();
    let tls = TcpListener::bind("127.0.0.1:5001").await.unwrap();
    tokio::spawn(serve(tls, Some(server_config(state.clone())), Router::new(), super::Limits::new(false), cancel.clone()));
    let http = TcpListener::bind("127.0.0.1:5002").await.unwrap();
    let redirect = redirect::router("armada.test".into(), state.clone());
    tokio::spawn(async move { axum::serve(http, redirect).await });

    let account = acme.account().await.unwrap();
    for kind in [instant_acme::ChallengeType::TlsAlpn01, instant_acme::ChallengeType::Http01] {
        let (chain, key) = acme.order(&account, &kind).await.unwrap_or_else(|error| panic!("{kind:?}: {error:#}"));
        let certificate = acme.store.save_certificate("armada.test", &chain, &key).unwrap();
        assert!(certificate.not_after > crate::util::now());
        assert!(state.alpn_challenge.load().is_none() && state.http_challenges.lock().is_empty());
    }
    // The account is kept, and used again.
    assert!(acme.store.load_account().unwrap().is_some());
    acme.account().await.unwrap();
}
