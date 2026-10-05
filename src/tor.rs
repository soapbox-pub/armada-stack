//! Tor, built in: armada as an onion service, and the way to relays that
//! are onions themselves.
//!
//! Tor runs inside armada. It's Arti, the Tor Project's own implementation
//! in Rust, so there's no daemon to install and no control port to secure.
//! Its state lives under `tor/` in the storage directory:
//!
//! ```text
//! tor/hs_ed25519_secret_key   the onion's identity key, made on first start
//! tor/hs_ed25519_public_key   its public half
//! tor/hostname                the onion address
//! tor/state/, tor/cache/      Arti's guards and directory cache
//! ```
//!
//! The three onion files are what C Tor keeps in a `HiddenServiceDir`, in
//! its format, so an address can move between armada and C Tor either way
//! by copying them. Arti's own keystore is the in-memory one: the key file
//! is the only copy, and the only thing to back up. Losing the rest costs
//! nothing but a slower start.
//!
//! Onion streams are served by the same router as the TCP listener, as
//! plain HTTP on port 80: Tor encrypts and authenticates the connection
//! itself. Tor hides where they come from, so for the limits every service
//! keeps per address, each rendezvous circuit — one client, as far as
//! anything can tell — is given an address of its own (see
//! [`circuit_peer`]).
//!
//! Joining the network doesn't hold up starting: nothing waits for it but
//! the onion service and connections to onions.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use arti_client::config::TorClientConfigBuilder;
use arti_client::config::onion_service::OnionServiceConfigBuilder;
use arti_client::{DataStream, TorClient};
use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use http::{StatusCode, header};
use safelog::DisplayRedacted;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tor_cell::relaycell::msg::{Connected, End, EndReason};
use tor_config::ExplicitOrAuto;
use tor_hscrypto::pk::{HsIdKey, HsIdKeypair};
use tor_hsservice::status::{OnionServiceStatus, State as ServiceState};
use tor_hsservice::{HsIdKeypairSpecifier, HsNickname, StreamRequest};
use tor_keymgr::KeystoreSelector;
use tor_keymgr::config::ArtiKeystoreKind;
use tor_llcrypto::pk::ed25519;
use tor_proto::stream::IncomingStreamRequest;

use crate::tls::Accept;

type Client = TorClient<tor_rtcompat::PreferredRuntime>;

/// The one port the onion service answers on.
const ONION_PORT: u16 = 80;

const SECRET_KEY_FILE: &str = "hs_ed25519_secret_key";
const PUBLIC_KEY_FILE: &str = "hs_ed25519_public_key";
const HOSTNAME_FILE: &str = "hostname";
/// C Tor's headers on its key files, each padded to 32 bytes.
const SECRET_KEY_HEADER: &[u8; 32] = b"== ed25519v1-secret: type0 ==\0\0\0";
const PUBLIC_KEY_HEADER: &[u8; 32] = b"== ed25519v1-public: type0 ==\0\0\0";

/// How long to wait before trying the onion service again, at first and at
/// most.
const RETRY_MIN: Duration = Duration::from_secs(5);
const RETRY_MAX: Duration = Duration::from_secs(300);

/// Bytes Tor may hold in its queues.
const TOR_MEMORY: usize = 1 << 30;

/// Onion streams waiting for the server to take them.
const BACKLOG: usize = 64;

/// Headers a proxy would set. Nothing stands between Tor and armada, so on
/// an onion stream they could only be the client's own, written to pass for
/// someone else.
const PROXY_HEADERS: &[&str] = &["forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-real-ip"];

/// Tor, as the rest of armada uses it.
#[derive(Clone)]
pub struct Tor {
    client: Arc<Client>,
}

impl Tor {
    /// A client keeping its state in `dir`. It joins the network once
    /// something first needs it to.
    pub async fn open(dir: &Path) -> Result<Tor> {
        // What Arti records about a service's introduction points is only
        // half of them: the keys they were made with were in memory, and
        // went with the last process. Left in place, the service would start
        // out reviving points it can no longer prove it owns. Starting from
        // nothing is what C Tor does too.
        match std::fs::remove_dir_all(dir.join("state").join("hss")) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        let mut config = TorClientConfigBuilder::from_directories(dir.join("state"), dir.join("cache"));
        // The key file is the one copy of the onion's key; Arti's keystore
        // on disk would be a second, in a format of its own.
        config.storage().keystore().primary().kind(ExplicitOrAuto::Explicit(ArtiKeystoreKind::Ephemeral));
        // The most Tor may queue before it starts closing the circuits that
        // queue most. Left to itself it takes a share of the machine's
        // memory, sized for a Tor relay rather than one service among
        // several, or 8 GiB when it can't read how much there is, as under
        // systemd's ProcSubset=pid.
        config.system().memory().max(TOR_MEMORY);
        let config = config.build()?;
        let client = TorClient::builder().config(config).create_unbootstrapped_async().await.map_err(|error| {
            anyhow!("Could not start Tor: {error}. Tor refuses a state directory others can write to; check the permissions of {} and the directories above it.", dir.display())
        })?;
        Ok(Tor { client })
    }

    /// A stream to `host`'s `port` over Tor, joining the network first if
    /// it hasn't yet.
    pub async fn connect(&self, host: &str, port: u16) -> Result<DataStream> {
        Ok(self.client.connect((host, port)).await?)
    }

    /// Publish the onion service `key` is for, and hand over every stream a
    /// client opens to it until `cancel` fires. If Tor fails, it's tried
    /// again, so this only ever stops when cancelled.
    pub fn serve(&self, key: OnionKey, cancel: CancellationToken) -> Onions {
        let (streams, receiver) = mpsc::channel(BACKLOG);
        let client = self.client.clone();
        tokio::spawn(async move {
            let mut delay = RETRY_MIN;
            loop {
                let error = tokio::select! {
                    error = publish(&client, &key, &streams) => error,
                    _ = cancel.cancelled() => return,
                };
                tracing::warn!(retry_in = delay.as_secs(), "onion service: {error:#}");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancel.cancelled() => return,
                }
                delay = (delay * 2).min(RETRY_MAX);
            }
        });
        Onions { streams: receiver }
    }
}

/// Join the network, launch the service, and hand over its streams, for as
/// long as Tor keeps sending them. Returns only on failure.
async fn publish(client: &Client, key: &OnionKey, streams: &mpsc::Sender<(DataStream, SocketAddr)>) -> anyhow::Error {
    if let Err(error) = client.bootstrap().await {
        return anyhow!("could not join the Tor network: {error}");
    }
    tracing::info!("joined the Tor network");
    // Arti finds a service's key, and keeps its state, by nickname. Naming
    // the service by its own address means a nickname only ever means one key.
    let launched = (|| {
        let nickname = HsNickname::new(key.address.trim_end_matches(".onion").to_string()).map_err(|_| anyhow!("{} is not an onion address", key.address))?;
        client.keymgr()?.insert(key.keypair()?, &HsIdKeypairSpecifier::new(nickname.clone()), KeystoreSelector::Primary, true)?;
        let config = OnionServiceConfigBuilder::default().nickname(nickname).build()?;
        let (service, requests) = client.launch_onion_service(config)?.context("Tor would not launch the onion service")?;
        // Launching a service with no key makes up a new one, an address
        // nobody was given.
        let address = service.onion_address().map(|id| id.display_unredacted().to_string());
        if address.as_deref() != Some(key.address.as_str()) {
            bail!("Tor launched {} as {address:?}", key.address);
        }
        anyhow::Ok((service, requests))
    })();
    let (service, requests) = match launched {
        Ok(launched) => launched,
        Err(error) => return error,
    };
    tracing::info!(onion = key.address, "launched the onion service; clients can reach it once it's published");
    tokio::spawn(report(service.status_events(), key.address.clone()));

    let mut requests = std::pin::pin!(requests);
    while let Some(rendezvous) = requests.next().await {
        let streams = streams.clone();
        tokio::spawn(async move {
            let Ok(requests) = rendezvous.accept().await else { return };
            let mut requests = std::pin::pin!(requests);
            let peer = circuit_peer();
            while let Some(request) = requests.next().await {
                if let Some(stream) = open(request).await
                    && streams.send((stream, peer)).await.is_err()
                {
                    return;
                }
            }
        });
    }
    drop(service);
    anyhow!("Tor stopped handing over requests")
}

/// Say what Tor makes of the service as that changes. Arti launches a
/// service at once, but publishing it, with introduction points that work,
/// takes anywhere from seconds to several minutes, and until then clients
/// can't connect. Arti's state can lag the descriptor going up, so this is
/// what Tor says rather than proof either way.
async fn report(mut events: impl futures_util::Stream<Item = OnionServiceStatus> + Unpin, onion: String) {
    let mut last = None;
    while let Some(status) = events.next().await {
        let state = status.state();
        if last == Some(state) {
            continue;
        }
        last = Some(state);
        match state {
            ServiceState::Running | ServiceState::DegradedReachable => tracing::info!(onion, ?state, "Tor has published the onion service"),
            ServiceState::Bootstrapping | ServiceState::Shutdown => {}
            _ => tracing::warn!(onion, ?state, problem = ?status.current_problem(), "Tor reports a problem publishing the onion service"),
        }
    }
}

/// Accept a stream if it's for the web port. Anything else is refused with
/// `DONE`, as C Tor does, so the refusal says nothing about this service.
async fn open(request: StreamRequest) -> Option<DataStream> {
    if !matches!(request.request(), IncomingStreamRequest::Begin(begin) if begin.port() == ONION_PORT) {
        let _ = request.reject(End::new_with_reason(EndReason::DONE)).await;
        return None;
    }
    request.accept(Connected::new_empty()).await.ok()
}

/// An address for one rendezvous circuit, standing in for the client's,
/// which Tor hides: a random /64 in the unique local range, which no real
/// peer of armada's on the internet can have. The limits key an IPv6 client
/// by its /64, so each circuit gets its own.
///
/// A client can open another circuit for the price of a few round trips,
/// which makes these weaker than an IP address. But one busy Tor user
/// doesn't use up the limits for every other, as one shared address would.
fn circuit_peer() -> SocketAddr {
    let network = (0xfd_u64 << 56) | (rand::random::<u64>() >> 8);
    SocketAddr::new(IpAddr::V6(Ipv6Addr::from(u128::from(network) << 64 | 1)), 0)
}

/// The streams clients open to the onion service, for [`crate::tls::serve`].
pub struct Onions {
    streams: mpsc::Receiver<(DataStream, SocketAddr)>,
}

impl Accept for Onions {
    type Stream = DataStream;

    async fn accept(&mut self) -> std::io::Result<(DataStream, SocketAddr)> {
        match self.streams.recv().await {
            Some(stream) => Ok(stream),
            // Only once serving has stopped: wait for it to notice.
            None => std::future::pending().await,
        }
    }
}

/// `router`, as the onion serves it: only to requests for `onion`, since
/// the onion is the only name a stream that came over it can have reached,
/// and without proxy headers, which here could only be forged.
pub fn router(router: Router, onion: &str) -> Router {
    router.layer(axum::middleware::from_fn_with_state(Arc::<str>::from(onion), onion_only))
}

async fn onion_only(State(onion): State<Arc<str>>, mut request: Request, next: Next) -> Response {
    let host = request.headers().get(header::HOST).and_then(|value| value.to_str().ok()).or_else(|| request.uri().host());
    let name = host.map(|host| crate::origin::domain(host).trim_end_matches('.'));
    if !name.is_some_and(|name| name.eq_ignore_ascii_case(&onion)) {
        return (StatusCode::NOT_FOUND, "Not found.").into_response();
    }
    for name in PROXY_HEADERS {
        request.headers_mut().remove(*name);
    }
    next.run(request).await
}

/// An onion service's identity: its key, and the address it makes.
pub struct OnionKey {
    /// The address, with its `.onion`.
    pub address: String,
    /// The expanded secret key, as C Tor keeps it.
    secret: [u8; 64],
}

impl OnionKey {
    /// The key in `dir`, made and saved there first if there isn't one.
    pub fn load_or_create(dir: &Path) -> Result<OnionKey> {
        if let Some(key) = Self::load(dir)? {
            return Ok(key);
        }
        let keypair = ed25519::ExpandedKeypair::from(&ed25519::Keypair::from(&rand::random::<[u8; 32]>()));
        let key = OnionKey { address: address_of(&keypair), secret: keypair.to_secret_key_bytes() };
        key.save(dir)?;
        tracing::info!(onion = key.address, "made an onion address");
        Ok(key)
    }

    /// The key in `dir`, if there is one.
    pub fn load(dir: &Path) -> Result<Option<OnionKey>> {
        let path = dir.join(SECRET_KEY_FILE);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("Could not read {}", path.display())),
        };
        let key = Self::parse(&bytes).with_context(|| format!("{} isn't an onion service key in C Tor's format", path.display()))?;
        // The key is what counts; the rest is for whoever reads them.
        if !dir.join(HOSTNAME_FILE).exists() || !dir.join(PUBLIC_KEY_FILE).exists() {
            key.save(dir)?;
        }
        Ok(Some(key))
    }

    fn parse(bytes: &[u8]) -> Result<OnionKey> {
        let secret: [u8; 64] = bytes.strip_prefix(SECRET_KEY_HEADER).and_then(|secret| secret.try_into().ok()).context("expected a 32-byte header and 64 bytes of key")?;
        let keypair = ed25519::ExpandedKeypair::from_secret_key_bytes(secret).context("not a valid ed25519 key")?;
        Ok(OnionKey { address: address_of(&keypair), secret })
    }

    fn save(&self, dir: &Path) -> Result<()> {
        let keypair = self.expanded()?;
        crate::util::write_private(&dir.join(SECRET_KEY_FILE), &[&SECRET_KEY_HEADER[..], &self.secret].concat())?;
        crate::util::write_private(&dir.join(PUBLIC_KEY_FILE), &[&PUBLIC_KEY_HEADER[..], keypair.public().as_bytes()].concat())?;
        crate::util::write_private(&dir.join(HOSTNAME_FILE), format!("{}\n", self.address).as_bytes())
    }

    fn expanded(&self) -> Result<ed25519::ExpandedKeypair> {
        ed25519::ExpandedKeypair::from_secret_key_bytes(self.secret).context("not a valid ed25519 key")
    }

    fn keypair(&self) -> Result<HsIdKeypair> {
        Ok(HsIdKeypair::from(self.expanded()?))
    }
}

fn address_of(keypair: &ed25519::ExpandedKeypair) -> String {
    HsIdKey::from(*keypair.public()).id().display_unredacted().to_string()
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use base64::Engine;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;

    /// Made by C Tor 0.4.8 in a `HiddenServiceDir`: its `hostname`, and the
    /// 64 bytes of `hs_ed25519_secret_key` after its header.
    const C_TOR_ADDRESS: &str = "dl6nglbofs66w2ctcqp3hdgw7lgql7b5xc3dqtj3oqjrcihztrqrkjyd.onion";
    const C_TOR_KEY: &str = "MEaMJctlsgmU3HCYqZAda76Xvu0XFmMELLWNDm/8qWq6AYZW0AiNB8uF0+BTPKF/8eFTfIr9ZBF/TGWo1waDcA==";

    fn c_tor_key_file() -> Vec<u8> {
        [&SECRET_KEY_HEADER[..], &base64::engine::general_purpose::STANDARD.decode(C_TOR_KEY).unwrap()].concat()
    }

    #[test]
    fn reads_the_key_c_tor_wrote() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET_KEY_FILE), c_tor_key_file()).unwrap();
        let key = OnionKey::load(dir.path()).unwrap().unwrap();
        assert_eq!(key.address, C_TOR_ADDRESS);
        assert!(key.keypair().is_ok());
        // And fills in what C Tor would have beside it.
        assert_eq!(std::fs::read_to_string(dir.path().join(HOSTNAME_FILE)).unwrap(), format!("{C_TOR_ADDRESS}\n"));
        let public = std::fs::read(dir.path().join(PUBLIC_KEY_FILE)).unwrap();
        assert_eq!(&public[..32], PUBLIC_KEY_HEADER);
        assert_eq!(public.len(), 64);
    }

    #[test]
    fn makes_a_key_once_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(OnionKey::load(dir.path()).unwrap().is_none());
        let made = OnionKey::load_or_create(dir.path()).unwrap();
        assert!(made.address.ends_with(".onion") && made.address.len() == 62, "{}", made.address);
        assert_eq!(OnionKey::load_or_create(dir.path()).unwrap().address, made.address);
        assert_eq!(std::fs::read_to_string(dir.path().join(HOSTNAME_FILE)).unwrap().trim(), made.address);
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.path().join(SECRET_KEY_FILE)).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn refuses_what_isnt_a_key() {
        let mut file = c_tor_key_file();
        assert!(OnionKey::parse(&file[..90]).is_err());
        file[3] = b'X';
        assert!(OnionKey::parse(&file).is_err());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(SECRET_KEY_FILE), b"nope").unwrap();
        assert!(OnionKey::load(dir.path()).is_err());
        // Never replaced by a new one, which would lose the address.
        assert!(OnionKey::load_or_create(dir.path()).is_err());
    }

    #[test]
    fn each_circuit_is_a_client_of_its_own() {
        let a = circuit_peer();
        let b = circuit_peer();
        let key = |peer: SocketAddr| crate::ratelimit::key(&peer.ip().to_string());
        assert!(key(a).starts_with("fd"), "{}", key(a));
        assert_ne!(key(a), key(b));
        assert!(!crate::net::is_public_address(a.ip()));
    }

    async fn send(router: &Router, host: &str) -> (StatusCode, String) {
        let request = Request::builder().uri("/").header("host", host).header("x-forwarded-for", "203.0.113.9").body(Body::empty()).unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        (status, String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap())
    }

    #[tokio::test]
    async fn answers_only_to_its_onion_and_drops_proxy_headers() {
        let inner = Router::new().fallback(|request: Request| async move { format!("{:?}", request.headers().get("x-forwarded-for")) });
        let router = router(inner, C_TOR_ADDRESS);
        for host in [C_TOR_ADDRESS.to_string(), format!("{C_TOR_ADDRESS}:80"), C_TOR_ADDRESS.to_uppercase()] {
            assert_eq!(send(&router, &host).await, (StatusCode::OK, "None".into()), "{host}");
        }
        for host in ["armada.example.com", "abc.onion", "localhost"] {
            assert_eq!(send(&router, host).await.0, StatusCode::NOT_FOUND, "{host}");
        }
    }
}
