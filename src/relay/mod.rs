//! The relay: NIP-01, with NIP-09 deletion, NIP-11, NIP-40 expiration,
//! and NIP-62 vanishing. No NIP-42 AUTH (see [`conn`]), so no NIP-70
//! protected events either.
//!
//! It takes the kinds Armada uses and nothing else, each checked against
//! rules of its own ([`policy`]). Anyone may publish them, within the
//! limits in [`RelayConfig`] — per connection, and per client address
//! ([`clients`]) — and read them, but gift wraps and NIP-46 messages are
//! only found by filters that name their author or recipient.
//!
//! - [`store`] keeps events in LMDB as compact [`record`]s, with
//!   duplicate-sorted indexes (over [`lmdb`], since heed can't seek within
//!   duplicates).
//! - [`query`] answers filters from whichever index its key counts say is
//!   cheapest.
//! - [`writer`] commits events in batches on a thread of its own, then hands
//!   them to [`monitors`]: threads that each keep a reverse index of their
//!   share of the live subscriptions.
//! - [`conn`] speaks the protocol to each client.

mod clients;
mod conn;
mod filter;
mod lmdb;
mod monitors;
mod nip44;
mod policy;
mod query;
mod record;
mod store;
mod writer;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use anyhow::Result;
use axum::extract::FromRequestParts;
use axum::extract::Request;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, StatusCode, header};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::RelayConfig;
use crate::ratelimit;
use crate::storage::Storage;
use clients::Clients;
use monitors::Hub;
use store::Store;
use writer::Writer;

pub use nip44::{is_v2_payload, padded_len};

#[derive(Clone)]
pub struct Relay {
    shared: Arc<Shared>,
}

/// What every connection shares.
struct Shared {
    config: RelayConfig,
    /// The [`policy::authority`] of `public_url`, if it's set. Otherwise
    /// each connection's comes from its request.
    authority: Option<Arc<str>>,
    /// Whether to believe `X-Forwarded-For`; see [`crate::config::Config::trust_proxy`].
    trust_proxy: bool,
    clients: Arc<Clients>,
    store: Arc<Store>,
    hub: Hub,
    writer: Writer,
    /// Queries running at once, at most one per core.
    queries: Arc<Semaphore>,
    /// Events being looked up and verified at once, at most one per core.
    verifiers: Arc<Semaphore>,
    next_conn: AtomicU64,
    /// Fires on shutdown, closing every connection.
    cancel: CancellationToken,
}

impl Relay {
    /// Open the relay's store. Every connection closes once `cancel` fires.
    /// `public_url` is where clients reach it, as requests to vanish name it.
    pub fn open(config: &RelayConfig, public_url: Option<url::Url>, trust_proxy: bool, storage: &Storage, cancel: &CancellationToken) -> Result<Relay> {
        let store = Arc::new(Store::open(&storage.service_dir("relay")?, config.map_size as usize)?);
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        let hub = Hub::spawn((cores / 2).clamp(1, 8));
        let writer = Writer::spawn(store.clone(), hub.clone());
        Ok(Relay {
            shared: Arc::new(Shared {
                config: config.clone(),
                authority: public_url.and_then(|url| policy::authority(url.as_str())).map(Arc::from),
                trust_proxy,
                clients: Clients::new(config),
                store,
                hub,
                writer,
                queries: Arc::new(Semaphore::new(cores)),
                verifiers: Arc::new(Semaphore::new(cores)),
                next_conn: AtomicU64::new(1),
                cancel: cancel.child_token(),
            }),
        })
    }

    #[cfg(test)]
    pub fn router(&self) -> axum::Router {
        let relay = self.clone();
        axum::Router::new().fallback(move |request: Request| async move { relay.handle(request).await })
    }

    /// A WebSocket upgrade, or a NIP-11 request.
    pub async fn handle(&self, request: Request) -> Response {
        let shared = self.shared.clone();
        let (mut parts, _) = request.into_parts();
        match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
            Ok(upgrade) => {
                let Some(key) = ratelimit::client_key(&parts.headers, &parts.extensions, shared.trust_proxy) else {
                    // Without one there's nothing to limit by, and a shared
                    // count would let any such client exhaust it for the rest.
                    return (StatusCode::BAD_REQUEST, "cannot determine peer address").into_response();
                };
                let Some(slot) = shared.clients.connect(key, Instant::now()) else {
                    return (StatusCode::TOO_MANY_REQUESTS, "too many connections from this address").into_response();
                };
                let max = shared.config.max_message_length;
                let authority = shared.authority.clone().unwrap_or_else(|| request_authority(&parts).into());
                upgrade.max_message_size(max).max_frame_size(max).on_upgrade(move |socket| conn::serve(shared, socket, authority, slot)).into_response()
            }
            Err(_) if wants_nip11(&parts.headers) => {
                let headers = [(header::CONTENT_TYPE, "application/nostr+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")];
                (headers, info(&shared.config).to_string()).into_response()
            }
            Err(rejection) => rejection.into_response(),
        }
    }
}

/// Whether a request is the relay's: a WebSocket upgrade or a NIP-11
/// request, to `/`. Anything else there is the web app's.
pub fn wants(method: &Method, path: &str, headers: &HeaderMap) -> bool {
    if path != "/" {
        return false;
    }
    // HTTP/1.1's `Upgrade: websocket`, or HTTP/2's extended CONNECT.
    let upgrade = headers.get(header::UPGRADE).and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
    upgrade || *method == Method::CONNECT || wants_nip11(headers)
}

/// The authority a request was made to: HTTP/1.1's `Host`, or HTTP/2's
/// `:authority`.
fn request_authority(parts: &http::request::Parts) -> String {
    let host = parts.headers.get(header::HOST).and_then(|v| v.to_str().ok()).or_else(|| parts.uri.authority().map(|a| a.as_str()));
    host.and_then(|host| policy::authority(&format!("wss://{}", host.trim()))).unwrap_or_default()
}

fn wants_nip11(headers: &HeaderMap) -> bool {
    headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|accept| accept.contains("application/nostr+json"))
}

/// The relay's NIP-11 document.
fn info(config: &RelayConfig) -> serde_json::Value {
    serde_json::json!({
        "name": "Armada",
        "description": "The relay of a self-hosted Armada.",
        "software": "armada-stack",
        "version": env!("CARGO_PKG_VERSION"),
        "supported_nips": [1, 9, 11, 40, 62],
        "limitation": {
            "max_message_length": config.max_message_length,
            "max_subscriptions": config.max_subscriptions,
            "max_filters": config.max_filters,
            "max_limit": config.max_limit,
            "default_limit": config.max_limit,
            "max_subid_length": 64,
            "max_event_tags": config.max_event_tags,
            "max_content_length": config.max_content_length,
            "created_at_upper_limit": config.created_at_upper_limit,
            "auth_required": false,
            "payment_required": false,
            "restricted_writes": true,
        },
    })
}

#[cfg(test)]
mod tests;
