//! The relay: NIP-01, with NIP-09 deletion, NIP-11, NIP-40 expiration,
//! and NIP-62 vanishing. No NIP-42 AUTH (see [`conn`]), so no NIP-70
//! protected events either.
//!
//! It takes the kinds Armada uses and nothing else, each checked against
//! rules of its own ([`policy`]). Anyone may publish them, within the
//! limits in [`RelayConfig`] — per connection, and per client address
//! ([`clients`]) — and read them, but gift wraps, NIP-46 messages, and
//! push requests are only found by filters that name their author or
//! recipient.
//!
//! Services inside armada reach it through [`Internal`], without a socket.
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
pub mod nip44;
mod policy;
mod query;
mod record;
mod store;
mod writer;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::Result;
use axum::extract::FromRequestParts;
use axum::extract::Request;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, Method, StatusCode, header};
use serde_json::Value;
use tokio::sync::{Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

use crate::config::RelayConfig;
use crate::origin::request_origin;
use crate::ratelimit;
use crate::storage::Storage;
use crate::nostr::Event;
use crate::web::brand::{BANNER_PATH, ICON_PATH};
use clients::Clients;
use filter::Filter;
use monitors::{Hub, Link};
use store::Store;
use writer::Writer;

pub use monitors::{ConnId, Outbound};

#[derive(Clone)]
pub struct Relay {
    shared: Arc<Shared>,
}

/// What every connection shares.
struct Shared {
    config: RelayConfig,
    /// The [`policy::authority`] of `public_url`, if it's set. Without it
    /// the relay doesn't know its own name, so takes only requests to
    /// vanish from `ALL_RELAYS`.
    authority: Option<Arc<str>>,
    /// Where NIP-11's icon and banner are, when it's set.
    public_url: Option<url::Url>,
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
                authority: public_url.as_ref().and_then(|url| policy::authority(url.as_str())).map(Arc::from),
                public_url,
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
                // Never the request's `Host`: anyone can send any, and with
                // it replay a request to vanish meant for another relay.
                let authority = shared.authority.clone().unwrap_or_else(|| Arc::from(""));
                upgrade.max_message_size(max).max_frame_size(max).on_upgrade(move |socket| conn::serve(shared, socket, authority, slot)).into_response()
            }
            Err(_) if wants_nip11(&parts.headers) => {
                // Its image URLs are the request's origin's unless
                // `public_url` is set, so it varies with `Host`.
                let origin = request_origin(shared.public_url.as_ref(), &parts.headers);
                let headers = [(header::CONTENT_TYPE, "application/nostr+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*"), (header::VARY, "Host")];
                (headers, info(&shared.config, &origin.base).to_string()).into_response()
            }
            Err(rejection) => rejection.into_response(),
        }
    }
}

/// The relay as services inside armada use it: connections of their own,
/// without a socket, whose subscriptions see each new event as a client's
/// would and under the same rules, and a way to publish events.
#[derive(Clone)]
pub struct Internal {
    shared: Arc<Shared>,
}

impl Relay {
    pub fn internal(&self) -> Internal {
        Internal { shared: self.shared.clone() }
    }
}

impl Internal {
    /// A new connection. New events for its subscriptions arrive on the
    /// receiver, until it falls `capacity` behind and the token fires;
    /// after that it gets nothing more, and should be replaced.
    pub async fn connect(&self, capacity: usize) -> (ConnId, mpsc::Receiver<Outbound>, CancellationToken) {
        let id = self.shared.next_conn.fetch_add(1, Ordering::Relaxed);
        let (link, rx, overflow) = Link::new(capacity);
        self.shared.hub.connect(id, link).await;
        (id, rx, overflow)
    }

    /// [`Internal::connect`], as one connection per monitor shard sharing
    /// one receiver, for a service with more subscriptions than one shard
    /// should match alone. Each subscription goes on whichever it's given.
    pub async fn connect_spread(&self, capacity: usize) -> (Vec<ConnId>, mpsc::Receiver<Outbound>, CancellationToken) {
        let shards = self.shared.hub.shards() as u64;
        let first = self.shared.next_conn.fetch_add(shards, Ordering::Relaxed);
        let (link, rx, overflow) = Link::new(capacity);
        let mut conns = Vec::new();
        // Consecutive ids, so one on each shard.
        for id in first..first + shards {
            self.shared.hub.connect(id, link.clone()).await;
            conns.push(id);
        }
        (conns, rx, overflow)
    }

    pub async fn disconnect(&self, conn: ConnId) {
        self.shared.hub.disconnect(conn).await;
    }

    /// Open a subscription to new events, replacing any of the same id,
    /// once it's live. Stored events aren't looked up. Filters are scoped as
    /// a client's are, and errors are the reason a client would be given.
    pub async fn subscribe(&self, conn: ConnId, sub: &str, filters: &[Value]) -> Result<(), String> {
        let filters = filters.iter().map(scoped).collect::<Result<Vec<_>, _>>()?;
        let _ = self.shared.hub.subscribe(conn, sub.into(), filters).await.await;
        Ok(())
    }

    pub async fn unsubscribe(&self, conn: ConnId, sub: &str) {
        self.shared.hub.unsubscribe(conn, sub).await;
    }

    /// Queue an event for the writer, as a client's would be once checked.
    /// It's checked as a client's is, short of the rate limits, so that
    /// nothing the store can't hold gets in. Returns whether it passed and
    /// the writer had room.
    pub fn publish(&self, event: &Event) -> bool {
        let now = crate::util::now();
        let valid = conn::well_formed(event)
            && (0..=i64::from(u32::MAX)).contains(&event.created_at)
            && policy::validate(event, now, "").is_ok()
            && event.verify();
        if !valid {
            tracing::error!(id = %event.id, kind = event.kind, "an event of armada's own isn't valid; not publishing it");
            return false;
        }
        let record = record::encode_expiring(event, policy::expiration(event, now));
        // Nothing reads the `OK`.
        let (reply, _, _) = Link::new(1);
        self.shared.writer.submit(writer::Submission { record, reply }).is_ok()
    }
}

/// A filter as a client's REQ would have it, or why it's refused.
fn scoped(value: &Value) -> Result<Filter, String> {
    let mut filter = Filter::parse(value)?;
    policy::scope(&mut filter)?;
    Ok(filter)
}

/// Whether the relay takes events of a kind at all.
pub fn accepts_kind(kind: u16) -> bool {
    policy::is_accepted(kind)
}

/// Whether [`Internal::subscribe`] would take a filter, and if not, why.
pub fn check_filter(value: &Value) -> Result<(), String> {
    scoped(value).map(drop)
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

fn wants_nip11(headers: &HeaderMap) -> bool {
    headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|accept| accept.contains("application/nostr+json"))
}

/// The relay's NIP-11 document, as served from `origin`.
fn info(config: &RelayConfig, origin: &str) -> serde_json::Value {
    serde_json::json!({
        "name": "Armada",
        "description": "The relay of a self-hosted Armada.",
        "icon": format!("{origin}{ICON_PATH}"),
        "banner": format!("{origin}{BANNER_PATH}"),
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
