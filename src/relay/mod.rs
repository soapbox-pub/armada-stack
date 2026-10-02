//! The relay: NIP-01, with NIP-09 deletion, NIP-11, and NIP-40 expiration.
//!
//! Anyone may read and publish, within the limits in [`RelayConfig`].
//!
//! - [`store`] keeps events in LMDB as compact [`record`]s, with
//!   duplicate-sorted indexes (over [`lmdb`], since heed can't seek within
//!   duplicates).
//! - [`query`] answers filters from whichever index its key counts say is
//!   cheapest.
//! - [`writer`] commits events in batches on a thread of its own, then hands
//!   them to [`monitors`], a reverse index of live subscriptions.
//! - [`conn`] speaks the protocol to each client.

mod conn;
mod filter;
mod lmdb;
mod monitors;
mod query;
mod record;
mod store;
mod writer;

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use anyhow::Result;
use axum::Router;
use axum::extract::FromRequestParts;
use axum::extract::Request;
use axum::extract::ws::WebSocketUpgrade;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode, header};
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::config::RelayConfig;
use crate::storage::Storage;
use monitors::Monitors;
use store::Store;
use writer::Writer;

pub struct Relay {
    shared: Arc<Shared>,
}

/// What every connection shares.
struct Shared {
    config: RelayConfig,
    store: Arc<Store>,
    monitors: Arc<Mutex<Monitors>>,
    writer: Writer,
    /// Queries running at once, at most one per core.
    queries: Arc<Semaphore>,
    next_conn: AtomicU64,
    /// Fires on shutdown, closing every connection.
    cancel: CancellationToken,
}

impl Relay {
    pub fn open(config: &RelayConfig, storage: &Storage) -> Result<Relay> {
        let store = Arc::new(Store::open(&storage.service_dir("relay")?, config.map_size as usize)?);
        let monitors = Arc::new(Mutex::new(Monitors::default()));
        let writer = Writer::spawn(store.clone(), monitors.clone());
        let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
        Ok(Relay {
            shared: Arc::new(Shared {
                config: config.clone(),
                store,
                monitors,
                writer,
                queries: Arc::new(Semaphore::new(cores)),
                next_conn: AtomicU64::new(1),
                cancel: CancellationToken::new(),
            }),
        })
    }

    pub fn router(&self) -> Router {
        let shared = self.shared.clone();
        Router::new().fallback(move |request: Request| handle(shared.clone(), request))
    }

    /// Serve on `listener` until `cancel` fires.
    pub async fn run(self, listener: TcpListener, cancel: CancellationToken) -> Result<()> {
        let connections = self.shared.cancel.clone();
        let stop = cancel.clone();
        tokio::spawn(async move {
            stop.cancelled().await;
            connections.cancel();
        });
        axum::serve(listener, self.router()).with_graceful_shutdown(cancel.cancelled_owned()).await?;
        Ok(())
    }
}

async fn handle(shared: Arc<Shared>, request: Request) -> Response {
    let (mut parts, _) = request.into_parts();

    if let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        let max = shared.config.max_message_length;
        return upgrade.max_message_size(max).max_frame_size(max).on_upgrade(move |socket| conn::serve(shared, socket)).into_response();
    }

    if wants_nip11(&parts.headers) {
        let headers = [(header::CONTENT_TYPE, "application/nostr+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")];
        return (headers, info(&shared.config).to_string()).into_response();
    }

    (StatusCode::OK, "This is a Nostr relay. Connect to it with a Nostr client.\n").into_response()
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
        "supported_nips": [1, 9, 11, 40],
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
            "restricted_writes": false,
        },
    })
}

#[cfg(test)]
mod tests;
