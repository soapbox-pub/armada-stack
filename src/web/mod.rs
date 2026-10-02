//! The web service: Armada's web app, served from its nsite.
//!
//! npanel trimmed to a single site. One nsite, named in the config, is
//! followed on Nostr, its blobs downloaded into the shared store, and served
//! from there. No dashboard, no API, no host routing: every request is for
//! that one site.

mod db;
#[cfg(test)]
mod e2e;
mod serve;
mod site;
mod sync;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwapOption;
use axum::Router;
use axum::extract::Request;
use http::HeaderValue;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::config::WebConfig;
use crate::nostr::service::NostrSource;
use crate::storage::Storage;
use db::WebDb;
use serve::SiteServer;
use site::Site;
use sync::{SyncSettings, SyncWorker};

pub struct Web {
    server: Arc<SiteServer>,
    worker: SyncWorker,
}

impl Web {
    /// Open the web service's database and put the version it last served
    /// back on the air, before any relay has been asked anything.
    pub async fn open(config: &WebConfig, storage: &Storage, nostr: Arc<dyn NostrSource>) -> Result<Web> {
        let address = config.address()?;
        let db = WebDb::open(storage)?;
        let blobs = storage.blobs.clone();

        let (current, loader) = (db.clone(), blobs.clone());
        let live = tokio::task::spawn_blocking(move || -> Result<Option<Site>> {
            let Some(version) = current.current()? else { return Ok(None) };
            match Site::load(&version.event, &loader) {
                Ok(site) => Ok(Some(site)),
                Err(missing) => {
                    // Someone cleared the store. The sync worker downloads it again.
                    tracing::warn!(event_id = version.event.id, sha256 = %missing, "the live version is missing blobs; downloading them again");
                    Ok(None)
                }
            }
        })
        .await??;
        if let Some(site) = &live {
            tracing::info!(event_id = site.event_id, files = site.files.len(), "serving the stored version");
        }
        let live = Arc::new(ArcSwapOption::from(live.map(Arc::new)));

        let server = Arc::new(SiteServer {
            live: live.clone(),
            blobs: blobs.clone(),
            spa: config.spa,
            naddr: HeaderValue::from_str(&address.naddr()).expect("an naddr is a valid header"),
        });
        let worker = SyncWorker {
            address,
            db,
            blobs,
            nostr,
            settings: SyncSettings {
                auto_update: config.auto_update,
                fallback_servers: config.blossom_servers.clone(),
                resync_interval: Duration::from_secs(config.resync_interval),
                max_file_size: config.max_file_size,
                max_site_size: config.max_site_size,
                retry_backoff: Duration::from_secs(5),
            },
            live,
        };
        Ok(Web { server, worker })
    }

    pub fn router(&self) -> Router {
        let server = self.server.clone();
        Router::new().fallback(move |request: Request| async move { server.serve(request).await })
    }

    /// Serve on `listener` and keep the site in sync, until `cancel` fires.
    pub async fn run(self, listener: TcpListener, cancel: CancellationToken) -> Result<()> {
        let router = self.router();
        let sync = tokio::spawn(self.worker.run(cancel.clone()));
        axum::serve(listener, router).with_graceful_shutdown(cancel.cancelled_owned()).await?;
        let _ = sync.await;
        Ok(())
    }
}
