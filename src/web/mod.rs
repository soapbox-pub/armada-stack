//! The web service: Armada's web app, served from its nsite.
//!
//! npanel trimmed to a single site. One nsite, named in the config, is
//! followed on Nostr, its blobs downloaded into the shared store, and served
//! from there. No dashboard, no API, no host routing: every request that
//! isn't the relay's or the Blossom server's is for that one site.

mod csp;
mod db;
#[cfg(test)]
mod e2e;
pub mod env;
mod inject;
mod prune;
pub mod serve;
mod site;
mod sync;

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use arc_swap::ArcSwapOption;
use http::HeaderValue;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::WebConfig;
use crate::nostr::service::NostrSource;
use crate::storage::Storage;
use db::WebDb;
use env::ClientEnv;
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
    pub async fn open(config: &WebConfig, env: ClientEnv, storage: &Storage, nostr: Arc<dyn NostrSource>) -> Result<Web> {
        let address = config.address()?;
        let db = WebDb::open(storage)?;
        let blobs = storage.blobs.clone();

        let (current, loader, keep) = (db.clone(), blobs.clone(), config.keep_versions);
        let live = tokio::task::spawn_blocking(move || -> Result<Option<Site>> {
            let Some(version) = current.current()? else { return Ok(None) };
            let earlier: Vec<_> = current.chain(&version.event.id, keep)?.into_iter().skip(1).map(|version| version.event).collect();
            match Site::load(&version.event, &earlier, &loader) {
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
            naddr: HeaderValue::from_str(&address.naddr()).expect("an naddr is a valid header"),
            env,
        });
        let worker = SyncWorker {
            address,
            db,
            blobs,
            nostr,
            settings: SyncSettings {
                auto_update: config.auto_update,
                resync_interval: Duration::from_secs(config.resync_interval),
                max_file_size: config.max_file_size,
                max_site_size: config.max_site_size,
                keep_versions: config.keep_versions,
                retry_backoff: Duration::from_secs(5),
            },
            live,
        };
        Ok(Web { server, worker })
    }

    #[cfg(test)]
    pub fn router(&self) -> axum::Router {
        let server = self.server.clone();
        axum::Router::new().fallback(move |request: axum::extract::Request| async move { server.serve(request).await })
    }

    /// Keep the site in sync until `cancel` fires, and hand back what serves it.
    pub fn start(self, cancel: CancellationToken) -> (Arc<SiteServer>, JoinHandle<()>) {
        (self.server, tokio::spawn(self.worker.run(cancel)))
    }
}
