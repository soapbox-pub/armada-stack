//! `armada`: a self-hosted Armada in one binary — its web app, a relay, and
//! a Blossom server, all on one origin and sharing one storage directory.

mod blobs;
mod blossom;
mod config;
mod hash;
mod mime;
mod net;
mod nostr;
mod nsite;
mod relay;
mod routes;
mod storage;
mod util;
mod web;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use config::{Config, Environment};
use nostr::service::NostrService;
use storage::Storage;

#[derive(Parser)]
#[command(name = "armada", version, about = "Self-host Armada: its web app, a relay, and a Blossom server")]
struct Cli {
    /// Configuration file [default: the first that exists of
    /// $XDG_CONFIG_HOME/armada/armada.toml (~/.config/armada/armada.toml)
    /// and /etc/armada/armada.toml]
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging();

    // rustls needs one crypto provider chosen for the process; relays and
    // Blossom servers are both reached over it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config::Loaded { config, source, storage_dir } = Config::load(cli.config.as_deref(), &Environment::current())?;
    match &source {
        Some(path) => tracing::info!(config = %path.display(), "config loaded"),
        None => tracing::info!("no config file found; using the defaults"),
    }
    let storage = Storage::open(&storage_dir)?;
    tracing::info!(storage = %storage.root().display(), "storage opened");

    // Bound before anything starts, so a port already in use stops at once
    // rather than after the site has started downloading.
    let listener = TcpListener::bind(config.listen).await.with_context(|| format!("Could not listen on {}", config.listen))?;
    tracing::info!(address = %listener.local_addr()?, "listening");

    let cancel = CancellationToken::new();
    let nostr = Arc::new(NostrService::new(config.web.relay_urls()));
    let web = web::Web::open(&config.web, &storage, nostr).await?;
    let blossom = blossom::Blossom::open(&config.blossom, config.public_url()?, &storage, &cancel)?;
    let relay = relay::Relay::open(&config.relay, &storage, &cancel)?;

    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            cancel.cancel();
        }
    });

    let (web, sync) = web.start(cancel.clone());
    let router = routes::router(routes::Services { web, relay, blossom });
    let served = axum::serve(listener, router).with_graceful_shutdown(cancel.clone().cancelled_owned()).await;
    // However serving ended, the rest stops with it.
    cancel.cancel();
    let _ = sync.await;
    served.context("serving")?;
    Ok(())
}

/// Human-readable logs by default; `LOG_FORMAT=json` for one JSON object per
/// line. `RUST_LOG` picks the level, `info` if unset.
fn init_logging() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if std::env::var("LOG_FORMAT").as_deref() == Ok("json") {
        tracing_subscriber::fmt().json().flatten_event(true).with_env_filter(filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("a SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = ctrl_c.await;
}
