//! `armada`: a self-hosted Armada in one binary — its web app, a relay, and
//! a Blossom server, each on its own port, sharing one storage directory.

mod blobs;
mod blossom;
mod config;
mod hash;
mod mime;
mod net;
mod nostr;
mod nsite;
mod relay;
mod storage;
mod util;
mod web;

use std::net::SocketAddr;
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

    // Bound before anything starts, so a port already in use stops the whole
    // stack at once rather than leaving two of three services running.
    let web_listener = bind("web", config.web.listen).await?;
    let relay_listener = bind("relay", config.relay.listen).await?;
    let blossom_listener = bind("blossom", config.blossom.listen).await?;

    let nostr = Arc::new(NostrService::new(config.web.relay_urls()));
    let web = web::Web::open(&config.web, &storage, nostr).await?;
    let blossom = blossom::Blossom::open(&config.blossom, &storage)?;

    let cancel = CancellationToken::new();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            cancel.cancel();
        }
    });

    let (web, relay, blossom) = tokio::join!(
        stop_all_on_exit(web.run(web_listener, cancel.clone()), &cancel),
        stop_all_on_exit(relay::run(relay_listener, cancel.clone()), &cancel),
        stop_all_on_exit(blossom.run(blossom_listener, cancel.clone()), &cancel),
    );
    web.context("web")?;
    relay.context("relay")?;
    blossom.context("blossom")?;
    Ok(())
}

/// Run a service, and take the rest of the stack down with it if it stops.
async fn stop_all_on_exit(service: impl Future<Output = Result<()>>, cancel: &CancellationToken) -> Result<()> {
    let result = service.await;
    cancel.cancel();
    result
}

async fn bind(service: &str, address: SocketAddr) -> Result<TcpListener> {
    let listener = TcpListener::bind(address).await.with_context(|| format!("The {service} service could not listen on {address}"))?;
    tracing::info!(service, address = %listener.local_addr()?, "listening");
    Ok(listener)
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
