//! `armada`: a self-hosted Armada in one binary — its web app, a relay, a
//! Blossom server, and optionally a Concord AV broker, all on one origin and
//! sharing one storage directory.

mod av;
mod blobs;
mod blossom;
mod config;
mod hash;
mod mime;
mod net;
mod nostr;
mod nsite;
mod origin;
mod push;
mod ratelimit;
mod relay;
mod routes;
mod storage;
mod tls;
mod upgrade;
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
#[command(name = "armada", version, about = "Self-host Armada: its web app, a relay, a Blossom server, and a Concord AV broker")]
struct Cli {
    /// Configuration file [default: the first that exists of
    /// $XDG_CONFIG_HOME/armada/armada.toml (~/.config/armada/armada.toml)
    /// and /etc/armada/armada.toml]
    #[arg(short, long, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(clap::Subcommand)]
enum Command {
    /// Install the latest signed release over this binary, and restart the
    /// armada service if one is set up
    Upgrade {
        /// Install this release instead of the latest
        #[arg(long, value_name = "VERSION")]
        version: Option<String>,
        /// Only say whether there's a newer release
        #[arg(long)]
        check: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // rustls needs one crypto provider chosen for the process; relays and
    // Blossom servers are both reached over it.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if let Some(Command::Upgrade { version, check }) = cli.command {
        return upgrade::run(upgrade::Options { version, check }).await;
    }
    init_logging();

    let config::Loaded { config, source, storage_dir } = Config::load(cli.config.as_deref(), &Environment::current())?;
    match &source {
        Some(path) => tracing::info!(config = %path.display(), "config loaded"),
        None => tracing::info!("no config file found; using the defaults"),
    }
    let storage = Storage::open(&storage_dir)?;
    tracing::info!(storage = %storage.root().display(), "storage opened");

    // Bound before anything starts, so a port already in use stops at once
    // rather than after the site has started downloading.
    let tls = tls::Tls::open(&config, &storage)?;
    let listener = bind(config.listen()).await?;
    tracing::info!(address = %listener.local_addr()?, tls = tls.is_some(), "listening");
    let redirect_listener = match &tls {
        Some(_) if config.tls.redirect_http => {
            let listener = bind(config.tls.http_listen).await?;
            tracing::info!(address = %listener.local_addr()?, "redirecting to HTTPS");
            Some(listener)
        }
        _ => None,
    };

    let cancel = CancellationToken::new();
    let nostr = Arc::new(NostrService::new(config.web.relay_urls()));
    let push = if config.push.enabled { Some(push::Push::open(&storage)?) } else { None };
    let mut client_env = web::env::ClientEnv::new(&config)?;
    if let Some(push) = &push {
        client_env = client_env.with_push(push.pubkey());
    }
    let web = web::Web::open(&config.web, client_env, &storage, nostr).await?;
    let blossom = blossom::Blossom::open(&config.blossom, config.public_url()?, config.trusts_proxy(), &storage, &cancel)?;
    blossom.start();
    let relay = relay::Relay::open(&config.relay, config.public_url()?, config.trusts_proxy(), &storage, &cancel)?;
    if let Some(push) = push {
        let relay_url = config.public_url()?.and_then(|url| origin::public_origin(Some(&url), &http::HeaderMap::new())).map(|origin| origin.websocket());
        let options = push::Options { relay_url, subject: config.push_subject()?, public_only: true };
        push.start(relay.internal(), options, cancel.clone())?;
    }
    let av = av::Av::open(&config, &cancel)?;
    if av.is_some() {
        tracing::info!(nodes = config.av.nodes.len(), "offering AV");
    }
    if config.trust_proxy == Some(true) && config.listen().ip().is_unspecified() {
        tracing::warn!("trust_proxy is on while listening on every interface: anyone reaching armada directly can forge X-Forwarded-For.");
    }
    if config.trust_proxy.is_none() && config.trusts_proxy() {
        tracing::warn!(
            "trust_proxy is on, since armada listens on loopback: each client is told apart by the last X-Forwarded-For entry, which your proxy has to append (nginx: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for). If it doesn't, set trust_proxy = false, or every client shares one set of limits."
        );
    }
    if config.public_url.is_none() {
        tracing::warn!("public_url isn't set, so armada takes its own name from each request's Host header. Set it to the URL clients reach armada at.");
    }

    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            shutdown_signal().await;
            tracing::info!("shutting down");
            cancel.cancel();
        }
    });

    let (web, sync) = web.start(cancel.clone());
    let router = routes::router(routes::Services { web, relay, blossom, av });
    let behind_proxy = config.trusts_proxy();
    let served = match tls {
        Some(tls) => {
            if let Some(redirect_listener) = redirect_listener {
                let redirect = tls.redirect_router();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(error) = tls::serve(redirect_listener, None, redirect, tls::Limits::new(behind_proxy), cancel).await {
                        tracing::error!("serving the HTTPS redirect: {error}");
                    }
                });
            }
            let config = tls.server_config();
            tls.start(cancel.clone());
            tls::serve(listener, Some(config), router, tls::Limits::new(behind_proxy), cancel.clone()).await
        }
        None => tls::serve(listener, None, router, tls::Limits::new(behind_proxy), cancel.clone()).await,
    };
    // However serving ended, the rest stops with it.
    cancel.cancel();
    let _ = sync.await;
    served.context("serving")?;
    Ok(())
}

async fn bind(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address).await.with_context(|| {
        if address.port() < 1024 {
            format!("Could not listen on {address}. Ports below 1024 need root, or CAP_NET_BIND_SERVICE (AmbientCapabilities=CAP_NET_BIND_SERVICE under systemd).")
        } else {
            format!("Could not listen on {address}")
        }
    })
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
