//! Serving the router over HTTPS.
//!
//! `axum::serve` accepts connections one after another, so a TLS handshake
//! done there would hold up every connection behind it, and one client
//! that never finishes its handshake would stall them all. Here each
//! connection gets a task of its own, handshake included.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use super::ACME_TLS_ALPN;

/// How long a client has to finish its TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long connections still open at shutdown have to finish.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve `router` over TLS on `listener` until `cancel` fires. Requests
/// carry the client's address as [`ConnectInfo`], as under `axum::serve`.
pub async fn serve(listener: TcpListener, config: Arc<rustls::ServerConfig>, router: Router, cancel: CancellationToken) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(config);
    let builder = Arc::new(auto::Builder::new(TokioExecutor::new()));
    let graceful = GracefulShutdown::new();
    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    accept_failed(error).await;
                    continue;
                }
            },
            _ = cancel.cancelled() => break,
        };
        let acceptor = acceptor.clone();
        let builder = builder.clone();
        let router = router.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let Ok(Ok(stream)) = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await else { return };
            // A CA validating a challenge only needed the handshake.
            if stream.get_ref().1.alpn_protocol() == Some(ACME_TLS_ALPN) {
                return;
            }
            let service = TowerToHyperService::new(router.layer(axum::Extension(ConnectInfo::<SocketAddr>(peer))));
            let connection = builder.serve_connection_with_upgrades(TokioIo::new(stream), service).into_owned();
            let _ = watcher.watch(connection).await;
        });
    }
    drop(listener);
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, graceful.shutdown()).await;
    Ok(())
}

/// An error from `accept` that isn't one connection's own means the process
/// is out of something, like file descriptors: wait a moment rather than
/// spin.
async fn accept_failed(error: io::Error) {
    use io::ErrorKind::*;
    if matches!(error.kind(), ConnectionAborted | ConnectionReset | ConnectionRefused) {
        return;
    }
    tracing::error!("could not accept a connection: {error}");
    tokio::time::sleep(Duration::from_secs(1)).await;
}
