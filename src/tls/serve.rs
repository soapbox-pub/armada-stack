//! Serving the router, over HTTPS or plain HTTP.
//!
//! `axum::serve` accepts connections one after another, so a TLS handshake
//! done there would hold up every connection behind it, and one client
//! that never finishes its handshake would stall them all. Here each
//! connection gets a task of its own, handshake included.
//!
//! Nor does `axum::serve` give hyper a timer, without which hyper's
//! header-read timeout silently does nothing: a client could open
//! connections and send a byte of headers every few minutes, or none,
//! until the process ran out of file descriptors. Here every connection
//! has [`HEADER_TIMEOUT`] to send each request's headers, HTTP/2 ones are
//! pinged and dropped if they stop answering, any connection on which
//! nothing has moved either way for [`IDLE_TIMEOUT`] is closed — before its
//! first request, between requests, or once upgraded to a WebSocket — and
//! there are only so many
//! connections at once: [`MAX_CONNECTIONS`] in all, and
//! [`MAX_CONNECTIONS_PER_ADDRESS`] from any one client.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::extract::ConnectInfo;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use super::ACME_TLS_ALPN;

/// How long a client has to finish its TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a client has to send a request's headers, once it's started
/// one or the last has been answered.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a connection may go with nothing read or written. The relay
/// pings its WebSockets every minute, so live ones never get near it.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// How often an HTTP/2 connection is pinged, and how long it has to answer.
const H2_PING_INTERVAL: Duration = Duration::from_secs(60);
const H2_PING_TIMEOUT: Duration = Duration::from_secs(20);
/// How long connections still open at shutdown have to finish.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections open at once. Well under the service's file descriptor
/// limit (65,536), which the relay's store and outgoing connections share.
const MAX_CONNECTIONS: usize = 32_768;
/// Connections open at once from one IPv4 address or IPv6 /64. Above the
/// relay's own per-address limit on WebSockets, which ride on these.
const MAX_CONNECTIONS_PER_ADDRESS: usize = 256;

/// How connections are accepted.
pub struct Limits {
    /// The most open at once in all.
    pub total: usize,
    /// The most open at once from one address, if limited by the socket's
    /// peer. Not behind a proxy, every connection from which comes from
    /// one address.
    pub per_address: Option<usize>,
    /// How long a client has to send a request's headers.
    pub header_timeout: Duration,
    /// How long a connection may go with nothing read or written.
    pub idle_timeout: Duration,
}

impl Limits {
    /// The defaults, limiting each peer address unless a proxy's in front.
    pub fn new(behind_proxy: bool) -> Limits {
        Limits { total: MAX_CONNECTIONS, per_address: (!behind_proxy).then_some(MAX_CONNECTIONS_PER_ADDRESS), header_timeout: HEADER_TIMEOUT, idle_timeout: IDLE_TIMEOUT }
    }
}

/// Where connections come from: a TCP listener, or Tor's onion streams.
pub trait Accept: Send {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    /// The next connection, and the address it's counted against.
    fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send;
}

impl Accept for TcpListener {
    type Stream = TcpStream;

    fn accept(&mut self) -> impl Future<Output = io::Result<(TcpStream, SocketAddr)>> + Send {
        TcpListener::accept(self)
    }
}

/// Serve `router` until `cancel` fires: over TLS with `tls`, or else plain
/// HTTP. Requests carry the client's address as [`ConnectInfo`], as under
/// `axum::serve`.
pub async fn serve<A: Accept>(mut listener: A, tls: Option<Arc<rustls::ServerConfig>>, router: Router, limits: Limits, cancel: CancellationToken) -> io::Result<()> {
    let acceptor = tls.map(TlsAcceptor::from);
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(limits.header_timeout);
    builder.http2().timer(TokioTimer::new()).keep_alive_interval(H2_PING_INTERVAL).keep_alive_timeout(H2_PING_TIMEOUT);
    let builder = Arc::new(builder);
    let graceful = GracefulShutdown::new();
    let total = Arc::new(Semaphore::new(limits.total));
    let addresses = Arc::new(Addresses { max: limits.per_address, open: Mutex::new(HashMap::new()) });
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
        // Over either limit, it's closed at once, costing nothing more.
        let Ok(permit) = total.clone().try_acquire_owned() else { continue };
        let Some(held) = addresses.open(peer) else { continue };
        let acceptor = acceptor.clone();
        let builder = builder.clone();
        let router = router.clone();
        let watcher = graceful.watcher();
        let idle = limits.idle_timeout;
        tokio::spawn(async move {
            let _held = (permit, held);
            let service = TowerToHyperService::new(router.layer(axum::Extension(ConnectInfo::<SocketAddr>(peer))));
            match acceptor {
                Some(acceptor) => {
                    let Some(stream) = handshake(&acceptor, stream).await else { return };
                    let stream = Idle::new(stream, idle);
                    let _ = watcher.watch(builder.serve_connection_with_upgrades(TokioIo::new(stream), service).into_owned()).await;
                }
                None => {
                    let stream = Idle::new(stream, idle);
                    let _ = watcher.watch(builder.serve_connection_with_upgrades(TokioIo::new(stream), service).into_owned()).await;
                }
            }
        });
    }
    drop(listener);
    let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, graceful.shutdown()).await;
    Ok(())
}

/// A connection's TLS handshake, or `None` if it took too long, failed, or
/// was only a CA validating a challenge, which needs nothing more.
async fn handshake<S: AsyncRead + AsyncWrite + Unpin>(acceptor: &TlsAcceptor, stream: S) -> Option<tokio_rustls::server::TlsStream<S>> {
    let stream = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await.ok()?.ok()?;
    (stream.get_ref().1.alpn_protocol() != Some(ACME_TLS_ALPN)).then_some(stream)
}

/// A connection that fails with `TimedOut` once nothing has been read or
/// written for its timeout while it's waiting to do either.
struct Idle<S> {
    inner: S,
    timeout: Duration,
    deadline: Pin<Box<tokio::time::Sleep>>,
}

impl<S> Idle<S> {
    fn new(inner: S, timeout: Duration) -> Idle<S> {
        Idle { inner, timeout, deadline: Box::pin(tokio::time::sleep(timeout)) }
    }

    fn moved(&mut self) {
        let deadline = tokio::time::Instant::now() + self.timeout;
        self.deadline.as_mut().reset(deadline);
    }

    /// For an operation still waiting: whether it has waited too long.
    fn expired<T>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<T>> {
        match self.deadline.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Idle<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(result) => {
                if buf.filled().len() > before {
                    self.moved();
                }
                Poll::Ready(result)
            }
            Poll::Pending => self.expired(cx),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Idle<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.moved();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => self.expired(cx),
        }
    }

    fn poll_write_vectored(mut self: Pin<&mut Self>, cx: &mut Context<'_>, bufs: &[io::IoSlice<'_>]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write_vectored(cx, bufs) {
            Poll::Ready(Ok(written)) => {
                if written > 0 {
                    self.moved();
                }
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => self.expired(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Pending => self.expired(cx),
            ready => ready,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Connections open from each address, if they're limited.
struct Addresses {
    max: Option<usize>,
    open: Mutex<HashMap<String, usize>>,
}

/// One connection, counted against its address until it's dropped.
struct Held {
    addresses: Arc<Addresses>,
    key: String,
}

impl Addresses {
    fn open(self: &Arc<Self>, peer: SocketAddr) -> Option<Option<Held>> {
        let Some(max) = self.max else { return Some(None) };
        let key = crate::ratelimit::key(&peer.ip().to_string());
        let mut open = self.open.lock();
        let count = open.entry(key.clone()).or_default();
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Some(Held { addresses: self.clone(), key }))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut open = self.addresses.open.lock();
        if let Some(count) = open.get_mut(&self.key) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.key);
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    async fn listening(limits: Limits) -> (SocketAddr, tokio_util::sync::DropGuard) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let router = Router::new().fallback(|| async { "hi" });
        tokio::spawn(serve(listener, None, router, limits, cancel.clone()));
        (address, cancel.drop_guard())
    }

    /// Whether the server closes the connection within `within`.
    async fn closed(stream: &mut TcpStream, within: Duration) -> bool {
        let mut buf = [0; 1024];
        loop {
            match tokio::time::timeout(within, stream.read(&mut buf)).await {
                Ok(Ok(0) | Err(_)) => return true,
                Ok(Ok(_)) => continue,
                Err(_) => return false,
            }
        }
    }

    #[tokio::test]
    async fn serves_plain_http() {
        let (address, _guard) = listening(Limits::new(false)).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.ends_with("hi"));
    }

    #[tokio::test]
    async fn caps_each_addresss_connections() {
        let (address, _guard) = listening(Limits { total: 100, per_address: Some(2), header_timeout: HEADER_TIMEOUT, idle_timeout: IDLE_TIMEOUT }).await;
        let _a = TcpStream::connect(address).await.unwrap();
        let _b = TcpStream::connect(address).await.unwrap();
        let mut c = TcpStream::connect(address).await.unwrap();
        assert!(closed(&mut c, Duration::from_secs(2)).await);
        drop(_a);
        // Its place is given back once it's gone.
        let mut freed = false;
        for _ in 0..50 {
            let mut d = TcpStream::connect(address).await.unwrap();
            if !closed(&mut d, Duration::from_millis(100)).await {
                freed = true;
                break;
            }
        }
        assert!(freed);
    }

    /// Between requests, a connection is kept only so long.
    #[tokio::test]
    async fn closes_idle_connections() {
        let (address, _guard) = listening(Limits { idle_timeout: Duration::from_millis(300), ..Limits::new(false) }).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").await.unwrap();
        let mut buf = [0; 1024];
        assert!(stream.read(&mut buf).await.unwrap() > 0);
        assert!(closed(&mut stream, Duration::from_secs(5)).await);
    }

    #[tokio::test]
    async fn caps_connections_in_all() {
        let (address, _guard) = listening(Limits { total: 1, per_address: None, header_timeout: HEADER_TIMEOUT, idle_timeout: IDLE_TIMEOUT }).await;
        let _a = TcpStream::connect(address).await.unwrap();
        let mut b = TcpStream::connect(address).await.unwrap();
        assert!(closed(&mut b, Duration::from_secs(2)).await);
    }

    /// A client that starts a request and never finishes its headers is
    /// dropped.
    #[tokio::test]
    async fn drops_a_client_slow_with_its_headers() {
        let (address, _guard) = listening(Limits { header_timeout: Duration::from_millis(300), idle_timeout: Duration::from_millis(600), ..Limits::new(false) }).await;
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"GET / HTTP/1.1\r\nHost: x\r\n").await.unwrap();
        assert!(closed(&mut stream, Duration::from_secs(5)).await);
        // As is one that sends nothing at all.
        let mut silent = TcpStream::connect(address).await.unwrap();
        assert!(closed(&mut silent, Duration::from_secs(5)).await);
    }
}
