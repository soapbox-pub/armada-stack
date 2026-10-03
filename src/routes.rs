//! Every service on one origin.
//!
//! Their paths barely overlap, so each request goes to whichever service it
//! names, in this order:
//!
//! 1. A WebSocket upgrade or NIP-11 request to `/`: the relay.
//! 2. `/upload`, `/mirror`, `/<sha256>` and Blossom's other endpoints, by
//!    any method, CORS preflights included: the Blossom server.
//! 3. `/.well-known/concord/av` and beneath it: the AV broker, or a 404 if
//!    there isn't one.
//! 4. `/rtc` and beneath it, if an AV node is on this origin: forwarded to
//!    that node, LiveKit's signaling.
//! 5. Everything else: the web app, whose shell answers any path it lacks a
//!    file for — which is why it comes last.
//!
//! Each service sets its own response headers, so a blob keeps its sandbox
//! and the site its Content Security Policy.

use std::sync::Arc;

use axum::Router;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};

use crate::av::{self, Av};
use crate::blossom::{self, Blossom};
use crate::relay::{self, Relay};
use crate::web::serve::SiteServer;

#[derive(Clone)]
pub struct Services {
    pub web: Arc<SiteServer>,
    pub relay: Relay,
    pub blossom: Blossom,
    /// Absent unless AV nodes are configured.
    pub av: Option<Av>,
}

pub fn router(services: Services) -> Router {
    Router::new().fallback(move |request: Request| {
        let services = services.clone();
        async move { dispatch(&services, request).await }
    })
}

async fn dispatch(services: &Services, request: Request) -> Response {
    let path = request.uri().path();
    if relay::wants(request.method(), path, request.headers()) {
        services.relay.handle(request).await
    } else if blossom::wants(path) {
        services.blossom.handle(request).await.into_response()
    } else if av::wants(path) {
        match &services.av {
            Some(av) => av.handle(request).into_response(),
            None => av::not_offered().into_response(),
        }
    } else if let Some(signaling) = services.av.as_ref().and_then(Av::signaling).filter(|_| av::signaling::wants(path)) {
        signaling.handle(request).await
    } else {
        services.web.serve(request).await.into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use futures_util::{SinkExt, StreamExt};
    use http::{Method, StatusCode};
    use http_body_util::BodyExt;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_util::sync::CancellationToken;
    use tower::ServiceExt;

    use super::*;
    use crate::config::Config;
    use crate::storage::Storage;
    use crate::web::serve::SiteServer;

    const SHA: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    struct Harness {
        _dir: tempfile::TempDir,
        router: Router,
        _cancel: tokio_util::sync::DropGuard,
    }

    /// The stack, with no site downloaded yet: the web app answers 503 to
    /// everything, which tells its answers apart from the others'.
    fn harness() -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::allowing_private(dir.path());
        let config = Config::default();
        let cancel = CancellationToken::new();
        let web = Arc::new(SiteServer {
            live: Default::default(),
            blobs: storage.blobs.clone(),
            naddr: http::HeaderValue::from_static("naddr"),
        });
        let relay = Relay::open(&config.relay, None, false, &storage, &cancel).unwrap();
        let blossom = Blossom::open(&config.blossom, None, false, &storage, &cancel).unwrap();
        let router = router(Services { web, relay, blossom, av: None });
        Harness { _dir: dir, router, _cancel: cancel.drop_guard() }
    }

    impl Harness {
        async fn send(&self, method: Method, path: &str, headers: &[(&str, &str)]) -> (StatusCode, http::HeaderMap, String) {
            // As a real server would, the peer's address.
            let peer = axum::extract::ConnectInfo(std::net::SocketAddr::from(([203, 0, 113, 1], 4000)));
            let mut builder = Request::builder().method(method).uri(path).extension(peer);
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            let response = self.router.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
            let (parts, body) = response.into_parts();
            (parts.status, parts.headers, String::from_utf8_lossy(&body.collect().await.unwrap().to_bytes()).into_owned())
        }
    }

    #[tokio::test]
    async fn the_root_is_the_sites_unless_its_the_relays() {
        let harness = harness();
        let (status, _, _) = harness.send(Method::GET, "/", &[]).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

        let (status, headers, body) = harness.send(Method::GET, "/", &[("accept", "application/nostr+json")]).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers["content-type"], "application/nostr+json");
        assert!(body.contains("supported_nips"));

        // Only at the root: anywhere else is a path of the site's.
        let (status, _, _) = harness.send(Method::GET, "/relay", &[("accept", "application/nostr+json")]).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn blossoms_paths_are_blossoms() {
        let harness = harness();
        // Not the site's shell, whatever the extension.
        for path in [format!("/{SHA}"), format!("/{SHA}.bin"), format!("/{SHA}.html")] {
            let (status, headers, _) = harness.send(Method::GET, &path, &[]).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(headers["x-reason"], "Blob not found.");
        }
        let (status, headers, _) = harness.send(Method::PUT, "/upload", &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(headers.contains_key("x-reason"));
        let (status, _, _) = harness.send(Method::HEAD, "/upload", &[("x-content-length", "1024")]).await;
        assert_eq!(status, StatusCode::OK);
        let (_, headers, _) = harness.send(Method::GET, "/list/abc", &[]).await;
        assert_eq!(headers["x-reason"], "This server doesn't list blobs.");

        // A hash-like path that isn't one is the site's.
        let (status, _, _) = harness.send(Method::GET, &format!("/{SHA}x"), &[]).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let (status, _, _) = harness.send(Method::GET, &format!("/assets/{SHA}.js"), &[]).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn preflights_go_where_the_request_will() {
        let harness = harness();
        let preflight = [("origin", "https://example.com"), ("access-control-request-method", "PUT")];

        let (status, headers, _) = harness.send(Method::OPTIONS, "/upload", &preflight).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(headers["access-control-allow-methods"].to_str().unwrap().contains("PUT"));

        let (status, headers, _) = harness.send(Method::OPTIONS, "/assets/app.js", &preflight).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(headers["access-control-allow-methods"], "GET, HEAD, OPTIONS");
    }

    #[tokio::test]
    async fn the_av_broker_is_never_the_sites() {
        let harness = harness();
        for path in ["/.well-known/concord/av", "/.well-known/concord/av/abc"] {
            let (status, headers, _) = harness.send(Method::GET, path, &[]).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(headers["access-control-allow-origin"], "*");
        }
        let (status, _, _) = harness.send(Method::GET, "/.well-known/concord/avatar", &[]).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn the_relay_speaks_websockets_at_the_root() {
        let harness = harness();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/", listener.local_addr().unwrap());
        let router = harness.router.clone();
        tokio::spawn(async move { axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>()).await });

        let (mut socket, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        let challenge = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.unwrap().unwrap().unwrap();
        assert!(challenge.into_text().unwrap().starts_with(r#"["AUTH","#));
        socket.send(Message::Text(r#"["REQ","s",{"limit":1}]"#.into())).await.unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(5), socket.next()).await.unwrap().unwrap().unwrap();
        assert_eq!(reply.into_text().unwrap().as_str(), r#"["EOSE","s"]"#);
    }
}
