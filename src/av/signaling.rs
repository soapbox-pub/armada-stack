//! LiveKit's signaling, forwarded, for a node served on armada's own origin.
//!
//! The LiveKit SDK reaches a node at `<url>/rtc`: a WebSocket, and a plain
//! `GET /rtc/validate` when that fails. A node whose `url` is armada's own
//! origin has those forwarded to its `api_url`, so it needs no domain or
//! certificate of its own, and no reverse proxy in front. Only signaling
//! passes through here: media goes to the node directly, over UDP or TCP.
//! Its server API, `/twirp`, is never forwarded.
//!
//! The forwarding is byte for byte: once the node agrees to the upgrade,
//! the two connections are joined, so the WebSocket's subprotocols and
//! extensions are the client's and the node's business alone.
//!
//! Only plain paths beneath `/rtc` go: none with `.` or `..` segments, or
//! an encoded `.` or `/`, which the node might resolve to somewhere else.
//! And the node hears who the client is from armada alone: headers that
//! would say otherwise are dropped unless armada trusts the proxy that set
//! them.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use axum::body::Body;
use axum::extract::{ConnectInfo, Request};
use http::header::{self, HeaderMap, HeaderName, HeaderValue};
use http::{Response, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;

/// How long the node has to accept a connection, and then to answer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether a path is LiveKit's signaling.
pub fn wants(path: &str) -> bool {
    path.strip_prefix("/rtc").is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

pub struct Signaling {
    /// Where the node's HTTP server is: `host:port`.
    authority: String,
    /// What `api_url`'s path puts ahead of the request's, without a
    /// trailing slash.
    prefix: String,
    trust_proxy: bool,
}

impl Signaling {
    pub fn new(api_url: &str, trust_proxy: bool) -> Result<Signaling> {
        let url = url::Url::parse(api_url).with_context(|| format!("Not a valid api_url: {api_url}"))?;
        let host = url.host_str().ok_or_else(|| anyhow!("api_url has no host: {api_url}"))?;
        let port = url.port_or_known_default().unwrap_or(80);
        Ok(Signaling { authority: format!("{host}:{port}"), prefix: url.path().trim_end_matches('/').to_string(), trust_proxy })
    }

    pub async fn handle(&self, request: Request) -> Response<Body> {
        if !plain(request.uri().path()) {
            return Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty()).expect("response");
        }
        match self.forward(request).await {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(node = self.authority, "AV signaling: {error:#}");
                Response::builder().status(StatusCode::BAD_GATEWAY).body(Body::empty()).expect("response")
            }
        }
    }

    async fn forward(&self, mut request: Request) -> Result<Response<Body>> {
        let upgrade = upgrade_requested(request.headers());
        let client_upgrade = upgrade.is_some().then(|| hyper::upgrade::on(&mut request));
        let peer = request.extensions().get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(peer)| peer.ip());

        let (mut parts, body) = request.into_parts();
        let authority = parts.uri.authority().cloned();
        let path = parts.uri.path_and_query().map_or("/", |path| path.as_str());
        parts.uri = Uri::try_from(format!("{}{path}", self.prefix))?;
        parts.version = http::Version::HTTP_11;
        strip_hop_by_hop(&mut parts.headers);
        if let Some(upgrade) = &upgrade {
            parts.headers.insert(header::CONNECTION, HeaderValue::from_static("upgrade"));
            parts.headers.insert(header::UPGRADE, upgrade.clone());
        }
        // HTTP/2 has no Host, only the URI's authority, which is gone now.
        if !parts.headers.contains_key(header::HOST) {
            let host = authority.as_ref().map_or(self.authority.as_str(), |authority| authority.as_str());
            parts.headers.insert(header::HOST, HeaderValue::from_str(host)?);
        }
        for name in ["x-real-ip", "forwarded"] {
            parts.headers.remove(name);
        }
        if !self.trust_proxy {
            for name in ["x-forwarded-host", "x-forwarded-proto"] {
                parts.headers.remove(name);
            }
        }
        if let Some(peer) = peer {
            self.forwarded_for(&mut parts.headers, peer);
        }

        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.authority))
            .await
            .map_err(|_| anyhow!("timed out connecting"))?
            .context("could not connect")?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        tokio::spawn(connection.with_upgrades());
        let mut response = tokio::time::timeout(RESPONSE_TIMEOUT, sender.send_request(Request::from_parts(parts, body)))
            .await
            .map_err(|_| anyhow!("timed out waiting for an answer"))??;

        if response.status() == StatusCode::SWITCHING_PROTOCOLS
            && let Some(client_upgrade) = client_upgrade
        {
            let node_upgrade = hyper::upgrade::on(&mut response);
            tokio::spawn(async move {
                let (Ok(client), Ok(node)) = tokio::join!(client_upgrade, node_upgrade) else { return };
                let _ = tokio::io::copy_bidirectional(&mut TokioIo::new(client), &mut TokioIo::new(node)).await;
            });
            let (parts, _) = response.into_parts();
            return Ok(Response::from_parts(parts, Body::empty()));
        }

        let (mut parts, body) = response.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        Ok(Response::from_parts(parts, Body::new(body)))
    }

    /// `X-Forwarded-For`, ending with the client's address. What came before
    /// is kept only from a proxy armada trusts.
    fn forwarded_for(&self, headers: &mut HeaderMap, peer: std::net::IpAddr) {
        let earlier = if self.trust_proxy {
            let values: Vec<&str> = headers.get_all("x-forwarded-for").iter().filter_map(|value| value.to_str().ok()).collect();
            (!values.is_empty()).then(|| values.join(", "))
        } else {
            None
        };
        let value = match earlier {
            Some(earlier) => format!("{earlier}, {peer}"),
            None => peer.to_string(),
        };
        if let Ok(value) = HeaderValue::from_str(&value) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), value);
        }
    }
}

/// Whether a path names itself plainly: no `.` or `..` segments, no `//`,
/// and nothing encoded that could become either, or a `/`.
fn plain(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let encoded = ["%2e", "%2f", "%5c"].iter().any(|encoded| lower.contains(encoded));
    !encoded && !path.contains('\\') && !path.contains("//") && path.split('/').all(|segment| segment != "." && segment != "..")
}

/// The protocol a request asks to upgrade to, if it does.
fn upgrade_requested(headers: &HeaderMap) -> Option<HeaderValue> {
    let connection = headers.get_all(header::CONNECTION).iter().filter_map(|value| value.to_str().ok());
    let mut tokens = connection.flat_map(|value| value.split(',')).map(str::trim);
    tokens.any(|token| token.eq_ignore_ascii_case("upgrade")).then(|| headers.get(header::UPGRADE).cloned()).flatten()
}

/// Remove the headers that describe one connection, not the message
/// (RFC 9110 §7.6.1): they mean nothing on the next.
fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::try_from(name.trim()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in ["connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade"] {
        headers.remove(name);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwards_only_plain_paths() {
        for path in ["/rtc", "/rtc/", "/rtc/validate", "/rtc/v1"] {
            assert!(plain(path), "{path}");
        }
        for path in ["/rtc/../twirp/livekit.RoomService/ListRooms", "/rtc/./x", "/rtc/%2e%2e/debug", "/rtc/%2E%2E/debug", "/rtc%2f..%2fdebug", "/rtc//x", "/rtc/..", "/rtc/\\..\\debug"] {
            assert!(!plain(path), "{path}");
        }
    }

    #[test]
    fn drops_what_says_who_the_client_is() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("6.6.6.6"));
        let signaling = Signaling::new("http://127.0.0.1:7880", false).unwrap();
        signaling.forwarded_for(&mut headers, "203.0.113.9".parse().unwrap());
        assert_eq!(headers["x-forwarded-for"], "203.0.113.9");
        let trusting = Signaling::new("http://127.0.0.1:7880", true).unwrap();
        trusting.forwarded_for(&mut headers, "127.0.0.1".parse().unwrap());
        assert_eq!(headers["x-forwarded-for"], "203.0.113.9, 127.0.0.1");
    }
}
