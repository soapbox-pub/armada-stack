//! A blind Concord AV broker (CORD-07 §2), and the health of the LiveKit
//! servers behind it.
//!
//! ```text
//! GET /.well-known/concord/av               → 204, if a node is up
//! GET /.well-known/concord/av/<voice_room>  → { token, url, identity }
//!     Authorization: Concord <base64(kind 27235 event)>
//! ```
//!
//! It holds no Community secrets and keeps nothing but the ids of grants
//! recently used. It can't tell which Community a room belongs to, and never
//! learns who's joining: the only authorization is a signature by
//! `voice_key.sk`, which every member of the Channel, and nobody else, can
//! derive. Calls are end-to-end encrypted, so the SFU forwards ciphertext.
//!
//! So it's an open service by design: anyone can mint a keypair and call it
//! a room. Abuse is bounded by a [rate limit](crate::ratelimit), by LiveKit's own
//! `max_participants`, and by short-lived tokens — never by checking who's
//! calling, which would end the blindness.
//!
//! Nothing is logged per request.

pub mod builtin;
mod fleet;
mod grant;
mod livekit;
pub mod signaling;

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use axum::body::Body;
use axum::extract::Request;
use http::header::{self, HeaderMap, HeaderValue};
use http::{Method, Response, StatusCode};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::nostr::event::is_hex64;
use crate::ratelimit::{self, RateLimiter, Trust};
use crate::util::{now, random_hex};
use fleet::{Fleet, Node};
use grant::ReplaySet;

/// Where §2 puts the broker.
const PATH: &str = "/.well-known/concord/av";

/// The most grant ids remembered at once, and clients counted at once.
const MAX_REPLAY_IDS: usize = 1_000_000;
const MAX_RATE_LIMITED: usize = 100_000;

type Reply = Response<Body>;

#[derive(Clone)]
pub struct Av {
    broker: Arc<Broker>,
    /// Forwards `/rtc` to the node on armada's own origin, if there is one.
    signaling: Option<Arc<signaling::Signaling>>,
}

struct Broker {
    fleet: Fleet,
    /// The public URL a request for `room` arrives at is this, then `room`.
    /// Grants are signed over it, so it's never taken from the request,
    /// whose headers a client could forge.
    base_url: String,
    trust: Trust,
    token_ttl: u64,
    max_skew: i64,
    replays: Mutex<ReplaySet>,
    limiter: Mutex<RateLimiter>,
}

impl Av {
    /// The broker `config` describes, or `None` if it names no nodes. Nodes
    /// are checked on every `health_interval` until `cancel` fires.
    pub fn open(config: &Config, cancel: &CancellationToken) -> Result<Option<Av>> {
        let av = Self::new(config)?;
        if let Some(av) = &av {
            for node in av.broker.fleet.nodes() {
                if !node.url.starts_with("wss://") {
                    tracing::warn!(node = %node.url, "AV node isn't wss://, which clients refuse");
                }
            }
            if config.public_url.as_deref().is_some_and(|url| !url.trim().starts_with("https://")) {
                tracing::warn!("public_url isn't https://, which clients refuse to send grants to");
            }
            tokio::spawn(check_health(av.broker.clone(), Duration::from_secs(config.av.health_interval), cancel.child_token()));
        }
        Ok(av)
    }

    /// The broker, without health checks.
    fn new(config: &Config) -> Result<Option<Av>> {
        let av = &config.av;
        if av.nodes.is_empty() {
            return Ok(None);
        }
        let nodes = av.nodes.iter().map(Node::from_config).collect::<Result<Vec<_>>>()?;
        let public_url = config.public_url()?.expect("validated: public_url is set when AV is on");
        let local = av.nodes.iter().find(|node| node.is_on(&public_url));
        let signaling = local.map(|node| signaling::Signaling::new(&node.api_url().expect("validated"), config.trust())).transpose()?;
        Ok(Some(Av {
            signaling: signaling.map(Arc::new),
            broker: Arc::new(Broker {
                fleet: Fleet::new(nodes),
                base_url: format!("{}{PATH}/", public_url.origin().ascii_serialization()),
                trust: config.trust(),
                token_ttl: av.token_ttl,
                max_skew: av.max_skew as i64,
                replays: Mutex::new(ReplaySet::new(Duration::from_secs(av.replay_ttl), MAX_REPLAY_IDS)),
                limiter: Mutex::new(RateLimiter::new(av.rate_limit_per_minute.into(), Duration::from_secs(60), MAX_RATE_LIMITED)),
            }),
        }))
    }

    #[cfg(test)]
    pub fn router(&self) -> axum::Router {
        let av = self.clone();
        axum::Router::new().fallback(move |request: Request| async move { av.handle(request) })
    }

    pub fn handle(&self, request: Request) -> Reply {
        with_headers(self.broker.route(request))
    }

    /// The forwarder for LiveKit's signaling, if a node is on armada's own
    /// origin.
    pub fn signaling(&self) -> Option<&signaling::Signaling> {
        self.signaling.as_deref()
    }
}

/// Whether a path is the broker's. It shares an origin with the web app,
/// whose shell would otherwise answer these with a page and a 200.
pub fn wants(path: &str) -> bool {
    path.strip_prefix(PATH).is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
}

/// The answer to a request for the broker when there isn't one: unavailable,
/// in the same terms, so clients look for another (§5).
pub fn not_offered() -> Reply {
    with_headers(json(StatusCode::NOT_FOUND, &serde_json::json!({ "error": "AV is not offered here" })))
}

impl Broker {
    fn route(&self, request: Request) -> Reply {
        let method = request.method();
        if method == Method::OPTIONS {
            return empty(StatusCode::NO_CONTENT);
        }
        if method != Method::GET {
            let mut reply = error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
            reply.headers_mut().insert(header::ALLOW, HeaderValue::from_static("GET, OPTIONS"));
            return reply;
        }

        let path = request.uri().path();
        // The capability probe. Not a place to shed load: clients that find
        // it failing go to another broker (§5), splitting calls already live
        // here. It fails only when there's no node to place a room on.
        if path == PATH || path == format!("{PATH}/") {
            return empty(if self.fleet.available() { StatusCode::NO_CONTENT } else { StatusCode::SERVICE_UNAVAILABLE });
        }

        // §1: a room is an x-only pubkey in lowercase hex.
        let room = &path[PATH.len() + 1..];
        if !is_hex64(room) {
            return error(StatusCode::NOT_FOUND, "invalid room name");
        }

        let Some(key) = ratelimit::client_key(request.headers(), request.extensions(), self.trust) else {
            // Without one there's nothing to limit by, and a shared bucket
            // would let any such caller exhaust it for the rest.
            return error(StatusCode::BAD_REQUEST, "cannot determine peer address");
        };
        if let Err(retry_after) = self.limiter.lock().admit(&key, Instant::now()) {
            let mut reply = error(StatusCode::TOO_MANY_REQUESTS, "rate limited");
            reply.headers_mut().insert(header::RETRY_AFTER, retry_after.into());
            return reply;
        }

        let event = match grant::parse(request.headers().get(header::AUTHORIZATION)) {
            Ok(event) => event,
            Err(refusal) => return error(refusal.status, refusal.reason),
        };
        let url = format!("{}{room}", self.base_url);
        let checked = grant::verify(&event, &grant::Request { room, url: &url, method: "GET", now: now(), max_skew: self.max_skew });
        if let Err(refusal) = checked {
            return error(refusal.status, refusal.reason);
        }
        // Last, since it's remembered.
        if !self.replays.lock().admit(&event.id, Instant::now()) {
            return error(StatusCode::UNAUTHORIZED, "grant already used");
        }

        let room_bytes: [u8; 32] = hex::decode(room).expect("checked hex").try_into().expect("checked length");
        let Some(node) = self.fleet.select(&room_bytes) else {
            return error(StatusCode::SERVICE_UNAVAILABLE, "no SFU available");
        };
        // 128 bits, §2's floor for an assigned identity.
        let identity = random_hex(16);
        let token = livekit::join_token(node, room, &identity, self.token_ttl, now());
        json(StatusCode::OK, &serde_json::json!({ "token": token, "url": node.url, "identity": identity }))
    }
}

/// Check every node, now and then on every `interval`.
async fn check_health(broker: Arc<Broker>, interval: Duration, cancel: CancellationToken) {
    // Nodes are usually beside armada or on its network, not anywhere a
    // stranger chose, so this client may reach private addresses.
    let http = match reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build() {
        Ok(http) => http,
        Err(error) => {
            tracing::error!(%error, "AV health checks can't start");
            return;
        }
    };
    let timeout = fleet::probe_timeout(interval);
    let mut ticks = tokio::time::interval(interval);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticks.tick() => {}
        }
        let nodes = broker.fleet.nodes();
        let checks = nodes.iter().map(|node| livekit::probe(&http, node, timeout, now()));
        let outcomes = tokio::select! {
            _ = cancel.cancelled() => return,
            outcomes = futures_util::future::join_all(checks) => outcomes,
        };
        for (index, outcome) in outcomes.into_iter().enumerate() {
            broker.fleet.observe(index, outcome);
        }
    }
}

/// Headers every answer carries.
///
/// CORS wide open: the broker is reached from whatever origin a client is
/// served on, it's open by design, and the grant rides a header the client
/// sets, never a cookie. `no-store`, since a token is a bearer credential
/// and the probe is only worth anything current.
fn with_headers(mut reply: Reply) -> Reply {
    let headers: &mut HeaderMap = reply.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_METHODS, HeaderValue::from_static("GET, OPTIONS"));
    headers.insert(header::ACCESS_CONTROL_ALLOW_HEADERS, HeaderValue::from_static("Authorization, Content-Type"));
    headers.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("86400"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    reply
}

fn empty(status: StatusCode) -> Reply {
    Response::builder().status(status).body(Body::empty()).expect("response")
}

fn json(status: StatusCode, body: &serde_json::Value) -> Reply {
    Response::builder().status(status).header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).expect("response")
}

fn error(status: StatusCode, reason: &str) -> Reply {
    json(status, &serde_json::json!({ "error": reason }))
}

#[cfg(test)]
mod tests;
