//! Plain HTTP, when armada serves HTTPS: the CA's HTTP-01 challenges are
//! answered, and everything else is sent to the same path over HTTPS.
//!
//! Except for Cloudflare in its Flexible SSL mode, which reaches armada
//! over plain HTTP however its visitor came: redirected, a visitor already
//! on HTTPS would come straight back, round and round. So a request from
//! Cloudflare for a visitor on HTTPS is served the site, as it would be on
//! port 443.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State as Extract};
use axum::middleware::Next;
use http::{HeaderValue, Response, StatusCode, header};

use super::State;

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

/// `site` is served to Cloudflare's HTTPS visitors, if it's given: when
/// Cloudflare is trusted.
pub fn router(domain: String, state: Arc<State>, site: Option<Router>) -> Router {
    match site {
        None => Router::new().fallback(move |request: Request| {
            let response = answer(&domain, &state, &request);
            async move { response }
        }),
        Some(site) => {
            let port80 = Arc::new(Port80 { domain, state, noted: AtomicBool::new(false) });
            site.layer(axum::middleware::from_fn_with_state(port80, serve_cloudflare))
        }
    }
}

struct Port80 {
    domain: String,
    state: Arc<State>,
    /// Whether Flexible SSL has been logged yet: once is plenty.
    noted: AtomicBool,
}

async fn serve_cloudflare(Extract(port80): Extract<Arc<Port80>>, request: Request, next: Next) -> Response<Body> {
    if !for_cloudflare_https(&request) {
        return answer(&port80.domain, &port80.state, &request);
    }
    if !port80.noted.swap(true, Ordering::Relaxed) {
        tracing::info!("Cloudflare reaches armada over plain HTTP (its Flexible SSL mode), so that hop isn't encrypted. Its Full (strict) mode would encrypt it.");
    }
    next.run(request).await
}

/// Whether the request is Cloudflare's, for a visitor who used HTTPS, and
/// not a challenge, which is the CA's whoever relays it.
fn for_cloudflare_https(request: &Request) -> bool {
    let Some(ConnectInfo(peer)) = request.extensions().get::<ConnectInfo<SocketAddr>>() else { return false };
    !request.uri().path().starts_with(CHALLENGE_PATH) && crate::cloudflare::visitor_used_https(request.headers(), peer.ip())
}

fn answer(domain: &str, state: &State, request: &Request) -> Response<Body> {
    if let Some(token) = request.uri().path().strip_prefix(CHALLENGE_PATH) {
        let key_authorization = state.http_challenges.lock().get(token).cloned();
        return match key_authorization {
            Some(key_authorization) => Response::builder()
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(key_authorization))
                .expect("response"),
            None => Response::builder().status(StatusCode::NOT_FOUND).body(Body::empty()).expect("response"),
        };
    }
    // To the one domain the certificate is for, whatever Host was asked
    // for, so the redirect can't be pointed anywhere else.
    let path = request.uri().path_and_query().map_or("/", |path| path.as_str());
    let location = HeaderValue::try_from(format!("https://{domain}{path}")).unwrap_or(HeaderValue::from_static("/"));
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .expect("response")
}
