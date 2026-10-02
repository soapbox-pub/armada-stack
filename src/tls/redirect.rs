//! Plain HTTP, when armada serves HTTPS: the CA's HTTP-01 challenges are
//! answered, and everything else is sent to the same path over HTTPS.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use http::{HeaderValue, Response, StatusCode, header};

use super::State;

const CHALLENGE_PATH: &str = "/.well-known/acme-challenge/";

pub fn router(domain: String, state: Arc<State>) -> Router {
    Router::new().fallback(move |request: Request| {
        let response = answer(&domain, &state, &request);
        async move { response }
    })
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
