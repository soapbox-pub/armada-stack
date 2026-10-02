//! The relay. A stub for now: it listens, describes itself (NIP-11), and
//! tells any client that connects that it doesn't store anything yet.

use anyhow::Result;
use axum::Router;
use axum::extract::ws::{Message, WebSocketUpgrade};
use axum::extract::FromRequestParts;
use axum::extract::Request;
use axum::response::{IntoResponse, Response};
use http::{HeaderMap, StatusCode, header};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub fn router() -> Router {
    Router::new().fallback(handle)
}

pub async fn run(listener: TcpListener, cancel: CancellationToken) -> Result<()> {
    axum::serve(listener, router()).with_graceful_shutdown(cancel.cancelled_owned()).await?;
    Ok(())
}

async fn handle(request: Request) -> Response {
    let (mut parts, _) = request.into_parts();

    if let Ok(upgrade) = WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        return upgrade
            .on_upgrade(|mut socket| async move {
                let notice = serde_json::json!(["NOTICE", "This relay is not implemented yet."]).to_string();
                let _ = socket.send(Message::Text(notice.into())).await;
                let _ = socket.send(Message::Close(None)).await;
            })
            .into_response();
    }

    if wants_nip11(&parts.headers) {
        return ([(header::CONTENT_TYPE, "application/nostr+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], info().to_string())
            .into_response();
    }

    (StatusCode::OK, "This is a Nostr relay. Connect to it with a Nostr client.\n").into_response()
}

fn wants_nip11(headers: &HeaderMap) -> bool {
    headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()).is_some_and(|accept| accept.contains("application/nostr+json"))
}

/// The relay's NIP-11 document.
fn info() -> serde_json::Value {
    serde_json::json!({
        "name": "Armada",
        "description": "The relay of a self-hosted Armada.",
        "software": "armada-stack",
        "version": env!("CARGO_PKG_VERSION"),
        "supported_nips": [11],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[tokio::test]
    async fn describes_itself() {
        let request = Request::builder().uri("/").header("accept", "application/nostr+json").body(axum::body::Body::empty()).unwrap();
        let response = router().oneshot(request).await.unwrap();
        assert_eq!(response.headers()["content-type"], "application/nostr+json");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let info: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(info["software"], "armada-stack");
    }
}
