//! The Blossom server. A stub for now: it listens, and answers that it
//! doesn't serve anything yet.
//!
//! It will share the blob store the web service downloads into, so the
//! site's own files are blobs it already has.

use anyhow::Result;
use axum::Router;
use axum::response::IntoResponse;
use http::{Method, StatusCode, Uri, header};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

pub fn router() -> Router {
    Router::new().fallback(handle)
}

pub async fn run(listener: TcpListener, cancel: CancellationToken) -> Result<()> {
    axum::serve(listener, router()).with_graceful_shutdown(cancel.cancelled_owned()).await?;
    Ok(())
}

async fn handle(method: Method, uri: Uri) -> impl IntoResponse {
    let cors = [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")];
    if method == Method::GET && uri.path() == "/" {
        return (StatusCode::OK, cors, "This is a Blossom server.\n");
    }
    (StatusCode::NOT_IMPLEMENTED, cors, "This Blossom server is not implemented yet.\n")
}
