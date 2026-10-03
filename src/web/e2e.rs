//! End-to-end: the web service assembled as `main` assembles it, with a fake
//! Nostr and a fake Blossom server standing in for the network. A manifest
//! goes in one end; a served site comes out the other.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use futures_util::future::BoxFuture;
use http::{Request, StatusCode};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

use super::Web;
use super::db::Status;
use crate::config::WebConfig;
use crate::nostr::Event;
use crate::nostr::service::NostrSource;
use crate::nsite::{NAMED_SITE_KIND, NsiteAddress};
use crate::storage::Storage;

const AUTHOR: &str = "0000000000000000000000000000000000000000000000000000000000000009";

/// Relays that hold exactly the manifests a test gives them, and pass on
/// whatever it publishes while subscribed.
struct FakeNostr {
    manifests: Mutex<Vec<Event>>,
    updates: Mutex<Option<mpsc::Receiver<Event>>>,
    server: String,
}

impl NostrSource for FakeNostr {
    fn fetch_manifest<'a>(&'a self, address: &'a NsiteAddress, _: &'a CancellationToken) -> BoxFuture<'a, Option<Event>> {
        Box::pin(async move { self.manifests.lock().iter().filter(|e| address.matches(e)).max_by_key(|e| e.created_at).cloned() })
    }

    fn blob_sources<'a>(&'a self, _: &'a Event, _: &'a CancellationToken) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move { vec![self.server.clone()] })
    }

    fn subscribe<'a>(&'a self, _: &'a NsiteAddress, _: CancellationToken) -> BoxFuture<'a, mpsc::Receiver<Event>> {
        Box::pin(async move { self.updates.lock().take().unwrap_or_else(|| mpsc::channel(1).1) })
    }
}

/// A Blossom server on loopback, holding whatever blobs a test adds.
async fn blossom(blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = axum::Router::new().route(
        "/{sha}",
        axum::routing::get(move |axum::extract::Path(sha): axum::extract::Path<String>| {
            let blobs = blobs.clone();
            async move {
                match blobs.lock().get(&sha) {
                    Some(bytes) => (StatusCode::OK, bytes.clone()),
                    None => (StatusCode::NOT_FOUND, Vec::new()),
                }
            }
        }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}/")
}

struct Harness {
    dir: tempfile::TempDir,
    address: NsiteAddress,
    blobs: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    server: String,
}

impl Harness {
    async fn new() -> Harness {
        let blobs = Arc::new(Mutex::new(HashMap::new()));
        let server = blossom(blobs.clone()).await;
        let pubkey = crate::nostr::event::public_key(AUTHOR);
        let address = NsiteAddress { pubkey, kind: NAMED_SITE_KIND, identifier: "armada".into() };
        Harness { dir: tempfile::tempdir().unwrap(), address, blobs, server }
    }

    /// A version of the site with these files, its blobs on the Blossom server.
    fn publish(&self, created_at: i64, files: &[(&str, &str)]) -> Event {
        let mut tags = vec![vec!["d".to_string(), self.address.identifier.clone()]];
        for (path, content) in files {
            let sha = hex::encode(Sha256::digest(content.as_bytes()));
            self.blobs.lock().insert(sha.clone(), content.as_bytes().to_vec());
            tags.push(vec!["path".into(), path.to_string(), sha]);
        }
        Event::sign(AUTHOR, created_at, NAMED_SITE_KIND, tags, "")
    }

    /// Start the web service, as `main` would, over this harness's storage.
    async fn start(&self, manifests: Vec<Event>, auto_update: bool) -> Running {
        self.start_keeping(manifests, auto_update, WebConfig::default().keep_versions).await
    }

    async fn start_keeping(&self, manifests: Vec<Event>, auto_update: bool, keep_versions: usize) -> Running {
        let (tx, rx) = mpsc::channel(8);
        let nostr = Arc::new(FakeNostr { manifests: Mutex::new(manifests), updates: Mutex::new(Some(rx)), server: self.server.clone() });
        let config = WebConfig { nsite: self.address.naddr(), auto_update, keep_versions, ..WebConfig::default() };
        let mut web = Web::open(&config, Default::default(), &Storage::allowing_private(self.dir.path()), nostr).await.unwrap();
        web.worker.settings.retry_backoff = Duration::from_millis(10);

        let router = web.router();
        let db = web.worker.db.clone();
        let cancel = CancellationToken::new();
        let worker = tokio::spawn(web.worker.run(cancel.clone()));
        Running { router, db, updates: tx, cancel, worker }
    }
}

struct Running {
    router: axum::Router,
    db: super::db::WebDb,
    updates: mpsc::Sender<Event>,
    cancel: CancellationToken,
    worker: tokio::task::JoinHandle<()>,
}

impl Running {
    async fn get(&self, path: &str, headers: &[(&str, &str)]) -> (StatusCode, http::HeaderMap, Vec<u8>) {
        self.request("GET", path, headers).await
    }

    async fn request(&self, method: &str, path: &str, headers: &[(&str, &str)]) -> (StatusCode, http::HeaderMap, Vec<u8>) {
        let mut builder = Request::builder().method(method).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = self.router.clone().oneshot(builder.body(Body::empty()).unwrap()).await.unwrap();
        let (parts, body) = response.into_parts();
        (parts.status, parts.headers, body.collect().await.unwrap().to_bytes().to_vec())
    }

    async fn stop(self) {
        self.cancel.cancel();
        self.worker.await.unwrap();
    }
}

/// Wait for a condition the sync worker will bring about.
async fn eventually(what: &str, mut check: impl AsyncFnMut() -> bool) {
    for _ in 0..200 {
        if check().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("{what} never happened");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_published_site_is_downloaded_and_served() {
    let harness = Harness::new().await;
    let page = format!(
        "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'; img-src https:\"><title>Armada</title></head><body>{}</body></html>",
        "hello ".repeat(200)
    );
    let script = "console.log('hi');\n".repeat(100);
    let manifest = harness.publish(crate::util::now() - 60, &[("/index.html", &page), ("/assets/app.js", &script)]);
    let web = harness.start(vec![manifest.clone()], true).await;

    eventually("the site going live", async || web.get("/", &[]).await.0 == StatusCode::OK).await;

    // The page is served with the env script first in its head, under a
    // hash of its own; the site's policy already lets it load.
    let served = page.replacen("<head>", r#"<head><script src="/_armada/env.js"></script>"#, 1);
    let (status, headers, body) = web.get("/", &[("accept-encoding", "gzip, br")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-encoding"], "br");
    assert_eq!(headers["etag"], format!("\"{}-br\"", hex::encode(Sha256::digest(served.as_bytes()))));
    assert_eq!(headers["content-type"], "text/html; charset=utf-8");
    assert_eq!(headers["cache-control"], "public, no-cache");
    assert_eq!(headers["vary"], "accept-encoding");
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(headers["x-nsite-addr"], harness.address.naddr());
    assert_eq!(headers["content-security-policy"], "default-src 'self'; img-src https:, frame-ancestors 'none'");
    assert_eq!(headers["x-frame-options"], "DENY");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    let mut decoded = Vec::new();
    brotli::BrotliDecompress(&mut body.as_slice(), &mut decoded).unwrap();
    assert_eq!(decoded, served.as_bytes());

    let etag = headers["etag"].to_str().unwrap().to_string();
    let (status, ..) = web.get("/", &[("accept-encoding", "br"), ("if-none-match", &etag)]).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);

    let (status, headers, body) = web.get("/assets/app.js", &[("range", "bytes=0-6")]).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers["content-range"], format!("bytes 0-6/{}", script.len()));
    assert_eq!(headers["cache-control"], "public, max-age=3600, must-revalidate");
    assert_eq!(body, b"console");

    // Any path the site has no file for gets the app, dots and all.
    for path in ["/invite/naddr1xyz", "/s/relay.ditto.pub"] {
        let (status, _, body) = web.get(path, &[]).await;
        assert_eq!((status, body), (StatusCode::OK, served.as_bytes().to_vec()), "{path}");
    }
    // But not a chunk: that's a 404, still under the site's policy.
    let (status, headers, _) = web.get("/assets/gone.js", &[]).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["content-security-policy"], "default-src 'self'; img-src https:, frame-ancestors 'none'");

    let (status, ..) = web.request("POST", "/", &[]).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);

    let (status, headers, body) = web.get("/_armada/env.js", &[]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-type"], "text/javascript; charset=utf-8");
    assert_eq!(body, b"self.ENV = {};\n");

    web.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn new_versions_go_live_over_the_kept_ones_and_survive_a_restart() {
    let harness = Harness::new().await;
    let now = crate::util::now();
    let first = harness.publish(now - 180, &[("/index.html", "first"), ("/assets/first.js", "1")]);
    let web = harness.start_keeping(vec![first.clone()], true, 2).await;
    eventually("the first version going live", async || web.get("/", &[]).await.2 == b"first").await;
    // A site with no policy of its own gets the default.
    assert_eq!(web.get("/", &[]).await.1["content-security-policy"], super::csp::DEFAULT_CSP);

    // Published while subscribed: it goes live without waiting for a resync.
    let second = harness.publish(now - 120, &[("/index.html", "second"), ("/assets/second.js", "2")]);
    web.updates.send(second.clone()).await.unwrap();
    eventually("the second version going live", async || web.get("/", &[]).await.2 == b"second").await;
    // The first is kept, and what it alone has is still served beneath the second.
    assert!(web.db.get(&first.id).unwrap().is_some());
    assert_eq!(web.get("/assets/first.js", &[]).await.2, b"1");
    assert_eq!(web.get("/assets/second.js", &[]).await.2, b"2");

    // Past keep_versions, the oldest is forgotten, and its files with it.
    let third = harness.publish(now - 60, &[("/index.html", "third")]);
    web.updates.send(third.clone()).await.unwrap();
    eventually("the third version going live", async || web.get("/", &[]).await.2 == b"third").await;
    assert!(web.db.get(&first.id).unwrap().is_none());
    assert_eq!(web.get("/assets/first.js", &[]).await.0, StatusCode::NOT_FOUND);
    assert_eq!(web.get("/assets/second.js", &[]).await.2, b"2");

    // An older version turning up late changes nothing.
    web.updates.send(first.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(web.get("/", &[]).await.2, b"third");
    web.stop().await;

    // Restarted with the network gone, it serves what it had at once,
    // merged as it was.
    harness.blobs.lock().clear();
    let web = harness.start_keeping(vec![], true, 2).await;
    assert_eq!(web.get("/", &[]).await.2, b"third");
    assert_eq!(web.get("/assets/second.js", &[]).await.2, b"2");
    web.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn with_auto_update_off_the_first_version_stays() {
    let harness = Harness::new().await;
    let now = crate::util::now();
    let first = harness.publish(now - 120, &[("/index.html", "first")]);
    let web = harness.start(vec![first.clone()], false).await;
    eventually("the first version going live", async || web.get("/", &[]).await.2 == b"first").await;
    // The worker is done: nothing more is followed.
    eventually("the worker stopping", async || web.worker.is_finished()).await;
    web.stop().await;

    // Nor is anything looked for on a restart, while a version is stored.
    let second = harness.publish(now - 60, &[("/index.html", "second")]);
    let web = harness.start(vec![first, second], false).await;
    eventually("the worker stopping", async || web.worker.is_finished()).await;
    assert_eq!(web.get("/", &[]).await.2, b"first");
    web.stop().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_missing_blob_fails_the_deploy_and_says_why() {
    let harness = Harness::new().await;
    let manifest = harness.publish(crate::util::now() - 60, &[("/index.html", "lost")]);
    harness.blobs.lock().clear();
    let web = harness.start(vec![manifest.clone()], true).await;

    eventually("the deploy failing", async || {
        web.db.get(&manifest.id).unwrap().is_some_and(|version| version.status == Status::Failed)
    })
    .await;
    let version = web.db.get(&manifest.id).unwrap().unwrap();
    assert!(version.error.unwrap().contains("could not be downloaded"));

    let (status, headers, _) = web.get("/", &[]).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers["retry-after"], "30");
    assert_eq!(headers["content-security-policy"], super::csp::DEFAULT_CSP);
    web.stop().await;
}
