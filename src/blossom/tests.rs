//! The Blossom server end to end, through its router.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use axum::Router;
use tokio::net::TcpListener;
use tower::ServiceExt;

use super::auth::tests::{header, token};
use super::*;
use crate::config::BlossomConfig;
use crate::util::now;

const ALICE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const BOB: &str = "0000000000000000000000000000000000000000000000000000000000000002";
const MAX: u64 = 1 << 20;

struct Harness {
    _dir: tempfile::TempDir,
    storage: Storage,
    blossom: Blossom,
}

impl Harness {
    fn new() -> Harness {
        Self::with(BlossomConfig { max_blob_size: MAX, ..BlossomConfig::default() })
    }

    fn with(config: BlossomConfig) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::allowing_private(dir.path());
        let public_url = url::Url::parse("https://blossom.example.com").ok();
        let blossom = Blossom::open(&config, public_url, false, &storage, &CancellationToken::new()).unwrap();
        Harness { _dir: dir, storage, blossom }
    }

    /// From `203.0.113.1`, unless the request says otherwise.
    async fn send(&self, mut request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        if request.extensions().get::<ConnectInfo<SocketAddr>>().is_none() {
            request.extensions_mut().insert(from("203.0.113.1"));
        }
        let response = self.blossom.router().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        (parts.status, parts.headers, body.collect().await.unwrap().to_bytes().to_vec())
    }

    async fn upload(&self, secret: &str, bytes: &[u8]) -> (StatusCode, HeaderMap, Vec<u8>) {
        let sha = sha_of(bytes);
        let request = Request::put("/upload")
            .header("authorization", auth(secret, "upload", &[&sha]))
            .header("x-sha-256", &sha)
            .header("content-type", "image/jpeg")
            .body(Body::from(bytes.to_vec()))
            .unwrap();
        self.send(request).await
    }

    async fn get(&self, path: &str) -> (StatusCode, HeaderMap, Vec<u8>) {
        self.send(Request::get(path).body(Body::empty()).unwrap()).await
    }

    async fn delete(&self, secret: &str, sha: &str) -> StatusCode {
        let request = Request::delete(format!("/{sha}")).header("authorization", auth(secret, "delete", &[sha])).body(Body::empty()).unwrap();
        self.send(request).await.0
    }

    fn tmp_is_empty(&self) -> bool {
        std::fs::read_dir(self.storage.root().join("blossom/blobs/tmp")).map_or(true, |mut dir| dir.next().is_none())
    }
}

fn from(address: &str) -> ConnectInfo<SocketAddr> {
    ConnectInfo(SocketAddr::new(address.parse().unwrap(), 4000))
}

fn upload_request(secret: &str, bytes: &[u8]) -> Request<Body> {
    let sha = sha_of(bytes);
    Request::put("/upload")
        .header("authorization", auth(secret, "upload", &[&sha]))
        .header("x-sha-256", &sha)
        .body(Body::from(bytes.to_vec()))
        .unwrap()
}

fn auth(secret: &str, verb: &str, x: &[&str]) -> http::HeaderValue {
    let expires = (now() + 60).to_string();
    let expiration = ["expiration", expires.as_str()];
    let t = ["t", verb];
    let mut tags: Vec<&[&str]> = vec![&expiration, &t];
    let xs: Vec<[&str; 2]> = x.iter().map(|x| ["x", *x]).collect();
    tags.extend(xs.iter().map(|x| &x[..]));
    header(&token(secret, now() - 1, &tags))
}

fn sha_of(bytes: &[u8]) -> String {
    BlobHash::of(bytes).to_string()
}

fn ciphertext(seed: u64, n: usize) -> Vec<u8> {
    let mut bytes = vec![0; n];
    StdRng::seed_from_u64(seed).fill_bytes(&mut bytes);
    bytes
}

fn reason(headers: &HeaderMap) -> &str {
    headers.get("x-reason").and_then(|v| v.to_str().ok()).unwrap_or("")
}

#[tokio::test]
async fn uploads_and_serves_ciphertext_as_binary() {
    let harness = Harness::new();
    let blob = ciphertext(1, 5000);
    let sha = sha_of(&blob);

    let (status, headers, body) = harness.upload(ALICE, &blob).await;
    assert_eq!(status, StatusCode::CREATED, "{}", reason(&headers));
    assert_eq!(headers["access-control-allow-origin"], "*");
    let descriptor: Descriptor = serde_json::from_slice(&body).unwrap();
    assert_eq!(descriptor.url, format!("https://blossom.example.com/{sha}.bin"));
    assert_eq!(descriptor.sha256, sha);
    assert_eq!(descriptor.size, 5000);
    // The declared image/jpeg is neither kept nor repeated.
    assert_eq!(descriptor.kind, "application/octet-stream");
    assert_eq!(descriptor.uploaded % 86_400, 0);

    // Again, by someone else: already there.
    assert_eq!(harness.upload(BOB, &blob).await.0, StatusCode::OK);

    // Whatever extension is asked for, it's served as bytes.
    let (status, headers, body) = harness.get(&format!("/{sha}.png")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, blob);
    assert_eq!(headers["content-type"], "application/octet-stream");
    assert_eq!(headers["content-disposition"], "attachment");
    assert_eq!(headers["x-content-type-options"], "nosniff");
    assert_eq!(headers["content-security-policy"], BLOB_CSP);
    assert_eq!(headers["content-length"], "5000");

    let (status, headers, body) = harness.send(Request::head(format!("/{sha}")).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-length"], "5000");
    assert_eq!(headers["accept-ranges"], "bytes");
    assert!(body.is_empty());

    let (status, headers, body) = harness.send(Request::get(format!("/{sha}")).header("range", "bytes=10-19").body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(headers["content-range"], "bytes 10-19/5000");
    assert_eq!(body, &blob[10..20]);

    let etag = headers["etag"].clone();
    let (status, _, _) = harness.send(Request::get(format!("/{sha}")).header("if-none-match", etag).body(Body::empty()).unwrap()).await;
    assert_eq!(status, StatusCode::NOT_MODIFIED);
}

#[tokio::test]
async fn refuses_what_isnt_encrypted() {
    let harness = Harness::new();
    let mut png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR".to_vec();
    png.extend(ciphertext(2, 5000));
    let text = "Dear diary, today I uploaded a plaintext file. ".repeat(50);

    for plaintext in [png.as_slice(), text.as_bytes(), &[0u8; 4000]] {
        let (status, headers, _) = harness.upload(ALICE, plaintext).await;
        assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert!(reason(&headers).starts_with("Only encrypted blobs are accepted"), "{}", reason(&headers));
        assert_eq!(harness.get(&format!("/{}", sha_of(plaintext))).await.0, StatusCode::NOT_FOUND);
    }
    assert!(harness.tmp_is_empty());
}

#[tokio::test]
async fn requires_a_matching_token() {
    let harness = Harness::new();
    let blob = ciphertext(3, 3000);
    let sha = sha_of(&blob);
    let put = || Request::put("/upload").header("x-sha-256", &sha);

    let (status, _, _) = harness.send(put().body(Body::from(blob.clone())).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A token for some other blob.
    let other = sha_of(b"other");
    let (status, headers, _) = harness.send(put().header("authorization", auth(ALICE, "upload", &[&other])).body(Body::from(blob.clone())).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(reason(&headers).contains("x tag"));

    // A delete token.
    let (status, _, _) = harness.send(put().header("authorization", auth(ALICE, "delete", &[&sha])).body(Body::from(blob.clone())).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Scoped to another server.
    let expires = (now() + 60).to_string();
    let scoped = header(&token(ALICE, now(), &[&["t", "upload"], &["expiration", &expires], &["x", &sha], &["server", "elsewhere.example.com"]]));
    let (status, _, _) = harness.send(put().header("authorization", scoped).body(Body::from(blob.clone())).unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // No X-SHA-256: checked against the body once it's in.
    let request = |x: &str| Request::put("/upload").header("authorization", auth(ALICE, "upload", &[x])).body(Body::from(blob.clone())).unwrap();
    assert_eq!(harness.send(request(&other)).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(harness.send(request(&sha)).await.0, StatusCode::CREATED);
    assert!(harness.tmp_is_empty());
}

#[tokio::test]
async fn refuses_mismatched_and_oversized_bodies() {
    let harness = Harness::new();
    let blob = ciphertext(4, 3000);
    let claimed = sha_of(b"something else");
    let request = Request::put("/upload")
        .header("authorization", auth(ALICE, "upload", &[&claimed]))
        .header("x-sha-256", &claimed)
        .body(Body::from(blob.clone()))
        .unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::CONFLICT);

    let big = ciphertext(5, MAX as usize + 1);
    assert_eq!(harness.upload(ALICE, &big).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    // Without a Content-Length to give it away, it's caught mid-stream.
    let sha = sha_of(&big);
    let stream = futures_util::stream::iter(big.chunks(64 * 1024).map(|c| Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(c))).collect::<Vec<_>>());
    let request = Request::put("/upload")
        .header("authorization", auth(ALICE, "upload", &[&sha]))
        .header("x-sha-256", &sha)
        .body(Body::from_stream(stream))
        .unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::PAYLOAD_TOO_LARGE);

    let request = Request::put("/upload").header("authorization", auth(ALICE, "upload", &[])).header("x-sha-256", "nope").body(Body::empty()).unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::BAD_REQUEST);
    assert!(harness.tmp_is_empty());
}

#[tokio::test]
async fn answers_upload_preflights() {
    let harness = Harness::new();
    let sha = sha_of(b"x");
    let head = |headers: &[(&str, &str)]| {
        let mut request = Request::head("/upload");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(Body::empty()).unwrap()
    };

    // No token needed, and the declared type doesn't matter.
    assert_eq!(harness.send(head(&[("x-content-length", "5000"), ("x-content-type", "image/jpeg")])).await.0, StatusCode::OK);
    assert_eq!(harness.send(head(&[("x-sha-256", &sha), ("x-content-length", "5000")])).await.0, StatusCode::OK);
    assert_eq!(harness.send(head(&[])).await.0, StatusCode::LENGTH_REQUIRED);
    assert_eq!(harness.send(head(&[("x-content-length", "lots")])).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(harness.send(head(&[("x-content-length", &(MAX + 1).to_string())])).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(harness.send(head(&[("x-content-length", "3")])).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(harness.send(head(&[("x-sha-256", "nope"), ("x-content-length", "5000")])).await.0, StatusCode::BAD_REQUEST);

    // A token, if sent, must be good.
    let good = auth(ALICE, "upload", &[&sha]);
    let wrong = auth(ALICE, "upload", &[&sha_of(b"y")]);
    let good = good.to_str().unwrap();
    let wrong = wrong.to_str().unwrap();
    assert_eq!(harness.send(head(&[("authorization", good), ("x-sha-256", &sha), ("x-content-length", "5000")])).await.0, StatusCode::OK);
    assert_eq!(harness.send(head(&[("authorization", wrong), ("x-sha-256", &sha), ("x-content-length", "5000")])).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn deletes_with_the_last_owner() {
    let harness = Harness::new();
    let blob = ciphertext(6, 4000);
    let sha = sha_of(&blob);
    harness.upload(ALICE, &blob).await;
    harness.upload(BOB, &blob).await;
    let path = harness.storage.root().join(format!("blossom/blobs/{}/{}/{sha}", &sha[..2], &sha[2..4]));
    assert!(path.exists());

    // Only an owner, with a token naming the blob.
    let stranger = "0000000000000000000000000000000000000000000000000000000000000003";
    assert_eq!(harness.delete(stranger, &sha).await, StatusCode::NOT_FOUND);
    let request = Request::delete(format!("/{sha}")).header("authorization", auth(ALICE, "delete", &[])).body(Body::empty()).unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::UNAUTHORIZED);
    let request = Request::delete(format!("/{sha}")).header("authorization", auth(ALICE, "upload", &[&sha])).body(Body::empty()).unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::UNAUTHORIZED);

    assert_eq!(harness.delete(ALICE, &sha).await, StatusCode::NO_CONTENT);
    assert_eq!(harness.get(&format!("/{sha}")).await.0, StatusCode::OK);
    assert_eq!(harness.delete(ALICE, &sha).await, StatusCode::NOT_FOUND);

    assert_eq!(harness.delete(BOB, &sha).await, StatusCode::NO_CONTENT);
    assert_eq!(harness.get(&format!("/{sha}")).await.0, StatusCode::NOT_FOUND);
    assert!(!path.exists());

    // And it can come back.
    assert_eq!(harness.upload(BOB, &blob).await.0, StatusCode::CREATED);
}

/// A server elsewhere, holding blobs by hash.
async fn origin(blobs: Vec<Vec<u8>>) -> String {
    use std::collections::HashMap;

    let blobs: HashMap<String, Vec<u8>> = blobs.into_iter().map(|blob| (sha_of(&blob), blob)).collect();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = Router::new().fallback(move |request: Request<Body>| {
        let name = request.uri().path().trim_start_matches('/').split('.').next().unwrap_or("").to_string();
        let found = blobs.get(&name).cloned();
        async move {
            match found {
                Some(bytes) => Response::builder().header("content-type", "image/png").body(Body::from(bytes)).unwrap(),
                None => Response::builder().status(404).body(Body::empty()).unwrap(),
            }
        }
    });
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    format!("http://{address}")
}

#[tokio::test]
async fn mirrors_under_the_same_rules() {
    let harness = Harness::new();
    let blob = ciphertext(7, 6000);
    let sha = sha_of(&blob);
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend(ciphertext(8, 6000));
    let png_sha = sha_of(&png);
    let elsewhere = origin(vec![blob.clone(), png.clone()]).await;

    let mirror = |url: String, x: &str| {
        Request::put("/mirror")
            .header("authorization", auth(ALICE, "upload", &[x]))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({ "url": url }).to_string()))
            .unwrap()
    };

    let (status, headers, body) = harness.send(mirror(format!("{elsewhere}/{sha}.jpg"), &sha)).await;
    assert_eq!(status, StatusCode::CREATED, "{}", reason(&headers));
    let descriptor: Descriptor = serde_json::from_slice(&body).unwrap();
    assert_eq!(descriptor.kind, "application/octet-stream");
    assert_eq!(harness.get(&format!("/{sha}")).await.2, blob);
    // Again: nothing fetched, the same blob described.
    assert_eq!(harness.send(mirror(format!("{elsewhere}/{sha}"), &sha)).await.0, StatusCode::OK);

    let (status, headers, _) = harness.send(mirror(format!("{elsewhere}/{png_sha}.png"), &png_sha)).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert!(reason(&headers).contains("PNG"));
    assert_eq!(harness.get(&format!("/{png_sha}")).await.0, StatusCode::NOT_FOUND);

    // Not covered by the token, not at the origin, not a blob URL.
    assert_eq!(harness.send(mirror(format!("{elsewhere}/{sha}"), &png_sha)).await.0, StatusCode::UNAUTHORIZED);
    let missing = sha_of(b"missing");
    assert_eq!(harness.send(mirror(format!("{elsewhere}/{missing}"), &missing)).await.0, StatusCode::BAD_GATEWAY);
    assert_eq!(harness.send(mirror(format!("{elsewhere}/nothing"), &sha)).await.0, StatusCode::BAD_REQUEST);
    assert!(harness.tmp_is_empty());
}

#[tokio::test]
async fn limits_each_addresss_uploads() {
    let harness = Harness::with(BlossomConfig { max_blob_size: MAX, uploads_per_minute: 2, ..BlossomConfig::default() });
    assert_eq!(harness.upload(ALICE, &ciphertext(10, 3000)).await.0, StatusCode::CREATED);
    // Refused or not, an attempt counts.
    assert_eq!(harness.send(Request::put("/upload").body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    let (status, headers, _) = harness.upload(ALICE, &ciphertext(11, 3000)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reason(&headers), "Too many uploads; try again later.");
    let retry_after: u64 = headers["retry-after"].to_str().unwrap().parse().unwrap();
    assert!((1..=60).contains(&retry_after), "{retry_after}");
    // Mirrors share the count.
    let mirror = Request::put("/mirror").header("authorization", auth(ALICE, "upload", &[])).body(Body::from("{}")).unwrap();
    assert_eq!(harness.send(mirror).await.0, StatusCode::TOO_MANY_REQUESTS);

    // Others aren't charged for it; one IPv6 /64 is one client.
    let mut request = upload_request(BOB, &ciphertext(12, 3000));
    request.extensions_mut().insert(from("2001:db8::1"));
    assert_eq!(harness.send(request).await.0, StatusCode::CREATED);
    for n in [13, 14] {
        let mut request = upload_request(BOB, &ciphertext(n, 3000));
        request.extensions_mut().insert(from("2001:db8::2"));
        let expected = if n == 13 { StatusCode::CREATED } else { StatusCode::TOO_MANY_REQUESTS };
        assert_eq!(harness.send(request).await.0, expected);
    }

    // Reads, deletes, and preflights aren't limited.
    assert_eq!(harness.get(&format!("/{}", sha_of(&ciphertext(10, 3000)))).await.0, StatusCode::OK);
    let head = Request::head("/upload").header("x-content-length", "5000").body(Body::empty()).unwrap();
    assert_eq!(harness.send(head).await.0, StatusCode::OK);
    assert_eq!(harness.delete(ALICE, &sha_of(&ciphertext(10, 3000))).await, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn limits_each_addresss_bytes() {
    let harness = Harness::with(BlossomConfig { max_blob_size: 10_000, upload_bytes_per_hour: 10_000, ..BlossomConfig::default() });
    let declared = |n, size| {
        let mut request = upload_request(ALICE, &ciphertext(n, size));
        request.headers_mut().insert("content-length", size.into());
        request
    };
    assert_eq!(harness.send(declared(20, 6000)).await.0, StatusCode::CREATED);
    // One that would go over is refused before it's read.
    let (status, headers, _) = harness.send(declared(21, 6000)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reason(&headers), "Too many bytes uploaded; try again later.");
    assert!(headers.contains_key("retry-after"));
    // One that fits isn't.
    assert_eq!(harness.send(declared(22, 4000)).await.0, StatusCode::CREATED);

    // Without a Content-Length, it's charged once it's in; then nothing more.
    let harness = Harness::with(BlossomConfig { max_blob_size: 10_000, upload_bytes_per_hour: 10_000, ..BlossomConfig::default() });
    for (n, expected) in [(23, StatusCode::CREATED), (24, StatusCode::CREATED), (25, StatusCode::TOO_MANY_REQUESTS)] {
        let blob = ciphertext(n, 6000);
        let sha = sha_of(&blob);
        let stream = futures_util::stream::iter([Ok::<_, std::io::Error>(bytes::Bytes::from(blob))]);
        let request = Request::put("/upload").header("authorization", auth(ALICE, "upload", &[&sha])).body(Body::from_stream(stream)).unwrap();
        assert_eq!(harness.send(request).await.0, expected, "{n}");
    }
}

#[tokio::test]
async fn refuses_an_upload_from_no_address() {
    let harness = Harness::new();
    let response = harness.blossom.router().oneshot(upload_request(ALICE, &ciphertext(30, 3000))).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn serves_only_its_own_blobs() {
    let harness = Harness::new();
    // A file of the site's, in the shared store, is not the Blossom server's.
    let page = b"<!doctype html><title>site</title>";
    harness.storage.blobs.put(BlobHash::of(page), page).unwrap();
    assert_eq!(harness.get(&format!("/{}", sha_of(page))).await.0, StatusCode::NOT_FOUND);

    assert_eq!(harness.get("/not-a-hash").await.0, StatusCode::NOT_FOUND);
    assert_eq!(harness.get(&format!("/{}", "ab".repeat(32))).await.0, StatusCode::NOT_FOUND);
    let (status, headers, _) = harness.get(&format!("/list/{}", "ab".repeat(32))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(headers["access-control-allow-origin"], "*");
}

#[tokio::test]
async fn answers_cors_preflights() {
    let harness = Harness::new();
    let request = Request::options("/upload")
        .header("origin", "https://armada.example")
        .header("access-control-request-method", "PUT")
        .header("access-control-request-headers", "authorization, x-sha-256")
        .body(Body::empty())
        .unwrap();
    let (status, headers, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(headers["access-control-allow-origin"], "*");
    assert_eq!(headers["access-control-allow-headers"], "Authorization, *");
    assert_eq!(headers["access-control-allow-methods"], "GET, HEAD, PUT, DELETE");
    assert_eq!(headers["access-control-max-age"], "86400");
}

#[test]
fn parses_blob_paths() {
    let sha = "ab".repeat(32);
    assert!(blob_path(&format!("/{sha}")).is_some());
    assert!(blob_path(&format!("/{sha}.pdf")).is_some());
    assert!(blob_path(&format!("/{sha}x")).is_none());
    assert!(blob_path(&format!("/a/{sha}")).is_none());
    assert!(blob_url(&format!("https://cdn.example.com/files/{sha}.png")).is_some());
    assert!(blob_url("https://cdn.example.com/").is_none());
}

#[tokio::test]
async fn blob_urls_name_a_public_host_over_https() {
    let dir = tempfile::tempdir().unwrap();
    let storage = Storage::allowing_private(dir.path());
    let config = BlossomConfig { max_blob_size: MAX, ..BlossomConfig::default() };
    let blossom = Blossom::open(&config, None, false, &storage, &CancellationToken::new()).unwrap();
    let blob = ciphertext(9, 5000);
    let sha = sha_of(&blob);
    for (host, base) in [("armada.example.org", "https://armada.example.org"), ("localhost:8080", "http://localhost:8080")] {
        let mut request = upload_request(ALICE, &blob);
        request.headers_mut().insert("host", host.parse().unwrap());
        request.extensions_mut().insert(from("203.0.113.1"));
        let response = blossom.router().oneshot(request).await.unwrap();
        assert!(response.status().is_success(), "{host}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let descriptor: Descriptor = serde_json::from_slice(&body).unwrap();
        assert_eq!(descriptor.url, format!("{base}/{sha}.bin"));
    }
}

/// Bytes received count against the hour's budget whether or not the blob
/// is kept: refusing a blob at its last byte mustn't make it free.
#[tokio::test]
async fn charges_uploads_that_fail() {
    let harness = Harness::with(BlossomConfig { max_blob_size: 10_000, upload_bytes_per_hour: 10_000, ..BlossomConfig::default() });
    for n in [40, 41] {
        let blob = ciphertext(n, 4500);
        // A hash it doesn't have.
        let wrong = sha_of(&ciphertext(n + 100, 10));
        let request = Request::put("/upload").header("authorization", auth(ALICE, "upload", &[&wrong])).header("x-sha-256", &wrong).body(Body::from(blob)).unwrap();
        assert_eq!(harness.send(request).await.0, StatusCode::CONFLICT);
    }
    let blob = ciphertext(42, 4500);
    let mut request = upload_request(ALICE, &blob);
    request.headers_mut().insert("content-length", http::HeaderValue::from_static("4500"));
    let (status, headers, _) = harness.send(request).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(reason(&headers), "Too many bytes uploaded; try again later.");
}

/// A declared length is held against the budget while the upload runs,
/// and what it didn't send is given back.
#[tokio::test]
async fn reserves_declared_lengths() {
    let harness = Harness::with(BlossomConfig { max_blob_size: 10_000, upload_bytes_per_hour: 10_000, ..BlossomConfig::default() });
    // Says 9,000, sends 3,000, and breaks off.
    let sha = sha_of(&ciphertext(50, 9000));
    let stream = futures_util::stream::iter([Ok(bytes::Bytes::from(ciphertext(50, 3000))), Err(std::io::Error::other("gone"))]);
    let request = Request::put("/upload")
        .header("authorization", auth(ALICE, "upload", &[&sha]))
        .header("x-sha-256", &sha)
        .header("content-length", "9000")
        .body(Body::from_stream(stream))
        .unwrap();
    assert_eq!(harness.send(request).await.0, StatusCode::BAD_REQUEST);
    // The 3,000 it sent count; the 6,000 it didn't don't.
    let mut fits = upload_request(ALICE, &ciphertext(51, 7000));
    fits.headers_mut().insert("content-length", http::HeaderValue::from_static("7000"));
    assert_eq!(harness.send(fits).await.0, StatusCode::CREATED);
    let mut over = upload_request(ALICE, &ciphertext(52, 1000));
    over.headers_mut().insert("content-length", http::HeaderValue::from_static("1000"));
    assert_eq!(harness.send(over).await.0, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn leaves_the_disk_room() {
    let harness = Harness::with(BlossomConfig { max_blob_size: MAX, min_free_space: u64::MAX / 2, ..BlossomConfig::default() });
    let (status, headers, _) = harness.upload(ALICE, &ciphertext(60, 5000)).await;
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(reason(&headers), "This server is out of space for blobs.");
    let harness = Harness::with(BlossomConfig { max_blob_size: MAX, min_free_space: 0, ..BlossomConfig::default() });
    assert_eq!(harness.upload(ALICE, &ciphertext(60, 5000)).await.0, StatusCode::CREATED);
}

#[test]
fn caps_transfers_running_at_once() {
    let transfers = Transfers::new(3, 2);
    let a = transfers.start("a").unwrap();
    let _b = transfers.start("a").unwrap();
    assert!(transfers.start("a").is_none());
    let _c = transfers.start("c").unwrap();
    // In all, too.
    assert!(transfers.start("d").is_none());
    drop(a);
    assert!(transfers.start("a").is_some());
    assert_eq!(transfers.running.lock().len(), 2);
}

#[tokio::test]
async fn rate_limits_deletes() {
    let harness = Harness::new();
    let sha = "ab".repeat(32);
    for _ in 0..DELETES_PER_MINUTE {
        assert_eq!(harness.delete(ALICE, &sha).await, StatusCode::NOT_FOUND);
    }
    assert_eq!(harness.delete(ALICE, &sha).await, StatusCode::TOO_MANY_REQUESTS);
}
