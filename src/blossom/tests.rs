//! The Blossom server end to end, through its router.

use axum::body::Body;
use http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
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
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::allowing_private(dir.path());
        let config = BlossomConfig {
            public_url: Some("https://blossom.example.com".into()),
            max_blob_size: MAX,
            ..BlossomConfig::default()
        };
        let blossom = Blossom::open(&config, &storage).unwrap();
        Harness { _dir: dir, storage, blossom }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
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
    assert_eq!(domain("example.com:8080"), "example.com");
    assert_eq!(domain("[::1]:8080"), "::1");
    assert_eq!(domain("example.com"), "example.com");
}
