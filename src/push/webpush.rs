//! Sending one Web Push message: RFC 8291's `aes128gcm` encryption to the
//! browser's keys, and RFC 8292's VAPID signature with the client's own key.

use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use base64::Engine;
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;

use super::connection::{BASE64URL, Connection};
use crate::net::PublicResolver;

/// The record size every message is sent with, and the size every body is
/// padded to, so its length says nothing about what's in it.
const RECORD_SIZE: usize = 4096;
/// Salt, record size, key id length, and the 65-byte key id.
const HEADER: usize = 16 + 4 + 1 + 65;
const TAG: usize = 16;
/// The most plaintext one message carries: what's left of a record after
/// the header, the tag, and the padding delimiter.
pub const MAX_PLAINTEXT: usize = RECORD_SIZE - HEADER - TAG - 1;

/// Seconds the push service may hold a message for an offline browser.
const TTL: u32 = 86_400;
/// How long a VAPID token is good for. RFC 8292 allows up to a day.
const VAPID_LIFETIME: i64 = 12 * 60 * 60;

/// What came of a delivery.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Sent,
    /// The subscription is gone for good: 404 or 410.
    Gone,
    /// Anything else, which may pass.
    Failed(String),
}

#[derive(Clone)]
pub struct Sender {
    http: reqwest::Client,
    /// The VAPID `sub`: who push services may contact about these messages.
    subject: Arc<str>,
}

impl Sender {
    /// `public_only` connects only to public addresses; only tests turn it
    /// off.
    pub fn new(subject: &str, public_only: bool) -> Sender {
        let mut http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("armada/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(10));
        if public_only {
            // Through a proxy, the proxy would resolve the name, not
            // PublicResolver, and connect wherever it pointed.
            http = http.dns_resolver(Arc::new(PublicResolver)).no_proxy();
        }
        Sender { http: http.build().expect("an HTTP client"), subject: subject.into() }
    }

    pub async fn send(&self, connection: &Connection, plaintext: &[u8], now: i64) -> Outcome {
        let (body, authorization) = match prepare(connection, plaintext, &self.subject, now) {
            Ok(prepared) => prepared,
            Err(error) => return Outcome::Failed(error),
        };
        let request = self
            .http
            .post(&connection.endpoint)
            .header("authorization", authorization)
            .header("ttl", TTL)
            .header("urgency", "high")
            .header("content-encoding", "aes128gcm")
            .header("content-type", "application/octet-stream")
            .body(body);
        match request.send().await {
            Ok(response) if response.status().is_success() => Outcome::Sent,
            Ok(response) if matches!(response.status().as_u16(), 404 | 410) => Outcome::Gone,
            Ok(response) => Outcome::Failed(format!("HTTP {}", response.status())),
            Err(error) => Outcome::Failed(error.to_string()),
        }
    }
}

/// The encrypted body and the `Authorization` header for one message.
fn prepare(connection: &Connection, plaintext: &[u8], subject: &str, now: i64) -> Result<(Vec<u8>, String), String> {
    let decode = |value: &str| BASE64URL.decode(value).map_err(|error| error.to_string());
    let ua_public = PublicKey::from_sec1_bytes(&decode(&connection.p256dh)?).map_err(|_| "p256dh is not a P-256 key")?;
    let auth: [u8; 16] = decode(&connection.auth)?.try_into().map_err(|_| "auth is not 16 bytes")?;
    let vapid = SecretKey::from_slice(&decode(&connection.vapid_private_key)?).map_err(|_| "vapid_private_key is not a P-256 key")?;
    let audience = url::Url::parse(&connection.endpoint).map_err(|error| error.to_string())?.origin().ascii_serialization();
    let body = encrypt(&ua_public, &auth, plaintext, &random_secret(), &rand::random())?;
    Ok((body, vapid_authorization(&vapid, &audience, subject, now)))
}

fn random_secret() -> SecretKey {
    loop {
        // All but a vanishing fraction of 32-byte strings are valid scalars.
        if let Ok(secret) = SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
            return secret;
        }
    }
}

/// RFC 8291 §3: one `aes128gcm` record, from the ephemeral key `as_secret`,
/// padded to [`RECORD_SIZE`].
fn encrypt(ua_public: &PublicKey, auth: &[u8; 16], plaintext: &[u8], as_secret: &SecretKey, salt: &[u8; 16]) -> Result<Vec<u8>, String> {
    encrypt_padded(ua_public, auth, plaintext, as_secret, salt, RECORD_SIZE)
}

fn encrypt_padded(ua_public: &PublicKey, auth: &[u8; 16], plaintext: &[u8], as_secret: &SecretKey, salt: &[u8; 16], body_size: usize) -> Result<Vec<u8>, String> {
    let record_len = body_size.checked_sub(HEADER + TAG).filter(|len| *len > plaintext.len()).ok_or("the payload is too big for one message")?;
    let ua_bytes = ua_public.to_encoded_point(false);
    let as_bytes = as_secret.public_key().to_encoded_point(false);
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_public.as_affine());

    let mut key_info = b"WebPush: info\0".to_vec();
    key_info.extend_from_slice(ua_bytes.as_bytes());
    key_info.extend_from_slice(as_bytes.as_bytes());
    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes()).expand(&key_info, &mut ikm).expect("32 bytes");
    let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
    let (mut cek, mut nonce) = ([0u8; 16], [0u8; 12]);
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek).expect("16 bytes");
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce).expect("12 bytes");

    // The plaintext, the delimiter of the last record, then zeros.
    let mut record = Vec::with_capacity(record_len);
    record.extend_from_slice(plaintext);
    record.push(2);
    record.resize(record_len, 0);
    let ciphertext = Aes128Gcm::new_from_slice(&cek).expect("16 bytes").encrypt(Nonce::from_slice(&nonce), record.as_slice()).map_err(|_| "could not encrypt")?;

    let mut body = Vec::with_capacity(HEADER + ciphertext.len());
    body.extend_from_slice(salt);
    body.extend_from_slice(&(RECORD_SIZE as u32).to_be_bytes());
    body.push(65);
    body.extend_from_slice(as_bytes.as_bytes());
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// RFC 8292's `vapid t=…, k=…`: an ES256 JWT for the push service's
/// origin, and the key that signed it.
fn vapid_authorization(key: &SecretKey, audience: &str, subject: &str, now: i64) -> String {
    let header = BASE64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
    let claims = BASE64URL.encode(serde_json::json!({"aud": audience, "exp": now + VAPID_LIFETIME, "sub": subject}).to_string());
    let signing_input = format!("{header}.{claims}");
    let signature: Signature = SigningKey::from(key).sign(signing_input.as_bytes());
    let public = key.public_key().to_encoded_point(false);
    format!("vapid t={signing_input}.{}, k={}", BASE64URL.encode(signature.to_bytes()), BASE64URL.encode(public.as_bytes()))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::Verifier;

    /// What the browser does with a body: decrypt it with its own keys.
    pub fn decrypt(ua_secret: &SecretKey, auth: &[u8; 16], body: &[u8]) -> Vec<u8> {
        let salt = &body[..16];
        let record_size = u32::from_be_bytes(body[16..20].try_into().unwrap()) as usize;
        let id_len = body[20] as usize;
        let as_public = PublicKey::from_sec1_bytes(&body[21..21 + id_len]).unwrap();
        let ciphertext = &body[21 + id_len..];
        assert!(ciphertext.len() <= record_size);

        let shared = p256::ecdh::diffie_hellman(ua_secret.to_nonzero_scalar(), as_public.as_affine());
        let mut key_info = b"WebPush: info\0".to_vec();
        key_info.extend_from_slice(ua_secret.public_key().to_encoded_point(false).as_bytes());
        key_info.extend_from_slice(as_public.to_encoded_point(false).as_bytes());
        let mut ikm = [0u8; 32];
        Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes()).expand(&key_info, &mut ikm).unwrap();
        let prk = Hkdf::<Sha256>::new(Some(salt), &ikm);
        let (mut cek, mut nonce) = ([0u8; 16], [0u8; 12]);
        prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek).unwrap();
        prk.expand(b"Content-Encoding: nonce\0", &mut nonce).unwrap();
        let mut record = Aes128Gcm::new_from_slice(&cek).unwrap().decrypt(Nonce::from_slice(&nonce), ciphertext).unwrap();
        let end = record.iter().rposition(|&b| b != 0).unwrap();
        assert_eq!(record[end], 2, "the last record's delimiter");
        record.truncate(end);
        record
    }

    /// RFC 8291's Appendix A.
    #[test]
    fn matches_the_rfc_example() {
        let decode = |value: &str| BASE64URL.decode(value).unwrap();
        let ua_public = PublicKey::from_sec1_bytes(&decode("BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4")).unwrap();
        let auth: [u8; 16] = decode("BTBZMqHH6r4Tts7J_aSIgg").try_into().unwrap();
        let as_secret = SecretKey::from_slice(&decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")).unwrap();
        let salt: [u8; 16] = decode("DGv6ra1nlYgDCS1FRnbzlw").try_into().unwrap();
        let plaintext = b"When I grow up, I want to be a watermelon";
        // The example pads nothing: one record just big enough.
        let body = encrypt_padded(&ua_public, &auth, plaintext, &as_secret, &salt, HEADER + plaintext.len() + 1 + TAG).unwrap();
        assert_eq!(
            BASE64URL.encode(body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
        );
        let ua_secret = SecretKey::from_slice(&decode("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94")).unwrap();
        assert_eq!(ua_secret.public_key(), ua_public);
    }

    #[test]
    fn pads_every_message_to_one_size() {
        let ua_secret = random_secret();
        let auth = [3; 16];
        for plaintext in [&b"hi"[..], &[b'x'; MAX_PLAINTEXT]] {
            let body = encrypt(&ua_secret.public_key(), &auth, plaintext, &random_secret(), &rand::random()).unwrap();
            assert_eq!(body.len(), RECORD_SIZE);
            assert_eq!(decrypt(&ua_secret, &auth, &body), plaintext);
        }
        assert!(encrypt(&ua_secret.public_key(), &auth, &[b'x'; MAX_PLAINTEXT + 1], &random_secret(), &rand::random()).is_err());
    }

    #[test]
    fn signs_vapid_tokens() {
        let key = SecretKey::from_slice(&[9; 32]).unwrap();
        let header = vapid_authorization(&key, "https://push.example.com", "https://armada.example.com", 1000);
        let (token, k) = header.strip_prefix("vapid t=").unwrap().split_once(", k=").unwrap();
        assert_eq!(BASE64URL.decode(k).unwrap(), key.public_key().to_encoded_point(false).as_bytes());
        let (input, signature) = token.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&BASE64URL.decode(signature).unwrap()).unwrap();
        VerifyingKey::from(key.public_key()).verify(input.as_bytes(), &signature).unwrap();
        let claims: serde_json::Value = serde_json::from_slice(&BASE64URL.decode(input.split_once('.').unwrap().1).unwrap()).unwrap();
        assert_eq!(claims, serde_json::json!({"aud": "https://push.example.com", "exp": 1000 + VAPID_LIFETIME, "sub": "https://armada.example.com"}));
    }
}
