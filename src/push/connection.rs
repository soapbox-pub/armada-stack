//! How a client is reached: `create`'s params. Only Web Push here; APNs
//! and FCM, which nostr-push2 also speaks, are refused as a service without
//! them configured refuses them.

use std::net::IpAddr;

use base64::Engine;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Base64url as browsers write it, padded or not, and forgiving of
/// trailing bits as nostr-push2's decoder is.
pub const BASE64URL: GeneralPurpose =
    GeneralPurpose::new(&URL_SAFE, GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true));

const MAX_ENDPOINT: usize = 2048;

/// A Web Push subscription, and the VAPID key the client subscribed with:
/// it's the client's own, so there's none to configure here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connection {
    /// `PushSubscription.endpoint`.
    pub endpoint: String,
    /// `PushSubscription.toJSON().keys`, base64url without padding.
    pub p256dh: String,
    pub auth: String,
    /// The private scalar (JWK `d`) of the P-256 key the client passed as
    /// `applicationServerKey`, base64url without padding.
    pub vapid_private_key: String,
}

impl Connection {
    /// Check `create`'s params. Errors are the message to hand back.
    /// `public_only` refuses endpoints on private networks; only tests
    /// turn it off.
    pub fn parse(params: &Value, public_only: bool) -> Result<Connection, String> {
        let Some(params) = params.as_object() else { return Err("params: Invalid input: expected object".into()) };
        match params.get("method").and_then(Value::as_str) {
            Some("web") => {}
            Some(method @ ("apn" | "fcm")) => return Err(format!("method {method} is not available on this service")),
            _ => return Err("method: Invalid input: expected \"web\", \"apn\" or \"fcm\"".into()),
        }
        let string = |field: &str| params.get(field).and_then(Value::as_str).ok_or_else(|| format!("{field}: Invalid input: expected string"));
        let endpoint = string("endpoint")?;
        if endpoint.len() > MAX_ENDPOINT {
            return Err(format!("endpoint: Too big: expected string to have <={MAX_ENDPOINT} characters"));
        }
        let key = |field: &str, bytes: usize| {
            let value = string(field)?.trim_end_matches('=');
            match BASE64URL.decode(value) {
                Ok(decoded) if decoded.len() == bytes && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') => Ok((value.to_string(), decoded)),
                _ => Err(format!("{field}: {field} must be {bytes} bytes of base64url")),
            }
        };
        let (p256dh, p256dh_bytes) = key("p256dh", 65)?;
        let (auth, _) = key("auth", 16)?;
        let (vapid_private_key, vapid_bytes) = key("vapid_private_key", 32)?;
        if p256::PublicKey::from_sec1_bytes(&p256dh_bytes).is_err() {
            return Err("p256dh: p256dh must be a P-256 public key".into());
        }
        if p256::SecretKey::from_slice(&vapid_bytes).is_err() {
            return Err("vapid_private_key: vapid_private_key must be a P-256 private key".into());
        }
        if public_only {
            check_endpoint(endpoint)?;
        }
        Ok(Connection { endpoint: endpoint.to_string(), p256dh, auth, vapid_private_key })
    }
}

/// Keep the service from being pointed at its own network, as far as the
/// URL alone says. Names are checked again when they're resolved, by the
/// client [deliveries](super::webpush) go through.
fn check_endpoint(endpoint: &str) -> Result<(), String> {
    let url = url::Url::parse(endpoint).map_err(|_| "endpoint must be a URL")?;
    if url.scheme() != "https" {
        return Err("endpoint must use https://".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("endpoint must not carry credentials".into());
    }
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") {
        return Err("endpoint must not be a loopback address".into());
    }
    if host == "metadata.google.internal" {
        return Err("endpoint must not be a metadata service".into());
    }
    if let Ok(ip) = host.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>()
        && !crate::net::is_public_address(ip)
    {
        return Err("endpoint must not be a private address".into());
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use serde_json::json;

    /// A client's keys: its subscription's and its VAPID key.
    pub fn web(endpoint: &str) -> Value {
        let p256dh = p256::SecretKey::from_slice(&[7; 32]).unwrap().public_key();
        let p256dh = p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&p256dh, false);
        json!({
            "method": "web",
            "endpoint": endpoint,
            "p256dh": BASE64URL.encode(p256dh.as_bytes()),
            "auth": format!("{}==", BASE64URL.encode([1; 16])),
            "vapid_private_key": BASE64URL.encode([9; 32]),
        })
    }

    #[test]
    fn takes_web_push_only() {
        let connection = Connection::parse(&web("https://push.example.com/abc"), true).unwrap();
        assert_eq!(connection.endpoint, "https://push.example.com/abc");
        // Padding is dropped.
        assert_eq!(connection.auth, BASE64URL.encode([1; 16]));

        assert_eq!(Connection::parse(&json!({"method": "apn", "token": "x"}), true).unwrap_err(), "method apn is not available on this service");
        assert_eq!(Connection::parse(&json!({"method": "fcm"}), true).unwrap_err(), "method fcm is not available on this service");
        assert!(Connection::parse(&json!({"method": "mail"}), true).unwrap_err().starts_with("method: "));
        assert!(Connection::parse(&json!(null), true).unwrap_err().starts_with("params: "));
    }

    #[test]
    fn checks_keys_and_endpoints() {
        let with = |field: &str, value: Value| {
            let mut params = web("https://push.example.com/abc");
            params[field] = value;
            Connection::parse(&params, true).unwrap_err()
        };
        assert_eq!(with("p256dh", json!("AAAA")), "p256dh: p256dh must be 65 bytes of base64url");
        assert_eq!(with("p256dh", json!(BASE64URL.encode([4; 65]))), "p256dh: p256dh must be a P-256 public key");
        assert_eq!(with("auth", json!(BASE64URL.encode([1; 17]))), "auth: auth must be 16 bytes of base64url");
        assert_eq!(with("auth", json!("AQEBAQEBAQEBAQEBAQEB+Q")), "auth: auth must be 16 bytes of base64url");
        assert_eq!(with("vapid_private_key", json!(BASE64URL.encode([0; 32]))), "vapid_private_key: vapid_private_key must be a P-256 private key");
        assert_eq!(with("vapid_private_key", json!(5)), "vapid_private_key: Invalid input: expected string");
        assert!(with("endpoint", json!(format!("https://x.example/{}", "a".repeat(2048)))).starts_with("endpoint: Too big"));
        for (endpoint, error) in [
            ("not a url", "endpoint must be a URL"),
            ("http://push.example.com/", "endpoint must use https://"),
            ("https://u:p@push.example.com/", "endpoint must not carry credentials"),
            ("https://localhost/", "endpoint must not be a loopback address"),
            ("https://a.localhost/", "endpoint must not be a loopback address"),
            ("https://127.0.0.1/", "endpoint must not be a private address"),
            ("https://192.168.1.1:8443/", "endpoint must not be a private address"),
            ("https://[::1]/", "endpoint must not be a private address"),
            ("https://[fd00::1]/", "endpoint must not be a private address"),
            ("https://metadata.google.internal/", "endpoint must not be a metadata service"),
        ] {
            assert_eq!(with("endpoint", json!(endpoint)), error, "{endpoint}");
        }
        // Tests' own servers are on loopback.
        assert!(Connection::parse(&web("http://127.0.0.1:1234/"), false).is_ok());
    }
}
