//! Just enough LiveKit: the access tokens it accepts, and one call to its
//! server API to see that a node is up.
//!
//! A token is a JWT signed with HS256 under the node's API secret, the same
//! one `livekit-server-sdk`'s `AccessToken` makes.

use std::time::Duration;

use anyhow::{Result, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;

use super::fleet::Node;

/// A token for `video`'s grants, signed with the node's credentials.
pub fn token(node: &Node, identity: Option<&str>, video: Value, ttl: u64, now: i64) -> String {
    let mut claims = json!({ "video": video, "iss": node.api_key, "nbf": now, "exp": now + ttl as i64 });
    if let Some(identity) = identity {
        claims["sub"] = identity.into();
    }
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signing_input = format!("{header}.{payload}");
    let mut mac = Hmac::<Sha256>::new_from_slice(node.api_secret.as_bytes()).expect("HMAC takes a key of any length");
    mac.update(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}

/// A seat in `room` for `identity`: join, publish, and subscribe.
pub fn join_token(node: &Node, room: &str, identity: &str, ttl: u64, now: i64) -> String {
    let video = json!({
        "roomJoin": true,
        "room": room,
        "canPublish": true,
        "canSubscribe": true,
        "canPublishData": true,
    });
    token(node, Some(identity), video, ttl, now)
}

/// Ask the node to list a room that doesn't exist. Cheap, and it proves more
/// than that the node is up: a wrong API secret fails here, rather than as
/// a puzzling failure for the clients it was handed to.
pub async fn probe(http: &reqwest::Client, node: &Node, timeout: Duration, now: i64) -> Result<()> {
    let auth = token(node, None, json!({ "roomList": true }), 600, now);
    let response = http
        .post(format!("{}/twirp/livekit.RoomService/ListRooms", node.api_url))
        .bearer_auth(auth)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(r#"{"names":["__armada_av_health__"]}"#)
        .timeout(timeout)
        .send()
        .await?;
    if !response.status().is_success() {
        bail!("{} answered {}", node.api_url, response.status());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_tokens_livekit_accepts() {
        let node = Node { url: "wss://sfu.example.com".into(), api_url: String::new(), api_key: "APIkey".into(), api_secret: "secret".into() };
        let token = join_token(&node, "room", "me", 3600, 1_800_000_000);
        let [header, payload, signature]: [&str; 3] = token.split('.').collect::<Vec<_>>().try_into().unwrap();

        let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
        assert_eq!(claims["iss"], "APIkey");
        assert_eq!(claims["sub"], "me");
        assert_eq!(claims["nbf"], 1_800_000_000);
        assert_eq!(claims["exp"], 1_800_003_600);
        assert_eq!(claims["video"]["room"], "room");
        assert_eq!(claims["video"]["roomJoin"], true);

        let mut mac = Hmac::<Sha256>::new_from_slice(b"secret").unwrap();
        mac.update(format!("{header}.{payload}").as_bytes());
        mac.verify_slice(&URL_SAFE_NO_PAD.decode(signature).unwrap()).unwrap();
    }
}
