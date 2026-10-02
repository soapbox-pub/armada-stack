//! Blossom authorization tokens (BUD-11): kind 24242 events, signed by the
//! user, sent base64-encoded in `Authorization: Nostr <token>`.

use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::{DecodePaddingMode, general_purpose};
use http::HeaderMap;
use http::header::AUTHORIZATION;

use crate::hash::BlobHash;
use crate::nostr::Event;

pub const KIND: i64 = 24242;

/// How far in the future a token's `created_at` may be, for clients whose
/// clocks run a little fast.
const CLOCK_SKEW: i64 = 60;

/// BUD-11 asks for base64url, but clients send standard base64 too
/// (`btoa`), padded or not. Both alphabets are accepted either way.
const URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// A token that passed every check but the blob hash, which only the
/// endpoint knows.
#[derive(Debug)]
pub struct Token {
    pub pubkey: String,
    x: Vec<String>,
}

impl Token {
    /// Whether the token names `sha256` in an `x` tag.
    pub fn covers(&self, sha256: BlobHash) -> bool {
        let hex = sha256.hex();
        self.x.iter().any(|x| x.eq_ignore_ascii_case(hex.as_str()))
    }
}

/// Why a request isn't authorized. Both are a 401.
#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Invalid(String),
}

impl AuthError {
    pub fn reason(&self) -> &str {
        match self {
            AuthError::Missing => "Authorization required.",
            AuthError::Invalid(reason) => reason,
        }
    }
}

fn invalid(reason: impl Into<String>) -> AuthError {
    AuthError::Invalid(reason.into())
}

/// Check a request's token for `verb`. `host` is this server's domain, for
/// tokens scoped to servers with `server` tags; `None` means it's unknown,
/// and a scoped token can't be honored.
pub fn authorize(headers: &HeaderMap, verb: &str, host: Option<&str>, now: i64) -> Result<Token, AuthError> {
    let Some(header) = headers.get(AUTHORIZATION) else {
        return Err(AuthError::Missing);
    };
    let header = header.to_str().map_err(|_| invalid("Malformed Authorization header."))?.trim();
    let (scheme, token) = header.split_once(' ').ok_or_else(|| invalid("Malformed Authorization header."))?;
    if !scheme.eq_ignore_ascii_case("nostr") {
        return Err(invalid("Authorization must use the Nostr scheme."));
    }
    let token = token.trim();
    let json = URL_SAFE
        .decode(token)
        .or_else(|_| STANDARD.decode(token))
        .or_else(|_| general_purpose::STANDARD.decode(token))
        .map_err(|_| invalid("Authorization token is not valid base64."))?;
    let event: Event = serde_json::from_slice(&json).map_err(|_| invalid("Authorization token is not a Nostr event."))?;
    check(&event, verb, host, now)?;
    let x = values(&event, "x").cloned().collect();
    Ok(Token { pubkey: event.pubkey, x })
}

/// The values of every tag named `name`.
fn values<'a>(event: &'a Event, name: &'a str) -> impl Iterator<Item = &'a String> {
    event.tags.iter().filter(move |tag| tag.first().is_some_and(|n| n == name)).filter_map(|tag| tag.get(1))
}

fn check(event: &Event, verb: &str, host: Option<&str>, now: i64) -> Result<(), AuthError> {
    if event.kind != KIND {
        return Err(invalid(format!("Authorization event must be kind {KIND}.")));
    }
    if !event.verify() {
        return Err(invalid("Authorization event has an invalid signature."));
    }
    if event.created_at > now + CLOCK_SKEW {
        return Err(invalid("Authorization event is from the future."));
    }
    let expiration = event.tag("expiration").and_then(|value| value.trim().parse::<i64>().ok());
    match expiration {
        None => return Err(invalid("Authorization event has no expiration.")),
        Some(expiration) if expiration <= now => return Err(invalid("Authorization event has expired.")),
        Some(_) => {}
    }
    if !values(event, "t").any(|t| t == verb) {
        return Err(invalid(format!("Authorization event is not for \"{verb}\".")));
    }
    let mut servers = values(event, "server").peekable();
    if servers.peek().is_some() {
        let ours = host.map(str::to_ascii_lowercase);
        if !servers.any(|server| Some(server.to_ascii_lowercase()) == ours) {
            return Err(invalid("Authorization event is for another server."));
        }
    }
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use http::HeaderValue;

    use super::*;

    pub const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    pub const NOW: i64 = 1_800_000_000;

    /// A signed token, as a header value.
    pub fn header(event: &Event) -> HeaderValue {
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(event).unwrap());
        HeaderValue::from_str(&format!("Nostr {token}")).unwrap()
    }

    pub fn token(secret: &str, created_at: i64, tags: &[&[&str]]) -> Event {
        let tags = tags.iter().map(|tag| tag.iter().map(|s| s.to_string()).collect()).collect();
        Event::sign(secret, created_at, KIND, tags, "Upload photo.jpg")
    }

    fn headers(event: &Event) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, header(event));
        headers
    }

    fn auth(event: &Event, verb: &str, host: Option<&str>) -> Result<Token, AuthError> {
        authorize(&headers(event), verb, host, NOW)
    }

    #[test]
    fn accepts_a_good_token() {
        let sha = BlobHash::of(b"x");
        let expires = (NOW + 60).to_string();
        let event = token(SECRET, NOW - 5, &[&["t", "upload"], &["expiration", &expires], &["x", &sha.to_string()]]);
        let token = auth(&event, "upload", None).unwrap();
        assert_eq!(token.pubkey, crate::nostr::event::public_key(SECRET));
        assert!(token.covers(sha));
        assert!(!token.covers(BlobHash::of(b"y")));

        // Standard base64 with padding, as `btoa` makes it.
        let mut headers = HeaderMap::new();
        let standard = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&event).unwrap());
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("nostr {standard}")).unwrap());
        assert!(authorize(&headers, "upload", None, NOW).is_ok());
    }

    #[test]
    fn refuses_bad_tokens() {
        let expires = (NOW + 60).to_string();
        let good: &[&[&str]] = &[&["t", "upload"], &["expiration", &expires]];
        assert_eq!(authorize(&HeaderMap::new(), "upload", None, NOW).unwrap_err(), AuthError::Missing);

        // Wrong verb.
        assert!(auth(&token(SECRET, NOW, good), "delete", None).is_err());
        // From the future, beyond the allowed skew.
        assert!(auth(&token(SECRET, NOW + 600, good), "upload", None).is_err());
        assert!(auth(&token(SECRET, NOW + 30, good), "upload", None).is_ok());
        // Expired, or no expiration at all.
        let past = (NOW - 1).to_string();
        assert!(auth(&token(SECRET, NOW - 100, &[&["t", "upload"], &["expiration", &past]]), "upload", None).is_err());
        assert!(auth(&token(SECRET, NOW, &[&["t", "upload"]]), "upload", None).is_err());
        // Wrong kind.
        let mut kind = Event::sign(SECRET, NOW, 1, good.iter().map(|t| t.iter().map(|s| s.to_string()).collect()).collect(), "");
        assert!(auth(&kind, "upload", None).is_err());
        // Tampered.
        kind = token(SECRET, NOW, good);
        kind.content = "changed".into();
        assert!(auth(&kind, "upload", None).is_err());

        // Garbage.
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Nostr !!!"));
        assert!(authorize(&headers, "upload", None, NOW).is_err());
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        assert!(authorize(&headers, "upload", None, NOW).is_err());
    }

    #[test]
    fn honors_server_scopes() {
        let expires = (NOW + 60).to_string();
        let scoped = token(SECRET, NOW, &[&["t", "get"], &["expiration", &expires], &["server", "cdn.example.com"]]);
        assert!(auth(&scoped, "get", Some("cdn.example.com")).is_ok());
        assert!(auth(&scoped, "get", Some("CDN.example.com")).is_ok());
        assert!(auth(&scoped, "get", Some("other.example.com")).is_err());
        assert!(auth(&scoped, "get", None).is_err());
    }
}
