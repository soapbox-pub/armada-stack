//! Token grants (CORD-07 §2): proof that a caller holds a Channel's key.
//!
//! A client self-signs a NIP-98-style kind 27235 event with `voice_key.sk`,
//! so `event.pubkey` *is* the room name. There is no lookup, no membership
//! check, and no Community knowledge: the signature is the whole
//! authorization.
//!
//! §2 lists five conditions for accepting one, and this implements them.
//! A `nonce` tag isn't among them. It's the client's obligation — every
//! member of a Channel signs with the same key, so two joining in the same
//! second would otherwise sign identical grants and the second would be
//! refused as a replay — and requiring it here would lock out every client
//! that predates it.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use http::StatusCode;

use crate::nostr::Event;
use crate::nostr::event::is_hex64;

/// §2: a grant is a NIP-98-style HTTP auth event.
pub const KIND: i64 = 27235;

/// `btoa`'s alphabet, padded or not.
const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// Why a grant was refused, and the status that says so.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub status: StatusCode,
    pub reason: &'static str,
}

fn unauthorized(reason: &'static str) -> Refusal {
    Refusal { status: StatusCode::UNAUTHORIZED, reason }
}

fn bad_request(reason: &'static str) -> Refusal {
    Refusal { status: StatusCode::BAD_REQUEST, reason }
}

/// The grant in `Authorization: Concord <base64(event)>`. The scheme is
/// case-insensitive (RFC 7235); nothing else is forgiven.
pub fn parse(header: Option<&http::HeaderValue>) -> Result<Event, Refusal> {
    let header = header.ok_or(unauthorized("missing Authorization header"))?;
    let header = header.to_str().map_err(|_| unauthorized("Authorization must use the Concord scheme"))?.trim();
    let token = header
        .split_once(char::is_whitespace)
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("concord"))
        .map(|(_, token)| token.trim())
        .filter(|token| !token.is_empty())
        .ok_or(unauthorized("Authorization must use the Concord scheme"))?;
    let json = STANDARD.decode(token).map_err(|_| bad_request("grant is not valid base64"))?;
    // Typed, so tags that aren't arrays of strings, and a created_at that
    // isn't a whole number, are refused here as malformed rather than
    // reaching the hash.
    let event: Event = serde_json::from_slice(&json).map_err(|_| bad_request("grant is not a well-formed event"))?;
    if event.created_at < 0 {
        return Err(bad_request("grant created_at must be a whole number of seconds"));
    }
    Ok(event)
}

/// What a grant has to match: the request it came with.
pub struct Request<'a> {
    /// The room named in the path.
    pub room: &'a str,
    /// The full public URL of the request, as the client would have built it.
    pub url: &'a str,
    pub method: &'a str,
    pub now: i64,
    pub max_skew: i64,
}

/// Apply §2's conditions to a grant, all but the replay check, which is
/// left to the caller because it changes state.
pub fn verify(event: &Event, request: &Request) -> Result<(), Refusal> {
    if event.kind != KIND {
        return Err(unauthorized("grant must be kind 27235"));
    }
    // The authorization itself: only a holder of the Channel key can derive
    // `voice_key.sk`.
    if event.pubkey != request.room {
        return Err(unauthorized("grant pubkey does not match the room in the path"));
    }
    if event.tag("u") != Some(request.url) {
        return Err(unauthorized("grant `u` tag does not match this request"));
    }
    if !event.tag("method").is_some_and(|method| method.eq_ignore_ascii_case(request.method)) {
        return Err(unauthorized("grant `method` tag does not match this request"));
    }
    if event.created_at.abs_diff(request.now) > request.max_skew.unsigned_abs() {
        return Err(unauthorized("grant timestamp is outside the freshness window"));
    }
    // The replay set keys on the id, so it has to commit to the event.
    if !is_hex64(&event.id) || Event::compute_id(&event.pubkey, event.created_at, event.kind, &event.tags, &event.content) != event.id {
        return Err(unauthorized("grant id does not commit to the event"));
    }
    if !event.verify() {
        return Err(unauthorized("grant signature is invalid"));
    }
    Ok(())
}

/// Ids of grants already used (§2), each remembered for a fixed time — at
/// least twice the freshness window, so none is forgotten while its grant
/// could still be accepted.
///
/// Per process: behind several replicas, a captured grant could be used once
/// at each. It only travels inside TLS, and E2EE leaves a stolen seat worth
/// no more than the call's metadata.
pub struct ReplaySet {
    ttl: Duration,
    max: usize,
    expiry: HashMap<String, Instant>,
    /// Ids in the order they were admitted, which with one fixed TTL is also
    /// the order they expire in.
    order: VecDeque<(String, Instant)>,
}

impl ReplaySet {
    /// `max` bounds memory. Only verified grants reach the set, so filling it
    /// takes a signature per entry; past it, the oldest ids are forgotten
    /// early, which risks no more than the multi-replica case above.
    pub fn new(ttl: Duration, max: usize) -> ReplaySet {
        ReplaySet { ttl, max, expiry: HashMap::new(), order: VecDeque::new() }
    }

    /// Remember `id`, or return false if it's still remembered: a replay.
    pub fn admit(&mut self, id: &str, now: Instant) -> bool {
        while let Some((front, expires)) = self.order.front() {
            if *expires > now {
                break;
            }
            // A stale queue entry for an id since re-admitted leaves the newer one.
            if self.expiry.get(front) == Some(expires) {
                self.expiry.remove(front);
            }
            self.order.pop_front();
        }
        if self.expiry.get(id).is_some_and(|expires| *expires > now) {
            return false;
        }
        let expires = now + self.ttl;
        self.expiry.insert(id.to_string(), expires);
        self.order.push_back((id.to_string(), expires));
        while self.expiry.len() > self.max {
            let Some((front, expires)) = self.order.pop_front() else { break };
            if self.expiry.get(&front) == Some(&expires) {
                self.expiry.remove(&front);
            }
        }
        true
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.expiry.len()
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;
    use crate::nostr::event::public_key;

    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const NOW: i64 = 1_800_000_000;

    fn url(room: &str) -> String {
        format!("https://armada.example.com/.well-known/concord/av/{room}")
    }

    fn grant(created_at: i64, tags: Vec<Vec<String>>) -> Event {
        Event::sign(SECRET, created_at, KIND, tags, "")
    }

    fn tags(room: &str) -> Vec<Vec<String>> {
        vec![vec!["u".into(), url(room)], vec!["method".into(), "GET".into()], vec!["nonce".into(), "ab".repeat(32)]]
    }

    fn check(event: &Event, room: &str) -> Result<(), Refusal> {
        verify(event, &Request { room, url: &url(room), method: "GET", now: NOW, max_skew: 60 })
    }

    fn header(json: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Concord {}", base64::engine::general_purpose::STANDARD.encode(json))).unwrap()
    }

    #[test]
    fn accepts_a_good_grant() {
        let room = public_key(SECRET);
        let event = grant(NOW, tags(&room));
        let parsed = parse(Some(&header(&serde_json::to_string(&event).unwrap()))).unwrap();
        assert_eq!(parsed, event);
        assert_eq!(check(&parsed, &room), Ok(()));
        // Clocks a little off either way.
        assert_eq!(check(&grant(NOW - 60, tags(&room)), &room), Ok(()));
        assert_eq!(check(&grant(NOW + 60, tags(&room)), &room), Ok(()));
        // Without a nonce, as clients that predate it sign them.
        assert_eq!(check(&grant(NOW, tags(&room)[..2].to_vec()), &room), Ok(()));
        // The scheme in any case, the base64 unpadded.
        let unpadded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(serde_json::to_vec(&event).unwrap());
        assert!(parse(Some(&HeaderValue::from_str(&format!("concord {unpadded}")).unwrap())).is_ok());
    }

    #[test]
    fn refuses_bad_grants() {
        let room = public_key(SECRET);
        let reason = |event: &Event| check(event, &room).unwrap_err().reason;

        assert_eq!(reason(&grant(NOW - 61, tags(&room))), "grant timestamp is outside the freshness window");
        assert_eq!(reason(&grant(NOW + 61, tags(&room))), "grant timestamp is outside the freshness window");
        let other = "1".repeat(64);
        assert_eq!(check(&grant(NOW, tags(&room)), &other).unwrap_err().reason, "grant pubkey does not match the room in the path");
        let mut wrong_url = tags(&room);
        wrong_url[0][1] = url(&room).replace("armada.", "evil.");
        assert_eq!(reason(&grant(NOW, wrong_url)), "grant `u` tag does not match this request");
        let mut wrong_method = tags(&room);
        wrong_method[1][1] = "POST".into();
        assert_eq!(reason(&grant(NOW, wrong_method)), "grant `method` tag does not match this request");
        assert_eq!(reason(&Event::sign(SECRET, NOW, 24242, tags(&room), "")), "grant must be kind 27235");

        let mut tampered = grant(NOW, tags(&room));
        tampered.content = "changed".into();
        assert_eq!(reason(&tampered), "grant id does not commit to the event");
        let mut forged = grant(NOW, tags(&room));
        forged.sig = "00".repeat(64);
        assert_eq!(reason(&forged), "grant signature is invalid");
    }

    #[test]
    fn refuses_malformed_headers() {
        let status = |value: Option<&HeaderValue>| parse(value).unwrap_err().status;
        assert_eq!(status(None), StatusCode::UNAUTHORIZED);
        assert_eq!(status(Some(&HeaderValue::from_static("Nostr abc"))), StatusCode::UNAUTHORIZED);
        assert_eq!(status(Some(&HeaderValue::from_static("Concord"))), StatusCode::UNAUTHORIZED);
        assert_eq!(status(Some(&HeaderValue::from_static("Concord !!!"))), StatusCode::BAD_REQUEST);
        assert_eq!(status(Some(&header("[]"))), StatusCode::BAD_REQUEST);

        // Tags that aren't arrays of strings, and timestamps that aren't
        // whole seconds, are malformed, not merely unverified.
        let event = serde_json::to_value(grant(NOW, tags(&public_key(SECRET)))).unwrap();
        for (field, value) in [
            ("tags", serde_json::json!([[1]])),
            ("tags", serde_json::json!([["x", ["y"]]])),
            ("tags", serde_json::json!([null])),
            ("tags", serde_json::json!([{}])),
            ("created_at", serde_json::json!(1.5)),
            ("created_at", serde_json::json!(-1)),
        ] {
            let mut bad = event.clone();
            bad[field] = value;
            assert_eq!(status(Some(&header(&bad.to_string()))), StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[test]
    fn remembers_ids_for_their_window() {
        let start = Instant::now();
        let mut set = ReplaySet::new(Duration::from_secs(240), 1000);
        assert!(set.admit("a", start));
        assert!(!set.admit("a", start + Duration::from_secs(239)));
        assert!(set.admit("b", start + Duration::from_secs(100)));
        // Forgotten once expired, and remembered afresh when seen again.
        assert!(set.admit("a", start + Duration::from_secs(240)));
        assert!(!set.admit("a", start + Duration::from_secs(300)));
        assert!(!set.admit("b", start + Duration::from_secs(300)));
        assert!(set.admit("b", start + Duration::from_secs(340)));
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn holds_the_set_at_its_ceiling() {
        let now = Instant::now();
        let mut set = ReplaySet::new(Duration::from_secs(240), 3);
        for id in ["a", "b", "c", "d"] {
            assert!(set.admit(id, now));
        }
        assert_eq!(set.len(), 3);
        // The oldest went first.
        assert!(set.admit("a", now));
        assert!(!set.admit("d", now));
    }
}
