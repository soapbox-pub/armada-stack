//! What the relay takes: the kinds Armada uses, each in the shape Armada
//! gives it, and who may read them. Anything else is refused.
//!
//! These checks look at the event alone. Its signature, and what the
//! connection has authenticated as, are checked by [`conn`](super::conn).

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use std::collections::HashSet;

use super::filter::Filter;
use super::nip44;
use super::record::{Element, EventView};
use crate::nostr::Event;
use crate::nostr::event::is_hex64;

pub const DELETION: u16 = 5;
pub const VANISH: u16 = 62;
pub const GIFT_WRAP: u16 = 1059;
pub const EPHEMERAL_GIFT_WRAP: u16 = 21059;
pub const AUTH: u16 = 22242;
pub const NIP46: u16 = 24133;
pub const APP_DATA: u16 = 30078;
const INVITE_BUNDLE: u16 = 33301;

/// Every kind the relay accepts, sorted.
pub const KINDS: &[u16] = &[
    0,
    3,
    DELETION,
    VANISH,
    GIFT_WRAP,
    10000,
    10002,
    10007,
    10009,
    10030,
    10050,
    10063,
    10133,
    10304,
    13303,
    16767,
    EPHEMERAL_GIFT_WRAP,
    NIP46,
    30030,
    APP_DATA,
    30315,
    INVITE_BUNDLE,
    33302,
    36767,
];

/// Seconds ephemeral events are kept, so a client that reconnects within
/// them can catch up.
pub const EPHEMERAL_LIFETIME: u32 = 300;

/// How old an ephemeral event may be when it arrives.
const EPHEMERAL_MAX_AGE: i64 = 60;

/// Each target of a deletion leaves a tombstone for good, so cap them.
const MAX_DELETION_TARGETS: usize = 100;

/// Addressable `d` values are indexed like any tag value.
const MAX_D: usize = 255;

/// The longest any one tag element may be.
const MAX_TAG_VALUE: usize = 4096;

pub fn is_accepted(kind: u16) -> bool {
    KINDS.binary_search(&kind).is_ok()
}

/// Gift wraps belong to their `p` recipient rather than their author: only
/// the recipient may delete one. Concord's stream keys are shared by every
/// member, so an author's deletion could come from anyone in the channel.
pub fn is_gift_wrap(kind: u16) -> bool {
    matches!(kind, GIFT_WRAP | EPHEMERAL_GIFT_WRAP)
}

/// When an event is to be deleted: its NIP-40 expiration, or for an
/// ephemeral one, [`EPHEMERAL_LIFETIME`] from `now` if that's sooner.
pub fn expiration(event: &Event, now: i64) -> Option<u32> {
    let own = super::record::expiration(event);
    let kind = u16::try_from(event.kind).unwrap_or_default();
    if !super::record::is_ephemeral(kind) {
        return own;
    }
    let lifetime = u32::try_from(now).unwrap_or(u32::MAX).saturating_add(EPHEMERAL_LIFETIME);
    Some(own.map_or(lifetime, |own| own.min(lifetime)))
}

/// Who may read an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Anyone,
    /// Connections authenticated as its author or its `p` recipient.
    AuthorOrRecipient,
    /// Connections authenticated as its author.
    Author,
}

pub fn access(kind: u16) -> Access {
    match kind {
        GIFT_WRAP | EPHEMERAL_GIFT_WRAP | NIP46 => Access::AuthorOrRecipient,
        APP_DATA => Access::Author,
        _ => Access::Anyone,
    }
}

/// The pubkeys a connection has authenticated as (NIP-42).
pub type Keys = HashSet<[u8; 32]>;

/// Whether a connection authenticated as `keys` may see an event.
pub fn visible(event: &EventView, keys: &Keys) -> bool {
    match access(event.kind()) {
        Access::Anyone => true,
        Access::Author => keys.contains(event.pubkey()),
        Access::AuthorOrRecipient => {
            keys.contains(event.pubkey())
                || event.indexed_tags().any(|tag| matches!(tag, (b'p', Element::Hex(recipient)) if keys.contains(recipient)))
        }
    }
}

/// Restrict a filter to what a connection authenticated as `keys` may
/// read, before anything runs. A filter naming private kinds has to be
/// scoped to authenticated `authors` (or `#p` recipients, where they may
/// read), or it's refused: there's no reading someone else's gift wraps by
/// asking for everyone's. One without `kinds` is narrowed to the kinds it
/// may read. Lookups by id can't sweep the store, so pass. Whatever
/// passes, each event is still checked with [`visible`] before it's sent.
pub fn scope(filter: &mut Filter, keys: &Keys) -> Result<(), String> {
    if filter.ids.is_some() {
        return Ok(());
    }
    let authors = filter.authors.as_ref().is_some_and(|authors| !authors.is_empty() && authors.iter().all(|author| keys.contains(author)));
    let recipients = filter.tags.iter().find(|(letter, _)| *letter == b'p').is_some_and(|(_, values)| {
        !values.is_empty() && values.iter().all(|value| matches!(value.split_first(), Some((1, key)) if <&[u8; 32]>::try_from(key).is_ok_and(|key| keys.contains(key))))
    });
    let readable = |kind: u16| match access(kind) {
        Access::Anyone => true,
        Access::Author => authors,
        Access::AuthorOrRecipient => authors || recipients,
    };
    match &mut filter.kinds {
        Some(kinds) if kinds.iter().all(|&kind| readable(kind)) => Ok(()),
        Some(_) => {
            let scoped = filter.authors.is_some() || filter.tags.iter().any(|(letter, _)| *letter == b'p');
            Err(if scoped {
                "auth-required: every author, or every #p, has to be authenticated to read gift wraps and app data".into()
            } else if keys.is_empty() {
                "auth-required: reading gift wraps and app data takes authors or #p, authenticated".into()
            } else {
                "restricted: reading gift wraps and app data takes authors or #p, authenticated".into()
            })
        }
        None => {
            filter.kinds = Some(KINDS.iter().copied().filter(|&kind| kind != VANISH && readable(kind)).collect());
            Ok(())
        }
    }
}

/// Check an event against its kind's rules. `relay` is this relay's
/// [`authority`], which requests to vanish have to name. Errors are the
/// `OK` message to refuse with.
pub fn validate(event: &Event, now: i64, relay: &str) -> Result<(), String> {
    let kind = u16::try_from(event.kind).map_err(|_| "invalid: kind must be between 0 and 65535".to_string())?;
    if !is_accepted(kind) {
        return Err(format!("blocked: kind {kind} is not accepted by this relay"));
    }
    known_tags(event)?;
    if super::record::is_ephemeral(kind) && event.created_at.saturating_add(EPHEMERAL_MAX_AGE) < now {
        return Err("invalid: ephemeral event is too old".into());
    }
    if super::record::is_addressable(kind) {
        let mut d = tag_values(event, "d");
        match (d.next(), d.next()) {
            (Some(value), None) if value.len() <= MAX_D => {}
            (Some(_), None) => return Err("invalid: d tag is too long".into()),
            _ => return Err("invalid: addressable events need exactly one d tag".into()),
        }
    }

    match kind {
        GIFT_WRAP | EPHEMERAL_GIFT_WRAP | NIP46 => {
            envelope_tags(event, kind != NIP46)?;
            content(event, Content::Nip44)
        }
        0 | 10304 => content(event, Content::JsonObject),
        3 | 10133 | 30315 => Ok(()),
        10000 | 10030 => content(event, Content::Private),
        10002 => {
            each(event, "r", |tag| is_ws_url(&tag[1]) && (tag.len() == 2 || (tag.len() == 3 && matches!(tag[2].as_str(), "read" | "write"))))?;
            content(event, Content::Empty)
        }
        10007 | 10050 => {
            each(event, "relay", |tag| is_ws_url(&tag[1]))?;
            content(event, Content::Private)
        }
        10009 => {
            each(event, "r", |tag| is_ws_url(&tag[1]))?;
            each(event, "group", |tag| !tag[1].is_empty() && tag.get(2).is_none_or(|relay| is_ws_url(relay)))?;
            content(event, Content::Private)
        }
        10063 => {
            each(event, "server", |tag| is_http_url(&tag[1]))?;
            content(event, Content::Private)
        }
        13303 | APP_DATA | 33302 => content(event, Content::Nip44),
        16767 | 36767 => content(event, Content::Empty),
        30030 => each(event, "emoji", |tag| tag.len() >= 3 && is_shortcode(&tag[1]) && is_http_url(&tag[2])),
        INVITE_BUNDLE => {
            if event.tag("d") != Some("") {
                return Err("invalid: invite bundles need an empty d tag".into());
            }
            match event.tag("vsk") {
                Some("6") => content(event, Content::Nip44),
                Some("9") => content(event, Content::Empty),
                _ => Err("invalid: invite bundles need a vsk tag of 6 or 9".into()),
            }
        }
        DELETION => {
            let targets = event.tags.iter().filter(|tag| matches!(tag[0].as_str(), "e" | "a")).count();
            match targets {
                0 => Err("invalid: deletion requests need an e or a tag".into()),
                n if n > MAX_DELETION_TARGETS => Err(format!("invalid: deletion requests may name at most {MAX_DELETION_TARGETS} events")),
                _ => Ok(()),
            }
        }
        VANISH => {
            if tag_values(event, "relay").any(|url| url == "ALL_RELAYS" || authority(url).as_deref() == Some(relay)) {
                Ok(())
            } else {
                Err("invalid: the request to vanish doesn't name this relay".into())
            }
        }
        _ => unreachable!("every accepted kind has rules"),
    }
}

/// The formats of tags whose meaning is the same on every kind.
fn known_tags(event: &Event) -> Result<(), String> {
    let (mut expirations, mut protected) = (0, 0);
    for tag in &event.tags {
        let Some(name) = tag.first() else { return Err("invalid: empty tag".into()) };
        if tag.iter().any(|value| value.len() > MAX_TAG_VALUE) {
            return Err("invalid: tag value is too long".into());
        }
        let value = tag.get(1).map(String::as_str);
        let ok = match name.as_str() {
            "p" | "e" => value.is_some_and(is_hex64),
            "k" => value.and_then(parse_uint).is_some_and(|k| k <= u64::from(u16::MAX)),
            "a" => value.is_some_and(is_address),
            "d" => value.is_some(),
            "expiration" => {
                expirations += 1;
                value.and_then(parse_uint).is_some()
            }
            "-" => {
                protected += 1;
                tag.len() == 1
            }
            _ => true,
        };
        if !ok {
            return Err(format!("invalid: malformed {name:?} tag"));
        }
    }
    if expirations > 1 {
        return Err("invalid: more than one expiration tag".into());
    }
    if protected > 1 {
        return Err("invalid: more than one \"-\" tag".into());
    }
    Ok(())
}

/// An encrypted envelope's tags: exactly one `p`, then optionally one `k`
/// (where `allow_k`), an `expiration`, and a `-`. No relay hints, and
/// nothing else to say more about who's talking than the `p` must.
fn envelope_tags(event: &Event, allow_k: bool) -> Result<(), String> {
    let (mut p, mut k) = (0, 0);
    for tag in &event.tags {
        let len = match tag[0].as_str() {
            "p" => {
                p += 1;
                2
            }
            "k" if allow_k => {
                k += 1;
                2
            }
            "expiration" => 2,
            "-" => 1,
            other => return Err(format!("invalid: {other:?} tags aren't allowed on kind {}", event.kind)),
        };
        if tag.len() != len {
            return Err(format!("invalid: {:?} tag has extra fields", tag[0]));
        }
    }
    if p != 1 {
        return Err("invalid: exactly one p tag is required".into());
    }
    if k > 1 {
        return Err("invalid: more than one k tag".into());
    }
    Ok(())
}

/// Check every tag named `name` with `check`, which sees tags of at least
/// two elements.
fn each(event: &Event, name: &str, check: impl Fn(&[String]) -> bool) -> Result<(), String> {
    for tag in event.tags.iter().filter(|tag| tag[0] == name) {
        if tag.len() < 2 || !check(tag) {
            return Err(format!("invalid: malformed {name:?} tag"));
        }
    }
    Ok(())
}

fn tag_values<'a>(event: &'a Event, name: &'a str) -> impl Iterator<Item = &'a str> {
    event.tags.iter().filter(move |tag| tag[0] == name).filter_map(|tag| tag.get(1)).map(String::as_str)
}

#[derive(Clone, Copy)]
enum Content {
    Empty,
    JsonObject,
    Nip44,
    /// A list's private items: none, or encrypted with NIP-44 or, as older
    /// clients did, NIP-04.
    Private,
}

fn content(event: &Event, expected: Content) -> Result<(), String> {
    let content = event.content.as_str();
    let (ok, message) = match expected {
        Content::Empty => (content.is_empty(), "invalid: content must be empty"),
        Content::JsonObject => (serde_json::from_str::<serde_json::Map<String, Value>>(content).is_ok(), "invalid: content must be a JSON object"),
        Content::Nip44 => (nip44::is_v2_payload(content), "invalid: content must be a NIP-44 v2 payload"),
        Content::Private => (
            content.is_empty() || nip44::is_v2_payload(content) || is_nip04(content),
            "invalid: content must be empty, or encrypted with NIP-44 or NIP-04",
        ),
    };
    if ok { Ok(()) } else { Err(message.into()) }
}

/// `base64(ciphertext)?iv=base64(iv)`, AES-256-CBC.
fn is_nip04(content: &str) -> bool {
    let Some((ciphertext, iv)) = content.split_once("?iv=") else { return false };
    let (Ok(ciphertext), Ok(iv)) = (STANDARD.decode(ciphertext), STANDARD.decode(iv)) else { return false };
    !ciphertext.is_empty() && ciphertext.len() % 16 == 0 && iv.len() == 16
}

/// A canonical decimal: digits only, no sign, no leading zeros.
fn parse_uint(value: &str) -> Option<u64> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

/// `kind:pubkey:d`.
fn is_address(value: &str) -> bool {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next().and_then(parse_uint).is_some_and(|kind| kind <= u64::from(u16::MAX));
    kind && parts.next().is_some_and(is_hex64) && parts.next().is_some()
}

fn is_ws_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "ws" | "wss") && url.host_str().is_some())
}

fn is_http_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| matches!(url.scheme(), "http" | "https") && url.host_str().is_some())
}

fn is_shortcode(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A URL's host, lowercase, and its port if it isn't the scheme's own: what
/// a relay URL has to agree with this relay on, whatever its scheme or path.
pub fn authority(url: &str) -> Option<String> {
    let url = url::Url::parse(url.trim()).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::event::public_key;
    use crate::relay::nip44::payload;
    use crate::relay::store::tests::{ALICE, BOB, tags};

    const NOW: i64 = 1_700_000_000;
    const RELAY: &str = "armada.example.com";

    fn check(kind: u16, event_tags: &[&[&str]], content: &str) -> Result<(), String> {
        validate(&Event::sign(ALICE, NOW, kind.into(), tags(event_tags), content), NOW, RELAY)
    }

    fn ok(kind: u16, event_tags: &[&[&str]], content: &str) {
        if let Err(error) = check(kind, event_tags, content) {
            panic!("kind {kind} {event_tags:?} {content:?}: {error}");
        }
    }

    fn refused(kind: u16, event_tags: &[&[&str]], content: &str) -> String {
        check(kind, event_tags, content).expect_err(&format!("kind {kind} {event_tags:?} {content:?} accepted"))
    }

    #[test]
    fn kinds_are_sorted_and_each_has_rules() {
        assert!(KINDS.is_sorted());
        for &kind in KINDS {
            // Panics on a kind with no arm.
            let _ = check(kind, &[], "");
        }
    }

    #[test]
    fn refuses_other_kinds() {
        for kind in [1, 4, 7, 9, 1111, 20001, AUTH, 25742, 30023, 39000] {
            assert!(refused(kind, &[], "").starts_with("blocked:"), "{kind}");
        }
    }

    #[test]
    fn envelopes_are_strict() {
        let p = public_key(BOB);
        let wrap = payload(500);
        for kind in [GIFT_WRAP, EPHEMERAL_GIFT_WRAP, NIP46] {
            ok(kind, &[&["p", &p]], &wrap);
            ok(kind, &[&["p", &p], &["expiration", "1800000000"], &["-"]], &wrap);
            refused(kind, &[], &wrap);
            refused(kind, &[&["p", &p], &["p", &p]], &wrap);
            refused(kind, &[&["p", &p, "wss://relay.example.com"]], &wrap);
            refused(kind, &[&["p", &p.to_uppercase()]], &wrap);
            refused(kind, &[&["p", &p], &["t", "x"]], &wrap);
            refused(kind, &[&["p", &p], &["expiration", "soon"]], &wrap);
            refused(kind, &[&["p", &p]], "plain text");
        }
        ok(GIFT_WRAP, &[&["p", &p], &["k", "3313"]], &wrap);
        // However long.
        ok(GIFT_WRAP, &[&["p", &p]], &payload(500_000));
        refused(GIFT_WRAP, &[&["p", &p], &["k", "3313"], &["k", "14"]], &wrap);
        refused(GIFT_WRAP, &[&["p", &p], &["k", "x"]], &wrap);
        refused(NIP46, &[&["p", &p], &["k", "1"]], &wrap);
    }

    #[test]
    fn checks_timestamps() {
        let p = public_key(BOB);
        let wrap = |kind: u16, at| validate(&Event::sign(ALICE, at, kind.into(), tags(&[&["p", &p]]), &payload(10)), NOW, RELAY);
        // Gift wraps are backdated on purpose.
        assert!(wrap(GIFT_WRAP, NOW - 2 * 86400).is_ok());
        assert!(wrap(EPHEMERAL_GIFT_WRAP, NOW - 30).is_ok());
        assert_eq!(wrap(EPHEMERAL_GIFT_WRAP, NOW - 120).unwrap_err(), "invalid: ephemeral event is too old");
    }

    #[test]
    fn keeps_ephemeral_events_briefly() {
        let p = public_key(BOB);
        let event = |kind: u16, expiration: Option<&str>| {
            let mut event_tags = vec![vec!["p".to_string(), p.clone()]];
            event_tags.extend(expiration.map(|at| vec!["expiration".to_string(), at.to_string()]));
            Event::sign(ALICE, NOW, kind.into(), event_tags, "")
        };
        let lifetime = NOW as u32 + EPHEMERAL_LIFETIME;
        assert_eq!(expiration(&event(GIFT_WRAP, None), NOW), None);
        assert_eq!(expiration(&event(GIFT_WRAP, Some("1800000000")), NOW), Some(1_800_000_000));
        assert_eq!(expiration(&event(EPHEMERAL_GIFT_WRAP, None), NOW), Some(lifetime));
        assert_eq!(expiration(&event(NIP46, Some("1800000000")), NOW), Some(lifetime));
        assert_eq!(expiration(&event(NIP46, Some("1700000010")), NOW), Some(1_700_000_010));
    }

    #[test]
    fn checks_known_tags_everywhere() {
        let alice = public_key(ALICE);
        ok(3, &[&["p", &alice], &["p", &alice, "wss://relay.example.com", "alice"]], "");
        refused(3, &[&["p", "npub1xyz"]], "");
        refused(3, &[&[]], "");
        refused(3, &[&["k", "70000"]], "");
        refused(3, &[&["k", "01"]], "");
        refused(3, &[&["a", "30023:npub:x"]], "");
        ok(3, &[&["a", &format!("30023:{alice}:x")]], "");
        refused(3, &[&["expiration", "1800000000"], &["expiration", "1800000001"]], "");
        refused(3, &[&["-", "x"]], "");
        refused(3, &[&["t", &"x".repeat(MAX_TAG_VALUE + 1)]], "");
        // Tags it knows nothing of are fine.
        ok(3, &[&["client", "Armada"], &["published_at", "1700000000"]], "");
    }

    #[test]
    fn checks_profiles_and_manifests() {
        ok(0, &[], r#"{"name":"alice"}"#);
        refused(0, &[], "alice");
        refused(0, &[], "[]");
        ok(10304, &[], r#"{"v":1,"commands":[]}"#);
        refused(10304, &[], "");
    }

    #[test]
    fn checks_lists() {
        let nip04 = format!("{}?iv={}", STANDARD.encode([7; 32]), STANDARD.encode([9; 16]));
        for kind in [10000, 10007, 10009, 10030, 10050, 10063] {
            ok(kind, &[], "");
            ok(kind, &[], &payload(100));
            ok(kind, &[], &nip04);
            refused(kind, &[], "private");
        }
        ok(10002, &[&["r", "wss://relay.example.com"], &["r", "ws://localhost:7777/", "read"]], "");
        refused(10002, &[&["r", "https://relay.example.com"]], "");
        refused(10002, &[&["r", "wss://relay.example.com", "both"]], "");
        refused(10002, &[], &payload(10));
        ok(10050, &[&["relay", "wss://inbox.example.com"]], "");
        refused(10050, &[&["relay"]], "");
        ok(10009, &[&["group", "abc", "wss://groups.example.com"], &["r", "wss://groups.example.com"]], "");
        refused(10009, &[&["group", "abc", "groups.example.com"]], "");
        ok(10063, &[&["server", "https://blossom.example.com"]], "");
        refused(10063, &[&["server", "wss://blossom.example.com"]], "");
        ok(10133, &[&["payto", "bitcoin", "bc1q"]], "");
        ok(13303, &[], &payload(100));
        refused(13303, &[], "");
        ok(16767, &[&["c", "#000000", "background"]], "");
        refused(16767, &[], "theme");
    }

    #[test]
    fn checks_addressable_kinds() {
        let blob = payload(100);
        ok(APP_DATA, &[&["d", "armada/metadata"], &["title", "Armada Settings"]], &blob);
        refused(APP_DATA, &[&["d", "armada/metadata"]], r#"{"plain":true}"#);
        refused(APP_DATA, &[], &blob);
        refused(APP_DATA, &[&["d", "a"], &["d", "b"]], &blob);
        refused(APP_DATA, &[&["d", &"x".repeat(MAX_D + 1)]], &blob);
        ok(33302, &[&["d", "0"]], &blob);
        ok(30315, &[&["d", "general"]], "busy");
        ok(36767, &[&["d", "dark"], &["title", "Dark"]], "");
        ok(30030, &[&["d", "pack"], &["emoji", "soap_box", "https://example.com/soap.png"]], "");
        refused(30030, &[&["d", "pack"], &["emoji", "soap box", "https://example.com/soap.png"]], "");
        refused(30030, &[&["d", "pack"], &["emoji", "soap"]], "");

        ok(INVITE_BUNDLE, &[&["d", ""], &["vsk", "6"]], &blob);
        ok(INVITE_BUNDLE, &[&["d", ""], &["vsk", "9"]], "");
        refused(INVITE_BUNDLE, &[&["d", ""], &["vsk", "9"]], &blob);
        refused(INVITE_BUNDLE, &[&["d", "x"], &["vsk", "6"]], &blob);
        refused(INVITE_BUNDLE, &[&["d", ""], &["vsk", "7"]], &blob);
    }

    #[test]
    fn checks_deletion_and_vanish() {
        let id = "ab".repeat(32);
        ok(DELETION, &[&["e", &id], &["k", "3314"]], "");
        refused(DELETION, &[&["k", "1"]], "");
        let many: Vec<[&str; 2]> = (0..=MAX_DELETION_TARGETS).map(|_| ["e", id.as_str()]).collect();
        let many: Vec<&[&str]> = many.iter().map(|tag| &tag[..]).collect();
        ok(DELETION, &many[..MAX_DELETION_TARGETS], "");
        refused(DELETION, &many, "");

        ok(VANISH, &[&["relay", "ALL_RELAYS"]], "");
        ok(VANISH, &[&["relay", "wss://Armada.Example.com/"]], "bye");
        refused(VANISH, &[&["relay", "wss://other.example.com"]], "");
        refused(VANISH, &[], "");
    }

    #[test]
    fn reads_authorities() {
        assert_eq!(authority("wss://Armada.Example.com/").as_deref(), Some("armada.example.com"));
        assert_eq!(authority("wss://armada.example.com:443").as_deref(), Some("armada.example.com"));
        assert_eq!(authority("ws://127.0.0.1:8080").as_deref(), Some("127.0.0.1:8080"));
        assert_eq!(authority("not a url"), None);
    }
}
