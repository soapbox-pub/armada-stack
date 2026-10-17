//! Just enough Concord to find a Community's events from one of its invite
//! links, for [`crate::ban`]: open the link's bundle, derive the addresses
//! the Community publishes at, and read its Control and Chat Planes.
//!
//! The specs are the CORD documents (github.com/soapbox-pub/concord). The
//! derivations here are frozen wire format, checked against vectors Armada
//! made.
//!
//! Nothing here judges authority, as a member's client must: a ban only
//! needs to know what was published at the Community's addresses, which only
//! its members can write to.

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use secp256k1::{SECP256K1, SecretKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::nostr::Event;
use crate::nostr::nip19::{self, Decoded};
use crate::nostr::nip44;

pub type Bytes32 = [u8; 32];

pub const INVITE_BUNDLE: u16 = 33301;
const WRAP: i64 = 1059;
const SEAL_ENCRYPTED: i64 = 20013;
const SEAL_PLAINTEXT: i64 = 20014;
const CONTROL: u16 = 3308;

const VSK_METADATA: &str = "0";
const VSK_CHANNEL: &str = "2";
const VSK_INVITE_REGISTRY: &str = "8";
const VSK_INVITE_LIVE: &str = "6";
const VSK_INVITE_REVOKED: &str = "9";

const ZERO32: Bytes32 = [0; 32];

// CORD-02 Appendix A.

fn info(label: &str, id: &Bytes32, epoch: Option<u64>) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 41);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info.extend_from_slice(id);
    if let Some(epoch) = epoch {
        info.extend_from_slice(&epoch.to_be_bytes());
    }
    info
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> Bytes32 {
    let mut out = [0; 32];
    Hkdf::<Sha256>::new(None, ikm).expand(info, &mut out).expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

/// A.3: a seed that isn't a valid scalar is retried with a counter byte
/// appended.
fn secret_key(ikm: &[u8], base: &[u8]) -> SecretKey {
    if let Ok(secret) = SecretKey::from_slice(&hkdf32(ikm, base)) {
        return secret;
    }
    let mut info = base.to_vec();
    info.push(0);
    for counter in 0..=u8::MAX {
        *info.last_mut().unwrap() = counter;
        if let Ok(secret) = SecretKey::from_slice(&hkdf32(ikm, &info)) {
            return secret;
        }
    }
    unreachable!("257 consecutive scalar rejections")
}

/// A plane's stream key (A.2): its x-only pubkey is where its events are
/// published, and its NIP-44 self-ECDH key encrypts them.
pub struct GroupKey {
    pub pk: String,
    pub conv_key: Bytes32,
}

fn group_key(label: &str, secret: &[u8], id: &Bytes32, epoch: Option<u64>) -> GroupKey {
    let secret = secret_key(secret, &info(label, id, epoch));
    let pk = secret.x_only_public_key(SECP256K1).0;
    GroupKey { pk: hex::encode(pk.serialize()), conv_key: nip44::conversation_key(&secret, &pk) }
}

/// A Channel's Chat Plane: keyed by the community_root for a Public one, by
/// its own key for a Private one.
pub fn channel_key(secret: &Bytes32, channel_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key("concord/channel", secret, channel_id, Some(epoch))
}

/// The Control Plane's read key; on a Community from before the
/// control_root split, its address too.
pub fn control_key(root: &Bytes32, community_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key("concord/control", root, community_id, Some(epoch))
}

pub fn guestbook_key(root: &Bytes32, community_id: &Bytes32, epoch: u64) -> GroupKey {
    group_key("concord/guestbook", root, community_id, Some(epoch))
}

pub fn dissolved_key(community_id: &Bytes32) -> GroupKey {
    group_key("concord/dissolved", community_id, &ZERO32, None)
}

pub fn channel_rekey_key(prior_root: &Bytes32, channel_id: &Bytes32, new_epoch: u64) -> GroupKey {
    group_key("concord/rekey-pseudonym", prior_root, channel_id, Some(new_epoch))
}

pub fn base_rekey_key(prior_root: &Bytes32, community_id: &Bytes32, new_epoch: u64) -> GroupKey {
    group_key("concord/base-rekey-pseudonym", prior_root, community_id, Some(new_epoch))
}

fn invite_bundle_key(token: &[u8]) -> Bytes32 {
    hkdf32(token, &info("concord/invite-key", &ZERO32, None))
}

fn community_id_of(owner: &Bytes32, owner_salt: &Bytes32) -> Bytes32 {
    let mut hash = Sha256::new();
    hash.update(b"concord/community");
    hash.update(owner);
    hash.update(owner_salt);
    hash.finalize().into()
}

// CORD-05.

/// The CORD-05 §3 relay dictionary, generation 4.
const RELAY_DICTIONARY: [(u8, &str); 4] =
    [(1, "wss://jskitty.com/nostr"), (2, "wss://asia.vectorapp.io/nostr"), (3, "wss://relay.ditto.pub"), (4, "wss://relay.dreamith.to")];
const FRAGMENT_VERSION: u8 = 4;
const TOKEN_BYTES: usize = 16;

/// An invite link: `…/invite/<naddr>#<fragment>`.
#[derive(Debug, PartialEq, Eq)]
pub struct InviteLink {
    /// The bundle's author, hex.
    pub link_signer: String,
    pub token: [u8; TOKEN_BYTES],
    /// Where to find the bundle.
    pub relays: Vec<String>,
}

/// The link signer an invite link's naddr names, hex: a link's locator,
/// without its secret. Takes `…/invite/<naddr>…` or a bare `<naddr>`.
pub fn link_signer(link: &str) -> Option<String> {
    let path = link.trim().split('#').next()?;
    let naddr = match path.find("/invite/") {
        Some(at) => &path[at + "/invite/".len()..],
        None => path,
    };
    let naddr = crate::util::decode_path(naddr.split(['?', '/']).next()?);
    match nip19::decode(&naddr) {
        Ok(Decoded::Naddr { pubkey, kind, identifier, .. }) if kind == u32::from(INVITE_BUNDLE) && identifier.is_empty() => Some(pubkey),
        _ => None,
    }
}

pub fn parse_link(link: &str) -> Result<InviteLink, String> {
    let link_signer = link_signer(link).ok_or("Not an invite link: expected …/invite/<naddr>#<fragment>.")?;
    let fragment = link.trim().split_once('#').map(|(_, fragment)| fragment).ok_or("The invite link has no #fragment, which holds its key.")?;
    let (token, relays) = decode_fragment(fragment)?;
    Ok(InviteLink { link_signer, token, relays })
}

/// `[version][flags][relays?][token:16]`, unpadded base64url (CORD-05 §3).
fn decode_fragment(fragment: &str) -> Result<([u8; TOKEN_BYTES], Vec<String>), String> {
    let bytes = URL_SAFE_NO_PAD.decode(fragment.trim().trim_end_matches('=')).map_err(|_| "The invite link's fragment isn't base64url.")?;
    let mut rest = &bytes[..];
    let mut take = |n: usize| -> Result<&[u8], String> {
        if rest.len() < n {
            return Err("The invite link's fragment is cut short.".into());
        }
        let (taken, tail) = rest.split_at(n);
        rest = tail;
        Ok(taken)
    };
    let version = take(1)?[0];
    if version != FRAGMENT_VERSION {
        return Err(format!("The invite link is format {version}; this only reads format {FRAGMENT_VERSION}."));
    }
    let flags = take(1)?[0];
    let mut relays = Vec::new();
    if flags & 1 != 0 {
        relays = RELAY_DICTIONARY.iter().map(|(_, url)| url.to_string()).collect();
    } else {
        for _ in 0..take(1)?[0] {
            let lead = take(1)?[0];
            if (1..=254).contains(&lead) {
                if let Some((_, url)) = RELAY_DICTIONARY.iter().find(|(id, _)| *id == lead) {
                    relays.push(url.to_string());
                }
            } else {
                let len = take(1)?[0] as usize;
                let text = String::from_utf8_lossy(take(len)?).into_owned();
                relays.push(if lead == 255 { text } else { format!("wss://{text}") });
            }
        }
    }
    let token = take(TOKEN_BYTES)?.try_into().unwrap();
    if !rest.is_empty() {
        return Err("The invite link's fragment has bytes after its token.".into());
    }
    Ok((token, relays))
}

/// What a bundle holds that a ban needs (CORD-05 §1).
#[derive(Debug, Deserialize)]
pub struct Bundle {
    pub community_id: String,
    pub owner: String,
    pub owner_salt: String,
    pub community_root: String,
    pub root_epoch: u64,
    #[serde(default)]
    pub control_pk: Option<String>,
    #[serde(default)]
    pub channels: Vec<BundleChannel>,
    #[serde(default)]
    pub relays: Vec<String>,
    #[serde(default)]
    pub name: String,
}

/// A Private Channel's key, as a bundle carries it.
#[derive(Debug, Deserialize)]
pub struct BundleChannel {
    pub id: String,
    pub key: String,
    pub epoch: u64,
    #[serde(default)]
    pub name: String,
}

impl Bundle {
    pub fn id(&self) -> Bytes32 {
        bytes32(&self.community_id).unwrap_or_default()
    }

    pub fn root(&self) -> Bytes32 {
        bytes32(&self.community_root).unwrap_or_default()
    }
}

/// Open the bundle a link points at: `None` if the link was revoked. Its
/// expiry doesn't matter here.
pub fn open_bundle(event: &Event, link: &InviteLink) -> Result<Option<Bundle>, String> {
    if event.kind != i64::from(INVITE_BUNDLE) || event.pubkey != link.link_signer || !event.verify() {
        return Err("That isn't the link's invite bundle.".into());
    }
    match event.tag("vsk") {
        Some(VSK_INVITE_REVOKED) => return Ok(None),
        Some(VSK_INVITE_LIVE) => {}
        other => return Err(format!("The invite bundle has an unknown marker {other:?}.")),
    }
    let json = nip44::decrypt(&invite_bundle_key(&link.token), &event.content).ok_or("The invite link's key doesn't open its bundle.")?;
    let bundle: Bundle = serde_json::from_str(&json).map_err(|error| format!("The invite bundle is malformed: {error}"))?;
    let (Some(id), Some(owner), Some(salt), Some(_)) =
        (bytes32(&bundle.community_id), bytes32(&bundle.owner), bytes32(&bundle.owner_salt), bytes32(&bundle.community_root))
    else {
        return Err("The invite bundle's keys aren't 32 bytes of hex.".into());
    };
    if community_id_of(&owner, &salt) != id {
        return Err("The invite bundle's owner doesn't match its community_id.".into());
    }
    Ok(Some(bundle))
}

// CORD-01: streams.

/// The innermost event of a stream wrap, its author proven by the seal.
#[derive(Debug, Deserialize)]
pub struct Rumor {
    pub pubkey: String,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
}

impl Rumor {
    fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|tag| tag.first().map(String::as_str) == Some(name)).and_then(|tag| tag.get(1)).map(String::as_str)
    }
}

/// Open a stream wrap with its plane's key: decrypt the seal, check its
/// signature, and recover the rumor it signed for.
pub fn open_wrap(wrap: &Event, conv_key: &Bytes32) -> Option<Rumor> {
    if wrap.kind != WRAP {
        return None;
    }
    let seal: Event = serde_json::from_str(&nip44::decrypt(conv_key, &wrap.content)?).ok()?;
    if !seal.verify() {
        return None;
    }
    let json = match seal.kind {
        SEAL_PLAINTEXT => seal.content,
        SEAL_ENCRYPTED => nip44::decrypt(conv_key, &seal.content)?,
        _ => return None,
    };
    let rumor: Rumor = serde_json::from_str(&json).ok()?;
    (rumor.pubkey == seal.pubkey).then_some(rumor)
}

/// A blob a rumor points at, and who pointed at it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobRef {
    pub sha256: String,
    pub author: String,
}

/// What a Community's Control Plane says that a ban needs, from every
/// edition however it folds.
#[derive(Debug, Default)]
pub struct Control {
    pub name: Option<String>,
    /// Every Channel defined, by id, with a name it had.
    pub channels: BTreeMap<Bytes32, String>,
    /// Link signers from every creator's invite Registry, hex.
    pub link_signers: Vec<String>,
    /// The icon and banner.
    pub blobs: Vec<BlobRef>,
}

pub fn read_control(wraps: &[Event], conv_key: &Bytes32) -> Control {
    let mut control = Control::default();
    for rumor in wraps.iter().filter_map(|wrap| open_wrap(wrap, conv_key)).filter(|rumor| rumor.kind == CONTROL) {
        let content: Value = serde_json::from_str(&rumor.content).unwrap_or_default();
        match rumor.tag("vsk") {
            Some(VSK_METADATA) => {
                if let Some(name) = content["name"].as_str() {
                    control.name = Some(name.to_string());
                }
                for image in ["icon", "banner"] {
                    let pointer = &content[image];
                    for value in [&pointer["hash"], &pointer["url"]] {
                        if let Some(sha256) = value.as_str().and_then(blob_hash) {
                            control.blobs.push(BlobRef { sha256, author: rumor.pubkey.clone() });
                        }
                    }
                }
            }
            Some(VSK_CHANNEL) => {
                if let Some(id) = rumor.tag("eid").and_then(bytes32) {
                    let name = control.channels.entry(id).or_default();
                    if let Some(named) = content["name"].as_str().filter(|named| !named.is_empty()) {
                        *name = named.to_string();
                    }
                }
            }
            Some(VSK_INVITE_REGISTRY) => {
                let signers = content.as_array().into_iter().flatten().filter_map(Value::as_str);
                control.link_signers.extend(signers.filter(|s| bytes32(s).is_some()).map(str::to_lowercase));
            }
            _ => {}
        }
    }
    control.link_signers.sort_unstable();
    control.link_signers.dedup();
    control.blobs.sort_by(|a, b| (&a.sha256, &a.author).cmp(&(&b.sha256, &b.author)));
    control.blobs.dedup();
    control
}

/// The blobs a Channel's messages attach (NIP-92 `imeta`).
pub fn attachments(wraps: &[Event], conv_key: &Bytes32) -> Vec<BlobRef> {
    let mut blobs = Vec::new();
    for rumor in wraps.iter().filter_map(|wrap| open_wrap(wrap, conv_key)) {
        for tag in rumor.tags.iter().filter(|tag| tag.first().map(String::as_str) == Some("imeta")) {
            for part in &tag[1..] {
                if let Some(("url" | "x", value)) = part.split_once(' ')
                    && let Some(sha256) = blob_hash(value)
                {
                    blobs.push(BlobRef { sha256, author: rumor.pubkey.clone() });
                }
            }
        }
    }
    blobs.sort_by(|a, b| (&a.sha256, &a.author).cmp(&(&b.sha256, &b.author)));
    blobs.dedup();
    blobs
}

/// A blob's sha256: the value itself, or the last part of a Blossom URL's
/// path, without its extension.
fn blob_hash(value: &str) -> Option<String> {
    let last = value.split(['?', '#']).next()?.rsplit('/').next()?;
    let hash = last.split('.').next()?.to_lowercase();
    bytes32(&hash).map(|_| hash)
}

pub fn bytes32(value: &str) -> Option<Bytes32> {
    let mut out = [0; 32];
    hex::decode_to_slice(value, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Made by Armada's TypeScript, from armada-discord-bridge's
    /// `crates/concord/tests/vectors/armada.json`.
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/concord.json")).unwrap()
    }

    fn h(value: &Value) -> Bytes32 {
        bytes32(value.as_str().unwrap()).unwrap()
    }

    fn event(value: &Value) -> Event {
        serde_json::from_value(value.clone()).unwrap()
    }

    #[test]
    fn derives_as_armada_does() {
        let v = vectors();
        let (k, d) = (&v["keys"], &v["derive"]);
        let (cid, root) = (h(&k["community_id"]), h(&k["community_root"]));
        assert_eq!(community_id_of(&h(&k["owner"]), &h(&k["owner_salt"])), cid);
        let check = |key: GroupKey, name: &str| {
            assert_eq!(key.pk, d[name]["pk"].as_str().unwrap(), "{name}");
            assert_eq!(hex::encode(key.conv_key), d[name]["conv_key"].as_str().unwrap(), "{name}");
        };
        check(channel_key(&root, &h(&k["channel_id"]), 0), "channel_public_e0");
        check(channel_key(&h(&k["private_channel_key"]), &h(&k["channel_id"]), 3), "channel_private_e3");
        check(control_key(&root, &cid, 0), "control_e0");
        check(guestbook_key(&root, &cid, 2), "guestbook_e2");
        check(dissolved_key(&cid), "dissolved");
        check(channel_rekey_key(&root, &h(&k["channel_id"]), 4), "channel_rekey_e4");
        check(base_rekey_key(&root, &cid, 1), "base_rekey_e1");
        assert_eq!(hex::encode(invite_bundle_key(&[0x99; 16])), d["invite_bundle_key"].as_str().unwrap());
    }

    #[test]
    fn opens_armada_invites() {
        let v = vectors();
        let i = &v["invite"];
        let link = parse_link(i["url"].as_str().unwrap()).unwrap();
        assert_eq!(link.link_signer, i["link_signer"].as_str().unwrap());
        assert_eq!(hex::encode(link.token), i["token"].as_str().unwrap());

        let bundle = open_bundle(&event(&i["bundle_event"]), &link).unwrap().unwrap();
        assert_eq!(bundle.community_id, v["keys"]["community_id"].as_str().unwrap());
        assert_eq!(bundle.name, "Test Community");
        assert_eq!(bundle.channels[0].epoch, 3);

        let mut wrong = parse_link(i["url"].as_str().unwrap()).unwrap();
        wrong.token = [0; 16];
        assert!(open_bundle(&event(&i["bundle_event"]), &wrong).is_err());
        assert!(parse_link("https://example.com/not-an-invite#abc").is_err());
    }

    #[test]
    fn decodes_fragments() {
        let i = &vectors()["invite"];
        let (token, relays) = decode_fragment(i["fragment_stock"].as_str().unwrap()).unwrap();
        assert_eq!(token, [0x99; 16]);
        assert_eq!(relays.len(), 4);
        let (_, relays) = decode_fragment(i["fragment_custom"].as_str().unwrap()).unwrap();
        assert_eq!(relays, ["wss://relay.ditto.pub", "wss://relay.example.com", "ws://localhost:7777"]);
    }

    #[test]
    fn reads_armada_control_planes() {
        let v = vectors();
        let (k, c) = (&v["keys"], &v["control"]);
        let wraps: Vec<Event> = c["wraps"].as_array().unwrap().iter().map(event).collect();
        let control = read_control(&wraps, &control_key(&h(&k["community_root"]), &h(&k["community_id"]), 0).conv_key);
        assert_eq!(control.name.as_deref(), Some("Test Community"));
        // Names aren't folded, so one an unauthorized edit gave may show; only
        // which Channels exist matters.
        let want: Vec<Bytes32> = c["expect"]["channels"].as_object().unwrap().keys().map(|id| bytes32(id).unwrap()).collect();
        assert_eq!(control.channels.keys().copied().collect::<Vec<_>>(), want);

        // A key that isn't the plane's opens nothing.
        assert!(read_control(&wraps, &[1; 32]).channels.is_empty());
    }

    #[test]
    fn opens_armada_chat() {
        let v = vectors();
        let k = &v["keys"];
        let wrap = event(&v["chat_wrap"]["wrap"]);
        let key = channel_key(&h(&k["community_root"]), &h(&k["channel_id"]), 0);
        let rumor = open_wrap(&wrap, &key.conv_key).unwrap();
        assert_eq!(rumor.kind, 9);
        assert_eq!(rumor.pubkey, k["alice"].as_str().unwrap());
    }

    #[test]
    fn finds_blob_hashes() {
        let x = "ab".repeat(32);
        assert_eq!(blob_hash(&format!("https://blossom.example/{x}.jpg")), Some(x.clone()));
        assert_eq!(blob_hash(&format!("https://blossom.example/{}?a=b", x.to_uppercase())), Some(x.clone()));
        assert_eq!(blob_hash(&x), Some(x));
        assert_eq!(blob_hash("https://example.com/image.png"), None);
    }
}
