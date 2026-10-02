//! nsites (NIP-5A): addresses, and what a manifest event lists.

use std::collections::HashMap;

use crate::hash::BlobHash;
use crate::nostr::Event;
use crate::nostr::nip19::{self, Decoded};

pub const ROOT_SITE_KIND: i64 = 15128;
pub const NAMED_SITE_KIND: i64 = 35128;

/// Which site: an author, and for a named site its `d` tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NsiteAddress {
    pub pubkey: String,
    pub kind: i64,
    /// Empty for a root site.
    pub identifier: String,
}

impl NsiteAddress {
    /// An `naddr` of a site kind, or an `npub` for that author's root site.
    pub fn parse(input: &str) -> Result<NsiteAddress, String> {
        let value = input.trim();
        let value = value.strip_prefix("nostr:").unwrap_or(value);
        match nip19::decode(value) {
            Ok(Decoded::Naddr { pubkey, kind, identifier, .. }) => match i64::from(kind) {
                NAMED_SITE_KIND => Ok(NsiteAddress { pubkey, kind: NAMED_SITE_KIND, identifier }),
                ROOT_SITE_KIND => Ok(NsiteAddress { pubkey, kind: ROOT_SITE_KIND, identifier: String::new() }),
                other => Err(format!("{value} is a kind {other} address, not an nsite (kind {NAMED_SITE_KIND} or {ROOT_SITE_KIND}).")),
            },
            Ok(Decoded::Npub(pubkey)) => Ok(NsiteAddress { pubkey, kind: ROOT_SITE_KIND, identifier: String::new() }),
            Ok(other) => Err(format!("{value} is an {}, not an naddr or npub.", other.type_name())),
            Err(error) => Err(format!("{value} is not a valid naddr or npub: {error}.")),
        }
    }

    pub fn naddr(&self) -> String {
        nip19::naddr_encode(&self.pubkey, self.kind as u32, &self.identifier, &[])
    }

    /// Whether an event is a version of this site.
    pub fn matches(&self, event: &Event) -> bool {
        event.kind == self.kind
            && event.pubkey == self.pubkey
            && (self.kind != NAMED_SITE_KIND || event.tag("d").unwrap_or("") == self.identifier)
    }
}

/// The file map of a manifest: absolute site path to blob hash.
///
/// Tags whose hash isn't a sha256 are dropped rather than failing the whole
/// deploy — a single malformed tag shouldn't take a site offline.
pub fn manifest_paths(event: &Event) -> HashMap<String, BlobHash> {
    let mut paths = HashMap::new();
    for tag in &event.tags {
        if tag.first().map(String::as_str) != Some("path") {
            continue;
        }
        let (Some(path), Some(hash)) = (tag.get(1), tag.get(2)) else { continue };
        if path.is_empty() {
            continue;
        }
        let Some(sha256) = BlobHash::parse(hash) else { continue };
        // A later tag for the same path wins.
        paths.insert(join_root(path), sha256);
    }
    paths
}

/// Blossom servers named by `server` tags: a manifest's own, or a kind 10063
/// list's (BUD-03). The two use the same tag.
pub fn server_tags(event: &Event) -> Vec<String> {
    tag_values(event, "server")
}

/// Write relays from a kind 10002 list: where an author's own events land,
/// which is where their manifests will be.
pub fn write_relays(event: &Event) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some("r"))
        .filter(|tag| tag.get(2).map(String::as_str) != Some("read"))
        .filter_map(|tag| tag.get(1).filter(|url| !url.is_empty()).cloned())
        .collect()
}

fn tag_values(event: &Event, name: &str) -> Vec<String> {
    event
        .tags
        .iter()
        .filter(|tag| tag.first().map(String::as_str) == Some(name))
        .filter_map(|tag| tag.get(1).filter(|value| !value.is_empty()).cloned())
        .collect()
}

/// `path.posix.join("/", path)`: rooted, with `.`, `..` and repeated slashes
/// resolved, and a trailing slash kept.
pub fn join_root(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other),
        }
    }

    let mut joined = format!("/{}", segments.join("/"));
    if path.ends_with('/') && joined != "/" {
        joined.push('/');
    }
    joined
}

/// A request path as resolution sees it: percent-decoded and rooted, so it
/// can be compared against a manifest's paths.
pub fn normalize_site_path(request_path: &str) -> String {
    join_root(&crate::util::decode_path(request_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_like_posix() {
        assert_eq!(join_root("index.html"), "/index.html");
        assert_eq!(join_root("/a//b/./c.html"), "/a/b/c.html");
        assert_eq!(join_root("/../../etc/passwd"), "/etc/passwd");
        assert_eq!(join_root("/docs/"), "/docs/");
        assert_eq!(join_root(""), "/");
        assert_eq!(join_root("/a/.."), "/");
    }

    #[test]
    fn reads_manifests() {
        let sha = "a".repeat(64);
        let event = Event {
            id: String::new(),
            pubkey: String::new(),
            created_at: 0,
            kind: ROOT_SITE_KIND,
            tags: vec![
                vec!["path".into(), "/index.html".into(), sha.to_uppercase()],
                vec!["path".into(), "/bad".into(), "nothex".into()],
                vec!["path".into(), "about.html".into(), sha.clone()],
                vec!["server".into(), "https://b.example.com".into()],
            ],
            content: String::new(),
            sig: String::new(),
        };
        let paths = manifest_paths(&event);
        assert_eq!(paths.len(), 2);
        assert_eq!(paths["/index.html"].to_string(), sha);
        assert!(paths.contains_key("/about.html"));
        assert_eq!(server_tags(&event), ["https://b.example.com"]);
    }

    #[test]
    fn parses_addresses() {
        let pubkey = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
        let named = NsiteAddress { pubkey: pubkey.into(), kind: NAMED_SITE_KIND, identifier: "docs".into() };
        assert_eq!(NsiteAddress::parse(&named.naddr()).unwrap(), named);
        assert_eq!(NsiteAddress::parse(&format!("nostr:{}", named.naddr())).unwrap(), named);

        let root = NsiteAddress { pubkey: pubkey.into(), kind: ROOT_SITE_KIND, identifier: String::new() };
        assert_eq!(NsiteAddress::parse(&nip19::npub_encode(pubkey)).unwrap(), root);

        let note = nip19::naddr_encode(pubkey, 30023, "post", &[]);
        assert!(NsiteAddress::parse(&note).unwrap_err().contains("kind 30023"));
    }

    #[test]
    fn matches_its_own_versions() {
        let secret = "0000000000000000000000000000000000000000000000000000000000000001";
        let event = Event::sign(secret, 1, NAMED_SITE_KIND, vec![vec!["d".into(), "docs".into()]], "");
        let address = NsiteAddress { pubkey: event.pubkey.clone(), kind: NAMED_SITE_KIND, identifier: "docs".into() };
        assert!(address.matches(&event));
        assert!(!NsiteAddress { identifier: "blog".into(), ..address.clone() }.matches(&event));
        assert!(!NsiteAddress { kind: ROOT_SITE_KIND, ..address }.matches(&event));
    }
}
