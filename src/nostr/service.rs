//! Relay lookups the web service's sync worker makes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::future::BoxFuture;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::Event;
use super::pool::{Filter, Pool};
use crate::nsite::{NAMED_SITE_KIND, NsiteAddress, server_tags, write_relays};

/// NIP-65 relay list.
const RELAY_LIST_KIND: i64 = 10002;
/// BUD-03 Blossom server list.
const SERVER_LIST_KIND: i64 = 10063;

/// How long a cached relay or server list is trusted before refetching.
const LIST_STALE_TIME: Duration = Duration::from_secs(60 * 60);

const QUERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Most relays taken from one author's kind 10002 list. Every entry is a
/// connection opened and held; a handful covers any honest outbox.
pub const MAX_AUTHOR_RELAYS: usize = 5;

/// Most Blossom servers taken from a manifest and its author's list together.
/// A blob is asked of each in turn until one has it, so every extra name is
/// another request per missing file, at an address of the author's choosing.
pub const MAX_AUTHOR_SERVERS: usize = 8;

/// What the sync worker asks of Nostr. A trait so tests can stand in for the
/// relays.
pub trait NostrSource: Send + Sync {
    /// The newest manifest event for a site, if any relay has one.
    fn fetch_manifest<'a>(&'a self, address: &'a NsiteAddress, cancel: &'a CancellationToken) -> BoxFuture<'a, Option<Event>>;

    /// Blossom servers to try for a site's blobs, best first.
    fn blob_sources<'a>(&'a self, manifest: &'a Event, fallbacks: &'a [String], cancel: &'a CancellationToken) -> BoxFuture<'a, Vec<String>>;

    /// Stream new versions of a site until `cancel` fires.
    fn subscribe<'a>(&'a self, address: &'a NsiteAddress, cancel: CancellationToken) -> BoxFuture<'a, mpsc::Receiver<Event>>;
}

struct CachedList {
    value: Vec<String>,
    fetched_at: Instant,
}

pub struct NostrService {
    pool: Pool,
    relays: Vec<String>,
    relay_lists: Mutex<HashMap<String, CachedList>>,
    server_lists: Mutex<HashMap<String, CachedList>>,
}

impl NostrService {
    /// `relays` are the configured ones, in the spelling
    /// [`crate::config::parse_relay_url`] gives them.
    pub fn new(relays: Vec<String>) -> Self {
        let configured = Arc::new(relays.clone());
        Self {
            pool: Pool::new(Arc::new(move |url: &str| configured.iter().any(|relay| relay == url))),
            relays,
            relay_lists: Mutex::new(HashMap::new()),
            server_lists: Mutex::new(HashMap::new()),
        }
    }

    /// Collect events matching `filters` from the configured relays and
    /// `extra`, giving up after the query timeout.
    async fn query(&self, filters: Vec<Filter>, extra: &[String], cancel: &CancellationToken) -> Vec<Event> {
        let relays = dedupe(extra.iter().cloned().chain(self.relays.iter().cloned()));
        if relays.is_empty() {
            return Vec::new();
        }
        self.pool.query(filters, &relays, QUERY_TIMEOUT, cancel).await
    }

    async fn author_relays(&self, pubkey: &str, cancel: &CancellationToken) -> Vec<String> {
        if let Some(cached) = self.relay_lists.lock().get(pubkey).filter(|c| c.fetched_at.elapsed() < LIST_STALE_TIME) {
            return cached.value.clone();
        }

        let filter = Filter { kinds: vec![RELAY_LIST_KIND], authors: vec![pubkey.to_string()], ..Default::default() };
        let events = self.query(vec![filter], &[], cancel).await;
        let value = match latest(&events) {
            Some(event) => vet_relay_hints(&write_relays(event)).await,
            None => Vec::new(),
        };

        tracing::debug!(pubkey, relays = value.len(), "relay list fetched");
        self.relay_lists.lock().insert(pubkey.to_string(), CachedList { value: value.clone(), fetched_at: Instant::now() });
        value
    }

    async fn author_servers(&self, pubkey: &str, cancel: &CancellationToken) -> Vec<String> {
        if let Some(cached) = self.server_lists.lock().get(pubkey).filter(|c| c.fetched_at.elapsed() < LIST_STALE_TIME) {
            return cached.value.clone();
        }

        let filter = Filter { kinds: vec![SERVER_LIST_KIND], authors: vec![pubkey.to_string()], limit: Some(1), ..Default::default() };
        let events = self.query(vec![filter], &[], cancel).await;
        let value = latest(&events).map(server_tags).unwrap_or_default();

        tracing::debug!(pubkey, servers = value.len(), "server list fetched");
        self.server_lists.lock().insert(pubkey.to_string(), CachedList { value: value.clone(), fetched_at: Instant::now() });
        value
    }
}

impl NostrSource for NostrService {
    fn fetch_manifest<'a>(&'a self, address: &'a NsiteAddress, cancel: &'a CancellationToken) -> BoxFuture<'a, Option<Event>> {
        Box::pin(async move {
            // A manifest is most likely on its author's write relays.
            let author_relays = self.author_relays(&address.pubkey, cancel).await;
            let events = self.query(vec![manifest_filter(address, None)], &author_relays, cancel).await;
            latest(&events).cloned()
        })
    }

    fn blob_sources<'a>(&'a self, manifest: &'a Event, fallbacks: &'a [String], cancel: &'a CancellationToken) -> BoxFuture<'a, Vec<String>> {
        Box::pin(async move {
            let author_servers = self.author_servers(&manifest.pubkey, cancel).await;
            let named = server_tags(manifest).into_iter().chain(author_servers).filter_map(|server| normalize_server(&server));
            // The operator's fallbacks are not the author's to crowd out.
            let named = dedupe(named).into_iter().take(MAX_AUTHOR_SERVERS);
            dedupe(named.chain(fallbacks.iter().filter_map(|server| normalize_server(server))))
        })
    }

    fn subscribe<'a>(&'a self, address: &'a NsiteAddress, cancel: CancellationToken) -> BoxFuture<'a, mpsc::Receiver<Event>> {
        Box::pin(async move {
            // Watch the author's own write relays too — that's where they publish.
            let hints = self.author_relays(&address.pubkey, &cancel).await;
            let relays = dedupe(self.relays.iter().cloned().chain(hints));
            tracing::info!(relays = relays.len(), "subscribed to site updates");
            self.pool.subscribe(vec![manifest_filter(address, Some(crate::util::now()))], &relays, cancel)
        })
    }
}

/// Filter matching a site's manifest events.
pub fn manifest_filter(address: &NsiteAddress, since: Option<i64>) -> Filter {
    Filter {
        kinds: vec![address.kind],
        authors: vec![address.pubkey.clone()],
        d: if address.kind == NAMED_SITE_KIND { vec![address.identifier.clone()] } else { Vec::new() },
        since,
        limit: None,
    }
}

/// The URL a blob would live at on a Blossom server.
pub fn blob_url(server: &str, sha256: &str) -> String {
    match url::Url::parse(server).and_then(|base| base.join(sha256)) {
        Ok(url) => url.to_string(),
        Err(_) => format!("{server}{sha256}"),
    }
}

/// The relays from an author's list worth connecting to: well-formed
/// `wss://` URLs on public addresses, at most [`MAX_AUTHOR_RELAYS`].
///
/// The list is written by whoever publishes the site. Checking here spends
/// the few slots on relays that can pass; the pool checks again at connect,
/// on the addresses it dials, which is what a rebinding name can't get past.
pub async fn vet_relay_hints(urls: &[String]) -> Vec<String> {
    let candidates: Vec<String> = dedupe(urls.iter().filter_map(|url| author_relay_url(url)))
        .into_iter()
        .take(MAX_AUTHOR_RELAYS * 4)
        .collect();

    let verdicts = futures_util::future::join_all(candidates.iter().map(|candidate| async move {
        match url::Url::parse(candidate) {
            Ok(url) => crate::net::is_public_url(&url).await.unwrap_or(false),
            Err(_) => false,
        }
    }))
    .await;

    candidates.into_iter().zip(verdicts).filter(|(_, ok)| *ok).map(|(url, _)| url).take(MAX_AUTHOR_RELAYS).collect()
}

/// A relay an author named, if it's `wss://`: no relay worth naming lacks TLS.
fn author_relay_url(input: &str) -> Option<String> {
    crate::config::parse_relay_url(input).ok().filter(|url| url.starts_with("wss://"))
}

fn normalize_server(server: &str) -> Option<String> {
    let mut url = url::Url::parse(server).ok()?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return None;
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Some(url.to_string())
}

/// The newest of some events; the first seen wins a tie.
fn latest(events: &[Event]) -> Option<&Event> {
    events.iter().fold(None, |newest: Option<&Event>, event| match newest {
        Some(newest) if event.created_at <= newest.created_at => Some(newest),
        _ => Some(event),
    })
}

/// Order-preserving deduplication.
pub fn dedupe<T: Clone + Eq + std::hash::Hash>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    let mut seen = std::collections::HashSet::new();
    values.into_iter().filter(|value| seen.insert(value.clone())).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_urls() {
        assert_eq!(blob_url("https://b.example.com/", &"a".repeat(64)), format!("https://b.example.com/{}", "a".repeat(64)));
        assert_eq!(blob_url("https://b.example.com/prefix/", "x"), "https://b.example.com/prefix/x");
        assert_eq!(normalize_server("https://b.example.com/prefix").as_deref(), Some("https://b.example.com/prefix/"));
        assert_eq!(normalize_server("wss://b.example.com"), None);
    }

    #[tokio::test]
    async fn vets_relay_hints() {
        let hints = vec![
            "wss://127.0.0.1".to_string(),
            "ws://1.1.1.1".to_string(),
            "wss://1.1.1.1/".to_string(),
            "wss://1.1.1.1".to_string(),
            "wss://[::1]".to_string(),
        ];
        assert_eq!(vet_relay_hints(&hints).await, ["wss://1.1.1.1"]);
    }
}
