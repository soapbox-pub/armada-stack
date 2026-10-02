//! The LiveKit nodes behind the broker, and which one a room lands on.
//!
//! CORD-07's rendezvous (§5) brings clients to one broker origin; what's
//! behind it is the broker's business, and each token response names its
//! own SFU. So a fleet is any number of independent LiveKit servers — no
//! clustering, nothing shared between them.
//!
//! A room goes to the healthy node ranked lowest by
//! `sha256(voice_room[32] || utf8(node.url))`: rendezvous hashing, the same
//! hash §5 breaks ties between brokers with. It depends on nothing but the
//! room and the healthy nodes, so every member of a call lands on the same
//! node, on any replica, without coordinating — and adding or removing a
//! node only moves the rooms that were on it.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Result;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};

use crate::config::AvNode;

/// One LiveKit server, as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// What clients are told to connect to. Also the node's identity.
    pub url: String,
    pub api_url: String,
    pub api_key: String,
    pub api_secret: String,
}

impl Node {
    pub fn from_config(node: &AvNode) -> Result<Node> {
        Ok(Node { url: node.client_url()?, api_url: node.api_url()?, api_key: node.api_key.clone(), api_secret: node.api_secret.clone() })
    }
}

/// A node's rank for a room. Lowest wins.
pub fn rank(room: &[u8; 32], url: &str) -> [u8; 32] {
    Sha256::new().chain_update(room).chain_update(url.as_bytes()).finalize().into()
}

/// The node `room` is placed on, of `nodes`.
pub fn select<'a>(room: &[u8; 32], nodes: impl IntoIterator<Item = &'a Node>) -> Option<&'a Node> {
    nodes.into_iter().min_by_key(|node| rank(room, &node.url))
}

/// How long one health check may take: under the interval, so checks never
/// pile up, and bounded at all, so a node that silently drops packets fails
/// rather than hanging forever in rotation.
pub fn probe_timeout(interval: Duration) -> Duration {
    Duration::from_secs(interval.as_secs().saturating_sub(1).clamp(1, 10))
}

/// Failed checks in a row before a node leaves rotation. More than one:
/// a broker with no node to offer reports itself unavailable, which sends
/// clients elsewhere and splits calls already live here (§5).
const FAILURES_TO_DEMOTE: u32 = 2;

/// The nodes, and which are up. They start up, so the broker serves at once
/// rather than refusing everything until the first checks come back.
pub struct Fleet {
    nodes: Vec<Node>,
    /// Failed checks in a row, by node index.
    failures: Mutex<HashMap<usize, u32>>,
}

impl Fleet {
    pub fn new(nodes: Vec<Node>) -> Fleet {
        Fleet { nodes, failures: Mutex::new(HashMap::new()) }
    }

    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    fn is_healthy(&self, failures: &HashMap<usize, u32>, index: usize) -> bool {
        failures.get(&index).is_none_or(|count| *count < FAILURES_TO_DEMOTE)
    }

    /// Whether any node is up.
    pub fn available(&self) -> bool {
        let failures = self.failures.lock();
        (0..self.nodes.len()).any(|index| self.is_healthy(&failures, index))
    }

    /// The healthy node for `room`, if any. Strictly from the same set
    /// [`Fleet::available`] reports on, so a broker that says it's up can
    /// always place a room.
    pub fn select(&self, room: &[u8; 32]) -> Option<&Node> {
        let failures = self.failures.lock();
        select(room, self.nodes.iter().enumerate().filter(|(index, _)| self.is_healthy(&failures, *index)).map(|(_, node)| node))
    }

    /// Record the outcome of checking node `index`. One success restores it:
    /// wrongly up costs a failed join, wrongly down a split call.
    pub fn observe(&self, index: usize, outcome: Result<()>) {
        let url = &self.nodes[index].url;
        let mut failures = self.failures.lock();
        match outcome {
            Ok(()) => {
                if failures.remove(&index).is_some_and(|count| count >= FAILURES_TO_DEMOTE) {
                    tracing::info!(node = %url, "AV node healthy again");
                }
            }
            Err(error) => {
                let count = failures.entry(index).or_default();
                *count = count.saturating_add(1);
                if *count == FAILURES_TO_DEMOTE {
                    tracing::warn!(node = %url, error = %error, "AV node out of rotation");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use super::*;

    fn node(url: &str) -> Node {
        Node { url: url.into(), api_url: String::new(), api_key: "k".into(), api_secret: "s".into() }
    }

    fn nodes() -> Vec<Node> {
        (1..=4).map(|n| node(&format!("wss://sfu{n}.example.com"))).collect()
    }

    fn room(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn ranks_by_room_and_url() {
        assert_eq!(rank(&room(1), "wss://a"), rank(&room(1), "wss://a"));
        assert_ne!(rank(&room(1), "wss://a"), rank(&room(2), "wss://a"));
        assert_ne!(rank(&room(1), "wss://a"), rank(&room(1), "wss://b"));
        // sha256 of the 32 room bytes, then the URL.
        let mut preimage = vec![1u8; 32];
        preimage.extend_from_slice(b"wss://a");
        assert_eq!(rank(&room(1), "wss://a").as_slice(), Sha256::digest(&preimage).as_slice());
    }

    #[test]
    fn places_rooms_the_same_way_whatever_the_order() {
        let nodes = nodes();
        assert_eq!(select(&room(1), &[]), None);
        for seed in 0..32 {
            let reversed: Vec<Node> = nodes.iter().rev().cloned().collect();
            assert_eq!(select(&room(seed), &nodes), select(&room(seed), &reversed));
            let lowest = nodes.iter().map(|node| rank(&room(seed), &node.url)).min().unwrap();
            assert_eq!(rank(&room(seed), &select(&room(seed), &nodes).unwrap().url), lowest);
        }
    }

    #[test]
    fn spreads_rooms_and_moves_only_a_removed_nodes() {
        let nodes = nodes();
        let mut hits = HashMap::new();
        for seed in 0..=255 {
            *hits.entry(&select(&room(seed), &nodes).unwrap().url).or_insert(0) += 1;
        }
        assert_eq!(hits.len(), 4);
        assert!(hits.values().all(|count| *count > 20), "{hits:?}");

        let remaining: Vec<Node> = nodes.iter().filter(|node| node.url != nodes[2].url).cloned().collect();
        for seed in 0..=255 {
            let before = select(&room(seed), &nodes).unwrap();
            if before.url != nodes[2].url {
                assert_eq!(select(&room(seed), &remaining).unwrap().url, before.url);
            }
        }
    }

    #[test]
    fn bounds_health_checks_under_the_interval() {
        assert_eq!(probe_timeout(Duration::from_secs(15)), Duration::from_secs(10));
        assert_eq!(probe_timeout(Duration::from_secs(5)), Duration::from_secs(4));
        assert_eq!(probe_timeout(Duration::from_secs(1)), Duration::from_secs(1));
        assert_eq!(probe_timeout(Duration::from_secs(3600)), Duration::from_secs(10));
    }

    #[test]
    fn demotes_after_failures_in_a_row() {
        let fleet = Fleet::new(vec![node("wss://sfu.example.com")]);
        let fail = || Err(anyhow!("unreachable"));
        assert!(fleet.available());

        fleet.observe(0, fail());
        assert!(fleet.available(), "one blip isn't enough");
        fleet.observe(0, Ok(()));
        fleet.observe(0, fail());
        assert!(fleet.available(), "a success in between starts the count again");

        fleet.observe(0, fail());
        assert!(!fleet.available());
        assert_eq!(fleet.select(&room(1)), None);

        fleet.observe(0, Ok(()));
        assert!(fleet.available());
        assert!(fleet.select(&room(1)).is_some());
    }

    #[test]
    fn places_rooms_only_on_healthy_nodes() {
        let fleet = Fleet::new(nodes());
        let first = fleet.select(&room(7)).unwrap().clone();
        let index = fleet.nodes().iter().position(|node| *node == first).unwrap();
        fleet.observe(index, Err(anyhow!("down")));
        fleet.observe(index, Err(anyhow!("down")));
        let second = fleet.select(&room(7)).unwrap();
        assert_ne!(*second, first);
    }
}
