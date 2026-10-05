//! What each client address has open, and has published lately, across
//! all its connections. The per-connection limits in [`RelayConfig`] mean
//! nothing to a client that opens another socket; these do.
//!
//! An address, as [`crate::ratelimit::key`] puts it, is held only while it
//! has a connection open or a budget still refilling.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::Semaphore;

use crate::config::RelayConfig;
use crate::ratelimit::TokenBucket;

/// Addresses held before the first sweep for ones with nothing left to
/// remember.
const SWEEP_FLOOR: usize = 1024;

pub struct Clients {
    max_connections: usize,
    max_queries: usize,
    max_values: usize,
    events_per_minute: u32,
    reqs_per_minute: u32,
    table: Mutex<Table>,
}

struct Table {
    clients: HashMap<String, Client>,
    /// The size at which to next sweep: twice what survived the last one, so
    /// sweeping costs nothing much per connection.
    sweep_at: usize,
}

struct Client {
    connections: usize,
    /// Filter values its open subscriptions list.
    values: usize,
    events: TokenBucket,
    reqs: TokenBucket,
    /// Its queries' places, if they're limited.
    queries: Option<Arc<Semaphore>>,
}

impl Client {
    /// Holds nothing that forgetting it would give away.
    fn is_idle(&mut self, now: Instant) -> bool {
        self.connections == 0 && self.events.is_full(now) && self.reqs.is_full(now)
    }
}

/// One open connection from `key`, counted until it's dropped.
pub struct Slot {
    clients: Arc<Clients>,
    key: String,
    /// The client's queries' places, shared by all its connections, if
    /// they're limited: a query takes one before it waits for a core, so one
    /// client can't fill the queue for them.
    pub queries: Option<Arc<Semaphore>>,
    /// Filter values this connection holds of the client's.
    values: usize,
}

impl Clients {
    pub fn new(config: &RelayConfig) -> Arc<Clients> {
        Arc::new(Clients {
            max_connections: config.max_connections_per_ip,
            max_queries: config.max_queries_per_ip,
            max_values: config.max_filter_values_per_ip,
            events_per_minute: config.events_per_minute_per_ip,
            reqs_per_minute: config.reqs_per_minute_per_ip,
            table: Mutex::new(Table { clients: HashMap::new(), sweep_at: SWEEP_FLOOR }),
        })
    }

    /// Count a connection from the client keyed `key`, or `None` if it has
    /// as many open as it may.
    pub fn connect(self: &Arc<Self>, key: String, now: Instant) -> Option<Slot> {
        let mut table = self.table.lock();
        if table.clients.len() >= table.sweep_at {
            table.clients.retain(|_, client| !client.is_idle(now));
            table.sweep_at = (table.clients.len() * 2).max(SWEEP_FLOOR);
        }
        let client = table.clients.entry(key.clone()).or_insert_with(|| Client {
            connections: 0,
            values: 0,
            events: TokenBucket::new(self.events_per_minute, now),
            reqs: TokenBucket::new(self.reqs_per_minute, now),
            queries: (self.max_queries != 0).then(|| Arc::new(Semaphore::new(self.max_queries))),
        });
        if self.max_connections != 0 && client.connections >= self.max_connections {
            return None;
        }
        client.connections += 1;
        let queries = client.queries.clone();
        Some(Slot { clients: self.clone(), key, queries, values: 0 })
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.table.lock().clients.len()
    }
}

impl Slot {
    /// Spend one of the client's events, shared by all its connections.
    pub fn take_event(&self, now: Instant) -> bool {
        let mut table = self.clients.table.lock();
        table.clients.get_mut(&self.key).is_none_or(|client| client.events.take(now))
    }

    /// Hold `count` more filter values for a subscription, unless the
    /// client already holds as many as it may.
    pub fn hold_values(&mut self, count: usize) -> bool {
        let mut table = self.clients.table.lock();
        let Some(client) = table.clients.get_mut(&self.key) else { return true };
        if self.clients.max_values != 0 && client.values.saturating_add(count) > self.clients.max_values {
            return false;
        }
        client.values += count;
        self.values += count;
        true
    }

    /// Give back values a closed subscription held.
    pub fn release_values(&mut self, count: usize) {
        let count = count.min(self.values);
        self.values -= count;
        if let Some(client) = self.clients.table.lock().clients.get_mut(&self.key) {
            client.values -= count;
        }
    }

    /// Spend one of the client's REQs, shared by all its connections.
    pub fn take_req(&self, now: Instant) -> bool {
        let mut table = self.clients.table.lock();
        table.clients.get_mut(&self.key).is_none_or(|client| client.reqs.take(now))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let now = Instant::now();
        let mut table = self.clients.table.lock();
        if let Some(client) = table.clients.get_mut(&self.key) {
            client.connections -= 1;
            client.values -= self.values;
            if client.is_idle(now) {
                table.clients.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn table(max_connections: usize, events_per_minute: u32) -> Arc<Clients> {
        Clients::new(&RelayConfig { max_connections_per_ip: max_connections, events_per_minute_per_ip: events_per_minute, ..RelayConfig::default() })
    }

    #[test]
    fn caps_connections_per_client() {
        let clients = table(2, 60);
        let now = Instant::now();
        let a = clients.connect("a".into(), now).unwrap();
        let _b = clients.connect("a".into(), now).unwrap();
        assert!(clients.connect("a".into(), now).is_none());
        // Others aren't charged for it.
        assert!(clients.connect("b".into(), now).is_some());
        drop(a);
        assert!(clients.connect("a".into(), now).is_some());
        assert!(table(0, 60).connect("a".into(), now).is_some());
    }

    #[test]
    fn shares_one_event_budget() {
        let clients = table(0, 3);
        let now = Instant::now();
        let a = clients.connect("a".into(), now).unwrap();
        let b = clients.connect("a".into(), now).unwrap();
        assert!(a.take_event(now) && a.take_event(now) && b.take_event(now));
        assert!(!b.take_event(now));
        assert!(!a.take_event(now));
    }

    #[test]
    fn shares_one_req_budget() {
        let clients = Clients::new(&RelayConfig { reqs_per_minute_per_ip: 2, ..RelayConfig::default() });
        let now = Instant::now();
        let a = clients.connect("a".into(), now).unwrap();
        let b = clients.connect("a".into(), now).unwrap();
        assert!(a.take_req(now) && b.take_req(now));
        assert!(!a.take_req(now));
        // Apart from its events.
        assert!(a.take_event(now));
        assert!(b.take_req(now + std::time::Duration::from_secs(30)));
        // Remembered after disconnecting, until it refills.
        drop((a, b));
        assert_eq!(clients.len(), 1);
    }

    #[test]
    fn shares_one_budget_of_filter_values() {
        let clients = Clients::new(&RelayConfig { max_filter_values_per_ip: 10, ..RelayConfig::default() });
        let now = Instant::now();
        let mut a = clients.connect("a".into(), now).unwrap();
        let mut b = clients.connect("a".into(), now).unwrap();
        assert!(a.hold_values(6));
        assert!(!b.hold_values(5));
        assert!(b.hold_values(4));
        assert!(!a.hold_values(1));
        a.release_values(2);
        assert!(b.hold_values(2));
        // Others aren't charged for it.
        assert!(clients.connect("b".into(), now).unwrap().hold_values(10));
        // A connection's are given back when it goes.
        drop(b);
        assert!(a.hold_values(6));
        assert!(Clients::new(&RelayConfig { max_filter_values_per_ip: 0, ..RelayConfig::default() }).connect("a".into(), now).unwrap().hold_values(usize::MAX));
    }

    #[test]
    fn shares_query_places() {
        let clients = Clients::new(&RelayConfig { max_queries_per_ip: 2, ..RelayConfig::default() });
        let now = Instant::now();
        let a = clients.connect("a".into(), now).unwrap();
        let b = clients.connect("a".into(), now).unwrap();
        let _first = a.queries.clone().unwrap().try_acquire_owned().unwrap();
        let _second = b.queries.clone().unwrap().try_acquire_owned().unwrap();
        assert!(a.queries.clone().unwrap().try_acquire_owned().is_err());
        // Others aren't charged for it.
        assert!(clients.connect("b".into(), now).unwrap().queries.clone().unwrap().try_acquire_owned().is_ok());
        assert!(Clients::new(&RelayConfig { max_queries_per_ip: 0, ..RelayConfig::default() }).connect("a".into(), now).unwrap().queries.is_none());
    }

    #[test]
    fn remembers_a_spent_budget_after_disconnecting() {
        let clients = table(0, 1);
        let now = Instant::now();
        let slot = clients.connect("a".into(), now).unwrap();
        assert!(slot.take_event(now));
        drop(slot);
        // Reconnecting doesn't refill it.
        let slot = clients.connect("a".into(), now).unwrap();
        assert!(!slot.take_event(now));
        drop(slot);
        assert_eq!(clients.len(), 1);

        // An untouched budget is forgotten with the last connection.
        drop(clients.connect("b".into(), now).unwrap());
        assert_eq!(clients.len(), 1);
    }

    #[test]
    fn sweeps_idle_clients() {
        let clients = table(0, 1);
        let start = Instant::now();
        for n in 0..SWEEP_FLOOR {
            let slot = clients.connect(n.to_string(), start).unwrap();
            assert!(slot.take_event(start));
        }
        assert_eq!(clients.len(), SWEEP_FLOOR);
        // Once their budgets refill, the next arrival sweeps them away.
        let _slot = clients.connect("new".into(), start + Duration::from_secs(61)).unwrap();
        assert_eq!(clients.len(), 1);
    }
}
