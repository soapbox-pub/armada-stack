//! Per-client ceilings, by address.
//!
//! Every service is open: anyone can mint a keypair and pass every check a
//! signature makes. So abuse is bounded by rate and capacity, keyed by the
//! one thing a client can't make up for free, its address. Addresses are
//! held in memory, only as long as a limit needs them, and never logged or
//! stored.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use axum::extract::ConnectInfo;
use http::{Extensions, HeaderMap};

/// The address a request came from. Behind a trusted proxy that's the
/// rightmost `X-Forwarded-For` entry, the one the proxy appended:
/// everything left of it came from the client, which could otherwise rotate
/// its key at will.
pub fn client_address(headers: &HeaderMap, extensions: &Extensions, trust_proxy: bool) -> Option<String> {
    if trust_proxy {
        let forwarded = headers.get_all("x-forwarded-for").iter().next_back();
        let last = forwarded.and_then(|value| value.to_str().ok()).and_then(|value| value.rsplit(',').next()).map(str::trim);
        if let Some(last) = last.filter(|last| !last.is_empty()) {
            return Some(last.to_string());
        }
    }
    extensions.get::<ConnectInfo<SocketAddr>>().map(|ConnectInfo(peer)| peer.ip().to_string())
}

/// [`key`] for the address a request came from; see [`client_address`].
pub fn client_key(headers: &HeaderMap, extensions: &Extensions, trust_proxy: bool) -> Option<String> {
    client_address(headers, extensions, trust_proxy).map(|address| key(&address))
}

/// The key a client is limited under.
///
/// An IPv6 address counts as its /64: one host is routinely delegated a
/// whole /64, and could otherwise rotate through 2^64 addresses to reset its
/// count. IPv4-mapped addresses, as a dual-stack socket reports IPv4 peers,
/// are IPv4 first — as a /64 they'd put every IPv4 client in one bucket.
/// Anything unparseable keys verbatim, never widening into a shared bucket.
pub fn key(address: &str) -> String {
    let bare = address.trim().trim_start_matches('[').trim_end_matches(']');
    let bare = bare.split('%').next().unwrap_or(bare);
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let [a, b, c, d, ..] = v6.segments();
                format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
            }
        },
        Err(_) => address.to_string(),
    }
}

/// A fixed window per key, the cheapest accounting there is. It counts
/// requests, or anything else a request costs, like bytes.
pub struct RateLimiter {
    limit: u64,
    window: Duration,
    max: usize,
    counts: HashMap<String, Window>,
    /// Keys in the order their windows opened, which with one fixed window
    /// length is the order they close in.
    order: VecDeque<(String, Instant)>,
}

struct Window {
    count: u64,
    resets: Instant,
}

impl RateLimiter {
    /// `max` bounds memory however many keys arrive in one window. Past it,
    /// the oldest are forgotten, which at worst resets an idle client early.
    pub fn new(limit: u64, window: Duration, max: usize) -> RateLimiter {
        RateLimiter { limit, window, max, counts: HashMap::new(), order: VecDeque::new() }
    }

    /// Count a request from `key`, or refuse it with the seconds until its
    /// window resets.
    pub fn admit(&mut self, key: &str, now: Instant) -> Result<(), u64> {
        self.check(key, now)?;
        self.charge(key, 1, now);
        Ok(())
    }

    /// Whether `key` has anything left this window, without spending it, or
    /// else the seconds until its window resets.
    pub fn check(&mut self, key: &str, now: Instant) -> Result<(), u64> {
        self.expire(now);
        match self.counts.get(key) {
            Some(window) if window.count >= self.limit => Err((window.resets - now).as_millis().div_ceil(1000) as u64),
            _ => Ok(()),
        }
    }

    /// Spend `cost` of `key`'s window, past its limit if need be: for costs
    /// only known once they're paid.
    pub fn charge(&mut self, key: &str, cost: u64, now: Instant) {
        self.expire(now);
        if let Some(window) = self.counts.get_mut(key) {
            window.count = window.count.saturating_add(cost);
            return;
        }
        let resets = now + self.window;
        self.counts.insert(key.to_string(), Window { count: cost, resets });
        self.order.push_back((key.to_string(), resets));
        while self.counts.len() > self.max {
            let Some((front, resets)) = self.order.pop_front() else { break };
            if self.counts.get(&front).is_some_and(|window| window.resets == resets) {
                self.counts.remove(&front);
            }
        }
    }

    fn expire(&mut self, now: Instant) {
        while let Some((front, resets)) = self.order.front() {
            if *resets > now {
                break;
            }
            if self.counts.get(front).is_some_and(|window| window.resets == *resets) {
                self.counts.remove(front);
            }
            self.order.pop_front();
        }
    }
}

/// Allows `per_minute` a minute, in bursts of up to as many. 0 is no limit.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    per_minute: u32,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(per_minute: u32, now: Instant) -> TokenBucket {
        TokenBucket { per_minute, tokens: f64::from(per_minute), last: now }
    }

    pub fn take(&mut self, now: Instant) -> bool {
        if self.per_minute == 0 {
            return true;
        }
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Whether it has refilled, so forgetting it would give nothing away.
    pub fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= f64::from(self.per_minute)
    }

    fn refill(&mut self, now: Instant) {
        let refill = now.saturating_duration_since(self.last).as_secs_f64() * f64::from(self.per_minute) / 60.0;
        self.tokens = (self.tokens + refill).min(f64::from(self.per_minute));
        self.last = self.last.max(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        assert_eq!(key("203.0.113.9"), "203.0.113.9");
        assert_eq!(key("::ffff:203.0.113.9"), "203.0.113.9");
        assert_eq!(key("::ffff:cb00:7109"), "203.0.113.9");
        assert_eq!(key("2001:db8:1:1::5"), "2001:db8:1:1::/64");
        assert_eq!(key("2001:db8:1:1:ffff:ffff:ffff:ffff"), "2001:db8:1:1::/64");
        assert_eq!(key("[2001:db8:1:2::1]"), "2001:db8:1:2::/64");
        assert_eq!(key("fe80::1%eth0"), "fe80:0:0:0::/64");
        assert_eq!(key("not an address"), "not an address");
    }

    #[test]
    fn limits_each_key_for_its_window() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(3, Duration::from_secs(60), 1000);
        for _ in 0..3 {
            assert_eq!(limiter.admit("a", start), Ok(()));
        }
        assert_eq!(limiter.admit("a", start + Duration::from_millis(500)), Err(60));
        assert_eq!(limiter.admit("a", start + Duration::from_secs(59)), Err(1));
        // Others aren't charged for it.
        assert_eq!(limiter.admit("b", start), Ok(()));
        // And it resets.
        assert_eq!(limiter.admit("a", start + Duration::from_secs(60)), Ok(()));
    }

    #[test]
    fn holds_the_table_at_its_ceiling() {
        let now = Instant::now();
        let mut limiter = RateLimiter::new(1, Duration::from_secs(60), 2);
        for key in ["a", "b", "c"] {
            assert_eq!(limiter.admit(key, now), Ok(()));
        }
        assert_eq!(limiter.counts.len(), 2);
        // The oldest was forgotten; the newest wasn't.
        assert_eq!(limiter.admit("a", now), Ok(()));
        assert!(limiter.admit("c", now).is_err());
    }

    #[test]
    fn charges_costs_paid_after_the_fact() {
        let start = Instant::now();
        let mut limiter = RateLimiter::new(100, Duration::from_secs(60), 1000);
        assert_eq!(limiter.check("a", start), Ok(()));
        limiter.charge("a", 60, start);
        assert_eq!(limiter.check("a", start), Ok(()));
        // Over, since it was already spent; then nothing more until it resets.
        limiter.charge("a", 60, start);
        assert_eq!(limiter.check("a", start + Duration::from_secs(30)), Err(30));
        assert_eq!(limiter.check("a", start + Duration::from_secs(60)), Ok(()));
    }

    #[test]
    fn buckets_refill() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(60, start);
        for _ in 0..60 {
            assert!(bucket.take(start));
        }
        assert!(!bucket.take(start));
        assert!(!bucket.is_full(start));
        assert!(bucket.take(start + Duration::from_secs(1)));
        assert!(bucket.is_full(start + Duration::from_secs(61)));
        assert!(TokenBucket::new(0, start).take(start));
    }

    #[test]
    fn believes_only_a_trusted_proxy() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", "6.6.6.6, 198.51.100.1".parse().unwrap());
        headers.append("x-forwarded-for", "203.0.113.9".parse().unwrap());
        let mut extensions = Extensions::new();
        extensions.insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4000))));
        assert_eq!(client_address(&headers, &extensions, true).as_deref(), Some("203.0.113.9"));
        assert_eq!(client_address(&headers, &extensions, false).as_deref(), Some("127.0.0.1"));
        assert_eq!(client_address(&HeaderMap::new(), &extensions, true).as_deref(), Some("127.0.0.1"));
        assert_eq!(client_address(&headers, &Extensions::new(), false), None);
    }
}
