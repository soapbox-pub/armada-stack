//! A per-client ceiling on token requests.
//!
//! A blind broker is an open service (§2): anyone can mint a keypair, call
//! its pubkey a room, and pass every check. So abuse is bounded by rate and
//! capacity, never by allow-listing rooms or callers, which would end the
//! blindness. This is that bound, charged before the signature check it
//! protects. A fixed window, since the cheapest accounting is the point.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant};

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

pub struct RateLimiter {
    limit: u32,
    window: Duration,
    max: usize,
    counts: HashMap<String, Window>,
    /// Keys in the order their windows opened, which with one fixed window
    /// length is the order they close in.
    order: VecDeque<(String, Instant)>,
}

struct Window {
    count: u32,
    resets: Instant,
}

impl RateLimiter {
    /// `max` bounds memory however many keys arrive in one window. Past it,
    /// the oldest are forgotten, which at worst resets an idle client early.
    pub fn new(limit: u32, window: Duration, max: usize) -> RateLimiter {
        RateLimiter { limit, window, max, counts: HashMap::new(), order: VecDeque::new() }
    }

    /// Count a request from `key`, or refuse it with the seconds until its
    /// window resets.
    pub fn admit(&mut self, key: &str, now: Instant) -> Result<(), u64> {
        while let Some((front, resets)) = self.order.front() {
            if *resets > now {
                break;
            }
            if self.counts.get(front).is_some_and(|window| window.resets == *resets) {
                self.counts.remove(front);
            }
            self.order.pop_front();
        }
        if let Some(window) = self.counts.get_mut(key) {
            if window.count >= self.limit {
                return Err((window.resets - now).as_millis().div_ceil(1000) as u64);
            }
            window.count += 1;
            return Ok(());
        }
        let resets = now + self.window;
        self.counts.insert(key.to_string(), Window { count: 1, resets });
        self.order.push_back((key.to_string(), resets));
        while self.counts.len() > self.max {
            let Some((front, resets)) = self.order.pop_front() else { break };
            if self.counts.get(&front).is_some_and(|window| window.resets == resets) {
                self.counts.remove(&front);
            }
        }
        Ok(())
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
}
