//! Cloudflare's proxy (the "orange cloud") in front of armada.
//!
//! Then every connection comes from one of Cloudflare's addresses, and the
//! visitor's own is in `CF-Connecting-IP`, which Cloudflare sets itself,
//! overwriting any a visitor sends. So it's believed only from a peer in
//! Cloudflare's published ranges: anyone reaching armada directly could
//! write it too. (A Cloudflare Worker's requests come from those ranges as
//! well, so a Worker can still name an address of its choosing. That's the
//! limit of what the ranges can say.)

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::HeaderMap;

/// Cloudflare's ranges, from <https://api.cloudflare.com/client/v4/ips>
/// (also <https://www.cloudflare.com/ips/>), as of October 2026. They change
/// rarely; a new one means a release.
const V4: &[(Ipv4Addr, u8)] = &[
    (Ipv4Addr::new(173, 245, 48, 0), 20),
    (Ipv4Addr::new(103, 21, 244, 0), 22),
    (Ipv4Addr::new(103, 22, 200, 0), 22),
    (Ipv4Addr::new(103, 31, 4, 0), 22),
    (Ipv4Addr::new(141, 101, 64, 0), 18),
    (Ipv4Addr::new(108, 162, 192, 0), 18),
    (Ipv4Addr::new(190, 93, 240, 0), 20),
    (Ipv4Addr::new(188, 114, 96, 0), 20),
    (Ipv4Addr::new(197, 234, 240, 0), 22),
    (Ipv4Addr::new(198, 41, 128, 0), 17),
    (Ipv4Addr::new(162, 158, 0, 0), 15),
    (Ipv4Addr::new(104, 16, 0, 0), 13),
    (Ipv4Addr::new(104, 24, 0, 0), 14),
    (Ipv4Addr::new(172, 64, 0, 0), 13),
    (Ipv4Addr::new(131, 0, 72, 0), 22),
];

const V6: &[(Ipv6Addr, u8)] = &[
    (Ipv6Addr::new(0x2400, 0xcb00, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2803, 0xf800, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0xb500, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2405, 0x8100, 0, 0, 0, 0, 0, 0), 32),
    (Ipv6Addr::new(0x2a06, 0x98c0, 0, 0, 0, 0, 0, 0), 29),
    (Ipv6Addr::new(0x2c0f, 0xf248, 0, 0, 0, 0, 0, 0), 32),
];

/// Whether `ip` is one of Cloudflare's. IPv4-mapped addresses, as a
/// dual-stack socket reports IPv4 peers, count as IPv4.
pub fn is_cloudflare(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(ip) => V4.iter().any(|&(net, bits)| u32::from(ip) >> (32 - bits) == u32::from(net) >> (32 - bits)),
        IpAddr::V6(ip) => V6.iter().any(|&(net, bits)| u128::from(ip) >> (128 - bits) == u128::from(net) >> (128 - bits)),
    }
}

/// The visitor a request from `from` was proxied for, if `from` is
/// Cloudflare and says.
pub fn visitor(headers: &HeaderMap, from: IpAddr) -> Option<IpAddr> {
    if !is_cloudflare(from) {
        return None;
    }
    headers.get("cf-connecting-ip")?.to_str().ok()?.trim().parse().ok()
}

/// Whether a request from `from` was proxied by Cloudflare for a visitor who
/// came over HTTPS. Cloudflare says so in `CF-Visitor`, as
/// `{"scheme":"https"}`.
pub fn visitor_used_https(headers: &HeaderMap, from: IpAddr) -> bool {
    if !is_cloudflare(from) {
        return false;
    }
    let Some(value) = headers.get("cf-visitor").and_then(|value| value.to_str().ok()) else { return false };
    serde_json::from_str::<serde_json::Value>(value).is_ok_and(|visitor| visitor["scheme"] == "https")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn knows_cloudflares_addresses() {
        for inside in ["173.245.48.0", "173.245.63.255", "104.23.187.206", "162.159.255.255", "172.71.203.68", "2606:4700::6810:1", "2a06:98c7:ffff::1", "::ffff:162.158.154.208"] {
            assert!(is_cloudflare(ip(inside)), "{inside}");
        }
        for outside in ["173.245.64.0", "104.15.255.255", "162.160.0.0", "203.0.113.9", "127.0.0.1", "2606:4701::1", "2a06:98c8::1", "::ffff:203.0.113.9"] {
            assert!(!is_cloudflare(ip(outside)), "{outside}");
        }
    }

    #[test]
    fn believes_only_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.9".parse().unwrap());
        headers.insert("cf-visitor", r#"{"scheme":"https"}"#.parse().unwrap());
        assert_eq!(visitor(&headers, ip("172.70.111.150")), Some(ip("203.0.113.9")));
        assert!(visitor_used_https(&headers, ip("172.70.111.150")));
        // Anyone else could have written them.
        assert_eq!(visitor(&headers, ip("198.51.100.1")), None);
        assert!(!visitor_used_https(&headers, ip("198.51.100.1")));

        headers.insert("cf-connecting-ip", "2001:db8::1".parse().unwrap());
        assert_eq!(visitor(&headers, ip("2606:4700::1")), Some(ip("2001:db8::1")));
        headers.insert("cf-connecting-ip", "not an address".parse().unwrap());
        assert_eq!(visitor(&headers, ip("2606:4700::1")), None);
        assert_eq!(visitor(&HeaderMap::new(), ip("2606:4700::1")), None);

        for value in [r#"{"scheme":"http"}"#, "https", "{}"] {
            headers.insert("cf-visitor", value.parse().unwrap());
            assert!(!visitor_used_https(&headers, ip("172.70.111.150")), "{value}");
        }
    }
}
