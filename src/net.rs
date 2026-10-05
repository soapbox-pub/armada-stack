//! Whether an address is somewhere on the public internet, and a resolver that
//! only ever hands out addresses that are.
//!
//! Blob download targets come from places npanel does not control — a
//! manifest's `server` tags, the author's kind 10063 list, and any redirect
//! those servers hand back — so an nsite author can otherwise aim npanel at
//! anything reachable from the box it runs on. The status code and timing of
//! the attempt land in the deploy log, which would turn the deploy queue into
//! an internal-network scanner.
//!
//! Checking a name and then letting the HTTP client resolve it again to
//! connect would leave a race for a DNS-rebinding attacker. So the check *is*
//! the resolver: [`PublicResolver`] is what the HTTP client connects
//! through, so the address checked is the address used.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Result};

/// Whether an IP address is routable on the public internet.
pub fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => !is_private_ipv4(v4),
        IpAddr::V6(v6) => !is_private_ipv6(v6),
    }
}

/// [`is_public_address`] for text. Anything unparseable is treated as private:
/// the point is to fail closed.
#[cfg(test)]
pub fn is_public_address_str(address: &str) -> bool {
    let bare = address.split('%').next().unwrap_or("");
    bare.parse().map(is_public_address).unwrap_or(false)
}

fn is_private_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();

    a == 0 // 0.0.0.0/8, "this network"
        || a == 10 // private
        || a == 127 // loopback
        || (a == 100 && (64..=127).contains(&b)) // carrier-grade NAT
        || (a == 169 && b == 254) // link-local, incl. cloud metadata
        || (a == 172 && (16..=31).contains(&b)) // private
        || (a == 192 && b == 0 && (c == 0 || c == 2)) // protocol assignments, and TEST-NET-1
        || (a == 198 && b == 51 && c == 100) // TEST-NET-2
        || (a == 203 && b == 0 && c == 113) // TEST-NET-3
        || (a == 192 && b == 168) // private
        || (a == 198 && (b == 18 || b == 19)) // benchmarking
        || a >= 224 // multicast and reserved, incl. broadcast
}

fn is_private_ipv6(address: Ipv6Addr) -> bool {
    let groups = address.segments();
    let [first, second, ..] = groups;
    let embedded = |high: u16, low: u16| {
        is_private_ipv4(Ipv4Addr::new((high >> 8) as u8, high as u8, (low >> 8) as u8, low as u8))
    };

    // Every address that carries an IPv4 one inside it is only as public as
    // that address, since that is where a packet to it may end up.
    if groups[..5].iter().all(|&group| group == 0) {
        // ::ffff:0:0/96, IPv4-mapped.
        if groups[5] == 0xffff {
            return embedded(groups[6], groups[7]);
        }
        // ::/96, which is `::`, `::1`, and the deprecated IPv4-compatible block.
        if groups[5] == 0 {
            return true;
        }
    }
    // ::ffff:0:0:0/96, IPv4-translated (RFC 2765), which an SIIT translator
    // forwards to the IPv4 address in its last 32 bits.
    if groups[..4].iter().all(|&group| group == 0) && groups[4] == 0xffff && groups[5] == 0 {
        return embedded(groups[6], groups[7]);
    }
    // 64:ff9b::/96, NAT64's well-known prefix: a NAT64 gateway on the network
    // forwards it to the IPv4 address in its last 32 bits.
    if first == 0x64 && second == 0xff9b && groups[2..6].iter().all(|&group| group == 0) {
        return embedded(groups[6], groups[7]);
    }
    // 6to4, 2002::/16, whose next 32 bits are an IPv4 address.
    if first == 0x2002 {
        return embedded(second, groups[2]);
    }

    (first == 0x64 && second == 0xff9b) // 64:ff9b:1::/48, local-use NAT64
        || (first == 0x2001 && second == 0) // 2001::/32, Teredo, which hides its IPv4 relay
        || (first == 0x2001 && second == 0xdb8) // 2001:db8::/32, documentation
        || (first == 0x100 && groups[1..4].iter().all(|&group| group == 0)) // 100::/64, discard
        || (first & 0xfe00) == 0xfc00 // fc00::/7 unique local
        || (first & 0xffc0) == 0xfe80 // fe80::/10 link local
        || (first & 0xffc0) == 0xfec0 // fec0::/10, site local, deprecated but still routed
        || (first & 0xff00) == 0xff00 // ff00::/8 multicast
}

/// Every address `host` resolves to — or the host itself, when it is an IP
/// literal (with or without the brackets a URL keeps around IPv6).
pub async fn resolve_all(host: &str) -> Result<Vec<IpAddr>> {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }

    let addresses: Vec<IpAddr> = tokio::net::lookup_host((bare, 0)).await?.map(|addr| addr.ip()).collect();
    if addresses.is_empty() {
        return Err(anyhow!("{host} does not resolve"));
    }
    Ok(addresses)
}

/// Whether every address a URL's host resolves to is public. A name resolving
/// to both a public and a private address is refused.
pub async fn is_public_url(url: &url::Url) -> Result<bool> {
    let Some(host) = url.host_str() else {
        return Ok(false);
    };
    Ok(resolve_all(host).await?.into_iter().all(is_public_address))
}

/// A DNS resolver for `reqwest` that refuses any name with a non-public
/// address, so a connection can only ever be made to an address that passed.
pub struct PublicResolver;

impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = resolve_all(&host).await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            if !addresses.iter().copied().all(is_public_address) {
                return Err(format!("{host} is not a public address").into());
            }
            let iter: Box<dyn Iterator<Item = SocketAddr> + Send> =
                Box::new(addresses.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(iter)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_addresses() {
        for private in [
            "0.1.2.3",
            "10.0.0.1",
            "127.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.1",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "::ffff:7f00:1",
            "::ffff:0:7f00:1",
            "::ffff:0:a00:1",
            "64:ff9b::a00:1",
            "64:ff9b:1::1",
            "2002:a00:1::",
            "2001::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1%eth0",
            "fec0::1",
            "ff02::1",
            "100::1",
            "not an ip",
        ] {
            assert!(!is_public_address_str(private), "{private} should be private");
        }
        for public in ["::ffff:0:808:808", "1.1.1.1", "8.8.8.8", "192.0.78.9", "2606:4700::1111", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::"] {
            assert!(is_public_address_str(public), "{public} should be public");
        }
    }
}
