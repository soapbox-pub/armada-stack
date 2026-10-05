//! The origin clients reach armada at: `public_url` when it's configured,
//! otherwise what each request's `Host` says.
//!
//! A `Host` that names a public domain is taken to be reached over HTTPS
//! whatever the request came in on, since a public armada not serving TLS
//! itself sits behind a proxy that does, and not every proxy says so in
//! `X-Forwarded-Proto`. Anything else — loopback, an address, a single label,
//! a name only a LAN resolves — isn't public, and what it's reached over is
//! only what the request says.

use http::{HeaderMap, header};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Origin {
    /// Scheme, host and any port, like `https://armada.example.com`.
    pub base: String,
    /// The domain alone, lowercase, without its port.
    pub host: Option<String>,
}

impl Origin {
    fn of(url: &url::Url) -> Origin {
        Origin { base: url.origin().ascii_serialization(), host: url.host_str().map(str::to_ascii_lowercase) }
    }

    /// The same origin with `wss`/`ws` for its scheme, for the relay.
    pub fn websocket(&self) -> String {
        match self.base.split_once("://") {
            Some(("https", rest)) => format!("wss://{rest}"),
            Some((_, rest)) => format!("ws://{rest}"),
            None => self.base.clone(),
        }
    }
}

/// The origin to hand clients for armada's own services: `public_url`, or
/// `https://` and a public `Host`. `None` when neither says.
pub fn public_origin(public_url: Option<&url::Url>, headers: &HeaderMap) -> Option<Origin> {
    if let Some(url) = public_url {
        return Some(Origin::of(url));
    }
    let host = request_host(headers)?;
    let domain = domain(host).to_ascii_lowercase();
    is_public(&domain).then(|| Origin { base: format!("https://{}", host.to_ascii_lowercase()), host: Some(domain) })
}

/// The origin a request reached armada at: [`public_origin`] when there is
/// one, else its `Host` over `X-Forwarded-Proto`'s scheme, or `http`. A
/// request without a usable `Host` gets `http://localhost` and no domain.
pub fn request_origin(public_url: Option<&url::Url>, headers: &HeaderMap) -> Origin {
    if let Some(origin) = public_origin(public_url, headers) {
        return origin;
    }
    let Some(host) = request_host(headers) else {
        return Origin { base: "http://localhost".into(), host: None };
    };
    let forwarded = headers.get("x-forwarded-proto").and_then(|v| v.to_str().ok());
    let scheme = match forwarded.and_then(|v| v.split(',').next()).map(str::trim) {
        Some("https") => "https",
        _ => "http",
    };
    Origin { base: format!("{scheme}://{host}"), host: Some(domain(host).to_ascii_lowercase()) }
}

/// The `Host` header, if it's made only of what a host and port can be,
/// in the shape they take: a name or `[address]`, and any port in digits.
fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|host| !host.is_empty() && host.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b)))
        .filter(|host| well_formed(host))
}

fn well_formed(host: &str) -> bool {
    // The name, and what follows it: nothing, or `:` and a port.
    let (name, rest) = match host.strip_prefix('[') {
        // Only an IPv6 address goes in brackets.
        Some(rest) => match rest.split_once(']') {
            Some(split) if split.0.parse::<std::net::Ipv6Addr>().is_ok() => split,
            _ => return false,
        },
        None => host.find(':').map_or((host, ""), |at| host.split_at(at)),
    };
    let port_ok = rest.is_empty() || rest.strip_prefix(':').is_some_and(|port| port.bytes().all(|b| b.is_ascii_digit()) && port.parse::<u16>().is_ok());
    !name.is_empty() && !name.contains(['[', ']']) && port_ok
}

/// A `Host` without its port.
pub fn domain(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match host.rsplit_once(':') {
        Some((name, port)) if !name.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Suffixes of names that resolve only privately, or never (RFC 6761,
/// RFC 6762, RFC 8375, and the ones home routers hand out).
const PRIVATE_SUFFIXES: &[&str] = &["localhost", "local", "lan", "home", "internal", "intranet", "corp", "localdomain", "home.arpa", "test", "example", "invalid", "onion"];

/// Whether a domain looks like one the public internet reaches: a dotted
/// name, not an address, outside every private-use suffix.
fn is_public(domain: &str) -> bool {
    let domain = domain.trim_end_matches('.');
    if domain.parse::<std::net::IpAddr>().is_ok() || !domain.contains('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.iter().any(|label| label.is_empty() || label.starts_with('-') || label.ends_with('-')) {
        return false;
    }
    // A numeric top-level label is an address in some form `IpAddr` won't parse.
    if labels.last().is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    !PRIVATE_SUFFIXES.iter().any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::HOST, value.parse().unwrap());
        headers
    }

    #[test]
    fn public_hosts_are_https() {
        let origin = public_origin(None, &host("Armada.Example.com")).unwrap();
        assert_eq!(origin, Origin { base: "https://armada.example.com".into(), host: Some("armada.example.com".into()) });
        assert_eq!(origin.websocket(), "wss://armada.example.com");
        // Even when the proxy says otherwise: it's the proxy's leg, not the client's.
        let mut headers = host("armada.example.com:8443");
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(public_origin(None, &headers).unwrap().base, "https://armada.example.com:8443");
    }

    #[test]
    fn private_hosts_are_not_public() {
        for value in ["localhost:8080", "127.0.0.1", "[::1]:8080", "203.0.113.5", "armada", "box.lan", "nas.local", "x.home.arpa", "a.localhost", "1.2.3", "bad..name", "evil.com/x", "a.com:x.y", "a.com:443:1", "a.com:", "[a.com]", "[::1", "a]b.com"] {
            assert_eq!(public_origin(None, &host(value)), None, "{value}");
        }
        assert_eq!(public_origin(None, &HeaderMap::new()), None);
    }

    #[test]
    fn public_url_wins() {
        let url = url::Url::parse("https://armada.example.com").unwrap();
        let origin = public_origin(Some(&url), &host("other.example.org")).unwrap();
        assert_eq!(origin.base, "https://armada.example.com");
        let url = url::Url::parse("http://localhost:8080").unwrap();
        assert_eq!(public_origin(Some(&url), &HeaderMap::new()).unwrap().websocket(), "ws://localhost:8080");
    }

    #[test]
    fn requests_fall_back_to_their_own_scheme() {
        assert_eq!(request_origin(None, &host("localhost:8080")).base, "http://localhost:8080");
        let mut headers = host("box.lan");
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(request_origin(None, &headers), Origin { base: "https://box.lan".into(), host: Some("box.lan".into()) });
        assert_eq!(request_origin(None, &HeaderMap::new()), Origin { base: "http://localhost".into(), host: None });
    }

    #[test]
    fn takes_hosts_in_their_shapes() {
        for host in ["a.com", "a.com:8443", "[2001:db8::1]", "[2001:db8::1]:443", "localhost"] {
            assert!(well_formed(host), "{host}");
        }
        for host in ["a.com:x.y", "a.com:99999", "2001:db8::1", "[2001:db8::1]x", ":80", "[]:80"] {
            assert!(!well_formed(host), "{host}");
        }
    }

    #[test]
    fn domains_drop_their_port() {
        assert_eq!(domain("example.com:8080"), "example.com");
        assert_eq!(domain("[::1]:8080"), "::1");
        assert_eq!(domain("example.com"), "example.com");
    }
}
