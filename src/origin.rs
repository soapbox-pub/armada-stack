//! The origin clients reach armada at: its onion address when that's what
//! a request asked for, `public_url` when it's configured, otherwise what
//! each request's `Host` says.
//!
//! The onion comes first because a client that reached armada over Tor
//! should be pointed at its services over Tor too, not handed clearnet URLs
//! that would take it out of Tor for every relay and Blossom request. It's
//! `http`: Tor encrypts and authenticates the connection itself, and no CA
//! issues certificates for onions in the usual way.
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

/// The names armada is reached by.
#[derive(Clone, Debug, Default)]
pub struct Names {
    /// `public_url`.
    pub url: Option<url::Url>,
    /// The onion address armada publishes, if it does: `<56 letters>.onion`.
    pub onion: Option<String>,
}

impl Names {
    pub fn new(url: Option<url::Url>, onion: Option<String>) -> Names {
        Names { url, onion: onion.map(|onion| onion.to_ascii_lowercase()) }
    }

    /// Whether `origin` is the onion's.
    pub fn is_onion(&self, origin: &Origin) -> bool {
        self.onion.is_some() && origin.host == self.onion
    }

    /// Every name a relay URL may give this one by, as
    /// [`crate::relay::authority`] puts them.
    pub fn authorities(&self) -> Vec<String> {
        let url = self.url.as_ref().and_then(|url| crate::relay::authority(url.as_str()));
        url.into_iter().chain(self.onion.clone()).collect()
    }

    /// The onion's origin, if `headers` asked for it.
    fn onion_origin(&self, headers: &HeaderMap) -> Option<Origin> {
        let onion = self.onion.as_ref()?;
        // Whatever port it gives: the service answers only on 80.
        let asked = domain(request_host(headers)?).trim_end_matches('.').eq_ignore_ascii_case(onion);
        asked.then(|| Origin { base: format!("http://{onion}"), host: Some(onion.clone()) })
    }
}

impl From<Option<url::Url>> for Names {
    fn from(url: Option<url::Url>) -> Names {
        Names { url, onion: None }
    }
}

/// The origin to hand clients for armada's own services: the onion if that's
/// what was asked for, `public_url`, or `https://` and a public `Host`.
/// `None` when none of them says.
pub fn public_origin(names: &Names, headers: &HeaderMap) -> Option<Origin> {
    if let Some(origin) = names.onion_origin(headers) {
        return Some(origin);
    }
    if let Some(url) = &names.url {
        return Some(Origin::of(url));
    }
    let host = request_host(headers)?;
    let domain = domain(host).to_ascii_lowercase();
    is_public(&domain).then(|| Origin { base: format!("https://{}", host.to_ascii_lowercase()), host: Some(domain) })
}

/// The origin a request reached armada at: [`public_origin`] when there is
/// one, else its `Host` over `X-Forwarded-Proto`'s scheme, or `http`. A
/// request without a usable `Host` gets `http://localhost` and no domain.
pub fn request_origin(names: &Names, headers: &HeaderMap) -> Origin {
    if let Some(origin) = public_origin(names, headers) {
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
        let origin = public_origin(&Names::default(), &host("Armada.Example.com")).unwrap();
        assert_eq!(origin, Origin { base: "https://armada.example.com".into(), host: Some("armada.example.com".into()) });
        assert_eq!(origin.websocket(), "wss://armada.example.com");
        // Even when the proxy says otherwise: it's the proxy's leg, not the client's.
        let mut headers = host("armada.example.com:8443");
        headers.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(public_origin(&Names::default(), &headers).unwrap().base, "https://armada.example.com:8443");
    }

    #[test]
    fn private_hosts_are_not_public() {
        for value in ["localhost:8080", "127.0.0.1", "[::1]:8080", "203.0.113.5", "armada", "box.lan", "nas.local", "x.home.arpa", "a.localhost", "1.2.3", "bad..name", "evil.com/x", "a.com:x.y", "a.com:443:1", "a.com:", "[a.com]", "[::1", "a]b.com"] {
            assert_eq!(public_origin(&Names::default(), &host(value)), None, "{value}");
        }
        assert_eq!(public_origin(&Names::default(), &HeaderMap::new()), None);
    }

    #[test]
    fn public_url_wins() {
        let url = url::Url::parse("https://armada.example.com").unwrap();
        let origin = public_origin(&Names::from(Some(url.clone())), &host("other.example.org")).unwrap();
        assert_eq!(origin.base, "https://armada.example.com");
        let url = url::Url::parse("http://localhost:8080").unwrap();
        assert_eq!(public_origin(&Names::from(Some(url.clone())), &HeaderMap::new()).unwrap().websocket(), "ws://localhost:8080");
    }

    const ONION: &str = "dl6nglbofs66w2ctcqp3hdgw7lgql7b5xc3dqtj3oqjrcihztrqrkjyd.onion";

    #[test]
    fn the_onion_wins_when_its_asked_for() {
        let names = Names::new(url::Url::parse("https://armada.example.com").ok(), Some(ONION.to_uppercase()));
        for value in [ONION.to_string(), format!("{ONION}:80"), ONION.to_uppercase()] {
            let origin = public_origin(&names, &host(&value)).unwrap();
            assert_eq!(origin, Origin { base: format!("http://{ONION}"), host: Some(ONION.into()) }, "{value}");
            assert_eq!(origin.websocket(), format!("ws://{ONION}"));
            assert!(names.is_onion(&origin));
            assert_eq!(request_origin(&names, &host(&value)), origin);
        }
        // Any other host gets `public_url`, another onion included.
        let other = public_origin(&names, &host("abc.onion")).unwrap();
        assert_eq!(other.base, "https://armada.example.com");
        assert!(!names.is_onion(&other));
        assert_eq!(names.authorities(), ["armada.example.com", ONION]);
        // And without an onion of its own, an onion isn't public.
        assert_eq!(public_origin(&Names::default(), &host(ONION)), None);
        assert_eq!(Names::new(None, Some(ONION.into())).authorities(), [ONION]);
    }

    #[test]
    fn requests_fall_back_to_their_own_scheme() {
        assert_eq!(request_origin(&Names::default(), &host("localhost:8080")).base, "http://localhost:8080");
        let mut headers = host("box.lan");
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(request_origin(&Names::default(), &headers), Origin { base: "https://box.lan".into(), host: Some("box.lan".into()) });
        assert_eq!(request_origin(&Names::default(), &HeaderMap::new()), Origin { base: "http://localhost".into(), host: None });
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
