//! `window.ENV` for the web app: the script that points Armada at this
//! armada's own relay, Blossom server, AV broker and push service, and makes
//! its relay a home for new Concord communities.
//!
//! Armada reads its deployment settings through `config(name)`, which takes a
//! string on `window.ENV` over the value its build baked in. A tag loading
//! [`ENV_PATH`] goes into every page when a version goes live (see
//! [`super::inject`]); the script itself is written per request, since
//! without `public_url` the origin it names is the request's.
//!
//! Unconfigured, it adds armada's own services to Armada's public ones, so
//! a new user gets both. `[web.env]` replaces any of them by name — say
//! `RELAYS = "wss://armada.example.com"` for this relay alone — and sets
//! anything else Armada reads.
//!
//! These are defaults for a new install, not settings: once a user's synced
//! settings arrive, their lists win, and what this armada seeded travels to
//! their other devices. That's intended. So is `PUBLIC_WEB_ORIGIN` being this
//! armada's own URL: it's its own deployment, so a link to armada.buzz is a
//! link elsewhere.

use std::collections::BTreeMap;

use http::HeaderMap;

use crate::config::Config;
use crate::origin::{Names, Origin, public_origin};

/// Where the script is served. Out of the way of any path a site would use.
pub const ENV_PATH: &str = "/_armada/env.js";

/// Armada's own defaults for the lists armada adds to, from `src/lib/platform.ts`
/// and `src/lib/blossom.ts`. Setting a name replaces Armada's default rather
/// than adding to it, so they're restated here to keep using them.
///
/// `RELAYS` is every relay default at once, the backups of a user's
/// community and invite lists included, so these two public ones keep a copy
/// of those off this server. Naming relays also turns off Armada's helper
/// relays (a broadcast relay, NIP-65 indexes and a git index).
const ARMADA_RELAYS: &[&str] = &["wss://relay.ditto.pub", "wss://relay.dreamith.to"];
/// The first of `BLOSSOM_SERVERS` is preferred for uploads, so armada's own
/// goes first.
const ARMADA_BLOSSOM_SERVERS: &[&str] = &["https://blossom.ditto.pub/", "https://blossom.dreamith.to/", "https://blossom.primal.net/"];
/// `CONCORD_AV_SERVERS`' default, in `src/lib/platform.ts`.
const ARMADA_AV_SERVERS: &[&str] = &["https://armada.buzz"];

#[derive(Default)]
pub struct ClientEnv {
    names: Names,
    /// Whether this armada brokers AV.
    av: bool,
    /// The [push service](crate::push)'s pubkey, if it runs.
    push: Option<String>,
    /// `[web.env]`.
    overrides: BTreeMap<String, String>,
}

impl ClientEnv {
    pub fn new(config: &Config) -> anyhow::Result<ClientEnv> {
        Ok(ClientEnv { names: config.public_url()?.into(), av: !config.av.nodes.is_empty(), push: None, overrides: config.web.env.clone() })
    }

    /// Point the web app at the push service with this pubkey, on this
    /// relay, in place of Armada's default one.
    pub fn with_push(self, pubkey: &str) -> ClientEnv {
        ClientEnv { push: Some(pubkey.to_string()), ..self }
    }

    /// Name armada's own services on its onion to clients that came over it.
    pub fn with_onion(self, onion: Option<String>) -> ClientEnv {
        ClientEnv { names: Names::new(self.names.url.clone(), onion), ..self }
    }

    /// The names armada is reached by.
    pub fn names(&self) -> &Names {
        &self.names
    }

    /// The settings for a request: armada's own services, where it knows
    /// the origin they're reached at, under `[web.env]`.
    pub fn values(&self, headers: &HeaderMap) -> BTreeMap<String, String> {
        let mut values = public_origin(&self.names, headers).map(|origin| self.own(&origin)).unwrap_or_default();
        values.extend(self.overrides.iter().map(|(name, value)| (name.clone(), value.clone())));
        values
    }

    fn own(&self, origin: &Origin) -> BTreeMap<String, String> {
        let join = |own: String, rest: &[&str]| std::iter::once(own.as_str()).chain(rest.iter().copied()).collect::<Vec<_>>().join(",");
        let mut values = BTreeMap::from([
            ("RELAYS".to_string(), join(origin.websocket(), ARMADA_RELAYS)),
            ("BLOSSOM_SERVERS".to_string(), join(format!("{}/", origin.base), ARMADA_BLOSSOM_SERVERS)),
            // This armada, not armada.buzz, on purpose: see the module docs.
            ("PUBLIC_WEB_ORIGIN".to_string(), origin.base.clone()),
        ]);
        // Not on the onion: calls go peer to peer over WebRTC, which Tor
        // can't carry, so offering them there would only leak the client.
        if self.av && !self.names.is_onion(origin) {
            values.insert("CONCORD_AV_SERVERS".to_string(), join(origin.base.clone(), ARMADA_AV_SERVERS));
        }
        if let Some(pubkey) = &self.push {
            values.insert("NOSTR_PUSH2_PUBKEY".to_string(), pubkey.clone());
            values.insert("NOSTR_PUSH2_RELAYS".to_string(), origin.websocket());
        }
        values
    }

    /// The script for a request.
    pub fn script(&self, headers: &HeaderMap) -> String {
        script(&self.values(headers))
    }
}

/// `self.ENV = {…};` — `self` rather than `window`, so a worker could load
/// it too. U+2028 and U+2029 are escaped for engines older than ES2019,
/// where they end a line even inside a string. A `</script>` needs nothing:
/// this is a file of its own, not inline.
pub fn script(values: &BTreeMap<String, String>) -> String {
    let literal = serde_json::to_string(values).expect("strings serialize").replace('\u{2028}', "\\u2028").replace('\u{2029}', "\\u2029");
    format!("self.ENV = {literal};\n")
}

/// Whether a `[web.env]` name is one a page could read: a JavaScript
/// identifier in ASCII.
pub fn valid_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_') && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_') && name.len() <= 128
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AvNode;

    fn host(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::HOST, value.parse().unwrap());
        headers
    }

    #[test]
    fn adds_its_own_services_for_a_public_host() {
        let env = ClientEnv::new(&Config::default()).unwrap();
        let values = env.values(&host("armada.example.com"));
        assert_eq!(values["RELAYS"], "wss://armada.example.com,wss://relay.ditto.pub,wss://relay.dreamith.to");
        assert_eq!(values["BLOSSOM_SERVERS"], "https://armada.example.com/,https://blossom.ditto.pub/,https://blossom.dreamith.to/,https://blossom.primal.net/");
        assert_eq!(values["PUBLIC_WEB_ORIGIN"], "https://armada.example.com");
        // No AV or push here, so Armada keeps its own.
        assert!(!values.contains_key("CONCORD_AV_SERVERS"));
        assert!(!values.contains_key("NOSTR_PUSH2_PUBKEY"));
    }

    #[test]
    fn points_push_at_its_own_service() {
        let mut config = Config::default();
        let env = ClientEnv::new(&config).unwrap().with_push("ab");
        let values = env.values(&host("armada.example.com"));
        assert_eq!(values["NOSTR_PUSH2_PUBKEY"], "ab");
        assert_eq!(values["NOSTR_PUSH2_RELAYS"], "wss://armada.example.com");
        assert!(env.values(&host("box.lan")).is_empty());

        config.web.env = BTreeMap::from([("NOSTR_PUSH2_PUBKEY".into(), "".into())]);
        let values = ClientEnv::new(&config).unwrap().with_push("ab").values(&host("armada.example.com"));
        assert_eq!(values["NOSTR_PUSH2_PUBKEY"], "");
    }

    #[test]
    fn says_nothing_of_a_host_it_cant_vouch_for() {
        let env = ClientEnv::new(&Config::default()).unwrap();
        for value in ["localhost:8080", "192.168.1.5", "box.lan"] {
            assert!(env.values(&host(value)).is_empty(), "{value}");
        }
        assert_eq!(env.script(&HeaderMap::new()), "self.ENV = {};\n");
    }

    #[test]
    fn public_url_names_the_origin_and_av_joins() {
        let config = Config {
            public_url: Some("https://armada.example.com".into()),
            av: crate::config::AvConfig {
                nodes: vec![AvNode { url: "wss://armada.example.com".into(), api_url: None, api_key: "k".into(), api_secret: "s".into() }],
                ..Default::default()
            },
            ..Config::default()
        };
        let values = ClientEnv::new(&config).unwrap().values(&host("other.example.org"));
        assert_eq!(values["RELAYS"].split(',').next(), Some("wss://armada.example.com"));
        assert_eq!(values["CONCORD_AV_SERVERS"], "https://armada.example.com,https://armada.buzz");
    }

    #[test]
    fn the_onion_is_named_to_those_on_it_without_av() {
        let onion = "dl6nglbofs66w2ctcqp3hdgw7lgql7b5xc3dqtj3oqjrcihztrqrkjyd.onion";
        let config = Config {
            public_url: Some("https://armada.example.com".into()),
            av: crate::config::AvConfig {
                nodes: vec![AvNode { url: "wss://armada.example.com".into(), api_url: None, api_key: "k".into(), api_secret: "s".into() }],
                ..Default::default()
            },
            ..Config::default()
        };
        let env = ClientEnv::new(&config).unwrap().with_push("ab").with_onion(Some(onion.into()));
        let values = env.values(&host(onion));
        assert_eq!(values["RELAYS"].split(',').next(), Some(format!("ws://{onion}").as_str()));
        assert_eq!(values["BLOSSOM_SERVERS"].split(',').next(), Some(format!("http://{onion}/").as_str()));
        assert_eq!(values["PUBLIC_WEB_ORIGIN"], format!("http://{onion}"));
        assert_eq!(values["NOSTR_PUSH2_RELAYS"], format!("ws://{onion}"));
        assert!(!values.contains_key("CONCORD_AV_SERVERS"));
        // Everyone else still gets public_url.
        let values = env.values(&host("armada.example.com"));
        assert_eq!(values["RELAYS"].split(',').next(), Some("wss://armada.example.com"));
        assert!(values.contains_key("CONCORD_AV_SERVERS"));
    }

    #[test]
    fn overrides_replace_by_name() {
        let mut config = Config::default();
        config.web.env = BTreeMap::from([
            ("RELAYS".into(), "wss://armada.example.com".into()),
            ("CONCORD_AV_SERVERS".into(), "".into()),
            ("KLIPY_API_KEY".into(), "key".into()),
        ]);
        let env = ClientEnv::new(&config).unwrap();
        let values = env.values(&host("armada.example.com"));
        assert_eq!(values["RELAYS"], "wss://armada.example.com");
        assert_eq!(values["CONCORD_AV_SERVERS"], "");
        assert_eq!(values["KLIPY_API_KEY"], "key");
        assert_eq!(values["BLOSSOM_SERVERS"].split(',').next(), Some("https://armada.example.com/"));
        // And with no origin to go on, only what was set.
        assert_eq!(env.values(&HeaderMap::new()).len(), 3);
    }

    #[test]
    fn scripts_escape_line_separators() {
        let values = BTreeMap::from([("NOTE".to_string(), "</script>\u{2028}\"".to_string())]);
        assert_eq!(script(&values), "self.ENV = {\"NOTE\":\"</script>\\u2028\\\"\"};\n");
    }

    #[test]
    fn names() {
        for name in ["RELAYS", "_x", "a1"] {
            assert!(valid_name(name), "{name}");
        }
        for name in ["", "1A", "A-B", "a.b", "ä"] {
            assert!(!valid_name(name), "{name}");
        }
    }
}
