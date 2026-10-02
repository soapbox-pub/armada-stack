//! The one configuration file every service reads.
//!
//! TOML, at [`DEFAULT_PATH`] unless `--config` names another. A missing file
//! at the default path means "all defaults", so `./armada` runs out of the
//! box; a missing file the operator named is an error, since they clearly
//! meant something by it.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::nsite::NsiteAddress;

pub const DEFAULT_PATH: &str = "/etc/armada/armada.toml";

/// Armada's official nsite, published by Team Soapbox.
pub const DEFAULT_NSITE: &str = "naddr1qvzqqqyf8qpzq7q6z5ns2hm5c8msyv83qwzxpxe52j8c4d4q5m92wsp9sflelkh9qqrxzundv9jxz0nw9gl";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Shared by every service: each keeps its database in a directory of its
    /// own beneath this, and blobs live in one store they all use.
    pub storage_dir: PathBuf,
    pub web: WebConfig,
    pub relay: RelayConfig,
    pub blossom: BlossomConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
    pub listen: SocketAddr,
    /// The nsite to serve: an `naddr` (kind 35128 or 15128), or an `npub` for
    /// that author's root site.
    pub nsite: String,
    /// Follow the site as its author publishes new versions. Off, the first
    /// version deployed is served for good.
    pub auto_update: bool,
    /// Relays to look for the site's manifest on, alongside its author's own.
    pub relays: Vec<String>,
    /// Blossom servers to try after the ones the manifest and its author name.
    pub blossom_servers: Vec<String>,
    /// Serve `/index.html` for document paths the site has no file for, as a
    /// client-side router expects.
    pub spa: bool,
    /// Seconds between full re-fetches of the manifest, which catch anything
    /// the live subscription missed.
    pub resync_interval: u64,
    /// Bytes one file may be.
    pub max_file_size: u64,
    /// Bytes one version of the site may be, all files together.
    pub max_site_size: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RelayConfig {
    pub listen: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlossomConfig {
    pub listen: SocketAddr,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            storage_dir: PathBuf::from("/var/lib/armada"),
            web: WebConfig::default(),
            relay: RelayConfig::default(),
            blossom: BlossomConfig::default(),
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            listen: ([127, 0, 0, 1], 8080).into(),
            nsite: DEFAULT_NSITE.into(),
            auto_update: true,
            relays: vec!["wss://relay.ditto.pub".into(), "wss://relay.dreamith.to".into()],
            blossom_servers: vec![
                "https://blossom.ditto.pub/".into(),
                "https://blossom.dreamith.to/".into(),
                "https://blossom.primal.net/".into(),
            ],
            spa: true,
            resync_interval: 600,
            max_file_size: 100 << 20,
            max_site_size: 1 << 30,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig { listen: ([127, 0, 0, 1], 7777).into() }
    }
}

impl Default for BlossomConfig {
    fn default() -> Self {
        BlossomConfig { listen: ([127, 0, 0, 1], 24242).into() }
    }
}

impl Config {
    /// Read the configuration from `path`, or from [`DEFAULT_PATH`] if it
    /// exists, or else use the defaults.
    pub fn load(path: Option<&Path>) -> Result<Config> {
        let config = match path {
            Some(path) => Self::read(path)?,
            None if Path::new(DEFAULT_PATH).exists() => Self::read(Path::new(DEFAULT_PATH))?,
            None => Config::default(),
        };
        config.validate()?;
        Ok(config)
    }

    fn read(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("Could not read the config file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("{} is not a valid config file", path.display()))
    }

    #[cfg(test)]
    pub fn parse(text: &str) -> Result<Config> {
        let config: Config = toml::from_str(text)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        self.web.address()?;
        for relay in &self.web.relays {
            parse_relay_url(relay)?;
        }
        for server in &self.web.blossom_servers {
            let url = url::Url::parse(server).with_context(|| format!("web.blossom_servers: not a valid URL: {server}"))?;
            if url.scheme() != "https" && url.scheme() != "http" {
                bail!("web.blossom_servers: a Blossom server URL has to start with https:// or http://: {server}");
            }
        }
        if self.web.resync_interval == 0 {
            bail!("web.resync_interval has to be at least 1 second.");
        }

        let listeners = [("web", self.web.listen), ("relay", self.relay.listen), ("blossom", self.blossom.listen)];
        for (i, (a, address)) in listeners.iter().enumerate() {
            for (b, other) in &listeners[i + 1..] {
                if address == other && address.port() != 0 {
                    bail!("{a}.listen and {b}.listen are both {address}. Give each service its own port.");
                }
            }
        }
        Ok(())
    }
}

impl WebConfig {
    /// The site `nsite` names. Checked when the config is loaded, so later
    /// callers can rely on it.
    pub fn address(&self) -> Result<NsiteAddress> {
        NsiteAddress::parse(&self.nsite).map_err(|error| anyhow::anyhow!("web.nsite: {error}"))
    }

    /// The configured relays, in the one spelling the pool compares them by.
    pub fn relay_urls(&self) -> Vec<String> {
        self.relays.iter().filter_map(|relay| parse_relay_url(relay).ok()).collect()
    }
}

/// A relay URL with the trailing slash of a bare origin dropped, since
/// `wss://relay.example.com/` and `wss://relay.example.com` are one relay.
/// `ws://` is allowed here, unlike for relays an author names, so a relay on
/// the same box or LAN can be used.
pub fn parse_relay_url(input: &str) -> Result<String> {
    let value = input.trim();
    let url = url::Url::parse(value).with_context(|| format!("Not a valid relay URL: {value}"))?;
    if url.scheme() != "wss" && url.scheme() != "ws" {
        bail!("A relay URL has to start with wss:// or ws://: {value}");
    }
    let serialized = url.to_string();
    Ok(serialized.strip_suffix('/').map(str::to_string).unwrap_or(serialized))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.web.listen.port(), 8080);
        assert_eq!(config.relay.listen.port(), 7777);
        assert_eq!(config.blossom.listen.port(), 24242);
        assert!(config.web.auto_update);
        assert_eq!(config.web.relay_urls(), ["wss://relay.ditto.pub", "wss://relay.dreamith.to"]);

        let address = config.web.address().unwrap();
        assert_eq!(address.pubkey, "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5");
        assert_eq!(address.kind, 35128);
        assert_eq!(address.identifier, "armada");
    }

    #[test]
    fn overrides() {
        let config = Config::parse(
            r#"
            storage_dir = "/srv/armada"
            [web]
            auto_update = false
            relays = ["ws://localhost:7777/"]
            "#,
        )
        .unwrap();
        assert_eq!(config.storage_dir, Path::new("/srv/armada"));
        assert!(!config.web.auto_update);
        assert_eq!(config.web.relay_urls(), ["ws://localhost:7777"]);
        assert_eq!(config.web.listen.port(), 8080);
    }

    #[test]
    fn refuses_mistakes() {
        assert!(Config::parse("[web]\nnsite = \"nope\"").is_err());
        assert!(Config::parse("[web]\nrelays = [\"https://relay.example.com\"]").is_err());
        assert!(Config::parse("[web]\nlisten = \"127.0.0.1:7777\"").is_err());
        assert!(Config::parse("[web]\ntypo = 1").is_err());
        assert!(Config::load(Some(Path::new("/nonexistent/armada.toml"))).is_err());
    }
}
