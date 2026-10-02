//! The one configuration file every service reads.
//!
//! TOML, from the file `--config` names, or else the first of
//! `$XDG_CONFIG_HOME/armada/armada.toml` (`~/.config/...`) and
//! [`SYSTEM_PATH`] that exists, or else nothing: the defaults alone are
//! enough to run, so `./armada` works out of the box. A missing file the
//! operator named is an error, since they clearly meant something by it.
//!
//! The defaults suit whoever runs it. Root keeps its data in
//! `/var/lib/armada`; anyone else in `$XDG_DATA_HOME/armada`
//! (`~/.local/share/armada`), which they can write to.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::nsite::NsiteAddress;

pub const SYSTEM_PATH: &str = "/etc/armada/armada.toml";

/// Where root keeps its data by default.
const SYSTEM_STORAGE_DIR: &str = "/var/lib/armada";

/// Armada's official nsite, published by Team Soapbox.
pub const DEFAULT_NSITE: &str = "naddr1qvzqqqyf8qpzq7q6z5ns2hm5c8msyv83qwzxpxe52j8c4d4q5m92wsp9sflelkh9qqrxzundv9jxz0nw9gl";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where every service is served from. They share one origin: the web
    /// app has the paths, the relay WebSocket upgrades and NIP-11 requests
    /// to `/`, and the Blossom server its own endpoints (see [`crate::routes`]).
    pub listen: SocketAddr,
    /// The origin clients reach armada at, like `https://armada.example.com`:
    /// what Blossom blob URLs are built on, and the domain `server` tags in
    /// Blossom tokens must name. Unset, it's taken from each request's `Host`
    /// and `X-Forwarded-Proto`.
    pub public_url: Option<String>,
    /// Shared by every service: each keeps its database in a directory of its
    /// own beneath this, and blobs live in one store they all use. Relative to
    /// the config file's directory; unset, [`Environment::default_storage_dir`].
    pub storage_dir: Option<PathBuf>,
    pub web: WebConfig,
    pub relay: RelayConfig,
    pub blossom: BlossomConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebConfig {
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
    /// Bytes one WebSocket message from a client may be.
    pub max_message_length: usize,
    /// Subscriptions one connection may have open at once.
    pub max_subscriptions: usize,
    /// Filters one REQ may have.
    pub max_filters: usize,
    /// The most events one filter returns, and how many it returns without
    /// a limit of its own.
    pub max_limit: u64,
    /// Tags one event may have.
    pub max_event_tags: usize,
    /// Bytes an event's content may be.
    pub max_content_length: usize,
    /// Seconds into the future an event's `created_at` may be.
    pub created_at_upper_limit: u64,
    /// Events one connection may publish a minute, in bursts of as many.
    /// 0 for no limit.
    pub events_per_minute: u32,
    /// The most the database may grow to, in bytes. Address space reserved,
    /// not disk used, so generous is free.
    pub map_size: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlossomConfig {
    /// Bytes one blob may be.
    pub max_blob_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: ([127, 0, 0, 1], 8080).into(),
            public_url: None,
            storage_dir: None,
            web: WebConfig::default(),
            relay: RelayConfig::default(),
            blossom: BlossomConfig::default(),
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            nsite: DEFAULT_NSITE.into(),
            auto_update: true,
            relays: vec!["wss://relay.ditto.pub".into(), "wss://relay.dreamith.to".into()],
            blossom_servers: vec![
                "https://blossom.ditto.pub/".into(),
                "https://blossom.dreamith.to/".into(),
                "https://blossom.primal.net/".into(),
            ],
            resync_interval: 600,
            max_file_size: 100 << 20,
            max_site_size: 1 << 30,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            max_message_length: 128 << 10,
            max_subscriptions: 32,
            max_filters: 16,
            max_limit: 500,
            max_event_tags: 2000,
            max_content_length: 64 << 10,
            created_at_upper_limit: 900,
            events_per_minute: 600,
            map_size: 256 << 30,
        }
    }
}

impl Default for BlossomConfig {
    fn default() -> Self {
        BlossomConfig { max_blob_size: 100 << 20 }
    }
}

/// The parts of the process's surroundings the defaults depend on. Read once,
/// and passed in, so tests can stand in any user they like.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    pub root: bool,
    pub home: Option<PathBuf>,
    pub xdg_config_home: Option<PathBuf>,
    pub xdg_data_home: Option<PathBuf>,
}

impl Environment {
    pub fn current() -> Environment {
        // The XDG spec has relative values ignored, and an empty one is unset.
        let absolute = |name: &str| std::env::var_os(name).map(PathBuf::from).filter(|path| path.is_absolute());
        Environment {
            // SAFETY: geteuid has no preconditions and cannot fail.
            root: unsafe { libc::geteuid() } == 0,
            home: absolute("HOME"),
            xdg_config_home: absolute("XDG_CONFIG_HOME"),
            xdg_data_home: absolute("XDG_DATA_HOME"),
        }
    }

    /// Config files looked for when none is named, in the order tried.
    pub fn config_candidates(&self) -> Vec<PathBuf> {
        let user = self.xdg_config_home.clone().or_else(|| self.home.as_ref().map(|home| home.join(".config")));
        user.map(|dir| dir.join("armada/armada.toml")).into_iter().chain([PathBuf::from(SYSTEM_PATH)]).collect()
    }

    /// Where data goes when the config doesn't say: somewhere the user
    /// running it can write.
    pub fn default_storage_dir(&self) -> Result<PathBuf> {
        if self.root {
            return Ok(PathBuf::from(SYSTEM_STORAGE_DIR));
        }
        let data = self.xdg_data_home.clone().or_else(|| self.home.as_ref().map(|home| home.join(".local/share")));
        match data {
            Some(dir) => Ok(dir.join("armada")),
            None => bail!("Neither HOME nor XDG_DATA_HOME is set, so there is no default place to keep data. Set storage_dir in the config file."),
        }
    }
}

/// A configuration as loaded, with what was settled about it on the way.
#[derive(Debug)]
pub struct Loaded {
    pub config: Config,
    /// The file it came from, or `None` for the defaults alone.
    pub source: Option<PathBuf>,
    /// `storage_dir` resolved: made absolute against the file's directory, or
    /// defaulted for the user running it.
    pub storage_dir: PathBuf,
}

impl Config {
    /// Read the configuration from `path`, or from the first of
    /// [`Environment::config_candidates`] that exists, or else use the
    /// defaults.
    pub fn load(path: Option<&Path>, env: &Environment) -> Result<Loaded> {
        let source = match path {
            Some(path) => Some(path.to_path_buf()),
            None => env.config_candidates().into_iter().find(|candidate| candidate.is_file()),
        };
        let config = match &source {
            Some(path) => Self::read(path)?,
            None => Config::default(),
        };
        config.validate()?;

        let storage_dir = match (&config.storage_dir, &source) {
            // Against the file, so the setting means one place however the
            // binary was started.
            (Some(dir), Some(source)) => source.parent().unwrap_or(Path::new("")).join(dir),
            (Some(dir), None) => dir.clone(),
            (None, _) => env.default_storage_dir()?,
        };
        Ok(Loaded { config, source, storage_dir })
    }

    fn read(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path).with_context(|| format!("Could not read the config file {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("{} is not a valid config file", path.display()))
    }

    /// `public_url` parsed. Checked when the config is loaded: an http(s)
    /// origin with nothing after it, since everything is served from the root.
    pub fn public_url(&self) -> Result<Option<url::Url>> {
        let Some(value) = &self.public_url else { return Ok(None) };
        let url = url::Url::parse(value.trim()).with_context(|| format!("public_url: not a valid URL: {value}"))?;
        if url.scheme() != "https" && url.scheme() != "http" {
            bail!("public_url has to start with https:// or http://: {value}");
        }
        if url.host_str().is_none() || url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
            bail!("public_url has to be an origin alone, like https://armada.example.com: {value}");
        }
        Ok(Some(url))
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
        let relay = &self.relay;
        if relay.max_message_length < 1024 {
            bail!("relay.max_message_length has to be at least 1024 bytes.");
        }
        if relay.max_subscriptions == 0 || relay.max_filters == 0 || relay.max_limit == 0 {
            bail!("relay.max_subscriptions, relay.max_filters, and relay.max_limit have to be at least 1.");
        }
        if relay.map_size < 1 << 24 || usize::try_from(relay.map_size).is_err() {
            bail!("relay.map_size has to be at least 16 MiB, and fit in this machine's address space.");
        }
        self.public_url()?;
        if self.blossom.max_blob_size < crate::blossom::sniff::MIN_SIZE {
            bail!("blossom.max_blob_size is smaller than any encrypted blob could be.");
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
        assert_eq!(config.listen.port(), 8080);
        assert_eq!(config.public_url().unwrap(), None);
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
            listen = "0.0.0.0:80"
            [web]
            auto_update = false
            relays = ["ws://localhost:7777/"]
            "#,
        )
        .unwrap();
        assert_eq!(config.storage_dir.as_deref(), Some(Path::new("/srv/armada")));
        assert!(!config.web.auto_update);
        assert_eq!(config.web.relay_urls(), ["ws://localhost:7777"]);
        assert_eq!(config.listen.port(), 80);
    }

    #[test]
    fn refuses_mistakes() {
        assert!(Config::parse("[web]\nnsite = \"nope\"").is_err());
        assert!(Config::parse("[web]\nrelays = [\"https://relay.example.com\"]").is_err());
        // Each service had a port of its own once; now they share one.
        assert!(Config::parse("[web]\nlisten = \"127.0.0.1:8080\"").is_err());
        assert!(Config::parse("[blossom]\npublic_url = \"https://example.com\"").is_err());
        assert!(Config::parse("[web]\ntypo = 1").is_err());
        assert!(Config::parse("public_url = \"ftp://example.com\"").is_err());
        assert!(Config::parse("public_url = \"https://example.com/armada\"").is_err());
        assert!(Config::parse("[blossom]\nmax_blob_size = 0").is_err());
        assert!(Config::parse("[relay]\nmax_limit = 0").is_err());
        assert!(Config::parse("[relay]\nmap_size = 1024").is_err());
        let config = Config::parse("public_url = \"https://Armada.Example.com/\"").unwrap();
        assert_eq!(config.public_url().unwrap().unwrap().host_str(), Some("armada.example.com"));
        assert!(Config::load(Some(Path::new("/nonexistent/armada.toml")), &Environment::default()).is_err());
    }

    fn user(home: &str) -> Environment {
        Environment { home: Some(home.into()), ..Environment::default() }
    }

    #[test]
    fn defaults_suit_the_user() {
        let alice = user("/home/alice");
        assert_eq!(alice.default_storage_dir().unwrap(), Path::new("/home/alice/.local/share/armada"));
        assert_eq!(alice.config_candidates(), [Path::new("/home/alice/.config/armada/armada.toml"), Path::new(SYSTEM_PATH)]);

        let xdg = Environment { xdg_config_home: Some("/cfg".into()), xdg_data_home: Some("/data".into()), ..alice.clone() };
        assert_eq!(xdg.default_storage_dir().unwrap(), Path::new("/data/armada"));
        assert_eq!(xdg.config_candidates()[0], Path::new("/cfg/armada/armada.toml"));

        let root = Environment { root: true, ..user("/root") };
        assert_eq!(root.default_storage_dir().unwrap(), Path::new("/var/lib/armada"));

        let homeless = Environment::default();
        assert!(homeless.default_storage_dir().unwrap_err().to_string().contains("Set storage_dir"));
        assert_eq!(homeless.config_candidates(), [Path::new(SYSTEM_PATH)]);
    }

    #[test]
    fn finds_the_user_config_first() {
        let home = tempfile::tempdir().unwrap();
        let env = user(home.path().to_str().unwrap());

        // Nothing written yet: the defaults, unless the box has a system config.
        if !Path::new(SYSTEM_PATH).exists() {
            let loaded = Config::load(None, &env).unwrap();
            assert_eq!(loaded.source, None);
            assert_eq!(loaded.storage_dir, home.path().join(".local/share/armada"));
        }

        let file = home.path().join(".config/armada/armada.toml");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "storage_dir = \"data\"\n[web]\nauto_update = false\n").unwrap();
        let loaded = Config::load(None, &env).unwrap();
        assert_eq!(loaded.source.as_deref(), Some(file.as_path()));
        assert!(!loaded.config.web.auto_update);
        // Relative to the file, not to wherever it was started from.
        assert_eq!(loaded.storage_dir, home.path().join(".config/armada/data"));

        std::fs::write(&file, "storage_dir = \"/srv/armada\"\n").unwrap();
        assert_eq!(Config::load(None, &env).unwrap().storage_dir, Path::new("/srv/armada"));
    }
}
