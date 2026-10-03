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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Where every service is served from. They share one origin: the web
    /// app has the paths, the relay WebSocket upgrades and NIP-11 requests
    /// to `/`, and the Blossom server its own endpoints (see [`crate::routes`]).
    /// Unset, `127.0.0.1:8080` for a reverse proxy to reach, or `[::]:443`
    /// when armada serves TLS itself; see [`Config::listen`].
    pub listen: Option<SocketAddr>,
    /// The origin clients reach armada at, like `https://armada.example.com`:
    /// what Blossom blob URLs are built on, and the domain `server` tags in
    /// Blossom tokens must name. Unset, it's taken from each request's `Host`
    /// and `X-Forwarded-Proto`.
    pub public_url: Option<String>,
    /// Shared by every service: each keeps its database in a directory of its
    /// own beneath this, and blobs live in one store they all use. Relative to
    /// the config file's directory; unset, [`Environment::default_storage_dir`].
    pub storage_dir: Option<PathBuf>,
    /// Whether a reverse proxy of the operator's sits in front of armada, so
    /// the client's address is the rightmost `X-Forwarded-For` entry — the
    /// one that proxy appended — rather than the socket peer. Unset, it's on
    /// when `listen` is a loopback address, since then nothing but a local
    /// proxy can reach armada at all.
    pub trust_proxy: Option<bool>,
    pub web: WebConfig,
    pub relay: RelayConfig,
    pub blossom: BlossomConfig,
    pub av: AvConfig,
    pub tls: TlsConfig,
}

/// HTTPS served by armada itself, with a certificate it gets and renews
/// over ACME, so no reverse proxy is needed in front.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    /// Get a certificate for `public_url`'s domain, renew it, and serve
    /// HTTPS on `listen`. Off, armada serves plain HTTP for a proxy to front.
    pub acme: bool,
    /// An address the CA may write to about the certificate, if any.
    pub email: Option<String>,
    /// The ACME directory to get certificates from: Let's Encrypt's by
    /// default, or its staging one to try things out without its rate limits.
    pub directory: String,
    /// Also listen on `http_listen`, redirecting everything to HTTPS and
    /// answering the CA's HTTP-01 challenges.
    pub redirect_http: bool,
    pub http_listen: SocketAddr,
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
    /// Connections one client may have open at once, by IPv4 address or
    /// IPv6 /64. 0 for no limit.
    pub max_connections_per_ip: usize,
    /// Events one client may publish a minute across all its connections,
    /// in bursts of as many, by IPv4 address or IPv6 /64. 0 for no limit.
    pub events_per_minute_per_ip: u32,
    /// Pubkeys one connection may authenticate as. Armada authenticates as
    /// each Concord stream key it reads, as well as its user.
    pub max_authed_keys: usize,
    /// The most the database may grow to, in bytes. Address space reserved,
    /// not disk used, so generous is free.
    pub map_size: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BlossomConfig {
    /// Bytes one blob may be.
    pub max_blob_size: u64,
    /// Uploads and mirrors one client may start a minute, by IPv4 address
    /// or IPv6 /64. 0 for no limit.
    pub uploads_per_minute: u32,
    /// Bytes one client may upload or mirror an hour, by IPv4 address or
    /// IPv6 /64: at least `max_blob_size`, or 0 for no limit.
    pub upload_bytes_per_hour: u64,
}

/// A blind Concord AV broker (CORD-07 §2), handing out seats on LiveKit
/// servers run alongside. Off unless at least one node is configured.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AvConfig {
    /// The LiveKit servers rooms are placed on. Each is an independent
    /// deployment; a room's name picks which one it lands on.
    pub nodes: Vec<AvNode>,
    /// Seconds a LiveKit token lasts. Clients use one for a whole call and
    /// never fetch another, so it must outlive a long call.
    pub token_ttl: u64,
    /// Seconds a grant's `created_at` may be from now, either way.
    pub max_skew: u64,
    /// Seconds a grant's id is remembered, to refuse it a second time. At
    /// least 240 (§2), and at least twice `max_skew`.
    pub replay_ttl: u64,
    /// Token requests one client may make a minute, by IPv4 address or
    /// IPv6 /64.
    pub rate_limit_per_minute: u32,
    /// Seconds between health checks of each node.
    pub health_interval: u64,
}

/// One LiveKit server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvNode {
    /// The `wss://` URL clients connect to: a bare origin, since the LiveKit
    /// SDK appends `/rtc` itself.
    pub url: String,
    /// Where its server API is reached, for health checks: by default `url`
    /// with `https://` for `wss://`. Set it to reach a node on the same box
    /// or network directly, like `http://127.0.0.1:7880`.
    pub api_url: Option<String>,
    pub api_key: String,
    pub api_secret: String,
}

/// The longest an AV token may last. It's a bearer credential for a seat.
pub const MAX_AV_TOKEN_TTL: u64 = 24 * 60 * 60;

/// Let's Encrypt's production directory.
pub const LETS_ENCRYPT: &str = "https://acme-v02.api.letsencrypt.org/directory";

impl Default for TlsConfig {
    fn default() -> Self {
        TlsConfig {
            acme: false,
            email: None,
            directory: LETS_ENCRYPT.into(),
            redirect_http: true,
            http_listen: (std::net::Ipv6Addr::UNSPECIFIED, 80).into(),
        }
    }
}

impl Default for AvConfig {
    fn default() -> Self {
        AvConfig {
            nodes: Vec::new(),
            token_ttl: 6 * 60 * 60,
            max_skew: 60,
            replay_ttl: 240,
            rate_limit_per_minute: 60,
            health_interval: 15,
        }
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        WebConfig {
            nsite: DEFAULT_NSITE.into(),
            auto_update: true,
            relays: vec!["wss://relay.ditto.pub".into(), "wss://relay.dreamith.to".into()],
            resync_interval: 600,
            max_file_size: 100 << 20,
            max_site_size: 1 << 30,
        }
    }
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            max_message_length: 2 << 20,
            max_subscriptions: 32,
            max_filters: 16,
            max_limit: 500,
            max_event_tags: 2000,
            max_content_length: 1 << 20,
            created_at_upper_limit: 900,
            events_per_minute: 600,
            max_connections_per_ip: 50,
            events_per_minute_per_ip: 1200,
            max_authed_keys: 2000,
            map_size: 256 << 30,
        }
    }
}

impl Default for BlossomConfig {
    fn default() -> Self {
        BlossomConfig { max_blob_size: 100 << 20, uploads_per_minute: 60, upload_bytes_per_hour: 1 << 30 }
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

    /// Where everything is served from; see [`Config::listen`].
    pub fn listen(&self) -> SocketAddr {
        match self.listen {
            Some(listen) => listen,
            None if self.tls.acme => (std::net::Ipv6Addr::UNSPECIFIED, 443).into(),
            None => ([127, 0, 0, 1], 8080).into(),
        }
    }

    /// The domain to get a certificate for, if armada serves TLS itself.
    /// Checked when the config is loaded.
    pub fn acme_domain(&self) -> Option<String> {
        if !self.tls.acme {
            return None;
        }
        self.public_url().ok().flatten().and_then(|url| url.domain().map(str::to_string))
    }

    /// Whether to believe `X-Forwarded-For`; see [`Config::trust_proxy`].
    pub fn trusts_proxy(&self) -> bool {
        self.trust_proxy.unwrap_or_else(|| self.listen().ip().is_loopback())
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
        if self.web.resync_interval == 0 {
            bail!("web.resync_interval has to be at least 1 second.");
        }
        let relay = &self.relay;
        if relay.max_message_length < 1024 {
            bail!("relay.max_message_length has to be at least 1024 bytes.");
        }
        if relay.max_subscriptions == 0 || relay.max_filters == 0 || relay.max_limit == 0 || relay.max_authed_keys == 0 {
            bail!("relay.max_subscriptions, relay.max_filters, relay.max_limit, and relay.max_authed_keys have to be at least 1.");
        }
        if relay.map_size < 1 << 24 || usize::try_from(relay.map_size).is_err() {
            bail!("relay.map_size has to be at least 16 MiB, and fit in this machine's address space.");
        }
        self.public_url()?;
        if self.blossom.max_blob_size < crate::blossom::sniff::MIN_SIZE {
            bail!("blossom.max_blob_size is smaller than any encrypted blob could be.");
        }
        if self.blossom.upload_bytes_per_hour != 0 && self.blossom.upload_bytes_per_hour < self.blossom.max_blob_size {
            bail!("blossom.upload_bytes_per_hour has to be at least blossom.max_blob_size, or 0 for no limit.");
        }
        self.validate_av()?;
        self.validate_tls()?;
        Ok(())
    }

    fn validate_tls(&self) -> Result<()> {
        let tls = &self.tls;
        if !tls.acme {
            return Ok(());
        }
        // The certificate is for the domain clients reach armada at, and
        // nothing else can say what that is.
        let Some(url) = self.public_url()? else {
            bail!("public_url has to be set for tls.acme: it names the domain to get a certificate for.");
        };
        if url.scheme() != "https" || url.port().is_some() {
            bail!("public_url has to be https:// on the default port for tls.acme: {url}");
        }
        if url.domain().is_none_or(|domain| !domain.contains('.')) {
            bail!("public_url has to be a public domain name for tls.acme, not an IP address: {url}");
        }
        let directory = url::Url::parse(&tls.directory).with_context(|| format!("tls.directory: not a valid URL: {}", tls.directory))?;
        if directory.scheme() != "https" {
            bail!("tls.directory has to be an https:// URL: {}", tls.directory);
        }
        if tls.email.as_deref().is_some_and(|email| !email.contains('@') || email.contains(char::is_whitespace)) {
            bail!("tls.email is not an email address.");
        }
        if tls.redirect_http && tls.http_listen.port() == self.listen().port() && tls.http_listen.ip() == self.listen().ip() {
            bail!("tls.http_listen and listen can't be the same address.");
        }
        Ok(())
    }

    fn validate_av(&self) -> Result<()> {
        let av = &self.av;
        if av.nodes.is_empty() {
            return Ok(());
        }
        // Grants are signed over the full URL the client reached, so it has
        // to be known rather than taken from headers a client could forge.
        if self.public_url.is_none() {
            bail!("public_url has to be set to offer AV: clients sign their grants over it.");
        }
        if av.token_ttl == 0 || av.max_skew == 0 || av.rate_limit_per_minute == 0 || av.health_interval == 0 {
            bail!("av.token_ttl, av.max_skew, av.rate_limit_per_minute, and av.health_interval have to be at least 1.");
        }
        if av.token_ttl > MAX_AV_TOKEN_TTL {
            bail!("av.token_ttl can be at most {MAX_AV_TOKEN_TTL} (24 hours): a token is a bearer credential.");
        }
        // An id forgotten while its grant is still fresh could be replayed.
        if av.replay_ttl < 240 || av.replay_ttl < 2 * av.max_skew {
            bail!("av.replay_ttl has to be at least 240 (CORD-07 §2), and at least twice av.max_skew.");
        }
        let mut urls = std::collections::HashSet::new();
        let public_url = self.public_url()?.expect("checked above");
        let mut local = false;
        for node in &av.nodes {
            let url = node.client_url()?;
            node.api_url()?;
            // Served on armada's own origin, with /rtc forwarded to it.
            if node.is_on(&public_url) {
                if std::mem::replace(&mut local, true) {
                    bail!("av.nodes: only one node can be on armada's own origin, {url}.");
                }
                if !node.api_url.as_deref().is_some_and(|api_url| api_url.trim().starts_with("http://")) {
                    bail!("av.nodes: {url} is armada's own origin, so its signaling is forwarded to the node: it needs an http:// api_url to forward to, like http://127.0.0.1:7880.");
                }
            }
            if node.api_key.is_empty() || node.api_secret.is_empty() {
                bail!("av.nodes: {url} needs an api_key and an api_secret.");
            }
            // The URL is a node's identity: it keys its health and its rank.
            if !urls.insert(url.clone()) {
                bail!("av.nodes: {url} is listed twice.");
            }
        }
        Ok(())
    }
}

impl AvNode {
    /// `url`, checked, without a trailing slash.
    pub fn client_url(&self) -> Result<String> {
        let value = self.url.trim().trim_end_matches('/');
        let url = url::Url::parse(value).with_context(|| format!("av.nodes: not a valid URL: {}", self.url))?;
        if url.scheme() != "wss" && url.scheme() != "ws" {
            bail!("av.nodes: a node's url has to start with wss:// or ws://: {}", self.url);
        }
        if url.path().ends_with("/rtc") {
            bail!("av.nodes: a node's url can't end in /rtc, which the LiveKit SDK appends itself: {}", self.url);
        }
        Ok(value.to_string())
    }

    /// Whether clients reach the node on `origin`, the `ws(s)://` form of
    /// armada's public URL, so armada forwards its signaling.
    pub fn is_on(&self, origin: &url::Url) -> bool {
        let Ok(url) = self.client_url() else { return false };
        let Ok(mut url) = url::Url::parse(&url) else { return false };
        let scheme = if url.scheme() == "wss" { "https" } else { "http" };
        url.set_scheme(scheme).is_ok() && url.path() == "/" && url.origin() == origin.origin()
    }

    /// The base of the node's server API, without a trailing slash.
    pub fn api_url(&self) -> Result<String> {
        let value = match &self.api_url {
            Some(api_url) => api_url.trim().trim_end_matches('/').to_string(),
            None => {
                let client = self.client_url()?;
                match client.strip_prefix("wss://") {
                    Some(rest) => format!("https://{rest}"),
                    None => format!("http://{}", client.trim_start_matches("ws://")),
                }
            }
        };
        let url = url::Url::parse(&value).with_context(|| format!("av.nodes: not a valid api_url: {value}"))?;
        if url.scheme() != "https" && url.scheme() != "http" {
            bail!("av.nodes: an api_url has to start with https:// or http://: {value}");
        }
        Ok(value)
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
        assert_eq!(config.listen().port(), 8080);
        assert!(!config.tls.acme);
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
        assert_eq!(config.listen().port(), 80);
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
        assert!(Config::parse("[blossom]\nupload_bytes_per_hour = 1048576").is_err());
        assert!(Config::parse("[blossom]\nupload_bytes_per_hour = 0").is_ok());
        assert!(Config::parse("[relay]\nmax_limit = 0").is_err());
        assert!(Config::parse("[relay]\nmap_size = 1024").is_err());
        let config = Config::parse("public_url = \"https://Armada.Example.com/\"").unwrap();
        assert_eq!(config.public_url().unwrap().unwrap().host_str(), Some("armada.example.com"));
        assert!(Config::load(Some(Path::new("/nonexistent/armada.toml")), &Environment::default()).is_err());
    }

    const NODE: &str = "[[av.nodes]]\nurl = \"wss://sfu.example.com/\"\napi_key = \"k\"\napi_secret = \"s\"\n";

    #[test]
    fn av() {
        // Off by default, and needing nothing then.
        assert!(Config::parse("").unwrap().av.nodes.is_empty());

        let config = Config::parse(&format!("public_url = \"https://armada.example.com\"\n{NODE}")).unwrap();
        let node = &config.av.nodes[0];
        assert_eq!(node.client_url().unwrap(), "wss://sfu.example.com");
        assert_eq!(node.api_url().unwrap(), "https://sfu.example.com");

        let local = "[[av.nodes]]\nurl = \"ws://localhost:7880\"\napi_url = \"http://127.0.0.1:7880/\"\napi_key = \"k\"\napi_secret = \"s\"\n";
        let config = Config::parse(&format!("public_url = \"https://armada.example.com\"\n{local}")).unwrap();
        assert_eq!(config.av.nodes[0].api_url().unwrap(), "http://127.0.0.1:7880");

        // Grants are signed over the public URL, so it can't be guessed at.
        assert!(Config::parse(NODE).is_err());
        let with = |extra: &str| Config::parse(&format!("public_url = \"https://armada.example.com\"\n[av]\n{extra}\n{NODE}"));
        assert!(with("replay_ttl = 239").is_err());
        assert!(with("max_skew = 200").is_err());
        assert!(with("max_skew = 120").is_ok());
        assert!(with("token_ttl = 86401").is_err());
        assert!(with("token_ttl = 0").is_err());
        assert!(with("rate_limit_per_minute = 0").is_err());

        let node = |url: &str| format!("public_url = \"https://a.example.com\"\n[[av.nodes]]\nurl = \"{url}\"\napi_key = \"k\"\napi_secret = \"s\"\n");
        assert!(Config::parse(&node("https://sfu.example.com")).is_err());
        assert!(Config::parse(&node("wss://sfu.example.com/rtc")).is_err());
        let twice = format!("public_url = \"https://a.example.com\"\n{NODE}{NODE}");
        assert!(Config::parse(&twice).unwrap_err().to_string().contains("listed twice"));
        assert!(Config::parse("public_url = \"https://a.example.com\"\n[[av.nodes]]\nurl = \"wss://sfu.example.com\"\napi_key = \"k\"\napi_secret = \"\"").is_err());
    }

    #[test]
    fn av_on_armadas_own_origin() {
        let node = |url: &str, api_url: Option<&str>| {
            let api_url = api_url.map(|api_url| format!("api_url = \"{api_url}\"\n")).unwrap_or_default();
            format!("[[av.nodes]]\nurl = \"{url}\"\n{api_url}api_key = \"k\"\napi_secret = \"s\"\n")
        };
        let parse = |nodes: &[String]| Config::parse(&format!("public_url = \"https://armada.example.com\"\n{}", nodes.concat()));
        let local = node("wss://armada.example.com/", Some("http://127.0.0.1:7880"));
        let config = parse(std::slice::from_ref(&local)).unwrap();
        let public_url = config.public_url().unwrap().unwrap();
        assert!(config.av.nodes[0].is_on(&public_url));
        assert!(parse(&[local.clone(), node("wss://sfu.example.com", None)]).is_ok());

        // Forwarded to its API, which can't be left to default to armada itself.
        assert!(parse(&[node("wss://armada.example.com", None)]).is_err());
        assert!(parse(&[node("wss://armada.example.com", Some("https://sfu.internal"))]).is_err());
        assert!(parse(&[local.clone(), node("wss://armada.example.com", Some("http://127.0.0.1:7881"))]).is_err());
        // Another port, scheme, or path is another place.
        let elsewhere = Config::parse(&format!("public_url = \"https://armada.example.com\"\n{}", node("wss://armada.example.com:7880", None))).unwrap();
        assert!(!elsewhere.av.nodes[0].is_on(&public_url));
        let elsewhere = Config::parse(&format!("public_url = \"https://armada.example.com\"\n{}", node("ws://armada.example.com", None))).unwrap();
        assert!(!elsewhere.av.nodes[0].is_on(&public_url));
        let elsewhere = Config::parse(&format!("public_url = \"https://armada.example.com\"\n{}", node("wss://armada.example.com/sfu", None))).unwrap();
        assert!(!elsewhere.av.nodes[0].is_on(&public_url));
    }

    #[test]
    fn trusts_a_proxy_only_in_front_of_loopback() {
        assert!(Config::parse("").unwrap().trusts_proxy());
        assert!(!Config::parse("listen = \"0.0.0.0:8080\"").unwrap().trusts_proxy());
        assert!(Config::parse("listen = \"0.0.0.0:8080\"\ntrust_proxy = true").unwrap().trusts_proxy());
        assert!(!Config::parse("trust_proxy = false").unwrap().trusts_proxy());
    }

    #[test]
    fn the_example_is_the_defaults() {
        let example = Config::parse(include_str!("../armada.example.toml")).unwrap();
        assert_eq!(format!("{example:?}"), format!("{:?}", Config::default()));
    }

    #[test]
    fn tls() {
        let config = Config::parse("public_url = \"https://armada.example.com\"\n[tls]\nacme = true").unwrap();
        assert_eq!(config.acme_domain().as_deref(), Some("armada.example.com"));
        assert_eq!(config.listen(), "[::]:443".parse().unwrap());
        assert_eq!(config.tls.http_listen, "[::]:80".parse().unwrap());
        // Reached directly, so nothing forwarded is believed.
        assert!(!config.trusts_proxy());
        assert_eq!(Config::parse("public_url = \"https://armada.example.com\"").unwrap().acme_domain(), None);

        let with = |url: &str, extra: &str| Config::parse(&format!("public_url = \"{url}\"\n[tls]\nacme = true\n{extra}"));
        assert!(Config::parse("[tls]\nacme = true").is_err());
        assert!(with("http://armada.example.com", "").is_err());
        assert!(with("https://armada.example.com:8443", "").is_err());
        assert!(with("https://203.0.113.5", "").is_err());
        assert!(with("https://localhost", "").is_err());
        assert!(with("https://a.example.com", "directory = \"http://acme.example.com/dir\"").is_err());
        assert!(with("https://a.example.com", "email = \"nope\"").is_err());
        assert!(with("https://a.example.com", "email = \"ops@example.com\"").is_ok());
        assert!(with("https://a.example.com", "http_listen = \"[::]:443\"").is_err());
        assert!(with("https://a.example.com", "http_listen = \"[::]:443\"\nredirect_http = false").is_ok());
        let config = Config::parse("listen = \"0.0.0.0:8443\"\npublic_url = \"https://a.example.com\"\n[tls]\nacme = true").unwrap();
        assert_eq!(config.listen().port(), 8443);
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
