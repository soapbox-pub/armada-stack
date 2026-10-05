//! LiveKit, built in: the SFU calls run on, carried inside armada's binary
//! so a server has calls with nothing more to install.
//!
//! LiveKit is a Go program, so it isn't linked in but embedded: a release
//! build compresses a pinned, checksummed `livekit-server` into the binary
//! (see `build.rs`). On start armada writes it out to `livekit/` in the
//! storage directory, makes it a key and secret there the first time, and
//! runs it with [`CONFIG`], restarting it if it stops. Its signaling stays on
//! loopback and armada forwards `/rtc` to it, so it's a node on armada's own
//! origin like one configured by hand; only its media ports, 7881/tcp and
//! 7882/udp, are reached directly.
//!
//! A node in `[[av.nodes]]` on armada's own origin takes its place, and
//! `[av] livekit = false` turns it off.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{AvNode, Config};
use crate::storage::Storage;
use crate::util::{random_hex, write_private};

/// LiveKit's config. Its keys come from the environment, never a file.
const CONFIG: &str = include_str!("../../deploy/livekit.yaml");

/// Where [`CONFIG`] puts LiveKit's signaling and server API.
const API_URL: &str = "http://127.0.0.1:7880";

/// The longest between restarts of a LiveKit that keeps stopping.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// How long LiveKit gets to stop on its own before it's killed.
const STOP_GRACE: Duration = Duration::from_secs(10);

/// The `livekit-server` built in: gzipped, and the sha256 of it unzipped.
struct Embedded {
    gz: &'static [u8],
    sha256: &'static str,
    version: &'static str,
}

#[cfg(armada_livekit)]
const EMBEDDED: Option<Embedded> = Some(Embedded {
    gz: include_bytes!(concat!(env!("OUT_DIR"), "/livekit.gz")),
    sha256: include_str!(concat!(env!("OUT_DIR"), "/livekit.sha256")),
    version: env!("ARMADA_LIVEKIT_VERSION"),
});
#[cfg(not(armada_livekit))]
const EMBEDDED: Option<Embedded> = None;

/// A LiveKit written out and ready to run.
pub struct LiveKit {
    dir: PathBuf,
    binary: PathBuf,
    keys: Keys,
    version: &'static str,
}

impl LiveKit {
    /// The built-in LiveKit, ready to [start](LiveKit::start), if `config`
    /// wants one and this build has one.
    pub fn prepare(config: &Config, storage: &Storage) -> Result<Option<LiveKit>> {
        if !config.av.livekit {
            return Ok(None);
        }
        let Some(embedded) = &EMBEDDED else {
            tracing::info!("this build of armada has no LiveKit built in, so AV is offered only on [[av.nodes]]");
            return Ok(None);
        };
        let Some(public_url) = config.public_url()? else {
            tracing::warn!("public_url isn't set, so the built-in LiveKit isn't started: AV grants are signed over armada's URL.");
            return Ok(None);
        };
        if let Some(node) = config.av.nodes.iter().find(|node| node.is_on(&public_url)) {
            tracing::info!(node = %node.url, "[[av.nodes]] names a node on armada's own origin, so the built-in LiveKit isn't started");
            return Ok(None);
        }
        let dir = storage.service_dir("livekit")?;
        let keys = Keys::load_or_create(&dir.join("keys"))?;
        let binary = write_binary(&dir, embedded)?;
        Ok(Some(LiveKit { dir, binary, keys, version: embedded.version }))
    }

    /// The node it is, on `public_url`'s origin.
    pub fn node(&self, public_url: &url::Url) -> AvNode {
        let origin = public_url.origin().ascii_serialization();
        let url = match origin.split_once("://") {
            Some(("https", rest)) => format!("wss://{rest}"),
            Some((_, rest)) => format!("ws://{rest}"),
            None => origin,
        };
        AvNode { url, api_url: Some(API_URL.into()), api_key: self.keys.key.clone(), api_secret: self.keys.secret.clone() }
    }

    /// Run it until `cancel` fires, restarting it whenever it stops. The
    /// task ends once LiveKit has.
    pub fn start(self, cancel: CancellationToken) -> JoinHandle<()> {
        tokio::spawn(self.supervise(cancel))
    }

    async fn supervise(self, cancel: CancellationToken) {
        let mut backoff = Duration::from_secs(1);
        loop {
            let started = Instant::now();
            match self.spawn() {
                Ok(mut child) => {
                    tracing::info!(version = self.version, "started the built-in LiveKit");
                    tokio::select! {
                        status = child.wait() => match status {
                            Ok(status) => tracing::warn!(%status, "the built-in LiveKit stopped"),
                            Err(error) => tracing::warn!(%error, "the built-in LiveKit stopped"),
                        },
                        _ = cancel.cancelled() => {
                            stop(child).await;
                            return;
                        }
                    }
                }
                Err(error) => tracing::error!("Could not start the built-in LiveKit: {error:#}"),
            }
            // One that ran a while gets restarted at once; one that keeps
            // dying, less and less often.
            if started.elapsed() > MAX_BACKOFF {
                backoff = Duration::from_secs(1);
            }
            tokio::select! {
                _ = tokio::time::sleep(backoff) => {}
                _ = cancel.cancelled() => return,
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    fn spawn(&self) -> Result<Child> {
        let config = self.dir.join("livekit.yaml");
        if std::fs::read_to_string(&config).ok().as_deref() != Some(CONFIG) {
            write_private(&config, CONFIG.as_bytes())?;
        }
        let mut child = Command::new(&self.binary)
            .arg("--config")
            .arg(&config)
            .env_clear()
            .env("LIVEKIT_KEYS", format!("{}: {}", self.keys.key, self.keys.secret))
            .current_dir(&self.dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Could not run {}", self.binary.display()))?;
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(log_lines(stdout));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(log_lines(stderr));
        }
        Ok(child)
    }
}

/// Ask LiveKit to stop, so calls end cleanly, and kill it if it won't.
async fn stop(mut child: Child) {
    if let Some(pid) = child.id() {
        // SAFETY: a plain signal to a child this process still holds, so
        // the pid can't have been reused.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
        if tokio::time::timeout(STOP_GRACE, child.wait()).await.is_ok() {
            return;
        }
    }
    let _ = child.kill().await;
}

/// Pass LiveKit's log on as armada's, at the level it gave. Its lines are
/// `<time>\t<LEVEL>\t<the rest>`; the time is armada's to give.
async fn log_lines(output: impl tokio::io::AsyncRead + Unpin) {
    let mut lines = BufReader::new(output).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut fields = line.splitn(3, '\t');
        let (level, message) = match (fields.next(), fields.next(), fields.next()) {
            (Some(_), Some(level), Some(rest)) => (level, rest),
            _ => ("INFO", line.as_str()),
        };
        match level {
            "ERROR" | "DPANIC" | "PANIC" | "FATAL" => tracing::error!(target: "livekit", "{message}"),
            "WARN" => tracing::warn!(target: "livekit", "{message}"),
            "DEBUG" => tracing::debug!(target: "livekit", "{message}"),
            _ => tracing::info!(target: "livekit", "{message}"),
        }
    }
}

/// Write the built-in binary out, named for its hash, unless it's there
/// already; and remove any other version left from before.
fn write_binary(dir: &Path, embedded: &Embedded) -> Result<PathBuf> {
    let name = format!("livekit-server-{}", &embedded.sha256[..16]);
    let path = dir.join(&name);
    if !std::fs::read(&path).is_ok_and(|bytes| sha256(&bytes) == embedded.sha256) {
        let mut binary = Vec::new();
        std::io::Read::read_to_end(&mut flate2::read::GzDecoder::new(embedded.gz), &mut binary).context("Could not unpack the built-in LiveKit")?;
        if sha256(&binary) != embedded.sha256 {
            bail!("The built-in LiveKit doesn't match its sha256.");
        }
        let temporary = dir.join(format!("{name}.tmp"));
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o700)
                .open(&temporary)
                .with_context(|| format!("Could not write {}", temporary.display()))?;
            file.write_all(&binary)?;
            file.sync_all()?;
        }
        std::fs::rename(&temporary, &path).with_context(|| format!("Could not write {}", path.display()))?;
    }
    for entry in std::fs::read_dir(dir)?.flatten() {
        let other = entry.file_name();
        let other = other.to_string_lossy();
        if other.starts_with("livekit-server-") && other != name {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    Ok(path)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// LiveKit's API key and secret, which armada signs its tokens with. Made on
/// first start and kept in `livekit/keys`, as `<key> <secret>`.
struct Keys {
    key: String,
    secret: String,
}

impl Keys {
    fn load_or_create(path: &Path) -> Result<Keys> {
        match std::fs::read_to_string(path) {
            Ok(text) => match text.split_whitespace().collect::<Vec<_>>()[..] {
                [key, secret] => Ok(Keys { key: key.into(), secret: secret.into() }),
                _ => bail!("{} isn't a LiveKit key and secret", path.display()),
            },
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                // LiveKit wants a secret of at least 32 characters.
                let keys = Keys { key: format!("API{}", random_hex(6)), secret: random_hex(32) };
                write_private(path, format!("{} {}\n", keys.key, keys.secret).as_bytes())?;
                Ok(keys)
            }
            Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makes_keys_once_and_keeps_them() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys");
        let first = Keys::load_or_create(&path).unwrap();
        assert!(first.key.starts_with("API") && first.secret.len() >= 32);
        let again = Keys::load_or_create(&path).unwrap();
        assert_eq!((first.key, first.secret), (again.key, again.secret));
        std::fs::write(&path, "nonsense").unwrap();
        assert!(Keys::load_or_create(&path).is_err());
    }

    #[test]
    fn writes_the_binary_once_and_clears_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        let program = b"#!/bin/sh\n".to_vec();
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gz, &program).unwrap();
        let gz: &'static [u8] = Box::leak(gz.finish().unwrap().into_boxed_slice());
        let sha: &'static str = Box::leak(sha256(&program).into_boxed_str());
        let embedded = Embedded { gz, sha256: sha, version: "test" };
        std::fs::write(dir.path().join("livekit-server-0000000000000000"), b"old").unwrap();

        let path = write_binary(dir.path(), &embedded).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), program);
        let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(names, vec![path.file_name().unwrap().to_owned()]);

        // A damaged copy is written again.
        std::fs::write(&path, b"damaged").unwrap();
        write_binary(dir.path(), &embedded).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), program);
    }

    #[test]
    fn its_node_is_on_armadas_origin() {
        let keys = Keys { key: "APIk".into(), secret: "s".into() };
        let livekit = LiveKit { dir: PathBuf::new(), binary: PathBuf::new(), keys, version: "test" };
        let public_url = url::Url::parse("https://armada.example.com").unwrap();
        let node = livekit.node(&public_url);
        assert_eq!(node.url, "wss://armada.example.com");
        assert!(node.is_on(&public_url));
        assert_eq!(node.api_url().unwrap(), API_URL);
    }
}
