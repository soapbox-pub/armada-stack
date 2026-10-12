//! `armada upgrade`: replace this binary with the latest signed release, and
//! restart the service if one is set up, as rerunning install.sh does.
//!
//! Releases are found on Nostr and trusted only if signed by Soapbox's key.
//! The binary is checked against the sha256 in its signed release, and asked
//! its version, before it's moved into place. install.sh, where there's no
//! package manager, gets the same binary from pkg.soapbox.pub and installs it
//! with the same unit; a test keeps them alike.

use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::nostr::Event;
use crate::nostr::event::is_hex64;
use crate::nostr::pool::{Filter, Pool};
use crate::nostr::service::{blob_url, dedupe};

/// Soapbox's key: releases signed by anyone else are ignored.
const PUBKEY: &str = "781a1527055f74c1f70230f10384609b34548f8ab6a0a6caa74025827f9fdae5";
const APP: &str = "armada-stack";
const RELAYS: &[&str] = &[
    "wss://relay.ditto.pub",
    "wss://relay.dreamith.to",
    "wss://git.shakespeare.diy",
    "wss://relay.ngit.dev",
    "wss://relay.primal.net",
];
/// Asked for the binary by its hash when the URL in its release fails.
const BLOSSOM: &[&str] = &["https://blossom.ditto.pub", "https://blossom.dreamith.to", "https://blossom.primal.net"];

/// NIP-82 software release, file, and application.
const RELEASE_KIND: i64 = 30063;
const ASSET_KIND: i64 = 3063;
const APPLICATION_KIND: i64 = 32267;
/// The MIME types of the .deb and .rpm a release has beside each binary, for
/// the same platform.
const PACKAGE_TYPES: &[&str] = &["application/vnd.debian.binary-package", "application/x-rpm"];

const MAX_BINARY: u64 = 256 * 1024 * 1024;
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
/// How long a restarted service is given before it's asked if it's running.
const SETTLE_TIME: Duration = Duration::from_secs(3);

/// Where install.sh puts the binary, and the unit that runs it from there.
const BIN: &str = "/usr/local/bin/armada";
const UNIT: &str = "/etc/systemd/system/armada.service";
const DEPLOY_UNIT: &str = include_str!("../deploy/armada.service");
/// Where the .deb and .rpm put the binary, which their package manager
/// upgrades.
const PACKAGE_BIN: &str = "/usr/bin/armada";

pub struct Options {
    /// A release to install instead of the latest.
    pub version: Option<String>,
    /// Only say whether there's a newer release.
    pub check: bool,
}

pub async fn run(options: Options) -> Result<()> {
    let platform = platform()?;
    let current = env!("CARGO_PKG_VERSION");
    let exe = std::env::current_exe().context("finding this binary")?;
    if exe == Path::new(PACKAGE_BIN) {
        bail!("{PACKAGE_BIN} was installed from a package. Upgrade it the way it was installed, with apt or dnf.");
    }
    // The service runs BIN, so it's only restarted when that's what's upgraded.
    let service = service_installed();
    let runs_this = std::fs::canonicalize(BIN).is_ok_and(|bin| bin == exe);
    if !options.check && service && runs_this && euid() != 0 {
        bail!("Restarting the armada service needs root. Run: {}", sudo_upgrade(&exe));
    }

    let pool = Pool::new(Arc::new(|_: &str| true), None);
    let relays: Vec<String> = RELAYS.iter().map(|relay| relay.to_string()).collect();
    let cancel = CancellationToken::new();
    let filter = Filter { kinds: vec![RELEASE_KIND], authors: vec![PUBKEY.into()], i: vec![APP.into()], ..Default::default() };
    let releases = pool.query(vec![filter], &relays, QUERY_TIMEOUT, &cancel).await;
    let release = pick_release(&releases, PUBKEY, options.version.as_deref())?;
    let version = release.tag("version").unwrap_or_default().to_string();
    say(&format!("found {APP} {version}, signed by Soapbox"));
    // A relay that's slow or kept from answering can leave an older release
    // looking like the newest: never go back unless asked to by version.
    let older = is_older(&version, current);
    if older && options.version.is_none() {
        say(&format!("armada {current} is installed, newer than {version}: nothing to do"));
        return Ok(());
    }

    if options.check {
        if version == current {
            say(&format!("armada {current} is installed: nothing to do"));
        } else {
            say(&format!("armada {current} is installed; to install {version}, run: {}", sudo_upgrade(&exe)));
        }
        return Ok(());
    }

    let changed = if version == current {
        say(&format!("armada {current} is already installed at {}", exe.display()));
        false
    } else {
        if older {
            say(&format!("installing {version}, older than the {current} installed, as asked"));
        }
        let ids: Vec<String> = release.tags.iter().filter(|tag| tag.first().map(String::as_str) == Some("e")).filter_map(|tag| tag.get(1).cloned()).collect();
        let filter = Filter { ids, kinds: vec![ASSET_KIND], authors: vec![PUBKEY.into()], ..Default::default() };
        let assets = pool.query(vec![filter], &relays, QUERY_TIMEOUT, &cancel).await;
        let asset = pick_asset(&assets, &release, PUBKEY, &platform)?;
        install(&asset, &version, &exe).await?;
        say(&format!("installed armada {version} at {}", exe.display()));
        true
    };

    if service && runs_this {
        refresh_service(changed)?;
    } else if service && changed {
        say(&format!("the armada service runs {BIN}, not {}; leaving it alone", exe.display()));
    }
    Ok(())
}

fn say(message: &str) {
    eprintln!("armada: {message}");
}

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The release platform this binary runs on, as the `f` tag names it.
fn platform() -> Result<String> {
    if std::env::consts::OS != "linux" {
        bail!("armada's releases are for Linux.");
    }
    match std::env::consts::ARCH {
        arch @ ("x86_64" | "aarch64") => Ok(format!("linux-{arch}")),
        arch => bail!("There's no release for {arch} yet; INSTALL.md says how to build from source."),
    }
}

/// 1.2.3 as [1, 2, 3], or None for anything that isn't plain numbers.
fn version_key(version: &str) -> Option<Vec<u64>> {
    version.split('.').map(|part| part.parse().ok()).collect()
}

/// Whether `version` is older than `than`, both being plain numbers.
fn is_older(version: &str, than: &str) -> bool {
    matches!((version_key(version), version_key(than)), (Some(version), Some(than)) if version < than)
}

/// The newest release on the main channel, or the release named `wanted`.
fn pick_release(events: &[Event], pubkey: &str, wanted: Option<&str>) -> Result<Event> {
    // Each version is an addressable event, so only its newest counts.
    let mut latest: HashMap<&str, &Event> = HashMap::new();
    for event in events.iter().filter(|event| event.kind == RELEASE_KIND && event.pubkey == pubkey && event.verify()) {
        let Some(d) = event.tag("d") else { continue };
        if latest.get(d).is_none_or(|kept| event.created_at > kept.created_at) {
            latest.insert(d, event);
        }
    }
    let releases = latest.into_iter().filter_map(|(d, event)| {
        let version = event.tag("version")?;
        (d == format!("{APP}@{version}")).then_some((version, event))
    });

    if let Some(wanted) = wanted {
        return releases
            .into_iter()
            .find(|(version, _)| *version == wanted)
            .map(|(_, event)| event.clone())
            .with_context(|| format!("There's no release {wanted} of {APP}."));
    }
    releases
        .filter(|(_, event)| event.tag("c") == Some("main"))
        .filter_map(|(version, event)| Some((version_key(version)?, event)))
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, event)| event.clone())
        .with_context(|| format!("Couldn't find a release of {APP} signed by Soapbox on any relay."))
}

/// The release's binary for `platform`, not one of its packages.
fn pick_asset(events: &[Event], release: &Event, pubkey: &str, platform: &str) -> Result<Event> {
    let version = release.tag("version");
    let values = |event: &'_ Event, name: &str| -> Vec<String> {
        event.tags.iter().filter(|tag| tag.first().map(String::as_str) == Some(name)).filter_map(|tag| tag.get(1).cloned()).collect()
    };
    let ids = values(release, "e");
    let application = format!("{APPLICATION_KIND}:{pubkey}:{APP}");
    events
        .iter()
        .find(|event| {
            event.kind == ASSET_KIND
                && event.pubkey == pubkey
                && ids.contains(&event.id)
                && values(event, "a").contains(&application)
                && values(event, "f").iter().any(|f| f == platform)
                && !event.tag("m").is_some_and(|m| PACKAGE_TYPES.contains(&m))
                && event.tag("version") == version
                && event.verify()
        })
        .cloned()
        .with_context(|| format!("Release {} has no build for {platform}.", version.unwrap_or_default()))
}

/// The command to upgrade as root. By path, since sudo on RHEL and its
/// kin doesn't search /usr/local/bin.
fn sudo_upgrade(exe: &Path) -> String {
    format!("sudo {} upgrade", exe.display())
}

/// Download the asset beside `exe`, check it, and move it over `exe`.
///
/// The new binary is written and then run beside the old one, so anyone
/// else who can write to that directory could swap in their own between
/// its check and its run, as root. So such a directory is refused, and the
/// file is made fresh, never through a link already there.
async fn install(asset: &Event, version: &str, exe: &Path) -> Result<()> {
    let mut name = exe.file_name().context("this binary has no file name")?.to_os_string();
    name.push(".new");
    let new = exe.with_file_name(name);
    let dir = exe.parent().context("this binary has no directory")?;
    check_directory(dir)?;
    // Made here first, so a directory that can't be written stops this
    // before anything is downloaded.
    let mut file = create(&new).with_context(|| format!("Couldn't write {}. Run: {}", new.display(), sudo_upgrade(exe)))?;

    let result = async {
        let url = download(asset, &mut file).await?;
        drop(file);
        say(&format!("downloaded {url} and checked its sha256, {}", asset.tag("x").unwrap_or_default()));
        let output = Command::new(&new).arg("--version").stdin(Stdio::null()).output().context("running the downloaded binary")?;
        if String::from_utf8_lossy(&output.stdout).trim() != format!("armada {version}") {
            bail!("The downloaded binary doesn't say it's version {version}.");
        }
        std::fs::rename(&new, exe).with_context(|| format!("moving {} to {}", new.display(), exe.display()))
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_file(&new);
    }
    result
}

/// A new file at `path`, replacing whatever's there, and refusing to
/// follow a link someone may put there meanwhile.
fn create(path: &Path) -> std::io::Result<std::fs::File> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
        _ => {}
    }
    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o755).custom_flags(libc::O_NOFOLLOW).open(path)
}

/// Refuse a directory someone other than this user (or root) could write
/// to; see [`install`].
fn check_directory(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(dir).with_context(|| format!("looking at {}", dir.display()))?;
    let owner = metadata.uid();
    if (owner != euid() && owner != 0) || metadata.mode() & 0o022 != 0 {
        bail!("{} can be written by others, who could swap the new binary for their own before it's run. Install armada somewhere only you can write, like /usr/local/bin.", dir.display());
    }
    Ok(())
}

/// Download the asset into `destination` from its URL, or else from a
/// Blossom server by its hash, and return where it came from.
async fn download(asset: &Event, destination: &mut std::fs::File) -> Result<String> {
    let sha256 = asset.tag("x").map(str::to_ascii_lowercase).filter(|x| is_hex64(x)).context("The release doesn't give the binary's sha256.")?;
    let size = asset.tag("size").and_then(|size| size.parse::<u64>().ok());
    let urls = dedupe(asset.tag("url").map(String::from).into_iter().chain(BLOSSOM.iter().map(|server| blob_url(server, &sha256))));
    let http = reqwest::Client::builder().user_agent("armada-upgrade").timeout(DOWNLOAD_TIMEOUT).build()?;
    for url in urls.iter().filter(|url| url.starts_with("https://")) {
        match fetch(&http, url, destination, &sha256, size).await {
            Ok(()) => return Ok(url.clone()),
            Err(error) => say(&format!("couldn't download {url}: {error:#}")),
        }
    }
    bail!("No server had a copy of the binary matching sha256 {sha256}.")
}

async fn fetch(http: &reqwest::Client, url: &str, file: &mut std::fs::File, sha256: &str, size: Option<u64>) -> Result<()> {
    use std::io::Seek;
    let mut response = http.get(url).send().await?.error_for_status()?;
    // Whatever an earlier server sent goes.
    file.set_len(0)?;
    file.rewind()?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len() as u64;
        if total > MAX_BINARY {
            bail!("larger than {MAX_BINARY} bytes");
        }
        digest.update(&chunk);
        file.write_all(&chunk)?;
    }
    file.sync_all()?;
    if hex::encode(digest.finalize()) != sha256 {
        bail!("its sha256 doesn't match the release's");
    }
    if let Some(size) = size
        && total != size
    {
        bail!("sent {total} bytes; the release says {size}");
    }
    Ok(())
}

fn service_installed() -> bool {
    Path::new("/run/systemd/system").is_dir() && Path::new(UNIT).exists()
}

/// The unit as install.sh writes it: deploy/armada.service from [Unit] on.
fn unit_text() -> &'static str {
    &DEPLOY_UNIT[DEPLOY_UNIT.find("[Unit]").unwrap_or(0)..]
}

/// Bring the unit up to date and restart the service, unless nothing changed
/// and it's running.
fn refresh_service(changed: bool) -> Result<()> {
    let unit_changed = std::fs::read_to_string(UNIT).ok().as_deref() != Some(unit_text());
    if !changed && !unit_changed && systemctl(&["is-active", "--quiet", "armada"])? {
        return Ok(());
    }
    if unit_changed {
        write_unit(Path::new(UNIT))?;
        say(&format!("refreshed {UNIT}"));
    }
    if !systemctl(&["daemon-reload"])? || !systemctl(&["restart", "armada"])? {
        bail!("Couldn't restart the armada service. See what armada says with: journalctl -u armada -e");
    }
    std::thread::sleep(SETTLE_TIME);
    if !systemctl(&["is-active", "--quiet", "armada"])? {
        bail!("The armada service didn't stay up. See what armada says with: journalctl -u armada -e");
    }
    say("restarted the armada service");
    Ok(())
}

fn write_unit(path: &Path) -> Result<()> {
    let mut new = PathBuf::from(path);
    new.set_extension("service.new");
    std::fs::write(&new, unit_text()).with_context(|| format!("writing {}", new.display()))?;
    std::fs::rename(&new, path).with_context(|| format!("writing {}", path.display()))
}

/// Whether `systemctl args` succeeded.
fn systemctl(args: &[&str]) -> Result<bool> {
    let status = Command::new("systemctl").args(args).stdin(Stdio::null()).stdout(Stdio::null()).status().context("running systemctl")?;
    Ok(status.success())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::event::public_key;

    const SECRET: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    fn tags(pairs: &[(&str, &str)]) -> Vec<Vec<String>> {
        pairs.iter().map(|(name, value)| vec![name.to_string(), value.to_string()]).collect()
    }

    fn release(version: &str, channel: &str, created_at: i64, extra: &[(&str, &str)]) -> Event {
        let d = format!("{APP}@{version}");
        let mut pairs = vec![("d", d.as_str()), ("i", APP), ("version", version), ("c", channel)];
        pairs.extend_from_slice(extra);
        Event::sign(SECRET, created_at, RELEASE_KIND, tags(&pairs), "")
    }

    #[test]
    fn picks_the_newest_main_release() {
        let pubkey = public_key(SECRET);
        let events = vec![
            release("0.9.0", "main", 1, &[]),
            release("0.10.0", "main", 2, &[]),
            release("0.11.0", "beta", 3, &[]),
            release("1.0.0-rc1", "main", 4, &[]),
        ];
        let picked = pick_release(&events, &pubkey, None).unwrap();
        assert_eq!(picked.tag("version"), Some("0.10.0"));
        assert_eq!(pick_release(&events, &pubkey, Some("0.11.0")).unwrap().tag("version"), Some("0.11.0"));
        assert!(pick_release(&events, &pubkey, Some("2.0.0")).is_err());
        // Anyone else's releases are ignored.
        assert!(pick_release(&events, PUBKEY, None).is_err());
    }

    #[test]
    fn takes_only_the_newest_of_each_version_and_only_authentic_ones() {
        let pubkey = public_key(SECRET);
        // 0.2.0 was later moved off main.
        let events = vec![release("0.1.0", "main", 1, &[]), release("0.2.0", "main", 2, &[]), release("0.2.0", "beta", 3, &[])];
        assert_eq!(pick_release(&events, &pubkey, None).unwrap().tag("version"), Some("0.1.0"));

        let mut forged = release("0.3.0", "main", 4, &[]);
        forged.created_at += 1;
        assert_eq!(pick_release(&[events[0].clone(), forged], &pubkey, None).unwrap().tag("version"), Some("0.1.0"));

        // A d tag that doesn't name the version it claims.
        let mismatched = Event::sign(SECRET, 5, RELEASE_KIND, tags(&[("d", "armada-stack@9.0.0"), ("version", "0.4.0"), ("c", "main")]), "");
        assert_eq!(pick_release(&[events[0].clone(), mismatched], &pubkey, None).unwrap().tag("version"), Some("0.1.0"));
    }

    #[test]
    fn picks_the_asset_for_the_platform() {
        let pubkey = public_key(SECRET);
        let application = format!("{APPLICATION_KIND}:{pubkey}:{APP}");
        let file = |platform: &str, version: &str, created_at: i64, mime: &str| {
            Event::sign(SECRET, created_at, ASSET_KIND, tags(&[("a", &application), ("f", platform), ("version", version), ("x", &"0".repeat(64)), ("m", mime)]), "")
        };
        let asset = |platform: &str, version: &str, created_at: i64| file(platform, version, created_at, "application/octet-stream");
        let x86 = asset("linux-x86_64", "1.0.0", 1);
        let arm = asset("linux-aarch64", "1.0.0", 1);
        let stale = asset("linux-x86_64", "0.9.0", 1);
        // One the release doesn't name.
        let stray = asset("linux-aarch64", "1.0.0", 2);
        // The same binaries, packaged.
        let deb = file("linux-x86_64", "1.0.0", 1, "application/vnd.debian.binary-package");
        let rpm = file("linux-aarch64", "1.0.0", 1, "application/x-rpm");
        let release = release("1.0.0", "main", 1, &[("e", &deb.id), ("e", &rpm.id), ("e", &x86.id), ("e", &arm.id), ("e", &stale.id)]);
        let events = vec![deb.clone(), rpm.clone(), stale.clone(), stray.clone(), x86.clone(), arm.clone()];

        assert_eq!(pick_asset(&events, &release, &pubkey, "linux-x86_64").unwrap().id, x86.id);
        assert_eq!(pick_asset(&events, &release, &pubkey, "linux-aarch64").unwrap().id, arm.id);
        assert!(pick_asset(&events, &release, &pubkey, "linux-riscv64").is_err());
        assert!(pick_asset(&[stale], &release, &pubkey, "linux-x86_64").is_err());
        assert!(pick_asset(&[stray], &release, &pubkey, "linux-aarch64").is_err());
    }

    #[test]
    fn versions() {
        assert_eq!(version_key("1.10.2"), Some(vec![1, 10, 2]));
        assert!(version_key("1.10.2") > version_key("1.9.9"));
        assert_eq!(version_key("1.0.0-rc1"), None);
        assert!(is_older("0.9.9", "0.10.0"));
        assert!(!is_older("0.10.0", "0.10.0"));
        assert!(!is_older("0.11.0", "0.10.0"));
        // Nothing to compare by.
        assert!(!is_older("0.9.0", "1.0.0-rc1"));
    }

    #[test]
    fn makes_the_new_binary_afresh() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "keep me").unwrap();
        let new = dir.path().join("armada.new");
        std::os::unix::fs::symlink(&target, &new).unwrap();
        // The link is replaced, not followed.
        create(&new).unwrap();
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep me");
        assert!(!std::fs::symlink_metadata(&new).unwrap().file_type().is_symlink());
    }

    #[test]
    fn refuses_a_directory_others_can_write() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(check_directory(dir.path()).is_ok());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(check_directory(dir.path()).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(check_directory(dir.path()).is_err());
    }

    /// install.sh installs the binary where this upgrades it, with the same
    /// unit, so neither undoes the other.
    #[test]
    fn install_sh_agrees() {
        let script = include_str!("../install.sh");
        assert!(script.contains(&format!("BIN={BIN}\n")));
        assert!(script.contains(&format!("UNIT={UNIT}\n")));
        assert!(script.contains(&format!("PACKAGE_BIN={PACKAGE_BIN}\n")));
        assert!(script.contains(&format!("cat <<'EOF'\n{}EOF\n", unit_text())), "install.sh's unit differs");
    }
}
