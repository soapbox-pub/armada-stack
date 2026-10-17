//! `armada ban`, `armada ban --list`, and `armada unban`: take a Concord
//! Community off this server, given one of its invite links.
//!
//! The link opens the Community's bundle, whose keys give every address the
//! Community publishes at in its current epoch: its Control Plane, its
//! Guestbook, each Channel's Chat Plane, where its next Refounding and
//! rekeys would go, and where its dissolution would. The Control Plane names
//! its Channels and its other invite links. Every one of those pubkeys is
//! banned, and what they signed deleted, along with Discover announcements
//! of the links, and the blobs the Community's icon, banner, and messages
//! point at that their authors uploaded here.
//!
//! Earlier epochs are out of reach: no key in the bundle derives them.
//!
//! The bundle and Control Plane are read from this relay, or from the
//! link's relays and the Community's when it doesn't have them.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use crate::blossom::Blossom;
use crate::concord::{self, BlobRef, Bytes32, bytes32};
use crate::config::{self, Config, Environment};
use crate::hash::BlobHash;
use crate::nostr::Event;
use crate::nostr::nip19::{self, Decoded};
use crate::nostr::pool::{Filter, Pool, is_onion};
use crate::relay::bans::{Ban, Bans};
use crate::storage::Storage;

/// How long the link's relays get to answer.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// A pubkey to ban, and what it is to the Community.
struct Target {
    pubkey: Bytes32,
    role: String,
}

struct Opened {
    storage: Storage,
    relay: Bans,
}

fn open(config: Option<&Path>) -> Result<Opened> {
    let config::Loaded { config, storage_dir, .. } = Config::load(config, &Environment::current())?;
    let storage = Storage::open(&storage_dir)?;
    let relay = Bans::open(&config.relay, &storage)?;
    Ok(Opened { storage, relay })
}

/// `armada ban <link>`.
pub async fn ban(config: Option<&Path>, link: &str, dry_run: bool) -> Result<()> {
    let Opened { storage, relay, .. } = open(config)?;
    let link = concord::parse_link(link).map_err(anyhow::Error::msg)?;
    let signer = bytes32(&link.link_signer).context("the link's signer")?;
    let pool = Pool::new(Arc::new(|_: &str| false), None);
    let cancel = CancellationToken::new();

    let mut targets = vec![Target { pubkey: signer, role: "this invite link".into() }];
    let mut skipped = Vec::new();
    let mut blobs = Vec::new();
    let mut community = [0; 32];

    let local = relay.events_by(&signer)?.into_iter().filter(is_bundle).max_by_key(|event| event.created_at);
    let found = match local {
        Some(event) => Some(event),
        None => {
            let filter = Filter { kinds: vec![concord::INVITE_BUNDLE.into()], authors: vec![link.link_signer.clone()], d: vec![String::new()], ..Default::default() };
            fetch(&pool, filter, &link.relays, &cancel).await.into_iter().filter(is_bundle).max_by_key(|event| event.created_at)
        }
    };
    let bundle = match found {
        None => {
            println!("No invite bundle for this link was found, here or on its relays. Banning the link alone.");
            None
        }
        Some(event) => match concord::open_bundle(&event, &link).map_err(anyhow::Error::msg)? {
            None => {
                println!("This invite link has been revoked, so it holds no keys. Banning the link alone.");
                None
            }
            Some(bundle) => Some(bundle),
        },
    };

    if let Some(bundle) = &bundle {
        let (id, root, epoch) = (bundle.id(), bundle.root(), bundle.root_epoch);
        community = id;

        let read = concord::control_key(&root, &id, epoch);
        let mut control_plane = vec![read.pk.clone()];
        control_plane.extend(bundle.control_pk.iter().map(|pk| pk.to_lowercase()).filter(|pk| bytes32(pk).is_some()));
        let mut wraps = Vec::new();
        for pk in &control_plane {
            wraps.extend(relay.events_by(&bytes32(pk).unwrap())?);
        }
        if wraps.is_empty() {
            let relays: Vec<String> = link.relays.iter().chain(&bundle.relays).cloned().collect();
            let filter = Filter { kinds: vec![1059], authors: control_plane.clone(), ..Default::default() };
            wraps = fetch(&pool, filter, &relays, &cancel).await;
        }
        let control = concord::read_control(&wraps, &read.conv_key);
        let name = control.name.as_deref().unwrap_or(&bundle.name);
        println!("Community: {name} ({})", bundle.community_id);
        if epoch > 0 {
            println!("It's at epoch {epoch}. Epochs before it can't be reached from this link: no key in it derives them.");
        }

        if let Some(pk) = &bundle.control_pk {
            targets.extend(target(pk, "Control Plane"));
        }
        targets.extend(target(&read.pk, "Control Plane, at its pre-split address"));
        targets.extend(target(&concord::guestbook_key(&root, &id, epoch).pk, "Guestbook"));
        targets.extend(target(&concord::base_rekey_key(&root, &id, epoch + 1).pk, "its next Refounding"));
        targets.extend(target(&concord::dissolved_key(&id).pk, "its dissolution"));
        blobs.extend(control.blobs);

        for (channel, channel_name) in &control.channels {
            let key = concord::channel_key(&root, channel, epoch);
            blobs.extend(concord::attachments(&relay.events_by(&bytes32(&key.pk).unwrap())?, &key.conv_key));
            targets.extend(target(&key.pk, &format!("#{}", display_name(channel_name, channel))));
        }
        for channel in &bundle.channels {
            let (Some(channel_id), Some(key)) = (bytes32(&channel.id), bytes32(&channel.key)) else { continue };
            let name = display_name(control.channels.get(&channel_id).filter(|name| !name.is_empty()).unwrap_or(&channel.name), &channel_id);
            let key = concord::channel_key(&key, &channel_id, channel.epoch);
            blobs.extend(concord::attachments(&relay.events_by(&bytes32(&key.pk).unwrap())?, &key.conv_key));
            targets.extend(target(&key.pk, &format!("#{name}, private")));
            targets.extend(target(&concord::channel_rekey_key(&root, &channel_id, channel.epoch + 1).pk, &format!("#{name}'s next key")));
        }

        // A Registry is a member's word for which pubkeys are invite links,
        // so it could name anyone's: only one that has signed nothing here
        // but invite bundles is taken as one.
        for other in control.link_signers.iter().filter(|other| **other != link.link_signer) {
            let pubkey = bytes32(other).unwrap();
            let kinds = relay.kinds_by(&pubkey)?;
            if kinds.is_empty() {
                skipped.push(format!("{other}  another of its invite links, by its Registry, but nothing of it is here"));
            } else if kinds.iter().all(|kind| *kind == concord::INVITE_BUNDLE) {
                targets.push(Target { pubkey, role: "another of its invite links".into() });
            } else {
                skipped.push(format!("{other}  another of its invite links, by its Registry, but it has signed other kinds of events here"));
            }
        }
    }

    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(target.pubkey));
    let pubkeys: Vec<Bytes32> = targets.iter().map(|target| target.pubkey).collect();
    let link_signers: Vec<Bytes32> = targets.iter().filter(|target| target.role.contains("invite link")).map(|target| target.pubkey).collect();

    let removals = Blossom::open_for_removal(&storage)?;
    let mut doomed = BTreeSet::new();
    for BlobRef { sha256, author } in &blobs {
        if let Some(hash) = BlobHash::parse(sha256)
            && removals.uploaded_by(hash, author)?
        {
            doomed.insert(hash);
        }
    }

    println!("{} {} pubkeys:", if dry_run { "Would ban" } else { "Banning" }, targets.len());
    for target in &targets {
        println!("  {}  {}, {} events here", hex::encode(target.pubkey), target.role, relay.count_by(&target.pubkey)?);
    }
    for line in &skipped {
        println!("  Not banning {line}.");
    }
    let announcements = relay.count_announcements(&link_signers)?;
    if dry_run {
        println!("Would delete {announcements} Discover announcements of its invite links, and {} blobs.", doomed.len());
        return Ok(());
    }

    relay.ban(&pubkeys, &community)?;
    let mut removed = 0;
    for pubkey in &pubkeys {
        removed += relay.remove_by(pubkey)?;
    }
    let announcements = relay.remove_announcements(&link_signers)?;
    for hash in &doomed {
        removals.remove(*hash)?;
    }
    println!("Banned. Deleted {removed} events, {announcements} Discover announcements of its invite links, and {} blobs.", doomed.len());
    Ok(())
}

/// `armada ban --list`.
pub fn list(config: Option<&Path>) -> Result<()> {
    let Opened { relay, .. } = open(config)?;
    let mut bans = relay.list()?;
    if bans.is_empty() {
        println!("Nothing is banned.");
        return Ok(());
    }
    bans.sort_by_key(|ban| (ban.community, ban.at, ban.pubkey));
    let mut community = None;
    for ban in bans {
        if community != Some(ban.community) {
            community = Some(ban.community);
            if ban.community == [0; 32] {
                println!("Invite links whose bundles weren't found:");
            } else {
                println!("Community {}:", hex::encode(ban.community));
            }
        }
        println!("  {}  banned {}", hex::encode(ban.pubkey), httpdate::fmt_http_date(std::time::UNIX_EPOCH + Duration::from_secs(ban.at.into())));
    }
    Ok(())
}

/// `armada unban <target>`: an invite link or community id lifts its
/// Community's bans, a pubkey just its own.
pub fn unban(config: Option<&Path>, target: &str) -> Result<()> {
    let Opened { relay, .. } = open(config)?;
    let bans = relay.list()?;
    let of_community = |community: Bytes32| -> Vec<Bytes32> { bans.iter().filter(|ban| ban.community == community).map(|ban| ban.pubkey).collect() };
    let pubkeys = if let Some(signer) = concord::link_signer(target) {
        let signer = bytes32(&signer).unwrap();
        match bans.iter().find(|ban| ban.pubkey == signer) {
            Some(Ban { community, .. }) if *community != [0; 32] => of_community(*community),
            _ => vec![signer],
        }
    } else {
        let hex = match nip19::decode(target) {
            Ok(Decoded::Npub(pubkey)) => pubkey,
            _ => target.trim().to_lowercase(),
        };
        let Some(key) = bytes32(&hex) else { bail!("Not an invite link, community id, or pubkey: {target}") };
        match of_community(key) {
            community if !community.is_empty() => community,
            _ => vec![key],
        }
    };
    let lifted = relay.unban(&pubkeys)?;
    println!("Lifted {lifted} bans. What was deleted stays deleted.");
    Ok(())
}

fn is_bundle(event: &Event) -> bool {
    event.kind == i64::from(concord::INVITE_BUNDLE) && event.tag("d").unwrap_or_default().is_empty()
}

fn target(pubkey: &str, role: &str) -> Option<Target> {
    Some(Target { pubkey: bytes32(pubkey)?, role: role.to_string() })
}

fn display_name(name: &str, id: &Bytes32) -> String {
    if name.is_empty() { hex::encode(&id[..4]) } else { name.to_string() }
}

/// Events from `relays`, but no onions, since Tor isn't running here.
async fn fetch(pool: &Pool, filter: Filter, relays: &[String], cancel: &CancellationToken) -> Vec<Event> {
    let relays: Vec<String> = crate::nostr::service::dedupe(relays.iter().filter(|relay| !is_onion(relay)).cloned());
    if relays.is_empty() {
        return Vec::new();
    }
    pool.query(vec![filter], &relays, FETCH_TIMEOUT, cancel).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::bans::Outcome;
    use serde_json::Value;

    /// Armada's vectors: a Community, its bundle, and its Control Plane.
    fn vectors() -> Value {
        serde_json::from_str(include_str!("../tests/vectors/concord.json")).unwrap()
    }

    fn event(value: &Value) -> Event {
        serde_json::from_value(value.clone()).unwrap()
    }

    #[tokio::test]
    async fn bans_a_community_by_its_invite_link() {
        let v = vectors();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("armada.toml");
        std::fs::write(&config, format!("storage_dir = {:?}\n", dir.path().join("data"))).unwrap();
        let url = v["invite"]["url"].as_str().unwrap();

        let unrelated = Event::sign(&"11".repeat(32), 100, 0, vec![], "{}");
        let announcement = Event::sign(&"22".repeat(32), 100, 3314, vec![], url);
        let control: Vec<Event> = v["control"]["wraps"].as_array().unwrap().iter().map(event).collect();
        {
            let Opened { relay, .. } = open(Some(&config)).unwrap();
            for event in control.iter().chain([&event(&v["invite"]["bundle_event"]), &unrelated, &announcement]) {
                assert!(matches!(relay.insert(event), Outcome::Stored(_)), "{}", event.id);
            }
        }

        ban(Some(&config), url, true).await.unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty(), "a dry run changes nothing");
        drop(relay);

        ban(Some(&config), url, false).await.unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        let control_pk = bytes32(v["control"]["control_pk"].as_str().unwrap()).unwrap();
        let signer = bytes32(v["invite"]["link_signer"].as_str().unwrap()).unwrap();
        assert_eq!(relay.count_by(&control_pk).unwrap(), 0);
        assert_eq!(relay.count_by(&signer).unwrap(), 0);
        assert_eq!(relay.count_announcements(&[signer]).unwrap(), 0);
        assert_eq!(relay.count_by(&bytes32(&unrelated.pubkey).unwrap()).unwrap(), 1);
        let bans = relay.list().unwrap();
        let community = bytes32(v["keys"]["community_id"].as_str().unwrap()).unwrap();
        assert!(bans.iter().all(|ban| ban.community == community));
        // The link, Control Plane at both addresses, Guestbook, next
        // Refounding, dissolution, two public Channels, and the private one
        // and its next key.
        assert_eq!(bans.len(), 10);
        assert!(matches!(relay.insert(&control[0]), Outcome::Banned));
        drop(relay);

        unban(Some(&config), url).unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty());
    }
}
