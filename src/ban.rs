//! `armada ban`, `armada ban --list`, and `armada unban`: take a Concord
//! Community off this server, given one of its invite links, or a user,
//! given their pubkey.
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
//! With `--members`, so is everyone in the Community, by their own keys:
//! the Guestbook coalesced, with everyone seen publishing on its planes,
//! less anyone its own Banlist names. That bans them from posting anything
//! here, not only to the Community, and deletes everything they published
//! here and their uploads, short of blobs someone else uploaded too.
//!
//! Earlier epochs are out of reach: no key in the bundle derives them.
//!
//! The Community goes on this armada's blocklist too ([`moderation`]), so
//! Armada won't open it here at all, and `armada unban` lifts it.
//!
//! `armada ban --user <npub>` bans a user on their own, by no Community, and
//! deletes everything they published and uploaded here, short of blobs
//! someone else uploaded too. They go on the blocklist as a user, so Armada
//! purges what it holds of theirs and shows tombstones in its place.
//! Lifting a Community's bans leaves theirs, as does banning one they're in.
//!
//! The bundle and Control Plane are read from this relay, or from the
//! link's relays, the Community's, and any given with `--relay` when it
//! doesn't have them. Its Chat Planes and Guestbook are read from this relay,
//! and with `--members` from those relays too, to find everyone in it.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio_util::sync::CancellationToken;

use crate::blossom::Blossom;
use crate::concord::{self, BlobRef, Bytes32, bytes32};
use crate::config::{self, Config, Environment};
use crate::hash::BlobHash;
use crate::moderation::{self, Scope, Status};
use crate::nostr::Event;
use crate::nostr::nip19::{self, Decoded};
use crate::nostr::pool::{Filter, Pool, is_onion};
use crate::relay::bans::{Ban, Bans, Role};
use crate::storage::Storage;

/// How long the link's relays get to answer.
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

/// A pubkey to ban, what it is to the Community, and in what words.
struct Target {
    pubkey: Bytes32,
    role: Role,
    what: String,
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

/// What `armada ban <link>` is asked to do.
#[derive(Default)]
pub struct Options {
    /// Ban everyone in the Community too.
    pub members: bool,
    /// Relays to read the Community from, besides the link's and its own.
    pub relays: Vec<String>,
    /// Say what would happen, and change nothing.
    pub dry_run: bool,
}

/// `armada ban <link>`.
pub async fn ban(config: Option<&Path>, link: &str, options: &Options) -> Result<()> {
    let pool = Pool::new(Arc::new(|_: &str| false), None);
    let cancel = CancellationToken::new();
    ban_with(config, link, options, async |filter, relays| fetch(&pool, filter, relays, &cancel).await).await
}

/// [`ban`], reading from relays with `query`.
async fn ban_with(config: Option<&Path>, link: &str, options: &Options, query: impl AsyncFn(Filter, &[String]) -> Vec<Event>) -> Result<()> {
    let Opened { storage, relay, .. } = open(config)?;
    let link = concord::parse_link(link).map_err(anyhow::Error::msg)?;
    let signer = bytes32(&link.link_signer).context("the link's signer")?;
    let mut relays: Vec<String> = link.relays.iter().chain(&options.relays).cloned().collect();

    let mut targets = vec![Target { pubkey: signer, role: Role::Community, what: "this invite link".into() }];
    let mut skipped = Vec::new();
    let mut blobs = Vec::new();
    let mut community = [0; 32];

    let local = relay.events_by(&signer)?.into_iter().filter(is_bundle).max_by_key(|event| event.created_at);
    let found = match local {
        Some(event) => Some(event),
        None => {
            let filter = Filter { kinds: vec![concord::INVITE_BUNDLE.into()], authors: vec![link.link_signer.clone()], d: vec![String::new()], ..Default::default() };
            query(filter, &relays).await.into_iter().filter(is_bundle).max_by_key(|event| event.created_at)
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
        relays.extend(bundle.relays.iter().cloned());

        let read = concord::control_key(&root, &id, epoch);
        let mut control_plane = vec![read.pk.clone()];
        control_plane.extend(bundle.control_pk.iter().map(|pk| pk.to_lowercase()).filter(|pk| bytes32(pk).is_some()));
        let mut wraps = Vec::new();
        for pk in &control_plane {
            wraps.extend(relay.events_by(&bytes32(pk).unwrap())?);
        }
        if wraps.is_empty() {
            wraps = query(wraps_by(control_plane.clone()), &relays).await;
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
        let guestbook = concord::guestbook_key(&root, &id, epoch);
        targets.extend(target(&guestbook.pk, "Guestbook"));
        targets.extend(target(&concord::base_rekey_key(&root, &id, epoch + 1).pk, "its next Refounding"));
        targets.extend(target(&concord::dissolved_key(&id).pk, "its dissolution"));
        blobs.extend(control.blobs);

        // Each Chat Plane's address, and the key that opens it.
        let mut chats = Vec::new();
        for (channel, channel_name) in &control.channels {
            let key = concord::channel_key(&root, channel, epoch);
            targets.extend(target(&key.pk, &format!("#{}", display_name(channel_name, channel))));
            chats.push(key);
        }
        for channel in &bundle.channels {
            let (Some(channel_id), Some(key)) = (bytes32(&channel.id), bytes32(&channel.key)) else { continue };
            let name = display_name(control.channels.get(&channel_id).filter(|name| !name.is_empty()).unwrap_or(&channel.name), &channel_id);
            let key = concord::channel_key(&key, &channel_id, channel.epoch);
            targets.extend(target(&key.pk, &format!("#{name}, private")));
            targets.extend(target(&concord::channel_rekey_key(&root, &channel_id, channel.epoch + 1).pk, &format!("#{name}'s next key")));
            chats.push(key);
        }

        let mut planes: BTreeMap<String, Vec<Event>> = BTreeMap::new();
        for pk in chats.iter().map(|key| &key.pk).chain(options.members.then_some(&guestbook.pk)) {
            planes.insert(pk.clone(), relay.events_by(&bytes32(pk).unwrap())?);
        }
        if options.members {
            let mut held: HashSet<String> = planes.values().flatten().map(|event| event.id.clone()).collect();
            for wrap in query(wraps_by(planes.keys().cloned().collect()), &relays).await {
                if held.insert(wrap.id.clone()) {
                    planes.entry(wrap.pubkey.clone()).or_default().push(wrap);
                }
            }
        }
        let wraps_at = |pk: &str| planes.get(pk).map_or(&[][..], Vec::as_slice);
        for key in &chats {
            blobs.extend(concord::attachments(wraps_at(&key.pk), &key.conv_key));
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
                targets.push(Target { pubkey, role: Role::Community, what: "another of its invite links".into() });
            } else {
                skipped.push(format!("{other}  another of its invite links, by its Registry, but it has signed other kinds of events here"));
            }
        }

        if options.members {
            let mut authors = control.authors.clone();
            for key in &chats {
                for (author, last) in concord::authors(wraps_at(&key.pk), &key.conv_key) {
                    let seen = authors.entry(author).or_insert(i64::MIN);
                    *seen = (*seen).max(last);
                }
            }
            // The owner is in it, whether or not they've been seen.
            let owner = bundle.owner.to_lowercase();
            authors.entry(owner.clone()).or_insert(i64::MIN);
            let book = concord::read_guestbook(wraps_at(&guestbook.pk), &guestbook.conv_key);
            if !control.banned.is_empty() {
                skipped.push(format!("the {} people its own Banlist names", control.banned.len()));
            }
            for member in concord::members(&book, &authors, &control.banned) {
                let what = if member == owner { "its owner" } else { "a member" };
                targets.extend(bytes32(&member).map(|pubkey| Target { pubkey, role: Role::Member, what: what.into() }));
            }
        }
    } else if options.members {
        println!("Without its bundle, there's no telling who's in it, so no members are banned.");
    }

    let mut seen = BTreeSet::new();
    targets.retain(|target| seen.insert(target.pubkey));
    let pubkeys: Vec<(Bytes32, Role)> = targets.iter().map(|target| (target.pubkey, target.role)).collect();
    let link_signers: Vec<Bytes32> = targets.iter().filter(|target| target.what.contains("invite link")).map(|target| target.pubkey).collect();
    let members: BTreeSet<Bytes32> = targets.iter().filter(|target| target.role == Role::Member).map(|target| target.pubkey).collect();

    let removals = Blossom::open_for_removal(&storage)?;
    let mut doomed = BTreeSet::new();
    for BlobRef { sha256, author } in &blobs {
        if let Some(hash) = BlobHash::parse(sha256)
            && removals.uploaded_by(hash, author)?
        {
            doomed.insert(hash);
        }
    }
    let uploads = if members.is_empty() { Vec::new() } else { removals.uploads_by(&members)? };

    println!("{} {} pubkeys:", if options.dry_run { "Would ban" } else { "Banning" }, targets.len());
    for target in &targets {
        println!("  {}  {}, {} events here", hex::encode(target.pubkey), target.what, relay.count_by(&target.pubkey)?);
    }
    for line in &skipped {
        println!("  Not banning {line}.");
    }
    let announcements = relay.count_announcements(&link_signers)?;
    let moderator = moderation::load(&storage)?;
    if options.dry_run {
        println!("Would delete {announcements} Discover announcements of its invite links, and {} blobs.", doomed.len());
        if !members.is_empty() {
            println!("Would take back its members' {} uploads here, deleting each blob no one else uploaded too.", uploads.len());
        }
        if bundle.is_some() && moderator.is_some() {
            println!("Would add it to this armada's blocklist.");
        }
        return Ok(());
    }

    relay.ban(&pubkeys, &community)?;
    let mut removed = 0;
    for (pubkey, _) in &pubkeys {
        removed += relay.remove_by(pubkey)?;
    }
    let announcements = relay.remove_announcements(&link_signers)?;
    for hash in &doomed {
        removals.remove(*hash)?;
    }
    println!("Banned. Deleted {removed} events, {announcements} Discover announcements of its invite links, and {} blobs.", doomed.len());
    if !members.is_empty() {
        let mut gone = 0;
        for (hash, pubkey) in &uploads {
            gone += usize::from(removals.disown(*hash, pubkey)?);
        }
        println!("Took back its members' {} uploads here, and deleted the {gone} blobs no one else had uploaded.", uploads.len());
    }
    if bundle.is_some() {
        match &moderator {
            Some(keys) => {
                moderation::publish(&relay, keys, Scope::Community, &community, Status::Blocked)?;
                println!("Added it to this armada's blocklist, so Armada won't open it here.");
            }
            None => println!("armada hasn't started yet, so it has no moderation key to add the community to its blocklist with."),
        }
    }
    Ok(())
}

/// `armada ban --user <key>`.
pub fn ban_user(config: Option<&Path>, key: &str, dry_run: bool) -> Result<()> {
    let Opened { storage, relay } = open(config)?;
    let Some(pubkey) = pubkey(key) else { bail!("Not a pubkey or npub: {key}") };
    let removals = Blossom::open_for_removal(&storage)?;
    let uploads = removals.uploads_by(&BTreeSet::from([pubkey]))?;
    let was = match relay.list()?.into_iter().find(|ban| ban.pubkey == pubkey) {
        Some(Ban { role: Role::Person, .. }) => ", already banned on their own",
        Some(Ban { role: Role::Member, .. }) => ", already banned as a community's member",
        Some(_) => ", already banned as a community's address",
        None => "",
    };
    println!("{} {}: {} events and {} uploads here{was}.", if dry_run { "Would ban" } else { "Banning" }, hex::encode(pubkey), relay.count_by(&pubkey)?, uploads.len());
    let moderator = moderation::load(&storage)?;
    if dry_run {
        println!("Would delete their events, and each upload no one else made too.");
        if moderator.is_some() {
            println!("Would add them to this armada's blocklist.");
        }
        return Ok(());
    }
    relay.ban(&[(pubkey, Role::Person)], &[0; 32])?;
    let removed = relay.remove_by(&pubkey)?;
    let mut gone = 0;
    for (hash, owner) in &uploads {
        gone += usize::from(removals.disown(*hash, owner)?);
    }
    println!("Banned. Deleted {removed} events, took back {} uploads, and deleted the {gone} blobs no one else had uploaded.", uploads.len());
    match &moderator {
        Some(keys) => {
            moderation::publish(&relay, keys, Scope::User, &pubkey, Status::Blocked)?;
            println!("Added them to this armada's blocklist, so Armada purges what it holds of theirs here.");
        }
        None => println!("armada hasn't started yet, so it has no moderation key to add them to its blocklist with."),
    }
    Ok(())
}

/// A hex pubkey or an npub.
fn pubkey(key: &str) -> Option<Bytes32> {
    let hex = match nip19::decode(key.trim()) {
        Ok(Decoded::Npub(pubkey)) => pubkey,
        _ => key.trim().to_lowercase(),
    };
    bytes32(&hex)
}

/// `armada ban --list`.
pub fn list(config: Option<&Path>) -> Result<()> {
    let Opened { relay, .. } = open(config)?;
    let bans = relay.list()?;
    if bans.is_empty() {
        println!("Nothing is banned.");
        return Ok(());
    }
    let when = |at: u32| httpdate::fmt_http_date(std::time::UNIX_EPOCH + Duration::from_secs(at.into()));
    let (mut people, mut bans): (Vec<Ban>, Vec<Ban>) = bans.into_iter().partition(|ban| ban.role == Role::Person);
    people.sort_by_key(|ban| (ban.at, ban.pubkey));
    if !people.is_empty() {
        println!("Users:");
    }
    for ban in people {
        println!("  {}  banned {}", hex::encode(ban.pubkey), when(ban.at));
    }
    bans.sort_by_key(|ban| (ban.community, ban.role, ban.at, ban.pubkey));
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
        let role = if ban.role == Role::Member { "  member" } else { "" };
        println!("  {}  banned {}{role}", hex::encode(ban.pubkey), when(ban.at));
    }
    Ok(())
}

/// `armada unban <target>`: an invite link or community id lifts its
/// Community's bans, its members' included but not users banned on their
/// own, and its blocklist entry; a pubkey just its own ban, and its entry
/// if it was banned as a user.
pub fn unban(config: Option<&Path>, target: &str) -> Result<()> {
    let Opened { storage, relay } = open(config)?;
    let bans = relay.list()?;
    let of_community = |community: Bytes32| -> Vec<Bytes32> { bans.iter().filter(|ban| community != [0; 32] && ban.community == community).map(|ban| ban.pubkey).collect() };
    let (pubkeys, community) = if let Some(signer) = concord::link_signer(target) {
        let signer = bytes32(&signer).unwrap();
        match bans.iter().find(|ban| ban.pubkey == signer) {
            Some(Ban { community, .. }) if *community != [0; 32] => (of_community(*community), Some(*community)),
            _ => (vec![signer], None),
        }
    } else {
        let Some(key) = pubkey(target) else { bail!("Not an invite link, community id, or pubkey: {target}") };
        match of_community(key) {
            community if !community.is_empty() => (community, Some(key)),
            _ => (vec![key], None),
        }
    };
    let user = match pubkeys.as_slice() {
        [one] if community.is_none() => bans.iter().find(|ban| ban.pubkey == *one && ban.role == Role::Person).map(|ban| ban.pubkey),
        _ => None,
    };
    let lifted = relay.unban(&pubkeys)?;
    println!("Lifted {lifted} bans. What was deleted stays deleted.");
    let keys = moderation::load(&storage)?;
    if let (Some(community), Some(keys)) = (community, &keys) {
        moderation::publish(&relay, keys, Scope::Community, &community, Status::Lifted)?;
        println!("Lifted its entry on this armada's blocklist.");
    }
    if let (Some(user), Some(keys)) = (user, &keys) {
        moderation::publish(&relay, keys, Scope::User, &user, Status::Lifted)?;
        println!("Lifted their entry on this armada's blocklist.");
    }
    Ok(())
}

fn is_bundle(event: &Event) -> bool {
    event.kind == i64::from(concord::INVITE_BUNDLE) && event.tag("d").unwrap_or_default().is_empty()
}

/// One of the Community's own addresses.
fn target(pubkey: &str, what: &str) -> Option<Target> {
    Some(Target { pubkey: bytes32(pubkey)?, role: Role::Community, what: what.to_string() })
}

fn wraps_by(authors: Vec<String>) -> Filter {
    Filter { kinds: vec![1059], authors, ..Default::default() }
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

    async fn offline(_: Filter, _: &[String]) -> Vec<Event> {
        Vec::new()
    }

    #[tokio::test]
    async fn bans_its_members_too() {
        let v = vectors();
        let k = &v["keys"];
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("armada.toml");
        std::fs::write(&config, format!("storage_dir = {:?}\n", dir.path().join("data"))).unwrap();
        let url = v["invite"]["url"].as_str().unwrap();
        let key = |name: &str| bytes32(k[name].as_str().unwrap()).unwrap();
        let profile = |name: &str| Event::sign(k[&format!("{name}_sk")].as_str().unwrap(), 100, 0, vec![], "{}");
        let (alices, bobs) = (profile("alice"), profile("bob"));
        let (own, shared) = (BlobHash::of(b"alice's"), BlobHash::of(b"shared"));
        {
            let Opened { storage, relay } = open(Some(&config)).unwrap();
            let control = v["control"]["wraps"].as_array().unwrap().iter().map(event);
            for event in control.chain([event(&v["invite"]["bundle_event"]), event(&v["chat_wrap"]["wrap"]), alices.clone(), bobs.clone()]) {
                assert!(matches!(relay.insert(&event), Outcome::Stored(_)), "{}", event.id);
            }
            let removals = Blossom::open_for_removal(&storage).unwrap();
            removals.record_upload(own, &alices.pubkey);
            removals.record_upload(shared, &alices.pubkey);
            removals.record_upload(shared, &"33".repeat(32));
        }

        // The Guestbook is only on the Community's relays.
        let guestbook = event(&v["guestbook"]["wrap"]);
        let remote = async |filter: Filter, _: &[String]| -> Vec<Event> {
            [&guestbook].into_iter().filter(|wrap| filter.authors.contains(&wrap.pubkey) && filter.kinds.contains(&wrap.kind)).cloned().collect()
        };
        let options = Options { members: true, ..Default::default() };
        ban_with(Some(&config), url, &options, remote).await.unwrap();

        let Opened { storage, relay } = open(Some(&config)).unwrap();
        let members: BTreeSet<Bytes32> = relay.list().unwrap().iter().filter(|ban| ban.role == Role::Member).map(|ban| ban.pubkey).collect();
        // The owner, and Alice, who wrote in a Channel; not Bob, whom the
        // Community itself banned.
        assert!(members.contains(&key("owner")) && members.contains(&key("alice")));
        assert!(!members.contains(&key("bob")));
        assert_eq!(relay.count_by(&key("alice")).unwrap(), 0);
        assert_eq!(relay.count_by(&key("bob")).unwrap(), 1);
        assert!(matches!(relay.insert(&alices), Outcome::Banned));
        // Her own upload goes; one someone else made too stays theirs.
        let removals = Blossom::open_for_removal(&storage).unwrap();
        assert!(!removals.uploaded_by(own, &alices.pubkey).unwrap());
        assert!(!removals.uploaded_by(shared, &alices.pubkey).unwrap());
        assert!(removals.uploaded_by(shared, &"33".repeat(32)).unwrap());
        drop((relay, removals));

        // The link lifts the whole Community, members and all.
        unban(Some(&config), url).unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty());
    }

    #[tokio::test]
    async fn bans_a_community_by_its_invite_link() {
        let v = vectors();
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("armada.toml");
        std::fs::write(&config, format!("storage_dir = {:?}\n", dir.path().join("data"))).unwrap();
        let url = v["invite"]["url"].as_str().unwrap();

        let keys = moderation::load_or_create(&Storage::open(&dir.path().join("data")).unwrap()).unwrap();
        let moderator = bytes32(&keys.pubkey).unwrap();
        let community = bytes32(v["keys"]["community_id"].as_str().unwrap()).unwrap();
        let entry = |relay: &Bans| {
            let entries = relay.events_by(&moderator).unwrap();
            assert!(entries.len() <= 1, "an entry replaces the last");
            entries.first().map(|event| (event.tag("d").unwrap().to_string(), event.tag("status").unwrap().to_string()))
        };
        let unrelated = Event::sign(&"11".repeat(32), 100, 0, vec![], "{}");
        let announcement = Event::sign(&"22".repeat(32), 100, 3314, vec![], url);
        let control: Vec<Event> = v["control"]["wraps"].as_array().unwrap().iter().map(event).collect();
        {
            let Opened { relay, .. } = open(Some(&config)).unwrap();
            for event in control.iter().chain([&event(&v["invite"]["bundle_event"]), &unrelated, &announcement]) {
                assert!(matches!(relay.insert(event), Outcome::Stored(_)), "{}", event.id);
            }
        }

        let dry_run = Options { dry_run: true, ..Default::default() };
        ban_with(Some(&config), url, &dry_run, offline).await.unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty(), "a dry run changes nothing");
        assert_eq!(entry(&relay), None);
        drop(relay);

        ban_with(Some(&config), url, &Options::default(), offline).await.unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        let control_pk = bytes32(v["control"]["control_pk"].as_str().unwrap()).unwrap();
        let signer = bytes32(v["invite"]["link_signer"].as_str().unwrap()).unwrap();
        assert_eq!(relay.count_by(&control_pk).unwrap(), 0);
        assert_eq!(relay.count_by(&signer).unwrap(), 0);
        assert_eq!(relay.count_announcements(&[signer]).unwrap(), 0);
        assert_eq!(relay.count_by(&bytes32(&unrelated.pubkey).unwrap()).unwrap(), 1);
        let bans = relay.list().unwrap();
        assert!(bans.iter().all(|ban| ban.community == community));
        assert_eq!(entry(&relay), Some((moderation::hash(Scope::Community, &community), "blocked".to_string())));
        // The link, Control Plane at both addresses, Guestbook, next
        // Refounding, dissolution, two public Channels, and the private one
        // and its next key.
        assert_eq!(bans.len(), 10);
        assert!(matches!(relay.insert(&control[0]), Outcome::Banned));
        drop(relay);

        unban(Some(&config), url).unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty());
        assert_eq!(entry(&relay), Some((moderation::hash(Scope::Community, &community), "lifted".to_string())));
    }

    #[tokio::test]
    async fn bans_a_user_on_their_own() {
        let v = vectors();
        let k = &v["keys"];
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("armada.toml");
        std::fs::write(&config, format!("storage_dir = {:?}\n", dir.path().join("data"))).unwrap();
        let url = v["invite"]["url"].as_str().unwrap();
        let alice = bytes32(k["alice"].as_str().unwrap()).unwrap();
        let alices = Event::sign(k["alice_sk"].as_str().unwrap(), 100, 0, vec![], "{}");
        let (own, shared) = (BlobHash::of(b"alice's"), BlobHash::of(b"shared"));
        let keys = moderation::load_or_create(&Storage::open(&dir.path().join("data")).unwrap()).unwrap();
        let moderator = bytes32(&keys.pubkey).unwrap();
        {
            let Opened { storage, relay } = open(Some(&config)).unwrap();
            let control = v["control"]["wraps"].as_array().unwrap().iter().map(event);
            for event in control.chain([event(&v["invite"]["bundle_event"]), event(&v["chat_wrap"]["wrap"]), alices.clone()]) {
                assert!(matches!(relay.insert(&event), Outcome::Stored(_)), "{}", event.id);
            }
            let removals = Blossom::open_for_removal(&storage).unwrap();
            removals.record_upload(own, &alices.pubkey);
            removals.record_upload(shared, &alices.pubkey);
            removals.record_upload(shared, &"33".repeat(32));
        }

        assert!(ban_user(Some(&config), "nonsense", false).is_err());
        ban_user(Some(&config), k["alice"].as_str().unwrap(), true).unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty(), "a dry run changes nothing");
        drop(relay);

        ban_user(Some(&config), &k["alice"].as_str().unwrap().to_uppercase(), false).unwrap();
        let Opened { storage, relay } = open(Some(&config)).unwrap();
        let bans = relay.list().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!((bans[0].pubkey, bans[0].role), (alice, Role::Person));
        assert_eq!(relay.count_by(&alice).unwrap(), 0);
        assert!(matches!(relay.insert(&alices), Outcome::Banned));
        let removals = Blossom::open_for_removal(&storage).unwrap();
        assert!(!removals.uploaded_by(own, &alices.pubkey).unwrap());
        assert!(removals.uploaded_by(shared, &"33".repeat(32)).unwrap());
        let entry = |relay: &Bans| {
            let entries = relay.events_by(&moderator).unwrap();
            assert_eq!(entries.len(), 1, "an entry replaces the last");
            let e = &entries[0];
            (e.tag("d").unwrap().to_string(), e.tag("scope").unwrap().to_string(), e.tag("status").unwrap().to_string())
        };
        assert_eq!(entry(&relay), (moderation::hash(Scope::User, &alice), "user".into(), "blocked".into()));
        drop((relay, removals));

        // Banning, then lifting, a Community she's in leaves her own ban.
        ban_with(Some(&config), url, &Options { members: true, ..Default::default() }, offline).await.unwrap();
        unban(Some(&config), url).unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        let bans = relay.list().unwrap();
        assert_eq!(bans.len(), 1);
        assert_eq!(bans[0].role, Role::Person);
        drop(relay);

        unban(Some(&config), k["alice"].as_str().unwrap()).unwrap();
        let Opened { relay, .. } = open(Some(&config)).unwrap();
        assert!(relay.list().unwrap().is_empty());
        let user_entry = relay.events_by(&moderator).unwrap().into_iter().find(|e| e.tag("scope") == Some("user")).unwrap();
        assert_eq!(user_entry.tag("status"), Some("lifted"));
    }
}
