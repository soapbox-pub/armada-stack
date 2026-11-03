//! This armada's moderation key, and the entries it signs on Armada's
//! blocklist, for communities and users.
//!
//! Armada won't open a community whose newest entry by a key it trusts says
//! `blocked`, and purges a user's so, showing tombstones in their place. It trusts the keys `BLOCKLIST_AUTHORS` names, Soapbox's unless
//! `window.ENV` says otherwise, and this armada names its own key there
//! beside Soapbox's (see [`crate::web::env`]). The key is made on first
//! start, like the push service's. `armada ban` adds the community it takes
//! down, `armada ban --user` the user, and `armada unban` lifts the entry,
//! on this relay, which takes entries from this key and no other.
//!
//! An entry is armada-blocklist's: one addressable event per community or
//! user, naming only a hash of its id, so it can't be matched against the id
//! anywhere else it appears.
//!
//! ```text
//! entry hash = sha256(utf8("armada/blocklist/community/v1") || 0x00 || community_id[32])
//! entry hash = sha256(utf8("armada/blocklist/user/v1") || 0x00 || pubkey[32])
//! ```

use anyhow::Result;
use sha2::{Digest, Sha256};

use crate::concord::Bytes32;
use crate::nostr::Event;
use crate::nostr::key::Keys;
use crate::relay::BLOCKLIST;
use crate::relay::bans::{Bans, Outcome};
use crate::storage::Storage;


/// The key, made if armada hasn't one yet.
pub fn load_or_create(storage: &Storage) -> Result<Keys> {
    Keys::load_or_create(&storage.service_dir("moderation")?.join("key"))
}

/// The key, once armada has made one. `armada ban` runs as root, so a key
/// it made would be root's, and unreadable to the service.
pub fn load(storage: &Storage) -> Result<Option<Keys>> {
    Keys::load(&storage.root().join("moderation").join("key"))
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    Blocked,
    Lifted,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Blocked => "blocked",
            Status::Lifted => "lifted",
        }
    }
}

/// What an entry is for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Scope {
    /// A community, by its id.
    Community,
    /// A user, by their pubkey.
    User,
}

impl Scope {
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Community => "community",
            Scope::User => "user",
        }
    }
}

/// The hash `id`, a community id or a pubkey, is listed under.
pub fn hash(scope: Scope, id: &Bytes32) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("armada/blocklist/{}/v1", scope.as_str()));
    hasher.update([0]);
    hasher.update(id);
    hex::encode(hasher.finalize())
}

/// `id`'s entry, signed at `at`.
pub fn entry(keys: &Keys, scope: Scope, id: &Bytes32, status: Status, at: i64) -> Event {
    let tags = [["d", &hash(scope, id)], ["scope", scope.as_str()], ["status", status.as_str()], ["v", "1"]];
    Event::sign(&keys.secret_hex, at, BLOCKLIST.into(), tags.iter().map(|tag| tag.map(String::from).to_vec()).collect(), "")
}

/// Put `id` on this relay's blocklist as `status`. Signed after any entry
/// for it already here, so it's the newest even within the second.
pub fn publish(relay: &Bans, keys: &Keys, scope: Scope, id: &Bytes32, status: Status) -> Result<()> {
    let hash = hash(scope, id);
    let moderator = crate::concord::bytes32(&keys.pubkey).expect("a pubkey");
    let after = relay.events_by(&moderator)?.iter().filter(|event| event.kind == i64::from(BLOCKLIST) && event.tag("d") == Some(&hash)).map(|event| event.created_at + 1).max();
    let at = after.unwrap_or_default().max(crate::util::now());
    match relay.publish(&entry(keys, scope, id, status, at))? {
        Outcome::Stored(_) => Ok(()),
        outcome => anyhow::bail!("The relay didn't store the blocklist entry: {outcome:?}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_armada_blocklists_test_vector() {
        assert_eq!(hash(Scope::Community, &[0; 32]), "cdcb08e5b090621ac90f55b6dfeb124728883c4aded7922ac874e1dd7f415fb2");
        assert_eq!(hash(Scope::User, &[0; 32]), "5651d56b6e1741880b2c3822dfe70dbf1d14ed6497ef26ea5e82b81c29cc1856");
    }
}
