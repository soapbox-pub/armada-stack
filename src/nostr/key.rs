//! A Nostr key of armada's own, such as the push service's or the
//! moderation key's. Made on first start and kept in the storage directory,
//! so there's nothing to set up.

use std::path::Path;

use anyhow::{Context, Result};
use secp256k1::{SECP256K1, SecretKey};

pub struct Keys {
    pub secret: SecretKey,
    /// `secret` in hex, as [`crate::nostr::Event::sign`] takes it.
    pub secret_hex: String,
    /// The x-only public key, in hex.
    pub pubkey: String,
}

impl Keys {
    fn new(secret: SecretKey) -> Keys {
        let public = secret.x_only_public_key(SECP256K1).0;
        Keys { secret, secret_hex: hex::encode(secret.secret_bytes()), pubkey: hex::encode(public.serialize()) }
    }

    /// The key at `path`, if there is one.
    pub fn load(path: &Path) -> Result<Option<Keys>> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let bytes = hex::decode(text.trim()).ok().filter(|bytes| bytes.len() == 32).with_context(|| format!("{} is not a hex secret key", path.display()))?;
                Ok(Some(Keys::new(SecretKey::from_slice(&bytes).with_context(|| format!("{} is not a valid secret key", path.display()))?)))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
        }
    }

    /// The key at `path`, made and written there if there's none yet.
    pub fn load_or_create(path: &Path) -> Result<Keys> {
        match Keys::load(path)? {
            Some(keys) => Ok(keys),
            None => {
                let secret = loop {
                    if let Ok(secret) = SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
                        break secret;
                    }
                };
                let keys = Keys::new(secret);
                crate::util::write_private(path, format!("{}\n", keys.secret_hex).as_bytes())?;
                Ok(keys)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn makes_a_key_once_and_keeps_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("key");
        assert!(Keys::load(&path).unwrap().is_none());
        let first = Keys::load_or_create(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let again = Keys::load_or_create(&path).unwrap();
        assert_eq!(first.pubkey, again.pubkey);
        assert_eq!(first.pubkey, crate::nostr::event::public_key(&first.secret_hex));
        assert_eq!(Keys::load(&path).unwrap().unwrap().pubkey, first.pubkey);

        std::fs::write(&path, "nonsense").unwrap();
        assert!(Keys::load_or_create(&path).is_err());
    }
}
