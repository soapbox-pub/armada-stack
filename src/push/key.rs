//! The service's Nostr key: its address, which clients encrypt to. Made on
//! first start and kept beside its database, so there's nothing to set up.

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

    /// The key at `path`, made and written there if there's none yet.
    pub fn load_or_create(path: &Path) -> Result<Keys> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let bytes = hex::decode(text.trim()).ok().filter(|bytes| bytes.len() == 32).with_context(|| format!("{} is not a hex secret key", path.display()))?;
                Ok(Keys::new(SecretKey::from_slice(&bytes).with_context(|| format!("{} is not a valid secret key", path.display()))?))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let secret = loop {
                    if let Ok(secret) = SecretKey::from_slice(&rand::random::<[u8; 32]>()) {
                        break secret;
                    }
                };
                let keys = Keys::new(secret);
                crate::util::write_private(path, format!("{}\n", keys.secret_hex).as_bytes())?;
                Ok(keys)
            }
            Err(error) => Err(error).with_context(|| format!("Could not read {}", path.display())),
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
        let first = Keys::load_or_create(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let again = Keys::load_or_create(&path).unwrap();
        assert_eq!(first.pubkey, again.pubkey);
        assert_eq!(first.pubkey, crate::nostr::event::public_key(&first.secret_hex));

        std::fs::write(&path, "nonsense").unwrap();
        assert!(Keys::load_or_create(&path).is_err());
    }
}
