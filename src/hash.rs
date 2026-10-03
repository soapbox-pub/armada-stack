//! A blob's name: the SHA-256 of its bytes, as Blossom names it.
//!
//! Parsed once, where a hash enters — a manifest's `path` tag, a file name in
//! the store — so everything past that holds a name that is certainly 32
//! bytes, and building a path from one can't go wrong.

use std::fmt;
use std::str::FromStr;


#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BlobHash([u8; 32]);

impl BlobHash {
    /// The hash of some bytes.
    pub fn of(bytes: &[u8]) -> BlobHash {
        use sha2::{Digest, Sha256};
        BlobHash(Sha256::digest(bytes).into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> BlobHash {
        BlobHash(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Exactly 64 hex digits, in either case.
    pub fn parse(hex: &str) -> Option<BlobHash> {
        let mut bytes = [0u8; 32];
        (hex.len() == 64).then_some(())?;
        hex::decode_to_slice(hex, &mut bytes).ok()?;
        Some(BlobHash(bytes))
    }

    /// Lowercase hex, without allocating.
    pub fn hex(&self) -> HexBuf {
        let mut buf = [0u8; 64];
        hex::encode_to_slice(self.0, &mut buf).expect("64 digits for 32 bytes");
        HexBuf(buf)
    }
}

/// A hash written out, held on the stack.
pub struct HexBuf([u8; 64]);

impl HexBuf {
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.0).expect("hex digits are ASCII")
    }
}

impl fmt::Display for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hex().as_str())
    }
}

impl fmt::Debug for BlobHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.hex().as_str())
    }
}

impl FromStr for BlobHash {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        BlobHash::parse(value).ok_or_else(|| format!("Not a sha256 hash: {value}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let hash = BlobHash::of(b"hello");
        let text = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hash.to_string(), text);
        assert_eq!(BlobHash::parse(text), Some(hash));
        assert_eq!(BlobHash::parse(&text.to_uppercase()), Some(hash));
        assert_eq!(BlobHash::parse(&text[1..]), None);
        assert_eq!(BlobHash::parse(&format!("{}g", &text[1..])), None);
        assert_eq!(BlobHash::parse(&"é".repeat(32)), None);
    }
}
