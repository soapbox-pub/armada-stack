//! NIP-19 bech32 entities: `npub`, `nsec`, `note`, `nprofile`, `nevent`,
//! `naddr`.
//!
//! bech32 is implemented here rather than borrowed, because nostr's TLV
//! entities routinely run past the 90 characters BIP-173 allows, and past the
//! 1023 general-purpose libraries enforce; nostr-tools accepts up to 5000.

use std::fmt;

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const MAX_LENGTH: usize = 5000;
const GENERATOR: [u32; 5] = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decoded {
    Npub(String),
    Nsec(String),
    Note(String),
    Nprofile { pubkey: String, relays: Vec<String> },
    Nevent { id: String },
    Naddr { pubkey: String, kind: u32, identifier: String, relays: Vec<String> },
}

impl Decoded {
    /// The prefix this entity is spelled with, as nostr-tools names the type.
    pub fn type_name(&self) -> &'static str {
        match self {
            Decoded::Npub(_) => "npub",
            Decoded::Nsec(_) => "nsec",
            Decoded::Note(_) => "note",
            Decoded::Nprofile { .. } => "nprofile",
            Decoded::Nevent { .. } => "nevent",
            Decoded::Naddr { .. } => "naddr",
        }
    }
}

#[derive(Debug)]
pub struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

fn error(message: impl Into<String>) -> Error {
    Error(message.into())
}

pub fn decode(value: &str) -> Result<Decoded, Error> {
    let (hrp, data) = bech32_decode(value)?;

    match hrp.as_str() {
        "npub" => Ok(Decoded::Npub(key(&data)?)),
        "nsec" => Ok(Decoded::Nsec(key(&data)?)),
        "note" => Ok(Decoded::Note(key(&data)?)),
        "nprofile" => {
            let tlv = parse_tlv(&data)?;
            let pubkey = tlv.first(0).ok_or_else(|| error("missing TLV 0 for nprofile"))?;
            Ok(Decoded::Nprofile { pubkey: key(pubkey)?, relays: tlv.strings(1) })
        }
        "nevent" => {
            let tlv = parse_tlv(&data)?;
            let id = tlv.first(0).ok_or_else(|| error("missing TLV 0 for nevent"))?;
            Ok(Decoded::Nevent { id: key(id)? })
        }
        "naddr" => {
            let tlv = parse_tlv(&data)?;
            let identifier = tlv.first(0).ok_or_else(|| error("missing TLV 0 for naddr"))?;
            let pubkey = tlv.first(2).ok_or_else(|| error("missing TLV 2 for naddr"))?;
            let kind = tlv.first(3).ok_or_else(|| error("missing TLV 3 for naddr"))?;
            let kind: [u8; 4] = kind.try_into().map_err(|_| error("TLV 3 should be 4 bytes"))?;
            Ok(Decoded::Naddr {
                pubkey: key(pubkey)?,
                kind: u32::from_be_bytes(kind),
                identifier: String::from_utf8(identifier.to_vec()).map_err(|_| error("identifier is not UTF-8"))?,
                relays: tlv.strings(1),
            })
        }
        other => Err(error(format!("unknown prefix {other}"))),
    }
}

/// A pubkey's npub. Every pubkey held was checked where it entered, so
/// anything that isn't 32 bytes of hex is a bug upstream, and gets an empty
/// string — plainly wrong — rather than a valid-looking npub of nothing.
#[cfg(test)]
pub fn npub_encode(pubkey_hex: &str) -> String {
    encode_key("npub", pubkey_hex)
}

// TLV entries are written highest type first, as nostr-tools writes them, so
// that an entity encoded here is byte-identical to one a client encodes.

#[cfg(test)]
pub fn nprofile_encode(pubkey_hex: &str, relays: &[String]) -> String {
    let mut data = Vec::new();
    for relay in relays {
        push_tlv(&mut data, 1, relay.as_bytes());
    }
    let Some(pubkey) = key_bytes(pubkey_hex) else { return String::new() };
    push_tlv(&mut data, 0, &pubkey);
    bech32_encode("nprofile", &data)
}

/// An address's naddr; empty for a pubkey that isn't one, as [`npub_encode`].
pub fn naddr_encode(pubkey_hex: &str, kind: u32, identifier: &str, relays: &[String]) -> String {
    let Some(pubkey) = key_bytes(pubkey_hex) else { return String::new() };
    let mut data = Vec::new();
    push_tlv(&mut data, 3, &kind.to_be_bytes());
    push_tlv(&mut data, 2, &pubkey);
    for relay in relays {
        push_tlv(&mut data, 1, relay.as_bytes());
    }
    push_tlv(&mut data, 0, identifier.as_bytes());
    bech32_encode("naddr", &data)
}

#[cfg(test)]
fn encode_key(hrp: &str, hex_key: &str) -> String {
    key_bytes(hex_key).map_or_else(String::new, |key| bech32_encode(hrp, &key))
}

/// A key's 32 bytes, from exactly 64 hex digits.
fn key_bytes(hex_key: &str) -> Option<[u8; 32]> {
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(hex_key, &mut bytes).ok()?;
    Some(bytes)
}

fn key(bytes: &[u8]) -> Result<String, Error> {
    if bytes.len() != 32 {
        return Err(error("expected 32 bytes"));
    }
    Ok(hex::encode(bytes))
}

fn push_tlv(data: &mut Vec<u8>, kind: u8, value: &[u8]) {
    // One byte of length; nostr-tools refuses anything longer, and so would
    // every decoder.
    let value = &value[..value.len().min(255)];
    data.push(kind);
    data.push(value.len() as u8);
    data.extend_from_slice(value);
}

struct Tlv(Vec<(u8, Vec<u8>)>);

impl Tlv {
    fn first(&self, kind: u8) -> Option<&[u8]> {
        self.0.iter().find(|(k, _)| *k == kind).map(|(_, v)| v.as_slice())
    }

    fn strings(&self, kind: u8) -> Vec<String> {
        self.0
            .iter()
            .filter(|(k, _)| *k == kind)
            .filter_map(|(_, v)| String::from_utf8(v.clone()).ok())
            .collect()
    }
}

fn parse_tlv(mut data: &[u8]) -> Result<Tlv, Error> {
    let mut entries = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(error("truncated TLV"));
        }
        let kind = data[0];
        let len = data[1] as usize;
        let value = data.get(2..2 + len).ok_or_else(|| error(format!("not enough data to read on TLV {kind}")))?;
        entries.push((kind, value.to_vec()));
        data = &data[2 + len..];
    }
    Ok(Tlv(entries))
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for value in values {
        let top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ u32::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let bytes = hrp.as_bytes();
    let mut out: Vec<u8> = bytes.iter().map(|b| b >> 5).collect();
    out.push(0);
    out.extend(bytes.iter().map(|b| b & 31));
    out
}

fn bech32_encode(hrp: &str, data: &[u8]) -> String {
    let words = convert_bits(data, 8, 5, true).unwrap_or_default();
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&words);
    values.extend_from_slice(&[0; 6]);
    let checksum = polymod(values) ^ 1;

    let mut out = String::with_capacity(hrp.len() + 1 + words.len() + 6);
    out.push_str(hrp);
    out.push('1');
    for word in &words {
        out.push(CHARSET[*word as usize] as char);
    }
    for i in 0..6 {
        out.push(CHARSET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    out
}

fn bech32_decode(value: &str) -> Result<(String, Vec<u8>), Error> {
    if value.len() > MAX_LENGTH {
        return Err(error("string is too long"));
    }
    let has_lower = value.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = value.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(error("mixed-case string"));
    }
    let value = value.to_ascii_lowercase();

    let separator = value.rfind('1').ok_or_else(|| error("no separator character"))?;
    if separator == 0 || separator + 7 > value.len() {
        return Err(error("invalid separator position"));
    }
    let hrp = &value[..separator];
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err(error("invalid prefix"));
    }

    let mut words = Vec::with_capacity(value.len() - separator - 1);
    for c in value[separator + 1..].bytes() {
        let index = CHARSET.iter().position(|&x| x == c).ok_or_else(|| error(format!("unknown character {}", c as char)))?;
        words.push(index as u8);
    }

    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&words);
    if polymod(values) != 1 {
        return Err(error("invalid checksum"));
    }

    words.truncate(words.len() - 6);
    let data = convert_bits(&words, 5, 8, false).ok_or_else(|| error("invalid padding"))?;
    Ok((hrp.to_string(), data))
}

fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);

    for &value in data {
        let value = u32::from(value);
        if value >> from != 0 {
            return None;
        }
        acc = (acc << from) | value;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }

    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max) != 0 {
        return None;
    }

    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUBKEY: &str = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";

    #[test]
    fn npub_round_trip() {
        let npub = npub_encode(PUBKEY);
        assert_eq!(npub, "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6");
        assert_eq!(decode(&npub).unwrap(), Decoded::Npub(PUBKEY.into()));
        assert_eq!(decode(&npub.to_uppercase()).unwrap(), Decoded::Npub(PUBKEY.into()));
    }

    #[test]
    fn naddr_round_trip() {
        let naddr = naddr_encode(PUBKEY, 35128, "docs", &["wss://relay.example.com".into()]);
        assert_eq!(
            decode(&naddr).unwrap(),
            Decoded::Naddr {
                pubkey: PUBKEY.into(),
                kind: 35128,
                identifier: "docs".into(),
                relays: vec!["wss://relay.example.com".into()]
            }
        );
    }

    /// As nostr-tools encodes it.
    #[test]
    fn naddr_matches_nostr_tools() {
        assert_eq!(
            naddr_encode("364bd18e313eff510f2eeacbde1af7eec764807f23a3c1bd5309e40ded376dd5", 15128, "", &[]),
            "naddr1qvzqqqpmrqpzqdjt6x8rz0hl2y8ja6ktmcd00mk8vjq87garcx74xz0yphknwmw4qqqqe6t958"
        );
    }

    #[test]
    fn nprofile_round_trip() {
        let nprofile = nprofile_encode(PUBKEY, &["wss://r.example.com".into()]);
        assert!(matches!(decode(&nprofile).unwrap(), Decoded::Nprofile { pubkey, .. } if pubkey == PUBKEY));
    }

    #[test]
    fn refuses_bad_checksums() {
        let mut npub = npub_encode(PUBKEY);
        npub.pop();
        npub.push('q');
        assert!(decode(&npub).is_err());
        assert!(decode("npub1").is_err());
    }

    #[test]
    fn refuses_to_encode_what_is_not_a_key() {
        assert_eq!(npub_encode(""), "");
        assert_eq!(npub_encode("abc"), "");
        assert_eq!(naddr_encode(&"z".repeat(64), 35128, "docs", &[]), "");
    }
}
