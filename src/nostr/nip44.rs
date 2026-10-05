//! NIP-44 v2 encryption: the payloads the [push service](crate::push)
//! talks to its clients in.
//!
//! A conversation key is HKDF-extract over the x coordinate of the two
//! keys' shared point, salted with `nip44-v2`; each message expands it with
//! a fresh nonce into a ChaCha20 key and nonce and an HMAC key. The payload
//! is `base64(0x02 ‖ nonce[32] ‖ ciphertext ‖ mac[32])`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use secp256k1::{Parity, PublicKey, SecretKey, XOnlyPublicKey};
use sha2::Sha256;

/// The longest plaintext v2 carries.
const MAX_PLAINTEXT: usize = 65535;

/// The key two parties share: the same either way round.
pub fn conversation_key(secret: &SecretKey, pubkey: &XOnlyPublicKey) -> [u8; 32] {
    let point = secp256k1::ecdh::shared_secret_point(&PublicKey::from_x_only_public_key(*pubkey, Parity::Even), secret);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &point[..32]);
    prk.into()
}

/// The ChaCha20 key and nonce and the HMAC key for one message.
fn message_keys(conversation_key: &[u8; 32], nonce: &[u8; 32]) -> ([u8; 32], [u8; 12], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::from_prk(conversation_key).expect("32 bytes is a valid PRK");
    let mut keys = [0u8; 76];
    hkdf.expand(nonce, &mut keys).expect("76 bytes is a valid length");
    (keys[..32].try_into().unwrap(), keys[32..44].try_into().unwrap(), keys[44..].try_into().unwrap())
}

fn mac(hmac_key: &[u8; 32], nonce: &[u8; 32], ciphertext: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key).expect("any key length");
    mac.update(nonce);
    mac.update(ciphertext);
    mac
}

/// Encrypt with a fresh random nonce. `None` if the plaintext is empty or
/// longer than v2 allows.
pub fn encrypt(conversation_key: &[u8; 32], plaintext: &str) -> Option<String> {
    encrypt_with_nonce(conversation_key, plaintext, &rand::random())
}

fn encrypt_with_nonce(conversation_key: &[u8; 32], plaintext: &str, nonce: &[u8; 32]) -> Option<String> {
    let len = plaintext.len();
    if len == 0 || len > MAX_PLAINTEXT {
        return None;
    }
    let mut padded = Vec::with_capacity(2 + crate::relay::nip44::padded_len(len));
    padded.extend_from_slice(&(len as u16).to_be_bytes());
    padded.extend_from_slice(plaintext.as_bytes());
    padded.resize(2 + crate::relay::nip44::padded_len(len), 0);

    let (key, chacha_nonce, hmac_key) = message_keys(conversation_key, nonce);
    ChaCha20::new(&key.into(), &chacha_nonce.into()).apply_keystream(&mut padded);
    let tag = mac(&hmac_key, nonce, &padded).finalize().into_bytes();

    let mut payload = Vec::with_capacity(1 + 32 + padded.len() + 32);
    payload.push(2);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&padded);
    payload.extend_from_slice(&tag);
    Some(STANDARD.encode(payload))
}

/// Decrypt a payload, or `None` if it isn't a valid v2 payload for this key.
pub fn decrypt(conversation_key: &[u8; 32], payload: &str) -> Option<String> {
    if payload.starts_with('#') {
        return None;
    }
    let bytes = STANDARD.decode(payload).ok()?;
    // Version, nonce, the shortest padded plaintext and its length, and MAC.
    if bytes.len() < 1 + 32 + 2 + 32 + 32 || bytes[0] != 2 {
        return None;
    }
    let nonce: [u8; 32] = bytes[1..33].try_into().unwrap();
    let (ciphertext, tag) = bytes[33..].split_at(bytes.len() - 33 - 32);
    let (key, chacha_nonce, hmac_key) = message_keys(conversation_key, &nonce);
    mac(&hmac_key, &nonce, ciphertext).verify_slice(tag).ok()?;

    let mut padded = ciphertext.to_vec();
    ChaCha20::new(&key.into(), &chacha_nonce.into()).apply_keystream(&mut padded);
    let len = u16::from_be_bytes([padded[0], padded[1]]) as usize;
    if len == 0 || padded.len() != 2 + crate::relay::nip44::padded_len(len) {
        return None;
    }
    String::from_utf8(padded[2..2 + len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(hex: &str) -> SecretKey {
        SecretKey::from_slice(&hex::decode(hex).unwrap()).unwrap()
    }

    fn xonly(secret: &SecretKey) -> XOnlyPublicKey {
        secret.x_only_public_key(secp256k1::SECP256K1).0
    }

    /// From NIP-44's `nip44.vectors.json`.
    #[test]
    fn matches_the_spec_vectors() {
        let one = "0000000000000000000000000000000000000000000000000000000000000001";
        let two = "0000000000000000000000000000000000000000000000000000000000000002";
        let cases = [
            (one, two, "0000000000000000000000000000000000000000000000000000000000000001", "a", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"),
            (two, one, "f00000000000000000000000000000f00000000000000000000000000000000f", "🍕🫃", "AvAAAAAAAAAAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAAPSKSK6is9ngkX2+cSq85Th16oRTISAOfhStnixqZziKMDvB0QQzgFZdjLTPicCJaV8nDITO+QfaQ61+KbWQIOO2Yj"),
        ];
        for (sec1, sec2, nonce, plaintext, payload) in cases {
            let key = conversation_key(&secret(sec1), &xonly(&secret(sec2)));
            assert_eq!(hex::encode(key), "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d");
            assert_eq!(conversation_key(&secret(sec2), &xonly(&secret(sec1))), key);
            let nonce: [u8; 32] = hex::decode(nonce).unwrap().try_into().unwrap();
            assert_eq!(encrypt_with_nonce(&key, plaintext, &nonce).unwrap(), payload);
            assert_eq!(decrypt(&key, payload).unwrap(), plaintext);
        }
    }

    #[test]
    fn round_trips_and_refuses_what_it_should() {
        let key = conversation_key(&secret(&"11".repeat(32)), &xonly(&secret(&"22".repeat(32))));
        for len in [1, 32, 33, 1000, MAX_PLAINTEXT] {
            let plaintext = "x".repeat(len);
            let payload = encrypt(&key, &plaintext).unwrap();
            assert!(crate::relay::nip44::is_v2_payload(&payload));
            assert_eq!(decrypt(&key, &payload).unwrap(), plaintext);
        }
        assert!(encrypt(&key, "").is_none());
        assert!(encrypt(&key, &"x".repeat(MAX_PLAINTEXT + 1)).is_none());

        // From the spec's invalid vectors: a bad MAC, and an unknown version.
        let bad_mac = "Agn/l3ULCEAS4V7LhGFM6IGA17jsDUaFCKhrbXDANholyySBfeh+EN8wNB9gaLlg4j6wdBYh+3oK+mnxWu3NKRbSvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key: [u8; 32] = hex::decode("cff7bd6a3e29a450fd27f6c125d5edeb0987c475fd1e8d97591e0d4d8a89763c").unwrap().try_into().unwrap();
        assert!(decrypt(&key, bad_mac).is_none());
        assert!(decrypt(&key, "#Atqupco0WyaOW2IGDKcshwxI9xO8HgD/P8Ddt46CbxDbrhdG8VmJdU0MIDf06CUvEvdnr1cp1fiMtlM/GrE92xAc1K5odTpCzUB+mjXgbaqtntBUbTToSUoT0ovrlPwzGjyp").is_none());
        assert!(decrypt(&key, "not base64!").is_none());
    }
}
