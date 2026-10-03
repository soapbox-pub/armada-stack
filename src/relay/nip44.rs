//! The shape of NIP-44 v2 payloads.
//!
//! The relay can't decrypt, but it can refuse anything that couldn't be a v2
//! payload: `base64(0x02 ‖ nonce[32] ‖ ciphertext ‖ mac[32])`, where the
//! ciphertext is a 2-byte length then the plaintext, padded as NIP-44 pads.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const MAX_PLAINTEXT: usize = 65535;

/// NIP-44's `calc_padded_len`.
pub fn padded_len(unpadded: usize) -> usize {
    if unpadded <= 32 {
        return 32;
    }
    let next_power = 1usize << (usize::BITS - (unpadded - 1).leading_zeros());
    let chunk = if next_power <= 256 { 32 } else { next_power / 8 };
    chunk * ((unpadded - 1) / chunk + 1)
}

/// Whether `content` could be a NIP-44 v2 payload.
pub fn is_v2_payload(content: &str) -> bool {
    // A one-byte plaintext: 1 + 32 + 2 + 32 + 32 bytes, 132 in base64.
    const MIN_DECODED: usize = 99;
    let max_encoded = (1 + 32 + 2 + padded_len(MAX_PLAINTEXT) + 32_usize).div_ceil(3) * 4;
    if content.len() < 132 || content.len() > max_encoded {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(content) else { return false };
    if bytes.len() < MIN_DECODED || bytes[0] != 2 {
        return false;
    }
    let padded = bytes.len() - 1 - 32 - 2 - 32;
    padded <= padded_len(MAX_PLAINTEXT) && padded_len(padded) == padded
}

/// A payload of the right shape: random bytes rather than ciphertext.
#[cfg(test)]
pub fn payload(plaintext_len: usize) -> String {
    let mut bytes = vec![2u8];
    bytes.extend(std::iter::repeat_n(0xab, 32 + 2 + padded_len(plaintext_len) + 32));
    STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pads_as_the_spec_does() {
        for (input, expected) in [
            (1, 32),
            (32, 32),
            (33, 64),
            (37, 64),
            (45, 64),
            (49, 64),
            (64, 64),
            (65, 96),
            (100, 128),
            (111, 128),
            (200, 224),
            (250, 256),
            (320, 320),
            (383, 384),
            (384, 384),
            (400, 448),
            (500, 512),
            (512, 512),
            (515, 640),
            (700, 768),
            (800, 896),
            (900, 1024),
            (1020, 1024),
            (65536, 65536),
        ] {
            assert_eq!(padded_len(input), expected, "{input}");
        }
    }

    #[test]
    fn accepts_well_formed_payloads() {
        for len in [1, 32, 33, 300, 5000, 65535] {
            assert!(is_v2_payload(&payload(len)), "{len}");
        }
    }

    #[test]
    fn refuses_malformed_payloads() {
        assert!(!is_v2_payload(""));
        assert!(!is_v2_payload("hello world"));
        assert!(!is_v2_payload(&"A".repeat(200)));
        // Version 1.
        assert!(!is_v2_payload(&STANDARD.encode([&[1u8][..], &[0; 98]].concat())));
        // A length padding can't produce.
        assert!(!is_v2_payload(&STANDARD.encode([&[2u8][..], &[0; 99]].concat())));
        // Unpadded base64.
        assert!(!is_v2_payload(payload(33).trim_end_matches('=')));
        // NIP-04.
        assert!(!is_v2_payload(&format!("{}?iv=abcdefghijklmnopqrstuv==", "A".repeat(200))));
    }
}
