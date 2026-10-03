//! The shape of NIP-44 v2 payloads.
//!
//! The relay can't decrypt, but it can refuse anything that couldn't be a v2
//! payload: `base64(0x02 ‖ nonce[32] ‖ ciphertext ‖ mac[32])`, where the
//! ciphertext is the plaintext's length then the plaintext, padded as NIP-44
//! pads. The length takes 2 bytes, or 6 from 64 KiB on. NIP-44 sets no
//! practical limit on size; the relay's own limit on content does.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

/// Plaintexts this long and longer have a 6-byte length.
const EXTENDED: usize = 65536;

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
    if content.len() < 132 {
        return false;
    }
    let Ok(bytes) = STANDARD.decode(content) else { return false };
    if bytes.len() < MIN_DECODED || bytes[0] != 2 {
        return false;
    }
    let ciphertext = bytes.len() - 1 - 32 - 32;
    let is_padded = |len: usize| padded_len(len) == len;
    // A short plaintext pads to at most 64 KiB; a long one to at least that.
    is_padded(ciphertext - 2) && ciphertext - 2 <= EXTENDED || ciphertext >= 6 + EXTENDED && is_padded(ciphertext - 6)
}

/// A payload of the right shape: random bytes rather than ciphertext.
#[cfg(test)]
pub fn payload(plaintext_len: usize) -> String {
    let prefix = if plaintext_len < EXTENDED { 2 } else { 6 };
    let mut bytes = vec![2u8];
    bytes.extend(std::iter::repeat_n(0xab, 32 + prefix + padded_len(plaintext_len) + 32));
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
            (65537, 81920),
            (1 << 20, 1 << 20),
        ] {
            assert_eq!(padded_len(input), expected, "{input}");
        }
    }

    #[test]
    fn accepts_well_formed_payloads() {
        for len in [1, 32, 33, 300, 5000, 65535, 65536, 65537, 1 << 20] {
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
        let shaped = |prefix: usize, padded: usize| STANDARD.encode([&[2u8][..], &vec![0; 32 + prefix + padded + 32]].concat());
        assert!(is_v2_payload(&shaped(2, 65536)) && is_v2_payload(&shaped(6, 65536)) && is_v2_payload(&shaped(6, 81920)));
        // A length padding can't produce.
        assert!(!is_v2_payload(&shaped(2, 33)));
        assert!(!is_v2_payload(&shaped(6, 65537)));
        // A long plaintext's padding with a short one's prefix, and the reverse.
        assert!(!is_v2_payload(&shaped(2, 81920)));
        assert!(!is_v2_payload(&shaped(6, 32)));
        // Unpadded base64.
        assert!(!is_v2_payload(payload(33).trim_end_matches('=')));
        // NIP-04.
        assert!(!is_v2_payload(&format!("{}?iv=abcdefghijklmnopqrstuv==", "A".repeat(200))));
    }
}
