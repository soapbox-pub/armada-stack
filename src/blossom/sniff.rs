//! Telling ciphertext from everything else.
//!
//! The server never holds a key, so it can't prove a blob is encrypted.
//! Armada's blobs carry no header to check either: they are bare AES-256-GCM
//! output, `ciphertext || 16-byte tag`, with the key and nonce kept in the
//! encrypted message that links to them. What the server can do is refuse
//! anything that plainly isn't ciphertext. Good ciphertext is
//! indistinguishable from uniform random bytes, so a blob is refused when it:
//!
//! - is shorter than a GCM tag, so can't be AES-GCM output at all;
//! - opens with the signature of a known file format;
//! - is text: valid UTF-8 without control characters;
//! - has one byte value far more often than chance allows;
//! - is large enough for a chi-squared test of its byte frequencies, and
//!   fails it.
//!
//! Every threshold is set so random bytes trip it less than about once in
//! a billion blobs. This catches anything that *looks* unencrypted. It can't
//! catch a plaintext deliberately made to look random — compressed data with
//! its header stripped would pass — and isn't meant to.

use crate::blobs::Inspector;

/// The shortest blob accepted: AES-GCM output is at least its 16-byte tag.
pub const MIN_SIZE: u64 = 16;

/// Bytes of the head kept for matching signatures.
const HEAD: usize = 64;

/// The chi-squared test needs about eight expected hits per byte value
/// before its distribution is a fair approximation.
const CHI_SQUARED_MIN: u64 = 2048;

/// The chi-squared statistic, over 255 degrees of freedom, that uniform
/// bytes exceed with probability about 10⁻⁹ (Wilson–Hilferty).
const CHI_SQUARED_LIMIT: f64 = 420.0;

/// The chance of a false refusal each per-byte-count test may allow.
const FALSE_REJECTION: f64 = 1e-9;

/// File signatures: an offset, the bytes found there, and a name for the
/// refusal. Nothing shorter than three bytes, which random data would open
/// with too often.
const SIGNATURES: &[(usize, &[u8], &str)] = &[
    (0, b"\x89PNG\r\n\x1a\n", "a PNG image"),
    (0, b"\xff\xd8\xff", "a JPEG image"),
    (0, b"GIF87a", "a GIF image"),
    (0, b"GIF89a", "a GIF image"),
    (0, b"RIFF", "a RIFF file (WebP, WAV or AVI)"),
    (4, b"ftyp", "an ISO media file (MP4, MOV, HEIC, AVIF or M4A)"),
    (0, b"\x1a\x45\xdf\xa3", "a Matroska or WebM video"),
    (0, b"OggS", "an Ogg file"),
    (0, b"fLaC", "a FLAC file"),
    (0, b"ID3", "an MP3 file"),
    (0, b"FORM", "an AIFF file"),
    (0, b"#!AMR", "an AMR audio file"),
    (0, b"MThd", "a MIDI file"),
    (0, b"FLV\x01", "an FLV video"),
    (0, b"\x30\x26\xb2\x75", "an ASF or WMV file"),
    (0, b"\x00\x00\x01\xba", "an MPEG stream"),
    (0, b"\x00\x00\x01\xb3", "an MPEG stream"),
    (0, b"%PDF-", "a PDF"),
    (0, b"PK\x03\x04", "a ZIP archive or office document"),
    (0, b"PK\x05\x06", "a ZIP archive"),
    (0, b"PK\x07\x08", "a ZIP archive"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "an old office document"),
    (0, b"{\\rtf", "an RTF document"),
    (0, b"\x1f\x8b\x08", "a gzip archive"),
    (0, b"BZh", "a bzip2 archive"),
    (0, b"\xfd7zXZ\x00", "an xz archive"),
    (0, b"\x28\xb5\x2f\xfd", "a zstd archive"),
    (0, b"7z\xbc\xaf\x27\x1c", "a 7-Zip archive"),
    (0, b"Rar!\x1a\x07", "a RAR archive"),
    (0, b"MSCF", "a CAB archive"),
    (0, b"SQLite format 3\x00", "an SQLite database"),
    (0, b"\x7fELF", "an executable"),
    (0, b"\xca\xfe\xba\xbe", "an executable or Java class"),
    (0, b"\xcf\xfa\xed\xfe", "an executable"),
    (0, b"\x00asm", "a WebAssembly module"),
    (0, b"II*\x00", "a TIFF or camera raw image"),
    (0, b"MM\x00*", "a TIFF or camera raw image"),
    (0, b"8BPS", "a Photoshop document"),
    (0, b"\x00\x00\x00\x0cJXL \r\n\x87\n", "a JPEG XL image"),
    (0, b"\x00\x00\x00\x0cjP  \r\n\x87\n", "a JPEG 2000 image"),
    (0, b"\x00\x00\x01\x00", "an icon"),
    (0, b"qoif", "a QOI image"),
    (0, b"wOFF", "a web font"),
    (0, b"wOF2", "a web font"),
    (0, b"OTTO", "a font"),
    (0, b"\x00\x01\x00\x00\x00", "a font"),
    (0, b"\xef\xbb\xbf", "UTF-8 text"),
];

/// Watches an upload go by and refuses it unless it looks like ciphertext.
pub struct Sniffer {
    head: Vec<u8>,
    head_checked: bool,
    counts: Box<[u64; 256]>,
    len: u64,
    text: Text,
}

impl Default for Sniffer {
    fn default() -> Self {
        Sniffer { head: Vec::with_capacity(HEAD), head_checked: false, counts: Box::new([0; 256]), len: 0, text: Text::default() }
    }
}

impl Inspector for Sniffer {
    fn chunk(&mut self, bytes: &[u8]) -> Result<(), String> {
        if !self.head_checked {
            let wanted = HEAD - self.head.len();
            self.head.extend_from_slice(&bytes[..wanted.min(bytes.len())]);
            // Checked as soon as the head is in, so a plain file is refused
            // before the rest of it is read.
            if self.head.len() == HEAD {
                self.head_checked = true;
                check_signature(&self.head)?;
            }
        }
        for &byte in bytes {
            self.counts[byte as usize] += 1;
        }
        self.len += bytes.len() as u64;
        self.text.update(bytes);
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        if self.len < MIN_SIZE {
            return Err(refusal("is too short to be encrypted"));
        }
        if !self.head_checked {
            check_signature(&self.head)?;
        }
        if self.text.is_text() {
            return Err(refusal("is text"));
        }
        let most = self.counts.iter().copied().max().unwrap_or(0);
        if most > max_count(self.len) {
            return Err(refusal("repeats one byte far too often"));
        }
        if self.len >= CHI_SQUARED_MIN && chi_squared(&self.counts, self.len) > CHI_SQUARED_LIMIT {
            return Err(refusal("doesn't look random"));
        }
        Ok(())
    }
}

fn refusal(why: &str) -> String {
    format!("Only encrypted blobs are accepted, and this one {why}.")
}

fn check_signature(head: &[u8]) -> Result<(), String> {
    for (offset, signature, name) in SIGNATURES {
        if head.get(*offset..offset + signature.len()) == Some(signature) {
            return Err(refusal(&format!("looks like {name}")));
        }
    }
    Ok(())
}

/// Whether the bytes so far are valid UTF-8 with no control characters
/// beyond whitespace, followed one byte at a time across chunks. Overlong
/// forms and surrogates pass, which only makes it slower to call something
/// text.
#[derive(Default)]
struct Text {
    broken: bool,
    /// Continuation bytes the current character still needs.
    pending: u8,
}

impl Text {
    fn update(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            if self.broken {
                return;
            }
            if self.pending > 0 {
                if byte & 0xc0 == 0x80 {
                    self.pending -= 1;
                } else {
                    self.broken = true;
                }
                continue;
            }
            match byte {
                b'\t' | b'\n' | b'\r' | 0x0c | 0x20..=0x7e => {}
                0xc2..=0xdf => self.pending = 1,
                0xe0..=0xef => self.pending = 2,
                0xf0..=0xf4 => self.pending = 3,
                _ => self.broken = true,
            }
        }
    }

    fn is_text(&self) -> bool {
        !self.broken && self.pending == 0
    }
}

/// The most times one byte value may appear among `n` random bytes: past
/// it, some value is that common with probability under
/// [`FALSE_REJECTION`]. A union bound over the 256 values of the Chernoff
/// bound P(X ≥ t) ≤ exp(−n·D(t/n ‖ 1/256)), so the true rate is lower still.
fn max_count(n: u64) -> u64 {
    let p = 1.0 / 256.0;
    let nf = n as f64;
    let limit = (FALSE_REJECTION / 256.0).ln();
    let mut t = (nf * p).ceil() as u64 + 1;
    loop {
        let q = t as f64 / nf;
        if q >= 1.0 {
            return n;
        }
        let divergence = q * (q / p).ln() + (1.0 - q) * ((1.0 - q) / (1.0 - p)).ln();
        if -nf * divergence <= limit {
            return t;
        }
        // Linear steps are fine for small blobs; big ones take bigger steps,
        // which only errs towards accepting.
        t += 1.max(t / 64);
    }
}

fn chi_squared(counts: &[u64; 256], n: u64) -> f64 {
    let expected = n as f64 / 256.0;
    counts.iter().map(|&count| (count as f64 - expected).powi(2) / expected).sum()
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::consts::U16;
    use aes_gcm::aead::{Aead, KeyInit};
    use aes_gcm::aes::Aes256;
    use aes_gcm::{AesGcm, Nonce};
    use rand::rngs::StdRng;
    use rand::{RngCore, SeedableRng};

    use super::*;

    fn sniff(bytes: &[u8]) -> Result<(), String> {
        sniff_in(bytes, bytes.len().max(1))
    }

    /// Fed in chunks of `size`, as a body arrives.
    fn sniff_in(bytes: &[u8], size: usize) -> Result<(), String> {
        let mut sniffer = Sniffer::default();
        for chunk in bytes.chunks(size) {
            sniffer.chunk(chunk)?;
        }
        sniffer.finish()
    }

    fn random(rng: &mut StdRng, n: usize) -> Vec<u8> {
        let mut bytes = vec![0; n];
        rng.fill_bytes(&mut bytes);
        bytes
    }

    /// Exactly what Armada uploads: AES-256-GCM with a 16-byte nonce, the
    /// tag appended.
    fn armada_encrypt(plaintext: &[u8]) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(7);
        let key = random(&mut rng, 32);
        let nonce = random(&mut rng, 16);
        let cipher = AesGcm::<Aes256, U16>::new_from_slice(&key).unwrap();
        cipher.encrypt(Nonce::<U16>::from_slice(&nonce), plaintext).unwrap()
    }

    #[test]
    fn accepts_armada_ciphertext() {
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(2000);
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend(vec![0u8; 50_000]);
        for plaintext in [text.as_bytes(), &png, b"", b"hi"] {
            let ciphertext = armada_encrypt(plaintext);
            assert_eq!(ciphertext.len(), plaintext.len() + 16);
            assert_eq!(sniff(&ciphertext), Ok(()));
            assert_eq!(sniff_in(&ciphertext, 7), Ok(()));
        }
    }

    #[test]
    fn accepts_random_bytes_of_any_size() {
        let mut rng = StdRng::seed_from_u64(1);
        for n in (32..4096).step_by(7).chain([16, 17, 20, 24, 100_000, 1 << 20]) {
            for _ in 0..if n < 4096 { 20 } else { 3 } {
                let bytes = random(&mut rng, n);
                assert_eq!(sniff_in(&bytes, 1000), Ok(()), "{n} random bytes");
            }
        }
    }

    #[test]
    fn refuses_known_formats() {
        let mut rng = StdRng::seed_from_u64(2);
        let headers: &[&[u8]] = &[
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00",
            b"GIF89a",
            b"RIFF\x00\x00\x00\x00WEBPVP8 ",
            b"\x00\x00\x00\x20ftypisom",
            b"\x00\x00\x00\x1cftypheic",
            b"\x1a\x45\xdf\xa3",
            b"%PDF-1.7\n",
            b"PK\x03\x04\x14\x00",
            b"\x1f\x8b\x08\x00",
            b"ID3\x04\x00",
            b"OggS\x00\x02",
        ];
        for header in headers {
            // A random body, so only the signature gives it away.
            let mut bytes = header.to_vec();
            bytes.extend(random(&mut rng, 10_000));
            assert!(sniff(&bytes).unwrap_err().contains("looks like"), "{header:?}");
            // Refused from the head alone, before the body is read.
            let mut sniffer = Sniffer::default();
            assert!(sniffer.chunk(&bytes[..HEAD]).is_err());

            let mut short = header.to_vec();
            short.resize(20, 0xaa);
            assert!(sniff(&short).is_err(), "short {header:?}");
        }
    }

    #[test]
    fn refuses_text() {
        assert!(sniff(b"hello, this is a plain message").unwrap_err().contains("is text"));
        assert!(sniff("Grüße aus Köln, 日本語のテキスト\n".as_bytes()).unwrap_err().contains("is text"));
        assert!(sniff(b"<!DOCTYPE html><html><body>hi</body></html>").is_err());
        let json = format!("{{\"a\": [{}]}}", "1, ".repeat(5000));
        assert!(sniff_in(json.as_bytes(), 333).is_err());
    }

    #[test]
    fn refuses_structured_binary() {
        assert!(sniff(&[0u8; 100]).unwrap_err().contains("repeats"));
        // Mostly random, with one value padded in.
        let mut rng = StdRng::seed_from_u64(3);
        let mut bytes = random(&mut rng, 1000);
        bytes.extend([0u8; 100]);
        assert!(sniff(&bytes).is_err());
        // Each value equally often, but in a pattern no cipher makes: only
        // the low half of the byte range.
        let skewed: Vec<u8> = random(&mut rng, 100_000).into_iter().map(|b| b & 0x7f | 0x01).collect();
        assert!(sniff(&skewed).is_err());
        // Flat enough that no one value stands out, but still not random.
        // Odd values 5% more often than chance, even ones 5% less.
        use rand::seq::SliceRandom;
        let mut skewed: Vec<u8> = (0..=255u8).flat_map(|v| std::iter::repeat_n(v, if v % 2 == 1 { 4101 } else { 3711 })).collect();
        skewed.shuffle(&mut rng);
        assert!(sniff(&skewed).unwrap_err().contains("random"));
    }

    #[test]
    fn refuses_tiny_blobs() {
        let mut rng = StdRng::seed_from_u64(4);
        assert!(sniff(&random(&mut rng, 15)).unwrap_err().contains("too short"));
        assert!(sniff(b"").is_err());
    }

    #[test]
    fn max_counts_are_sane() {
        // About the mean plus a margin, never below it.
        for n in [16u64, 100, 1000, 10_000, 1 << 20, 100 << 20] {
            let t = max_count(n);
            assert!(t as f64 > n as f64 / 256.0, "{n}: {t}");
            assert!(t <= n);
        }
        assert!(max_count(1 << 20) < (1 << 20) / 200);
    }
}
