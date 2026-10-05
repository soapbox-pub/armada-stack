//! Builds LiveKit in, when `ARMADA_LIVEKIT` names a `livekit-server` binary
//! for the target: compressed into `OUT_DIR` with its sha256, for
//! `src/av/builtin.rs` to include. `ARMADA_LIVEKIT_VERSION` says which
//! release it is. Without it, armada is built without LiveKit and offers AV
//! only on nodes in `[[av.nodes]]`; release builds always have it.

use std::io::Write;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

fn main() {
    println!("cargo::rerun-if-env-changed=ARMADA_LIVEKIT");
    println!("cargo::rerun-if-env-changed=ARMADA_LIVEKIT_VERSION");
    println!("cargo::rustc-check-cfg=cfg(armada_livekit)");
    let Some(path) = std::env::var_os("ARMADA_LIVEKIT").filter(|path| !path.is_empty()) else { return };
    let path = PathBuf::from(path);
    println!("cargo::rerun-if-changed={}", path.display());

    let binary = std::fs::read(&path).unwrap_or_else(|error| panic!("ARMADA_LIVEKIT: could not read {}: {error}", path.display()));
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let file = std::fs::File::create(out.join("livekit.gz")).expect("OUT_DIR is writable");
    let mut gz = flate2::write::GzEncoder::new(std::io::BufWriter::new(file), flate2::Compression::best());
    gz.write_all(&binary).expect("compressing LiveKit");
    gz.finish().expect("compressing LiveKit").flush().expect("compressing LiveKit");
    let sha256: String = Sha256::digest(&binary).iter().map(|byte| format!("{byte:02x}")).collect();
    std::fs::write(out.join("livekit.sha256"), sha256).expect("OUT_DIR is writable");

    let version = std::env::var("ARMADA_LIVEKIT_VERSION").unwrap_or_else(|_| "unknown".into());
    println!("cargo::rustc-env=ARMADA_LIVEKIT_VERSION={version}");
    println!("cargo::rustc-cfg=armada_livekit");
}
