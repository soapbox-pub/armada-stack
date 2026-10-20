//! Just enough Nostr to follow an nsite — events, NIP-19, a relay pool, and
//! the lookups built on it — NIP-44 for the push service, and keys of
//! armada's own.

pub mod event;
pub mod key;
pub mod nip19;
pub mod nip44;
pub mod pool;
pub mod service;

pub use event::Event;
