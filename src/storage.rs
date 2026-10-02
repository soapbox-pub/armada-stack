//! The storage directory the whole stack shares.
//!
//! ```text
//! <storage_dir>/
//!   web/       LMDB: the site's versions and which one is served
//!   relay/     LMDB: the relay's events
//!   blossom/   LMDB: the Blossom server's blob records
//!   blobs/     the content-addressed blob store, shared
//! ```
//!
//! One LMDB environment per service rather than one for the stack: LMDB
//! allows a single writer per environment, and the relay's writes shouldn't
//! wait behind a deploy's. Separate environments can also be sized, backed up,
//! and wiped one at a time. Blob bytes stay out of LMDB altogether — large
//! values are what it handles worst — and live in one store, so a blob the
//! web service downloaded is one the Blossom server already has.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use heed::{Env, EnvOpenOptions, WithoutTls};

use crate::blobs::BlobStore;

pub struct Storage {
    root: PathBuf,
    pub blobs: BlobStore,
}

impl Storage {
    pub fn open(root: &Path) -> Result<Storage> {
        std::fs::create_dir_all(root).with_context(|| format!("Could not create the storage directory {}", root.display()))?;
        let root = root.canonicalize()?;
        let blobs = BlobStore::new(&root.join("blobs"));
        Ok(Storage { root, blobs })
    }

    /// A store whose blob downloads may reach private addresses. For tests.
    #[cfg(test)]
    pub fn allowing_private(root: &Path) -> Storage {
        Storage { root: root.to_path_buf(), blobs: BlobStore::allowing_private(&root.join("blobs")) }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Open the LMDB environment of one service, creating it if need be.
    ///
    /// `map_size` is the most the database may grow to. It's address space
    /// reserved, not disk used, so generous is free.
    pub fn env(&self, service: &str, map_size: usize, max_dbs: u32) -> Result<Env<WithoutTls>> {
        let path = self.root.join(service);
        std::fs::create_dir_all(&path).with_context(|| format!("Could not create {}", path.display()))?;
        // SAFETY: each environment is opened once per process, and nothing else
        // writes to its files while it is open.
        unsafe { EnvOpenOptions::new().read_txn_without_tls().map_size(map_size).max_dbs(max_dbs).open(&path) }
            .with_context(|| format!("Could not open the database at {}", path.display()))
    }
}
