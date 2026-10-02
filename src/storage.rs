//! The storage directory the whole stack shares.
//!
//! ```text
//! <storage_dir>/
//!   web/            LMDB: the site's versions and which one is served
//!   relay/          LMDB: the relay's events
//!   blossom/        LMDB: the Blossom server's blob records and owners
//!   blossom/blobs/  the Blossom server's own blob store
//!   blobs/          the content-addressed blob store the site is served from
//! ```
//!
//! One LMDB environment per service rather than one for the stack: LMDB
//! allows a single writer per environment, and the relay's writes shouldn't
//! wait behind a deploy's. Separate environments can also be sized, backed up,
//! and wiped one at a time. Blob bytes stay out of LMDB altogether — large
//! values are what it handles worst.
//!
//! The Blossom server keeps its blobs apart from the site's. It only ever
//! holds ciphertext, which the site's files never are, so sharing would buy
//! nothing — and apart, deleting an upload can't touch a file the site needs.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use heed::{Env, EnvOpenOptions, WithoutTls};

use crate::blobs::BlobStore;

pub struct Storage {
    root: PathBuf,
    pub blobs: BlobStore,
    /// Whether blob stores opened here may only download from public
    /// addresses. Only tests turn this off.
    public_only: bool,
}

impl Storage {
    pub fn open(root: &Path) -> Result<Storage> {
        std::fs::create_dir_all(root).with_context(|| format!("Could not create the storage directory {}", root.display()))?;
        let root = root.canonicalize()?;
        let blobs = BlobStore::new(&root.join("blobs"));
        Ok(Storage { root, blobs, public_only: true })
    }

    /// A store whose blob downloads may reach private addresses. For tests.
    #[cfg(test)]
    pub fn allowing_private(root: &Path) -> Storage {
        Storage { root: root.to_path_buf(), blobs: BlobStore::allowing_private(&root.join("blobs")), public_only: false }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A blob store of its own at `relative` beneath the root, downloading
    /// under the same rules as the shared one.
    pub fn blob_store(&self, relative: &str) -> BlobStore {
        let dir = self.root.join(relative);
        #[cfg(test)]
        if !self.public_only {
            return BlobStore::allowing_private(&dir);
        }
        debug_assert!(self.public_only);
        BlobStore::new(&dir)
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
