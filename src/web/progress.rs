//! How far the sync worker has got, for the page shown while there's no
//! site to serve yet. It says what stage the worker is at and no more: why a
//! deploy failed is for the operator's log, not for every visitor.

use parking_lot::Mutex;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Stage {
    /// Asking the relays for the site's manifest.
    #[default]
    Searching,
    /// No relay had it; the next resync asks again.
    NotFound,
    /// Fetching the version's blobs: `done` of `total` are on disk.
    Downloading { done: usize, total: usize },
    /// The last attempt failed; another comes.
    Failed,
}

#[derive(Default)]
pub struct Progress(Mutex<Stage>);

impl Progress {
    pub fn get(&self) -> Stage {
        *self.0.lock()
    }

    pub fn set(&self, stage: Stage) {
        *self.0.lock() = stage;
    }

    /// One more blob is on disk.
    pub fn downloaded_one(&self) {
        if let Stage::Downloading { done, total } = &mut *self.0.lock() {
            *done = (*done + 1).min(*total);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn says_only_the_stage() {
        let json = |stage| serde_json::to_string(&stage).unwrap();
        assert_eq!(json(Stage::Searching), r#"{"state":"searching"}"#);
        assert_eq!(json(Stage::NotFound), r#"{"state":"not_found"}"#);
        assert_eq!(json(Stage::Downloading { done: 3, total: 9 }), r#"{"state":"downloading","done":3,"total":9}"#);
        assert_eq!(json(Stage::Failed), r#"{"state":"failed"}"#);
    }

    #[test]
    fn counts_downloads_only_while_downloading() {
        let progress = Progress::default();
        progress.downloaded_one();
        assert_eq!(progress.get(), Stage::Searching);
        progress.set(Stage::Downloading { done: 1, total: 2 });
        progress.downloaded_one();
        progress.downloaded_one();
        assert_eq!(progress.get(), Stage::Downloading { done: 2, total: 2 });
    }
}
