//! The push service's LMDB: one record per client, by its pubkey. The
//! service keeps them all in memory too, so this is only written to, and
//! read once at start.

use anyhow::Result;
use heed::types::{SerdeJson, Str};
use heed::{Database, Env, WithoutTls};
use serde::{Deserialize, Serialize};

use super::connection::Connection;
use super::subscriptions::Subscription;
use crate::storage::Storage;

/// Address space reserved. A client is a few KiB at most.
const MAP_SIZE: usize = 4 << 30;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Client {
    pub connection: Connection,
    pub subscriptions: Vec<Subscription>,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds of the last `create`, `set`, `get` or `ping`.
    pub last_seen: i64,
}

#[derive(Clone)]
pub struct PushDb {
    env: Env<WithoutTls>,
    clients: Database<Str, SerdeJson<Client>>,
}

impl PushDb {
    pub fn open(storage: &Storage) -> Result<PushDb> {
        let env = storage.env("push", MAP_SIZE, 1)?;
        let mut txn = env.write_txn()?;
        let clients = env.create_database(&mut txn, Some("clients"))?;
        txn.commit()?;
        Ok(PushDb { env, clients })
    }

    pub fn all(&self) -> Result<Vec<(String, Client)>> {
        let txn = self.env.read_txn()?;
        let clients = self.clients.iter(&txn)?.map(|entry| entry.map(|(pubkey, client)| (pubkey.to_string(), client))).collect::<Result<_, _>>()?;
        Ok(clients)
    }

    pub fn put(&self, pubkey: &str, client: &Client) -> Result<()> {
        let mut txn = self.env.write_txn()?;
        self.clients.put(&mut txn, pubkey, client)?;
        txn.commit()?;
        Ok(())
    }

    pub fn delete(&self, pubkeys: &[String]) -> Result<()> {
        let mut txn = self.env.write_txn()?;
        for pubkey in pubkeys {
            self.clients.delete(&mut txn, pubkey)?;
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::connection::tests::web;

    #[test]
    fn keeps_clients() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::allowing_private(dir.path());
        let db = PushDb::open(&storage).unwrap();
        let client = Client { connection: Connection::parse(&web("https://push.example.com/"), true).unwrap(), subscriptions: vec![], created_at: 1, last_seen: 2 };
        db.put("a", &client).unwrap();
        db.put("b", &client).unwrap();
        db.delete(&["a".into()]).unwrap();
        drop(db);
        assert_eq!(PushDb::open(&storage).unwrap().all().unwrap(), [("b".to_string(), client)]);
    }
}
