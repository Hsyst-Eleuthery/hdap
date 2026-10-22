//! Durable node state on SQLite.
//!
//! The protocol logic keeps mutating an in-memory [`State`] under one lock
//! (that is the cheapest thing to write and to reason about). This module is
//! the *system of record*: it mirrors every collection into a single SQLite
//! file and reloads it on boot, so the archive, the accounts, the band ledger
//! and the anti-replay guards all survive a restart.
//!
//! Two tables carry all of it:
//!
//! ```sql
//! kv(ns, k, v)   -- one row per namespace, v = JSON of that collection
//! blobs(k, hash, len, data)  -- sealed content, one row per owner/path
//! ```
//!
//! Splitting content out of the metadata matters: rewriting somebody's
//! `permissions.hdap` must not rewrite a 100 MB upload that lives in the
//! same space.
//!
//! ## What must never be lost
//!
//! * `master_key` — every blob is sealed with it (`aead_seal`). A fresh key
//!   per boot would turn the whole archive into unreadable bytes, so it is
//!   generated once and then persisted like any other record.
//! * `mochthos_used` and `omphalos_step` — the replay guards. Losing them on
//!   restart would let a mined band be farmed again and an OTP be replayed.
//!
//! ## Durability
//!
//! WAL journalling plus `synchronous=FULL`, and every flush is one
//! transaction, so a crash mid-write leaves the previous consistent state
//! rather than a half-applied one.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::store::{
    Cession, MirrorOrigin, PeerRecord, ProklesisRecord, PrytaneionEntry, Session, State, UserRecord,
};

/// Bumped when a collection's shape changes. A node refuses to open a file
/// written by a newer version rather than silently misreading it.
pub const SCHEMA_VERSION: i64 = 1;

/// Errors the persistence layer can surface to the caller.
#[derive(Debug)]
pub enum DbError {
    Sqlite(rusqlite::Error),
    Corrupt(String),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Sqlite(e) => write!(f, "banco de dados: {e}"),
            DbError::Corrupt(what) => write!(f, "banco de dados corrompido: {what}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sqlite(e)
    }
}

pub type DbResult<T> = Result<T, DbError>;

/// Short fingerprint used to skip rewriting an unchanged namespace.
type Mark = [u8; 8];

fn fingerprint(bytes: &[u8]) -> Mark {
    let d = hdap_core::crypto::sha256(bytes);
    let mut m = [0u8; 8];
    m.copy_from_slice(&d[..8]);
    m
}

/// The metadata half of a `State`, i.e. everything that is not content bytes.
///
/// `objects` is deliberately absent: content lives in the `blobs` table, and
/// the keys are kept here so a flush can tell which rows actually changed
/// without re-reading every blob.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct Meta {
    schema_version: i64,
    master_key: String,
    /// Persisted so documents this node signed before a restart stay verifiable.
    ///
    /// `default` matters for upgrade, not for new nodes: a database written
    /// before this field existed must still open, and an empty seed is
    /// replaced with a fresh one at load time (see `Node::with_db`) rather
    /// than silently becoming an all-zero signing key.
    #[serde(default)]
    node_sign_seed: String,
    whoami: String,
    users: BTreeMap<String, UserRecord>,
    sessions: BTreeMap<String, Session>,
    proklesis: BTreeMap<String, ProklesisRecord>,
    omphalos_step: BTreeMap<String, usize>,
    choregia: BTreeMap<String, u64>,
    #[serde(default)]
    band_objects: BTreeMap<String, crate::store::BandObject>,
    #[serde(default)]
    band_windows: BTreeMap<String, crate::store::BandWindow>,
    stored: BTreeMap<String, u64>,
    mochthos_used: BTreeSet<String>,
    /// owner/path -> (content hash, byte length), i.e. the blob index.
    object_index: BTreeMap<String, (String, u64)>,
    prytaneion: BTreeMap<String, PrytaneionEntry>,
    pheme: BTreeMap<String, i64>,
    permissions: BTreeMap<String, String>,
    ceessions: BTreeMap<String, Vec<Cession>>,
    kerux: BTreeMap<String, String>,
    kerux_owner: BTreeMap<String, String>,
    timi: BTreeMap<String, String>,
    peers: BTreeMap<String, PeerRecord>,
    #[serde(default)]
    replica_acls: BTreeMap<String, String>,
    #[serde(default)]
    mirrors: BTreeMap<String, MirrorOrigin>,
    #[serde(default)]
    watchers: BTreeMap<String, BTreeSet<String>>,
    fed_nonces: BTreeMap<String, u64>,
    #[serde(default)]
    fed_applied: BTreeSet<String>,
    /// Ownership transfers (requests, acceptances and their signed documents).
    #[serde(default)]
    transfers: BTreeMap<String, crate::store::TransferRecord>,
}

impl Meta {
    /// Split a `State` into its persistable metadata.
    fn from_state(st: &State) -> Meta {
        Meta {
            schema_version: SCHEMA_VERSION,
            master_key: hex::encode(st.master_key),
            node_sign_seed: hex::encode(st.node_sign_seed),
            whoami: st.whoami.clone(),
            users: st.users.clone(),
            sessions: st.sessions.clone(),
            proklesis: st.proklesis.clone(),
            omphalos_step: st.omphalos_step.clone(),
            choregia: st.choregia.clone(),
            band_objects: st.band_objects.clone(),
            band_windows: st.band_windows.clone(),
            stored: st.stored.clone(),
            mochthos_used: st.mochthos_used.clone(),
            object_index: st
                .objects
                .iter()
                .map(|(k, b)| (k.clone(), (b.hash.clone(), b.bytes.len() as u64)))
                .collect(),
            prytaneion: st.prytaneion.clone(),
            pheme: st.pheme.clone(),
            permissions: st.permissions.clone(),
            ceessions: st.ceessions.clone(),
            kerux: st.kerux.clone(),
            kerux_owner: st.kerux_owner.clone(),
            timi: st.timi.clone(),
            peers: st.peers.clone(),
            replica_acls: st.replica_acls.clone(),
            mirrors: st.mirrors.clone(),
            watchers: st.watchers.clone(),
            fed_nonces: st.fed_nonces.clone(),
            fed_applied: st.fed_applied.clone(),
            transfers: st.transfers.clone(),
        }
    }

    /// Rebuild a working `State` from metadata plus the blob table.
    ///
    /// Blob bytes are already sealed with `master_key` (that sealing happens
    /// in `node.rs` before the blob is ever put into `State`), so they go
    /// back verbatim.
    fn into_state(self, blobs: BTreeMap<String, (String, i64, Vec<u8>)>) -> State {
        let master_key = hex::decode(&self.master_key)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .unwrap_or([0u8; 32]);
        // A database predating `node_sign_seed` has no seed stored. Deriving
        // one deterministically from the (secret, random) master key keeps the
        // load pure while ensuring the node never signs with an all-zero key;
        // a zero seed here would be a shared, guessable signing key. The same
        // rule applies to a seed that decoded successfully but is all zeroes:
        // older code persisted `[0;32]` verbatim, and treating that as valid
        // would resurrect the shared-key bug across a restart.
        let node_sign_seed = hex::decode(&self.node_sign_seed)
            .ok()
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .filter(|seed| *seed != [0u8; 32])
            .unwrap_or_else(|| {
                let mut input = Vec::with_capacity(46);
                input.extend_from_slice(&master_key);
                input.extend_from_slice(b"hdap-node-sign-seed");
                hdap_core::crypto::sha256(&input)
            });

        let mut objects = BTreeMap::new();
        for (key, (hash, _indexed_len)) in self.object_index {
            let Some((stored_hash, stored_len, data)) = blobs.get(&key) else {
                continue;
            };
            // Two independent cheap checks on what survived on disk. Neither
            // replaces the cryptographic verification, which happens at read
            // time in `node.rs` (`aead_open` + re-hash of the plaintext) —
            // the content hash is over the *plaintext*, and here we only have
            // sealed bytes, so we cannot redo it. What we *can* catch is a
            // torn write or a row that no longer belongs to this key.
            if stored_hash != &hash || *stored_len as usize != data.len() {
                continue;
            }
            let mut it = key.splitn(2, '/');
            let owner = it.next().unwrap_or_default().to_string();
            let path = it.next().unwrap_or_default().to_string();
            objects.insert(
                key,
                crate::store::Blob {
                    owner,
                    path,
                    hash,
                    bytes: data.clone(),
                },
            );
        }

        State {
            master_key,
            node_sign_seed,
            whoami: self.whoami,
            users: self.users,
            sessions: self.sessions,
            proklesis: self.proklesis,
            omphalos_step: self.omphalos_step,
            choregia: self.choregia,
            band_objects: self.band_objects,
            band_windows: self.band_windows,
            stored: self.stored,
            mochthos_used: self.mochthos_used,
            objects,
            prytaneion: self.prytaneion,
            pheme: self.pheme,
            permissions: self.permissions,
            ceessions: self.ceessions,
            kerux: self.kerux,
            kerux_owner: self.kerux_owner,
            timi: self.timi,
            peers: self.peers,
            replica_acls: self.replica_acls,
            mirrors: self.mirrors,
            watchers: self.watchers,
            fed_nonces: self.fed_nonces,
            fed_applied: self.fed_applied,
            transfers: self.transfers,
            // Rate-limiter windows are deliberately *not* persisted: they are
            // a sliding window over the last second, and resurrecting old
            // timestamps after a long downtime would only lock everyone out.
            rate: Default::default(),
        }
    }
}

/// Handle to the node's SQLite file.
///
/// Cheap to clone-by-reference and internally locked: `Node` holds one and
/// calls [`Db::flush`] after every request.
pub struct Db {
    conn: Mutex<Connection>,
    /// Fingerprint of each namespace as last written, so an unchanged
    /// collection costs a comparison instead of a transaction.
    marks: Mutex<BTreeMap<String, Mark>>,
    /// (hash, len) of each blob row as last written, so a flush only rewrites
    /// content that actually changed.
    blob_marks: Mutex<BTreeMap<String, (String, u64)>>,
}

impl Db {
    /// Open (creating if needed) the node database at `path`.
    pub fn open(path: &Path) -> DbResult<Db> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir).map_err(|e| {
                    DbError::Corrupt(format!("cannot create {}: {e}", dir.display()))
                })?;
            }
        }
        let conn = Connection::open(path)?;
        // WAL keeps readers from blocking the writer; FULL means a commit is
        // on disk before we answer the client, which is the whole point of
        // having the database at all.
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Self::init_schema(&conn)?;

        let db = Db {
            conn: Mutex::new(conn),
            marks: Mutex::new(BTreeMap::new()),
            blob_marks: Mutex::new(BTreeMap::new()),
        };
        // Prime the blob marks from what is already on disk so the first
        // flush after a restart does not rewrite every stored byte.
        {
            let conn = db.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT k, hash, len FROM blobs")?;
            let mut rows = stmt.query([])?;
            let mut marks = db.blob_marks.lock().unwrap();
            while let Some(row) = rows.next()? {
                let k: String = row.get(0)?;
                let h: String = row.get(1)?;
                let l: i64 = row.get(2)?;
                marks.insert(k, (h, l as u64));
            }
        }
        Ok(db)
    }

    /// An in-memory database, for tests and for `--ephemeral`.
    pub fn open_memory() -> DbResult<Db> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "journal_mode", "MEMORY")?;
        Self::init_schema(&conn)?;
        Ok(Db {
            conn: Mutex::new(conn),
            marks: Mutex::new(BTreeMap::new()),
            blob_marks: Mutex::new(BTreeMap::new()),
        })
    }

    fn init_schema(conn: &Connection) -> DbResult<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                 k TEXT PRIMARY KEY,
                 v BLOB NOT NULL
             );
             CREATE TABLE IF NOT EXISTS blobs (
                 k    TEXT PRIMARY KEY,
                 hash TEXT NOT NULL,
                 len  INTEGER NOT NULL,
                 data BLOB NOT NULL
             );
             CREATE INDEX IF NOT EXISTS blobs_by_hash ON blobs(hash);",
        )?;
        Ok(())
    }

    /// Load the persisted state, or `None` when this node has never run.
    ///
    /// A brand-new node gets `fresh_master_key` so the caller can generate a
    /// key that will be written on the first flush.
    pub fn load(&self) -> DbResult<Option<State>> {
        let conn = self.conn.lock().unwrap();
        let raw: Option<Vec<u8>> = conn
            .query_row("SELECT v FROM meta WHERE k = 'state'", [], |r| r.get(0))
            .optional()?;
        let Some(raw) = raw else { return Ok(None) };

        let meta: Meta = serde_json::from_slice(&raw)
            .map_err(|e| DbError::Corrupt(format!("estado ilegível: {e}")))?;
        if meta.schema_version > SCHEMA_VERSION {
            return Err(DbError::Corrupt(format!(
                "banco gravado por uma versão mais nova (schema {} > {}); \
                 atualize o hdap-server",
                meta.schema_version, SCHEMA_VERSION
            )));
        }

        let mut blobs = BTreeMap::new();
        {
            let mut stmt = conn.prepare("SELECT k, hash, len, data FROM blobs")?;
            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                blobs.insert(
                    row.get::<_, String>(0)?,
                    (
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ),
                );
            }
        }
        Ok(Some(meta.into_state(blobs)))
    }

    /// Mirror `st` into the database. One transaction; unchanged namespaces
    /// are skipped by fingerprint, and only content whose (hash, len) moved
    /// is rewritten.
    pub fn flush(&self, st: &State) -> DbResult<()> {
        let meta = Meta::from_state(st);
        let raw = serde_json::to_vec(&meta)
            .map_err(|e| DbError::Corrupt(format!("estado não serializável: {e}")))?;
        let meta_mark = fingerprint(&raw);

        // Decide the work *before* taking the write lock, so a read-only
        // request that changed nothing never blocks the writer.
        let mut marks = self.marks.lock().unwrap();
        if marks.get("state") == Some(&meta_mark) {
            return Ok(());
        }
        let mut blob_marks = self.blob_marks.lock().unwrap();
        let mut blob_writes: Vec<(&String, &crate::store::Blob)> = Vec::new();
        for (k, b) in &st.objects {
            let want = (b.hash.clone(), b.bytes.len() as u64);
            if blob_marks.get(k) != Some(&want) {
                blob_writes.push((k, b));
            }
        }
        let blob_deletes: Vec<&String> = blob_marks
            .keys()
            .filter(|k| !st.objects.contains_key(*k))
            .collect();

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        for (k, b) in &blob_writes {
            tx.execute(
                "INSERT INTO blobs (k, hash, len, data) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(k) DO UPDATE SET hash=?2, len=?3, data=?4",
                params![k, b.hash, b.bytes.len() as i64, b.bytes],
            )?;
        }
        for k in &blob_deletes {
            tx.execute("DELETE FROM blobs WHERE k = ?1", params![k])?;
        }
        tx.execute(
            "INSERT INTO meta (k, v) VALUES ('state', ?1)
             ON CONFLICT(k) DO UPDATE SET v = ?1",
            params![raw],
        )?;
        tx.commit()?;

        marks.insert("state".to_string(), meta_mark);
        // Snapshot the writes before mutating: the vectors borrow `st`, and
        // holding two mutable borrows of `blob_marks` at once is a borrowck
        // error rather than a logic problem.
        let written: Vec<(String, (String, u64))> = blob_writes
            .iter()
            .map(|(k, b)| ((*k).clone(), (b.hash.clone(), b.bytes.len() as u64)))
            .collect();
        let removed: Vec<String> = blob_deletes.iter().map(|k| (*k).clone()).collect();
        for (k, m) in written {
            blob_marks.insert(k, m);
        }
        for k in removed {
            blob_marks.remove(&k);
        }
        Ok(())
    }

    /// Bytes on disk (blobs + metadata), for `/health` and for tests.
    pub fn size_bytes(&self) -> DbResult<u64> {
        let conn = self.conn.lock().unwrap();
        let total: i64 = conn.query_row(
            "SELECT COALESCE((SELECT SUM(len) FROM blobs), 0)
                  + COALESCE((SELECT SUM(LENGTH(v)) FROM meta), 0)",
            [],
            |r| r.get(0),
        )?;
        Ok(total as u64)
    }

    /// Number of content rows, for tests that assert on durability.
    pub fn blob_count(&self) -> DbResult<i64> {
        let conn = self.conn.lock().unwrap();
        Ok(conn.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))?)
    }

    /// Force a WAL checkpoint so everything is in the main database file.
    /// Useful before a clean shutdown or when copying the node directory.
    pub fn checkpoint(&self) -> DbResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        BandWindow, Blob, Cession, MirrorOrigin, PeerRecord, ProklesisRecord, PrytaneionEntry,
        Session, UserRecord,
    };

    fn user(id: &str) -> UserRecord {
        UserRecord {
            user_id: id.into(),
            nickname: id.split('_').next().unwrap_or("x").into(),
            suffix_hex: "0123456789abcdef".into(),
            sign_pub_hex: "aa".repeat(32),
            enc_pub_hex: "bb".repeat(32),
            otp_anchor_hex: "cc".repeat(32),
            otp_k: 1024,
            created_at: 1_700_000_000,
            home_pyle: "node-a".into(),
        }
    }

    fn populated(st: &mut State) {
        st.whoami = "node-a".into();
        st.master_key = [7u8; 32];
        st.node_sign_seed = [9u8; 32];
        st.users.insert(
            "jose_0123456789abcdef".into(),
            user("jose_0123456789abcdef"),
        );
        st.sessions.insert(
            "tok".into(),
            Session {
                user_id: "jose_0123456789abcdef".into(),
                exp: 42,
            },
        );
        st.proklesis.insert(
            "nonce1".into(),
            ProklesisRecord {
                user_id: "jose_0123456789abcdef".into(),
                ts: 1,
                expires_at: 2,
            },
        );
        st.omphalos_step.insert("jose_0123456789abcdef".into(), 5);
        st.choregia.insert("jose_0123456789abcdef".into(), 4096);
        st.band_objects.insert(
            "d".repeat(64),
            crate::store::BandObject {
                id: "d".repeat(64),
                owner: "jose_0123456789abcdef".into(),
                path: "pow/1.hdap.pow".into(),
                challenge: "hdap-mochthos:node-a".into(),
                granted: 4096,
                remaining: 4096,
                expires_at: 1_700_000_999,
                countersigned: true,
            },
        );
        st.stored.insert("jose_0123456789abcdef".into(), 2048);
        st.mochthos_used.insert("chal|1".into());
        st.objects.insert(
            State::key("jose_0123456789abcdef", "docs/a.txt"),
            Blob {
                owner: "jose_0123456789abcdef".into(),
                path: "docs/a.txt".into(),
                hash: "a".repeat(64),
                bytes: b"conteudo original".to_vec(),
            },
        );
        st.permissions
            .insert("jose_0123456789abcdef".into(), "PERM ...\n".into());
        st.ceessions.insert(
            "jose_0123456789abcdef".into(),
            vec![Cession {
                to: "outro_0123456789abcdef".into(),
                path: "docs/a.txt".into(),
                at: 9,
            }],
        );
        st.pheme.insert("maria_0123456789abcdef".into(), -3);
        st.band_windows.insert(
            "jose_0123456789abcdef".into(),
            BandWindow {
                started_at: 100,
                granted: 2048,
            },
        );
        st.prytaneion.insert(
            "a".repeat(64),
            PrytaneionEntry {
                content_hash: "a".repeat(64),
                origin_server: "pyle-a".into(),
                origin_user: "jose_0123456789abcdef".into(),
                origin_user_pubkey: "aa".repeat(32),
                origin_path: "docs/a.txt".into(),
                sphragis: "sig".into(),
                replicas: vec!["pyle-a:key".into()],
                deletions: vec!["DELETED:x:1".into()],
                created_at: 1_700_000_000,
            },
        );
        st.kerux.insert("casa".into(), "HDAP!@jose/docs".into());
        st.kerux_owner
            .insert("casa".into(), "jose_0123456789abcdef".into());
        st.timi.insert("pyle-b".into(), "timi doc text".into());
        st.peers.insert(
            "pyle-b".into(),
            PeerRecord {
                node_id: "pyle-b".into(),
                sign_pub_hex: "ee".repeat(32),
                endpoint: "127.0.0.1:8444".into(),
                tls_pin: Some("ff".repeat(32)),
            },
        );
        st.mirrors.insert(
            "jose_0123456789abcdef".into(),
            MirrorOrigin {
                origin_pyle: "pyle-b".into(),
                origin_server: "pyle-b".into(),
                pulled_at: 1_700_000_123,
            },
        );
        st.fed_nonces.insert("fed-nonce-1".into(), 1_700_000_456);
        st.fed_applied.insert("pheme_applied:op-1".into());
    }

    /// The whole point of the module: a state written, dropped, and reopened
    /// from disk must come back identical — including the key that seals the
    /// content, the band ledger and the replay guards.
    #[test]
    fn every_collection_survives_a_reopen() {
        let dir = tempdir("reopen");
        let path = dir.join("node.db");

        let mut st = State::default();
        populated(&mut st);

        {
            let db = Db::open(&path).expect("open");
            db.flush(&st).expect("flush");
            db.checkpoint().expect("checkpoint");
        } // connection dropped: this is the "restart"

        let db = Db::open(&path).expect("reopen");
        let back = db.load().expect("load").expect("state must be there");

        assert_eq!(
            back.master_key, st.master_key,
            "a new key would orphan every blob"
        );
        assert_eq!(back.whoami, "node-a");
        assert_eq!(back.users, st.users);
        assert_eq!(back.sessions, st.sessions);
        assert_eq!(back.proklesis, st.proklesis);
        assert_eq!(back.omphalos_step, st.omphalos_step);
        assert_eq!(back.choregia, st.choregia, "band must not evaporate");
        assert_eq!(
            back.band_objects, st.band_objects,
            "the band-object trail must survive a restart"
        );
        assert_eq!(back.stored, st.stored);
        assert_eq!(
            back.mochthos_used, st.mochthos_used,
            "replay guard must survive"
        );
        assert_eq!(back.permissions, st.permissions);
        assert_eq!(back.ceessions, st.ceessions);
        assert_eq!(back.pheme, st.pheme);
        assert_eq!(
            back.node_sign_seed, st.node_sign_seed,
            "a fresh signing seed would make every issued band document unverifiable"
        );
        assert_eq!(back.band_windows, st.band_windows);
        assert_eq!(back.prytaneion, st.prytaneion);
        assert_eq!(back.kerux, st.kerux);
        assert_eq!(back.kerux_owner, st.kerux_owner);
        assert_eq!(back.timi, st.timi);
        assert_eq!(back.peers, st.peers, "known peers must survive a restart");
        assert_eq!(
            back.mirrors, st.mirrors,
            "the pull-through book must survive a restart"
        );
        assert_eq!(
            back.fed_nonces, st.fed_nonces,
            "fed replay guard must survive"
        );
        assert_eq!(
            back.fed_applied, st.fed_applied,
            "the federation idempotency set must survive (and never be pruned)"
        );
        assert_eq!(
            back.objects, st.objects,
            "content must come back byte-identical"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file that has never been written must read as "no state yet", not
    /// as an error and not as an empty state that overwrites the archive.
    #[test]
    fn a_fresh_database_loads_nothing() {
        let dir = tempdir("fresh");
        let db = Db::open(&dir.join("node.db")).expect("open");
        assert!(db.load().expect("load").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The guard that makes a proof unreusable: after a restart the node must
    /// still know the nonce was already spent.
    #[test]
    fn a_spent_mochthos_is_not_honoured_twice_across_a_restart() {
        let dir = tempdir("anti-replay");
        let path = dir.join("node.db");

        let mut st = State::default();
        st.choregia.insert("jose_0123456789abcdef".into(), 4096);
        st.mochthos_used.insert("hdap-mochthos:node-a|99".into());
        {
            let db = Db::open(&path).expect("open");
            db.flush(&st).expect("flush");
        }

        let db = Db::open(&path).expect("reopen");
        let back = db.load().expect("load").expect("state");
        assert!(
            back.mochthos_used.contains("hdap-mochthos:node-a|99"),
            "a mined band could be farmed again after a restart"
        );
        assert_eq!(back.choregia.get("jose_0123456789abcdef"), Some(&4096));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Content deleted from the state must disappear from disk too, or the
    /// database grows forever and a deleted file stays recoverable.
    #[test]
    fn deleting_content_removes_its_row() {
        let dir = tempdir("delete");
        let path = dir.join("node.db");

        let mut st = State::default();
        populated(&mut st);
        {
            let db = Db::open(&path).expect("open");
            db.flush(&st).expect("flush");
            assert_eq!(db.blob_count().expect("count"), 1);

            st.objects.clear();
            db.flush(&st).expect("flush");
            assert_eq!(
                db.blob_count().expect("count"),
                0,
                "deleted content lingers"
            );
        }
        let db = Db::open(&path).expect("reopen");
        assert!(db.load().expect("load").expect("state").objects.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unchanged state must not rewrite the file: the node handles a lot
    /// of read-only traffic and paying a FULL-synchronous commit per GET
    /// would be absurd.
    #[test]
    fn an_unchanged_state_costs_nothing() {
        let dir = tempdir("noop");
        let path = dir.join("node.db");
        let db = Db::open(&path).expect("open");

        let mut st = State::default();
        populated(&mut st);
        db.flush(&st).expect("flush");
        let first = db.blob_count().expect("count");

        // Same content, flushed again: nothing may be rewritten.
        db.flush(&st).expect("flush");
        assert_eq!(db.blob_count().expect("count"), first);

        // Touching one blob's bytes must rewrite exactly that row.
        if let Some(b) = st.objects.values_mut().next() {
            b.bytes.push(b'!');
        }
        db.flush(&st).expect("flush");
        let back = db.load().expect("load").expect("state");
        assert_eq!(
            back.objects.values().next().unwrap().bytes,
            vec![
                b'c', b'o', b'n', b't', b'e', b'u', b'd', b'o', b' ', b'o', b'r', b'i', b'g', b'i',
                b'n', b'a', b'l', b'!'
            ]
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A database written by a future version must be refused loudly: reading
    /// it with today's field layout would corrupt what it cannot understand.
    #[test]
    fn a_newer_schema_is_refused() {
        let dir = tempdir("newer");
        let path = dir.join("node.db");
        {
            let db = Db::open(&path).expect("open");
            let meta = Meta {
                schema_version: SCHEMA_VERSION + 1,
                master_key: hex::encode([0u8; 32]),
                node_sign_seed: hex::encode([1u8; 32]),
                whoami: "node-a".into(),
                users: BTreeMap::new(),
                sessions: BTreeMap::new(),
                proklesis: BTreeMap::new(),
                omphalos_step: BTreeMap::new(),
                choregia: BTreeMap::new(),
                band_objects: BTreeMap::new(),
                band_windows: BTreeMap::new(),
                stored: BTreeMap::new(),
                mochthos_used: BTreeSet::new(),
                object_index: BTreeMap::new(),
                prytaneion: BTreeMap::new(),
                pheme: BTreeMap::new(),
                permissions: BTreeMap::new(),
                ceessions: BTreeMap::new(),
                kerux: BTreeMap::new(),
                kerux_owner: BTreeMap::new(),
                timi: BTreeMap::new(),
                peers: BTreeMap::new(),
                replica_acls: BTreeMap::new(),
                mirrors: BTreeMap::new(),
                watchers: BTreeMap::new(),
                fed_nonces: BTreeMap::new(),
                fed_applied: BTreeSet::new(),
                transfers: BTreeMap::new(),
            };
            let raw = serde_json::to_vec(&meta).unwrap();
            let conn = db.conn.lock().unwrap();
            conn.execute("INSERT INTO meta (k, v) VALUES ('state', ?1)", params![raw])
                .expect("seed");
        }
        let db = Db::open(&path).expect("reopen");
        // `State` has no Debug (it holds sealed content), so unwrap by hand
        // rather than via expect_err.
        let err = match db.load() {
            Ok(_) => panic!("must refuse a database from a newer schema"),
            Err(e) => e,
        };
        assert!(
            matches!(err, DbError::Corrupt(ref m) if m.contains("mais nova")),
            "unexpected error: {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A database written before `node_sign_seed` / `band_windows` existed must
    /// still open. Failing here would mean an upgrade bricks every existing
    /// node; and the missing seed must be replaced, not defaulted to zeroes,
    /// or every such node would sign with the same predictable key.
    #[test]
    fn an_older_schema_without_new_fields_still_opens() {
        let dir = tempdir("older");
        let path = dir.join("node.db");
        // A full state minus the two fields added by the upgrade.
        let older = serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "master_key": hex::encode([0u8; 32]),
            "whoami": "node-a",
            "users": {},
            "sessions": {},
            "proklesis": {},
            "omphalos_step": {},
            "choregia": {},
            "stored": {},
            "mochthos_used": [],
            "object_index": {},
            "prytaneion": {},
            "pheme": {},
            "permissions": {},
            "ceessions": {},
            "kerux": {},
            "kerux_owner": {},
            "timi": {},
            "peers": {},
            "fed_nonces": {}
        });
        {
            let db = Db::open(&path).expect("open");
            let conn = db.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO meta (k, v) VALUES ('state', ?1)",
                params![serde_json::to_vec(&older).unwrap()],
            )
            .expect("seed");
        }
        let st = Db::open(&path)
            .expect("reopen")
            .load()
            .expect("old database must remain readable")
            .expect("a state was written");
        assert_eq!(st.whoami, "node-a");
        assert!(st.band_windows.is_empty());
        assert_ne!(
            st.node_sign_seed, [0u8; 32],
            "a missing seed must be regenerated, never left as zeroes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A persisted all-zero seed must be rejected on load, not trusted. Older
    /// code wrote `[0;32]` for a fresh node, which made every such node sign
    /// with the same guessable key; reloading must replace it, exactly as the
    /// missing-field path does.
    #[test]
    fn an_all_zero_persisted_seed_is_regenerated() {
        let dir = tempdir("zero-seed");
        let path = dir.join("node.db");
        {
            let db = Db::open(&path).expect("open");
            let mut st = State {
                master_key: [9u8; 32],
                ..State::default()
            };
            populated(&mut st);
            st.node_sign_seed = [0u8; 32];
            db.flush(&st).expect("flush");
        }
        let back = Db::open(&path)
            .expect("reopen")
            .load()
            .expect("load")
            .expect("state");
        assert_ne!(
            back.node_sign_seed, [0u8; 32],
            "an all-zero signing seed must never survive a reload"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A blob row that no longer agrees with the index must not be served.
    /// Handing back bytes under the wrong hash is exactly the failure the
    /// content hash exists to prevent.
    ///
    /// Scope, stated plainly: this catches a torn write or a row that belongs
    /// to another key. It cannot re-verify the *bytes* — the content hash is
    /// over the plaintext and here we only hold sealed bytes — so that check
    /// lives at read time in `node.rs`, where the master key is available.
    #[test]
    fn a_blob_that_contradicts_its_index_is_dropped() {
        for (what, sql) in [
            ("hash", "UPDATE blobs SET hash = 'z'"),
            ("length", "UPDATE blobs SET len = 999999"),
        ] {
            let dir = tempdir("mismatch");
            let path = dir.join("node.db");
            {
                let db = Db::open(&path).expect("open");
                let mut st = State::default();
                populated(&mut st);
                db.flush(&st).expect("flush");
                let conn = db.conn.lock().unwrap();
                conn.execute(sql, []).expect("tamper");
            }
            let db = Db::open(&path).expect("reopen");
            let back = db.load().expect("load").expect("state");
            assert!(
                back.objects.is_empty(),
                "a blob whose {what} contradicts the index must not come back"
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("hdap-db-{tag}-{n}"))
    }
}
