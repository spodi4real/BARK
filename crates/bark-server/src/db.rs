//! The coordination server's records.
//!
//! SQLite, compiled into the executable. The operator never installs a database
//! server, never configures one, and never administers one — which was a
//! requirement, not a convenience.
//!
//! **What is stored here and what is not.** This holds the device directory and
//! the audit log: which machines exist, what they are called, when they were
//! last seen, and what happened. It holds **no** private keys, **no** session
//! keys, **no** pairing codes, and nothing about what happens inside a session.
//! A copy of this file tells an attacker which computers your company has. It
//! does not let them connect to any of them — that requires a private key the
//! server has never seen, and an entry in the *target's* own trust store, which
//! the server cannot write to.
//!
//! Presence deliberately lives in memory, not here. A device is online exactly
//! when it has a live connection; writing that to disk would only create rows
//! that outlive the truth after a crash.

use bark_core::{BarkError, DeviceId, Fingerprint, Result};
use bark_crypto::PublicIdentity;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

/// Bumped when the schema changes in a way that needs migrating.
const SCHEMA_VERSION: i64 = 1;

/// One device known to the server.
#[derive(Debug, Clone, PartialEq)]
pub struct DeviceRecord {
    pub identity: PublicIdentity,
    pub name: String,
    pub os: String,
    pub bark_version: String,
    pub first_seen_unix_us: u64,
    pub last_seen_unix_us: u64,
    pub revoked: bool,
}

impl DeviceRecord {
    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    pub fn device_id(&self) -> DeviceId {
        self.identity.device_id()
    }
}

/// What happened when a device tried to register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// First time this device has been seen.
    Created,
    /// Known device; its details were refreshed.
    Updated,
    /// Refused: a *different* device already uses this short Device ID.
    ///
    /// The short ID is only 40 bits of the fingerprint, which is few enough
    /// that a determined attacker could grind a key to collide with one. That
    /// alone grants nothing — authentication uses the full public key — but two
    /// devices sharing a displayed ID would make the operator's view of their
    /// own network ambiguous, which is its own kind of security problem. So the
    /// server keeps short IDs unique and refuses the newcomer.
    ShortIdCollision { existing: Fingerprint },
}

/// A line in the server's audit log.
#[derive(Debug, Clone, PartialEq)]
pub struct AuditEntry {
    pub unix_us: u64,
    /// Device that did the thing, if it was authenticated at the time.
    pub actor: Option<Fingerprint>,
    /// Short verb: `authenticate`, `connect-request`, `pair-request`, …
    pub action: String,
    /// Device acted upon, where there is one.
    pub target: Option<Fingerprint>,
    /// Human-readable context. Must never contain secrets.
    pub detail: String,
    pub success: bool,
}

impl AuditEntry {
    pub fn new(action: impl Into<String>, success: bool) -> Self {
        AuditEntry {
            unix_us: bark_core::clock::unix_us(),
            actor: None,
            action: action.into(),
            target: None,
            detail: String::new(),
            success,
        }
    }

    pub fn actor(mut self, fp: Fingerprint) -> Self {
        self.actor = Some(fp);
        self
    }

    pub fn target(mut self, fp: Fingerprint) -> Self {
        self.target = Some(fp);
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }
}

/// The server's database.
///
/// A single connection behind a mutex. SQLite serialises writes anyway, the
/// request rate here is a handful per device per minute, and one connection
/// removes a whole class of pool-related bugs. If this ever becomes a
/// bottleneck it will be visible in a measurement, and that is the point to
/// change it.
pub struct Db {
    conn: Mutex<Connection>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Db")
    }
}

fn sql_err(what: &str, e: rusqlite::Error) -> BarkError {
    BarkError::Config(format!("The BARK server database could not {what}: {e}"))
}

impl Db {
    /// Opens or creates the database file.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path).map_err(|e| {
            BarkError::Config(format!(
                "The BARK server could not open its database at {}: {e}\n\n\
                 Possible causes:\n\
                 \u{2022} Another copy of the BARK server is already running\n\
                 \u{2022} The folder is read-only or on a disconnected drive\n\
                 \u{2022} The file is damaged",
                path.display()
            ))
        })?;
        Self::init(conn)
    }

    /// An in-memory database, for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| sql_err("start", e))?;
        Self::init(conn)
    }

    fn init(conn: Connection) -> Result<Self> {
        // WAL lets reads proceed while a write is in flight, and survives an
        // abrupt power loss without corrupting the file.
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| sql_err("enable write-ahead logging", e))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| sql_err("configure durability", e))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| sql_err("enable foreign keys", e))?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                fingerprint        TEXT PRIMARY KEY,
                device_id          TEXT NOT NULL UNIQUE,
                public_key         TEXT NOT NULL,
                name               TEXT NOT NULL DEFAULT '',
                os                 TEXT NOT NULL DEFAULT '',
                bark_version       TEXT NOT NULL DEFAULT '',
                first_seen_unix_us INTEGER NOT NULL,
                last_seen_unix_us  INTEGER NOT NULL,
                revoked            INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS audit (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                unix_us INTEGER NOT NULL,
                actor   TEXT,
                action  TEXT NOT NULL,
                target  TEXT,
                detail  TEXT NOT NULL DEFAULT '',
                success INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS audit_time ON audit (unix_us DESC);
            CREATE INDEX IF NOT EXISTS audit_actor ON audit (actor);

            -- One device's decision to stop trusting another. Affects only that
            -- pair: the blocked device can still use every other BARK machine.
            CREATE TABLE IF NOT EXISTS blocks (
                owner   TEXT NOT NULL,
                blocked TEXT NOT NULL,
                unix_us INTEGER NOT NULL,
                PRIMARY KEY (owner, blocked)
            );
            "#,
        )
        .map_err(|e| sql_err("create its tables", e))?;

        let existing: Option<String> = conn
            .query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get(0))
            .optional()
            .map_err(|e| sql_err("read its schema version", e))?;

        match existing {
            None => {
                conn.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', ?1)",
                    params![SCHEMA_VERSION.to_string()],
                )
                .map_err(|e| sql_err("record its schema version", e))?;
            }
            Some(v) => {
                let found: i64 = v.parse().unwrap_or(0);
                if found > SCHEMA_VERSION {
                    return Err(BarkError::Config(format!(
                        "This database was written by a newer version of the BARK server \
                         (format {found}, this version understands {SCHEMA_VERSION}). \
                         Update the BARK server on this computer."
                    )));
                }
                // No migrations needed yet; when version 2 exists it goes here.
            }
        }

        Ok(Db { conn: Mutex::new(conn) })
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| BarkError::other("the BARK server database is in a failed state"))
    }

    /// Records a device, or refreshes what is known about it.
    ///
    /// Called every time a device authenticates, so the directory stays current
    /// without any administration.
    pub fn register(
        &self,
        identity: &PublicIdentity,
        name: &str,
        os: &str,
        bark_version: &str,
    ) -> Result<Registration> {
        let conn = self.lock()?;
        let now = bark_core::clock::unix_us();
        let fp = identity.fingerprint().to_hex();
        let did = identity.device_id().to_string();

        let existing_fp: Option<String> = conn
            .query_row("SELECT fingerprint FROM devices WHERE device_id = ?1", params![did], |r| {
                r.get(0)
            })
            .optional()
            .map_err(|e| sql_err("look up a device", e))?;

        if let Some(other) = existing_fp {
            if other != fp {
                let existing = Fingerprint::from_hex(&other).ok_or_else(|| {
                    BarkError::Config("a stored fingerprint is malformed".into())
                })?;
                return Ok(Registration::ShortIdCollision { existing });
            }
        }

        let changed = conn
            .execute(
                "UPDATE devices
                    SET name = ?2, os = ?3, bark_version = ?4, last_seen_unix_us = ?5
                  WHERE fingerprint = ?1",
                params![fp, name, os, bark_version, now as i64],
            )
            .map_err(|e| sql_err("update a device", e))?;

        if changed > 0 {
            return Ok(Registration::Updated);
        }

        conn.execute(
            "INSERT INTO devices
                (fingerprint, device_id, public_key, name, os, bark_version,
                 first_seen_unix_us, last_seen_unix_us, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 0)",
            params![
                fp,
                did,
                hex::encode(identity.as_bytes()),
                name,
                os,
                bark_version,
                now as i64
            ],
        )
        .map_err(|e| sql_err("add a device", e))?;

        Ok(Registration::Created)
    }

    pub fn by_fingerprint(&self, fp: &Fingerprint) -> Result<Option<DeviceRecord>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT public_key, name, os, bark_version, first_seen_unix_us,
                    last_seen_unix_us, revoked
               FROM devices WHERE fingerprint = ?1",
            params![fp.to_hex()],
            row_to_record,
        )
        .optional()
        .map_err(|e| sql_err("look up a device", e))?
        .transpose()
    }

    pub fn by_device_id(&self, id: &DeviceId) -> Result<Option<DeviceRecord>> {
        let conn = self.lock()?;
        conn.query_row(
            "SELECT public_key, name, os, bark_version, first_seen_unix_us,
                    last_seen_unix_us, revoked
               FROM devices WHERE device_id = ?1",
            params![id.to_string()],
            row_to_record,
        )
        .optional()
        .map_err(|e| sql_err("look up a device", e))?
        .transpose()
    }

    pub fn touch_seen(&self, fp: &Fingerprint) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "UPDATE devices SET last_seen_unix_us = ?2 WHERE fingerprint = ?1",
            params![fp.to_hex(), bark_core::clock::unix_us() as i64],
        )
        .map_err(|e| sql_err("record that a device was seen", e))?;
        Ok(())
    }

    /// Marks a device as revoked, so the server refuses to signal for it.
    ///
    /// This is a server-side block in addition to, never instead of, the
    /// target's own trust store. A device removed here but still trusted by a
    /// peer could still be reached by direct address; a device revoked in the
    /// peer's trust store cannot connect at all. Both exist because the first
    /// is convenient and the second is the actual guarantee.
    pub fn set_revoked(&self, fp: &Fingerprint, revoked: bool) -> Result<bool> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "UPDATE devices SET revoked = ?2 WHERE fingerprint = ?1",
                params![fp.to_hex(), i64::from(revoked)],
            )
            .map_err(|e| sql_err("change a device's revocation", e))?;
        Ok(n > 0)
    }

    pub fn list_devices(&self) -> Result<Vec<DeviceRecord>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT public_key, name, os, bark_version, first_seen_unix_us,
                        last_seen_unix_us, revoked
                   FROM devices ORDER BY name COLLATE NOCASE, device_id",
            )
            .map_err(|e| sql_err("list devices", e))?;
        let rows = stmt
            .query_map([], row_to_record)
            .map_err(|e| sql_err("list devices", e))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| sql_err("read a device", e))??);
        }
        Ok(out)
    }

    /// Records that `owner` no longer accepts connections from `blocked`.
    ///
    /// This is *per pair*. It stops the server introducing `blocked` to
    /// `owner`; it does not affect `blocked` anywhere else. Banning a device
    /// from the whole network is a different, administrator-only action
    /// ([`set_revoked`](Self::set_revoked)).
    pub fn block_pair(&self, owner: &Fingerprint, blocked: &Fingerprint) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO blocks (owner, blocked, unix_us) VALUES (?1, ?2, ?3)",
            params![owner.to_hex(), blocked.to_hex(), bark_core::clock::unix_us() as i64],
        )
        .map_err(|e| sql_err("record a revocation", e))?;
        Ok(())
    }

    /// Lifts a per-pair block, which happens when the owner pairs with the
    /// device again.
    pub fn unblock_pair(&self, owner: &Fingerprint, blocked: &Fingerprint) -> Result<bool> {
        let conn = self.lock()?;
        let n = conn
            .execute(
                "DELETE FROM blocks WHERE owner = ?1 AND blocked = ?2",
                params![owner.to_hex(), blocked.to_hex()],
            )
            .map_err(|e| sql_err("lift a revocation", e))?;
        Ok(n > 0)
    }

    pub fn is_blocked(&self, owner: &Fingerprint, requester: &Fingerprint) -> Result<bool> {
        let conn = self.lock()?;
        let found: Option<i64> = conn
            .query_row(
                "SELECT 1 FROM blocks WHERE owner = ?1 AND blocked = ?2",
                params![owner.to_hex(), requester.to_hex()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|e| sql_err("check a revocation", e))?;
        Ok(found.is_some())
    }

    pub fn device_count(&self) -> Result<u64> {
        let conn = self.lock()?;
        conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
            .map_err(|e| sql_err("count devices", e))
    }

    /// Appends to the audit log.
    ///
    /// Never called with anything secret. The rule is enforced by what callers
    /// pass, and by a test that scans for the obvious mistakes.
    pub fn audit(&self, entry: &AuditEntry) -> Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO audit (unix_us, actor, action, target, detail, success)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.unix_us as i64,
                entry.actor.map(|f| f.to_hex()),
                entry.action,
                entry.target.map(|f| f.to_hex()),
                entry.detail,
                i64::from(entry.success),
            ],
        )
        .map_err(|e| sql_err("write to the audit log", e))?;
        Ok(())
    }

    pub fn recent_audit(&self, limit: u32) -> Result<Vec<AuditEntry>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT unix_us, actor, action, target, detail, success
                   FROM audit ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| sql_err("read the audit log", e))?;
        let rows = stmt
            .query_map(params![limit], |row| {
                let actor: Option<String> = row.get(1)?;
                let target: Option<String> = row.get(3)?;
                let success: i64 = row.get(5)?;
                Ok(AuditEntry {
                    unix_us: row.get::<_, i64>(0)? as u64,
                    actor: actor.and_then(|s| Fingerprint::from_hex(&s)),
                    action: row.get(2)?,
                    target: target.and_then(|s| Fingerprint::from_hex(&s)),
                    detail: row.get(4)?,
                    success: success != 0,
                })
            })
            .map_err(|e| sql_err("read the audit log", e))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| sql_err("read an audit entry", e))?);
        }
        Ok(out)
    }

    /// Deletes audit entries older than `keep_days`, so the file cannot grow
    /// without bound on a server left running for years.
    pub fn prune_audit(&self, keep_days: u32) -> Result<u64> {
        let conn = self.lock()?;
        let cutoff = bark_core::clock::unix_us()
            .saturating_sub(u64::from(keep_days) * 24 * 60 * 60 * 1_000_000);
        let n = conn
            .execute("DELETE FROM audit WHERE unix_us < ?1", params![cutoff as i64])
            .map_err(|e| sql_err("prune the audit log", e))?;
        Ok(n as u64)
    }
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<DeviceRecord>> {
    let key_hex: String = row.get(0)?;
    let name: String = row.get(1)?;
    let os: String = row.get(2)?;
    let bark_version: String = row.get(3)?;
    let first: i64 = row.get(4)?;
    let last: i64 = row.get(5)?;
    let revoked: i64 = row.get(6)?;

    Ok((|| {
        let raw = hex::decode(&key_hex)
            .map_err(|e| BarkError::Config(format!("a stored public key is malformed: {e}")))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| BarkError::Config("a stored public key is the wrong length".into()))?;
        let identity = PublicIdentity::from_bytes(bytes)?;
        Ok(DeviceRecord {
            identity,
            name,
            os,
            bark_version,
            first_seen_unix_us: first as u64,
            last_seen_unix_us: last as u64,
            revoked: revoked != 0,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bark_crypto::DeviceIdentity;

    fn device() -> PublicIdentity {
        DeviceIdentity::generate().unwrap().public()
    }

    fn db() -> Db {
        Db::open_in_memory().expect("open")
    }

    #[test]
    fn a_new_device_is_created_then_updated() {
        let db = db();
        let d = device();

        assert_eq!(
            db.register(&d, "LAPTOP", "Windows 11", "0.1.0").unwrap(),
            Registration::Created
        );
        assert_eq!(
            db.register(&d, "LAPTOP-RENAMED", "Windows 11", "0.1.1").unwrap(),
            Registration::Updated
        );
        assert_eq!(db.device_count().unwrap(), 1, "re-registering must not duplicate");

        let rec = db.by_fingerprint(&d.fingerprint()).unwrap().expect("should exist");
        assert_eq!(rec.name, "LAPTOP-RENAMED");
        assert_eq!(rec.bark_version, "0.1.1");
        assert_eq!(rec.identity, d);
    }

    #[test]
    fn devices_are_findable_by_their_short_id() {
        let db = db();
        let d = device();
        db.register(&d, "SERVER", "Windows Server", "0.1.0").unwrap();

        let found = db.by_device_id(&d.device_id()).unwrap().expect("should exist");
        assert_eq!(found.fingerprint(), d.fingerprint());
        assert_eq!(found.device_id(), d.device_id());
    }

    #[test]
    fn an_unknown_device_is_simply_absent() {
        let db = db();
        let d = device();
        assert_eq!(db.by_fingerprint(&d.fingerprint()).unwrap(), None);
        assert_eq!(db.by_device_id(&d.device_id()).unwrap(), None);
    }

    #[test]
    fn a_colliding_short_id_is_refused() {
        // Forty bits is grindable, so two devices must never share a displayed
        // ID. Simulated here by writing a row with a different fingerprint
        // under the same device_id, which is what a successful grind produces.
        let db = db();
        let first = device();
        db.register(&first, "REAL", "Windows 11", "0.1.0").unwrap();

        let impostor = device();
        {
            let conn = db.lock().unwrap();
            conn.execute(
                "UPDATE devices SET fingerprint = ?1, public_key = ?2 WHERE device_id = ?3",
                params![
                    impostor.fingerprint().to_hex(),
                    hex::encode(impostor.as_bytes()),
                    first.device_id().to_string()
                ],
            )
            .unwrap();
        }

        match db.register(&first, "REAL", "Windows 11", "0.1.0").unwrap() {
            Registration::ShortIdCollision { existing } => {
                assert_eq!(existing, impostor.fingerprint());
            }
            other => panic!("expected a collision, got {other:?}"),
        }
        assert_eq!(db.device_count().unwrap(), 1, "the collider must not be added");
    }

    #[test]
    fn revocation_is_recorded_and_reversible() {
        let db = db();
        let d = device();
        db.register(&d, "PC", "Windows 11", "0.1.0").unwrap();

        assert!(db.set_revoked(&d.fingerprint(), true).unwrap());
        assert!(db.by_fingerprint(&d.fingerprint()).unwrap().unwrap().revoked);

        assert!(db.set_revoked(&d.fingerprint(), false).unwrap());
        assert!(!db.by_fingerprint(&d.fingerprint()).unwrap().unwrap().revoked);

        // Revoking something that is not there is not an error, just false.
        assert!(!db.set_revoked(&device().fingerprint(), true).unwrap());
    }

    #[test]
    fn a_per_pair_block_affects_only_that_pair() {
        let db = db();
        let owner = device().fingerprint();
        let blocked = device().fingerprint();
        let bystander = device().fingerprint();

        assert!(!db.is_blocked(&owner, &blocked).unwrap());
        db.block_pair(&owner, &blocked).unwrap();
        assert!(db.is_blocked(&owner, &blocked).unwrap());

        // Direction matters, and nobody else is affected.
        assert!(!db.is_blocked(&blocked, &owner).unwrap());
        assert!(!db.is_blocked(&bystander, &blocked).unwrap());

        // Blocking twice is harmless; unblocking restores it.
        db.block_pair(&owner, &blocked).unwrap();
        assert!(db.unblock_pair(&owner, &blocked).unwrap());
        assert!(!db.is_blocked(&owner, &blocked).unwrap());
        assert!(!db.unblock_pair(&owner, &blocked).unwrap(), "nothing left to lift");
    }

    #[test]
    fn devices_list_in_a_stable_readable_order() {
        let db = db();
        for name in ["zebra", "Alpha", "middle"] {
            db.register(&device(), name, "Windows 11", "0.1.0").unwrap();
        }
        let names: Vec<String> = db.list_devices().unwrap().into_iter().map(|d| d.name).collect();
        assert_eq!(names, vec!["Alpha", "middle", "zebra"], "case-insensitive by name");
    }

    #[test]
    fn last_seen_moves_forward_when_touched() {
        let db = db();
        let d = device();
        db.register(&d, "PC", "Windows 11", "0.1.0").unwrap();
        let before = db.by_fingerprint(&d.fingerprint()).unwrap().unwrap().last_seen_unix_us;

        std::thread::sleep(std::time::Duration::from_millis(3));
        db.touch_seen(&d.fingerprint()).unwrap();

        let after = db.by_fingerprint(&d.fingerprint()).unwrap().unwrap().last_seen_unix_us;
        assert!(after > before, "{after} should be later than {before}");
    }

    #[test]
    fn audit_entries_are_written_and_read_newest_first() {
        let db = db();
        let a = device();
        let b = device();

        for i in 0..5 {
            db.audit(
                &AuditEntry::new("connect-request", i % 2 == 0)
                    .actor(a.fingerprint())
                    .target(b.fingerprint())
                    .detail(format!("attempt {i}")),
            )
            .unwrap();
        }

        let entries = db.recent_audit(10).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0].detail, "attempt 4", "newest first");
        assert_eq!(entries[0].actor, Some(a.fingerprint()));
        assert_eq!(entries[0].target, Some(b.fingerprint()));
        assert_eq!(entries[0].action, "connect-request");

        let limited = db.recent_audit(2).unwrap();
        assert_eq!(limited.len(), 2, "the limit must be respected");
    }

    #[test]
    fn audit_entries_survive_without_an_actor() {
        let db = db();
        db.audit(&AuditEntry::new("server-start", true).detail("listening on 0.0.0.0:57411"))
            .unwrap();
        let e = &db.recent_audit(1).unwrap()[0];
        assert_eq!(e.actor, None);
        assert_eq!(e.target, None);
        assert!(e.success);
    }

    #[test]
    fn pruning_removes_only_old_audit_entries() {
        let db = db();
        let old = AuditEntry {
            unix_us: bark_core::clock::unix_us() - 40 * 24 * 60 * 60 * 1_000_000,
            ..AuditEntry::new("ancient", true)
        };
        db.audit(&old).unwrap();
        db.audit(&AuditEntry::new("recent", true)).unwrap();

        let removed = db.prune_audit(30).unwrap();
        assert_eq!(removed, 1);
        let left = db.recent_audit(10).unwrap();
        assert_eq!(left.len(), 1);
        assert_eq!(left[0].action, "recent");
    }

    #[test]
    fn the_database_holds_no_private_key_material() {
        // The whole security argument for the server rests on this: stealing
        // the database must not let anyone connect to anything.
        let db = db();
        let id = DeviceIdentity::generate().unwrap();
        db.register(&id.public(), "PC", "Windows 11", "0.1.0").unwrap();
        db.audit(&AuditEntry::new("authenticate", true).actor(id.fingerprint())).unwrap();

        let conn = db.lock().unwrap();
        let stmt = conn.prepare("SELECT * FROM devices").unwrap();
        let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
        for banned in ["private", "secret", "password", "code", "session_key"] {
            assert!(
                !cols.iter().any(|c| c.contains(banned)),
                "column {banned:?} has no business in the server database: {cols:?}"
            );
        }
        // And the public key column really is the public key.
        let stored: String = conn
            .query_row("SELECT public_key FROM devices", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, hex::encode(id.public().as_bytes()));
    }

    #[test]
    fn a_file_backed_database_survives_reopening() {
        let dir = std::env::temp_dir().join(format!("bark-db-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("bark.sqlite");

        let d = device();
        {
            let db = Db::open(&path).expect("create");
            db.register(&d, "CENTRAL-SERVER", "Windows Server", "0.1.0").unwrap();
            db.audit(&AuditEntry::new("server-start", true)).unwrap();
        }
        {
            let db = Db::open(&path).expect("reopen");
            let rec = db.by_fingerprint(&d.fingerprint()).unwrap().expect("device persisted");
            assert_eq!(rec.name, "CENTRAL-SERVER");
            assert_eq!(db.recent_audit(10).unwrap().len(), 1, "audit persisted");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_database_from_a_newer_server_is_refused_clearly() {
        let dir = std::env::temp_dir().join(format!("bark-db-future-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("bark.sqlite");

        {
            let db = Db::open(&path).expect("create");
            let conn = db.lock().unwrap();
            conn.execute("UPDATE meta SET value = '99' WHERE key = 'schema_version'", [])
                .unwrap();
        }

        let err = Db::open(&path).unwrap_err();
        let text = format!("{err}");
        assert!(text.contains("newer version"), "got {text}");
        assert!(text.contains("Update"), "should say what to do: {text}");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
