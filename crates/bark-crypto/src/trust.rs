//! The trust store: which devices this computer will let in, and which
//! devices it believes it may connect to.
//!
//! This file is the whole of the "pair once, forever" requirement. It lives in
//! `C:\ProgramData\BARK\trust.json`, survives reboots and upgrades, and is only
//! ever changed by an explicit pairing or an explicit revocation.
//!
//! **Trust is directional.** Pairing laptop → server means the server will
//! accept sessions *from* the laptop. It does not mean the laptop will accept
//! sessions from the server. Modelling that honestly prevents the common and
//! nasty failure where pairing to a machine silently hands that machine control
//! of yours.

use crate::identity::PublicIdentity;
use bark_core::machine::MachineInfo;
use bark_core::{paths, BarkError, DeviceId, Fingerprint, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// One remembered device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEntry {
    /// The peer's public key. This, not the device ID, is the identity.
    pub public: PublicIdentity,

    /// Operator-assigned name, defaulting to the peer's hostname. Renaming is
    /// purely cosmetic and never affects trust.
    pub name: String,

    #[serde(default)]
    pub description: String,

    #[serde(default)]
    pub group: String,

    /// This peer may open remote-control sessions to us.
    #[serde(default)]
    pub may_control_us: bool,

    /// We have been granted the right to control this peer. Advisory only — the
    /// peer enforces its own policy; this just stops us presenting a device in
    /// the favourites list that will certainly refuse us.
    #[serde(default)]
    pub we_may_control: bool,

    /// When the pairing was established.
    pub paired_unix_us: u64,

    /// Last time the coordination server reported this device online.
    #[serde(default)]
    pub last_seen_unix_us: u64,

    /// Last time a session with this device actually succeeded.
    #[serde(default)]
    pub last_connected_unix_us: u64,

    /// Set by an administrator. A revoked entry is kept rather than deleted so
    /// the audit trail survives and so a revocation cannot be undone by
    /// accident.
    #[serde(default)]
    pub revoked: bool,

    #[serde(default)]
    pub revoked_unix_us: Option<u64>,

    /// Last reported OS string, for the device list.
    #[serde(default)]
    pub os: String,

    /// Last reported BARK version.
    #[serde(default)]
    pub bark_version: String,
}

impl TrustEntry {
    pub fn device_id(&self) -> DeviceId {
        self.public.device_id()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.public.fingerprint()
    }

    /// Whether this peer may open a session to us right now.
    pub fn inbound_allowed(&self) -> bool {
        self.may_control_us && !self.revoked
    }

    pub fn apply_machine_info(&mut self, info: &MachineInfo) {
        self.os = info.os.clone();
        self.bark_version = info.bark_version.clone();
        if self.name.is_empty() {
            self.name = info.hostname.clone();
        }
    }
}

/// What a pairing grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// The peer may control us.
    Inbound,
    /// We may control the peer.
    Outbound,
    /// Both directions.
    Mutual,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoredTrust {
    version: u32,
    #[serde(default)]
    entries: Vec<TrustEntry>,
}

/// The in-memory trust store, backed by a JSON file.
#[derive(Debug)]
pub struct TrustStore {
    path: PathBuf,
    by_fingerprint: HashMap<Fingerprint, TrustEntry>,
}

impl TrustStore {
    /// Loads the store, or starts an empty one if the file does not exist yet.
    pub fn load() -> Result<Self> {
        Self::load_from(&paths::trust_store_file())
    }

    pub fn load_from(path: &Path) -> Result<Self> {
        let mut store = TrustStore { path: path.to_path_buf(), by_fingerprint: HashMap::new() };
        if !path.exists() {
            return Ok(store);
        }
        let raw = std::fs::read(path)?;
        if raw.is_empty() {
            return Ok(store);
        }
        let stored: StoredTrust = serde_json::from_slice(&raw).map_err(|e| {
            BarkError::Config(format!(
                "The BARK trust list at {} is damaged and could not be read: {e}\n\n\
                 BARK has not changed the file. Restore it from a backup, or delete it \
                 and pair the devices again.",
                path.display()
            ))
        })?;
        if stored.version > 1 {
            return Err(BarkError::Config(format!(
                "The trust list at {} was written by a newer version of BARK. \
                 Update BARK on this computer.",
                path.display()
            )));
        }
        for e in stored.entries {
            store.by_fingerprint.insert(e.fingerprint(), e);
        }
        Ok(store)
    }

    fn save(&self) -> Result<()> {
        let mut entries: Vec<TrustEntry> = self.by_fingerprint.values().cloned().collect();
        // Stable order so the file diffs cleanly and a human can read it.
        entries.sort_by_key(|e| e.device_id().to_raw_string());
        let stored = StoredTrust { version: 1, entries };
        let json = serde_json::to_vec_pretty(&stored)
            .map_err(|e| BarkError::Config(format!("could not encode the trust list: {e}")))?;
        paths::write_atomic(&self.path, &json)
    }

    pub fn len(&self) -> usize {
        self.by_fingerprint.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_fingerprint.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &TrustEntry> {
        self.by_fingerprint.values()
    }

    /// All entries, sorted for display in the favourites list.
    pub fn sorted(&self) -> Vec<TrustEntry> {
        let mut v: Vec<TrustEntry> = self.by_fingerprint.values().cloned().collect();
        v.sort_by(|a, b| {
            a.group
                .to_lowercase()
                .cmp(&b.group.to_lowercase())
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
        v
    }

    pub fn get(&self, fp: &Fingerprint) -> Option<&TrustEntry> {
        self.by_fingerprint.get(fp)
    }

    /// Looks up by the short handle. Returns `None` if two entries share it,
    /// which the coordination server prevents but a hand-edited file could
    /// produce; refusing to guess is the safe response.
    pub fn get_by_device_id(&self, id: &DeviceId) -> Option<&TrustEntry> {
        let mut found = None;
        for e in self.by_fingerprint.values() {
            if e.device_id() == *id {
                if found.is_some() {
                    return None;
                }
                found = Some(e);
            }
        }
        found
    }

    /// The authorisation decision for an incoming connection. This is the
    /// function that actually protects the machine.
    pub fn authorise_inbound(&self, peer: &PublicIdentity) -> Result<&TrustEntry> {
        let fp = peer.fingerprint();
        match self.by_fingerprint.get(&fp) {
            None => Err(BarkError::NotTrusted(peer.device_id().to_string())),
            Some(e) if e.revoked => Err(BarkError::Revoked(peer.device_id().to_string())),
            Some(e) if !e.may_control_us => Err(BarkError::NotTrusted(format!(
                "{} is paired but is not permitted to control this computer",
                peer.device_id()
            ))),
            Some(e) => Ok(e),
        }
    }

    /// Records a successful pairing, or extends an existing one.
    ///
    /// Re-pairing an existing device updates it in place rather than creating a
    /// duplicate, and clears a previous revocation — which is exactly the
    /// documented way to restore a revoked device.
    pub fn pair(
        &mut self,
        peer: PublicIdentity,
        name: &str,
        grant: Grant,
        info: Option<&MachineInfo>,
    ) -> Result<TrustEntry> {
        let fp = peer.fingerprint();
        let now = bark_core::clock::unix_us();

        let entry = self.by_fingerprint.entry(fp).or_insert_with(|| TrustEntry {
            public: peer,
            name: name.to_string(),
            description: String::new(),
            group: String::new(),
            may_control_us: false,
            we_may_control: false,
            paired_unix_us: now,
            last_seen_unix_us: now,
            last_connected_unix_us: 0,
            revoked: false,
            revoked_unix_us: None,
            os: String::new(),
            bark_version: String::new(),
        });

        match grant {
            Grant::Inbound => entry.may_control_us = true,
            Grant::Outbound => entry.we_may_control = true,
            Grant::Mutual => {
                entry.may_control_us = true;
                entry.we_may_control = true;
            }
        }

        if entry.revoked {
            entry.revoked = false;
            entry.revoked_unix_us = None;
            entry.paired_unix_us = now;
        }
        if !name.is_empty() {
            entry.name = name.to_string();
        }
        if let Some(i) = info {
            entry.apply_machine_info(i);
        }

        let snapshot = entry.clone();
        self.save()?;
        Ok(snapshot)
    }

    /// Revokes a device. Its existing credentials stop working immediately.
    pub fn revoke(&mut self, fp: &Fingerprint) -> Result<()> {
        let entry = self
            .by_fingerprint
            .get_mut(fp)
            .ok_or_else(|| BarkError::NotTrusted(fp.short_id().to_string()))?;
        entry.revoked = true;
        entry.revoked_unix_us = Some(bark_core::clock::unix_us());
        entry.may_control_us = false;
        entry.we_may_control = false;
        self.save()
    }

    /// Removes a device entirely. Used by "Remove" in the favourites list.
    pub fn remove(&mut self, fp: &Fingerprint) -> Result<bool> {
        let existed = self.by_fingerprint.remove(fp).is_some();
        if existed {
            self.save()?;
        }
        Ok(existed)
    }

    pub fn rename(&mut self, fp: &Fingerprint, name: &str) -> Result<()> {
        let entry = self
            .by_fingerprint
            .get_mut(fp)
            .ok_or_else(|| BarkError::NotTrusted(fp.short_id().to_string()))?;
        entry.name = name.to_string();
        self.save()
    }

    pub fn set_description(&mut self, fp: &Fingerprint, description: &str) -> Result<()> {
        let entry = self
            .by_fingerprint
            .get_mut(fp)
            .ok_or_else(|| BarkError::NotTrusted(fp.short_id().to_string()))?;
        entry.description = description.to_string();
        self.save()
    }

    pub fn set_group(&mut self, fp: &Fingerprint, group: &str) -> Result<()> {
        let entry = self
            .by_fingerprint
            .get_mut(fp)
            .ok_or_else(|| BarkError::NotTrusted(fp.short_id().to_string()))?;
        entry.group = group.to_string();
        self.save()
    }

    /// Updates presence. Called often, so it does not write to disk every time;
    /// [`flush_presence`] persists it at a sane interval.
    pub fn note_seen(&mut self, fp: &Fingerprint, now_unix_us: u64) {
        if let Some(e) = self.by_fingerprint.get_mut(fp) {
            e.last_seen_unix_us = now_unix_us;
        }
    }

    pub fn note_connected(&mut self, fp: &Fingerprint) -> Result<()> {
        let now = bark_core::clock::unix_us();
        if let Some(e) = self.by_fingerprint.get_mut(fp) {
            e.last_connected_unix_us = now;
            e.last_seen_unix_us = now;
            self.save()?;
        }
        Ok(())
    }

    pub fn flush_presence(&self) -> Result<()> {
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentity;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bark-trust-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn peer() -> PublicIdentity {
        DeviceIdentity::generate().unwrap().public()
    }

    #[test]
    fn unknown_devices_are_refused() {
        let dir = tempdir("unknown");
        let store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let err = store.authorise_inbound(&peer()).unwrap_err();
        assert!(matches!(err, BarkError::NotTrusted(_)), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pairing_grants_access_and_survives_a_reload() {
        let dir = tempdir("persist");
        let path = dir.join("trust.json");
        let p = peer();

        {
            let mut store = TrustStore::load_from(&path).unwrap();
            store.pair(p, "LAPTOP-01", Grant::Inbound, None).unwrap();
            store.authorise_inbound(&p).expect("should be allowed");
        }

        // A restart must not lose the pairing. This is the whole point.
        let reloaded = TrustStore::load_from(&path).unwrap();
        let entry = reloaded.authorise_inbound(&p).expect("pairing must survive a restart");
        assert_eq!(entry.name, "LAPTOP-01");
        assert!(entry.may_control_us);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn trust_is_directional() {
        let dir = tempdir("direction");
        let mut store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let p = peer();

        // We are allowed to control them; that must not let them control us.
        store.pair(p, "SERVER", Grant::Outbound, None).unwrap();
        assert!(store.authorise_inbound(&p).is_err(), "outbound grant must not allow inbound");

        store.pair(p, "SERVER", Grant::Inbound, None).unwrap();
        assert!(store.authorise_inbound(&p).is_ok());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn revocation_blocks_immediately_and_persists() {
        let dir = tempdir("revoke");
        let path = dir.join("trust.json");
        let p = peer();

        let mut store = TrustStore::load_from(&path).unwrap();
        store.pair(p, "OFFICE-PC", Grant::Mutual, None).unwrap();
        store.authorise_inbound(&p).unwrap();

        store.revoke(&p.fingerprint()).unwrap();
        let err = store.authorise_inbound(&p).unwrap_err();
        assert!(matches!(err, BarkError::Revoked(_)), "got {err:?}");

        let reloaded = TrustStore::load_from(&path).unwrap();
        assert!(
            matches!(reloaded.authorise_inbound(&p), Err(BarkError::Revoked(_))),
            "revocation must survive a restart"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn re_pairing_restores_a_revoked_device_without_duplicating_it() {
        let dir = tempdir("repair");
        let mut store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let p = peer();

        store.pair(p, "PC", Grant::Inbound, None).unwrap();
        store.revoke(&p.fingerprint()).unwrap();
        assert_eq!(store.len(), 1, "revocation keeps the record");

        store.pair(p, "PC", Grant::Inbound, None).unwrap();
        assert_eq!(store.len(), 1, "re-pairing must not create a second entry");
        store.authorise_inbound(&p).expect("re-pairing must restore access");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn removing_a_device_forgets_it_entirely() {
        let dir = tempdir("remove");
        let mut store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let p = peer();
        store.pair(p, "PC", Grant::Inbound, None).unwrap();

        assert!(store.remove(&p.fingerprint()).unwrap());
        assert!(store.is_empty());
        assert!(!store.remove(&p.fingerprint()).unwrap(), "removing twice is not an error");
        assert!(store.authorise_inbound(&p).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn renaming_does_not_affect_trust() {
        let dir = tempdir("rename");
        let mut store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let p = peer();
        store.pair(p, "OLD-NAME", Grant::Inbound, None).unwrap();

        store.rename(&p.fingerprint(), "CENTRAL-SERVER").unwrap();
        let e = store.authorise_inbound(&p).unwrap();
        assert_eq!(e.name, "CENTRAL-SERVER");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn lookup_by_short_device_id_works() {
        let dir = tempdir("shortid");
        let mut store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let p = peer();
        store.pair(p, "PC", Grant::Inbound, None).unwrap();

        let found = store.get_by_device_id(&p.device_id()).expect("should find it");
        assert_eq!(found.fingerprint(), p.fingerprint());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_damaged_file_is_reported_and_not_silently_replaced() {
        let dir = tempdir("damaged");
        let path = dir.join("trust.json");
        std::fs::write(&path, b"{ this is not json").unwrap();

        let err = TrustStore::load_from(&path).unwrap_err();
        assert!(matches!(err, BarkError::Config(_)));
        // The damaged file must still be there for the operator to recover.
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), b"{ this is not json");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_missing_or_empty_file_starts_an_empty_store() {
        let dir = tempdir("fresh");
        let missing = TrustStore::load_from(&dir.join("nothing.json")).unwrap();
        assert!(missing.is_empty());

        let empty_path = dir.join("empty.json");
        std::fs::write(&empty_path, b"").unwrap();
        assert!(TrustStore::load_from(&empty_path).unwrap().is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn entries_are_sorted_by_group_then_name() {
        let dir = tempdir("sort");
        let mut store = TrustStore::load_from(&dir.join("trust.json")).unwrap();
        let a = peer();
        let b = peer();
        let c = peer();
        store.pair(a, "ZEBRA", Grant::Inbound, None).unwrap();
        store.pair(b, "ALPHA", Grant::Inbound, None).unwrap();
        store.pair(c, "MIDDLE", Grant::Inbound, None).unwrap();
        store.set_group(&c.fingerprint(), "Office").unwrap();

        let names: Vec<String> = store.sorted().into_iter().map(|e| e.name).collect();
        // Ungrouped ("") sorts before "Office".
        assert_eq!(names, vec!["ALPHA", "ZEBRA", "MIDDLE"]);

        std::fs::remove_dir_all(&dir).ok();
    }
}
