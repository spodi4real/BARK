//! Where a node keeps its files, and what it is configured to do.

use bark_core::{BarkError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The folder a node lives in.
///
/// An installed BARK keeps everything in `C:\ProgramData\BARK`, owned by the
/// service. A standalone copy (run without installing) keeps a separate set
/// under the user's profile, so trying BARK never touches machine-wide state
/// and never needs administrator rights.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDirs {
    root: PathBuf,
    /// Human-readable label for where this node lives, shown in the title bar
    /// and diagnostics so it is always clear which identity is in use.
    label: String,
}

impl NodeDirs {
    /// The installed node's folder.
    pub fn machine() -> Self {
        NodeDirs { root: bark_core::paths::machine_dir(), label: "installed".into() }
    }

    /// A standalone node under the current user's profile.
    ///
    /// `profile` lets two independent BARK nodes run on one computer — used for
    /// testing pairing and connections without a second machine.
    pub fn standalone(profile: &str) -> Self {
        let name = if profile.is_empty() { "default" } else { profile };
        NodeDirs {
            root: bark_core::paths::user_dir().join("profiles").join(name),
            label: if name == "default" {
                "standalone".into()
            } else {
                format!("standalone, profile \"{name}\"")
            },
        }
    }

    /// An arbitrary folder, for tests.
    pub fn at(root: impl Into<PathBuf>, label: &str) -> Self {
        NodeDirs { root: root.into(), label: label.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn identity(&self) -> PathBuf {
        self.root.join("identity.dat")
    }

    pub fn trust(&self) -> PathBuf {
        self.root.join("trust.json")
    }

    pub fn config(&self) -> PathBuf {
        self.root.join("config.json")
    }

    /// Coordination-server role state: its certificate and database.
    pub fn server(&self) -> PathBuf {
        self.root.join("server")
    }

    pub fn logs(&self) -> PathBuf {
        self.root.join("logs")
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        std::fs::create_dir_all(self.logs())?;
        Ok(())
    }
}

/// Which coordination server to use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerTarget {
    /// `host:port`, where host is a name or an IP address.
    pub address: String,
    /// The server key from the join information, in any reasonable format.
    pub key: String,
}

impl ServerTarget {
    pub fn key_bytes(&self) -> Result<[u8; 32]> {
        bark_net::tls::parse_fingerprint(&self.key)
    }

    /// `host:port` with the default port filled in if it was left off.
    pub fn address_with_port(&self) -> String {
        let a = self.address.trim();
        // A bare IPv4 address or host name has no colon; add the default port.
        if a.contains(':') {
            a.to_string()
        } else {
            format!("{a}:{}", bark_core::DEFAULT_SERVER_PORT)
        }
    }
}

/// Optional capabilities of this installation. See ARCHITECTURE.md section 17.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roles {
    /// This computer is the BARK coordination server.
    #[serde(default)]
    pub coordination_server: bool,
    #[serde(default = "default_server_port")]
    pub server_port: u16,
    /// Listen on one address only. Empty means every address, which is what a
    /// server other computers must reach needs.
    #[serde(default)]
    pub server_bind: String,
    /// This computer may relay encrypted traffic for other devices.
    #[serde(default)]
    pub relay: bool,
    #[serde(default = "default_relay_port")]
    pub relay_port: u16,
}

fn default_server_port() -> u16 {
    bark_core::DEFAULT_SERVER_PORT
}

fn default_relay_port() -> u16 {
    bark_core::DEFAULT_SERVER_PORT + 1
}

impl Default for Roles {
    fn default() -> Self {
        Roles {
            coordination_server: false,
            server_port: default_server_port(),
            server_bind: String::new(),
            relay: false,
            relay_port: default_relay_port(),
        }
    }
}

fn default_true() -> bool {
    true
}

/// Everything configurable about a node. Stored as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Name other devices see. Empty means "use the computer name".
    #[serde(default)]
    pub device_name: String,
    /// The coordination server to use, unless this computer is the server.
    #[serde(default)]
    pub server: Option<ServerTarget>,
    #[serde(default)]
    pub roles: Roles,
    /// Accept remote-control sessions from paired devices.
    #[serde(default = "default_true")]
    pub accept_incoming: bool,
    #[serde(default = "default_true")]
    pub clipboard_sync: bool,
    /// Skip direct connection attempts and always use the relay. For testing
    /// the relay path; set by editing config.json, not shown in Settings.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub force_relay: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        NodeConfig {
            device_name: String::new(),
            server: None,
            roles: Roles::default(),
            accept_incoming: true,
            clipboard_sync: true,
            force_relay: false,
        }
    }
}

impl NodeConfig {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(NodeConfig::default());
        }
        let raw = std::fs::read(path)?;
        if raw.is_empty() {
            return Ok(NodeConfig::default());
        }
        serde_json::from_slice(&raw).map_err(|e| {
            BarkError::Config(format!(
                "The BARK settings file at {} could not be read: {e}\n\n\
                 Fix or delete the file; deleting it restores the default settings \
                 but keeps this computer's identity and pairings.",
                path.display()
            ))
        })
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| BarkError::Config(format!("could not encode settings: {e}")))?;
        bark_core::paths::write_atomic(path, &json)
    }

    /// The name to present to other devices.
    pub fn effective_name(&self) -> String {
        let n = self.device_name.trim();
        if n.is_empty() {
            bark_core::machine::hostname()
        } else {
            n.to_string()
        }
    }

    /// Checks the settings make sense before they are saved, with messages an
    /// operator can act on.
    pub fn validate(&self) -> Result<()> {
        if self.device_name.len() > 64 {
            return Err(BarkError::Config("The device name can be at most 64 characters.".into()));
        }
        if let Some(s) = &self.server {
            if !self.roles.coordination_server {
                if s.address.trim().is_empty() {
                    return Err(BarkError::Config(
                        "Enter the BARK server's address, for example 192.168.1.10.".into(),
                    ));
                }
                s.key_bytes()?;
            }
        }
        if !self.roles.server_bind.trim().is_empty()
            && self.roles.server_bind.trim().parse::<std::net::IpAddr>().is_err()
        {
            return Err(BarkError::Config(format!(
                "\"{}\" is not an IP address this computer could listen on.",
                self.roles.server_bind.trim()
            )));
        }
        if self.roles.coordination_server && self.roles.server_port == self.roles.relay_port {
            return Err(BarkError::Config(
                "The server port and the relay port must be different.".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bark-node-cfg-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_missing_file_gives_defaults() {
        let d = tempdir("missing");
        let c = NodeConfig::load(&d.join("config.json")).unwrap();
        assert_eq!(c, NodeConfig::default());
        assert!(c.accept_incoming);
        assert!(!c.roles.coordination_server);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn settings_survive_a_save_and_load() {
        let d = tempdir("roundtrip");
        let p = d.join("config.json");
        let c = NodeConfig {
            device_name: "CENTRAL-SERVER".into(),
            roles: Roles { coordination_server: true, relay: true, ..Roles::default() },
            ..NodeConfig::default()
        };
        c.save(&p).unwrap();
        assert_eq!(NodeConfig::load(&p).unwrap(), c);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_old_file_missing_new_fields_still_loads() {
        // A settings file written by an earlier version must keep working
        // after an update; new fields take their defaults.
        let d = tempdir("old");
        let p = d.join("config.json");
        std::fs::write(&p, br#"{ "device_name": "OFFICE-PC-01" }"#).unwrap();
        let c = NodeConfig::load(&p).unwrap();
        assert_eq!(c.device_name, "OFFICE-PC-01");
        assert!(c.accept_incoming);
        assert_eq!(c.roles.server_port, bark_core::DEFAULT_SERVER_PORT);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_damaged_file_is_reported_with_what_to_do() {
        let d = tempdir("bad");
        let p = d.join("config.json");
        std::fs::write(&p, b"{ not json").unwrap();
        let e = NodeConfig::load(&p).unwrap_err();
        assert!(format!("{e}").contains("keeps this computer's identity"), "got {e}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_default_port_is_added_when_left_off() {
        let t = ServerTarget { address: "192.168.1.10".into(), key: String::new() };
        assert_eq!(t.address_with_port(), format!("192.168.1.10:{}", bark_core::DEFAULT_SERVER_PORT));
        let t = ServerTarget { address: "server.local:9000".into(), key: String::new() };
        assert_eq!(t.address_with_port(), "server.local:9000");
    }

    #[test]
    fn validation_catches_what_an_operator_might_get_wrong() {
        let mut c = NodeConfig {
            server: Some(ServerTarget { address: "".into(), key: "abc".into() }),
            ..NodeConfig::default()
        };
        assert!(format!("{}", c.validate().unwrap_err()).contains("address"));

        c.server = Some(ServerTarget { address: "10.0.0.1".into(), key: "too short".into() });
        assert!(format!("{}", c.validate().unwrap_err()).contains("64"));

        c.server = None;
        c.roles.coordination_server = true;
        c.roles.relay_port = c.roles.server_port;
        assert!(c.validate().is_err());

        let ok = NodeConfig::default();
        ok.validate().unwrap();
    }

    #[test]
    fn a_blank_name_falls_back_to_the_computer_name() {
        let c = NodeConfig::default();
        assert_eq!(c.effective_name(), bark_core::machine::hostname());
        let c = NodeConfig { device_name: "  WAREHOUSE-PC  ".into(), ..Default::default() };
        assert_eq!(c.effective_name(), "WAREHOUSE-PC");
    }

    #[test]
    fn standalone_profiles_are_separate_folders() {
        let a = NodeDirs::standalone("");
        let b = NodeDirs::standalone("second");
        assert_ne!(a.root(), b.root());
        assert!(a.identity().starts_with(a.root()));
        assert!(b.label().contains("second"));
    }
}
