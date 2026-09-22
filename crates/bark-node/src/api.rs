//! What the user interface can ask of a node, and what a node tells it.
//!
//! Every type here is serialisable. Today the GUI hosts the node in its own
//! process and these travel over in-memory channels; when BARK is installed,
//! the node lives in the service and the same messages travel over a local
//! named pipe. Keeping one vocabulary for both is what stops the standalone
//! and installed modes from drifting apart.

use crate::config::NodeConfig;
use bark_core::Fingerprint;
use serde::{Deserialize, Serialize};

/// Requests from the user interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Command {
    /// Re-send status and the device list.
    Refresh,
    /// Generate a pairing code and keep it valid until hidden or used.
    ShowPairingCode,
    HidePairingCode,
    /// Pair with a device, using the code shown on its screen.
    Pair { device_id: String, code: String, name: String },
    /// Open a remote session to a paired device.
    Connect { device: Fingerprint },
    Remove { device: Fingerprint },
    Revoke { device: Fingerprint },
    Rename { device: Fingerprint, name: String },
    SetDetails { device: Fingerprint, description: String, group: String },
    /// Replace the settings. Validated first; applied by reconnecting.
    SetConfig(NodeConfig),
    /// The person at this computer ends a session someone else is running
    /// on it.
    EndHostSession { session_id: u64 },
    Shutdown,
}

/// The state of this node's link to the coordination server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerLink {
    /// No server has been configured yet.
    NotConfigured,
    Connecting { address: String },
    Online {
        address: String,
        /// Measured round trip, once the first ping has come back.
        rtt_us: Option<u32>,
        /// Where the server sees this computer — its public address.
        public_address: String,
        server_version: String,
    },
    /// Not connected; will retry automatically.
    Offline { address: String, error: String, retry_in_secs: u32 },
}

impl ServerLink {
    pub fn is_online(&self) -> bool {
        matches!(self, ServerLink::Online { .. })
    }

    /// One word for the status bar.
    pub fn word(&self) -> &'static str {
        match self {
            ServerLink::NotConfigured => "NOT SET UP",
            ServerLink::Connecting { .. } => "CONNECTING",
            ServerLink::Online { .. } => "ONLINE",
            ServerLink::Offline { .. } => "OFFLINE",
        }
    }
}

/// The coordination-server role, when this computer has it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerRoleStatus {
    pub listening: String,
    /// The key other computers enter in their settings.
    pub key_text: String,
    pub devices_online: usize,
    pub devices_known: u64,
    /// Where the relay listens, when this server relays.
    pub relay: Option<String>,
}

/// A running session, for diagnostics.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionView {
    pub session_id: u64,
    pub device_name: String,
    /// This computer is controlling the other one (rather than being controlled).
    pub controlling: bool,
    /// "DIRECT (LAN)", "DIRECT (internet)" or "RELAYED".
    pub path: String,
    pub remote_address: String,
    pub started_unix_us: u64,
}

/// Everything about this computer the interface shows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub device_name: String,
    pub device_id: String,
    pub fingerprint: Fingerprint,
    pub version: String,
    /// "installed", "standalone", or a named standalone profile.
    pub mode: String,
    pub server: ServerLink,
    pub server_role: Option<ServerRoleStatus>,
    pub config: NodeConfig,
    /// This computer's usable IPv4 addresses, best first.
    pub local_addresses: Vec<String>,
    /// Sessions running now, in both directions.
    pub sessions: Vec<SessionView>,
}

/// One remembered device, as the favourites list shows it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceView {
    pub fingerprint: Fingerprint,
    pub device_id: String,
    pub name: String,
    pub online: bool,
    /// "DIRECT", "RELAYED" or "--".
    pub connection: String,
    pub last_seen_unix_us: u64,
    pub os: String,
    pub bark_version: String,
    pub description: String,
    pub group: String,
    /// It may control this computer.
    pub may_control_us: bool,
    /// This computer may control it.
    pub we_may_control: bool,
    pub revoked: bool,
    pub paired_unix_us: u64,
    pub last_connected_unix_us: u64,
}

/// A pairing code currently on screen.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairingCodeView {
    pub code: String,
    pub seconds_left: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoticeLevel {
    Info,
    Warning,
    Error,
}

/// Things the node tells the interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    Status(NodeStatus),
    Devices(Vec<DeviceView>),
    PairingCode(Option<PairingCodeView>),
    /// Result of a `Pair` command this computer made.
    PairFinished { ok: bool, message: String, device: Option<DeviceView> },
    /// Another computer paired with this one using the code on screen.
    PairedBy { device: DeviceView },
    /// A `Connect` failed. (Success arrives as `SessionOpened`.)
    ConnectFinished { device: Fingerprint, ok: bool, message: String },
    /// What a `Connect` is doing now, for the connecting dialog.
    ConnectProgress { device: Fingerprint, text: String },
    /// A session this computer controls is open. The window showing it
    /// collects its video and input channels with `NodeHandle::take_viewer`.
    SessionOpened {
        session_id: u64,
        device: Fingerprint,
        name: String,
        /// "DIRECT (LAN)", "DIRECT (internet)" or "RELAYED".
        path: String,
        remote_address: String,
        /// Words both computers show; matching words prove nothing is in the middle.
        verification: String,
        /// Time from pressing Connect to an authenticated session.
        connect_ms: u32,
    },
    /// A session this computer controlled has ended.
    SessionClosed { session_id: u64, device: Fingerprint, reason: String },
    /// Another computer has started controlling this one. Shown prominently:
    /// nobody is ever controlled without being able to see it.
    HostSessionStarted {
        session_id: u64,
        device: Fingerprint,
        name: String,
        path: String,
        /// The same words the controller sees; matching proves nothing is in the middle.
        verification: String,
    },
    HostSessionEnded { session_id: u64, device: Fingerprint, reason: String },
    Notice { level: NoticeLevel, text: String },
    /// The node could not start. The text explains why and what to do.
    Fatal(String),
}

/// Formats a Unix time as the "Last Seen" column shows it.
///
/// "Now" for anything in the last minute, a time of day for today, a date
/// otherwise, "Never" for zero. Uses the local time zone.
pub fn format_last_seen(unix_us: u64, now_unix_us: u64, online: bool) -> String {
    if online {
        return "Now".into();
    }
    if unix_us == 0 {
        return "Never".into();
    }
    let age_s = now_unix_us.saturating_sub(unix_us) / 1_000_000;
    if age_s < 60 {
        return "Now".into();
    }
    let secs = (unix_us / 1_000_000) as i64;
    let Ok(t) = time::OffsetDateTime::from_unix_timestamp(secs) else {
        return "--".into();
    };
    let t = match time::UtcOffset::current_local_offset() {
        Ok(off) => t.to_offset(off),
        Err(_) => t,
    };
    let now_t = time::OffsetDateTime::from_unix_timestamp((now_unix_us / 1_000_000) as i64)
        .map(|n| n.to_offset(t.offset()))
        .unwrap_or(t);
    if t.date() == now_t.date() {
        format!("{:02}:{:02}", t.hour(), t.minute())
    } else {
        format!("{:04}-{:02}-{:02}", t.year(), u8::from(t.month()), t.day())
    }
}

/// Formats a Unix time as a local date and time, "2026-09-21 21:27", or
/// "Never" for zero. For events like pairing, where "Now" would be vague.
pub fn format_date_time(unix_us: u64) -> String {
    if unix_us == 0 {
        return "Never".into();
    }
    let Ok(t) = time::OffsetDateTime::from_unix_timestamp((unix_us / 1_000_000) as i64) else {
        return "--".into();
    };
    let t = match time::UtcOffset::current_local_offset() {
        Ok(off) => t.to_offset(off),
        Err(_) => t,
    };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn last_seen_reads_naturally() {
        let now = 1_800_000_000_000_000u64;
        assert_eq!(format_last_seen(now, now, true), "Now");
        assert_eq!(format_last_seen(0, now, false), "Never");
        assert_eq!(format_last_seen(now - 30_000_000, now, false), "Now");
        let two_hours = format_last_seen(now - 2 * 3600 * 1_000_000, now, false);
        assert!(two_hours.contains(':') || two_hours.contains('-'), "got {two_hours}");
        let last_month = format_last_seen(now - 40 * 24 * 3600 * 1_000_000, now, false);
        assert_eq!(last_month.len(), 10, "a date, got {last_month}");
    }

    #[test]
    fn date_times_are_unambiguous() {
        assert_eq!(format_date_time(0), "Never");
        let t = format_date_time(1_800_000_000_000_000);
        assert_eq!(t.len(), 16, "got {t}");
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[13..14], ":");
    }

    #[test]
    fn status_words_are_short_and_upper_case() {
        for s in [
            ServerLink::NotConfigured,
            ServerLink::Connecting { address: "x".into() },
            ServerLink::Online {
                address: "x".into(),
                rtt_us: None,
                public_address: "y".into(),
                server_version: "0".into(),
            },
            ServerLink::Offline { address: "x".into(), error: "e".into(), retry_in_secs: 1 },
        ] {
            let w = s.word();
            assert_eq!(w, w.to_uppercase());
            assert!(w.len() <= 10);
        }
    }

    #[test]
    fn commands_and_events_serialise_for_the_service_pipe() {
        let c = Command::Pair { device_id: "BA-1234-5678".into(), code: "ABC-DEF".into(), name: "X".into() };
        let bytes = serde_json::to_vec(&c).unwrap();
        let back: Command = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(format!("{back:?}"), format!("{c:?}"));

        let e = Event::Notice { level: NoticeLevel::Warning, text: "hi".into() };
        let bytes = serde_json::to_vec(&e).unwrap();
        let back: Event = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(format!("{back:?}"), format!("{e:?}"));
    }
}
