//! The link between a running session and the window showing it.
//!
//! Low-rate facts about a session (it opened, it closed, its round-trip time)
//! travel as ordinary [`crate::api::Event`]s. The high-rate part — every video
//! frame, every cursor change, every keystroke — travels here instead, on
//! channels made for it, so a busy session never queues behind the device
//! list or holds up the user interface thread.
//!
//! In standalone mode both ends are in one process. When BARK is installed,
//! the viewer end moves to the GUI process and this becomes a named pipe;
//! the types stay the same.

use bark_proto::peer::{Action, MonitorInfo, RefreshReason};
use bark_proto::video::AssembledFrame;
use bark_proto::InputEvent;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// What the session tells the window.
#[derive(Debug)]
pub enum ViewerEvent {
    /// The remote is ready to send its screen.
    Ready { remote_name: String, monitors: Vec<MonitorInfo>, active_monitor: u8 },
    /// A complete encoded video frame.
    Frame(AssembledFrame),
    /// The remote cursor's shape. BGRA, top row first.
    Cursor { width: u16, height: u16, hotspot_x: u16, hotspot_y: u16, pixels: Vec<u8>, xor: bool, hidden: bool },
    /// Measured figures, about once a second.
    Stats(SessionStats),
    /// A message for the status line: capture paused on the remote, and so on.
    Notice(String),
    /// The session is over. Always the last event.
    Ended { reason: String },
}

/// What the window asks of the session.
#[derive(Debug, Clone)]
pub enum ViewerCommand {
    /// An input event and the controller's clock when it happened.
    Input { event: InputEvent, timestamp_us: u64 },
    RequestKeyframe(RefreshReason),
    SelectMonitor(u8),
    Action(Action),
    Disconnect,
}

/// Live figures for the information panel. Every number here is measured.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SessionStats {
    /// "DIRECT (LAN)", "DIRECT (internet)" or "RELAYED".
    pub path: String,
    pub remote_address: String,
    /// Round trip on the session's own connection, from QUIC's estimator.
    pub rtt_us: u32,
    pub frames_received: u64,
    pub frames_lost: u64,
    pub fps: f32,
    pub kbps: u32,
    /// Remote capture-to-send time of the latest frame.
    pub remote_pipeline_us: u32,
}

/// The viewer end, handed to the window that shows the session.
pub struct ViewerLink {
    pub session_id: u64,
    pub events: std::sync::mpsc::Receiver<ViewerEvent>,
    pub commands: tokio::sync::mpsc::UnboundedSender<ViewerCommand>,
}

/// The session end.
pub(crate) struct SessionEnd {
    pub events: std::sync::mpsc::Sender<ViewerEvent>,
    pub commands: tokio::sync::mpsc::UnboundedReceiver<ViewerCommand>,
}

pub(crate) fn link(session_id: u64) -> (ViewerLink, SessionEnd) {
    let (etx, erx) = std::sync::mpsc::channel();
    let (ctx, crx) = tokio::sync::mpsc::unbounded_channel();
    (
        ViewerLink { session_id, events: erx, commands: ctx },
        SessionEnd { events: etx, commands: crx },
    )
}

/// Links waiting for their window to collect them.
pub type ViewerSlots = Arc<Mutex<HashMap<u64, ViewerLink>>>;
