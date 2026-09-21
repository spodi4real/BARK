//! BARK's network transport.
//!
//! Built on QUIC, for one property above all others: **independent streams**.
//! On a TCP connection, a single lost packet stalls everything queued behind it
//! — including keystrokes stuck behind a video frame. That head-of-line
//! blocking is the main reason TCP-based remote desktop feels bad on an
//! imperfect network. QUIC streams are delivered independently, so input never
//! waits for video, and video never waits for a file transfer.
//!
//! Layers, from the bottom up:
//!
//! * [`tls`] — certificate policy. Pinned for the coordination server,
//!   encryption-only for peers (authenticated separately, inside the tunnel).
//! * [`endpoint`] — QUIC endpoints. One socket per node, listening and dialling,
//!   which is what makes NAT traversal possible.
//! * [`framing`] — length-prefixed control messages on a stream.

pub mod control;
pub mod endpoint;
pub mod framing;
pub mod tls;

pub use control::{ControlConnection, PresenceTable, ServerGreeting};
pub use endpoint::{bidirectional_endpoint, client_only_endpoint, connect, local_address, Role};
pub use framing::{read_expected, read_message, write_message};
pub use tls::{parse_fingerprint, TransportCredentials};
