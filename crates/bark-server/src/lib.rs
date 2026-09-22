//! The BARK coordination server.
//!
//! Its job is deliberately small. It introduces devices to each other and, when
//! they cannot reach each other directly, forwards opaque bytes between them.
//! That is all.
//!
//! What it specifically does **not** do:
//!
//! * It does not decide who may control what. That lives in each device's own
//!   trust store, on that device. A compromised server can refuse to introduce
//!   two machines; it cannot introduce itself to one.
//! * It does not hold session keys, and cannot read a session it is relaying.
//! * It does not see pairing codes. It forwards a hash it cannot reverse.
//!
//! This matters because the server is the one always-on component, and
//! therefore the most exposed. The design goal was that stealing it should be
//! disappointing.

pub mod db;
pub mod registry;
pub mod relay;
pub mod serve;
pub mod session;

pub use db::{AuditEntry, Db, DeviceRecord, Registration};
pub use registry::{ExchangeKind, NodeHandle, Registry};
pub use serve::{accept_loop, maintenance_loop, spawn};
pub use session::{handle_connection, ServerState};
