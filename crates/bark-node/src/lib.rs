//! The BARK node: the long-running part of every BARK installation.
//!
//! It holds this computer's identity and trust store, keeps the connection to
//! the coordination server, tracks which paired devices are online, runs the
//! pairing exchange, and hosts the optional coordination-server role.
//!
//! It is written once and hosted in two places: inside the GUI process when
//! BARK is run without being installed ("standalone"), and inside the Windows
//! service when it is installed. The user interface talks to it only through
//! [`api::Command`] and [`api::Event`], so both hosts behave identically.

pub mod api;
pub mod config;
#[cfg(windows)]
pub mod host;
pub mod runtime;
pub mod session;
pub mod viewer;

pub use api::{Command, DeviceView, Event, NodeStatus, ServerLink};
pub use config::{NodeConfig, NodeDirs, Roles, ServerTarget};
pub use runtime::{start, EventSink, NodeHandle};
pub use viewer::{SessionStats, ViewerCommand, ViewerEvent, ViewerLink};
