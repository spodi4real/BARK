//! Types and services shared by every BARK executable.
//!
//! Nothing in here talks to the network or touches the GPU. It is the vocabulary
//! the rest of the system is written in: device identifiers, the monotonic clock
//! used for latency accounting, where files live on disk, and logging.

pub mod clock;
pub mod error;
pub mod ids;
pub mod logging;
pub mod machine;
pub mod paths;

pub use error::{BarkError, Result};
pub use ids::{DeviceId, Fingerprint};

/// Product name as shown to the operator. Used in window titles, the service
/// display name, the installer and the event log source.
pub const PRODUCT_NAME: &str = "BARK";

/// Full product name.
pub const PRODUCT_LONG_NAME: &str = "BARK - Bright Arrow Remote-Access Kit";

/// Version string, taken from the workspace manifest at compile time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Wire-protocol version. Bumped only when the on-the-wire format changes in a
/// way an older peer cannot parse. Peers refuse to connect across a mismatch
/// and say so plainly instead of failing in a confusing way later.
pub const PROTOCOL_VERSION: u16 = 1;

/// Name of the Windows service that hosts the always-on node.
pub const SERVICE_NAME: &str = "BarkService";

/// Display name of that service in services.msc.
pub const SERVICE_DISPLAY_NAME: &str = "BARK Remote Access";

/// Name of the Windows service that hosts the coordination server.
pub const SERVER_SERVICE_NAME: &str = "BarkServer";

/// Display name of the coordination server service.
pub const SERVER_SERVICE_DISPLAY_NAME: &str = "BARK Coordination Server";

/// Named pipe the GUI uses to talk to the local service. The `\\.\pipe\` prefix
/// keeps it local-machine only; the pipe is ACL'd to interactive users.
pub const CONTROL_PIPE_NAME: &str = r"\\.\pipe\BARK\control";

/// Named pipe the service uses to talk to the session agent it launched.
pub const AGENT_PIPE_PREFIX: &str = r"\\.\pipe\BARK\agent";

/// Default UDP port the coordination server listens on. Chosen from the
/// unassigned range; the installer opens exactly this port and nothing else.
pub const DEFAULT_SERVER_PORT: u16 = 57411;

/// Secondary port the server also listens on, for networks that only permit
/// traffic to well-known ports. Tried automatically when the primary is blocked.
pub const FALLBACK_SERVER_PORT: u16 = 443;

/// ALPN protocol identifier for BARK's QUIC connections.
pub const ALPN: &[u8] = b"bark/1";
