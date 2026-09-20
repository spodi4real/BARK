//! Error type shared across BARK.
//!
//! Every variant carries enough context to produce the kind of message the
//! error-handling requirement asks for: what was attempted, what failed, and
//! what the operator can do about it. `BarkError::explain` renders the plain
//! English form that dialogs show.

use std::fmt;

pub type Result<T> = std::result::Result<T, BarkError>;

#[derive(Debug, thiserror::Error)]
pub enum BarkError {
    #[error("input/output error: {0}")]
    Io(#[from] std::io::Error),

    #[error("windows error: {0}")]
    Windows(String),

    #[error("{0}")]
    Config(String),

    #[error("{0}")]
    Identity(String),

    #[error("{0}")]
    Crypto(String),

    #[error("{0}")]
    Protocol(String),

    #[error("{0}")]
    Network(String),

    #[error("device {0} is not trusted by this computer")]
    NotTrusted(String),

    #[error("device {0} has been revoked")]
    Revoked(String),

    #[error("{0}")]
    Capture(String),

    #[error("{0}")]
    Encode(String),

    #[error("{0}")]
    Decode(String),

    #[error("operation timed out after {0} ms")]
    Timeout(u64),

    #[error("{0}")]
    Other(String),
}

impl BarkError {
    pub fn other(msg: impl Into<String>) -> Self {
        BarkError::Other(msg.into())
    }

    pub fn network(msg: impl Into<String>) -> Self {
        BarkError::Network(msg.into())
    }

    pub fn protocol(msg: impl Into<String>) -> Self {
        BarkError::Protocol(msg.into())
    }

    pub fn config(msg: impl Into<String>) -> Self {
        BarkError::Config(msg.into())
    }

    pub fn identity(msg: impl Into<String>) -> Self {
        BarkError::Identity(msg.into())
    }

    pub fn crypto(msg: impl Into<String>) -> Self {
        BarkError::Crypto(msg.into())
    }

    pub fn capture(msg: impl Into<String>) -> Self {
        BarkError::Capture(msg.into())
    }

    pub fn encode(msg: impl Into<String>) -> Self {
        BarkError::Encode(msg.into())
    }

    pub fn decode(msg: impl Into<String>) -> Self {
        BarkError::Decode(msg.into())
    }

    /// A short headline suitable for a dialog caption.
    pub fn headline(&self) -> &'static str {
        match self {
            BarkError::Io(_) => "File or disk error",
            BarkError::Windows(_) => "Windows reported an error",
            BarkError::Config(_) => "Configuration problem",
            BarkError::Identity(_) => "Device identity problem",
            BarkError::Crypto(_) => "Security error",
            BarkError::Protocol(_) => "Protocol error",
            BarkError::Network(_) => "Network error",
            BarkError::NotTrusted(_) => "Device not paired",
            BarkError::Revoked(_) => "Device revoked",
            BarkError::Capture(_) => "Screen capture error",
            BarkError::Encode(_) => "Video encoder error",
            BarkError::Decode(_) => "Video decoder error",
            BarkError::Timeout(_) => "No response",
            BarkError::Other(_) => "Error",
        }
    }

    /// Plain-English causes the operator can actually check. Rendered under a
    /// "Possible causes:" heading in error dialogs.
    pub fn possible_causes(&self) -> &'static [&'static str] {
        match self {
            BarkError::Network(_) | BarkError::Timeout(_) => &[
                "The remote computer is turned off or asleep",
                "The remote computer has no network connection",
                "The BARK service is not running on the remote computer",
                "A firewall or network policy is blocking the connection",
            ],
            BarkError::NotTrusted(_) => &[
                "This computer has never been paired with that device",
                "The pairing was removed on the remote computer",
                "The remote computer was reinstalled and has a new identity",
            ],
            BarkError::Revoked(_) => &[
                "An administrator revoked trust for this computer",
                "Pair the devices again to restore access",
            ],
            BarkError::Identity(_) => &[
                "The BARK data folder was deleted or moved",
                "The identity file is damaged",
                "BARK does not have permission to read C:\\ProgramData\\BARK",
            ],
            BarkError::Capture(_) => &[
                "No display is attached to the remote computer",
                "The display driver was restarted or updated",
                "The remote computer is at a secure screen that cannot be captured",
            ],
            BarkError::Encode(_) => &[
                "The graphics driver is out of date",
                "No hardware video encoder is available on the remote computer",
                "Another program is using all available encoder sessions",
            ],
            _ => &[],
        }
    }

    /// Full multi-line explanation used by dialogs and the log.
    pub fn explain(&self) -> String {
        let mut s = String::new();
        s.push_str(self.headline());
        s.push_str("\n\n");
        s.push_str(&self.to_string());
        let causes = self.possible_causes();
        if !causes.is_empty() {
            s.push_str("\n\nPossible causes:");
            for c in causes {
                s.push_str("\n\u{2022} ");
                s.push_str(c);
            }
        }
        s
    }
}

#[cfg(windows)]
impl From<windows::core::Error> for BarkError {
    fn from(e: windows::core::Error) -> Self {
        // Include the HRESULT so a support conversation can be precise, and the
        // system's own message so it is readable without a lookup table.
        BarkError::Windows(format!("{} (0x{:08X})", e.message(), e.code().0 as u32))
    }
}

/// Wraps a result with a sentence describing what was being attempted, so the
/// operator sees "Could not start the screen capture: ..." rather than a bare
/// system error.
pub trait Context<T> {
    fn ctx(self, what: &'static str) -> Result<T>;
}

impl<T, E> Context<T> for std::result::Result<T, E>
where
    E: fmt::Display,
{
    fn ctx(self, what: &'static str) -> Result<T> {
        self.map_err(|e| BarkError::Other(format!("{what}: {e}")))
    }
}
