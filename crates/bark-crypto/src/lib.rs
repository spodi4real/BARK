//! Device identity, pairing, trust and end-to-end session encryption.
//!
//! Everything security-relevant in BARK lives here so it can be reviewed as one
//! piece. The rules this crate is written to:
//!
//! * A private key is never written to disk unprotected, never logged, never
//!   included in a `Debug` rendering, and is wiped when dropped.
//! * Every signature is bound to the purpose it was made for, so one can never
//!   be replayed as another.
//! * Anything compared against a secret is compared in constant time.
//! * Authorisation happens before expensive work, so an unauthorised peer
//!   cannot consume resources.
//! * Failures say what the operator should do, not just what went wrong.

pub mod dpapi;
pub mod handshake;
pub mod identity;
pub mod pairing;
pub mod session;
pub mod trust;

pub use handshake::{Accept, Confirm, Hello, Initiator, Responder};
pub use identity::{DeviceIdentity, PublicIdentity, Signature64};
pub use pairing::{AttemptLimiter, CodeCommitment, PairingCode};
pub use session::{Direction, Opener, Sealer, SessionKeys, TAG_LEN};
pub use trust::{Grant, TrustEntry, TrustStore};
