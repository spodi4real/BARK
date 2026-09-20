//! The BARK wire protocol.
//!
//! Three families of message, each with a format chosen for what it carries:
//!
//! | Family | Transport | Encoding | Why |
//! |---|---|---|---|
//! | [`video`] packets | unreliable QUIC datagrams | hand-written binary | runs thousands of times a second and must not allocate |
//! | [`input`] events | dedicated reliable stream | hand-written binary | latency-critical, tiny, fixed shape |
//! | [`control`] and [`peer`] | reliable streams | postcard via serde | low rate, changes often, clarity matters more than bytes |
//!
//! Every decoder in this crate is bounds-checked and total: it either returns a
//! value or an error, and never panics, however hostile the input. That is not
//! a stylistic preference — these parsers run inside a process with SYSTEM
//! privileges, reading bytes from the network.

pub mod control;
pub mod input;
pub mod peer;
pub mod video;
pub mod wire;

pub use input::{InputEvent, InputMessage, MouseButton};
pub use video::{AssembledFrame, Codec, FrameMeta, PacketHeader, Reassembler};
pub use wire::{Cursor, WireError};

/// Safe payload size for a QUIC datagram.
///
/// QUIC's own minimum guaranteed datagram is 1200 bytes; from that comes the
/// QUIC header, then BARK's packet header and the AEAD tag. Being conservative
/// here matters more than squeezing out the last few bytes: a datagram that
/// exceeds the path MTU is silently dropped, and diagnosing that from the
/// symptom — a stream that works on one network and not another — is painful.
pub const SAFE_DATAGRAM_PAYLOAD: usize = 1200 - 48 - video::HEADER_LEN - bark_crypto::TAG_LEN;

// Checked at compile time rather than in a test: if a header ever grows enough
// to eat the datagram budget, the build should stop, not a test run.
const _: () = assert!(SAFE_DATAGRAM_PAYLOAD > 1000);
const _: () = assert!(SAFE_DATAGRAM_PAYLOAD < 1200);
