//! The relay's own two packets.
//!
//! A relay forwards UDP datagrams between two peers and understands nothing
//! about them, with one exception: before forwarding starts, each peer tells
//! the relay who it is with a **bind** packet carrying the token the
//! coordination server gave it, and the relay answers with an **ack**.
//!
//! Both packets start with a zero byte, which QUIC treats as invalid, so a
//! stray one reaching a QUIC endpoint is discarded rather than misread.

use crate::wire::WireError;

const MAGIC: [u8; 5] = [0x00, b'B', b'R', b'L', b'Y'];
const VERSION: u8 = 1;
const KIND_BIND: u8 = 1;
const KIND_ACK: u8 = 2;

pub const BIND_LEN: usize = MAGIC.len() + 2 + 16;
pub const ACK_LEN: usize = MAGIC.len() + 3;

/// "I am the holder of this token; forward my traffic."
pub fn encode_bind(token: &[u8; 16]) -> [u8; BIND_LEN] {
    let mut out = [0u8; BIND_LEN];
    out[..5].copy_from_slice(&MAGIC);
    out[5] = VERSION;
    out[6] = KIND_BIND;
    out[7..].copy_from_slice(token);
    out
}

/// The relay's answer. `ready` is true once both peers have bound, which is
/// the moment forwarding begins.
pub fn encode_ack(ready: bool) -> [u8; ACK_LEN] {
    let mut out = [0u8; ACK_LEN];
    out[..5].copy_from_slice(&MAGIC);
    out[5] = VERSION;
    out[6] = KIND_ACK;
    out[7] = u8::from(ready);
    out
}

/// Whether a datagram is a relay control packet at all. Cheap enough to run
/// on every forwarded datagram.
pub fn is_relay_packet(buf: &[u8]) -> bool {
    buf.len() >= MAGIC.len() + 2 && buf[..5] == MAGIC
}

/// Reads a bind packet's token.
pub fn decode_bind(buf: &[u8]) -> Result<[u8; 16], WireError> {
    if buf.len() != BIND_LEN || buf[..5] != MAGIC {
        return Err(WireError::Invalid("not a relay bind packet"));
    }
    if buf[5] != VERSION {
        return Err(WireError::Invalid("relay protocol version not supported"));
    }
    if buf[6] != KIND_BIND {
        return Err(WireError::Invalid("not a relay bind packet"));
    }
    let mut token = [0u8; 16];
    token.copy_from_slice(&buf[7..]);
    Ok(token)
}

/// Reads an ack packet: `Some(ready)`, or `None` if it is not an ack.
pub fn decode_ack(buf: &[u8]) -> Option<bool> {
    if buf.len() != ACK_LEN || buf[..5] != MAGIC || buf[5] != VERSION || buf[6] != KIND_ACK {
        return None;
    }
    Some(buf[7] != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_round_trips() {
        let token = [7u8; 16];
        let p = encode_bind(&token);
        assert!(is_relay_packet(&p));
        assert_eq!(decode_bind(&p).unwrap(), token);
    }

    #[test]
    fn ack_round_trips() {
        assert_eq!(decode_ack(&encode_ack(true)), Some(true));
        assert_eq!(decode_ack(&encode_ack(false)), Some(false));
        assert_eq!(decode_ack(&encode_bind(&[0; 16])), None);
    }

    #[test]
    fn quic_packets_are_never_mistaken_for_relay_packets() {
        // Every QUIC packet has the fixed bit (0x40) set in its first byte,
        // unless both ends negotiated greasing; either way a QUIC packet never
        // starts with the five-byte magic.
        let long_header = [0xC3u8, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        let short_header = [0x41u8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert!(!is_relay_packet(&long_header));
        assert!(!is_relay_packet(&short_header));
    }

    #[test]
    fn malformed_binds_are_refused() {
        let mut p = encode_bind(&[1; 16]);
        p[5] = 99;
        assert!(decode_bind(&p).is_err(), "unknown version");
        assert!(decode_bind(&p[..10]).is_err(), "truncated");
        assert!(decode_bind(&encode_ack(true)).is_err(), "an ack is not a bind");
    }
}
