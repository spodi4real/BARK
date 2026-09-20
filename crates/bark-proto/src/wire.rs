//! Byte-level encoding helpers.
//!
//! BARK hand-encodes the two formats that run at packet rate — input events and
//! video packet headers — and uses a serialiser for everything else. The hand
//! encoding exists because those two paths run thousands of times a second and
//! must not allocate; everywhere else, clarity wins.
//!
//! Every read is bounds-checked. This code parses bytes that arrived from the
//! network into a process running as SYSTEM, so a decoder that can be walked off
//! the end of a buffer is a remote compromise. There is no unchecked read in
//! this file and there must never be one.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before the value did.
    Truncated,
    /// The bytes were well-formed but meant something impossible.
    Invalid(&'static str),
    /// A length field claimed more than the configured maximum.
    TooLarge { claimed: usize, limit: usize },
    /// The serialiser rejected the payload.
    Malformed,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Truncated => write!(f, "the message ended unexpectedly"),
            WireError::Invalid(what) => write!(f, "the message was not valid: {what}"),
            WireError::TooLarge { claimed, limit } => write!(
                f,
                "the message claimed to be {claimed} bytes, over the {limit} byte limit"
            ),
            WireError::Malformed => write!(f, "the message could not be understood"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<WireError> for bark_core::BarkError {
    fn from(e: WireError) -> Self {
        bark_core::BarkError::Protocol(e.to_string())
    }
}

/// A bounds-checked forward reader.
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        // Checked addition: a hostile length could otherwise overflow `pos + n`
        // and wrap to a value inside the buffer.
        let end = self.pos.checked_add(n).ok_or(WireError::Truncated)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn i16(&mut self) -> Result<i16, WireError> {
        Ok(self.u16()? as i16)
    }

    pub fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn i32(&mut self) -> Result<i32, WireError> {
        Ok(self.u32()? as i32)
    }

    pub fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        let s = self.take(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// The rest of the buffer, consuming it.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.buf[self.pos..];
        self.pos = self.buf.len();
        s
    }
}

/// Largest control message BARK will accept.
///
/// Control messages are small — the biggest is a device list. A limit stops a
/// peer from making us allocate gigabytes by claiming a huge length, which is
/// the cheapest denial-of-service there is against a length-prefixed protocol.
pub const MAX_MESSAGE: usize = 1 << 20; // 1 MiB

/// Writes a length-prefixed, serialiser-encoded message.
pub fn encode_framed<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    let body = postcard::to_allocvec(value).map_err(|_| WireError::Malformed)?;
    if body.len() > MAX_MESSAGE {
        return Err(WireError::TooLarge { claimed: body.len(), limit: MAX_MESSAGE });
    }
    let mut out = Vec::with_capacity(body.len() + 4);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reads one length-prefixed message from the front of `buf`.
///
/// Returns the decoded value and how many bytes it consumed, or `None` if the
/// buffer does not yet hold a whole message — which is the normal case when
/// reading from a stream.
pub fn decode_framed<T: serde::de::DeserializeOwned>(
    buf: &[u8],
) -> Result<Option<(T, usize)>, WireError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_MESSAGE {
        return Err(WireError::TooLarge { claimed: len, limit: MAX_MESSAGE });
    }
    let total = 4usize.checked_add(len).ok_or(WireError::Truncated)?;
    if buf.len() < total {
        return Ok(None);
    }
    let value: T = postcard::from_bytes(&buf[4..total]).map_err(|_| WireError::Malformed)?;
    Ok(Some((value, total)))
}

/// Decodes a message whose length is already known exactly — a QUIC datagram,
/// for instance, which arrives whole or not at all.
pub fn decode_exact<T: serde::de::DeserializeOwned>(buf: &[u8]) -> Result<T, WireError> {
    postcard::from_bytes(buf).map_err(|_| WireError::Malformed)
}

pub fn encode_exact<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, WireError> {
    postcard::to_allocvec(value).map_err(|_| WireError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Sample {
        a: u32,
        b: String,
        c: Vec<u8>,
    }

    #[test]
    fn cursor_reads_each_width_correctly() {
        let mut buf = Vec::new();
        buf.push(0xABu8);
        buf.extend_from_slice(&0x1234u16.to_le_bytes());
        buf.extend_from_slice(&0x89ABCDEFu32.to_le_bytes());
        buf.extend_from_slice(&0x0123456789ABCDEFu64.to_le_bytes());

        let mut c = Cursor::new(&buf);
        assert_eq!(c.u8().unwrap(), 0xAB);
        assert_eq!(c.u16().unwrap(), 0x1234);
        assert_eq!(c.u32().unwrap(), 0x89ABCDEF);
        assert_eq!(c.u64().unwrap(), 0x0123456789ABCDEF);
        assert!(c.is_empty());
    }

    #[test]
    fn cursor_refuses_to_read_past_the_end() {
        let buf = [1u8, 2, 3];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.u16().unwrap(), 0x0201);
        assert_eq!(c.u16(), Err(WireError::Truncated));
        // And a failed read must not have advanced the position.
        assert_eq!(c.remaining(), 1);
        assert_eq!(c.u8().unwrap(), 3);
    }

    #[test]
    fn cursor_take_rejects_an_overflowing_length() {
        let buf = [0u8; 8];
        let mut c = Cursor::new(&buf);
        assert_eq!(c.take(usize::MAX), Err(WireError::Truncated));
        assert_eq!(c.remaining(), 8, "a rejected read must not consume anything");
    }

    #[test]
    fn empty_buffers_are_handled() {
        let mut c = Cursor::new(&[]);
        assert!(c.is_empty());
        assert_eq!(c.u8(), Err(WireError::Truncated));
        assert_eq!(c.rest(), &[] as &[u8]);
    }

    #[test]
    fn framed_messages_round_trip() {
        let s = Sample { a: 7, b: "central-server".into(), c: vec![1, 2, 3] };
        let encoded = encode_framed(&s).unwrap();
        let (back, used): (Sample, usize) = decode_framed(&encoded).unwrap().unwrap();
        assert_eq!(back, s);
        assert_eq!(used, encoded.len());
    }

    #[test]
    fn a_partial_frame_is_not_an_error() {
        let s = Sample { a: 1, b: "x".into(), c: vec![] };
        let encoded = encode_framed(&s).unwrap();
        for n in 0..encoded.len() {
            let r: Result<Option<(Sample, usize)>, _> = decode_framed(&encoded[..n]);
            assert_eq!(r.unwrap(), None, "a {n}-byte prefix should mean 'wait for more'");
        }
    }

    #[test]
    fn several_frames_decode_one_after_another() {
        let mut stream = Vec::new();
        for i in 0..3u32 {
            stream.extend_from_slice(
                &encode_framed(&Sample { a: i, b: format!("d{i}"), c: vec![i as u8] }).unwrap(),
            );
        }
        let mut offset = 0;
        for i in 0..3u32 {
            let (s, used): (Sample, usize) =
                decode_framed(&stream[offset..]).unwrap().expect("a whole frame");
            assert_eq!(s.a, i);
            offset += used;
        }
        assert_eq!(offset, stream.len());
    }

    #[test]
    fn an_absurd_length_prefix_is_rejected_before_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(u32::MAX).to_le_bytes());
        buf.extend_from_slice(b"short");
        let r: Result<Option<(Sample, usize)>, _> = decode_framed(&buf);
        assert!(matches!(r, Err(WireError::TooLarge { .. })), "got {r:?}");
    }

    #[test]
    fn corrupt_payloads_are_rejected() {
        let s = Sample { a: 1, b: "hello".into(), c: vec![9] };
        let mut encoded = encode_framed(&s).unwrap();
        let n = encoded.len();
        // Scribble over the body without changing the length prefix.
        for b in &mut encoded[4..n] {
            *b = 0xFF;
        }
        let r: Result<Option<(Sample, usize)>, _> = decode_framed(&encoded);
        assert!(r.is_err(), "corrupt payload should not decode");
    }

    #[test]
    fn exact_encoding_round_trips_and_rejects_junk() {
        let s = Sample { a: 3, b: "abc".into(), c: vec![4, 5] };
        let e = encode_exact(&s).unwrap();
        assert_eq!(decode_exact::<Sample>(&e).unwrap(), s);
        assert!(decode_exact::<Sample>(&[0xFF; 3]).is_err());
    }
}
