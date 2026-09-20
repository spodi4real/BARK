//! Video packet format and frame reassembly.
//!
//! Video travels as **unreliable QUIC datagrams**, deliberately. A retransmitted
//! frame arrives too late to be worth drawing: by the time it gets there, two
//! newer frames have been captured. Retransmission also causes the pathological
//! behaviour where a lossy link spends its whole capacity resending stale data
//! and never catches up. BARK drops what is lost and repairs the stream by
//! telling the encoder which reference frame went missing.
//!
//! A frame is larger than a datagram, so it is split into fragments. This module
//! defines the fragment header, the per-frame metadata, and the reassembler that
//! puts frames back together.
//!
//! The reassembler's governing rule is **never wait**. If fragments of frame 41
//! are still missing when frame 42 completes, frame 41 is abandoned. Holding
//! frame 42 back to preserve ordering would add exactly the latency this whole
//! system exists to avoid.

use crate::wire::{Cursor, WireError};
use bark_core::clock::FrameStamps;
use std::collections::BTreeMap;

/// Datagram type tags. The first byte of every datagram.
pub const CHANNEL_VIDEO: u8 = 1;
pub const CHANNEL_CURSOR: u8 = 2;
pub const CHANNEL_PING: u8 = 3;
pub const CHANNEL_AUDIO: u8 = 4;

/// This fragment belongs to a frame that does not reference any earlier frame.
pub const FLAG_KEYFRAME: u16 = 1 << 0;
/// Last fragment of its frame.
pub const FLAG_LAST_FRAGMENT: u16 = 1 << 1;
/// The frame changes resolution; the decoder must reconfigure.
pub const FLAG_RESOLUTION_CHANGE: u16 = 1 << 2;
/// The frame is a repeat of the previous one, sent to keep a lossy link warm.
pub const FLAG_REFRESH: u16 = 1 << 3;

/// Video codecs BARK can negotiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum Codec {
    H264 = 1,
    H265 = 2,
    Av1 = 3,
}

impl Codec {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Codec::H264,
            2 => Codec::H265,
            3 => Codec::Av1,
            _ => return None,
        })
    }

    /// Shown in the connection information panel.
    pub fn name(self) -> &'static str {
        match self {
            Codec::H264 => "H.264",
            Codec::H265 => "H.265",
            Codec::Av1 => "AV1",
        }
    }
}

/// The plaintext header on every video datagram.
///
/// Sent in the clear and authenticated as additional data, because the receiver
/// must read the sequence number to decrypt and the fragment fields to
/// reassemble. Authenticating them means an attacker can see them but cannot
/// change them — altering a fragment index to corrupt a frame would break the
/// tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub frame_id: u32,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub flags: u16,
    /// AEAD counter. Also what the replay window checks.
    pub sequence: u64,
}

/// Size of the encoded [`PacketHeader`].
pub const HEADER_LEN: usize = 1 + 2 + 4 + 2 + 2 + 8;

impl PacketHeader {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(CHANNEL_VIDEO);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.frame_id.to_le_bytes());
        out.extend_from_slice(&self.fragment_index.to_le_bytes());
        out.extend_from_slice(&self.fragment_count.to_le_bytes());
        out.extend_from_slice(&self.sequence.to_le_bytes());
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(buf);
        if c.u8()? != CHANNEL_VIDEO {
            return Err(WireError::Invalid("not a video packet"));
        }
        let flags = c.u16()?;
        let frame_id = c.u32()?;
        let fragment_index = c.u16()?;
        let fragment_count = c.u16()?;
        let sequence = c.u64()?;

        if fragment_count == 0 {
            return Err(WireError::Invalid("a frame must have at least one fragment"));
        }
        if fragment_index >= fragment_count {
            return Err(WireError::Invalid("fragment index is outside the frame"));
        }

        Ok(PacketHeader { frame_id, fragment_index, fragment_count, flags, sequence })
    }

    pub fn is_keyframe(&self) -> bool {
        self.flags & FLAG_KEYFRAME != 0
    }
}

/// Per-frame metadata, carried at the start of the reassembled payload and
/// therefore encrypted along with the picture data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrameMeta {
    pub width: u16,
    pub height: u16,
    pub codec_id: u8,
    /// Which monitor this frame came from, for multi-monitor sessions.
    pub output_index: u8,
    pub capture_begin_us: u64,
    pub capture_end_us: u64,
    pub encode_begin_us: u64,
    pub encode_end_us: u64,
    pub send_us: u64,
    /// Controller timestamp of the last input the remote had applied when this
    /// frame was captured. Zero when no input was pending.
    pub input_echo_us: u64,
}

/// Size of the encoded [`FrameMeta`].
pub const FRAME_META_LEN: usize = 2 + 2 + 1 + 1 + 2 + 8 * 6;

impl FrameMeta {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.width.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.push(self.codec_id);
        out.push(self.output_index);
        out.extend_from_slice(&0u16.to_le_bytes()); // reserved, keeps the u64s aligned
        for v in [
            self.capture_begin_us,
            self.capture_end_us,
            self.encode_begin_us,
            self.encode_end_us,
            self.send_us,
            self.input_echo_us,
        ] {
            out.extend_from_slice(&v.to_le_bytes());
        }
    }

    /// Splits a reassembled payload into its metadata and the bitstream.
    pub fn decode(buf: &[u8]) -> Result<(Self, &[u8]), WireError> {
        let mut c = Cursor::new(buf);
        let width = c.u16()?;
        let height = c.u16()?;
        let codec_id = c.u8()?;
        let output_index = c.u8()?;
        let _reserved = c.u16()?;
        let meta = FrameMeta {
            width,
            height,
            codec_id,
            output_index,
            capture_begin_us: c.u64()?,
            capture_end_us: c.u64()?,
            encode_begin_us: c.u64()?,
            encode_end_us: c.u64()?,
            send_us: c.u64()?,
            input_echo_us: c.u64()?,
        };
        if width == 0 || height == 0 {
            return Err(WireError::Invalid("frame has no size"));
        }
        if Codec::from_u8(codec_id).is_none() {
            return Err(WireError::Invalid("unknown codec"));
        }
        Ok((meta, c.rest()))
    }

    pub fn codec(&self) -> Option<Codec> {
        Codec::from_u8(self.codec_id)
    }

    /// Fills in the remote-side half of a latency record.
    pub fn stamps(&self, frame_id: u32) -> FrameStamps {
        FrameStamps {
            frame_id: frame_id as u64,
            capture_begin: self.capture_begin_us,
            capture_end: self.capture_end_us,
            encode_begin: self.encode_begin_us,
            encode_end: self.encode_end_us,
            send: self.send_us,
            input_echo: self.input_echo_us,
            ..Default::default()
        }
    }
}

/// A frame that arrived whole.
#[derive(Debug, Clone)]
pub struct AssembledFrame {
    pub frame_id: u32,
    pub keyframe: bool,
    pub flags: u16,
    pub meta: FrameMeta,
    /// The encoded bitstream, ready for the decoder.
    pub bitstream: Vec<u8>,
    /// Local clock when the last fragment arrived.
    pub received_us: u64,
}

/// Why a frame was given up on. Reported so the controller can ask for the
/// right kind of repair and so the information panel can say what is going on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameLoss {
    /// A newer frame completed first; this one is stale.
    Superseded { frame_id: u32, missing: u16 },
    /// Nothing more arrived for it in time.
    TimedOut { frame_id: u32, missing: u16 },
}

impl FrameLoss {
    pub fn frame_id(&self) -> u32 {
        match self {
            FrameLoss::Superseded { frame_id, .. } | FrameLoss::TimedOut { frame_id, .. } => {
                *frame_id
            }
        }
    }
}

struct Partial {
    fragments: Vec<Option<Vec<u8>>>,
    have: u16,
    flags: u16,
    first_seen_us: u64,
}

/// Puts fragments back into frames.
///
/// Bounded in both directions: at most [`MAX_INFLIGHT`] frames are tracked, and
/// each frame is abandoned after [`ASSEMBLY_TIMEOUT_US`]. Neither bound is
/// about correctness on a good network — they exist so a hostile or badly
/// broken peer cannot make the controller hold memory indefinitely.
pub struct Reassembler {
    partial: BTreeMap<u32, Partial>,
    /// Highest frame id fully delivered; anything at or below is stale.
    delivered_through: Option<u32>,
    max_frame_bytes: usize,
}

/// Frames tracked at once. Two is enough for a healthy link; four tolerates a
/// burst of reordering without ever holding a frame back.
pub const MAX_INFLIGHT: usize = 4;

/// How long an incomplete frame waits for its missing fragments.
///
/// 50 ms is far longer than any reordering a real network produces at these
/// rates, and short enough that a lost fragment does not visibly stall the
/// picture before recovery starts.
pub const ASSEMBLY_TIMEOUT_US: u64 = 50_000;

/// Refuses a frame claiming to be larger than this. A 4K keyframe is a couple
/// of megabytes at most.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Reassembler {
            partial: BTreeMap::new(),
            delivered_through: None,
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
        }
    }

    pub fn with_max_frame_bytes(max: usize) -> Self {
        Reassembler { max_frame_bytes: max, ..Self::new() }
    }

    /// Feeds one decrypted fragment payload.
    ///
    /// Returns the frame if this fragment completed it, plus any frames given up
    /// on as a result.
    pub fn push(
        &mut self,
        header: &PacketHeader,
        payload: Vec<u8>,
        now_us: u64,
    ) -> Result<(Option<AssembledFrame>, Vec<FrameLoss>), WireError> {
        let mut losses = Vec::new();

        // A fragment for a frame already delivered, or older than one already
        // delivered, is stale. Silently ignore it: this happens normally when a
        // duplicate arrives after the frame was completed.
        if let Some(through) = self.delivered_through {
            if header.frame_id <= through {
                return Ok((None, losses));
            }
        }

        if payload.len() > self.max_frame_bytes {
            return Err(WireError::TooLarge {
                claimed: payload.len(),
                limit: self.max_frame_bytes,
            });
        }

        let entry = self.partial.entry(header.frame_id).or_insert_with(|| Partial {
            fragments: vec![None; header.fragment_count as usize],
            have: 0,
            flags: 0,
            first_seen_us: now_us,
        });

        // A peer that changes its mind about how many fragments a frame has is
        // either broken or malicious; either way the frame is unusable.
        if entry.fragments.len() != header.fragment_count as usize {
            self.partial.remove(&header.frame_id);
            return Err(WireError::Invalid("fragment count changed mid-frame"));
        }

        let slot = &mut entry.fragments[header.fragment_index as usize];
        if slot.is_none() {
            entry.have += 1;
            *slot = Some(payload);
        }
        entry.flags |= header.flags;

        let complete = entry.have == header.fragment_count;
        let mut assembled = None;

        if complete {
            let entry = self.partial.remove(&header.frame_id).expect("just checked");
            let total: usize = entry.fragments.iter().flatten().map(|f| f.len()).sum();
            if total > self.max_frame_bytes {
                return Err(WireError::TooLarge { claimed: total, limit: self.max_frame_bytes });
            }
            let mut buf = Vec::with_capacity(total);
            for f in entry.fragments.into_iter() {
                buf.extend_from_slice(&f.expect("all fragments present"));
            }

            let (meta, bitstream) = FrameMeta::decode(&buf)?;
            assembled = Some(AssembledFrame {
                frame_id: header.frame_id,
                keyframe: entry.flags & FLAG_KEYFRAME != 0,
                flags: entry.flags,
                meta,
                bitstream: bitstream.to_vec(),
                received_us: now_us,
            });

            // Everything older than the frame just delivered is stale.
            let stale: Vec<u32> =
                self.partial.range(..header.frame_id).map(|(k, _)| *k).collect();
            for id in stale {
                if let Some(p) = self.partial.remove(&id) {
                    losses.push(FrameLoss::Superseded {
                        frame_id: id,
                        missing: p.fragments.len() as u16 - p.have,
                    });
                }
            }
            self.delivered_through = Some(header.frame_id);
        }

        losses.extend(self.expire(now_us));
        Ok((assembled, losses))
    }

    /// Drops frames that have waited too long or overflowed the tracking limit.
    /// Called automatically by `push`; call it directly when no packets are
    /// arriving so a stall is still noticed.
    pub fn expire(&mut self, now_us: u64) -> Vec<FrameLoss> {
        let mut losses = Vec::new();

        let timed_out: Vec<u32> = self
            .partial
            .iter()
            .filter(|(_, p)| now_us.saturating_sub(p.first_seen_us) > ASSEMBLY_TIMEOUT_US)
            .map(|(k, _)| *k)
            .collect();
        for id in timed_out {
            if let Some(p) = self.partial.remove(&id) {
                losses.push(FrameLoss::TimedOut {
                    frame_id: id,
                    missing: p.fragments.len() as u16 - p.have,
                });
            }
        }

        // Keep the newest frames if a peer floods us with partial ones.
        while self.partial.len() > MAX_INFLIGHT {
            let oldest = *self.partial.keys().next().expect("non-empty");
            if let Some(p) = self.partial.remove(&oldest) {
                losses.push(FrameLoss::Superseded {
                    frame_id: oldest,
                    missing: p.fragments.len() as u16 - p.have,
                });
            }
        }

        losses
    }

    pub fn inflight(&self) -> usize {
        self.partial.len()
    }

    /// Forgets everything. Used after a decoder reset or a reconnection, where
    /// partially received frames from the old stream must not be mixed in.
    pub fn reset(&mut self) {
        self.partial.clear();
        self.delivered_through = None;
    }
}

/// Splits an encoded frame into datagram-sized fragments.
///
/// `max_payload` is the room left in a datagram after the header and the AEAD
/// tag. Fragments are as equal in size as possible rather than "fill each one
/// and leave a runt at the end": equal fragments pace more smoothly and make a
/// single loss cost a predictable fraction of the frame.
pub fn fragment(payload_len: usize, max_payload: usize) -> Vec<(usize, usize)> {
    assert!(max_payload > 0, "fragment size must be positive");
    if payload_len == 0 {
        return vec![(0, 0)];
    }
    let count = payload_len.div_ceil(max_payload);
    let base = payload_len / count;
    let extra = payload_len % count;

    let mut out = Vec::with_capacity(count);
    let mut offset = 0;
    for i in 0..count {
        let len = base + usize::from(i < extra);
        out.push((offset, len));
        offset += len;
    }
    debug_assert_eq!(offset, payload_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> FrameMeta {
        FrameMeta {
            width: 1920,
            height: 1080,
            codec_id: Codec::H265 as u8,
            output_index: 0,
            capture_begin_us: 1000,
            capture_end_us: 1500,
            encode_begin_us: 1500,
            encode_end_us: 3000,
            send_us: 3100,
            input_echo_us: 900,
        }
    }

    /// Builds the datagrams for one frame.
    fn make_frame(frame_id: u32, bitstream: &[u8], fragments: u16, keyframe: bool)
        -> Vec<(PacketHeader, Vec<u8>)>
    {
        let mut payload = Vec::new();
        meta().encode(&mut payload);
        payload.extend_from_slice(bitstream);

        let per = payload.len().div_ceil(fragments as usize).max(1);
        let mut out = Vec::new();
        let base_seq = frame_id as u64 * 100;
        for (i, chunk) in payload.chunks(per).enumerate() {
            let seq = base_seq + i as u64;
            let mut flags = 0;
            if keyframe {
                flags |= FLAG_KEYFRAME;
            }
            if i as u16 == fragments - 1 {
                flags |= FLAG_LAST_FRAGMENT;
            }
            out.push((
                PacketHeader {
                    frame_id,
                    fragment_index: i as u16,
                    fragment_count: fragments,
                    flags,
                    sequence: seq,
                },
                chunk.to_vec(),
            ));
        }
        out
    }

    #[test]
    fn packet_header_round_trips() {
        let h = PacketHeader {
            frame_id: 123456,
            fragment_index: 3,
            fragment_count: 10,
            flags: FLAG_KEYFRAME | FLAG_LAST_FRAGMENT,
            sequence: 0xDEADBEEFCAFE,
        };
        let mut buf = Vec::new();
        h.encode(&mut buf);
        assert_eq!(buf.len(), HEADER_LEN);
        assert_eq!(PacketHeader::decode(&buf).unwrap(), h);
    }

    #[test]
    fn nonsensical_headers_are_rejected() {
        let mut buf = Vec::new();
        PacketHeader {
            frame_id: 1,
            fragment_index: 5,
            fragment_count: 3, // index outside the frame
            flags: 0,
            sequence: 0,
        }
        .encode(&mut buf);
        assert!(PacketHeader::decode(&buf).is_err());

        let mut buf = Vec::new();
        PacketHeader {
            frame_id: 1,
            fragment_index: 0,
            fragment_count: 0, // no fragments
            flags: 0,
            sequence: 0,
        }
        .encode(&mut buf);
        assert!(PacketHeader::decode(&buf).is_err());

        // Wrong channel tag.
        let mut buf = Vec::new();
        PacketHeader { frame_id: 1, fragment_index: 0, fragment_count: 1, flags: 0, sequence: 0 }
            .encode(&mut buf);
        buf[0] = CHANNEL_CURSOR;
        assert!(PacketHeader::decode(&buf).is_err());
    }

    #[test]
    fn truncated_headers_are_rejected() {
        let mut buf = Vec::new();
        PacketHeader { frame_id: 1, fragment_index: 0, fragment_count: 1, flags: 0, sequence: 0 }
            .encode(&mut buf);
        for n in 0..buf.len() {
            assert!(PacketHeader::decode(&buf[..n]).is_err(), "{n}-byte prefix decoded");
        }
    }

    #[test]
    fn frame_meta_round_trips_with_its_bitstream() {
        let mut buf = Vec::new();
        meta().encode(&mut buf);
        assert_eq!(buf.len(), FRAME_META_LEN);
        buf.extend_from_slice(b"bitstream bytes");

        let (m, rest) = FrameMeta::decode(&buf).unwrap();
        assert_eq!(m, meta());
        assert_eq!(rest, b"bitstream bytes");
    }

    #[test]
    fn frame_meta_rejects_impossible_values() {
        let mut m = meta();
        m.width = 0;
        let mut buf = Vec::new();
        m.encode(&mut buf);
        assert!(FrameMeta::decode(&buf).is_err(), "zero width should be rejected");

        let mut m = meta();
        m.codec_id = 99;
        let mut buf = Vec::new();
        m.encode(&mut buf);
        assert!(FrameMeta::decode(&buf).is_err(), "unknown codec should be rejected");
    }

    #[test]
    fn a_single_fragment_frame_assembles() {
        let mut r = Reassembler::new();
        let (h, p) = make_frame(1, b"picture data", 1, true).pop().unwrap();
        let (frame, losses) = r.push(&h, p, 1000).unwrap();
        let frame = frame.expect("should have completed");
        assert_eq!(frame.frame_id, 1);
        assert!(frame.keyframe);
        assert_eq!(frame.bitstream, b"picture data");
        assert_eq!(frame.meta, meta());
        assert!(losses.is_empty());
    }

    #[test]
    fn a_multi_fragment_frame_assembles_in_order() {
        let mut r = Reassembler::new();
        let parts = make_frame(1, &vec![0xAB; 5000], 5, false);
        let expected: Vec<u8> = vec![0xAB; 5000];

        let mut got = None;
        for (h, p) in &parts {
            let (frame, _) = r.push(h, p.clone(), 1000).unwrap();
            if let Some(f) = frame {
                got = Some(f);
            }
        }
        assert_eq!(got.expect("should complete").bitstream, expected);
    }

    #[test]
    fn a_frame_assembles_out_of_order() {
        let mut r = Reassembler::new();
        let mut parts = make_frame(1, &vec![0x11; 4000], 4, false);
        parts.reverse();

        let mut got = None;
        for (h, p) in &parts {
            if let (Some(f), _) = r.push(h, p.clone(), 1000).unwrap() {
                got = Some(f);
            }
        }
        assert_eq!(got.expect("should complete").bitstream, vec![0x11; 4000]);
    }

    #[test]
    fn duplicate_fragments_are_ignored() {
        let mut r = Reassembler::new();
        let parts = make_frame(1, &vec![0x22; 2000], 2, false);

        r.push(&parts[0].0, parts[0].1.clone(), 1000).unwrap();
        // The same fragment again must not count towards completion.
        let (frame, _) = r.push(&parts[0].0, parts[0].1.clone(), 1000).unwrap();
        assert!(frame.is_none(), "a duplicate must not complete the frame");

        let (frame, _) = r.push(&parts[1].0, parts[1].1.clone(), 1000).unwrap();
        assert!(frame.is_some(), "the real second fragment should complete it");
    }

    #[test]
    fn an_incomplete_frame_is_abandoned_when_a_newer_one_completes() {
        let mut r = Reassembler::new();

        // Frame 1 loses a fragment.
        let f1 = make_frame(1, &vec![0x33; 3000], 3, false);
        r.push(&f1[0].0, f1[0].1.clone(), 1000).unwrap();
        r.push(&f1[1].0, f1[1].1.clone(), 1000).unwrap();

        // Frame 2 arrives whole. Frame 1 must be given up on, not waited for.
        let f2 = make_frame(2, b"newer", 1, false);
        let (frame, losses) = r.push(&f2[0].0, f2[0].1.clone(), 1100).unwrap();

        assert_eq!(frame.expect("frame 2 should be delivered").frame_id, 2);
        assert_eq!(losses.len(), 1);
        assert_eq!(losses[0], FrameLoss::Superseded { frame_id: 1, missing: 1 });
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn late_fragments_of_an_abandoned_frame_are_ignored() {
        let mut r = Reassembler::new();
        let f1 = make_frame(1, &vec![0x44; 2000], 2, false);
        let f2 = make_frame(2, b"newer", 1, false);

        r.push(&f1[0].0, f1[0].1.clone(), 1000).unwrap();
        r.push(&f2[0].0, f2[0].1.clone(), 1100).unwrap();

        // The missing fragment of frame 1 finally turns up. It must not
        // resurrect the frame or be treated as an error.
        let (frame, losses) = r.push(&f1[1].0, f1[1].1.clone(), 1200).unwrap();
        assert!(frame.is_none());
        assert!(losses.is_empty());
    }

    #[test]
    fn an_incomplete_frame_times_out() {
        let mut r = Reassembler::new();
        let f1 = make_frame(1, &vec![0x55; 3000], 3, false);
        r.push(&f1[0].0, f1[0].1.clone(), 1000).unwrap();

        assert!(r.expire(1000 + ASSEMBLY_TIMEOUT_US).is_empty(), "not yet");
        let losses = r.expire(1000 + ASSEMBLY_TIMEOUT_US + 1);
        assert_eq!(losses, vec![FrameLoss::TimedOut { frame_id: 1, missing: 2 }]);
        assert_eq!(r.inflight(), 0);
    }

    #[test]
    fn the_number_of_tracked_frames_is_bounded() {
        let mut r = Reassembler::new();
        // Twenty frames, each missing a fragment, all within the timeout.
        for id in 1..=20u32 {
            let parts = make_frame(id, &vec![0x66; 2000], 2, false);
            r.push(&parts[0].0, parts[0].1.clone(), 1000).unwrap();
        }
        assert!(
            r.inflight() <= MAX_INFLIGHT,
            "tracking {} frames, over the limit of {MAX_INFLIGHT}",
            r.inflight()
        );
    }

    #[test]
    fn a_changed_fragment_count_is_rejected() {
        let mut r = Reassembler::new();
        let h1 = PacketHeader {
            frame_id: 1,
            fragment_index: 0,
            fragment_count: 4,
            flags: 0,
            sequence: 0,
        };
        let h2 = PacketHeader { fragment_count: 7, ..h1 };
        r.push(&h1, vec![0; 10], 1000).unwrap();
        assert!(r.push(&h2, vec![0; 10], 1000).is_err());
    }

    #[test]
    fn an_oversized_frame_is_refused() {
        let mut r = Reassembler::with_max_frame_bytes(1000);
        let h = PacketHeader {
            frame_id: 1,
            fragment_index: 0,
            fragment_count: 1,
            flags: 0,
            sequence: 0,
        };
        assert!(matches!(
            r.push(&h, vec![0u8; 2000], 1000),
            Err(WireError::TooLarge { .. })
        ));
    }

    #[test]
    fn reset_clears_everything() {
        let mut r = Reassembler::new();
        let f1 = make_frame(5, &vec![0x77; 2000], 2, false);
        r.push(&f1[0].0, f1[0].1.clone(), 1000).unwrap();
        assert_eq!(r.inflight(), 1);

        r.reset();
        assert_eq!(r.inflight(), 0);

        // And a frame with a lower id than before is accepted again, which is
        // what happens after a reconnection restarts the numbering.
        let f = make_frame(1, b"after reset", 1, true);
        let (frame, _) = r.push(&f[0].0, f[0].1.clone(), 2000).unwrap();
        assert!(frame.is_some(), "numbering should restart cleanly after a reset");
    }

    #[test]
    fn fragmentation_covers_the_payload_exactly() {
        for len in [1usize, 100, 1199, 1200, 1201, 65536, 1_000_000] {
            for max in [500usize, 1200] {
                let parts = fragment(len, max);
                assert!(!parts.is_empty(), "len={len} max={max}");
                let total: usize = parts.iter().map(|(_, l)| l).sum();
                assert_eq!(total, len, "len={len} max={max} did not cover the payload");
                for (_, l) in &parts {
                    assert!(*l <= max, "a fragment of {l} exceeds {max}");
                }
                // Contiguous, starting at zero.
                let mut expect = 0;
                for (off, l) in &parts {
                    assert_eq!(*off, expect);
                    expect += l;
                }
            }
        }
    }

    #[test]
    fn fragments_are_evenly_sized() {
        let parts = fragment(1000, 300);
        assert_eq!(parts.len(), 4);
        let lens: Vec<usize> = parts.iter().map(|(_, l)| *l).collect();
        let min = lens.iter().min().unwrap();
        let max = lens.iter().max().unwrap();
        assert!(max - min <= 1, "fragment sizes {lens:?} are uneven");
    }

    #[test]
    fn stamps_carry_the_remote_side_timings() {
        let s = meta().stamps(7);
        assert_eq!(s.frame_id, 7);
        assert_eq!(s.capture_begin, 1000);
        assert_eq!(s.encode_end, 3000);
        assert_eq!(s.input_echo, 900);
        // The controller-side fields are filled in later.
        assert_eq!(s.present, 0);
    }
}
