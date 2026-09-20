//! End-to-end session encryption.
//!
//! Everything a session carries — video, input, clipboard, files, control —
//! passes through this layer before it reaches the network. That matters most
//! for relayed sessions: the coordination server forwards these bytes and
//! cannot read or alter them, because it never sees the keys derived here.
//!
//! Cipher: **ChaCha20-Poly1305**. Chosen over AES-GCM because it is constant
//! time in software on every CPU, has no timing-attack caveats when AES-NI is
//! unavailable, and runs at well over a gigabyte a second — far beyond the
//! bitrate of a remote desktop stream, so encryption never becomes the
//! bottleneck the latency budget is fighting.
//!
//! Nonces are a per-direction counter, never random: a random 96-bit nonce has
//! a birthday collision risk that is small but not zero, and a counter has none
//! at all as long as it never repeats. It cannot repeat here because each
//! direction has its own key and its own counter, and the counter refuses to
//! wrap.

use bark_core::{BarkError, Result};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use zeroize::{Zeroize, Zeroizing};

/// Bytes the AEAD tag adds to every packet.
pub const TAG_LEN: usize = 16;

/// Which direction a key protects. Each direction has an independent key and
/// counter, so a packet can never be reflected back at its sender and accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Controller to remote.
    ControllerToRemote,
    /// Remote to controller.
    RemoteToController,
}

impl Direction {
    fn label(self) -> &'static [u8] {
        match self {
            Direction::ControllerToRemote => b"BARK-v1/c2r",
            Direction::RemoteToController => b"BARK-v1/r2c",
        }
    }

    pub fn opposite(self) -> Direction {
        match self {
            Direction::ControllerToRemote => Direction::RemoteToController,
            Direction::RemoteToController => Direction::ControllerToRemote,
        }
    }
}

/// One direction's sending half.
pub struct Sealer {
    cipher: ChaCha20Poly1305,
    counter: u64,
    nonce_prefix: [u8; 4],
}

impl std::fmt::Debug for Sealer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Sealer(counter={})", self.counter)
    }
}

impl Sealer {
    fn new(key: &[u8; 32], direction: Direction) -> Self {
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&direction.label()[direction.label().len() - 4..]);
        Sealer {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            counter: 0,
            nonce_prefix: prefix,
        }
    }

    /// The sequence number the next sealed packet will carry.
    pub fn next_sequence(&self) -> u64 {
        self.counter
    }

    /// Encrypts `buffer` in place and appends the authentication tag.
    ///
    /// `aad` is authenticated but not encrypted — used for the packet header,
    /// which the receiver must read before decrypting and which must therefore
    /// be tamper-evident rather than hidden.
    ///
    /// Returns the sequence number, which the caller puts in the header.
    pub fn seal_in_place(&mut self, aad: &[u8], buffer: &mut Vec<u8>) -> Result<u64> {
        let seq = self.counter;
        // Refuse to wrap rather than silently reusing a nonce, which would
        // destroy confidentiality for both messages sharing it. Reaching this
        // would take millions of years at any realistic packet rate; the check
        // exists because "impossible" and "unchecked" is how nonce reuse bugs
        // happen.
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or_else(|| BarkError::Crypto("session key exhausted; reconnect".into()))?;

        let nonce = make_nonce(&self.nonce_prefix, seq);
        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), aad, buffer)
            .map_err(|_| BarkError::Crypto("encryption failed".into()))?;
        buffer.extend_from_slice(&tag);
        Ok(seq)
    }

    /// Convenience form that allocates. Used on the control path, where the
    /// allocation is irrelevant; the media path uses `seal_in_place`.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<(u64, Vec<u8>)> {
        let mut buf = plaintext.to_vec();
        let seq = self.seal_in_place(aad, &mut buf)?;
        Ok((seq, buf))
    }
}

/// One direction's receiving half, including replay protection.
pub struct Opener {
    cipher: ChaCha20Poly1305,
    nonce_prefix: [u8; 4],
    window: ReplayWindow,
}

impl std::fmt::Debug for Opener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Opener(highest_seq={})", self.window.highest)
    }
}

impl Opener {
    fn new(key: &[u8; 32], direction: Direction) -> Self {
        let mut prefix = [0u8; 4];
        prefix.copy_from_slice(&direction.label()[direction.label().len() - 4..]);
        Opener {
            cipher: ChaCha20Poly1305::new(Key::from_slice(key)),
            nonce_prefix: prefix,
            window: ReplayWindow::new(),
        }
    }

    /// Decrypts in place, removing the tag, after checking the sequence number
    /// has not been seen before.
    ///
    /// The replay check happens **before** decryption so a flood of replayed
    /// packets costs a bitmap lookup rather than a full AEAD verification, and
    /// the window is only updated **after** the tag verifies so a forged
    /// sequence number cannot push the window forward and cause real packets to
    /// be discarded.
    pub fn open_in_place(&mut self, seq: u64, aad: &[u8], buffer: &mut Vec<u8>) -> Result<()> {
        if buffer.len() < TAG_LEN {
            return Err(BarkError::Crypto("packet is too short to be authentic".into()));
        }
        if !self.window.would_accept(seq) {
            return Err(BarkError::Crypto(format!(
                "replayed or too-old packet (sequence {seq})"
            )));
        }

        let tag_start = buffer.len() - TAG_LEN;
        let tag_bytes: [u8; TAG_LEN] = buffer[tag_start..]
            .try_into()
            .expect("length checked above");
        buffer.truncate(tag_start);

        let nonce = make_nonce(&self.nonce_prefix, seq);
        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&nonce),
                aad,
                buffer,
                Tag::from_slice(&tag_bytes),
            )
            .map_err(|_| {
                // Put the buffer back the way it was so the caller can retry or
                // log the raw packet without it being half-consumed.
                buffer.extend_from_slice(&tag_bytes);
                BarkError::Crypto(
                    "packet failed authentication; it was altered in transit or is not from this peer"
                        .into(),
                )
            })?;

        self.window.accept(seq);
        Ok(())
    }

    pub fn open(&mut self, seq: u64, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut buf = ciphertext.to_vec();
        self.open_in_place(seq, aad, &mut buf)?;
        Ok(buf)
    }

    pub fn highest_sequence(&self) -> u64 {
        self.window.highest
    }
}

fn make_nonce(prefix: &[u8; 4], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(prefix);
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Sliding window replay detector.
///
/// A reliable stream could simply require strictly increasing sequence numbers,
/// but video travels over unreliable datagrams and genuinely arrives out of
/// order. A fixed-size window accepts reordering up to its width and rejects
/// anything older, which is the standard approach used by IPsec and DTLS.
#[derive(Debug, Clone)]
pub struct ReplayWindow {
    highest: u64,
    /// Bit *i* set means `highest - i` has been seen. Bit 0 is `highest`.
    bitmap: u64,
    started: bool,
}

/// Width of the replay window, in packets. At 60 frames per second split across
/// several datagrams each, 64 packets is roughly a quarter of a second of
/// reordering tolerance — far more than any real network produces.
pub const REPLAY_WINDOW: u64 = 64;

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        ReplayWindow { highest: 0, bitmap: 0, started: false }
    }

    /// Whether this sequence number would be accepted, without recording it.
    pub fn would_accept(&self, seq: u64) -> bool {
        if !self.started {
            return true;
        }
        if seq > self.highest {
            return true;
        }
        let diff = self.highest - seq;
        if diff >= REPLAY_WINDOW {
            return false;
        }
        self.bitmap & (1u64 << diff) == 0
    }

    /// Records a sequence number as seen.
    pub fn accept(&mut self, seq: u64) {
        if !self.started {
            self.started = true;
            self.highest = seq;
            self.bitmap = 1;
            return;
        }
        if seq > self.highest {
            let shift = seq - self.highest;
            self.bitmap = if shift >= 64 { 0 } else { self.bitmap << shift };
            self.bitmap |= 1;
            self.highest = seq;
        } else {
            let diff = self.highest - seq;
            if diff < REPLAY_WINDOW {
                self.bitmap |= 1u64 << diff;
            }
        }
    }
}

/// The material both ends derive from the handshake.
pub struct SessionKeys {
    send: Zeroizing<[u8; 32]>,
    recv: Zeroizing<[u8; 32]>,
    send_direction: Direction,
    /// Binds this session to its handshake, so a packet from one session can
    /// never be accepted by another even if keys were somehow reused.
    session_binding: [u8; 32],
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SessionKeys(binding={}…)", hex::encode(&self.session_binding[..4]))
    }
}

impl SessionKeys {
    pub(crate) fn new(
        c2r: Zeroizing<[u8; 32]>,
        r2c: Zeroizing<[u8; 32]>,
        binding: [u8; 32],
        is_controller: bool,
    ) -> Self {
        if is_controller {
            SessionKeys {
                send: c2r,
                recv: r2c,
                send_direction: Direction::ControllerToRemote,
                session_binding: binding,
            }
        } else {
            SessionKeys {
                send: r2c,
                recv: c2r,
                send_direction: Direction::RemoteToController,
                session_binding: binding,
            }
        }
    }

    /// Consumes the keys into the two halves actually used to move data. The
    /// keys themselves are wiped as part of this.
    pub fn into_cipher(self) -> (Sealer, Opener) {
        let sealer = Sealer::new(&self.send, self.send_direction);
        let opener = Opener::new(&self.recv, self.send_direction.opposite());
        (sealer, opener)
    }

    /// A value both ends agree on, safe to show the operator so two people can
    /// confirm out of band that they are in the same session and no one is in
    /// the middle. Rendered as four groups of four, like a fingerprint.
    pub fn verification_words(&self) -> String {
        let h = hex::encode(&self.session_binding[..8]).to_uppercase();
        format!("{} {} {} {}", &h[0..4], &h[4..8], &h[8..12], &h[12..16])
    }

    pub fn binding(&self) -> &[u8; 32] {
        &self.session_binding
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.session_binding.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> (SessionKeys, SessionKeys) {
        let c2r = Zeroizing::new([7u8; 32]);
        let r2c = Zeroizing::new([9u8; 32]);
        let binding = [3u8; 32];
        (
            SessionKeys::new(c2r.clone(), r2c.clone(), binding, true),
            SessionKeys::new(c2r, r2c, binding, false),
        )
    }

    #[test]
    fn a_sealed_packet_opens_on_the_other_side() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let aad = b"header bytes";
        let (seq, packet) = sealer.seal(aad, b"mouse moved to 400,300").unwrap();
        let out = opener.open(seq, aad, &packet).unwrap();
        assert_eq!(out, b"mouse moved to 400,300");
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let (ck, _) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let secret = b"the quick brown fox jumps over the lazy dog";
        let (_, packet) = sealer.seal(b"", secret).unwrap();
        assert!(!packet.windows(secret.len()).any(|w| w == secret));
        assert_eq!(packet.len(), secret.len() + TAG_LEN);
    }

    #[test]
    fn a_modified_packet_is_rejected() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let (seq, mut packet) = sealer.seal(b"hdr", b"payload").unwrap();
        packet[0] ^= 0x01;
        assert!(opener.open(seq, b"hdr", &packet).is_err());
    }

    #[test]
    fn a_modified_header_is_rejected() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let (seq, packet) = sealer.seal(b"frame=7", b"payload").unwrap();
        assert!(
            opener.open(seq, b"frame=8", &packet).is_err(),
            "additional authenticated data must be covered by the tag"
        );
    }

    #[test]
    fn a_packet_cannot_be_reflected_back_at_its_sender() {
        let (ck, _rk) = keys();
        let (mut sealer, mut opener) = ck.into_cipher();
        let (seq, packet) = sealer.seal(b"", b"payload").unwrap();
        assert!(
            opener.open(seq, b"", &packet).is_err(),
            "each direction must use a different key"
        );
    }

    #[test]
    fn replays_are_rejected() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let (seq, packet) = sealer.seal(b"", b"click").unwrap();
        opener.open(seq, b"", &packet).expect("first delivery");
        assert!(
            opener.open(seq, b"", &packet).is_err(),
            "the same packet must not be accepted twice"
        );
    }

    #[test]
    fn out_of_order_delivery_inside_the_window_is_accepted() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let mut packets = Vec::new();
        for i in 0..10u8 {
            packets.push(sealer.seal(b"", &[i]).unwrap());
        }
        // Deliver 9, 8, ... 0 — fully reversed, which any real network beats.
        for (seq, p) in packets.iter().rev() {
            opener.open(*seq, b"", p).expect("reordered packets must be accepted");
        }
    }

    #[test]
    fn packets_older_than_the_window_are_dropped() {
        let mut w = ReplayWindow::new();
        w.accept(0);
        w.accept(1000);
        assert!(!w.would_accept(1000 - REPLAY_WINDOW), "exactly at the edge is too old");
        assert!(!w.would_accept(5), "far behind the window is too old");
        assert!(w.would_accept(1000 - REPLAY_WINDOW + 1), "inside the window is fine");
        assert!(w.would_accept(1001), "ahead of the window is fine");
    }

    #[test]
    fn a_forged_sequence_number_does_not_advance_the_window() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let (seq, packet) = sealer.seal(b"", b"real").unwrap();

        // An attacker replays the packet claiming a far-future sequence number.
        // It must fail authentication AND leave the window untouched, otherwise
        // every genuine packet afterwards would be rejected as too old.
        assert!(opener.open(seq + 1_000_000, b"", &packet).is_err());
        opener.open(seq, b"", &packet).expect("the genuine packet must still be accepted");
    }

    #[test]
    fn a_short_packet_is_rejected_without_panicking() {
        let (_, rk) = keys();
        let (_, mut opener) = rk.into_cipher();
        assert!(opener.open(0, b"", &[]).is_err());
        assert!(opener.open(0, b"", &[1, 2, 3]).is_err());
    }

    #[test]
    fn buffer_is_restored_when_authentication_fails() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();

        let (seq, packet) = sealer.seal(b"hdr", b"payload").unwrap();
        let mut buf = packet.clone();
        assert!(opener.open_in_place(seq, b"WRONG", &mut buf).is_err());
        assert_eq!(buf, packet, "the buffer should be left as it arrived");
    }

    #[test]
    fn sequence_numbers_increase_by_one() {
        let (ck, _) = keys();
        let (mut sealer, _) = ck.into_cipher();
        for expected in 0..5u64 {
            assert_eq!(sealer.next_sequence(), expected);
            let (seq, _) = sealer.seal(b"", b"x").unwrap();
            assert_eq!(seq, expected);
        }
    }

    #[test]
    fn both_ends_see_the_same_verification_words() {
        let (ck, rk) = keys();
        assert_eq!(ck.verification_words(), rk.verification_words());
        assert_eq!(ck.verification_words().len(), 19);
    }

    #[test]
    fn empty_payloads_are_handled() {
        let (ck, rk) = keys();
        let (mut sealer, _) = ck.into_cipher();
        let (_, mut opener) = rk.into_cipher();
        let (seq, packet) = sealer.seal(b"hdr", b"").unwrap();
        assert_eq!(packet.len(), TAG_LEN);
        assert_eq!(opener.open(seq, b"hdr", &packet).unwrap(), Vec::<u8>::new());
    }
}
