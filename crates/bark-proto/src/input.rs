//! Input events, and their wire format.
//!
//! This is the most latency-sensitive data BARK carries. Design rules:
//!
//! * **Fixed-size, hand-encoded.** Every event is at most 16 bytes and encodes
//!   with no allocation and no serialiser. A mouse move should never touch the
//!   heap.
//! * **Never coalesced on the sender.** Merging two mouse moves into one saves
//!   a few bytes and costs a frame of responsiveness. BARK sends each event the
//!   moment it happens. Bandwidth is not the constraint here: 1000 events per
//!   second is 16 KB/s, a rounding error next to the video stream.
//! * **Timestamped at the source.** Each event carries the controller's
//!   monotonic clock reading, which the remote echoes back in the next frame.
//!   That echo is what makes true input-to-photon measurement possible.
//!
//! ## Pixels, not normalised coordinates
//!
//! Mouse positions are exact pixel coordinates in the captured output's own
//! space. Windows' `SendInput` wants a 0..65535 normalised value across the
//! virtual desktop, and converting to that on the controller would round twice
//! — once into the normalised space and once back out — which shows up as a
//! cursor that lands a pixel away from where it was aimed. The agent does the
//! single conversion instead, with the remote's real monitor geometry in hand.
//!
//! ## Scancodes, not virtual keys
//!
//! Keys travel as hardware scancodes. That means the *remote* machine's
//! keyboard layout decides what a key produces, which is what an administrator
//! wants: shortcuts land where they look like they should, and a key in the
//! same physical place does the same thing. Characters that the remote layout
//! cannot produce from a scancode are sent separately as [`InputEvent::Text`].

use crate::wire::{Cursor, WireError};

/// Mouse buttons BARK forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseButton {
    Left = 0,
    Right = 1,
    Middle = 2,
    /// Browser "back", the fourth button.
    X1 = 3,
    /// Browser "forward", the fifth button.
    X2 = 4,
}

impl MouseButton {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => MouseButton::Left,
            1 => MouseButton::Right,
            2 => MouseButton::Middle,
            3 => MouseButton::X1,
            4 => MouseButton::X2,
            _ => return None,
        })
    }
}

/// One input action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputEvent {
    /// Absolute pointer position, in pixels, in the captured output's space.
    MouseMove { x: i32, y: i32 },

    /// A button transition at a known position. Position travels with the
    /// button event so a click can never be applied at a stale location, which
    /// is what causes the "clicked the wrong thing" class of bug when a move
    /// and a click race each other.
    MouseButton { button: MouseButton, down: bool, x: i32, y: i32 },

    /// Wheel movement. Units are the same as Windows uses: 120 per detent.
    /// Sent as-is so high-resolution trackpads keep their smoothness rather
    /// than being quantised to whole detents.
    MouseWheel { delta_v: i32, delta_h: i32, x: i32, y: i32 },

    /// A key transition, by hardware scancode.
    Key { scancode: u16, down: bool, extended: bool },

    /// A character that could not be expressed as a scancode on the remote
    /// layout. Injected as a Unicode key event.
    Text { ch: char },

    /// Releases every key and button the remote believes is held.
    ///
    /// Sent when the session window loses focus. Without it, holding Alt and
    /// alt-tabbing away leaves Alt stuck down on the remote machine forever,
    /// which is a genuinely maddening bug to hit in the field.
    ReleaseAll,

    /// Secure Attention Sequence — Ctrl+Alt+Delete.
    ///
    /// Cannot be produced by injecting the three keys, because Windows reserves
    /// that combination. The agent raises it through the documented mechanism
    /// instead.
    SecureAttention,
}

impl InputEvent {
    fn tag(&self) -> u8 {
        match self {
            InputEvent::MouseMove { .. } => 1,
            InputEvent::MouseButton { .. } => 2,
            InputEvent::MouseWheel { .. } => 3,
            InputEvent::Key { .. } => 4,
            InputEvent::Text { .. } => 5,
            InputEvent::ReleaseAll => 6,
            InputEvent::SecureAttention => 7,
        }
    }
}

/// An input event plus the bookkeeping the far end needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputMessage {
    /// Monotonically increasing. Lets the remote spot a gap, and lets the
    /// controller correlate an echo with the event that produced it.
    pub sequence: u32,
    /// Controller's monotonic clock in microseconds when the event occurred —
    /// stamped as close to the hardware as possible, not when it was sent.
    pub timestamp_us: u64,
    pub event: InputEvent,
}

/// Largest an encoded [`InputMessage`] can be. Callers size stack buffers with
/// this so the encode path never allocates.
pub const MAX_ENCODED: usize = 1 + 4 + 8 + 13;

impl InputMessage {
    /// Appends the encoded form to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.event.tag());
        out.extend_from_slice(&self.sequence.to_le_bytes());
        out.extend_from_slice(&self.timestamp_us.to_le_bytes());
        match &self.event {
            InputEvent::MouseMove { x, y } => {
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            InputEvent::MouseButton { button, down, x, y } => {
                out.push(*button as u8);
                out.push(u8::from(*down));
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            InputEvent::MouseWheel { delta_v, delta_h, x, y } => {
                out.extend_from_slice(&(*delta_v as i16).to_le_bytes());
                out.extend_from_slice(&(*delta_h as i16).to_le_bytes());
                out.extend_from_slice(&x.to_le_bytes());
                out.extend_from_slice(&y.to_le_bytes());
            }
            InputEvent::Key { scancode, down, extended } => {
                out.extend_from_slice(&scancode.to_le_bytes());
                // Two booleans in one byte; this path runs for every keystroke.
                out.push(u8::from(*down) | (u8::from(*extended) << 1));
            }
            InputEvent::Text { ch } => {
                out.extend_from_slice(&(*ch as u32).to_le_bytes());
            }
            InputEvent::ReleaseAll | InputEvent::SecureAttention => {}
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut c = Cursor::new(buf);
        let tag = c.u8()?;
        let sequence = c.u32()?;
        let timestamp_us = c.u64()?;

        let event = match tag {
            1 => InputEvent::MouseMove { x: c.i32()?, y: c.i32()? },
            2 => {
                let button = MouseButton::from_u8(c.u8()?)
                    .ok_or(WireError::Invalid("unknown mouse button"))?;
                let down = c.u8()? != 0;
                InputEvent::MouseButton { button, down, x: c.i32()?, y: c.i32()? }
            }
            3 => {
                let delta_v = c.i16()? as i32;
                let delta_h = c.i16()? as i32;
                InputEvent::MouseWheel { delta_v, delta_h, x: c.i32()?, y: c.i32()? }
            }
            4 => {
                let scancode = c.u16()?;
                let bits = c.u8()?;
                InputEvent::Key {
                    scancode,
                    down: bits & 1 != 0,
                    extended: bits & 2 != 0,
                }
            }
            5 => {
                let v = c.u32()?;
                InputEvent::Text {
                    ch: char::from_u32(v).ok_or(WireError::Invalid("not a character"))?,
                }
            }
            6 => InputEvent::ReleaseAll,
            7 => InputEvent::SecureAttention,
            _ => return Err(WireError::Invalid("unknown input event")),
        };

        Ok(InputMessage { sequence, timestamp_us, event })
    }
}

/// Decodes a run of input messages packed back to back.
///
/// Several events often arrive in one network packet — a move and a button
/// press in the same millisecond, say — and they must all be applied, in order,
/// in the same pass.
pub fn decode_batch(mut buf: &[u8]) -> Result<Vec<InputMessage>, WireError> {
    let mut out = Vec::new();
    while !buf.is_empty() {
        let before = buf.len();
        let msg = InputMessage::decode(buf)?;
        let mut probe = Vec::with_capacity(MAX_ENCODED);
        msg.encode(&mut probe);
        if probe.len() > before {
            return Err(WireError::Truncated);
        }
        buf = &buf[probe.len()..];
        out.push(msg);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(event: InputEvent) {
        let msg = InputMessage { sequence: 42, timestamp_us: 1_234_567_890, event };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert!(
            buf.len() <= MAX_ENCODED,
            "{:?} encoded to {} bytes, over the {MAX_ENCODED} budget",
            msg.event,
            buf.len()
        );
        let back = InputMessage::decode(&buf).expect("decode");
        assert_eq!(back, msg);
    }

    #[test]
    fn every_event_type_round_trips() {
        roundtrip(InputEvent::MouseMove { x: 1920, y: 1080 });
        roundtrip(InputEvent::MouseMove { x: -1600, y: -200 });
        roundtrip(InputEvent::MouseButton {
            button: MouseButton::Left,
            down: true,
            x: 10,
            y: 20,
        });
        roundtrip(InputEvent::MouseButton {
            button: MouseButton::X2,
            down: false,
            x: 0,
            y: 0,
        });
        roundtrip(InputEvent::MouseWheel { delta_v: 120, delta_h: -120, x: 5, y: 6 });
        roundtrip(InputEvent::Key { scancode: 0x1C, down: true, extended: false });
        roundtrip(InputEvent::Key { scancode: 0x5B, down: false, extended: true });
        roundtrip(InputEvent::Text { ch: 'A' });
        roundtrip(InputEvent::Text { ch: 'م' });
        roundtrip(InputEvent::Text { ch: '𝄞' });
        roundtrip(InputEvent::ReleaseAll);
        roundtrip(InputEvent::SecureAttention);
    }

    #[test]
    fn negative_coordinates_survive() {
        // A monitor to the left of the primary one has negative coordinates.
        let msg = InputMessage {
            sequence: 1,
            timestamp_us: 0,
            event: InputEvent::MouseMove { x: -1920, y: -1080 },
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf);
        assert_eq!(InputMessage::decode(&buf).unwrap(), msg);
    }

    #[test]
    fn a_mouse_move_is_small() {
        let mut buf = Vec::new();
        InputMessage {
            sequence: 0,
            timestamp_us: 0,
            event: InputEvent::MouseMove { x: 1, y: 1 },
        }
        .encode(&mut buf);
        // 1 tag + 4 sequence + 8 timestamp + 8 coordinates.
        assert_eq!(buf.len(), 21);
    }

    #[test]
    fn a_key_event_is_small() {
        let mut buf = Vec::new();
        InputMessage {
            sequence: 0,
            timestamp_us: 0,
            event: InputEvent::Key { scancode: 30, down: true, extended: false },
        }
        .encode(&mut buf);
        assert_eq!(buf.len(), 16);
    }

    #[test]
    fn key_flags_do_not_bleed_into_each_other() {
        for down in [false, true] {
            for extended in [false, true] {
                let msg = InputMessage {
                    sequence: 7,
                    timestamp_us: 9,
                    event: InputEvent::Key { scancode: 0x2A, down, extended },
                };
                let mut buf = Vec::new();
                msg.encode(&mut buf);
                assert_eq!(InputMessage::decode(&buf).unwrap(), msg, "down={down} ext={extended}");
            }
        }
    }

    #[test]
    fn a_batch_decodes_in_order() {
        let events = vec![
            InputEvent::MouseMove { x: 1, y: 1 },
            InputEvent::MouseButton { button: MouseButton::Left, down: true, x: 1, y: 1 },
            InputEvent::MouseButton { button: MouseButton::Left, down: false, x: 1, y: 1 },
            InputEvent::Key { scancode: 30, down: true, extended: false },
        ];
        let mut buf = Vec::new();
        for (i, e) in events.iter().enumerate() {
            InputMessage {
                sequence: i as u32,
                timestamp_us: 1000 + i as u64,
                event: e.clone(),
            }
            .encode(&mut buf);
        }

        let decoded = decode_batch(&buf).expect("batch decode");
        assert_eq!(decoded.len(), events.len());
        for (i, (d, e)) in decoded.iter().zip(&events).enumerate() {
            assert_eq!(&d.event, e, "event {i} out of order or wrong");
            assert_eq!(d.sequence, i as u32);
        }
    }

    #[test]
    fn truncated_input_is_rejected_without_panicking() {
        let mut buf = Vec::new();
        InputMessage {
            sequence: 1,
            timestamp_us: 2,
            event: InputEvent::MouseMove { x: 3, y: 4 },
        }
        .encode(&mut buf);

        for n in 0..buf.len() {
            assert!(
                InputMessage::decode(&buf[..n]).is_err(),
                "a {n}-byte prefix should not decode"
            );
        }
    }

    #[test]
    fn unknown_tags_are_rejected() {
        let mut buf = vec![99u8];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        assert!(InputMessage::decode(&buf).is_err());
    }

    #[test]
    fn an_invalid_mouse_button_is_rejected() {
        let mut buf = vec![2u8];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(200); // not a button
        buf.push(1);
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        assert!(InputMessage::decode(&buf).is_err());
    }

    #[test]
    fn an_invalid_character_is_rejected() {
        let mut buf = vec![5u8];
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        // A surrogate code point is not a valid char.
        buf.extend_from_slice(&0xD800u32.to_le_bytes());
        assert!(InputMessage::decode(&buf).is_err());
    }

    #[test]
    fn a_batch_with_trailing_junk_is_rejected() {
        let mut buf = Vec::new();
        InputMessage {
            sequence: 0,
            timestamp_us: 0,
            event: InputEvent::ReleaseAll,
        }
        .encode(&mut buf);
        buf.push(0xAB);
        assert!(decode_batch(&buf).is_err());
    }

    #[test]
    fn high_resolution_wheel_deltas_survive() {
        for delta in [1i32, 7, 120, -120, 3000, -3000] {
            let msg = InputMessage {
                sequence: 0,
                timestamp_us: 0,
                event: InputEvent::MouseWheel { delta_v: delta, delta_h: 0, x: 0, y: 0 },
            };
            let mut buf = Vec::new();
            msg.encode(&mut buf);
            assert_eq!(InputMessage::decode(&buf).unwrap(), msg, "delta {delta}");
        }
    }
}
