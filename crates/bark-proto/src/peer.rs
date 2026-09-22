//! Messages exchanged directly between two paired devices during a session.
//!
//! These travel on reliable QUIC streams inside the end-to-end encrypted
//! session, separate from the video datagrams. Each logical concern gets its own
//! stream so that a large file transfer cannot delay a keystroke, and a burst of
//! clipboard data cannot delay a frame — QUIC streams are independent, which is
//! the specific property that makes this work and that TCP cannot provide.

use crate::control::FailureReason;
use crate::video::Codec;
use bark_crypto::{handshake, PublicIdentity, Signature64};
use serde::{Deserialize, Serialize};

/// The first messages on a new peer connection: the session handshake.
///
/// They travel on the first stream the controller opens. **Nothing else is
/// read from or written to the connection until `Confirm` has been verified**
/// — the transport under these messages is encrypted but not yet
/// authenticated (see `bark_net::tls::TransportOnlyVerifier`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Setup {
    Hello {
        protocol: u16,
        nonce: [u8; 32],
        ephemeral: [u8; 32],
        identity: PublicIdentity,
    },
    Accept {
        nonce: [u8; 32],
        ephemeral: [u8; 32],
        identity: PublicIdentity,
        signature: Signature64,
    },
    Confirm {
        signature: Signature64,
    },
    /// The remote will not open a session. Sent instead of `Accept`, so the
    /// controller can show why rather than "connection lost".
    Refused {
        reason: FailureReason,
        detail: String,
    },
}

impl From<handshake::Hello> for Setup {
    fn from(h: handshake::Hello) -> Self {
        Setup::Hello { protocol: h.protocol, nonce: h.nonce, ephemeral: h.ephemeral, identity: h.identity }
    }
}

impl From<handshake::Accept> for Setup {
    fn from(a: handshake::Accept) -> Self {
        Setup::Accept {
            nonce: a.nonce,
            ephemeral: a.ephemeral,
            identity: a.identity,
            signature: a.signature.into(),
        }
    }
}

impl From<handshake::Confirm> for Setup {
    fn from(c: handshake::Confirm) -> Self {
        Setup::Confirm { signature: c.signature.into() }
    }
}

impl Setup {
    pub fn into_hello(self) -> Option<handshake::Hello> {
        match self {
            Setup::Hello { protocol, nonce, ephemeral, identity } => {
                Some(handshake::Hello { protocol, nonce, ephemeral, identity })
            }
            _ => None,
        }
    }

    pub fn into_accept(self) -> Option<handshake::Accept> {
        match self {
            Setup::Accept { nonce, ephemeral, identity, signature } => {
                Some(handshake::Accept { nonce, ephemeral, identity, signature: signature.0 })
            }
            _ => None,
        }
    }

    pub fn into_confirm(self) -> Option<handshake::Confirm> {
        match self {
            Setup::Confirm { signature } => Some(handshake::Confirm { signature: signature.0 }),
            _ => None,
        }
    }
}

/// Stream identifiers, used as the first byte of each opened stream so the
/// receiver knows what it is.
pub mod stream {
    /// Session negotiation, actions, quality feedback. Opened first.
    pub const CONTROL: u8 = 1;
    /// Input events. Highest priority; never blocked behind anything else.
    pub const INPUT: u8 = 2;
    /// Clipboard contents.
    pub const CLIPBOARD: u8 = 3;
    /// File transfer data and control.
    pub const FILES: u8 = 4;
}

/// One display on the remote machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub index: u8,
    /// Friendly name where Windows provides one, otherwise "Display 1".
    pub name: String,
    pub width: u16,
    pub height: u16,
    /// Position in the virtual desktop, which can be negative for a monitor
    /// placed left of or above the primary one.
    pub x: i32,
    pub y: i32,
    pub primary: bool,
    /// Refresh rate in hertz, used to choose a sensible capture rate.
    pub refresh_hz: u16,
    /// Windows display scaling, as a percentage. 100 means no scaling.
    pub scale_percent: u16,
}

/// What a device can do. Exchanged at session start so neither side has to
/// guess, and so a newer BARK can talk to an older one without breaking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    pub codecs: Vec<Codec>,
    pub max_width: u16,
    pub max_height: u16,
    /// Hardware encoder present. Absence is not fatal but is worth telling the
    /// operator about, because it is the usual cause of a high encode time.
    pub hardware_encode: bool,
    pub hardware_decode: bool,
    pub clipboard: bool,
    pub file_transfer: bool,
    pub input_blocking: bool,
    pub privacy_screen: bool,
    /// The remote can capture the Windows sign-in and UAC screens.
    pub secure_desktop: bool,
    pub audio: bool,
}

/// Administrative actions available from the session toolbar.
///
/// Only actions with a documented, supported Windows mechanism are listed.
/// Anything requiring a trick or an undocumented call is deliberately absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    /// Ctrl+Alt+Delete, via the Secure Attention Sequence.
    SecureAttention,
    LockWorkstation,
    SignOut,
    Restart,
    Shutdown,
    OpenTaskManager,
    OpenRunDialog,
    OpenCommandPrompt,
    OpenPowerShell,
    /// Redraws the desktop; occasionally repairs a stuck display driver.
    RefreshDesktop,
    /// Presses the Windows key on its own.
    SendWindowsKey,
}

impl Action {
    /// Whether the action needs an "are you sure" before being carried out.
    pub fn needs_confirmation(self) -> bool {
        matches!(self, Action::Restart | Action::Shutdown | Action::SignOut)
    }

    /// The text of that confirmation.
    pub fn confirmation_text(self) -> &'static str {
        match self {
            Action::Restart => {
                "Restart the remote computer?\n\nThe session will disconnect and reconnect \
                 automatically once the computer has started again."
            }
            Action::Shutdown => {
                "Shut down the remote computer?\n\nBARK will not be able to reconnect until \
                 someone turns the computer on again, unless Wake-on-LAN is available."
            }
            Action::SignOut => {
                "Sign the remote user out?\n\nAny unsaved work in their programs will be lost."
            }
            _ => "",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Action::SecureAttention => "Ctrl+Alt+Delete",
            Action::LockWorkstation => "Lock Computer",
            Action::SignOut => "Sign Out",
            Action::Restart => "Restart",
            Action::Shutdown => "Shut Down",
            Action::OpenTaskManager => "Task Manager",
            Action::OpenRunDialog => "Run",
            Action::OpenCommandPrompt => "Command Prompt",
            Action::OpenPowerShell => "PowerShell",
            Action::RefreshDesktop => "Refresh Desktop",
            Action::SendWindowsKey => "Windows Key",
        }
    }
}

/// Why the controller asked for a keyframe. Recorded so the diagnostics can
/// distinguish "the network is dropping packets" from "the user switched
/// monitors", which look identical in a plain keyframe counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RefreshReason {
    /// First frame of the session.
    SessionStart,
    /// Frames were lost and the stream cannot repair itself.
    Loss,
    /// The decoder failed and had to be reset.
    DecoderReset,
    /// The viewer changed monitor, resolution or scaling.
    ViewChanged,
    /// The window was hidden and is being shown again.
    WindowRestored,
}

/// Live load figures from the remote, for the information panel.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RemoteStats {
    /// Whole-machine CPU use, 0-100.
    pub cpu_percent: f32,
    /// GPU use where the driver reports it, 0-100. Negative when unavailable,
    /// so the panel can say "n/a" rather than showing a misleading zero.
    pub gpu_percent: f32,
    /// Frames captured in the last second.
    pub capture_fps: u16,
    /// Frames encoded in the last second.
    pub encode_fps: u16,
    /// Frames the capture stage had to skip because encoding was behind.
    pub dropped_frames: u16,
    /// Current encoder output rate in kilobits per second.
    pub bitrate_kbps: u32,
    /// Encoder queue depth. Anything above one means the encoder is the
    /// bottleneck.
    pub encoder_queue: u8,
}

/// Controller to remote.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToRemote {
    /// Opens the session and states what the controller can handle.
    Start {
        capabilities: Capabilities,
        /// Preferred codec order, most preferred first.
        codec_preference: Vec<Codec>,
        /// Viewport size, so the remote can scale rather than sending pixels
        /// that will be thrown away.
        view_width: u16,
        view_height: u16,
        /// Upper bound the operator set, in kilobits per second. Zero means
        /// automatic.
        bitrate_limit_kbps: u32,
    },

    SelectMonitor { index: u8 },

    /// The controller's window changed size.
    ViewResized { width: u16, height: u16 },

    /// Asks for a frame that does not depend on anything earlier.
    RequestKeyframe { reason: RefreshReason },

    /// Tells the encoder a specific frame never arrived, so it can stop
    /// referencing it. Far cheaper than a keyframe and the main reason BARK
    /// recovers from loss without a visible stutter.
    InvalidateReference { frame_id: u32 },

    /// Measured network conditions, feeding the remote's rate control.
    NetworkFeedback {
        /// Round-trip time in microseconds.
        rtt_us: u32,
        /// Fraction of packets lost, scaled by 10000 (so 125 means 1.25%).
        loss_per_10k: u16,
        /// Observed receive rate in kilobits per second.
        goodput_kbps: u32,
        /// Frames that failed to assemble in the last second.
        lost_frames: u16,
    },

    /// Blocks the physical keyboard and mouse on the remote machine.
    SetInputBlocked { blocked: bool },

    /// Blanks the remote's physical display.
    SetPrivacyScreen { enabled: bool },

    PerformAction { action: Action },

    /// Round-trip probe. The remote echoes it back unchanged.
    Ping { sent_us: u64 },

    /// Closes the session cleanly.
    Disconnect { reason: String },
}

/// Remote to controller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToController {
    /// The session is running.
    Ready {
        capabilities: Capabilities,
        monitors: Vec<MonitorInfo>,
        active_monitor: u8,
        codec: Codec,
        /// Name the remote goes by, for the title bar.
        device_name: String,
    },

    /// The session could not start.
    StartFailed { detail: String },

    /// Monitor layout changed — a display was plugged in, unplugged, or
    /// reconfigured. The controller refreshes its view.
    MonitorsChanged { monitors: Vec<MonitorInfo>, active_monitor: u8 },

    /// Cursor shape changed. The image is a 32-bit BGRA bitmap.
    ///
    /// Sent separately from the video so the controller can draw the pointer
    /// locally, at local speed. This is the single largest contributor to a
    /// session feeling responsive.
    CursorShape {
        width: u16,
        height: u16,
        hotspot_x: u16,
        hotspot_y: u16,
        /// BGRA, top row first.
        pixels: Vec<u8>,
        /// How to read the alpha byte. `false`: ordinary transparency.
        /// `true`: Windows "masked" semantics, needed for cursors that invert
        /// what is under them (the text I-beam): alpha 0xFF means "draw this
        /// colour", alpha 0 means "XOR this colour with the screen".
        xor: bool,
        /// The cursor is hidden entirely.
        hidden: bool,
    },

    Stats { stats: RemoteStats },

    /// Result of a `SetInputBlocked` or of the remote user cancelling it.
    InputBlockChanged {
        blocked: bool,
        /// True when the remote user released it with the emergency key.
        released_locally: bool,
    },

    /// Result of a `SetPrivacyScreen` request.
    PrivacyScreenChanged {
        enabled: bool,
        released_locally: bool,
        /// Set when privacy mode could not be applied, explaining why in terms
        /// the operator can act on.
        unavailable_reason: Option<String>,
    },

    ActionResult { action: Action, ok: bool, detail: String },

    /// The remote switched to a desktop that cannot be captured — the sign-in
    /// screen or a UAC prompt on a machine where policy forbids it. Sent so the
    /// controller can explain the black screen instead of looking broken.
    CaptureInterrupted { detail: String },

    CaptureResumed,

    Pong { sent_us: u64, remote_time_us: u64 },

    Disconnect { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_framed, encode_framed};

    fn caps() -> Capabilities {
        Capabilities {
            codecs: vec![Codec::H265, Codec::H264],
            max_width: 3840,
            max_height: 2160,
            hardware_encode: true,
            hardware_decode: true,
            clipboard: true,
            file_transfer: true,
            input_blocking: true,
            privacy_screen: true,
            secure_desktop: true,
            audio: false,
        }
    }

    #[test]
    fn a_whole_handshake_survives_the_wire() {
        let controller = bark_crypto::DeviceIdentity::generate().unwrap();
        let remote = bark_crypto::DeviceIdentity::generate().unwrap();
        let ch = [9u8; 32];

        fn wire(s: Setup) -> Setup {
            let bytes = encode_framed(&s).unwrap();
            decode_framed::<Setup>(&bytes).unwrap().unwrap().0
        }

        let (init, hello) = handshake::Initiator::start(&controller, &ch).unwrap();
        let hello = wire(hello.into()).into_hello().expect("a hello");
        let (resp, accept) = handshake::Responder::accept(&remote, &hello, &ch, |_| Ok(())).unwrap();
        let accept = wire(accept.into()).into_accept().expect("an accept");
        let (ck, confirm) = init.finish(&controller, &accept, Some(&remote.public())).unwrap();
        let confirm = wire(confirm.into()).into_confirm().expect("a confirm");
        let rk = resp.finish(&confirm).unwrap();
        assert_eq!(ck.binding(), rk.binding());
    }

    #[test]
    fn destructive_actions_ask_first_and_harmless_ones_do_not() {
        assert!(Action::Restart.needs_confirmation());
        assert!(Action::Shutdown.needs_confirmation());
        assert!(Action::SignOut.needs_confirmation());

        assert!(!Action::LockWorkstation.needs_confirmation());
        assert!(!Action::SecureAttention.needs_confirmation());
        assert!(!Action::OpenTaskManager.needs_confirmation());
        assert!(!Action::RefreshDesktop.needs_confirmation());
    }

    #[test]
    fn every_confirmation_explains_the_consequence() {
        for a in [Action::Restart, Action::Shutdown, Action::SignOut] {
            let t = a.confirmation_text();
            assert!(t.len() > 40, "{a:?} confirmation is too thin: {t}");
            assert!(t.contains('?'), "{a:?} confirmation should ask a question");
        }
    }

    #[test]
    fn every_action_has_a_label() {
        for a in [
            Action::SecureAttention,
            Action::LockWorkstation,
            Action::SignOut,
            Action::Restart,
            Action::Shutdown,
            Action::OpenTaskManager,
            Action::OpenRunDialog,
            Action::OpenCommandPrompt,
            Action::OpenPowerShell,
            Action::RefreshDesktop,
            Action::SendWindowsKey,
        ] {
            assert!(!a.label().is_empty(), "{a:?} has no label");
        }
    }

    #[test]
    fn controller_messages_round_trip() {
        let msgs = vec![
            ToRemote::Start {
                capabilities: caps(),
                codec_preference: vec![Codec::H265, Codec::H264],
                view_width: 1920,
                view_height: 1080,
                bitrate_limit_kbps: 0,
            },
            ToRemote::SelectMonitor { index: 1 },
            ToRemote::RequestKeyframe { reason: RefreshReason::Loss },
            ToRemote::InvalidateReference { frame_id: 4242 },
            ToRemote::NetworkFeedback {
                rtt_us: 18_000,
                loss_per_10k: 125,
                goodput_kbps: 18_000,
                lost_frames: 2,
            },
            ToRemote::SetInputBlocked { blocked: true },
            ToRemote::SetPrivacyScreen { enabled: true },
            ToRemote::PerformAction { action: Action::SecureAttention },
            ToRemote::Disconnect { reason: "operator closed the window".into() },
        ];
        for m in msgs {
            let bytes = encode_framed(&m).unwrap();
            let (back, _): (ToRemote, usize) = decode_framed(&bytes).unwrap().unwrap();
            assert_eq!(format!("{back:?}"), format!("{m:?}"));
        }
    }

    #[test]
    fn remote_messages_round_trip() {
        let msgs = vec![
            ToController::Ready {
                capabilities: caps(),
                monitors: vec![MonitorInfo {
                    index: 0,
                    name: "Display 1".into(),
                    width: 1920,
                    height: 1080,
                    x: 0,
                    y: 0,
                    primary: true,
                    refresh_hz: 60,
                    scale_percent: 100,
                }],
                active_monitor: 0,
                codec: Codec::H265,
                device_name: "CENTRAL-SERVER".into(),
            },
            ToController::CursorShape {
                width: 32,
                height: 32,
                hotspot_x: 0,
                hotspot_y: 0,
                pixels: vec![0u8; 32 * 32 * 4],
                xor: false,
                hidden: false,
            },
            ToController::Stats {
                stats: RemoteStats {
                    cpu_percent: 18.5,
                    gpu_percent: 27.0,
                    capture_fps: 60,
                    encode_fps: 60,
                    dropped_frames: 0,
                    bitrate_kbps: 18_000,
                    encoder_queue: 1,
                },
            },
            ToController::CaptureInterrupted { detail: "secure desktop".into() },
        ];
        for m in msgs {
            let bytes = encode_framed(&m).unwrap();
            let (back, _): (ToController, usize) = decode_framed(&bytes).unwrap().unwrap();
            assert_eq!(format!("{back:?}"), format!("{m:?}"));
        }
    }

    #[test]
    fn a_monitor_left_of_the_primary_keeps_its_negative_position() {
        let m = MonitorInfo {
            index: 1,
            name: "Display 2".into(),
            width: 1920,
            height: 1080,
            x: -1920,
            y: -120,
            primary: false,
            refresh_hz: 144,
            scale_percent: 150,
        };
        let bytes = encode_framed(&m).unwrap();
        let (back, _): (MonitorInfo, usize) = decode_framed(&bytes).unwrap().unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn unavailable_gpu_use_is_distinguishable_from_zero() {
        let s = RemoteStats {
            cpu_percent: 5.0,
            gpu_percent: -1.0,
            capture_fps: 60,
            encode_fps: 60,
            dropped_frames: 0,
            bitrate_kbps: 1000,
            encoder_queue: 0,
        };
        assert!(s.gpu_percent < 0.0, "negative marks the value as unavailable");
        let bytes = encode_framed(&s).unwrap();
        let (back, _): (RemoteStats, usize) = decode_framed(&bytes).unwrap().unwrap();
        assert_eq!(back, s);
    }
}
