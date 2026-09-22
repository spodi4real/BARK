//! Running sessions, once the connection is authenticated.
//!
//! Two drivers, one per side:
//!
//! * [`run_controller`] — on the computer doing the controlling. Asks the
//!   remote to start, turns video datagrams back into frames for the window,
//!   and sends the window's input.
//! * [`run_host`] — on the computer being controlled. Answers the controller,
//!   runs the screen pipeline and applies input.
//!
//! Control messages are read by a small dedicated task per session, because
//! reading a length-prefixed message is not safe to abandon half way, and the
//! drivers need to wait on several things at once.

use crate::host::{HostMedia, MediaCommand, MediaEvent};
use crate::viewer::{SessionEnd, SessionStats, ViewerCommand, ViewerEvent};
use bark_net::framing::{read_message, write_message};
use bark_net::peer::{close, PeerSession};
use bark_proto::input::InputMessage;
use bark_proto::peer::{stream, Capabilities, RefreshReason, ToController, ToRemote};
use bark_proto::video::{Codec, PacketHeader, Reassembler, CHANNEL_VIDEO};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// How a session's packets travel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    DirectLan,
    DirectInternet,
    Relayed,
}

impl PathKind {
    /// For the device list's Connection column.
    pub fn word(self) -> &'static str {
        match self {
            PathKind::DirectLan | PathKind::DirectInternet => "DIRECT",
            PathKind::Relayed => "RELAYED",
        }
    }

    /// For the session window and diagnostics.
    pub fn describe(self) -> &'static str {
        match self {
            PathKind::DirectLan => "DIRECT (LAN)",
            PathKind::DirectInternet => "DIRECT (internet)",
            PathKind::Relayed => "RELAYED",
        }
    }
}

/// An authenticated connection, with how it was reached.
pub struct Established {
    pub session: PeerSession,
    pub path: PathKind,
    /// A relayed session has its own socket, owned by this endpoint; it must
    /// live as long as the connection.
    pub endpoint: Option<quinn::Endpoint>,
}

impl Established {
    pub fn remote_address(&self) -> SocketAddr {
        self.session.conn.remote_address()
    }
}

/// Classifies a direct path by the address it reached. Private address
/// ranges mean the two computers found each other on a local network.
pub fn classify_direct(addr: SocketAddr) -> PathKind {
    let lan = match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    };
    if lan {
        PathKind::DirectLan
    } else {
        PathKind::DirectInternet
    }
}

/// What this build can receive. Filled in honestly: nothing is claimed that
/// the viewer cannot actually do.
fn controller_capabilities() -> Capabilities {
    Capabilities {
        codecs: vec![Codec::H264],
        max_width: 7680,
        max_height: 4320,
        hardware_encode: false,
        hardware_decode: true,
        clipboard: false,
        file_transfer: false,
        input_blocking: false,
        privacy_screen: false,
        secure_desktop: false,
        audio: false,
    }
}

/// Reads control messages into a channel until the stream ends.
fn spawn_reader<T>(mut recv: quinn::RecvStream) -> mpsc::Receiver<bark_core::Result<T>>
where
    T: serde::de::DeserializeOwned + Send + 'static,
{
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(async move {
        loop {
            match read_message::<T>(&mut recv).await {
                Ok(Some(m)) => {
                    if tx.send(Ok(m)).await.is_err() {
                        return;
                    }
                }
                Ok(None) => return,
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    return;
                }
            }
        }
    });
    rx
}

/// Why a connection ended, in words for the operator.
fn close_words(conn: &quinn::Connection) -> String {
    match conn.close_reason() {
        Some(quinn::ConnectionError::TimedOut) => {
            "The connection to the remote computer was lost (no response for 30 seconds).".into()
        }
        Some(quinn::ConnectionError::ApplicationClosed(c)) if c.error_code == close::NORMAL.into() => {
            "The remote computer ended the session.".into()
        }
        Some(quinn::ConnectionError::ApplicationClosed(c)) => {
            format!("The remote computer closed the session ({}).", String::from_utf8_lossy(&c.reason))
        }
        Some(quinn::ConnectionError::LocallyClosed) => "The session was closed.".into(),
        Some(other) => format!("The connection to the remote computer was lost: {other}"),
        None => "The connection to the remote computer was lost.".into(),
    }
}

// ------------------------------------------------------------- controller

/// Runs the controlling side until the session ends. Returns why it ended.
pub(crate) async fn run_controller(est: Established, end: SessionEnd, view: (u16, u16)) -> String {
    let Established { session, path, endpoint: _endpoint } = est;
    let PeerSession { conn, mut control_send, control_recv, .. } = session;
    let SessionEnd { events, mut commands } = end;

    let start = ToRemote::Start {
        capabilities: controller_capabilities(),
        codec_preference: vec![Codec::H264],
        view_width: view.0,
        view_height: view.1,
        bitrate_limit_kbps: 0,
    };
    if let Err(e) = write_message(&mut control_send, &start).await {
        return format!("Could not start the session: {e}");
    }

    let mut control = spawn_reader::<ToController>(control_recv);
    let counters = Arc::new(VideoCounters::default());
    let (keyframe_tx, mut keyframe_rx) = mpsc::unbounded_channel::<RefreshReason>();
    let video = tokio::spawn(receive_video(conn.clone(), events.clone(), counters.clone(), keyframe_tx));

    let mut input: Option<quinn::SendStream> = None;
    let mut input_seq: u32 = 0;
    let mut input_buf = Vec::with_capacity(bark_proto::input::MAX_ENCODED + 1);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last = (0u64, 0u64, 0u64, std::time::Instant::now());

    let reason = loop {
        tokio::select! {
            msg = control.recv() => match msg {
                Some(Ok(ToController::Ready { monitors, active_monitor, device_name, .. })) => {
                    let _ = events.send(ViewerEvent::Ready { remote_name: device_name, monitors, active_monitor });
                }
                Some(Ok(ToController::StartFailed { detail })) => break detail,
                Some(Ok(ToController::MonitorsChanged { monitors, active_monitor })) => {
                    let _ = events.send(ViewerEvent::Ready { remote_name: String::new(), monitors, active_monitor });
                }
                Some(Ok(ToController::CursorShape { width, height, hotspot_x, hotspot_y, pixels, xor, hidden })) => {
                    let _ = events.send(ViewerEvent::Cursor { width, height, hotspot_x, hotspot_y, pixels, xor, hidden });
                }
                Some(Ok(ToController::CaptureInterrupted { detail })) => {
                    let _ = events.send(ViewerEvent::Notice(detail));
                }
                Some(Ok(ToController::CaptureResumed)) => {
                    let _ = events.send(ViewerEvent::Notice(String::new()));
                }
                Some(Ok(ToController::Disconnect { reason })) => break reason,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break close_words(&conn),
            },

            Some(reason) = keyframe_rx.recv() => {
                let _ = write_message(&mut control_send, &ToRemote::RequestKeyframe { reason }).await;
            }

            cmd = commands.recv() => match cmd {
                Some(ViewerCommand::Input { event, timestamp_us }) => {
                    if input.is_none() {
                        match conn.open_uni().await {
                            Ok(mut s) => {
                                // Input must never wait behind anything else.
                                let _ = s.set_priority(10);
                                if s.write_all(&[stream::INPUT]).await.is_ok() {
                                    input = Some(s);
                                }
                            }
                            Err(_) => break close_words(&conn),
                        }
                    }
                    if let Some(s) = input.as_mut() {
                        input_seq = input_seq.wrapping_add(1);
                        input_buf.clear();
                        input_buf.push(0); // length, filled in below
                        InputMessage { sequence: input_seq, timestamp_us, event }.encode(&mut input_buf);
                        input_buf[0] = (input_buf.len() - 1) as u8;
                        if s.write_all(&input_buf).await.is_err() {
                            break close_words(&conn);
                        }
                    }
                }
                Some(ViewerCommand::RequestKeyframe(reason)) => {
                    let _ = write_message(&mut control_send, &ToRemote::RequestKeyframe { reason }).await;
                }
                Some(ViewerCommand::SelectMonitor(index)) => {
                    let _ = write_message(&mut control_send, &ToRemote::SelectMonitor { index }).await;
                }
                Some(ViewerCommand::Action(action)) => {
                    let _ = write_message(&mut control_send, &ToRemote::PerformAction { action }).await;
                }
                Some(ViewerCommand::Disconnect) | None => {
                    let _ = write_message(
                        &mut control_send,
                        &ToRemote::Disconnect { reason: "The operator closed the session.".into() },
                    )
                    .await;
                    // Let the message arrive before the close overtakes it.
                    let _ = control_send.finish();
                    let _ = tokio::time::timeout(Duration::from_millis(300), control_send.stopped()).await;
                    break "Session closed.".to_string();
                }
            },

            _ = tick.tick() => {
                let frames = counters.frames.load(Ordering::Relaxed);
                let lost = counters.lost.load(Ordering::Relaxed);
                let bytes = counters.bytes.load(Ordering::Relaxed);
                let secs = last.3.elapsed().as_secs_f32().max(0.001);
                let stats = SessionStats {
                    path: path.describe().to_string(),
                    remote_address: conn.remote_address().to_string(),
                    rtt_us: conn.rtt().as_micros().min(u32::MAX as u128) as u32,
                    frames_received: frames,
                    frames_lost: lost,
                    fps: (frames - last.0) as f32 / secs,
                    kbps: (((bytes - last.2) * 8) as f32 / secs / 1000.0) as u32,
                    remote_pipeline_us: counters.pipeline_us.load(Ordering::Relaxed) as u32,
                };
                last = (frames, lost, bytes, std::time::Instant::now());
                let _ = events.send(ViewerEvent::Stats(stats));
            }
        }
    };

    video.abort();
    conn.close(close::NORMAL.into(), b"session ended");
    let _ = events.send(ViewerEvent::Ended { reason: reason.clone() });
    reason
}

#[derive(Default)]
struct VideoCounters {
    frames: AtomicU64,
    lost: AtomicU64,
    bytes: AtomicU64,
    pipeline_us: AtomicU64,
}

/// Turns video datagrams back into frames and hands each to the window the
/// moment it completes. Runs on its own task so a frame never waits for the
/// control messages.
async fn receive_video(
    conn: quinn::Connection,
    events: std::sync::mpsc::Sender<ViewerEvent>,
    counters: Arc<VideoCounters>,
    keyframes: mpsc::UnboundedSender<RefreshReason>,
) {
    let mut reassembler = Reassembler::new();
    let mut last_request: Option<std::time::Instant> = None;
    // Frames stuck half-received are noticed even when nothing else
    // arrives, which is exactly when a lost last packet would go unnoticed.
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        let lost = tokio::select! {
            dgram = conn.read_datagram() => {
                let Ok(dgram) = dgram else { return };
                if dgram.first() != Some(&CHANNEL_VIDEO) {
                    continue;
                }
                let Ok(header) = PacketHeader::decode(&dgram) else { continue };
                counters.bytes.fetch_add(dgram.len() as u64, Ordering::Relaxed);
                let payload = dgram[bark_proto::video::HEADER_LEN..].to_vec();
                let now = bark_core::clock::now_us();
                match reassembler.push(&header, payload, now) {
                    Ok((frame, losses)) => {
                        if let Some(f) = frame {
                            counters.frames.fetch_add(1, Ordering::Relaxed);
                            counters
                                .pipeline_us
                                .store(f.meta.send_us.saturating_sub(f.meta.capture_begin_us), Ordering::Relaxed);
                            if events.send(ViewerEvent::Frame(f)).is_err() {
                                return;
                            }
                        }
                        losses.len()
                    }
                    Err(e) => {
                        tracing::debug!("discarded a malformed video fragment: {e}");
                        1
                    }
                }
            }
            _ = tick.tick() => reassembler.expire(bark_core::clock::now_us()).len(),
        };
        if lost > 0 {
            counters.lost.fetch_add(lost as u64, Ordering::Relaxed);
            // A lost frame breaks every frame after it until a keyframe.
            // Ask for one, but not more than five times a second.
            if last_request.is_none_or(|t| t.elapsed() > Duration::from_millis(200)) {
                let _ = keyframes.send(RefreshReason::Loss);
                last_request = Some(std::time::Instant::now());
            }
        }
    }
}

// ------------------------------------------------------------------- host

/// Commands for a host session from this computer's own user.
#[derive(Debug)]
pub enum HostCommand {
    /// The person at this computer ended the session.
    End,
}

/// Runs the controlled side until the session ends. Returns why it ended.
pub(crate) async fn run_host(
    est: Established,
    device_name: String,
    mut local: mpsc::UnboundedReceiver<HostCommand>,
) -> String {
    let Established { session, endpoint: _endpoint, .. } = est;
    let PeerSession { conn, mut control_send, control_recv, peer, .. } = session;
    let mut control = spawn_reader::<ToRemote>(control_recv);
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<InputMessage>();
    let inputs = tokio::spawn(accept_input_streams(conn.clone(), input_tx));
    let (media_tx, mut media_rx) = mpsc::unbounded_channel::<MediaEvent>();
    let mut media: Option<HostMedia> = None;
    // A controller on this very computer (a loopback test) would move the
    // mouse under its own window and chase it; its input is not applied.
    let inject = !conn.remote_address().ip().is_loopback() || std::env::var_os("BARK_INJECT_LOOPBACK").is_some();

    let reason = loop {
        tokio::select! {
            msg = control.recv() => match msg {
                Some(Ok(ToRemote::Start { .. })) => {
                    if media.is_none() {
                        media = Some(HostMedia::start(conn.clone(), 0, media_tx.clone(), inject));
                    }
                }
                Some(Ok(ToRemote::RequestKeyframe { .. })) => {
                    if let Some(m) = &media {
                        m.command(MediaCommand::Keyframe);
                    }
                }
                Some(Ok(ToRemote::SelectMonitor { index })) => {
                    if let Some(m) = &media {
                        m.command(MediaCommand::SelectMonitor(index));
                    }
                }
                Some(Ok(ToRemote::Ping { sent_us })) => {
                    let pong = ToController::Pong { sent_us, remote_time_us: bark_core::clock::now_us() };
                    let _ = write_message(&mut control_send, &pong).await;
                }
                Some(Ok(ToRemote::Disconnect { reason })) => break reason,
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break close_words(&conn),
            },
            Some(ev) = media_rx.recv() => {
                let msg = match ev {
                    MediaEvent::Started { monitors, active, encoder, hardware } => {
                        tracing::info!(%encoder, hardware, "remote screen is being sent");
                        ToController::Ready {
                            capabilities: Capabilities {
                                codecs: vec![Codec::H264],
                                max_width: 7680,
                                max_height: 4320,
                                hardware_encode: hardware,
                                hardware_decode: true,
                                clipboard: false,
                                file_transfer: false,
                                input_blocking: false,
                                privacy_screen: false,
                                secure_desktop: false,
                                audio: false,
                            },
                            monitors,
                            active_monitor: active,
                            codec: Codec::H264,
                            device_name: device_name.clone(),
                        }
                    }
                    MediaEvent::Cursor(c) => ToController::CursorShape {
                        width: c.width,
                        height: c.height,
                        hotspot_x: c.hotspot_x,
                        hotspot_y: c.hotspot_y,
                        pixels: c.pixels,
                        xor: c.xor,
                        hidden: false,
                    },
                    MediaEvent::Interrupted(detail) => ToController::CaptureInterrupted { detail },
                    MediaEvent::Resumed => ToController::CaptureResumed,
                    MediaEvent::Failed(detail) => {
                        let _ = write_message(&mut control_send, &ToController::StartFailed { detail: detail.clone() }).await;
                        let _ = control_send.finish();
                        let _ = tokio::time::timeout(Duration::from_millis(300), control_send.stopped()).await;
                        break detail;
                    }
                };
                if write_message(&mut control_send, &msg).await.is_err() {
                    break close_words(&conn);
                }
            }

            Some(m) = input_rx.recv() => {
                if let Some(media) = &media {
                    media.input(m);
                }
            }

            cmd = local.recv() => match cmd {
                Some(HostCommand::End) | None => {
                    let _ = write_message(
                        &mut control_send,
                        &ToController::Disconnect { reason: "The person at the remote computer ended the session.".into() },
                    )
                    .await;
                    // Give the message a moment to leave before closing.
                    let _ = tokio::time::timeout(Duration::from_millis(300), control_send.stopped()).await;
                    break "You ended the session.".to_string();
                }
            },
        }
    };

    inputs.abort();
    conn.close(close::NORMAL.into(), b"session ended");
    // Stopping the capture and input threads can take a moment (a capture
    // wait in progress); not on the async runtime's threads.
    if let Some(m) = media.take() {
        let _ = tokio::task::spawn_blocking(move || drop(m)).await;
    }
    tracing::info!(peer = %peer.device_id(), "host session ended: {reason}");
    reason
}

/// Accepts the controller's one-way streams and dispatches them by their
/// first byte.
async fn accept_input_streams(conn: quinn::Connection, to: mpsc::UnboundedSender<InputMessage>) {
    while let Ok(mut s) = conn.accept_uni().await {
        let mut kind = [0u8; 1];
        if s.read_exact(&mut kind).await.is_err() {
            continue;
        }
        if kind[0] == stream::INPUT {
            tokio::spawn(read_input(s, to.clone()));
        }
    }
}

/// Reads length-prefixed input messages and passes each on immediately.
async fn read_input(mut s: quinn::RecvStream, to: mpsc::UnboundedSender<InputMessage>) {
    let mut len = [0u8; 1];
    let mut buf = [0u8; 64];
    let mut count: u64 = 0;
    loop {
        if s.read_exact(&mut len).await.is_err() {
            break;
        }
        let n = len[0] as usize;
        if n == 0 || n > buf.len() || s.read_exact(&mut buf[..n]).await.is_err() {
            break;
        }
        match InputMessage::decode(&buf[..n]) {
            Ok(m) => {
                count += 1;
                if to.send(m).is_err() {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("malformed input from the controller: {e}");
                break;
            }
        }
    }
    tracing::debug!(count, "input stream ended");
}
