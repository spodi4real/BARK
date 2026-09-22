//! The controlled computer's side of a session: screen out, input in.
//!
//! Two threads per session, outside the async runtime because both call into
//! Windows in ways that block:
//!
//! * **media** — captures the screen, converts and encodes it, and sends each
//!   frame as datagrams the moment it is encoded.
//! * **input** — applies the controller's mouse and keyboard with
//!   `SendInput`, and records when the latest input was applied, which the
//!   next frame carries back so the controller can measure true
//!   input-to-photon latency.
//!
//! Frame pacing: at most 60 frames a second. When the screen changes faster
//! than that, the changes are merged into the next frame rather than queued;
//! a queue of stale frames is latency. When nothing changes, nothing is sent.

use bark_media::capture::{self, Captured};
use bark_media::convert::{Converter, Direction};
use bark_media::encode::{default_bitrate_kbps, EncoderSettings, H264Encoder};
use bark_media::{CursorShape, DesktopCapture};
use bark_proto::input::InputMessage;
use bark_proto::peer::MonitorInfo;
use bark_proto::video::{self, Codec, FrameMeta, PacketHeader, FLAG_KEYFRAME, FLAG_LAST_FRAGMENT};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use windows::Win32::Graphics::Direct3D11::{D3D11_BIND_FLAG, D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_NV12;

/// Frames per second at most.
const MAX_FPS: u32 = 60;

/// What the media thread reports to the session.
#[derive(Debug)]
pub enum MediaEvent {
    Started { monitors: Vec<MonitorInfo>, active: u8, encoder: String, hardware: bool },
    Cursor(CursorShape),
    /// The desktop cannot be captured right now (UAC prompt, lock screen...).
    Interrupted(String),
    Resumed,
    Failed(String),
}

#[derive(Debug)]
pub enum MediaCommand {
    Keyframe,
    SelectMonitor(u8),
}

/// Shared between the two threads: where the captured monitor is on the
/// desktop, and when input was last applied.
#[derive(Default)]
struct Shared {
    area: Mutex<Option<bark_input::ScreenArea>>,
    input_echo_us: AtomicU64,
    stop: AtomicBool,
}

pub struct HostMedia {
    shared: Arc<Shared>,
    commands: mpsc::Sender<MediaCommand>,
    media: Option<std::thread::JoinHandle<()>>,
    input_tx: Option<mpsc::Sender<InputMessage>>,
    input: Option<std::thread::JoinHandle<()>>,
}

impl HostMedia {
    /// Starts capturing monitor `monitor` and sending it over `conn`.
    /// `inject` false leaves input unapplied (see `run_host`).
    pub fn start(conn: quinn::Connection, monitor: u8, events: UnboundedSender<MediaEvent>, inject: bool) -> Self {
        let shared = Arc::new(Shared::default());
        let (commands, cmd_rx) = mpsc::channel();
        let media = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("bark-media".into())
                .spawn(move || media_thread(conn, monitor, cmd_rx, events, shared))
                .ok()
        };
        let (input_tx, input_rx) = mpsc::channel();
        let input = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("bark-input".into())
                .spawn(move || input_thread(input_rx, shared, inject))
                .ok()
        };
        HostMedia { shared, commands, media, input_tx: Some(input_tx), input }
    }

    pub fn command(&self, c: MediaCommand) {
        let _ = self.commands.send(c);
    }

    pub fn input(&self, m: InputMessage) {
        if let Some(tx) = &self.input_tx {
            let _ = tx.send(m);
        }
    }
}

impl Drop for HostMedia {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        // Closing the channel ends the input thread, which releases any keys
        // still held.
        self.input_tx.take();
        if let Some(t) = self.input.take() {
            let _ = t.join();
        }
        if let Some(t) = self.media.take() {
            let _ = t.join();
        }
    }
}

fn monitors() -> Vec<MonitorInfo> {
    capture::displays()
        .into_iter()
        .map(|d| MonitorInfo {
            index: d.index,
            name: d.device_name.trim_start_matches("\\\\.\\").to_string(),
            width: d.width() as u16,
            height: d.height() as u16,
            x: d.rect.left,
            y: d.rect.top,
            primary: d.primary,
            refresh_hz: 60,
            scale_percent: 100,
        })
        .collect()
}

fn media_thread(
    conn: quinn::Connection,
    mut monitor: u8,
    commands: mpsc::Receiver<MediaCommand>,
    events: UnboundedSender<MediaEvent>,
    shared: Arc<Shared>,
) {
    bark_media::gpu::raise_timer_resolution();
    let mut frame_id: u32 = 0;
    let mut sequence: u64 = 0;
    let mut interrupted = false;
    let mut started = false;

    'reopen: while !shared.stop.load(Ordering::Acquire) {
        let mut cap = match DesktopCapture::open(monitor) {
            Ok(c) => c,
            Err(e) => {
                // The lock screen or a UAC prompt: keep trying quietly.
                if !interrupted {
                    let _ = events.send(MediaEvent::Interrupted(format!(
                        "The remote screen cannot be captured right now. {}",
                        e.to_string().lines().next().unwrap_or_default()
                    )));
                    interrupted = true;
                }
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        let (w, h) = cap.size();
        let (ew, eh) = (w & !1, h & !1);
        let setup = (|| {
            let convert = Converter::new(&cap.gpu, Direction::RgbToYuv, (w, h), (ew, eh))?;
            let bind = D3D11_BIND_FLAG(D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0);
            let ring = [
                cap.gpu.texture(ew, eh, DXGI_FORMAT_NV12, bind)?,
                cap.gpu.texture(ew, eh, DXGI_FORMAT_NV12, bind)?,
                cap.gpu.texture(ew, eh, DXGI_FORMAT_NV12, bind)?,
            ];
            let settings =
                EncoderSettings { width: ew, height: eh, fps: MAX_FPS, bitrate_kbps: default_bitrate_kbps(ew, eh, MAX_FPS) };
            let encoder = H264Encoder::new(&cap.gpu, settings)?;
            Ok::<_, bark_core::BarkError>((convert, ring, encoder))
        })();
        let (convert, ring, mut encoder) = match setup {
            Ok(v) => v,
            Err(e) => {
                let _ = events.send(MediaEvent::Failed(format!("The remote computer could not start video: {e}")));
                return;
            }
        };

        *shared.area.lock().unwrap_or_else(|e| e.into_inner()) = Some(bark_input::ScreenArea {
            left: cap.display.rect.left,
            top: cap.display.rect.top,
            width: w as i32,
            height: h as i32,
        });
        if !started {
            let _ = events.send(MediaEvent::Started {
                monitors: monitors(),
                active: cap.display.index,
                encoder: encoder.name.clone(),
                hardware: encoder.hardware,
            });
            started = true;
        }
        if interrupted {
            let _ = events.send(MediaEvent::Resumed);
            interrupted = false;
        }
        tracing::info!(width = w, height = h, encoder = %encoder.name, "sending the screen");

        let interval = Duration::from_micros(1_000_000 / MAX_FPS as u64);
        let mut next_slot = Instant::now();
        let mut dirty = false;
        let mut force_key = true;
        let mut ring_index = 0usize;
        let mut capture_us = (0u64, 0u64);

        loop {
            if shared.stop.load(Ordering::Acquire) {
                return;
            }
            while let Ok(c) = commands.try_recv() {
                match c {
                    MediaCommand::Keyframe => force_key = true,
                    MediaCommand::SelectMonitor(m) if m != monitor => {
                        monitor = m;
                        continue 'reopen;
                    }
                    MediaCommand::SelectMonitor(_) => {}
                }
            }

            let wait_ms = if dirty || force_key {
                next_slot.saturating_duration_since(Instant::now()).as_millis() as u32
            } else {
                // Idle: wake regularly to notice commands and stopping.
                100
            };
            match cap.next(wait_ms) {
                Ok(Captured::Frame) => {
                    dirty = true;
                    let copied = bark_core::clock::now_us();
                    let shown = bark_core::clock::qpc_to_us(cap.present_qpc());
                    capture_us = (if shown > 0 && shown <= copied { shown } else { copied }, copied);
                }
                Ok(_) => {}
                Err(e) if capture::is_access_lost(&e) => continue 'reopen,
                Err(e) => {
                    tracing::warn!("capture failed, reopening: {e}");
                    std::thread::sleep(Duration::from_millis(100));
                    continue 'reopen;
                }
            }
            if let Some(shape) = cap.take_cursor_shape() {
                let _ = events.send(MediaEvent::Cursor(shape));
            }

            if !(dirty || force_key) || Instant::now() < next_slot || !cap.has_frame() {
                continue;
            }
            if capture_us.0 == 0 {
                let now = bark_core::clock::now_us();
                capture_us = (now, now);
            }
            let nv12 = &ring[ring_index];
            ring_index = (ring_index + 1) % ring.len();
            let slot_start = Instant::now();
            let encode_begin = bark_core::clock::now_us();
            let echo = shared.input_echo_us.load(Ordering::Acquire);
            let frames = match convert.run(cap.texture(), 0, nv12, None).and_then(|_| encoder.encode(nv12, force_key)) {
                Ok(f) => f,
                Err(e) => {
                    let _ = events.send(MediaEvent::Failed(format!("Video encoding failed on the remote computer: {e}")));
                    return;
                }
            };
            let encode_end = bark_core::clock::now_us();
            for f in frames {
                frame_id = frame_id.wrapping_add(1);
                let meta = FrameMeta {
                    width: ew as u16,
                    height: eh as u16,
                    codec_id: Codec::H264 as u8,
                    output_index: cap.display.index,
                    capture_begin_us: capture_us.0,
                    capture_end_us: capture_us.1,
                    encode_begin_us: encode_begin,
                    encode_end_us: encode_end,
                    send_us: bark_core::clock::now_us(),
                    input_echo_us: echo,
                };
                if !send_frame(&conn, frame_id, f.keyframe, &meta, &f.data, &mut sequence) {
                    return;
                }
            }
            dirty = false;
            force_key = false;
            capture_us = (0, 0);
            // Measured from when this frame's work began, not ended, so the
            // encode time does not stretch the frame interval.
            next_slot = slot_start + interval;
        }
    }
}

/// Splits a frame into datagrams and sends them. Returns false once the
/// connection is gone.
fn send_frame(conn: &quinn::Connection, frame_id: u32, keyframe: bool, meta: &FrameMeta, data: &[u8], sequence: &mut u64) -> bool {
    let mut payload = Vec::with_capacity(video::FRAME_META_LEN + data.len());
    meta.encode(&mut payload);
    payload.extend_from_slice(data);

    let Some(max) = conn.max_datagram_size() else { return false };
    let room = max.min(1400).saturating_sub(video::HEADER_LEN).max(200);
    let pieces = video::fragment(payload.len(), room);
    let count = pieces.len() as u16;
    for (i, (offset, len)) in pieces.into_iter().enumerate() {
        let mut flags = if keyframe { FLAG_KEYFRAME } else { 0 };
        if i + 1 == count as usize {
            flags |= FLAG_LAST_FRAGMENT;
        }
        let header = PacketHeader { frame_id, fragment_index: i as u16, fragment_count: count, flags, sequence: *sequence };
        *sequence += 1;
        let mut dgram = Vec::with_capacity(video::HEADER_LEN + len);
        header.encode(&mut dgram);
        dgram.extend_from_slice(&payload[offset..offset + len]);
        match conn.send_datagram(bytes::Bytes::from(dgram)) {
            Ok(()) => {}
            Err(quinn::SendDatagramError::ConnectionLost(_)) => return false,
            // Too large or not supported would be a bug; drop this frame.
            Err(e) => {
                tracing::debug!("a video datagram was not sent: {e}");
                return true;
            }
        }
    }
    true
}

fn input_thread(rx: mpsc::Receiver<InputMessage>, shared: Arc<Shared>, inject: bool) {
    let mut injector: Option<bark_input::Injector> = None;
    let mut warned = false;
    while let Ok(m) = rx.recv() {
        let area = *shared.area.lock().unwrap_or_else(|e| e.into_inner());
        let Some(area) = area else { continue };
        if !inject {
            if !warned {
                tracing::info!("input from a controller on this same computer is not applied (loopback test)");
                warned = true;
            }
            shared.input_echo_us.store(m.timestamp_us, Ordering::Release);
            continue;
        }
        let inj = injector.get_or_insert_with(|| bark_input::Injector::new(area));
        inj.set_area(area);
        if !inj.apply(&m.event) && !warned {
            if let Some(why) = &inj.last_failure {
                tracing::warn!("{why}");
            }
            warned = true;
        }
        shared.input_echo_us.store(m.timestamp_us, Ordering::Release);
    }
}
