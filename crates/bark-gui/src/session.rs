//! The remote session window.
//!
//! Menu bar, the remote screen, a status bar of measured figures. Each
//! session has a viewer thread that decodes frames and presents them straight
//! into the video area, so a frame never waits for this window's message
//! loop; the loop only handles input and the once-a-second figures.
//!
//! Input is sent the moment it arrives: no batching, no "input tick". The
//! pointer is drawn locally in the remote cursor's shape, so it moves at the
//! speed of this computer's own mouse however far away the remote is.

use crate::win::*;
use bark_node::viewer::{SessionStats, ViewerCommand, ViewerEvent, ViewerLink};
use bark_proto::input::{InputEvent, MouseButton};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

const FRAME_CLASS: PCWSTR = w!("BARK.Session");
const VIDEO_CLASS: PCWSTR = w!("BARK.SessionVideo");
const WM_SESSION_UI: u32 = WM_APP + 50;

const IDM_INFO: u16 = 3001;
const IDM_DISCONNECT: u16 = 3002;
const IDM_WINKEY: u16 = 3101;
const IDM_ALTTAB: u16 = 3102;
const IDM_CTRLESC: u16 = 3103;
const IDM_CAD: u16 = 3104;
const IDM_KEYFRAME: u16 = 3201;

/// What the viewer thread tells the window.
enum Ui {
    Ready { remote_name: String },
    FirstPicture,
    Stats(String, [String; 4]),
    Cursor { width: u16, height: u16, hotspot_x: u16, hotspot_y: u16, pixels: Vec<u8>, xor: bool, hidden: bool },
    Notice(String),
    Ended(String),
}

/// Where the picture is drawn inside the video area, and its real size.
#[derive(Default, Clone, Copy)]
struct Geometry {
    picture: RECT,
    remote: (u32, u32),
}

#[derive(Default)]
struct Shared {
    geometry: Mutex<Geometry>,
    closed: AtomicBool,
    have_picture: AtomicBool,
}

struct Session {
    video: HWND,
    status: HWND,
    commands: tokio_sender::Sender,
    shared: Arc<Shared>,
    cursor: Option<HCURSOR>,
    cursor_hidden: bool,
    name: String,
    path: String,
    remote_address: String,
    verification: String,
    connect_ms: u32,
    buttons_down: u32,
    last_pos: (i32, i32),
    ended: Option<String>,
    notice: String,
}

/// The command channel, wrapped so this module does not name tokio.
mod tokio_sender {
    use bark_node::viewer::ViewerCommand;
    #[derive(Clone)]
    pub struct Sender(pub(super) tokio::sync::mpsc::UnboundedSender<ViewerCommand>);
    impl Sender {
        pub fn send(&self, c: ViewerCommand) {
            let _ = self.0.send(c);
        }
    }
}

thread_local! {
    static SESSIONS: RefCell<HashMap<isize, Session>> = RefCell::new(HashMap::new());
}

fn key(h: HWND) -> isize {
    h.0 as isize
}

fn with_session<R>(frame: HWND, f: impl FnOnce(&mut Session) -> R) -> Option<R> {
    SESSIONS.with(|s| s.try_borrow_mut().ok().and_then(|mut m| m.get_mut(&key(frame)).map(f)))
}

fn now_us() -> u64 {
    bark_core::clock::now_us()
}

fn register() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let frame = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(frame_proc),
            hInstance: hinstance(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hIcon: crate::tray::app_icon(32),
            hbrBackground: HBRUSH((COLOR_BTNFACE.0 + 1) as usize as *mut _),
            lpszClassName: FRAME_CLASS,
            ..Default::default()
        };
        RegisterClassExW(&frame);
        let video = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_DBLCLKS,
            lpfnWndProc: Some(video_proc),
            hInstance: hinstance(),
            hCursor: HCURSOR::default(),
            hbrBackground: HBRUSH(GetStockObject(BLACK_BRUSH).0),
            lpszClassName: VIDEO_CLASS,
            ..Default::default()
        };
        RegisterClassExW(&video);
    });
}

fn build_menu() -> HMENU {
    unsafe {
        let bar = CreateMenu().unwrap_or_default();
        let add = |m: HMENU, id: u16, text: &str, enabled: bool| {
            let t = Wide::new(text);
            let flags = if enabled { MF_STRING } else { MF_STRING | MF_GRAYED };
            let _ = AppendMenuW(m, flags, id as usize, t.pcwstr());
        };
        let popup = |text: &str, m: HMENU| {
            let t = Wide::new(text);
            let _ = AppendMenuW(bar, MF_POPUP, m.0 as usize, t.pcwstr());
        };
        let session = CreatePopupMenu().unwrap_or_default();
        add(session, IDM_INFO, "Connection &Information...", true);
        add(session, IDM_KEYFRAME, "&Refresh Picture", true);
        let _ = AppendMenuW(session, MF_SEPARATOR, 0, PCWSTR::null());
        add(session, IDM_DISCONNECT, "&Disconnect", true);
        popup("&Session", session);

        let actions = CreatePopupMenu().unwrap_or_default();
        add(actions, IDM_WINKEY, "Send &Windows Key", true);
        add(actions, IDM_ALTTAB, "Send &Alt+Tab", true);
        add(actions, IDM_CTRLESC, "Send Ctrl+&Esc", true);
        let _ = AppendMenuW(actions, MF_SEPARATOR, 0, PCWSTR::null());
        add(actions, IDM_CAD, "Send Ctrl+Alt+&Del (needs BARK installed on the remote)", false);
        popup("&Actions", actions);
        bar
    }
}

/// Opens a window for a session the node has just established.
pub fn open(link: ViewerLink, name: String, path: String, remote_address: String, verification: String, connect_ms: u32) {
    register();
    unsafe {
        // Most of the screen, leaving room to see what is behind.
        let mut work = RECT::default();
        let _ = SystemParametersInfoW(SPI_GETWORKAREA, 0, Some(&mut work as *mut _ as *mut _), SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0));
        let (ww, wh) = (work.right - work.left, work.bottom - work.top);
        let (w, h) = (ww * 4 / 5, wh * 4 / 5);
        let title = Wide::new(&format!("{name} - BARK"));
        let Ok(frame) = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            FRAME_CLASS,
            title.pcwstr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            work.left + (ww - w) / 2,
            work.top + (wh - h) / 2,
            w,
            h,
            None,
            Some(build_menu()),
            Some(hinstance()),
            None,
        ) else {
            error_box(None, "BARK could not open the session window.");
            let _ = link.commands.send(ViewerCommand::Disconnect);
            return;
        };
        let video = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            VIDEO_CLASS,
            PCWSTR::null(),
            WS_CHILD | WS_VISIBLE | WS_TABSTOP,
            0,
            0,
            10,
            10,
            Some(frame),
            None,
            Some(hinstance()),
            None,
        )
        .unwrap_or_default();
        let status = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            STATUSCLASSNAMEW,
            PCWSTR::null(),
            WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | SBARS_SIZEGRIP),
            0,
            0,
            0,
            0,
            Some(frame),
            None,
            Some(hinstance()),
            None,
        )
        .unwrap_or_default();

        let shared = Arc::new(Shared::default());
        let commands = tokio_sender::Sender(link.commands.clone());
        SESSIONS.with(|s| {
            s.borrow_mut().insert(
                key(frame),
                Session {
                    video,
                    status,
                    commands: commands.clone(),
                    shared: shared.clone(),
                    cursor: None,
                    cursor_hidden: false,
                    name: name.clone(),
                    path: path.clone(),
                    remote_address: remote_address.clone(),
                    verification,
                    connect_ms,
                    buttons_down: 0,
                    last_pos: (0, 0),
                    ended: None,
                    notice: String::new(),
                },
            );
        });
        layout(frame);
        set_parts(frame, &[format!("{path}  {remote_address}"), "Waiting for the picture...".into(), String::new(), String::new(), String::new()]);
        let _ = ShowWindow(frame, SW_SHOW);
        let _ = SetFocus(Some(video));

        let frame_raw = key(frame);
        let video_raw = key(video);
        let ViewerLink { events, .. } = link;
        let _ = std::thread::Builder::new()
            .name("bark-viewer".into())
            .spawn(move || viewer_thread(events, commands, frame_raw, video_raw, shared));
    }
}

fn layout(frame: HWND) {
    let Some((video, status)) = with_session(frame, |s| (s.video, s.status)) else { return };
    unsafe {
        SendMessageW(status, WM_SIZE, None, None);
        let mut rc = RECT::default();
        let _ = GetClientRect(frame, &mut rc);
        let mut sr = RECT::default();
        let _ = GetWindowRect(status, &mut sr);
        let sh = sr.bottom - sr.top;
        let _ = MoveWindow(video, 0, 0, rc.right, (rc.bottom - sh).max(1), true);
        let dpi = windows::Win32::UI::HiDpi::GetDpiForWindow(frame).max(96);
        // Widths from the right: encoder, latency, rate, round trip; the
        // path takes what is left.
        let widths = [px(150, dpi), px(260, dpi), px(150, dpi), px(110, dpi)];
        let mut parts = [0i32; 5];
        let mut x = rc.right;
        parts[4] = -1;
        for (i, w) in widths.iter().enumerate() {
            x -= w;
            parts[3 - i] = x;
        }
        SendMessageW(status, SB_SETPARTS, Some(WPARAM(parts.len())), Some(LPARAM(parts.as_ptr() as isize)));
    }
}

fn set_parts(frame: HWND, texts: &[String; 5]) {
    let Some(status) = with_session(frame, |s| s.status) else { return };
    for (i, t) in texts.iter().enumerate() {
        let w = Wide::new(t);
        unsafe {
            SendMessageW(status, SB_SETTEXTW, Some(WPARAM(i)), Some(LPARAM(w.pcwstr().0 as isize)));
        }
    }
}

fn set_part(frame: HWND, i: usize, text: &str) {
    let Some(status) = with_session(frame, |s| s.status) else { return };
    let w = Wide::new(text);
    unsafe {
        SendMessageW(status, SB_SETTEXTW, Some(WPARAM(i)), Some(LPARAM(w.pcwstr().0 as isize)));
    }
}

// ------------------------------------------------------------ viewer thread

/// Figures the viewer measures itself, reported with the node's once a second.
#[derive(Default)]
struct Local {
    decode_us: Vec<u32>,
    input_to_frame_us: Vec<u32>,
    last_echo: u64,
    presented: u32,
}

fn median(v: &mut [u32]) -> Option<u32> {
    if v.is_empty() {
        return None;
    }
    v.sort_unstable();
    Some(v[v.len() / 2])
}

fn post(frame: isize, ui: Ui) {
    let b = Box::into_raw(Box::new(ui));
    unsafe {
        if PostMessageW(Some(HWND(frame as *mut _)), WM_SESSION_UI, WPARAM(0), LPARAM(b as isize)).is_err() {
            drop(Box::from_raw(b));
        }
    }
}

fn viewer_thread(
    events: std::sync::mpsc::Receiver<ViewerEvent>,
    commands: tokio_sender::Sender,
    frame: isize,
    video: isize,
    shared: Arc<Shared>,
) {
    use bark_media::{Gpu, H264Decoder, Presenter};
    let _ = bark_media::mf::init_thread();
    let gpu = match Gpu::new(None) {
        Ok(g) => g,
        Err(e) => {
            post(frame, Ui::Ended(format!("This computer could not start video decoding: {e}")));
            commands.send(ViewerCommand::Disconnect);
            return;
        }
    };
    let mut decoder: Option<H264Decoder> = None;
    let mut presenter: Option<Presenter> = None;
    let mut need_keyframe = true;
    let mut local = Local::default();
    let mut encoder_text = String::new();

    loop {
        let ev = match events.recv_timeout(std::time::Duration::from_millis(250)) {
            Ok(ev) => ev,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if shared.closed.load(Ordering::Acquire) {
                    return;
                }
                continue;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
        };
        match ev {
            ViewerEvent::Frame(f) => {
                if shared.closed.load(Ordering::Acquire) {
                    return;
                }
                if need_keyframe && !f.keyframe {
                    continue;
                }
                let t0 = now_us();
                if decoder.is_none() {
                    match H264Decoder::new(&gpu) {
                        Ok(d) => {
                            encoder_text = if d.hardware { "H.264, GPU decode".into() } else { "H.264, CPU decode".into() };
                            decoder = Some(d);
                        }
                        Err(e) => {
                            post(frame, Ui::Ended(format!("This computer could not start the video decoder: {e}")));
                            commands.send(ViewerCommand::Disconnect);
                            return;
                        }
                    }
                }
                let dec = decoder.as_mut().expect("just created");
                match dec.decode(&f.bitstream) {
                    Ok(Some(pic)) => {
                        need_keyframe = false;
                        if presenter.is_none() {
                            match Presenter::new(&gpu, HWND(video as *mut _)) {
                                Ok(p) => presenter = Some(p),
                                Err(e) => {
                                    post(frame, Ui::Ended(format!("This computer could not show video: {e}")));
                                    commands.send(ViewerCommand::Disconnect);
                                    return;
                                }
                            }
                        }
                        let p = presenter.as_mut().expect("just created");
                        if let Err(e) = p.present(&pic) {
                            tracing::debug!("present failed: {e}");
                        }
                        let now = now_us();
                        local.decode_us.push((now - t0) as u32);
                        local.presented += 1;
                        if let Ok(mut g) = shared.geometry.lock() {
                            *g = Geometry { picture: p.picture, remote: (f.meta.width as u32, f.meta.height as u32) };
                        }
                        if !shared.have_picture.swap(true, Ordering::AcqRel) {
                            post(frame, Ui::FirstPicture);
                        }
                        // The remote stamps each frame with the controller's
                        // own clock reading of the last input it applied,
                        // so this difference is true input-to-frame latency.
                        let echo = f.meta.input_echo_us;
                        if echo != 0 && echo != local.last_echo {
                            local.last_echo = echo;
                            let d = now.saturating_sub(echo);
                            if d < 2_000_000 {
                                local.input_to_frame_us.push(d as u32);
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::info!("decoder failed, asking for a keyframe: {e}");
                        decoder = None;
                        need_keyframe = true;
                        commands.send(ViewerCommand::RequestKeyframe(bark_proto::peer::RefreshReason::DecoderReset));
                    }
                }
            }
            ViewerEvent::Stats(s) => {
                let parts = stats_parts(&s, &mut local, &encoder_text);
                post(frame, Ui::Stats(format!("{}  {}", s.path, s.remote_address), parts));
            }
            ViewerEvent::Ready { remote_name, .. } => {
                if !remote_name.is_empty() {
                    post(frame, Ui::Ready { remote_name });
                }
            }
            ViewerEvent::Cursor { width, height, hotspot_x, hotspot_y, pixels, xor, hidden } => {
                post(frame, Ui::Cursor { width, height, hotspot_x, hotspot_y, pixels, xor, hidden });
            }
            ViewerEvent::Notice(t) => post(frame, Ui::Notice(t)),
            ViewerEvent::Ended { reason } => {
                post(frame, Ui::Ended(reason));
                return;
            }
        }
    }
}

fn ms(us: u32) -> String {
    format!("{:.1} ms", us as f64 / 1000.0)
}

fn stats_parts(s: &SessionStats, local: &mut Local, encoder: &str) -> [String; 4] {
    let rtt = format!("RTT {}", ms(s.rtt_us));
    let rate = format!("{:.0} fps  {:.1} Mbit/s", local.presented as f32, s.kbps as f32 / 1000.0);
    let decode = median(&mut local.decode_us);
    let input = median(&mut local.input_to_frame_us);
    let mut lat = format!("Remote {}", ms(s.remote_pipeline_us));
    if let Some(d) = decode {
        lat.push_str(&format!("  Decode {}", ms(d)));
    }
    if let Some(i) = input {
        lat.push_str(&format!("  Input→frame {}", ms(i)));
    }
    if s.frames_lost > 0 {
        lat.push_str(&format!("  Lost {}", s.frames_lost));
    }
    local.decode_us.clear();
    local.input_to_frame_us.clear();
    local.presented = 0;
    [rtt, rate, lat, encoder.to_string()]
}

// ------------------------------------------------------------- cursor shape

/// Builds a real Windows cursor from the remote pointer's pixels.
unsafe fn make_cursor(width: u16, height: u16, hx: u16, hy: u16, pixels: &[u8], xor: bool) -> Option<HCURSOR> {
    let (w, h) = (width as i32, height as i32);
    if w == 0 || h == 0 || pixels.len() < (w * h * 4) as usize {
        return None;
    }
    unsafe {
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let color = CreateDIBSection(None, &bmi, DIB_RGB_COLORS, &mut bits, None, 0).ok()?;
        let dst = std::slice::from_raw_parts_mut(bits as *mut u8, (w * h * 4) as usize);
        // Monochrome mask rows are padded to 16 bits.
        let stride = ((w + 15) / 16 * 2) as usize;
        let mut mask = vec![0u8; stride * h as usize];
        for y in 0..h as usize {
            for x in 0..w as usize {
                let i = (y * w as usize + x) * 4;
                let px = &pixels[i..i + 4];
                if xor {
                    // Masked: alpha 0xFF draws the colour (AND 0), alpha 0
                    // XORs it with the screen (AND 1).
                    dst[i..i + 3].copy_from_slice(&px[..3]);
                    dst[i + 3] = 0;
                    if px[3] == 0 {
                        mask[y * stride + x / 8] |= 0x80 >> (x % 8);
                    }
                } else {
                    dst[i..i + 4].copy_from_slice(px);
                }
            }
        }
        let mask_bmp = CreateBitmap(w, h, 1, 1, Some(mask.as_ptr() as *const _));
        let info = ICONINFO { fIcon: false.into(), xHotspot: hx as u32, yHotspot: hy as u32, hbmMask: mask_bmp, hbmColor: color };
        let icon = CreateIconIndirect(&info).ok();
        let _ = DeleteObject(color.into());
        let _ = DeleteObject(mask_bmp.into());
        icon.map(|i| HCURSOR(i.0))
    }
}

// ---------------------------------------------------------------- windows

fn send_input(frame: HWND, event: InputEvent) {
    if let Some(c) = with_session(frame, |s| s.commands.clone()) {
        c.send(ViewerCommand::Input { event, timestamp_us: now_us() });
    }
}

fn send_keys(frame: HWND, keys: &[(u16, bool)]) {
    for &(scan, ext) in keys {
        send_input(frame, InputEvent::Key { scancode: scan, down: true, extended: ext });
    }
    for &(scan, ext) in keys.iter().rev() {
        send_input(frame, InputEvent::Key { scancode: scan, down: false, extended: ext });
    }
}

fn show_info(frame: HWND) {
    let Some(text) = with_session(frame, |s| {
        format!(
            "Connected to:\t{}\nPath:\t\t{}\nRemote address:\t{}\nConnect time:\t{} ms\n\n\
             Verification words:\n{}\n\n\
             The remote computer shows the same words in the status bar of its BARK \
             window. If they match, nothing sits between the two computers.",
            s.name, s.path, s.remote_address, s.connect_ms, s.verification
        )
    }) else {
        return;
    };
    info_box(Some(frame), &text);
}

unsafe extern "system" fn frame_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_SIZE => {
                layout(hwnd);
                LRESULT(0)
            }
            WM_SETFOCUS => {
                if let Some(v) = with_session(hwnd, |s| s.video) {
                    let _ = SetFocus(Some(v));
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                match loword(wp.0) {
                    IDM_INFO => show_info(hwnd),
                    IDM_DISCONNECT => {
                        let _ = SendMessageW(hwnd, WM_CLOSE, None, None);
                    }
                    IDM_KEYFRAME => {
                        if let Some(c) = with_session(hwnd, |s| s.commands.clone()) {
                            c.send(ViewerCommand::RequestKeyframe(bark_proto::peer::RefreshReason::ViewChanged));
                        }
                    }
                    IDM_WINKEY => send_keys(hwnd, &[(0x5B, true)]),
                    IDM_ALTTAB => send_keys(hwnd, &[(0x38, false), (0x0F, false)]),
                    IDM_CTRLESC => send_keys(hwnd, &[(0x1D, false), (0x01, false)]),
                    _ => {}
                }
                LRESULT(0)
            }
            WM_SESSION_UI => {
                let ui = *Box::from_raw(lp.0 as *mut Ui);
                handle_ui(hwnd, ui);
                LRESULT(0)
            }
            WM_CLOSE => {
                if let Some((c, shared)) = with_session(hwnd, |s| (s.commands.clone(), s.shared.clone())) {
                    shared.closed.store(true, Ordering::Release);
                    c.send(ViewerCommand::Disconnect);
                }
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                if let Some(s) = SESSIONS.with(|m| m.borrow_mut().remove(&key(hwnd))) {
                    s.shared.closed.store(true, Ordering::Release);
                    if let Some(c) = s.cursor {
                        let _ = DestroyCursor(c);
                    }
                }
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

fn handle_ui(frame: HWND, ui: Ui) {
    match ui {
        Ui::Ready { remote_name } => {
            let path = with_session(frame, |s| {
                s.name = remote_name.clone();
                s.path.clone()
            })
            .unwrap_or_default();
            let t = Wide::new(&format!("{remote_name} - {path} - BARK"));
            unsafe {
                let _ = SetWindowTextW(frame, t.pcwstr());
            }
        }
        Ui::FirstPicture => {
            set_part(frame, 1, "");
        }
        Ui::Stats(path, parts) => {
            let (ended, notice) = with_session(frame, |s| (s.ended.clone(), s.notice.clone())).unwrap_or_default();
            if ended.is_some() {
                return;
            }
            set_part(frame, 0, &if notice.is_empty() { path } else { notice });
            for (i, p) in parts.iter().enumerate() {
                set_part(frame, i + 1, p);
            }
        }
        Ui::Cursor { width, height, hotspot_x, hotspot_y, pixels, xor, hidden } => {
            let c = if hidden { None } else { unsafe { make_cursor(width, height, hotspot_x, hotspot_y, &pixels, xor) } };
            with_session(frame, |s| {
                if let Some(old) = s.cursor.take() {
                    unsafe {
                        let _ = DestroyCursor(old);
                    }
                }
                s.cursor = c;
                s.cursor_hidden = hidden;
            });
            // Apply at once if the pointer is over the picture.
            unsafe {
                let mut pt = POINT::default();
                let _ = GetCursorPos(&mut pt);
                if let Some(v) = with_session(frame, |s| s.video) {
                    if WindowFromPoint(pt) == v {
                        SendMessageW(v, WM_SETCURSOR, Some(WPARAM(v.0 as usize)), Some(LPARAM(HTCLIENT as isize)));
                    }
                }
            }
        }
        Ui::Notice(t) => {
            with_session(frame, |s| s.notice = t.clone());
            if !t.is_empty() {
                set_part(frame, 0, &t);
            }
        }
        Ui::Ended(reason) => {
            let first = with_session(frame, |s| {
                let first = s.ended.is_none();
                s.ended = Some(reason.clone());
                first
            })
            .unwrap_or(false);
            if first {
                set_parts(frame, &["Session ended".into(), String::new(), String::new(), String::new(), String::new()]);
                let name = with_session(frame, |s| s.name.clone()).unwrap_or_default();
                let closed_by_us = reason.starts_with("Session closed");
                if !closed_by_us {
                    message_box(Some(frame), &format!("The session with {name} has ended.\n\n{reason}"), "BARK", MB_OK | MB_ICONINFORMATION);
                }
                unsafe {
                    let _ = DestroyWindow(frame);
                }
            }
        }
    }
}

fn frame_of(video: HWND) -> HWND {
    unsafe { GetParent(video).unwrap_or_default() }
}

/// Converts a point in the video area to remote pixels. Points on the black
/// bars clamp to the picture's edge.
fn to_remote(frame: HWND, x: i32, y: i32) -> Option<(i32, i32)> {
    let shared = with_session(frame, |s| s.shared.clone())?;
    let g = *shared.geometry.lock().ok()?;
    let pw = (g.picture.right - g.picture.left).max(1);
    let ph = (g.picture.bottom - g.picture.top).max(1);
    if g.remote.0 == 0 {
        return None;
    }
    let rx = ((x - g.picture.left) as i64 * g.remote.0 as i64 / pw as i64) as i32;
    let ry = ((y - g.picture.top) as i64 * g.remote.1 as i64 / ph as i64) as i32;
    Some((rx.clamp(0, g.remote.0 as i32 - 1), ry.clamp(0, g.remote.1 as i32 - 1)))
}

fn signed_lo(lp: LPARAM) -> i32 {
    (lp.0 & 0xFFFF) as i16 as i32
}
fn signed_hi(lp: LPARAM) -> i32 {
    ((lp.0 >> 16) & 0xFFFF) as i16 as i32
}

unsafe extern "system" fn video_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        let frame = frame_of(hwnd);
        let button = |b: MouseButton, down: bool| {
            let (x, y) = (signed_lo(lp), signed_hi(lp));
            if let Some((rx, ry)) = to_remote(frame, x, y) {
                with_session(frame, |s| {
                    s.last_pos = (rx, ry);
                    if down {
                        s.buttons_down += 1;
                    } else {
                        s.buttons_down = s.buttons_down.saturating_sub(1);
                    }
                });
                send_input(frame, InputEvent::MouseButton { button: b, down, x: rx, y: ry });
            }
            if down {
                SetCapture(hwnd);
                let _ = SetFocus(Some(hwnd));
            } else if with_session(frame, |s| s.buttons_down).unwrap_or(0) == 0 {
                let _ = ReleaseCapture();
            }
        };
        match msg {
            WM_MOUSEMOVE => {
                if let Some((rx, ry)) = to_remote(frame, signed_lo(lp), signed_hi(lp)) {
                    let changed = with_session(frame, |s| {
                        let c = s.last_pos != (rx, ry);
                        s.last_pos = (rx, ry);
                        c
                    })
                    .unwrap_or(false);
                    if changed {
                        send_input(frame, InputEvent::MouseMove { x: rx, y: ry });
                    }
                }
                LRESULT(0)
            }
            WM_LBUTTONDOWN | WM_LBUTTONDBLCLK => {
                button(MouseButton::Left, true);
                LRESULT(0)
            }
            WM_LBUTTONUP => {
                button(MouseButton::Left, false);
                LRESULT(0)
            }
            WM_RBUTTONDOWN | WM_RBUTTONDBLCLK => {
                button(MouseButton::Right, true);
                LRESULT(0)
            }
            WM_RBUTTONUP => {
                button(MouseButton::Right, false);
                LRESULT(0)
            }
            WM_MBUTTONDOWN | WM_MBUTTONDBLCLK => {
                button(MouseButton::Middle, true);
                LRESULT(0)
            }
            WM_MBUTTONUP => {
                button(MouseButton::Middle, false);
                LRESULT(0)
            }
            WM_XBUTTONDOWN | WM_XBUTTONDBLCLK | WM_XBUTTONUP => {
                let b = if hiword(wp.0) == 1 { MouseButton::X1 } else { MouseButton::X2 };
                button(b, msg != WM_XBUTTONUP);
                LRESULT(1)
            }
            WM_MOUSEWHEEL | WM_MOUSEHWHEEL => {
                let delta = hiword(wp.0) as i16 as i32;
                let (x, y) = with_session(frame, |s| s.last_pos).unwrap_or((0, 0));
                let (dv, dh) = if msg == WM_MOUSEWHEEL { (delta, 0) } else { (0, delta) };
                send_input(frame, InputEvent::MouseWheel { delta_v: dv, delta_h: dh, x, y });
                LRESULT(0)
            }
            WM_KEYDOWN | WM_SYSKEYDOWN | WM_KEYUP | WM_SYSKEYUP => {
                let scancode = ((lp.0 >> 16) & 0xFF) as u16;
                let extended = (lp.0 >> 24) & 1 != 0;
                let down = msg == WM_KEYDOWN || msg == WM_SYSKEYDOWN;
                if scancode != 0 {
                    send_input(frame, InputEvent::Key { scancode, down, extended });
                }
                // Swallowed, so Alt and F10 go to the remote instead of
                // opening this window's menu.
                LRESULT(0)
            }
            WM_CHAR | WM_SYSCHAR | WM_DEADCHAR | WM_SYSDEADCHAR => LRESULT(0),
            WM_KILLFOCUS => {
                // Nothing may stay held on the remote once we stop typing
                // into it.
                send_input(frame, InputEvent::ReleaseAll);
                with_session(frame, |s| s.buttons_down = 0);
                LRESULT(0)
            }
            WM_SETCURSOR => {
                if loword(lp.0 as usize) as u32 == HTCLIENT {
                    let (c, hidden) = with_session(frame, |s| (s.cursor, s.cursor_hidden)).unwrap_or((None, false));
                    if hidden {
                        SetCursor(None);
                    } else {
                        SetCursor(Some(c.unwrap_or_else(|| LoadCursorW(None, IDC_ARROW).unwrap_or_default())));
                    }
                    return LRESULT(1);
                }
                DefWindowProcW(hwnd, msg, wp, lp)
            }
            WM_ERASEBKGND => LRESULT(1),
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let have = with_session(frame, |s| s.shared.have_picture.load(Ordering::Acquire)).unwrap_or(false);
                if !have {
                    let mut rc = RECT::default();
                    let _ = GetClientRect(hwnd, &mut rc);
                    FillRect(hdc, &rc, HBRUSH(GetStockObject(BLACK_BRUSH).0));
                    SetBkMode(hdc, TRANSPARENT);
                    SetTextColor(hdc, COLORREF(0x00C0C0C0));
                    let mut text: Vec<u16> = "Waiting for the remote screen...".encode_utf16().collect();
                    DrawTextW(hdc, &mut text, &mut rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
                }
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_GETDLGCODE => LRESULT(DLGC_WANTALLKEYS as isize),
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// Whether `hwnd` belongs to a session window, so the main window's
/// keyboard shortcuts leave it alone.
pub fn is_session_window(hwnd: HWND) -> bool {
    let root = unsafe { GetAncestor(hwnd, GA_ROOT) };
    SESSIONS.with(|s| s.try_borrow().map(|m| m.contains_key(&key(root))).unwrap_or(false))
}
