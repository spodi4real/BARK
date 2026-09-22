//! BARK's dialog boxes.
//!
//! Built from in-memory Win32 dialog templates rather than drawn by hand. That
//! is how classic Windows utilities are made, and it brings the behaviour
//! people expect for free: Tab moves between fields, Enter presses the default
//! button, Esc cancels, and layout is in dialog units that scale with the font
//! and the screen's DPI.

use crate::app;
use crate::win::*;
use bark_node::api::{Command, DeviceView, NodeStatus, PairingCodeView, ServerLink};
use bark_node::config::{NodeConfig, ServerTarget};
use std::cell::RefCell;
use windows::Win32::Foundation::{HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::HFONT;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::WindowsAndMessaging::*;

// ------------------------------------------------------------ templates

const WS_POPUP_: u32 = 0x8000_0000;
const WS_CHILD_: u32 = 0x4000_0000;
const WS_VISIBLE_: u32 = 0x1000_0000;
const WS_CAPTION_: u32 = 0x00C0_0000;
const WS_SYSMENU_: u32 = 0x0008_0000;
const WS_TABSTOP_: u32 = 0x0001_0000;
const WS_GROUP_: u32 = 0x0002_0000;
const WS_VSCROLL_: u32 = 0x0020_0000;
const WS_EX_CLIENTEDGE_: u32 = 0x0000_0200;
const DS_SETFONT: u32 = 0x40;
const DS_MODALFRAME: u32 = 0x80;
const DS_CENTER: u32 = 0x0800;
const ES_AUTOHSCROLL: u32 = 0x80;
const ES_UPPERCASE: u32 = 0x08;
const ES_READONLY: u32 = 0x800;
const ES_MULTILINE: u32 = 0x04;
const ES_AUTOVSCROLL: u32 = 0x40;
const BS_DEFPUSHBUTTON: u32 = 0x01;
const BS_AUTOCHECKBOX: u32 = 0x03;
const BS_GROUPBOX: u32 = 0x07;
const SS_ETCHEDHORZ: u32 = 0x10;
const SS_NOPREFIX: u32 = 0x80;
const SS_RIGHT: u32 = 0x02;

const CLASS_BUTTON: u16 = 0x0080;
const CLASS_EDIT: u16 = 0x0081;
const CLASS_STATIC: u16 = 0x0082;

pub const IDOK_: i32 = 1;
pub const IDCANCEL_: i32 = 2;

/// Assembles a `DLGTEMPLATE` in memory.
struct Template {
    words: Vec<u16>,
    count_at: usize,
    count: u16,
}

impl Template {
    fn new(title: &str, w: i16, h: i16) -> Self {
        let mut t = Template { words: Vec::new(), count_at: 0, count: 0 };
        t.u32(WS_POPUP_ | WS_CAPTION_ | WS_SYSMENU_ | DS_MODALFRAME | DS_SETFONT | DS_CENTER);
        t.u32(0); // extended style
        t.count_at = t.words.len();
        t.words.push(0); // item count, patched in `finish`
        for v in [0i16, 0, w, h] {
            t.words.push(v as u16);
        }
        t.words.push(0); // no menu
        t.words.push(0); // default dialog class
        t.str(title);
        t.words.push(9); // point size
        t.str("Segoe UI");
        t
    }

    fn u32(&mut self, v: u32) {
        self.words.push((v & 0xffff) as u16);
        self.words.push((v >> 16) as u16);
    }

    fn str(&mut self, s: &str) {
        self.words.extend(s.encode_utf16());
        self.words.push(0);
    }

    #[allow(clippy::too_many_arguments)]
    fn item(mut self, class: u16, text: &str, id: i32, x: i16, y: i16, w: i16, h: i16, style: u32, ex: u32) -> Self {
        // Every item starts on a 4-byte boundary.
        if self.words.len() % 2 != 0 {
            self.words.push(0);
        }
        self.u32(style | WS_CHILD_ | WS_VISIBLE_);
        self.u32(ex);
        for v in [x, y, w, h] {
            self.words.push(v as u16);
        }
        self.words.push(id as u16);
        self.words.push(0xFFFF);
        self.words.push(class);
        self.str(text);
        self.words.push(0); // no creation data
        self.count += 1;
        self
    }

    fn label(self, text: &str, id: i32, x: i16, y: i16, w: i16, h: i16) -> Self {
        self.item(CLASS_STATIC, text, id, x, y, w, h, SS_NOPREFIX, 0)
    }

    fn label_right(self, text: &str, x: i16, y: i16, w: i16, h: i16) -> Self {
        self.item(CLASS_STATIC, text, -1, x, y, w, h, SS_NOPREFIX | SS_RIGHT, 0)
    }

    fn edit(self, id: i32, x: i16, y: i16, w: i16, h: i16, extra: u32) -> Self {
        self.item(CLASS_EDIT, "", id, x, y, w, h, WS_TABSTOP_ | ES_AUTOHSCROLL | extra, WS_EX_CLIENTEDGE_)
    }

    fn report(self, id: i32, x: i16, y: i16, w: i16, h: i16) -> Self {
        self.item(
            CLASS_EDIT,
            "",
            id,
            x,
            y,
            w,
            h,
            WS_TABSTOP_ | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | WS_VSCROLL_,
            WS_EX_CLIENTEDGE_,
        )
    }

    fn button(self, text: &str, id: i32, x: i16, y: i16, w: i16, default: bool) -> Self {
        let style = WS_TABSTOP_ | if default { BS_DEFPUSHBUTTON } else { 0 };
        self.item(CLASS_BUTTON, text, id, x, y, w, 14, style, 0)
    }

    fn check(self, text: &str, id: i32, x: i16, y: i16, w: i16) -> Self {
        self.item(CLASS_BUTTON, text, id, x, y, w, 10, WS_TABSTOP_ | BS_AUTOCHECKBOX, 0)
    }

    fn group(self, text: &str, x: i16, y: i16, w: i16, h: i16) -> Self {
        self.item(CLASS_BUTTON, text, -1, x, y, w, h, BS_GROUPBOX | WS_GROUP_, 0)
    }

    fn rule(self, x: i16, y: i16, w: i16) -> Self {
        self.item(CLASS_STATIC, "", -1, x, y, w, 1, SS_ETCHEDHORZ, 0)
    }

    /// Produces 4-byte aligned template memory.
    fn finish(mut self) -> Vec<u32> {
        self.words[self.count_at] = self.count;
        if self.words.len() % 2 != 0 {
            self.words.push(0);
        }
        self.words.chunks(2).map(|c| c[0] as u32 | ((c[1] as u32) << 16)).collect()
    }
}

// ------------------------------------------------------- modal machinery

/// What an open dialog is told by the main window when the node reports
/// something relevant to it.
#[derive(Debug, Clone)]
pub enum Mail {
    PairFinished { ok: bool, message: String },
    PairingCode(Option<PairingCodeView>),
    PairedBy(DeviceView),
}

pub const WM_DIALOG_MAIL: u32 = WM_APP + 20;

thread_local! {
    static MAILBOX: RefCell<Option<Mail>> = const { RefCell::new(None) };
}

/// Delivers mail to a dialog synchronously.
pub fn deliver(dialog: HWND, mail: Mail) {
    MAILBOX.with(|m| *m.borrow_mut() = Some(mail));
    unsafe {
        SendMessageW(dialog, WM_DIALOG_MAIL, None, None);
    }
}

fn take_mail() -> Option<Mail> {
    MAILBOX.with(|m| m.borrow_mut().take())
}

trait Dialog {
    fn init(&mut self, dlg: HWND);
    /// Returns true if the command was handled.
    fn command(&mut self, dlg: HWND, id: i32, notification: u16) -> bool;
    fn mail(&mut self, _dlg: HWND, _mail: Mail) {}
    fn timer(&mut self, _dlg: HWND) {}
    fn closing(&mut self, _dlg: HWND) {}
}

type Slot = RefCell<Box<dyn Dialog>>;

unsafe extern "system" fn dialog_proc(dlg: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> isize {
    unsafe {
        if msg == WM_INITDIALOG {
            SetWindowLongPtrW(dlg, GWLP_USERDATA, lp.0);
            let slot = &*(lp.0 as *const Slot);
            if let Ok(mut d) = slot.try_borrow_mut() {
                d.init(dlg);
            }
            return 1;
        }
        let ptr = GetWindowLongPtrW(dlg, GWLP_USERDATA) as *const Slot;
        if ptr.is_null() {
            return 0;
        }
        let slot = &*ptr;
        // A message that arrives while the dialog is already handling another
        // one (for example an edit-change notification caused by our own
        // SetWindowText) is simply not ours to handle twice.
        let Ok(mut d) = slot.try_borrow_mut() else { return 0 };
        match msg {
            WM_COMMAND => {
                let id = loword(wp.0) as i32;
                let code = hiword(wp.0);
                if d.command(dlg, id, code) {
                    return 1;
                }
                if id == IDCANCEL_ {
                    d.closing(dlg);
                    let _ = EndDialog(dlg, IDCANCEL_ as isize);
                    return 1;
                }
                0
            }
            WM_TIMER => {
                d.timer(dlg);
                1
            }
            WM_DIALOG_MAIL => {
                if let Some(m) = take_mail() {
                    d.mail(dlg, m);
                }
                1
            }
            _ => 0,
        }
    }
}

fn run(owner: HWND, template: Vec<u32>, dialog: Box<dyn Dialog>) -> isize {
    let slot: Slot = RefCell::new(dialog);
    unsafe {
        DialogBoxIndirectParamW(
            Some(hinstance()),
            template.as_ptr() as *const DLGTEMPLATE,
            Some(owner),
            Some(dialog_proc),
            LPARAM(&slot as *const Slot as isize),
        )
    }
}

fn end(dlg: HWND, code: i32) {
    unsafe {
        let _ = EndDialog(dlg, code as isize);
    }
}

// ------------------------------------------------------------ Add Device

const ID_ADD_DEVICE: i32 = 101;
const ID_ADD_CODE: i32 = 102;
const ID_ADD_NAME: i32 = 103;
const ID_ADD_STATUS: i32 = 104;

struct AddDevice {
    busy: bool,
}

impl Dialog for AddDevice {
    fn init(&mut self, dlg: HWND) {
        app::set_active_dialog(Some(dlg));
        unsafe {
            let _ = windows::Win32::UI::Input::KeyboardAndMouse::SetFocus(Some(dlg_item(dlg, ID_ADD_DEVICE)));
        }
    }

    fn command(&mut self, dlg: HWND, id: i32, _code: u16) -> bool {
        if id != IDOK_ || self.busy {
            return id == IDOK_;
        }
        let device_id = dlg_text(dlg, ID_ADD_DEVICE);
        let code = dlg_text(dlg, ID_ADD_CODE);
        let name = dlg_text(dlg, ID_ADD_NAME);
        if device_id.trim().is_empty() || code.trim().is_empty() {
            set_dlg_text(dlg, ID_ADD_STATUS, "Enter both the Device ID and the pairing code.");
            return true;
        }
        self.busy = true;
        for i in [ID_ADD_DEVICE, ID_ADD_CODE, ID_ADD_NAME, IDOK_] {
            enable(dlg_item(dlg, i), false);
        }
        set_dlg_text(dlg, ID_ADD_STATUS, "Pairing, please wait...");
        app::send_node(Command::Pair { device_id, code, name });
        true
    }

    fn mail(&mut self, dlg: HWND, mail: Mail) {
        if let Mail::PairFinished { ok, message } = mail {
            self.busy = false;
            if ok {
                info_box(Some(dlg), &message);
                app::set_active_dialog(None);
                end(dlg, IDOK_);
            } else {
                for i in [ID_ADD_DEVICE, ID_ADD_CODE, ID_ADD_NAME, IDOK_] {
                    enable(dlg_item(dlg, i), true);
                }
                set_dlg_text(dlg, ID_ADD_STATUS, "");
                error_box(Some(dlg), &format!("Pairing did not succeed.\n\n{message}"));
            }
        }
    }

    fn closing(&mut self, _dlg: HWND) {
        app::set_active_dialog(None);
    }
}

pub fn add_device(owner: HWND) {
    let t = Template::new("Add Device", 250, 130)
        .label(
            "Enter the Device ID and pairing code shown on the other computer.\n\
             On that computer choose Tools > Show Pairing Code.",
            -1, 7, 7, 236, 18,
        )
        .label_right("Device ID:", 7, 33, 58, 8)
        .edit(ID_ADD_DEVICE, 70, 31, 90, 13, ES_UPPERCASE)
        .label("e.g. BA-4K7P-2WQX", -1, 165, 33, 80, 8)
        .label_right("Pairing code:", 7, 50, 58, 8)
        .edit(ID_ADD_CODE, 70, 48, 55, 13, ES_UPPERCASE)
        .label_right("Name:", 7, 67, 58, 8)
        .edit(ID_ADD_NAME, 70, 65, 110, 13, 0)
        .label("(optional)", -1, 185, 67, 50, 8)
        .label("", ID_ADD_STATUS, 7, 86, 236, 10)
        .rule(7, 104, 236)
        .button("Pair", IDOK_, 139, 110, 50, true)
        .button("Cancel", IDCANCEL_, 193, 110, 50, false)
        .finish();
    run(owner, t, Box::new(AddDevice { busy: false }));
}

// ---------------------------------------------------------- Pairing code

const ID_CODE_ID: i32 = 201;
const ID_CODE_CODE: i32 = 202;
const ID_CODE_TIMER: i32 = 203;
const ID_CODE_RESULT: i32 = 205;

struct ShowCode {
    expires: Option<std::time::Instant>,
    large: Option<crate::win::Fonts>,
}

impl ShowCode {
    fn refresh_countdown(&self, dlg: HWND) {
        let text = match self.expires {
            Some(t) => {
                let left = t.saturating_duration_since(std::time::Instant::now()).as_secs();
                if left == 0 {
                    "This code has expired. Close this window and open it again for a new one.".to_string()
                } else {
                    format!("Valid for {}:{:02}. It can be used once.", left / 60, left % 60)
                }
            }
            None => String::new(),
        };
        set_dlg_text(dlg, ID_CODE_TIMER, &text);
    }
}

impl Dialog for ShowCode {
    fn init(&mut self, dlg: HWND) {
        app::set_active_dialog(Some(dlg));
        let fonts = crate::win::Fonts::for_dpi(unsafe { GetDpiForWindow(dlg) });
        set_font(dlg_item(dlg, ID_CODE_CODE), fonts.large);
        set_font(dlg_item(dlg, ID_CODE_ID), fonts.bold);
        self.large = Some(fonts);
        let id = app::status().map(|s| s.device_id).unwrap_or_default();
        set_dlg_text(dlg, ID_CODE_ID, &id);
        set_dlg_text(dlg, ID_CODE_CODE, "...");
        unsafe {
            SetTimer(Some(dlg), 1, 1000, None);
        }
        app::send_node(Command::ShowPairingCode);
    }

    fn command(&mut self, _dlg: HWND, id: i32, _code: u16) -> bool {
        id == IDOK_
    }

    fn mail(&mut self, dlg: HWND, mail: Mail) {
        match mail {
            Mail::PairingCode(Some(c)) => {
                set_dlg_text(dlg, ID_CODE_CODE, &c.code);
                self.expires = Some(std::time::Instant::now() + std::time::Duration::from_secs(c.seconds_left));
                self.refresh_countdown(dlg);
            }
            Mail::PairingCode(None) => {
                if self.expires.is_some() {
                    set_dlg_text(dlg, ID_CODE_CODE, "------");
                    self.expires = None;
                    self.refresh_countdown(dlg);
                }
            }
            Mail::PairedBy(d) => {
                set_dlg_text(
                    dlg,
                    ID_CODE_RESULT,
                    &format!("{} ({}) has paired with this computer.", d.name, d.device_id),
                );
            }
            _ => {}
        }
    }

    fn timer(&mut self, dlg: HWND) {
        self.refresh_countdown(dlg);
    }

    fn closing(&mut self, dlg: HWND) {
        unsafe {
            let _ = KillTimer(Some(dlg), 1);
        }
        app::send_node(Command::HidePairingCode);
        app::set_active_dialog(None);
        if let Some(f) = self.large.take() {
            f.destroy();
        }
    }
}

pub fn show_pairing_code(owner: HWND) {
    let t = Template::new("Pairing Code", 236, 150)
        .label("Another computer can pair with this one by entering:", -1, 7, 7, 222, 8)
        .label_right("Device ID:", 7, 24, 52, 8)
        .label("", ID_CODE_ID, 64, 24, 160, 10)
        .label_right("Pairing code:", 7, 44, 52, 8)
        .label("", ID_CODE_CODE, 64, 38, 160, 20)
        .label("", ID_CODE_TIMER, 7, 64, 222, 8)
        .label(
            "On the other computer choose File > Add Device and enter these two values. \
             After pairing, that computer can connect at any time without a code, until \
             you remove or revoke it.",
            -1, 7, 78, 222, 26,
        )
        .label("", ID_CODE_RESULT, 7, 108, 222, 10)
        .rule(7, 124, 222)
        .button("Close", IDCANCEL_, 179, 130, 50, true)
        .finish();
    run(owner, t, Box::new(ShowCode { expires: None, large: None }));
}

// --------------------------------------------------------------- Settings

const ID_SET_NAME: i32 = 301;
const ID_SET_IS_SERVER: i32 = 302;
const ID_SET_ADDRESS: i32 = 303;
const ID_SET_KEY: i32 = 304;
const ID_SET_HINT: i32 = 305;
const ID_SET_JOIN: i32 = 306;
const ID_SET_INCOMING: i32 = 307;
const ID_SET_CLIPBOARD: i32 = 308;
const ID_SET_RELAY: i32 = 309;
const ID_SET_COPY: i32 = 310;
const ID_SET_FIREWALL: i32 = 311;
const ID_SET_RELAY_HINT: i32 = 312;

/// Reads a server address and key out of pasted join information, in the
/// form the server's Settings shows (and copies) it.
pub fn parse_join(text: &str) -> (Option<String>, Option<String>) {
    let mut address = None;
    let mut key = None;
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if let Some((_, value)) = line.split_once(':') {
            let value = value.trim().to_string();
            if lower.contains("address") && !value.is_empty() {
                address = Some(value);
            } else if lower.contains("key") && !value.is_empty() {
                key = Some(value);
            }
        }
    }
    // A bare key on its own also works.
    if key.is_none() {
        let hex: String = text.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() == 64 {
            key = Some(text.trim().to_string());
        }
    }
    (address, key)
}

/// Adds a Windows Firewall rule letting other computers reach this BARK.
/// Needs administrator rights, so Windows asks (UAC) first.
fn allow_in_firewall(owner: HWND) {
    let Ok(exe) = std::env::current_exe() else { return };
    let exe = exe.to_string_lossy().to_string();
    let rule = "BARK Remote Access";
    let args = format!(
        "/c netsh advfirewall firewall delete rule name=\"{rule}\" >nul & \
         netsh advfirewall firewall add rule name=\"{rule}\" dir=in action=allow protocol=UDP \
         program=\"{exe}\" enable=yes profile=any"
    );
    let verb = Wide::new("runas");
    let file = Wide::new("cmd.exe");
    let params = Wide::new(&args);
    let r = unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(
            Some(owner),
            verb.pcwstr(),
            file.pcwstr(),
            params.pcwstr(),
            windows::core::PCWSTR::null(),
            SW_HIDE,
        )
    };
    if (r.0 as isize) <= 32 {
        error_box(Some(owner), "The firewall rule was not added (Windows did not get administrator permission).");
    } else {
        info_box(
            Some(owner),
            "Windows Firewall now lets other computers reach BARK on this computer.\n\n\
             BARK still refuses every connection that is not from a device paired with this computer.",
        );
    }
}

struct Settings {
    original: NodeConfig,
}

impl Settings {
    fn sync_enabled(&self, dlg: HWND) {
        let is_server = is_checked(dlg, ID_SET_IS_SERVER);
        enable(dlg_item(dlg, ID_SET_ADDRESS), !is_server);
        enable(dlg_item(dlg, ID_SET_KEY), !is_server);
        // In this version the relay runs as part of the server.
        enable(dlg_item(dlg, ID_SET_RELAY), is_server);
        set_dlg_text(
            dlg,
            ID_SET_RELAY_HINT,
            if is_server {
                "Uses this computer's upload bandwidth, only when a direct connection fails."
            } else {
                "Only the BARK server computer can relay in this version."
            },
        );
        set_dlg_text(dlg, ID_SET_COPY, if is_server { "&Copy" } else { "&Paste" });
        let status = app::status();
        let join = status.as_ref().and_then(|s| s.server_role.as_ref());
        let loopback_only = join.is_some_and(|r| r.listening.starts_with("127."));
        let (hint, text) = match (is_server, join) {
            (true, Some(r)) if loopback_only => (
                "Listens on 127.0.0.1 only, so other computers cannot reach this server.".to_string(),
                format!("Server key:  {}", r.key_text),
            ),
            (true, Some(r)) => (
                "Enter this on every other computer (Tools > Settings):".to_string(),
                format!(
                    "Server address:  {}:{}\r\nServer key:  {}",
                    status
                        .as_ref()
                        .and_then(|s| s.local_addresses.first())
                        .map(|a| a.split(' ').next().unwrap_or("").to_string())
                        .unwrap_or_else(|| "<this computer's IP address>".into()),
                    r.listening.rsplit(':').next().unwrap_or(""),
                    r.key_text
                ),
            ),
            (true, None) => (
                "Press OK to start the server. Its join information will then appear here.".into(),
                String::new(),
            ),
            (false, _) => (
                "Copy the address and key shown in the settings of the BARK server computer.".into(),
                String::new(),
            ),
        };
        set_dlg_text(dlg, ID_SET_HINT, &hint);
        set_dlg_text(dlg, ID_SET_JOIN, &text);
    }
}

impl Dialog for Settings {
    fn init(&mut self, dlg: HWND) {
        let c = &self.original;
        set_dlg_text(dlg, ID_SET_NAME, &c.device_name);
        set_checked(dlg, ID_SET_IS_SERVER, c.roles.coordination_server);
        if let Some(s) = &c.server {
            set_dlg_text(dlg, ID_SET_ADDRESS, &s.address);
            set_dlg_text(dlg, ID_SET_KEY, &s.key);
        }
        set_checked(dlg, ID_SET_INCOMING, c.accept_incoming);
        set_checked(dlg, ID_SET_CLIPBOARD, c.clipboard_sync);
        set_checked(dlg, ID_SET_RELAY, c.roles.relay);
        self.sync_enabled(dlg);
    }

    fn command(&mut self, dlg: HWND, id: i32, _code: u16) -> bool {
        match id {
            ID_SET_IS_SERVER => {
                // A new server relays by default (ARCHITECTURE.md s.17).
                if is_checked(dlg, ID_SET_IS_SERVER) && !self.original.roles.coordination_server {
                    set_checked(dlg, ID_SET_RELAY, true);
                }
                self.sync_enabled(dlg);
                true
            }
            ID_SET_COPY => {
                if is_checked(dlg, ID_SET_IS_SERVER) {
                    let text = dlg_text(dlg, ID_SET_JOIN);
                    if !text.trim().is_empty() && copy_to_clipboard(dlg, &text) {
                        info_box(Some(dlg), "The address and key are on the clipboard. Paste them into Settings on the other computer (Paste button).");
                    }
                } else {
                    match clipboard_text(dlg).map(|t| parse_join(&t)) {
                        Some((address, key)) if address.is_some() || key.is_some() => {
                            if let Some(a) = address {
                                set_dlg_text(dlg, ID_SET_ADDRESS, &a);
                            }
                            if let Some(k) = key {
                                set_dlg_text(dlg, ID_SET_KEY, &k);
                            }
                        }
                        _ => error_box(
                            Some(dlg),
                            "The clipboard does not contain BARK join information.\n\n\
                             On the BARK server computer open Tools > Settings and press Copy, then \
                             bring that text to this computer.",
                        ),
                    }
                }
                true
            }
            ID_SET_FIREWALL => {
                allow_in_firewall(dlg);
                true
            }
            IDOK_ => {
                let mut c = self.original.clone();
                c.device_name = dlg_text(dlg, ID_SET_NAME).trim().to_string();
                c.roles.coordination_server = is_checked(dlg, ID_SET_IS_SERVER);
                let address = dlg_text(dlg, ID_SET_ADDRESS).trim().to_string();
                let key = dlg_text(dlg, ID_SET_KEY).trim().to_string();
                c.server = if address.is_empty() && key.is_empty() {
                    None
                } else {
                    Some(ServerTarget { address, key })
                };
                c.accept_incoming = is_checked(dlg, ID_SET_INCOMING);
                c.clipboard_sync = is_checked(dlg, ID_SET_CLIPBOARD);
                c.roles.relay = c.roles.coordination_server && is_checked(dlg, ID_SET_RELAY);
                if let Err(e) = c.validate() {
                    error_box(Some(dlg), &e.to_string());
                    return true;
                }
                if c != self.original {
                    app::send_node(Command::SetConfig(c));
                }
                end(dlg, IDOK_);
                true
            }
            _ => false,
        }
    }
}

pub fn settings(owner: HWND) {
    let Some(status) = app::status() else { return };
    let t = Template::new("Settings", 300, 262)
        .label_right("Device name:", 7, 9, 60, 8)
        .edit(ID_SET_NAME, 72, 7, 130, 13, 0)
        .label("(blank = computer name)", -1, 207, 9, 90, 8)
        .group("BARK server", 7, 26, 286, 104)
        .check("This computer is the BARK server", ID_SET_IS_SERVER, 14, 38, 200)
        .label_right("Server address:", 14, 54, 60, 8)
        .edit(ID_SET_ADDRESS, 79, 52, 130, 13, 0)
        .label_right("Server key:", 14, 70, 60, 8)
        .edit(ID_SET_KEY, 79, 68, 207, 13, 0)
        .button("&Paste", ID_SET_COPY, 236, 51, 50, false)
        .label("", ID_SET_HINT, 14, 86, 272, 8)
        .report(ID_SET_JOIN, 14, 97, 272, 26)
        .group("This computer", 7, 134, 286, 94)
        .check("Allow paired devices to control this computer", ID_SET_INCOMING, 14, 146, 270)
        .check("Synchronise the clipboard during sessions", ID_SET_CLIPBOARD, 14, 160, 270)
        .check("Relay connections for other BARK devices", ID_SET_RELAY, 14, 174, 270)
        .label("", ID_SET_RELAY_HINT, 26, 187, 260, 8)
        .button("Allow in Windows &Firewall...", ID_SET_FIREWALL, 14, 204, 120, false)
        .rule(7, 236, 286)
        .button("OK", IDOK_, 189, 242, 50, true)
        .button("Cancel", IDCANCEL_, 243, 242, 50, false)
        .finish();
    run(owner, t, Box::new(Settings { original: status.config }));
}

// ------------------------------------------------------------ Properties

const ID_PROP_NAME: i32 = 401;
const ID_PROP_DESC: i32 = 402;
const ID_PROP_GROUP: i32 = 403;
const ID_PROP_DETAILS: i32 = 404;
const ID_PROP_REVOKE: i32 = 405;

struct Properties {
    device: DeviceView,
}

fn access_text(d: &DeviceView) -> &'static str {
    if d.revoked {
        "Revoked"
    } else {
        match (d.we_may_control, d.may_control_us) {
            (true, true) => "Both directions",
            (true, false) => "This computer controls it",
            (false, true) => "It controls this computer",
            (false, false) => "None",
        }
    }
}

pub fn access_column(d: &DeviceView) -> &'static str {
    if d.revoked {
        "Revoked"
    } else {
        match (d.we_may_control, d.may_control_us) {
            (true, true) => "Both",
            (true, false) => "You control it",
            (false, true) => "It controls you",
            (false, false) => "--",
        }
    }
}

impl Dialog for Properties {
    fn init(&mut self, dlg: HWND) {
        let d = &self.device;
        set_dlg_text(dlg, ID_PROP_NAME, &d.name);
        set_dlg_text(dlg, ID_PROP_DESC, &d.description);
        set_dlg_text(dlg, ID_PROP_GROUP, &d.group);
        let now = bark_core::clock::unix_us();
        let fp_hex = d.fingerprint.to_display_groups();
        let details = format!(
            "Device ID:\t\t{}\r\nStatus:\t\t{}\r\nAccess:\t\t{}\r\nOperating system:\t{}\r\nBARK version:\t{}\r\nPaired:\t\t{}\r\nLast seen:\t\t{}\r\nLast connected:\t{}\r\n\r\nFingerprint (the device's full cryptographic identity):\r\n{}",
            d.device_id,
            if d.online { "ONLINE" } else { "OFFLINE" },
            access_text(d),
            if d.os.is_empty() { "--" } else { &d.os },
            if d.bark_version.is_empty() { "--" } else { &d.bark_version },
            bark_node::api::format_date_time(d.paired_unix_us),
            bark_node::api::format_last_seen(d.last_seen_unix_us, now, d.online),
            bark_node::api::format_date_time(d.last_connected_unix_us),
            fp_hex,
        );
        set_dlg_text(dlg, ID_PROP_DETAILS, &details);
        enable(dlg_item(dlg, ID_PROP_REVOKE), !d.revoked);
    }

    fn command(&mut self, dlg: HWND, id: i32, _code: u16) -> bool {
        let fp = self.device.fingerprint;
        match id {
            IDOK_ => {
                let name = dlg_text(dlg, ID_PROP_NAME).trim().to_string();
                if name.is_empty() {
                    error_box(Some(dlg), "The name cannot be blank.");
                    return true;
                }
                if name != self.device.name {
                    app::send_node(Command::Rename { device: fp, name });
                }
                let desc = dlg_text(dlg, ID_PROP_DESC);
                let group = dlg_text(dlg, ID_PROP_GROUP);
                if desc.trim() != self.device.description || group.trim() != self.device.group {
                    app::send_node(Command::SetDetails { device: fp, description: desc, group });
                }
                end(dlg, IDOK_);
                true
            }
            ID_PROP_REVOKE => {
                let text = format!(
                    "Revoke trust for {}?\n\nIts old credentials stop working immediately: it will not \
                     be able to connect to this computer, and this computer will not connect to it.\n\n\
                     It stays in the list, marked Revoked. To restore access, pair it again with a new \
                     pairing code.",
                    self.device.name
                );
                if confirm(Some(dlg), &text) {
                    app::send_node(Command::Revoke { device: fp });
                    end(dlg, IDOK_);
                }
                true
            }
            _ => false,
        }
    }
}

pub fn properties(owner: HWND, device: DeviceView) {
    let t = Template::new(&format!("{} Properties", device.name), 270, 232)
        .label_right("Name:", 7, 9, 50, 8)
        .edit(ID_PROP_NAME, 62, 7, 140, 13, 0)
        .label_right("Description:", 7, 26, 50, 8)
        .edit(ID_PROP_DESC, 62, 24, 201, 13, 0)
        .label_right("Group:", 7, 43, 50, 8)
        .edit(ID_PROP_GROUP, 62, 41, 100, 13, 0)
        .group("Details", 7, 60, 256, 138)
        .report(ID_PROP_DETAILS, 14, 72, 242, 120)
        .rule(7, 206, 256)
        .button("Revoke Trust...", ID_PROP_REVOKE, 7, 212, 64, false)
        .button("OK", IDOK_, 159, 212, 50, true)
        .button("Cancel", IDCANCEL_, 213, 212, 50, false)
        .finish();
    run(owner, t, Box::new(Properties { device }));
}

// ----------------------------------------------------------- Diagnostics

const ID_DIAG_TEXT: i32 = 501;
const ID_DIAG_REFRESH: i32 = 502;
const ID_DIAG_COPY: i32 = 503;

struct Diagnostics {
    font: Option<HFONT>,
}

pub fn diagnostics_report(status: &NodeStatus) -> String {
    fn line(out: &mut String, s: &str) {
        out.push_str(s);
        // Multi-line edit controls need CR LF; a bare LF shows as nothing.
        out.push_str("\r\n");
    }
    fn check(out: &mut String, ok: Option<bool>, what: &str, detail: &str) {
        let tag = match ok {
            Some(true) => "[ OK ]",
            Some(false) => "[FAIL]",
            None => "[ -- ]",
        };
        line(out, &format!("{tag}  {what:<34} {detail}"));
    }

    let mut out = String::new();
    let o = &mut out;
    line(o, "BARK DIAGNOSTICS");
    line(o, "----------------------------------------------------------------");
    line(o, &format!("  Computer name   {}", status.device_name));
    line(o, &format!("  Device ID       {}", status.device_id));
    line(o, &format!("  Mode            {}", status.mode));
    line(o, &format!("  Version         {} (protocol {})", status.version, bark_core::PROTOCOL_VERSION));
    if status.local_addresses.is_empty() {
        line(o, "  Addresses       none found");
    } else {
        for (i, a) in status.local_addresses.iter().enumerate() {
            line(o, &format!("  {}{}", if i == 0 { "Addresses       " } else { "                " }, a));
        }
    }
    line(o, "");

    check(o, Some(true), "Device identity", "loaded, protected by Windows");
    match &status.server {
        ServerLink::NotConfigured => {
            check(o, Some(false), "BARK server configured", "no server set up");
            line(o, "        Open Tools > Settings and enter the server address and key,");
            line(o, "        or tick \"This computer is the BARK server\".");
        }
        ServerLink::Connecting { address } => {
            check(o, Some(true), "BARK server configured", address);
            check(o, None, "Connected to BARK server", "connecting now...");
        }
        ServerLink::Online { address, rtt_us, public_address, server_version } => {
            check(o, Some(true), "BARK server configured", address);
            let rtt = rtt_us
                .map(|r| format!("round trip {:.1} ms", r as f64 / 1000.0))
                .unwrap_or_else(|| "round trip not measured yet".into());
            check(o, Some(true), "Connected to BARK server", &rtt);
            check(o, Some(true), "Signed in with this device's key", &format!("server version {server_version}"));
            check(o, Some(true), "Address the server sees", public_address);
        }
        ServerLink::Offline { address, error, retry_in_secs } => {
            check(o, Some(true), "BARK server configured", address);
            check(o, Some(false), "Connected to BARK server", &format!("retrying in {retry_in_secs} s"));
            for l in error.lines() {
                line(o, &format!("        {l}"));
            }
        }
    }
    match &status.server_role {
        Some(r) => {
            check(
                o,
                Some(true),
                "Coordination server role",
                &format!("listening on {}, {} online / {} known", r.listening, r.devices_online, r.devices_known),
            );
            match &r.relay {
                Some(addr) => check(o, Some(true), "Relay role", &format!("listening on {addr} (UDP)")),
                None => check(o, None, "Relay role", "off (Tools > Settings)"),
            }
        }
        None => check(o, None, "Coordination server role", "off (another computer is the server)"),
    }
    line(o, "");
    if status.sessions.is_empty() {
        line(o, "  Sessions        none running");
    } else {
        for (i, s) in status.sessions.iter().enumerate() {
            let dir = if s.controlling { "controlling" } else { "controlled by" };
            line(
                o,
                &format!(
                    "  {}{dir} {}  {}  {}  since {}",
                    if i == 0 { "Sessions        " } else { "                " },
                    s.device_name,
                    s.path,
                    s.remote_address,
                    bark_node::api::format_date_time(s.started_unix_us)
                ),
            );
        }
    }
    line(o, "");
    line(o, "  Live figures for a session (round trip, frame rate, latency) are in");
    line(o, "  its window's status bar.");
    out
}

impl Dialog for Diagnostics {
    fn init(&mut self, dlg: HWND) {
        // A fixed-width font lines the report's columns up.
        let dpi = unsafe { GetDpiForWindow(dlg) };
        let mut lf = windows::Win32::Graphics::Gdi::LOGFONTW { lfHeight: -px(12, dpi), ..Default::default() };
        let face: Vec<u16> = "Consolas".encode_utf16().collect();
        lf.lfFaceName[..face.len()].copy_from_slice(&face);
        let f = unsafe { windows::Win32::Graphics::Gdi::CreateFontIndirectW(&lf) };
        set_font(dlg_item(dlg, ID_DIAG_TEXT), f);
        self.font = Some(f);
        self.refresh(dlg);
    }

    fn command(&mut self, dlg: HWND, id: i32, _code: u16) -> bool {
        match id {
            ID_DIAG_REFRESH => {
                self.refresh(dlg);
                true
            }
            ID_DIAG_COPY => {
                let t = dlg_text(dlg, ID_DIAG_TEXT);
                if copy_to_clipboard(dlg, &t) {
                    info_box(Some(dlg), "The diagnostics report was copied to the clipboard.");
                }
                true
            }
            IDOK_ => {
                self.closing(dlg);
                end(dlg, IDOK_);
                true
            }
            _ => false,
        }
    }

    fn closing(&mut self, _dlg: HWND) {
        if let Some(f) = self.font.take() {
            unsafe {
                let _ = windows::Win32::Graphics::Gdi::DeleteObject(windows::Win32::Graphics::Gdi::HGDIOBJ(f.0));
            }
        }
    }
}

impl Diagnostics {
    fn refresh(&self, dlg: HWND) {
        let text = match app::status() {
            Some(s) => diagnostics_report(&s),
            None => "BARK is still starting. Press Refresh in a moment.".into(),
        };
        set_dlg_text(dlg, ID_DIAG_TEXT, &text);
        // An edit control that receives focus selects all its text; a report
        // is easier to read without a solid blue block over it.
        const EM_SETSEL: u32 = 0x00B1;
        unsafe {
            SendMessageW(dlg_item(dlg, ID_DIAG_TEXT), EM_SETSEL, Some(WPARAM(0)), Some(LPARAM(0)));
            let _ = windows::Win32::UI::Input::KeyboardAndMouse::SetFocus(Some(dlg_item(dlg, IDOK_)));
        }
    }
}

pub fn diagnostics(owner: HWND) {
    let t = Template::new("Diagnostics", 360, 230)
        .report(ID_DIAG_TEXT, 7, 7, 346, 190)
        .rule(7, 204, 346)
        .button("Refresh", ID_DIAG_REFRESH, 7, 210, 50, false)
        .button("Copy to Clipboard", ID_DIAG_COPY, 61, 210, 70, false)
        .button("Close", IDOK_, 303, 210, 50, true)
        .finish();
    run(owner, t, Box::new(Diagnostics { font: None }));
}

// ----------------------------------------------------------------- About

struct About;

impl Dialog for About {
    fn init(&mut self, dlg: HWND) {
        let fonts = crate::win::Fonts::for_dpi(unsafe { GetDpiForWindow(dlg) });
        set_font(dlg_item(dlg, 601), fonts.bold);
        let s = app::status();
        set_dlg_text(
            dlg,
            602,
            &format!(
                "Version {} (protocol {})\nThis computer: {}  {}\nMode: {}",
                bark_core::VERSION,
                bark_core::PROTOCOL_VERSION,
                s.as_ref().map(|s| s.device_name.as_str()).unwrap_or(""),
                s.as_ref().map(|s| s.device_id.as_str()).unwrap_or(""),
                s.as_ref().map(|s| s.mode.as_str()).unwrap_or(""),
            ),
        );
    }

    fn command(&mut self, dlg: HWND, id: i32, _code: u16) -> bool {
        if id == IDOK_ {
            end(dlg, IDOK_);
            return true;
        }
        false
    }
}

pub fn about(owner: HWND) {
    let t = Template::new("About BARK", 220, 104)
        .label("BARK", 601, 7, 7, 206, 10)
        .label("Bright Arrow Remote-Access Kit", -1, 7, 19, 206, 8)
        .label("", 602, 7, 34, 206, 26)
        .label("Private remote access for your company's own computers.", -1, 7, 64, 206, 8)
        .rule(7, 78, 206)
        .button("OK", IDOK_, 163, 84, 50, true)
        .finish();
    run(owner, t, Box::new(About));
}

// ------------------------------------------------------ Connection failed

const ID_FAIL_TEXT: i32 = 701;
const ID_FAIL_RETRY: i32 = 702;
const ID_FAIL_DIAG: i32 = 703;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailedChoice {
    Retry,
    Diagnostics,
    Close,
}

struct Failed {
    text: String,
}

impl Dialog for Failed {
    fn init(&mut self, dlg: HWND) {
        set_dlg_text(dlg, ID_FAIL_TEXT, &self.text);
    }

    fn command(&mut self, dlg: HWND, id: i32, _code: u16) -> bool {
        match id {
            ID_FAIL_RETRY | ID_FAIL_DIAG | IDOK_ => {
                end(dlg, id);
                true
            }
            _ => false,
        }
    }
}

/// The "Unable to connect" box: what was attempted, the last known state, the
/// reason, likely causes, and something to do about it.
pub fn connection_failed(owner: HWND, device: &str, last_status: &str, reason: &str) -> FailedChoice {
    let text = format!(
        "Unable to connect.\r\n\r\n\
         Device:\t\t{device}\r\n\
         Last known status:\t{last_status}\r\n\r\n\
         Reason:\r\n{reason}\r\n\r\n\
         Possible causes:\r\n\
         \u{2022} The remote computer is turned off, asleep, or has no network\r\n\
         \u{2022} BARK is not running on the remote computer\r\n\
         \u{2022} A firewall or network policy is blocking the connection",
        reason = reason.replace('\n', "\r\n")
    );
    let t = Template::new("BARK - Connection", 280, 180)
        .report(ID_FAIL_TEXT, 7, 7, 266, 140)
        .rule(7, 154, 266)
        .button("Retry", ID_FAIL_RETRY, 7, 160, 50, true)
        .button("Diagnostics...", ID_FAIL_DIAG, 61, 160, 60, false)
        .button("Close", IDOK_, 223, 160, 50, false)
        .finish();
    match run(owner, t, Box::new(Failed { text })) as i32 {
        ID_FAIL_RETRY => FailedChoice::Retry,
        ID_FAIL_DIAG => FailedChoice::Diagnostics,
        _ => FailedChoice::Close,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_information_pastes_from_what_the_server_copies() {
        let copied = "Server address:  192.168.1.10:57411\r\nServer key:  AB12-CD34-EF56-7890-AB12-CD34-EF56-7890-AB12-CD34-EF56-7890-AB12-CD34-EF56-7890";
        let (a, k) = parse_join(copied);
        assert_eq!(a.as_deref(), Some("192.168.1.10:57411"));
        assert!(k.unwrap().starts_with("AB12-CD34"));
        let (a, k) = parse_join("  ab12cd34ef567890ab12cd34ef567890ab12cd34ef567890ab12cd34ef567890 ");
        assert!(a.is_none());
        assert!(k.is_some(), "a bare 64-digit key is recognised");
        assert_eq!(parse_join("hello world"), (None, None));
    }

    #[test]
    fn templates_are_dword_aligned_and_count_their_items() {
        let t = Template::new("X", 100, 50)
            .label("a", 1, 0, 0, 10, 10)
            .edit(2, 0, 0, 10, 10, 0)
            .button("OK", IDOK_, 0, 0, 10, true);
        let count_at = t.count_at;
        let words = t.words.clone();
        let _ = words;
        let out = t.finish();
        // Item count lives in the low half of the third DWORD... more simply,
        // re-read the 16-bit value where it was written.
        let as_u16: Vec<u16> = out.iter().flat_map(|d| [(*d & 0xffff) as u16, (*d >> 16) as u16]).collect();
        assert_eq!(as_u16[count_at], 3);
    }

    #[test]
    fn the_diagnostics_report_explains_a_missing_server() {
        let status = NodeStatus {
            device_name: "PC".into(),
            device_id: "BA-0000-0000".into(),
            fingerprint: bark_core::Fingerprint([0u8; 32]),
            version: "0.1.0".into(),
            mode: "standalone".into(),
            server: ServerLink::NotConfigured,
            server_role: None,
            config: NodeConfig::default(),
            local_addresses: vec!["192.168.1.5 (Ethernet)".into()],
            sessions: vec![],
        };
        let r = diagnostics_report(&status);
        assert!(r.contains("[FAIL]  BARK server configured"));
        assert!(r.contains("Tools > Settings"), "says what to do");
        assert!(r.contains("Sessions        none running"));
        assert!(r.contains("192.168.1.5"));
    }
}
