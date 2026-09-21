//! The main BARK window.
//!
//! Layout, top to bottom: menu bar; a "This Computer" panel with this
//! machine's name, Device ID and server connection; the favourites list; a row
//! of buttons; the status bar. Classic Win32 controls throughout, in the
//! system's own font and colours.
//!
//! The node runs on its own thread. It reports through a queue and a posted
//! window message, so the window never blocks on the network and the network
//! never touches a window.

use crate::dialogs;
use crate::win::*;
use bark_core::Fingerprint;
use bark_node::api::{format_last_seen, Command, DeviceView, Event, NodeStatus, NoticeLevel, ServerLink};
use bark_node::{EventSink, NodeHandle};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::sync::{Arc, Mutex};
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::{GetSysColor, COLOR_BTNFACE, COLOR_WINDOWTEXT, HBRUSH};
use windows::Win32::UI::Controls::*;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

pub const WM_NODE: u32 = WM_APP + 1;
const CLASS: PCWSTR = w!("BARK.MainWindow");

// Control identifiers.
const IDC_LIST: i32 = 1001;
const IDC_CONNECT: i32 = 1101;
const IDC_ADD: i32 = 1102;
const IDC_REMOVE: i32 = 1103;
const IDC_PROPS: i32 = 1104;
const IDC_CODE: i32 = 1105;

// Menu commands.
const IDM_ADD: u16 = 2001;
const IDM_REMOVE: u16 = 2002;
const IDM_PROPS: u16 = 2003;
const IDM_EXIT: u16 = 2004;
const IDM_CONNECT: u16 = 2101;
const IDM_SHOW_CODE: u16 = 2102;
const IDM_REFRESH: u16 = 2201;
const IDM_CONN_INFO: u16 = 2202;
const IDM_DIAG: u16 = 2301;
const IDM_SETTINGS: u16 = 2302;
const IDM_LOGS: u16 = 2303;
const IDM_ABOUT: u16 = 2401;
const IDM_REVOKE: u16 = 2501;

/// Column headings, with widths at 96 DPI.
const COLUMNS: [(&str, i32); 7] = [
    ("Name", 170),
    ("Status", 72),
    ("Connection", 82),
    ("Last Seen", 82),
    ("Device ID", 104),
    ("Access", 110),
    ("Operating System", 210),
];

static MAIN: AtomicIsize = AtomicIsize::new(0);
static QUEUE: Mutex<VecDeque<Event>> = Mutex::new(VecDeque::new());

#[derive(Clone, Copy)]
struct Handles {
    main: HWND,
    group: HWND,
    name_label: HWND,
    name_value: HWND,
    id_label: HWND,
    id_value: HWND,
    server_label: HWND,
    server_value: HWND,
    code_button: HWND,
    favourites: HWND,
    list: HWND,
    connect: HWND,
    add: HWND,
    remove: HWND,
    props: HWND,
    status_bar: HWND,
    fonts: Fonts,
    dpi: u32,
}

impl Handles {
    fn all_children(&self) -> [HWND; 15] {
        [
            self.group,
            self.name_label,
            self.name_value,
            self.id_label,
            self.id_value,
            self.server_label,
            self.server_value,
            self.code_button,
            self.favourites,
            self.list,
            self.connect,
            self.add,
            self.remove,
            self.props,
            self.status_bar,
        ]
    }
}

#[derive(Default)]
struct State {
    status: Option<NodeStatus>,
    devices: Vec<DeviceView>,
    /// What each list row shows, in row order: fingerprint, online, revoked.
    rows: Vec<(Fingerprint, bool, bool)>,
    title_suffix: String,
    last_message: String,
}

thread_local! {
    static HANDLES: Cell<Option<Handles>> = const { Cell::new(None) };
    static STATE: RefCell<State> = RefCell::new(State::default());
    static NODE: RefCell<Option<NodeHandle>> = const { RefCell::new(None) };
    static ACTIVE_DIALOG: Cell<Option<HWND>> = const { Cell::new(None) };
    static ACCEL: Cell<Option<HACCEL>> = const { Cell::new(None) };
}

fn handles() -> Option<Handles> {
    HANDLES.with(|h| h.get())
}

// ---------------------------------------------------- interface for dialogs

pub fn send_node(cmd: Command) {
    NODE.with(|n| {
        if let Ok(n) = n.try_borrow() {
            if let Some(n) = n.as_ref() {
                n.send(cmd);
            }
        }
    });
}

pub fn status() -> Option<NodeStatus> {
    STATE.with(|s| s.try_borrow().ok().and_then(|s| s.status.clone()))
}

pub fn set_active_dialog(d: Option<HWND>) {
    ACTIVE_DIALOG.with(|a| a.set(d));
}

fn active_dialog() -> Option<HWND> {
    ACTIVE_DIALOG.with(|a| a.get())
}

/// Where the node delivers its events.
pub fn event_sink() -> EventSink {
    Arc::new(|e| {
        if let Ok(mut q) = QUEUE.lock() {
            q.push_back(e);
        }
        let h = MAIN.load(Ordering::Acquire);
        if h != 0 {
            unsafe {
                let _ = PostMessageW(Some(HWND(h as *mut _)), WM_NODE, WPARAM(0), LPARAM(0));
            }
        }
    })
}

// ------------------------------------------------------------- start-up

/// Creates the main window, starts the node and runs the message loop until
/// the window closes.
pub fn run(node: impl FnOnce(EventSink) -> NodeHandle, title_suffix: &str) -> i32 {
    STATE.with(|s| s.borrow_mut().title_suffix = title_suffix.to_string());

    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_LISTVIEW_CLASSES | ICC_BAR_CLASSES | ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hIcon: LoadIconW(None, IDI_APPLICATION).unwrap_or_default(),
            hbrBackground: HBRUSH((COLOR_BTNFACE.0 + 1) as usize as *mut _),
            lpszClassName: CLASS,
            ..Default::default()
        };
        RegisterClassExW(&wc);

        let title = Wide::new(&format!("BARK - Bright Arrow Remote-Access Kit{title_suffix}"));
        let hwnd = match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            CLASS,
            title.pcwstr(),
            // No WS_CLIPCHILDREN: the group box is transparent and relies on
            // the window painting the grey background underneath it.
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            0,
            0,
            None,
            Some(build_menu()),
            Some(hinstance()),
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                error_box(None, &format!("BARK could not create its window: {e}"));
                return 1;
            }
        };

        let dpi = GetDpiForWindow(hwnd).max(96);
        create_children(hwnd, dpi);

        // Size the window for the screen it opened on, then show it.
        let _ = SetWindowPos(hwnd, None, 0, 0, px(860, dpi), px(540, dpi), SWP_NOMOVE | SWP_NOZORDER);
        MAIN.store(hwnd.0 as isize, Ordering::Release);
        NODE.with(|n| *n.borrow_mut() = Some(node(event_sink())));
        let _ = ShowWindow(hwnd, SW_SHOW);
        set_status_message("Starting...");

        let accel = build_accelerators();
        ACCEL.with(|a| a.set(accel));

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            if let Some(a) = accel {
                if TranslateAcceleratorW(hwnd, a, &msg) != 0 {
                    continue;
                }
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        MAIN.store(0, Ordering::Release);
        // Stopping the node says goodbye to the server so this device shows as
        // offline immediately rather than after a timeout.
        NODE.with(|n| {
            if let Some(n) = n.borrow_mut().take() {
                n.shutdown();
            }
        });
        if let Some(h) = handles() {
            h.fonts.destroy();
        }
        msg.wParam.0 as i32
    }
}

fn build_menu() -> HMENU {
    unsafe {
        let bar = CreateMenu().unwrap_or_default();
        let add = |m: HMENU, id: u16, text: &str| {
            let t = Wide::new(text);
            let _ = AppendMenuW(m, MF_STRING, id as usize, t.pcwstr());
        };
        let sep = |m: HMENU| {
            let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
        };
        let popup = |text: &str, m: HMENU| {
            let t = Wide::new(text);
            let _ = AppendMenuW(bar, MF_POPUP, m.0 as usize, t.pcwstr());
        };

        let file = CreatePopupMenu().unwrap_or_default();
        add(file, IDM_ADD, "&Add Device...\tCtrl+N");
        add(file, IDM_REMOVE, "&Remove Device\tDel");
        add(file, IDM_PROPS, "&Properties\tAlt+Enter");
        sep(file);
        add(file, IDM_EXIT, "E&xit");
        popup("&File", file);

        let conn = CreatePopupMenu().unwrap_or_default();
        add(conn, IDM_CONNECT, "&Connect\tEnter");
        sep(conn);
        add(conn, IDM_SHOW_CODE, "Show &Pairing Code...");
        popup("&Connection", conn);

        let view = CreatePopupMenu().unwrap_or_default();
        add(view, IDM_REFRESH, "&Refresh\tF5");
        sep(view);
        add(view, IDM_CONN_INFO, "Connection &Information");
        let _ = EnableMenuItem(view, IDM_CONN_INFO as u32, MF_BYCOMMAND | MF_GRAYED);
        popup("&View", view);

        let tools = CreatePopupMenu().unwrap_or_default();
        add(tools, IDM_SHOW_CODE, "Show &Pairing Code...");
        add(tools, IDM_DIAG, "&Diagnostics...");
        sep(tools);
        add(tools, IDM_SETTINGS, "&Settings...");
        add(tools, IDM_LOGS, "Open &Log Folder");
        popup("&Tools", tools);

        let help = CreatePopupMenu().unwrap_or_default();
        add(help, IDM_ABOUT, "&About BARK");
        popup("&Help", help);

        bar
    }
}

fn build_accelerators() -> Option<HACCEL> {
    let table = [
        ACCEL { fVirt: FVIRTKEY | FCONTROL, key: b'N' as u16, cmd: IDM_ADD },
        ACCEL { fVirt: FVIRTKEY, key: VK_DELETE.0, cmd: IDM_REMOVE },
        ACCEL { fVirt: FVIRTKEY | FALT, key: VK_RETURN.0, cmd: IDM_PROPS },
        ACCEL { fVirt: FVIRTKEY, key: VK_F5.0, cmd: IDM_REFRESH },
    ];
    unsafe { CreateAcceleratorTableW(&table).ok() }
}

unsafe fn child(parent: HWND, class: PCWSTR, text: &str, style: u32, id: i32) -> HWND {
    let t = Wide::new(text);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            t.pcwstr(),
            WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | style),
            0,
            0,
            10,
            10,
            Some(parent),
            Some(HMENU(id as isize as *mut _)),
            Some(hinstance()),
            None,
        )
        .unwrap_or_default()
    }
}

fn create_children(main: HWND, dpi: u32) {
    const SS_NOPREFIX: u32 = 0x80;
    const SS_ENDELLIPSIS: u32 = 0x4000;
    const BS_GROUPBOX: u32 = 0x7;
    const BS_PUSHBUTTON: u32 = 0x0;
    unsafe {
        let st = w!("STATIC");
        let bt = w!("BUTTON");
        let h = Handles {
            main,
            group: child(main, bt, "This Computer", BS_GROUPBOX, -1),
            name_label: child(main, st, "Name:", SS_NOPREFIX, -1),
            name_value: child(main, st, "", SS_NOPREFIX | SS_ENDELLIPSIS, -1),
            id_label: child(main, st, "Device ID:", SS_NOPREFIX, -1),
            id_value: child(main, st, "", SS_NOPREFIX, -1),
            server_label: child(main, st, "Server:", SS_NOPREFIX, -1),
            server_value: child(main, st, "", SS_NOPREFIX | SS_ENDELLIPSIS, -1),
            code_button: child(main, bt, "Show Pairing Code...", BS_PUSHBUTTON | WS_TABSTOP.0, IDC_CODE),
            favourites: child(main, st, "Favorites", SS_NOPREFIX, -1),
            list: {
                let l = CreateWindowExW(
                    WS_EX_CLIENTEDGE,
                    WC_LISTVIEWW,
                    PCWSTR::null(),
                    WINDOW_STYLE(
                        WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                    ),
                    0,
                    0,
                    10,
                    10,
                    Some(main),
                    Some(HMENU(IDC_LIST as isize as *mut _)),
                    Some(hinstance()),
                    None,
                )
                .unwrap_or_default();
                let ex = LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER;
                SendMessageW(l, LVM_SETEXTENDEDLISTVIEWSTYLE, Some(WPARAM(ex as usize)), Some(LPARAM(ex as isize)));
                for (i, (title, width)) in COLUMNS.iter().enumerate() {
                    let mut t = Wide::new(title);
                    let col = LVCOLUMNW {
                        mask: LVCF_TEXT | LVCF_WIDTH,
                        cx: px(*width, dpi),
                        pszText: t.pwstr(),
                        ..Default::default()
                    };
                    SendMessageW(l, LVM_INSERTCOLUMNW, Some(WPARAM(i)), Some(LPARAM(&col as *const _ as isize)));
                }
                l
            },
            connect: child(main, bt, "Connect", BS_PUSHBUTTON | WS_TABSTOP.0, IDC_CONNECT),
            add: child(main, bt, "Add Device...", BS_PUSHBUTTON | WS_TABSTOP.0, IDC_ADD),
            remove: child(main, bt, "Remove", BS_PUSHBUTTON | WS_TABSTOP.0, IDC_REMOVE),
            props: child(main, bt, "Properties", BS_PUSHBUTTON | WS_TABSTOP.0, IDC_PROPS),
            status_bar: child(main, STATUSCLASSNAMEW, "", SBARS_SIZEGRIP, -1),
            fonts: Fonts::for_dpi(dpi),
            dpi,
        };
        apply_fonts(&h);
        HANDLES.with(|c| c.set(Some(h)));
        update_buttons();
    }
}

fn apply_fonts(h: &Handles) {
    for c in h.all_children() {
        set_font(c, h.fonts.normal);
    }
    set_font(h.id_value, h.fonts.bold);
    set_font(h.favourites, h.fonts.bold);
}

// ---------------------------------------------------------------- layout

fn layout(h: &Handles) {
    unsafe {
        let mut rc = RECT::default();
        let _ = GetClientRect(h.main, &mut rc);
        let (cw, ch) = (rc.right, rc.bottom);
        let d = h.dpi;
        let p = |v: i32| px(v, d);

        // The status bar sizes itself; ask it where it ended up.
        SendMessageW(h.status_bar, WM_SIZE, None, None);
        let mut sb = RECT::default();
        let _ = GetWindowRect(h.status_bar, &mut sb);
        let sb_h = sb.bottom - sb.top;
        // Fixed-width parts on the right; the message part takes the rest.
        let parts = [cw - p(600), cw - p(390), cw - p(220), -1];
        SendMessageW(h.status_bar, SB_SETPARTS, Some(WPARAM(parts.len())), Some(LPARAM(parts.as_ptr() as isize)));

        let m = p(8);
        let mv = |w: HWND, x: i32, y: i32, width: i32, height: i32| {
            let _ = MoveWindow(w, x, y, width.max(0), height.max(0), true);
        };

        // "This Computer" panel.
        let group_h = p(72);
        mv(h.group, m, p(4), cw - 2 * m, group_h);
        let row1 = p(26);
        let row2 = p(48);
        let label_w = p(66);
        let text_h = p(18);
        let btn_w = p(150);
        let btn_x = cw - m - p(12) - btn_w;
        mv(h.name_label, m + p(12), row1, label_w, text_h);
        mv(h.name_value, m + p(12) + label_w, row1, p(260), text_h);
        mv(h.id_label, m + p(12) + label_w + p(270), row1, p(70), text_h);
        mv(h.id_value, m + p(12) + label_w + p(340), row1, p(150), text_h);
        mv(h.server_label, m + p(12), row2, label_w, text_h);
        mv(h.server_value, m + p(12) + label_w, row2, btn_x - (m + p(12) + label_w) - p(8), text_h);
        mv(h.code_button, btn_x, p(26), btn_w, p(26));

        // Favourites.
        let fav_y = p(4) + group_h + p(8);
        mv(h.favourites, m, fav_y, p(200), text_h);
        let list_y = fav_y + text_h + p(2);
        let buttons_h = p(26);
        let list_h = ch - sb_h - m - buttons_h - m - list_y;
        mv(h.list, m, list_y, cw - 2 * m, list_h);
        // The last column takes whatever width is left over.
        const LVSCW_AUTOSIZE_USEHEADER: isize = -2;
        SendMessageW(
            h.list,
            LVM_SETCOLUMNWIDTH,
            Some(WPARAM(COLUMNS.len() - 1)),
            Some(LPARAM(LVSCW_AUTOSIZE_USEHEADER)),
        );

        // Buttons.
        let by = list_y + list_h + m;
        let mut x = m;
        for (b, width) in [(h.connect, 96), (h.add, 110), (h.remove, 90), (h.props, 96)] {
            mv(b, x, by, p(width), buttons_h);
            x += p(width) + p(6);
        }
    }
}

// --------------------------------------------------------- showing state

fn set_status_message(text: &str) {
    STATE.with(|s| {
        if let Ok(mut s) = s.try_borrow_mut() {
            s.last_message = text.to_string();
        }
    });
    if let Some(h) = handles() {
        set_part(h.status_bar, 0, text);
    }
}

fn set_part(bar: HWND, part: usize, text: &str) {
    let t = Wide::new(text);
    unsafe {
        SendMessageW(bar, SB_SETTEXTW, Some(WPARAM(part)), Some(LPARAM(t.pcwstr().0 as isize)));
    }
}

fn server_line(s: &NodeStatus) -> String {
    let mut line = match &s.server {
        ServerLink::NotConfigured => "NOT SET UP  -  open Tools > Settings to enter the BARK server".into(),
        ServerLink::Connecting { address } => format!("CONNECTING  -  {address}"),
        ServerLink::Online { address, rtt_us, .. } => match rtt_us {
            Some(r) => format!("ONLINE  -  {address}  ({:.1} ms)", *r as f64 / 1000.0),
            None => format!("ONLINE  -  {address}"),
        },
        ServerLink::Offline { address, error, retry_in_secs } => {
            let first = error.lines().next().unwrap_or("");
            format!("OFFLINE  -  {address}  -  retrying in {retry_in_secs} s  -  {first}")
        }
    };
    if s.server_role.is_some() {
        line.push_str("   [this computer is the BARK server]");
    }
    line
}

fn show_status(s: &NodeStatus) {
    let Some(h) = handles() else { return };
    set_text(h.name_value, &s.device_name);
    set_text(h.id_value, &s.device_id);
    set_text(h.server_value, &server_line(s));
    let server = match &s.server {
        ServerLink::Online { rtt_us: Some(r), .. } => format!("Server: ONLINE  {:.1} ms", *r as f64 / 1000.0),
        other => format!("Server: {}", other.word()),
    };
    set_part(h.status_bar, 1, &server);
    let mode = if s.mode.starts_with("standalone") { "Standalone" } else { "Installed" };
    set_part(h.status_bar, 3, &format!("{mode}  |  BARK {}", s.version));
    if STATE.with(|st| st.borrow().last_message == "Starting...") {
        set_status_message("Ready");
    }
}

fn fill_list() {
    let Some(h) = handles() else { return };
    // Copy what is needed and release the borrow before talking to the list
    // view: inserting items makes it send notifications straight back into
    // this window's procedure.
    let (devices, previously_selected) = STATE.with(|s| {
        let s = s.borrow();
        (s.devices.clone(), selected_index(h.list).and_then(|i| s.rows.get(i).map(|r| r.0)))
    });
    let now = bark_core::clock::unix_us();

    unsafe {
        SendMessageW(h.list, LVM_DELETEALLITEMS, None, None);
    }
    let rows: Vec<(Fingerprint, bool, bool)> = devices.iter().map(|d| (d.fingerprint, d.online, d.revoked)).collect();
    STATE.with(|s| s.borrow_mut().rows = rows);

    for (i, d) in devices.iter().enumerate() {
        let status = if d.revoked {
            "REVOKED"
        } else if d.online {
            "ONLINE"
        } else {
            "OFFLINE"
        };
        let cells = [
            d.name.clone(),
            status.to_string(),
            if d.online { d.connection.clone() } else { "--".into() },
            format_last_seen(d.last_seen_unix_us, now, d.online),
            d.device_id.clone(),
            dialogs::access_column(d).to_string(),
            if d.os.is_empty() { "--".into() } else { d.os.clone() },
        ];
        unsafe {
            let mut first = Wide::new(&cells[0]);
            let item = LVITEMW {
                mask: LVIF_TEXT | LVIF_PARAM,
                iItem: i as i32,
                pszText: first.pwstr(),
                lParam: LPARAM(i as isize),
                ..Default::default()
            };
            let row = SendMessageW(h.list, LVM_INSERTITEMW, None, Some(LPARAM(&item as *const _ as isize))).0 as usize;
            for (col, text) in cells.iter().enumerate().skip(1) {
                let mut t = Wide::new(text);
                let sub = LVITEMW { iSubItem: col as i32, pszText: t.pwstr(), ..Default::default() };
                SendMessageW(h.list, LVM_SETITEMTEXTW, Some(WPARAM(row)), Some(LPARAM(&sub as *const _ as isize)));
            }
            if previously_selected == Some(d.fingerprint) {
                let both = LIST_VIEW_ITEM_STATE_FLAGS(LVIS_SELECTED.0 | LVIS_FOCUSED.0);
                let state = LVITEMW {
                    stateMask: both,
                    state: both,
                    ..Default::default()
                };
                SendMessageW(h.list, LVM_SETITEMSTATE, Some(WPARAM(row)), Some(LPARAM(&state as *const _ as isize)));
            }
        }
    }

    if devices.is_empty() {
        set_status_message("No paired devices yet - use Add Device.");
    } else if STATE.with(|s| s.borrow().last_message.starts_with("No paired devices")) {
        set_status_message("Ready");
    }
    let online = devices.iter().filter(|d| d.online).count();
    set_part(
        h.status_bar,
        2,
        &format!("{} device{}, {} online", devices.len(), if devices.len() == 1 { "" } else { "s" }, online),
    );
    update_buttons();
}

fn selected_index(list: HWND) -> Option<usize> {
    let i = unsafe {
        SendMessageW(list, LVM_GETNEXTITEM, Some(WPARAM(usize::MAX)), Some(LPARAM(LVNI_SELECTED as isize))).0
    };
    (i >= 0).then_some(i as usize)
}

fn selected_device() -> Option<DeviceView> {
    let h = handles()?;
    let idx = selected_index(h.list)?;
    STATE.with(|s| {
        let s = s.try_borrow().ok()?;
        let fp = s.rows.get(idx)?.0;
        s.devices.iter().find(|d| d.fingerprint == fp).cloned()
    })
}

fn update_buttons() {
    let Some(h) = handles() else { return };
    let sel = selected_device();
    let can_connect = sel.as_ref().is_some_and(|d| d.online && d.we_may_control && !d.revoked);
    enable(h.connect, can_connect);
    enable(h.remove, sel.is_some());
    enable(h.props, sel.is_some());
}

// -------------------------------------------------------------- actions

fn do_connect() {
    let Some(d) = selected_device() else { return };
    if !d.we_may_control {
        if let Some(h) = handles() {
            info_box(
                Some(h.main),
                &format!(
                    "{} paired with this computer, so it can control this computer.\n\n\
                     This computer cannot control {} unless you pair in that direction as well: \
                     on {} choose Tools > Show Pairing Code, then use Add Device here.",
                    d.name, d.name, d.name
                ),
            );
        }
        return;
    }
    set_status_message(&format!("Connecting to {}...", d.name));
    send_node(Command::Connect { device: d.fingerprint });
}

fn do_remove() {
    let Some(d) = selected_device() else { return };
    let Some(h) = handles() else { return };
    let text = format!(
        "Remove {} from this computer?\n\nThis computer will forget it completely. \
         To use it again you will need to pair again with a new pairing code.\n\n\
         (To keep it in the list but block it, use Properties > Revoke Trust instead.)",
        d.name
    );
    if confirm(Some(h.main), &text) {
        send_node(Command::Remove { device: d.fingerprint });
        set_status_message(&format!("Removed {}.", d.name));
    }
}

fn do_revoke() {
    let Some(d) = selected_device() else { return };
    let Some(h) = handles() else { return };
    let text = format!(
        "Revoke trust for {}?\n\nIts credentials stop working immediately. It stays in the list, \
         marked Revoked. To restore access, pair it again with a new pairing code.",
        d.name
    );
    if confirm(Some(h.main), &text) {
        send_node(Command::Revoke { device: d.fingerprint });
    }
}

fn do_properties() {
    let (Some(d), Some(h)) = (selected_device(), handles()) else { return };
    dialogs::properties(h.main, d);
}

fn open_log_folder() {
    let folder = match status() {
        Some(s) if s.mode == "installed" => bark_core::paths::log_dir(),
        _ => crate::node_dirs_hint().join("logs"),
    };
    let f = Wide::new(&folder.to_string_lossy());
    unsafe {
        windows::Win32::UI::Shell::ShellExecuteW(None, w!("open"), f.pcwstr(), PCWSTR::null(), PCWSTR::null(), SW_SHOWNORMAL);
    }
}

fn context_menu(h: &Handles) {
    let Some(d) = selected_device() else { return };
    unsafe {
        let m = CreatePopupMenu().unwrap_or_default();
        let add = |id: u16, text: &str, enabled: bool| {
            let t = Wide::new(text);
            let flags = if enabled { MF_STRING } else { MF_STRING | MF_GRAYED };
            let _ = AppendMenuW(m, flags, id as usize, t.pcwstr());
        };
        add(IDM_CONNECT, "&Connect", d.online && d.we_may_control && !d.revoked);
        let _ = AppendMenuW(m, MF_SEPARATOR, 0, PCWSTR::null());
        add(IDM_PROPS, "&Properties...", true);
        add(IDM_REVOKE, "Re&voke Trust...", !d.revoked);
        add(IDM_REMOVE, "&Remove", true);
        let _ = SetMenuDefaultItem(m, IDM_CONNECT as u32, 0);
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        let _ = TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, None, h.main, None);
        let _ = DestroyMenu(m);
    }
}

fn on_command(id: u16) {
    let Some(h) = handles() else { return };
    match id {
        IDM_ADD => dialogs::add_device(h.main),
        IDM_REMOVE => do_remove(),
        IDM_PROPS => do_properties(),
        IDM_EXIT => unsafe {
            let _ = DestroyWindow(h.main);
        },
        IDM_CONNECT => do_connect(),
        IDM_SHOW_CODE => dialogs::show_pairing_code(h.main),
        IDM_REFRESH => send_node(Command::Refresh),
        IDM_DIAG => dialogs::diagnostics(h.main),
        IDM_SETTINGS => dialogs::settings(h.main),
        IDM_LOGS => open_log_folder(),
        IDM_ABOUT => dialogs::about(h.main),
        IDM_REVOKE => do_revoke(),
        _ => {}
    }
}

// ------------------------------------------------------------ node events

fn drain_events() {
    // Take one at a time: handling an event may open a message box, whose own
    // message loop can deliver the next WM_NODE while this one is still being
    // handled. The queue's lock is released inside `and_then`, before the
    // event is handled.
    while let Some(e) = QUEUE.lock().ok().and_then(|mut q| q.pop_front()) {
        handle_event(e);
    }
}

fn handle_event(e: Event) {
    let Some(h) = handles() else { return };
    match e {
        Event::Status(s) => {
            show_status(&s);
            STATE.with(|st| st.borrow_mut().status = Some(s));
        }
        Event::Devices(d) => {
            STATE.with(|st| st.borrow_mut().devices = d);
            fill_list();
        }
        Event::PairingCode(code) => {
            if let Some(dlg) = active_dialog() {
                dialogs::deliver(dlg, dialogs::Mail::PairingCode(code));
            }
        }
        Event::PairFinished { ok, message, .. } => {
            if let Some(dlg) = active_dialog() {
                dialogs::deliver(dlg, dialogs::Mail::PairFinished { ok, message });
            } else if ok {
                info_box(Some(h.main), &message);
            } else {
                error_box(Some(h.main), &message);
            }
        }
        Event::PairedBy { device } => {
            set_status_message(&format!("{} paired with this computer.", device.name));
            if let Some(dlg) = active_dialog() {
                dialogs::deliver(dlg, dialogs::Mail::PairedBy(device));
            }
        }
        Event::ConnectFinished { device, ok, message } => {
            let d = STATE.with(|s| s.borrow().devices.iter().find(|x| x.fingerprint == device).cloned());
            let name = d.as_ref().map(|d| d.name.clone()).unwrap_or_else(|| "the device".into());
            if ok {
                set_status_message(&format!("{name} accepted the connection."));
                info_box(Some(h.main), &format!("Connection to {name}\n\n{message}"));
            } else {
                set_status_message(&format!("Could not connect to {name}."));
                let last = d.map(|d| if d.online { "ONLINE" } else { "OFFLINE" }).unwrap_or("--");
                let choice = dialogs::connection_failed(h.main, &name, last, &message);
                match choice {
                    dialogs::FailedChoice::Retry => send_node(Command::Connect { device }),
                    dialogs::FailedChoice::Diagnostics => dialogs::diagnostics(h.main),
                    dialogs::FailedChoice::Close => {}
                }
            }
        }
        Event::Notice { level, text } => match level {
            NoticeLevel::Info => set_status_message(&text),
            NoticeLevel::Warning => {
                message_box(Some(h.main), &text, "BARK", MB_OK | MB_ICONWARNING);
            }
            NoticeLevel::Error => error_box(Some(h.main), &text),
        },
        Event::Fatal(text) => {
            error_box(Some(h.main), &format!("BARK cannot continue.\n\n{text}"));
            unsafe {
                let _ = DestroyWindow(h.main);
            }
        }
    }
}

// --------------------------------------------------------- window procedure

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_NODE => {
                drain_events();
                LRESULT(0)
            }
            WM_CTLCOLORSTATIC => {
                // Labels draw on exactly the window's own grey.
                let hdc = windows::Win32::Graphics::Gdi::HDC(wp.0 as *mut _);
                windows::Win32::Graphics::Gdi::SetBkColor(hdc, COLORREF(GetSysColor(COLOR_BTNFACE)));
                LRESULT(windows::Win32::Graphics::Gdi::GetSysColorBrush(COLOR_BTNFACE).0 as isize)
            }
            WM_SIZE => {
                if let Some(h) = handles() {
                    layout(&h);
                }
                LRESULT(0)
            }
            WM_GETMINMAXINFO => {
                let mmi = &mut *(lp.0 as *mut MINMAXINFO);
                let dpi = GetDpiForWindow(hwnd).max(96);
                mmi.ptMinTrackSize = POINT { x: px(640, dpi), y: px(400, dpi) };
                LRESULT(0)
            }
            WM_DPICHANGED => {
                if let Some(mut h) = handles() {
                    let old = h.fonts;
                    h.dpi = hiword(wp.0) as u32;
                    h.fonts = Fonts::for_dpi(h.dpi);
                    HANDLES.with(|c| c.set(Some(h)));
                    apply_fonts(&h);
                    old.destroy();
                    for (i, (_, width)) in COLUMNS.iter().enumerate() {
                        SendMessageW(h.list, LVM_SETCOLUMNWIDTH, Some(WPARAM(i)), Some(LPARAM(px(*width, h.dpi) as isize)));
                    }
                    let r = &*(lp.0 as *const RECT);
                    let _ = SetWindowPos(hwnd, None, r.left, r.top, r.right - r.left, r.bottom - r.top, SWP_NOZORDER | SWP_NOACTIVATE);
                    layout(&h);
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = loword(wp.0);
                match id as i32 {
                    IDC_CONNECT => do_connect(),
                    IDC_ADD => on_command(IDM_ADD),
                    IDC_REMOVE => do_remove(),
                    IDC_PROPS => do_properties(),
                    IDC_CODE => on_command(IDM_SHOW_CODE),
                    _ => on_command(id),
                }
                LRESULT(0)
            }
            WM_NOTIFY => {
                let hdr = &*(lp.0 as *const NMHDR);
                if hdr.idFrom as i32 != IDC_LIST {
                    return DefWindowProcW(hwnd, msg, wp, lp);
                }
                match hdr.code {
                    NM_DBLCLK | NM_RETURN => {
                        do_connect();
                        LRESULT(0)
                    }
                    NM_RCLICK => {
                        if let Some(h) = handles() {
                            context_menu(&h);
                        }
                        LRESULT(0)
                    }
                    LVN_ITEMCHANGED => {
                        update_buttons();
                        LRESULT(0)
                    }
                    NM_CUSTOMDRAW => LRESULT(custom_draw(&mut *(lp.0 as *mut NMLVCUSTOMDRAW)) as isize),
                    _ => DefWindowProcW(hwnd, msg, wp, lp),
                }
            }
            WM_SETFOCUS => {
                if let Some(h) = handles() {
                    let _ = SetFocus(Some(h.list));
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

/// Colours the Status column: ONLINE in green, OFFLINE in grey, REVOKED in
/// red. Everything else draws normally.
fn custom_draw(cd: &mut NMLVCUSTOMDRAW) -> u32 {
    let stage = cd.nmcd.dwDrawStage;
    if stage == CDDS_PREPAINT {
        return CDRF_NOTIFYITEMDRAW;
    }
    if stage == CDDS_ITEMPREPAINT {
        return CDRF_NOTIFYSUBITEMDRAW;
    }
    if stage.0 == (CDDS_ITEMPREPAINT.0 | CDDS_SUBITEM.0) {
        let row = cd.nmcd.dwItemSpec;
        let info = STATE.with(|s| s.try_borrow().ok().and_then(|s| s.rows.get(row).copied()));
        let default = COLORREF(unsafe { GetSysColor(COLOR_WINDOWTEXT) });
        cd.clrText = match (cd.iSubItem, info) {
            (1, Some((_, _, true))) => COLORREF(0x0000_00B0), // red
            (1, Some((_, true, _))) => COLORREF(0x0000_8000), // green
            (1, Some((_, false, _))) => COLORREF(0x0080_8080), // grey
            _ => default,
        };
        return CDRF_DODEFAULT;
    }
    CDRF_DODEFAULT
}
