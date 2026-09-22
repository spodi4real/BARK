//! The notice shown on a computer while someone is controlling it.
//!
//! A small bar at the top of the screen, above every other window, naming who
//! is connected and offering End Session. It never takes the keyboard from
//! whoever is working at the computer, and it stays for as long as the session
//! does. BARK does not do invisible sessions.

use crate::app::send_node;
use crate::win::*;
use bark_node::api::Command;
use std::cell::RefCell;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::HiDpi::GetDpiForWindow;
use windows::Win32::UI::WindowsAndMessaging::*;

const CLASS: PCWSTR = w!("BARK.Banner");
const IDC_END: i32 = 1;

struct Banner {
    hwnd: HWND,
    session_id: u64,
    fonts: Fonts,
}

thread_local! {
    static BANNERS: RefCell<Vec<Banner>> = const { RefCell::new(Vec::new()) };
}

fn register() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| unsafe {
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(proc_),
            hInstance: hinstance(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH((COLOR_INFOBK.0 + 1) as usize as *mut _),
            lpszClassName: CLASS,
            ..Default::default()
        };
        RegisterClassExW(&wc);
    });
}

/// Shows the notice for a session that has just started on this computer.
pub fn show(session_id: u64, name: &str, path: &str) {
    register();
    unsafe {
        let mut work = RECT::default();
        let _ = SystemParametersInfoW(SPI_GETWORKAREA, 0, Some(&mut work as *mut _ as *mut _), SYSTEM_PARAMETERS_INFO_UPDATE_FLAGS(0));
        let Ok(hwnd) = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            CLASS,
            w!("BARK"),
            WS_POPUP | WS_BORDER,
            0,
            0,
            10,
            10,
            None,
            None,
            Some(hinstance()),
            None,
        ) else {
            return;
        };
        let dpi = GetDpiForWindow(hwnd).max(96);
        let fonts = Fonts::for_dpi(dpi);
        let text = Wide::new(&format!("{name} is controlling this computer ({path})."));
        let label = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("STATIC"),
            text.pcwstr(),
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(0x200), // SS_CENTERIMAGE: centred vertically
            0,
            0,
            0,
            0,
            Some(hwnd),
            None,
            Some(hinstance()),
            None,
        )
        .unwrap_or_default();
        let button = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("BUTTON"),
            w!("End Session"),
            WS_CHILD | WS_VISIBLE | WINDOW_STYLE(BS_PUSHBUTTON as u32),
            0,
            0,
            0,
            0,
            Some(hwnd),
            Some(HMENU(IDC_END as isize as *mut _)),
            Some(hinstance()),
            None,
        )
        .unwrap_or_default();
        set_font(label, fonts.bold);
        set_font(button, fonts.normal);

        // Size to the text.
        let hdc = GetDC(Some(label));
        let old = SelectObject(hdc, fonts.bold.into());
        let mut sz = SIZE::default();
        let wtext: Vec<u16> = format!("{name} is controlling this computer ({path}).").encode_utf16().collect();
        let _ = GetTextExtentPoint32W(hdc, &wtext, &mut sz);
        SelectObject(hdc, old);
        ReleaseDC(Some(label), hdc);

        let (pad, bw, bh) = (px(10, dpi), px(96, dpi), px(26, dpi));
        let height = bh + px(12, dpi);
        let width = sz.cx + bw + pad * 3;
        let index = BANNERS.with(|b| b.borrow().len()) as i32;
        let x = work.left + ((work.right - work.left) - width) / 2;
        let y = work.top + index * (height + px(4, dpi));
        let _ = MoveWindow(label, pad, 0, sz.cx, height, false);
        let _ = MoveWindow(button, pad * 2 + sz.cx, (height - bh) / 2 - 1, bw, bh, false);
        let _ = SetWindowPos(hwnd, Some(HWND_TOPMOST), x, y, width, height, SWP_NOACTIVATE | SWP_SHOWWINDOW);

        BANNERS.with(|b| b.borrow_mut().push(Banner { hwnd, session_id, fonts }));
    }
}

/// Removes the notice once the session has ended.
pub fn close(session_id: u64) {
    let found = BANNERS.with(|b| {
        let mut b = b.borrow_mut();
        b.iter().position(|x| x.session_id == session_id).map(|i| b.remove(i))
    });
    if let Some(banner) = found {
        unsafe {
            let _ = DestroyWindow(banner.hwnd);
        }
        banner.fonts.destroy();
    }
}

unsafe extern "system" fn proc_(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_COMMAND if loword(wp.0) as i32 == IDC_END => {
                let id = BANNERS.with(|b| b.borrow().iter().find(|x| x.hwnd == hwnd).map(|x| x.session_id));
                if let Some(session_id) = id {
                    send_node(Command::EndHostSession { session_id });
                }
                LRESULT(0)
            }
            WM_CTLCOLORSTATIC => {
                let hdc = HDC(wp.0 as *mut _);
                SetBkColor(hdc, COLORREF(GetSysColor(COLOR_INFOBK)));
                SetTextColor(hdc, COLORREF(GetSysColor(COLOR_INFOTEXT)));
                LRESULT(GetSysColorBrush(COLOR_INFOBK).0 as isize)
            }
            // Closing it would hide an active session; only the session
            // ending removes it.
            WM_CLOSE => LRESULT(0),
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}
