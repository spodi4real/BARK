//! BARK's icon, and its place in the notification area.
//!
//! A computer that can be controlled must keep BARK running, so closing the
//! main window only hides it: BARK stays in the notification area next to the
//! clock, where it can be opened again or exited on purpose.
//!
//! The icon is drawn when BARK starts rather than shipped as a resource file,
//! which keeps the build free of a resource compiler step.

use windows::core::w;
use windows::Win32::Foundation::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::UI::Shell::*;
use windows::Win32::UI::WindowsAndMessaging::*;

pub const WM_TRAY: u32 = WM_APP + 2;
const TRAY_ID: u32 = 1;

/// A white "B" on a dark blue square.
pub fn app_icon(size: i32) -> HICON {
    unsafe {
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: size,
                biHeight: -size,
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
        let Ok(color) = CreateDIBSection(None, &bmi, DIB_RGB_COLORS, &mut bits, None, 0) else {
            return LoadIconW(None, IDI_APPLICATION).unwrap_or_default();
        };
        let dc = CreateCompatibleDC(None);
        let old = SelectObject(dc, color.into());
        let rc = RECT { left: 0, top: 0, right: size, bottom: size };
        let brush = CreateSolidBrush(COLORREF(0x0079_4E1F)); // RGB(31, 78, 121)
        FillRect(dc, &rc, brush);
        let _ = DeleteObject(brush.into());
        let font = CreateFontW(
            -(size * 5 / 6),
            0,
            0,
            0,
            FW_BOLD.0 as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            ANTIALIASED_QUALITY,
            (DEFAULT_PITCH.0 | FF_SWISS.0) as u32,
            w!("Segoe UI"),
        );
        let old_font = SelectObject(dc, font.into());
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, COLORREF(0x00FF_FFFF));
        let mut text: Vec<u16> = "B".encode_utf16().collect();
        let mut r = rc;
        DrawTextW(dc, &mut text, &mut r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(dc, old_font);
        let _ = DeleteObject(font.into());
        SelectObject(dc, old);
        let _ = DeleteDC(dc);

        // GDI leaves alpha at zero; make it opaque, with the corners
        // trimmed so the square reads as a tile.
        let px = std::slice::from_raw_parts_mut(bits as *mut u8, (size * size * 4) as usize);
        for y in 0..size {
            for x in 0..size {
                let corner = (x == 0 || x == size - 1) && (y == 0 || y == size - 1);
                px[((y * size + x) * 4 + 3) as usize] = if corner { 0 } else { 0xFF };
            }
        }
        let mask = CreateBitmap(size, size, 1, 1, None);
        let info = ICONINFO { fIcon: true.into(), xHotspot: 0, yHotspot: 0, hbmMask: mask, hbmColor: color };
        let icon = CreateIconIndirect(&info).unwrap_or_default();
        let _ = DeleteObject(color.into());
        let _ = DeleteObject(mask.into());
        icon
    }
}

fn data(hwnd: HWND) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_ID,
        ..Default::default()
    }
}

fn copy_into(dst: &mut [u16], text: &str) {
    for (d, s) in dst.iter_mut().zip(text.encode_utf16().chain(std::iter::once(0))) {
        *d = s;
    }
    if let Some(last) = dst.last_mut() {
        *last = 0;
    }
}

/// Puts BARK's icon in the notification area (again, after Explorer
/// restarts).
pub fn add(hwnd: HWND, icon: HICON, tip: &str) {
    let mut d = data(hwnd);
    d.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    d.uCallbackMessage = WM_TRAY;
    d.hIcon = icon;
    copy_into(&mut d.szTip, tip);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_ADD, &d);
    }
}

pub fn set_tip(hwnd: HWND, tip: &str) {
    let mut d = data(hwnd);
    d.uFlags = NIF_TIP;
    copy_into(&mut d.szTip, tip);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
    }
}

/// A short notice from the notification-area icon.
pub fn balloon(hwnd: HWND, title: &str, text: &str) {
    let mut d = data(hwnd);
    d.uFlags = NIF_INFO;
    copy_into(&mut d.szInfoTitle, title);
    copy_into(&mut d.szInfo, text);
    d.dwInfoFlags = NIIF_INFO;
    unsafe {
        let _ = Shell_NotifyIconW(NIM_MODIFY, &d);
    }
}

pub fn remove(hwnd: HWND) {
    let d = data(hwnd);
    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &d);
    }
}

/// The right-click menu on the icon; the choice arrives as WM_COMMAND.
pub fn menu(hwnd: HWND, open_id: u16, exit_id: u16) {
    unsafe {
        let m = CreatePopupMenu().unwrap_or_default();
        let _ = AppendMenuW(m, MF_STRING, open_id as usize, w!("&Open BARK"));
        let _ = AppendMenuW(m, MF_SEPARATOR, 0, windows::core::PCWSTR::null());
        let _ = AppendMenuW(m, MF_STRING, exit_id as usize, w!("E&xit BARK"));
        let _ = SetMenuDefaultItem(m, open_id as u32, 0);
        let mut pt = POINT::default();
        let _ = GetCursorPos(&mut pt);
        // Required so the menu closes when clicking elsewhere.
        let _ = SetForegroundWindow(hwnd);
        let _ = TrackPopupMenu(m, TPM_RIGHTBUTTON, pt.x, pt.y, None, hwnd, None);
        let _ = DestroyMenu(m);
    }
}

pub fn taskbar_created_message() -> u32 {
    unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) }
}
