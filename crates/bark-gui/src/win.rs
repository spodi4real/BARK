//! Small helpers over the Win32 API, so the window code reads as layout and
//! behaviour rather than as pointer juggling.

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, WPARAM};
use windows::Win32::Graphics::Gdi::{CreateFontIndirectW, DeleteObject, HFONT, HGDIOBJ, LOGFONTW};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::SystemParametersInfoForDpi;
use windows::Win32::UI::WindowsAndMessaging::*;

/// A null-terminated UTF-16 string that stays alive while it is borrowed.
pub struct Wide(Vec<u16>);

impl Wide {
    pub fn new(s: &str) -> Self {
        Wide(s.encode_utf16().chain(std::iter::once(0)).collect())
    }

    pub fn pcwstr(&self) -> PCWSTR {
        PCWSTR(self.0.as_ptr())
    }

    /// For APIs that take a mutable pointer but only read it (list-view text).
    pub fn pwstr(&mut self) -> PWSTR {
        PWSTR(self.0.as_mut_ptr())
    }
}

pub fn hinstance() -> HINSTANCE {
    unsafe { GetModuleHandleW(None).map(|h| HINSTANCE(h.0)).unwrap_or_default() }
}

/// Pixels at 96 DPI, converted for the window's actual DPI.
pub fn px(v: i32, dpi: u32) -> i32 {
    (v as i64 * dpi as i64 / 96) as i32
}

pub fn loword(v: usize) -> u16 {
    (v & 0xffff) as u16
}

pub fn hiword(v: usize) -> u16 {
    ((v >> 16) & 0xffff) as u16
}

/// Fonts used by the main window, created for one DPI.
#[derive(Clone, Copy)]
pub struct Fonts {
    pub normal: HFONT,
    pub bold: HFONT,
    pub large: HFONT,
}

impl Fonts {
    /// The system's message font — Segoe UI 9pt on modern Windows — which is
    /// what every built-in Windows dialog and utility uses. No custom fonts.
    pub fn for_dpi(dpi: u32) -> Fonts {
        let mut m = NONCLIENTMETRICSW { cbSize: std::mem::size_of::<NONCLIENTMETRICSW>() as u32, ..Default::default() };
        let ok = unsafe {
            SystemParametersInfoForDpi(
                SPI_GETNONCLIENTMETRICS.0,
                m.cbSize,
                Some(&mut m as *mut _ as *mut _),
                0,
                dpi,
            )
        }
        .is_ok();
        let mut lf: LOGFONTW = if ok { m.lfMessageFont } else { LOGFONTW::default() };
        if !ok {
            lf.lfHeight = -px(12, dpi);
            let face: Vec<u16> = "Segoe UI".encode_utf16().collect();
            lf.lfFaceName[..face.len()].copy_from_slice(&face);
        }
        let normal = unsafe { CreateFontIndirectW(&lf) };
        let mut b = lf;
        b.lfWeight = 700;
        let bold = unsafe { CreateFontIndirectW(&b) };
        let mut l = lf;
        l.lfHeight = lf.lfHeight * 2;
        l.lfWeight = 700;
        let large = unsafe { CreateFontIndirectW(&l) };
        Fonts { normal, bold, large }
    }

    pub fn destroy(self) {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(self.normal.0));
            let _ = DeleteObject(HGDIOBJ(self.bold.0));
            let _ = DeleteObject(HGDIOBJ(self.large.0));
        }
    }
}

pub fn set_font(hwnd: HWND, font: HFONT) {
    unsafe {
        SendMessageW(hwnd, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
    }
}

pub fn set_text(hwnd: HWND, text: &str) {
    let w = Wide::new(text);
    unsafe {
        let _ = SetWindowTextW(hwnd, w.pcwstr());
    }
}

pub fn get_text(hwnd: HWND) -> String {
    unsafe {
        let len = GetWindowTextLengthW(hwnd);
        if len <= 0 {
            return String::new();
        }
        let mut buf = vec![0u16; len as usize + 1];
        let n = GetWindowTextW(hwnd, &mut buf);
        String::from_utf16_lossy(&buf[..n as usize])
    }
}

pub fn dlg_item(dlg: HWND, id: i32) -> HWND {
    unsafe { GetDlgItem(Some(dlg), id).unwrap_or_default() }
}

pub fn dlg_text(dlg: HWND, id: i32) -> String {
    get_text(dlg_item(dlg, id))
}

pub fn set_dlg_text(dlg: HWND, id: i32, text: &str) {
    set_text(dlg_item(dlg, id), text)
}

pub fn enable(hwnd: HWND, on: bool) {
    unsafe {
        let _ = windows::Win32::UI::Input::KeyboardAndMouse::EnableWindow(hwnd, on);
    }
}

pub fn is_checked(dlg: HWND, id: i32) -> bool {
    unsafe { windows::Win32::UI::Controls::IsDlgButtonChecked(dlg, id) == 1 }
}

pub fn set_checked(dlg: HWND, id: i32, on: bool) {
    unsafe {
        let _ = windows::Win32::UI::Controls::CheckDlgButton(
            dlg,
            id,
            if on {
                windows::Win32::UI::Controls::BST_CHECKED
            } else {
                windows::Win32::UI::Controls::BST_UNCHECKED
            },
        );
    }
}

/// A standard Windows message box.
pub fn message_box(owner: Option<HWND>, text: &str, caption: &str, style: MESSAGEBOX_STYLE) -> MESSAGEBOX_RESULT {
    let t = Wide::new(text);
    let c = Wide::new(caption);
    unsafe { MessageBoxW(owner, t.pcwstr(), c.pcwstr(), style) }
}

pub fn error_box(owner: Option<HWND>, text: &str) {
    message_box(owner, text, "BARK", MB_OK | MB_ICONERROR);
}

pub fn info_box(owner: Option<HWND>, text: &str) {
    message_box(owner, text, "BARK", MB_OK | MB_ICONINFORMATION);
}

pub fn confirm(owner: Option<HWND>, text: &str) -> bool {
    message_box(owner, text, "BARK", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2) == IDYES
}

/// Puts text on the clipboard, for "Copy to Clipboard" in the diagnostics.
pub fn copy_to_clipboard(owner: HWND, text: &str) -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData};
    use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
    const CF_UNICODETEXT: u32 = 13;

    let wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        if OpenClipboard(Some(owner)).is_err() {
            return false;
        }
        let _ = EmptyClipboard();
        let ok = (|| -> Option<()> {
            let mem = GlobalAlloc(GMEM_MOVEABLE, wide.len() * 2).ok()?;
            let p = GlobalLock(mem) as *mut u16;
            if p.is_null() {
                return None;
            }
            std::ptr::copy_nonoverlapping(wide.as_ptr(), p, wide.len());
            let _ = GlobalUnlock(mem);
            SetClipboardData(CF_UNICODETEXT, Some(HANDLE(mem.0))).ok()?;
            Some(())
        })()
        .is_some();
        let _ = CloseClipboard();
        ok
    }
}

/// Reads text from the clipboard, for "Paste" in Settings.
pub fn clipboard_text(owner: HWND) -> Option<String> {
    use windows::Win32::System::DataExchange::{CloseClipboard, GetClipboardData, OpenClipboard};
    use windows::Win32::Foundation::HGLOBAL;
    use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
    const CF_UNICODETEXT: u32 = 13;
    unsafe {
        OpenClipboard(Some(owner)).ok()?;
        let text = (|| {
            let h = GetClipboardData(CF_UNICODETEXT).ok()?;
            let mem = HGLOBAL(h.0);
            let p = GlobalLock(mem) as *const u16;
            if p.is_null() {
                return None;
            }
            let mut len = 0;
            while *p.add(len) != 0 {
                len += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
            let _ = GlobalUnlock(mem);
            Some(s)
        })();
        let _ = CloseClipboard();
        text
    }
}
