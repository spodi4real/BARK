//! Applying the controller's mouse and keyboard to this computer.
//!
//! Uses `SendInput`, the documented way to synthesise input on Windows. What
//! it can reach is decided by Windows, not by BARK: a normal process cannot
//! type into an administrator's window or onto the sign-in screen (User
//! Interface Privilege Isolation). The installed service's session agent runs
//! with the rights to do so; the standalone GUI does not, and says so.
//!
//! Every key and button pressed is remembered, so the session can release
//! them all when it ends or the controller's window loses focus. Without
//! that, a Ctrl held at the moment the network dropped would stay held on
//! this computer until someone noticed.

use bark_proto::input::{InputEvent, MouseButton};
use std::collections::HashSet;

/// Where the captured picture sits on this computer's desktop, in physical
/// pixels. Controller coordinates are relative to its top-left corner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenArea {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

/// The whole virtual desktop (all monitors), in physical pixels.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Desktop {
    pub left: i32,
    pub top: i32,
    pub width: i32,
    pub height: i32,
}

/// Maps a pixel in the captured picture to `SendInput`'s 0..65535 range over
/// the virtual desktop. This is the single conversion; the controller sends
/// exact pixels precisely so it is not done twice.
pub fn normalise(x: i32, y: i32, area: ScreenArea, desk: Desktop) -> (i32, i32) {
    let x = x.clamp(0, area.width - 1) + area.left - desk.left;
    let y = y.clamp(0, area.height - 1) + area.top - desk.top;
    // Microsoft's formula maps 0..width-1 onto 0..65535 exactly.
    let nx = (x as i64 * 65535 / (desk.width.max(2) as i64 - 1)) as i32;
    let ny = (y as i64 * 65535 / (desk.height.max(2) as i64 - 1)) as i32;
    (nx, ny)
}

/// Remembers what is held down.
#[derive(Debug, Default)]
pub struct Held {
    keys: HashSet<(u16, bool)>,
    buttons: HashSet<u8>,
}

impl Held {
    pub fn note(&mut self, e: &InputEvent) {
        match *e {
            InputEvent::Key { scancode, down, extended } => {
                if down {
                    self.keys.insert((scancode, extended));
                } else {
                    self.keys.remove(&(scancode, extended));
                }
            }
            InputEvent::MouseButton { button, down, .. } => {
                if down {
                    self.buttons.insert(button as u8);
                } else {
                    self.buttons.remove(&(button as u8));
                }
            }
            _ => {}
        }
    }

    /// The events that release everything held, and forget it.
    pub fn release_all(&mut self, x: i32, y: i32) -> Vec<InputEvent> {
        let mut out: Vec<InputEvent> = self
            .keys
            .drain()
            .map(|(scancode, extended)| InputEvent::Key { scancode, down: false, extended })
            .collect();
        out.extend(self.buttons.drain().filter_map(|b| {
            MouseButton::from_u8(b).map(|button| InputEvent::MouseButton { button, down: false, x, y })
        }));
        out
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.buttons.is_empty()
    }
}

#[cfg(windows)]
pub use platform::Injector;

#[cfg(windows)]
mod platform {
    use super::*;
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    /// Applies input to the desktop this thread is attached to.
    pub struct Injector {
        area: ScreenArea,
        held: Held,
        last: (i32, i32),
        /// Why input could not be applied, once, for the controller.
        pub last_failure: Option<String>,
    }

    fn desktop() -> Desktop {
        unsafe {
            Desktop {
                left: GetSystemMetrics(SM_XVIRTUALSCREEN),
                top: GetSystemMetrics(SM_YVIRTUALSCREEN),
                width: GetSystemMetrics(SM_CXVIRTUALSCREEN),
                height: GetSystemMetrics(SM_CYVIRTUALSCREEN),
            }
        }
    }

    fn mouse(dx: i32, dy: i32, data: u32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_MOUSE,
            Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: data, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
        }
    }

    fn key(scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT { wVk: VIRTUAL_KEY(0), wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 },
            },
        }
    }

    impl Injector {
        pub fn new(area: ScreenArea) -> Self {
            Injector { area, held: Held::default(), last: (0, 0), last_failure: None }
        }

        pub fn set_area(&mut self, area: ScreenArea) {
            self.area = area;
        }

        /// Applies one event. Returns false if Windows refused it (usually
        /// because the target window belongs to an administrator).
        pub fn apply(&mut self, e: &InputEvent) -> bool {
            let abs = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
            let inputs: Vec<INPUT> = match *e {
                InputEvent::MouseMove { x, y } => {
                    self.last = (x, y);
                    let (nx, ny) = normalise(x, y, self.area, desktop());
                    vec![mouse(nx, ny, 0, abs)]
                }
                InputEvent::MouseButton { button, down, x, y } => {
                    self.last = (x, y);
                    let (nx, ny) = normalise(x, y, self.area, desktop());
                    let (flag, data) = match (button, down) {
                        (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                        (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                        (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                        (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                        (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                        (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                        (MouseButton::X1, true) => (MOUSEEVENTF_XDOWN, XBUTTON1 as u32),
                        (MouseButton::X1, false) => (MOUSEEVENTF_XUP, XBUTTON1 as u32),
                        (MouseButton::X2, true) => (MOUSEEVENTF_XDOWN, XBUTTON2 as u32),
                        (MouseButton::X2, false) => (MOUSEEVENTF_XUP, XBUTTON2 as u32),
                    };
                    // Position and button in one call, so the click lands
                    // exactly where the controller clicked.
                    vec![mouse(nx, ny, data, abs | flag)]
                }
                InputEvent::MouseWheel { delta_v, delta_h, x, y } => {
                    self.last = (x, y);
                    let (nx, ny) = normalise(x, y, self.area, desktop());
                    let mut v = vec![mouse(nx, ny, 0, abs)];
                    if delta_v != 0 {
                        v.push(mouse(0, 0, delta_v as u32, MOUSEEVENTF_WHEEL));
                    }
                    if delta_h != 0 {
                        v.push(mouse(0, 0, delta_h as u32, MOUSEEVENTF_HWHEEL));
                    }
                    v
                }
                InputEvent::Key { scancode, down, extended } => {
                    let mut flags = KEYEVENTF_SCANCODE;
                    if !down {
                        flags |= KEYEVENTF_KEYUP;
                    }
                    if extended {
                        flags |= KEYEVENTF_EXTENDEDKEY;
                    }
                    vec![key(scancode, flags)]
                }
                InputEvent::Text { ch } => {
                    let mut units = [0u16; 2];
                    ch.encode_utf16(&mut units)
                        .iter()
                        .flat_map(|&u| [key(u, KEYEVENTF_UNICODE), key(u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)])
                        .collect()
                }
                InputEvent::ReleaseAll => {
                    let (x, y) = self.last;
                    let release = self.held.release_all(x, y);
                    let mut ok = true;
                    for r in &release {
                        ok &= self.apply(r);
                    }
                    return ok;
                }
                InputEvent::SecureAttention => {
                    // Needs the installed service (SendSAS from a SYSTEM
                    // process). Reported, not faked with a key combination
                    // Windows would ignore anyway.
                    self.last_failure = Some(
                        "Ctrl+Alt+Delete can only be sent when BARK is installed as a service on the remote computer."
                            .into(),
                    );
                    return false;
                }
            };
            self.held.note(e);
            let sent = unsafe { SendInput(&inputs, std::mem::size_of::<INPUT>() as i32) };
            if sent as usize != inputs.len() {
                self.last_failure = Some(
                    "Windows blocked input to the window in front, which usually means it is running \
                     as administrator. Install BARK as a service on the remote computer to control such windows."
                        .into(),
                );
                return false;
            }
            true
        }

        pub fn held(&self) -> &Held {
            &self.held
        }
    }

    impl Drop for Injector {
        fn drop(&mut self) {
            // Never leave a key down on the way out.
            if !self.held.is_empty() {
                self.apply(&InputEvent::ReleaseAll);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINGLE: Desktop = Desktop { left: 0, top: 0, width: 1920, height: 1080 };
    const AREA: ScreenArea = ScreenArea { left: 0, top: 0, width: 1920, height: 1080 };

    #[test]
    fn corners_map_to_the_ends_of_the_range() {
        assert_eq!(normalise(0, 0, AREA, SINGLE), (0, 0));
        assert_eq!(normalise(1919, 1079, AREA, SINGLE), (65535, 65535));
    }

    #[test]
    fn a_second_monitor_to_the_left_is_offset_correctly() {
        // Desktop spans a 1920-wide monitor at -1920 and the primary at 0.
        let desk = Desktop { left: -1920, top: 0, width: 3840, height: 1080 };
        let primary = ScreenArea { left: 0, top: 0, width: 1920, height: 1080 };
        let (nx, _) = normalise(0, 0, primary, desk);
        // Pixel 0 of the primary is pixel 1920 of the desktop: just past half.
        assert_eq!(nx, (1920i64 * 65535 / 3839) as i32);
        let left = ScreenArea { left: -1920, top: 0, width: 1920, height: 1080 };
        assert_eq!(normalise(0, 0, left, desk).0, 0);
    }

    #[test]
    fn positions_outside_the_picture_are_clamped_not_wrapped() {
        assert_eq!(normalise(-50, -50, AREA, SINGLE), (0, 0));
        assert_eq!(normalise(5000, 5000, AREA, SINGLE), (65535, 65535));
    }

    #[test]
    fn everything_held_is_released_and_forgotten() {
        let mut h = Held::default();
        h.note(&InputEvent::Key { scancode: 0x1D, down: true, extended: false }); // Ctrl
        h.note(&InputEvent::Key { scancode: 0x38, down: true, extended: false }); // Alt
        h.note(&InputEvent::Key { scancode: 0x38, down: false, extended: false });
        h.note(&InputEvent::MouseButton { button: MouseButton::Left, down: true, x: 5, y: 5 });
        let r = h.release_all(10, 20);
        assert_eq!(r.len(), 2, "Ctrl and the left button; Alt was already up: {r:?}");
        assert!(r.contains(&InputEvent::Key { scancode: 0x1D, down: false, extended: false }));
        assert!(r.contains(&InputEvent::MouseButton { button: MouseButton::Left, down: false, x: 10, y: 20 }));
        assert!(h.is_empty());
    }
}
