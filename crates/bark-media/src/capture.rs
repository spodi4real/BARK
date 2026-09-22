//! Screen capture with DXGI Desktop Duplication.
//!
//! Windows hands over each new desktop image as a GPU texture, only when
//! something changed, plus the mouse pointer's shape separately. BARK copies
//! the image into a texture of its own straight away and releases Windows'
//! copy, so the next frame is never held up by encoding.
//!
//! Capture "access lost" is normal, not a failure: it happens when the
//! display mode changes, when a UAC prompt or the lock screen takes over the
//! desktop, or when a full-screen game grabs the display. The caller reopens.

use crate::gpu::{adapters, win, Gpu};
use bark_core::{BarkError, Result};
use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_B8G8R8A8_UNORM;
use windows::Win32::Graphics::Dxgi::*;

/// One display, as Windows describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Display {
    /// BARK's number for it: the order Windows lists them in.
    pub index: u8,
    /// "\\.\DISPLAY1" and so on.
    pub device_name: String,
    /// Position and size in the virtual desktop, in physical pixels.
    pub rect: RECT,
    pub primary: bool,
    adapter_index: u32,
    output_index: u32,
}

impl Display {
    pub fn width(&self) -> u32 {
        (self.rect.right - self.rect.left) as u32
    }
    pub fn height(&self) -> u32 {
        (self.rect.bottom - self.rect.top) as u32
    }
}

/// Lists the displays attached to the desktop.
pub fn displays() -> Vec<Display> {
    let mut out = Vec::new();
    for (ai, adapter) in adapters().iter().enumerate() {
        let mut oi = 0;
        while let Ok(output) = unsafe { adapter.EnumOutputs(oi) } {
            if let Ok(desc) = unsafe { output.GetDesc() } {
                if desc.AttachedToDesktop.as_bool() {
                    let len = desc.DeviceName.iter().position(|&c| c == 0).unwrap_or(desc.DeviceName.len());
                    let r = desc.DesktopCoordinates;
                    out.push(Display {
                        index: out.len() as u8,
                        device_name: String::from_utf16_lossy(&desc.DeviceName[..len]),
                        rect: r,
                        primary: r.left == 0 && r.top == 0,
                        adapter_index: ai as u32,
                        output_index: oi,
                    });
                }
            }
            oi += 1;
        }
    }
    out
}

/// A pointer shape, ready to send. See `ToController::CursorShape` for what
/// `xor` means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShape {
    pub width: u16,
    pub height: u16,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub pixels: Vec<u8>,
    pub xor: bool,
}

/// What one call to [`DesktopCapture::next`] produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Captured {
    /// The screen changed; [`DesktopCapture::texture`] holds the new image.
    Frame,
    /// Only the pointer moved or changed shape.
    PointerOnly,
    /// Nothing changed within the timeout.
    Timeout,
}

pub struct DesktopCapture {
    pub gpu: Gpu,
    pub display: Display,
    duplication: IDXGIOutputDuplication,
    frame: ID3D11Texture2D,
    width: u32,
    height: u32,
    shape_buf: Vec<u8>,
    new_shape: Option<CursorShape>,
    pointer_visible: bool,
    has_frame: bool,
    present_qpc: u64,
}

/// DXGI's "nothing new" and "start again" results.
const WAIT_TIMEOUT: i32 = 0x887A0027u32 as i32;
const ACCESS_LOST: i32 = 0x887A0026u32 as i32;

/// Returned by [`DesktopCapture::next`] when the capture must be reopened.
pub fn is_access_lost(e: &BarkError) -> bool {
    matches!(e, BarkError::Capture(t) if t.starts_with("ACCESS_LOST"))
}

impl DesktopCapture {
    /// Starts capturing display `index` (0 is the first one Windows lists).
    pub fn open(index: u8) -> Result<Self> {
        let all = displays();
        let display = all
            .iter()
            .find(|d| d.index == index)
            .or_else(|| all.first())
            .cloned()
            .ok_or_else(|| BarkError::capture("This computer has no display attached to the desktop that can be captured."))?;

        let adapter = adapters()
            .into_iter()
            .nth(display.adapter_index as usize)
            .ok_or_else(|| BarkError::capture("the display's graphics adapter disappeared"))?;
        // The capture device must live on the adapter that drives the display.
        let gpu = Gpu::new(Some(&adapter))?;
        let output: IDXGIOutput1 = unsafe { adapter.EnumOutputs(display.output_index) }
            .map_err(|e| win("could not open the display", e))?
            .cast()
            .map_err(|e| win("this version of Windows cannot capture the screen", e))?;

        let duplication = unsafe { output.DuplicateOutput(&gpu.device) }.map_err(|e| {
            BarkError::Capture(format!(
                "Windows refused to let BARK capture the screen: {e}\n\n\
                 This happens when another program is already capturing the same display with \
                 exclusive access, on the secure desktop (sign-in or UAC screen) when BARK does \
                 not run as a service, or with some remote-desktop display drivers."
            ))
        })?;
        let desc = unsafe { duplication.GetDesc() };
        let (width, height) = (desc.ModeDesc.Width, desc.ModeDesc.Height);
        let frame = gpu.texture(
            width,
            height,
            DXGI_FORMAT_B8G8R8A8_UNORM,
            D3D11_BIND_FLAG(D3D11_BIND_SHADER_RESOURCE.0 | D3D11_BIND_RENDER_TARGET.0),
        )?;

        Ok(DesktopCapture {
            gpu,
            display,
            duplication,
            frame,
            width,
            height,
            shape_buf: Vec::new(),
            new_shape: None,
            pointer_visible: true,
            has_frame: false,
            present_qpc: 0,
        })
    }

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// The most recent screen image (BGRA). Valid after the first `Frame`.
    pub fn texture(&self) -> &ID3D11Texture2D {
        &self.frame
    }

    pub fn has_frame(&self) -> bool {
        self.has_frame
    }

    /// When the latest captured image reached this computer's screen, as a
    /// raw performance-counter reading (see `bark_core::clock::qpc_to_us`).
    /// The honest start of the latency chain.
    pub fn present_qpc(&self) -> u64 {
        self.present_qpc
    }

    /// A pointer shape change since the last call, if any.
    pub fn take_cursor_shape(&mut self) -> Option<CursorShape> {
        self.new_shape.take()
    }

    pub fn pointer_visible(&self) -> bool {
        self.pointer_visible
    }

    /// Waits up to `timeout_ms` for the screen or pointer to change.
    pub fn next(&mut self, timeout_ms: u32) -> Result<Captured> {
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource: Option<IDXGIResource> = None;
        if let Err(e) = unsafe { self.duplication.AcquireNextFrame(timeout_ms, &mut info, &mut resource) } {
            return match e.code().0 {
                WAIT_TIMEOUT => Ok(Captured::Timeout),
                ACCESS_LOST => Err(BarkError::Capture("ACCESS_LOST: the desktop changed".into())),
                _ => Err(BarkError::Capture(format!("screen capture failed: {e}"))),
            };
        }

        let result = (|| {
            let mut got_frame = false;
            if info.LastPresentTime != 0 {
                if let Some(r) = &resource {
                    let tex: ID3D11Texture2D = r.cast().map_err(|e| win("captured image has no texture", e))?;
                    unsafe { self.gpu.context.CopyResource(&self.frame, &tex) };
                    got_frame = true;
                    self.has_frame = true;
                    self.present_qpc = info.LastPresentTime as u64;
                }
            }
            if info.LastMouseUpdateTime != 0 {
                self.pointer_visible = info.PointerPosition.Visible.as_bool();
            }
            if info.PointerShapeBufferSize > 0 {
                self.read_pointer_shape(info.PointerShapeBufferSize)?;
            }
            Ok(if got_frame {
                Captured::Frame
            } else if info.LastMouseUpdateTime != 0 {
                Captured::PointerOnly
            } else {
                Captured::Timeout
            })
        })();

        unsafe {
            let _ = self.duplication.ReleaseFrame();
        }
        result
    }

    fn read_pointer_shape(&mut self, size: u32) -> Result<()> {
        self.shape_buf.resize(size as usize, 0);
        let mut needed = 0u32;
        let mut info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
        unsafe {
            self.duplication.GetFramePointerShape(
                size,
                self.shape_buf.as_mut_ptr() as *mut _,
                &mut needed,
                &mut info,
            )
        }
        .map_err(|e| win("could not read the pointer shape", e))?;
        self.new_shape = convert_pointer(&info, &self.shape_buf);
        Ok(())
    }
}

/// Turns any of Windows' three pointer formats into BGRA.
fn convert_pointer(info: &DXGI_OUTDUPL_POINTER_SHAPE_INFO, data: &[u8]) -> Option<CursorShape> {
    let w = info.Width as usize;
    let pitch = info.Pitch as usize;
    let kind = info.Type;
    let mut out;
    let h;
    let mut xor = false;
    if kind == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0 as u32 {
        // Two 1-bit masks stacked: AND on top, XOR below.
        h = info.Height as usize / 2;
        out = vec![0u8; w * h * 4];
        xor = true;
        for y in 0..h {
            for x in 0..w {
                let byte = x / 8;
                let bit = 0x80 >> (x % 8);
                let and = data.get(y * pitch + byte)? & bit != 0;
                let xr = data.get((y + h) * pitch + byte)? & bit != 0;
                let px = &mut out[(y * w + x) * 4..][..4];
                // Masked semantics: alpha 0xFF draws the colour, alpha 0
                // XORs it with the screen.
                let (rgb, a) = match (and, xr) {
                    (false, false) => (0x00, 0xFF),
                    (false, true) => (0xFF, 0xFF),
                    (true, false) => (0x00, 0x00),
                    (true, true) => (0xFF, 0x00),
                };
                px.copy_from_slice(&[rgb, rgb, rgb, a]);
            }
        }
    } else {
        h = info.Height as usize;
        out = vec![0u8; w * h * 4];
        for y in 0..h {
            let row = data.get(y * pitch..y * pitch + w * 4)?;
            out[y * w * 4..][..w * 4].copy_from_slice(row);
        }
        if kind == DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR.0 as u32 {
            // Here Windows' mask byte is the other way round (0 draws,
            // 0xFF XORs); flip it to BARK's convention.
            xor = true;
            for px in out.chunks_exact_mut(4) {
                px[3] = if px[3] == 0 { 0xFF } else { 0x00 };
            }
        }
    }
    Some(CursorShape {
        width: w as u16,
        height: h as u16,
        hotspot_x: info.HotSpot.x.max(0) as u16,
        hotspot_y: info.HotSpot.y.max(0) as u16,
        pixels: out,
        xor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_monochrome_pointer_keeps_its_inverting_pixels() {
        // 8x2 cursor: AND mask then XOR mask, one byte per row.
        // Pixel 0: AND=0 XOR=0 -> black. Pixel 1: AND=0 XOR=1 -> white.
        // Pixel 2: AND=1 XOR=0 -> transparent. Pixel 3: AND=1 XOR=1 -> invert.
        let and = [0b0011_1111u8, 0b0011_1111];
        let xr = [0b0101_0000u8, 0b0101_0000];
        let data = [and[0], and[1], xr[0], xr[1]];
        let info = DXGI_OUTDUPL_POINTER_SHAPE_INFO {
            Type: DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME.0 as u32,
            Width: 8,
            Height: 4,
            Pitch: 1,
            ..Default::default()
        };
        let s = convert_pointer(&info, &data).unwrap();
        assert!(s.xor);
        assert_eq!((s.width, s.height), (8, 2));
        assert_eq!(&s.pixels[0..4], &[0, 0, 0, 0xFF], "black, drawn");
        assert_eq!(&s.pixels[4..8], &[0xFF, 0xFF, 0xFF, 0xFF], "white, drawn");
        assert_eq!(&s.pixels[8..12], &[0, 0, 0, 0], "transparent");
        assert_eq!(&s.pixels[12..16], &[0xFF, 0xFF, 0xFF, 0], "inverts the screen");
    }

    #[test]
    fn this_computer_has_a_display_to_capture() {
        let d = displays();
        assert!(!d.is_empty(), "no display found");
        assert!(d.iter().all(|x| x.width() > 0 && x.height() > 0));
        eprintln!("displays: {d:?}");
    }
}
