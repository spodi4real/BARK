//! Putting decoded frames on the screen.
//!
//! A flip-model swap chain on the session window's video area. Frames are
//! presented the moment they are decoded, without waiting for the display's
//! vertical refresh: when the window is the only thing on its part of the
//! screen, Windows can show the frame immediately ("independent flip");
//! otherwise the desktop compositor shows the newest frame at its next
//! refresh and discards any it did not get to. Either way nothing queues.
//!
//! The picture keeps its shape: it is scaled to fit and the rest of the
//! window is black.

use crate::convert::{fit, Converter, Direction};
use crate::decode::DecodedFrame;
use crate::gpu::{win, Gpu};
use bark_core::{BarkError, Result};
use windows::core::Interface;
use windows::Win32::Foundation::{HWND, RECT};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::UI::WindowsAndMessaging::GetClientRect;

pub struct Presenter {
    gpu: Gpu,
    hwnd: HWND,
    swapchain: IDXGISwapChain1,
    size: (u32, u32),
    tearing: bool,
    converter: Option<Converter>,
    /// Where the last picture was drawn, in window pixels, for mapping the
    /// mouse back to remote coordinates.
    pub picture: RECT,
}

fn client_size(hwnd: HWND) -> (u32, u32) {
    let mut r = RECT::default();
    unsafe {
        let _ = GetClientRect(hwnd, &mut r);
    }
    ((r.right - r.left).max(1) as u32, (r.bottom - r.top).max(1) as u32)
}

impl Presenter {
    pub fn new(gpu: &Gpu, hwnd: HWND) -> Result<Self> {
        let factory: IDXGIFactory2 = unsafe { gpu.adapter.GetParent() }.map_err(|e| win("no DXGI factory", e))?;
        let tearing = factory
            .cast::<IDXGIFactory5>()
            .map(|f5| {
                let mut allow: windows::core::BOOL = false.into();
                unsafe {
                    f5.CheckFeatureSupport(
                        DXGI_FEATURE_PRESENT_ALLOW_TEARING,
                        &mut allow as *mut _ as *mut _,
                        std::mem::size_of::<windows::core::BOOL>() as u32,
                    )
                }
                .is_ok()
                    && allow.as_bool()
            })
            .unwrap_or(false);

        let size = client_size(hwnd);
        let desc = DXGI_SWAP_CHAIN_DESC1 {
            Width: size.0,
            Height: size.1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            Stereo: false.into(),
            SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            BufferUsage: DXGI_USAGE_RENDER_TARGET_OUTPUT,
            BufferCount: 2,
            Scaling: DXGI_SCALING_STRETCH,
            SwapEffect: DXGI_SWAP_EFFECT_FLIP_DISCARD,
            AlphaMode: DXGI_ALPHA_MODE_IGNORE,
            Flags: if tearing { DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING.0 as u32 } else { 0 },
        };
        let swapchain = unsafe { factory.CreateSwapChainForHwnd(&gpu.device, hwnd, &desc, None, None) }
            .map_err(|e| win("could not create the video surface", e))?;
        // BARK handles its own full screen; Alt+Enter must reach the remote.
        unsafe {
            let _ = factory.MakeWindowAssociation(hwnd, DXGI_MWA_NO_ALT_ENTER);
        }
        Ok(Presenter { gpu: gpu.clone(), hwnd, swapchain, size, tearing, converter: None, picture: RECT::default() })
    }

    pub fn allows_tearing(&self) -> bool {
        self.tearing
    }

    fn resize_if_needed(&mut self) -> Result<()> {
        let now = client_size(self.hwnd);
        if now != self.size {
            let flags = if self.tearing { DXGI_SWAP_CHAIN_FLAG_ALLOW_TEARING } else { DXGI_SWAP_CHAIN_FLAG(0) };
            unsafe { self.swapchain.ResizeBuffers(0, now.0, now.1, DXGI_FORMAT_UNKNOWN, flags) }
                .map_err(|e| win("could not resize the video surface", e))?;
            self.size = now;
            self.converter = None;
        }
        Ok(())
    }

    /// Draws `frame`, scaled to fit, and shows it now.
    pub fn present(&mut self, frame: &DecodedFrame) -> Result<()> {
        self.resize_if_needed()?;
        let picture = (frame.width, frame.height);
        let rebuild = match &self.converter {
            Some(c) => c.input_size != picture || c.output_size != self.size,
            None => true,
        };
        if rebuild {
            self.converter = Some(Converter::new(&self.gpu, Direction::YuvToRgb, picture, self.size)?);
        }
        let back: ID3D11Texture2D = unsafe { self.swapchain.GetBuffer(0) }.map_err(|e| win("no back buffer", e))?;
        let dest = fit(picture, self.size);
        self.converter
            .as_ref()
            .ok_or_else(|| BarkError::Windows("no converter".into()))?
            .run(&frame.texture, frame.slice, &back, Some(dest))?;
        drop(back);
        self.picture = dest;
        self.flip()
    }

    fn flip(&self) -> Result<()> {
        let flags = if self.tearing { DXGI_PRESENT_ALLOW_TEARING } else { DXGI_PRESENT(0) };
        let hr = unsafe { self.swapchain.Present(0, flags) };
        // "Occluded" (window minimised or covered) is a success code.
        if hr.is_err() {
            return Err(BarkError::Windows(format!("could not show the frame: {hr:?}")));
        }
        Ok(())
    }
}
