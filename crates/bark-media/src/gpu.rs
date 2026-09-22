//! The Direct3D 11 device the whole pipeline shares.
//!
//! Capture, colour conversion, encoding, decoding and presenting all work on
//! GPU textures, and a texture belongs to one device. Keeping every stage on
//! the same device is what lets a frame go from the screen to the encoder
//! without ever being copied to system memory.

use bark_core::{BarkError, Result};
use windows::core::Interface;
use windows::Win32::Foundation::{HMODULE, LUID};
use windows::Win32::Graphics::Direct3D::*;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::*;

/// A device, its immediate context, and the adapter it runs on.
#[derive(Clone)]
pub struct Gpu {
    pub device: ID3D11Device,
    pub context: ID3D11DeviceContext,
    pub adapter: IDXGIAdapter1,
    /// Graphics card name, for diagnostics.
    pub adapter_name: String,
    pub luid: LUID,
}

impl std::fmt::Debug for Gpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gpu({})", self.adapter_name)
    }
}

pub(crate) fn win(what: &str, e: windows::core::Error) -> BarkError {
    BarkError::Windows(format!("{what}: {e}"))
}

impl Gpu {
    /// Creates a device on `adapter`, or on the default adapter.
    pub fn new(adapter: Option<&IDXGIAdapter1>) -> Result<Gpu> {
        let adapter = match adapter {
            Some(a) => a.clone(),
            None => unsafe {
                let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(|e| win("DXGI is unavailable", e))?;
                factory.EnumAdapters1(0).map_err(|e| win("no graphics adapter found", e))?
            },
        };
        let desc = unsafe { adapter.GetDesc1() }.map_err(|e| win("could not read the graphics adapter", e))?;
        let name_len = desc.Description.iter().position(|&c| c == 0).unwrap_or(desc.Description.len());
        let adapter_name = String::from_utf16_lossy(&desc.Description[..name_len]);

        let levels = [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_1, D3D_FEATURE_LEVEL_10_0];
        let mut device = None;
        let mut context = None;
        unsafe {
            D3D11CreateDevice(
                &adapter,
                // An explicit adapter requires UNKNOWN here.
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                Some(&levels),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .map_err(|e| win(&format!("could not start Direct3D on {adapter_name}"), e))?;
        }
        let device = device.ok_or_else(|| BarkError::Windows("Direct3D returned no device".into()))?;
        let context = context.ok_or_else(|| BarkError::Windows("Direct3D returned no context".into()))?;

        // Media Foundation uses the device from its own threads.
        if let Ok(mt) = context.cast::<ID3D11Multithread>() {
            unsafe {
                let _ = mt.SetMultithreadProtected(true);
            }
        }

        Ok(Gpu { device, context, adapter, adapter_name, luid: desc.AdapterLuid })
    }

    /// A texture on this device.
    pub fn texture(
        &self,
        width: u32,
        height: u32,
        format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT,
        bind: D3D11_BIND_FLAG,
    ) -> Result<ID3D11Texture2D> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: format,
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: bind.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut tex = None;
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }
            .map_err(|e| win("could not create a video texture", e))?;
        tex.ok_or_else(|| BarkError::Windows("Direct3D returned no texture".into()))
    }
}

/// Every adapter in the machine, in the order Windows lists them.
pub fn adapters() -> Vec<IDXGIAdapter1> {
    let mut out = Vec::new();
    unsafe {
        let Ok(factory) = CreateDXGIFactory1::<IDXGIFactory1>() else { return out };
        let mut i = 0;
        while let Ok(a) = factory.EnumAdapters1(i) {
            out.push(a);
            i += 1;
        }
    }
    out
}

/// Asks Windows for 1 ms timer resolution for this process, and to keep it
/// even while BARK's windows are hidden or minimised.
///
/// Measured on the development laptop's Intel encoder: without this, each
/// frame waited two 15.6 ms timer ticks inside the driver, ~30 ms per frame.
/// The driver's worker threads sleep while polling the hardware, and a sleep
/// lasts at least one timer tick. Windows 11 also stops honouring a process's
/// timer request once its windows are hidden — which is exactly the state of
/// a computer being controlled — unless the process opts out, which the
/// second call does.
pub fn raise_timer_resolution() {
    use windows::Win32::System::Threading::*;
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| unsafe {
        windows::Win32::Media::timeBeginPeriod(1);
        let state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION,
            StateMask: 0,
        };
        let _ = SetProcessInformation(
            GetCurrentProcess(),
            ProcessPowerThrottling,
            &state as *const _ as *const _,
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        );
    });
}
