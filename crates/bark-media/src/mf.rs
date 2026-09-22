//! Small helpers shared by the encoder and the decoder.

use crate::gpu::{win, Gpu};
use bark_core::{BarkError, Result};
use windows::core::{Interface, GUID};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_UI4};

/// Prepares the calling thread for Media Foundation. Safe to call more than
/// once; every thread that touches an encoder or decoder must call it.
pub fn init_thread() -> Result<()> {
    unsafe {
        // S_FALSE (already initialised) is fine; a different apartment
        // model already chosen by the thread is also workable for MF.
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        MFStartup(MF_VERSION, MFSTARTUP_FULL).map_err(|e| win("Media Foundation is not available", e))
    }
}

pub fn variant_u32(v: u32) -> VARIANT {
    let mut var = VARIANT::default();
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_UI4;
        inner.Anonymous.ulVal = v;
    }
    var
}

pub fn variant_bool(v: bool) -> VARIANT {
    let mut var = VARIANT::default();
    unsafe {
        let inner = &mut *var.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous.boolVal = windows::Win32::Foundation::VARIANT_BOOL(if v { -1 } else { 0 });
    }
    var
}

/// Sets a codec property, returning whether the codec accepted it. Codecs
/// differ in what they support; BARK asks for everything it wants and logs
/// what was declined rather than failing.
pub fn set_codec(api: &ICodecAPI, what: &str, key: &GUID, value: VARIANT) -> bool {
    match unsafe { api.SetValue(key, &value) } {
        Ok(()) => true,
        Err(e) => {
            tracing::debug!("codec declined {what}: {e}");
            false
        }
    }
}

pub fn pack(hi: u32, lo: u32) -> u64 {
    ((hi as u64) << 32) | lo as u64
}

/// A video media type with the common fields filled in.
pub fn video_type(subtype: &GUID, width: u32, height: u32, fps: u32) -> Result<IMFMediaType> {
    unsafe {
        let t = MFCreateMediaType().map_err(|e| win("could not create a media type", e))?;
        t.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).map_err(|e| win("media type", e))?;
        t.SetGUID(&MF_MT_SUBTYPE, subtype).map_err(|e| win("media type", e))?;
        t.SetUINT64(&MF_MT_FRAME_SIZE, pack(width, height)).map_err(|e| win("media type", e))?;
        t.SetUINT64(&MF_MT_FRAME_RATE, pack(fps, 1)).map_err(|e| win("media type", e))?;
        t.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, pack(1, 1)).map_err(|e| win("media type", e))?;
        t.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32).map_err(|e| win("media type", e))?;
        Ok(t)
    }
}

/// A device manager that lets an MFT use `gpu`.
pub fn device_manager(gpu: &Gpu) -> Result<IMFDXGIDeviceManager> {
    unsafe {
        let mut token = 0u32;
        let mut manager = None;
        MFCreateDXGIDeviceManager(&mut token, &mut manager).map_err(|e| win("no DXGI device manager", e))?;
        let manager = manager.ok_or_else(|| BarkError::Windows("no DXGI device manager".into()))?;
        manager.ResetDevice(&gpu.device, token).map_err(|e| win("could not share the GPU with Media Foundation", e))?;
        Ok(manager)
    }
}

/// Copies a sample's bytes out.
pub fn sample_bytes(sample: &IMFSample) -> Result<Vec<u8>> {
    unsafe {
        let buffer = sample.ConvertToContiguousBuffer().map_err(|e| win("empty sample", e))?;
        let mut ptr = std::ptr::null_mut();
        let mut len = 0u32;
        buffer.Lock(&mut ptr, None, Some(&mut len)).map_err(|e| win("could not read a sample", e))?;
        let data = std::slice::from_raw_parts(ptr, len as usize).to_vec();
        let _ = buffer.Unlock();
        Ok(data)
    }
}

/// A sample holding `data` in system memory.
pub fn memory_sample(data: &[u8], time_100ns: i64, duration_100ns: i64) -> Result<IMFSample> {
    unsafe {
        let buffer = MFCreateMemoryBuffer(data.len() as u32).map_err(|e| win("out of memory for a sample", e))?;
        let mut ptr = std::ptr::null_mut();
        buffer.Lock(&mut ptr, None, None).map_err(|e| win("could not fill a sample", e))?;
        std::ptr::copy_nonoverlapping(data.as_ptr(), ptr, data.len());
        let _ = buffer.Unlock();
        buffer.SetCurrentLength(data.len() as u32).map_err(|e| win("sample length", e))?;
        let sample = MFCreateSample().map_err(|e| win("could not create a sample", e))?;
        sample.AddBuffer(&buffer).map_err(|e| win("sample buffer", e))?;
        sample.SetSampleTime(time_100ns).map_err(|e| win("sample time", e))?;
        sample.SetSampleDuration(duration_100ns).map_err(|e| win("sample duration", e))?;
        Ok(sample)
    }
}

/// Shuts an MFT down so its worker threads end with it.
pub fn shutdown(transform: &IMFTransform) {
    if let Ok(s) = transform.cast::<IMFShutdown>() {
        unsafe {
            let _ = s.Shutdown();
        }
    }
}
