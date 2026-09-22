//! H.264 decoding through Media Foundation.
//!
//! Uses the decoder built into Windows, which hands the work to the graphics
//! card (DXVA) when given a Direct3D device, and outputs NV12 textures that
//! go straight to the screen without leaving the GPU.
//!
//! Low-latency mode is essential here. Without it the decoder holds several
//! frames back to reorder them — correct for films with B-frames, pure delay
//! for a remote desktop stream that has none.

use crate::gpu::{win, Gpu};
use crate::mf;
use bark_core::{BarkError, Result};
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CLSCTX_INPROC_SERVER};

/// A decoded picture: a slice of a GPU texture array.
pub struct DecodedFrame {
    pub texture: ID3D11Texture2D,
    pub slice: u32,
    pub width: u32,
    pub height: u32,
    /// Held so the decoder does not reuse the texture while it is shown.
    _sample: IMFSample,
}

pub struct H264Decoder {
    transform: IMFTransform,
    _manager: Option<IMFDXGIDeviceManager>,
    provides_samples: bool,
    size: (u32, u32),
    /// The part of `size` that is picture rather than coding padding.
    visible: (u32, u32),
    frame_index: i64,
    /// True when the GPU is doing the work.
    pub hardware: bool,
}

impl Drop for H264Decoder {
    fn drop(&mut self) {
        mf::shutdown(&self.transform);
    }
}

impl H264Decoder {
    pub fn new(gpu: &Gpu) -> Result<Self> {
        mf::init_thread()?;
        unsafe {
            let transform: IMFTransform = CoCreateInstance(&CLSID_MSH264DecoderMFT, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| win("the Windows H.264 decoder is not available", e))?;
            let attrs = transform.GetAttributes().map_err(|e| win("decoder attributes", e))?;
            let _ = attrs.SetUINT32(&MF_LOW_LATENCY, 1);
            if let Ok(api) = transform.cast::<ICodecAPI>() {
                mf::set_codec(&api, "low-latency mode", &CODECAPI_AVLowLatencyMode, mf::variant_bool(true));
            }

            let d3d_aware = attrs.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) != 0;
            let mut manager = None;
            let mut hardware = false;
            if d3d_aware {
                let m = mf::device_manager(gpu)?;
                if transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, m.as_raw() as usize).is_ok() {
                    hardware = true;
                    manager = Some(m);
                } else {
                    tracing::warn!("the H.264 decoder cannot use the graphics card; decoding in software");
                }
            }

            let input = MFCreateMediaType().map_err(|e| win("media type", e))?;
            input.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video).map_err(|e| win("media type", e))?;
            input.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264).map_err(|e| win("media type", e))?;
            transform.SetInputType(0, &input, 0).map_err(|e| win("the decoder refused H.264", e))?;

            let mut dec = H264Decoder {
                transform,
                _manager: manager,
                provides_samples: true,
                size: (0, 0),
                visible: (0, 0),
                frame_index: 0,
                hardware,
            };
            dec.choose_output()?;
            dec.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| win("could not start decoding", e))?;
            Ok(dec)
        }
    }

    /// Selects NV12 output. Called at start and whenever the stream's format
    /// changes (a new resolution after the remote changed its display).
    fn choose_output(&mut self) -> Result<()> {
        unsafe {
            let mut i = 0;
            while let Ok(t) = self.transform.GetOutputAvailableType(0, i) {
                i += 1;
                if t.GetGUID(&MF_MT_SUBTYPE).ok() == Some(MFVideoFormat_NV12) {
                    self.transform.SetOutputType(0, &t, 0).map_err(|e| win("decoder output", e))?;
                    if let Ok(size) = t.GetUINT64(&MF_MT_FRAME_SIZE) {
                        self.size = ((size >> 32) as u32, size as u32);
                    }
                    // H.264 codes whole 16-pixel blocks, so a 1080-line
                    // picture decodes as 1088 lines; the aperture says which
                    // part is the real picture.
                    let mut area = MFVideoArea::default();
                    let bytes = std::slice::from_raw_parts_mut(
                        &mut area as *mut MFVideoArea as *mut u8,
                        std::mem::size_of::<MFVideoArea>(),
                    );
                    if t.GetBlob(&MF_MT_MINIMUM_DISPLAY_APERTURE, bytes, None).is_ok() && area.Area.cx > 0 && area.Area.cy > 0 {
                        self.visible = (area.Area.cx as u32, area.Area.cy as u32);
                    } else {
                        self.visible = self.size;
                    }
                    let info = self.transform.GetOutputStreamInfo(0).map_err(|e| win("decoder output", e))?;
                    self.provides_samples = (info.dwFlags
                        & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32))
                        != 0;
                    return Ok(());
                }
            }
        }
        Err(BarkError::Decode("the decoder offers no NV12 output".into()))
    }

    /// Feeds one encoded frame and returns the picture, if the decoder has
    /// one ready. With low-latency mode that is normally this same frame.
    pub fn decode(&mut self, bitstream: &[u8]) -> Result<Option<DecodedFrame>> {
        let duration = 166_667;
        let sample = mf::memory_sample(bitstream, self.frame_index * duration, duration)?;
        self.frame_index += 1;
        unsafe {
            match self.transform.ProcessInput(0, &sample, 0) {
                Ok(()) => {}
                // Output is waiting to be collected first.
                Err(e) if e.code() == MF_E_NOTACCEPTING => {
                    let _ = self.pull()?;
                    self.transform.ProcessInput(0, &sample, 0).map_err(|e| win("the decoder refused a frame", e))?;
                }
                Err(e) => return Err(win("the decoder refused a frame", e)),
            }
        }
        // Keep the newest picture if more than one comes out.
        let mut latest = None;
        while let Some(f) = self.pull()? {
            latest = Some(f);
        }
        Ok(latest)
    }

    fn pull(&mut self) -> Result<Option<DecodedFrame>> {
        for _ in 0..4 {
            unsafe {
                let provided = if self.provides_samples {
                    None
                } else {
                    let (w, h) = (self.size.0.max(16), self.size.1.max(16));
                    let buffer = MFCreateMemoryBuffer(w * h * 3 / 2).map_err(|e| win("output buffer", e))?;
                    let s = MFCreateSample().map_err(|e| win("output sample", e))?;
                    s.AddBuffer(&buffer).map_err(|e| win("output sample", e))?;
                    Some(s)
                };
                let mut buf = [MFT_OUTPUT_DATA_BUFFER {
                    dwStreamID: 0,
                    pSample: std::mem::ManuallyDrop::new(provided),
                    dwStatus: 0,
                    pEvents: std::mem::ManuallyDrop::new(None),
                }];
                let mut status = 0u32;
                let r = self.transform.ProcessOutput(0, &mut buf, &mut status);
                let [b] = buf;
                let sample = std::mem::ManuallyDrop::into_inner(b.pSample);
                drop(std::mem::ManuallyDrop::into_inner(b.pEvents));
                match r {
                    Ok(()) => {}
                    Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                    Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                        self.choose_output()?;
                        continue;
                    }
                    Err(e) => return Err(win("the decoder failed", e)),
                }
                let Some(sample) = sample else { return Ok(None) };
                let buffer = sample.GetBufferByIndex(0).map_err(|e| win("decoded frame", e))?;
                let dxgi: IMFDXGIBuffer = buffer.cast().map_err(|_| {
                    BarkError::Decode("the decoder produced a picture in system memory, not on the GPU".into())
                })?;
                let mut tex: *mut std::ffi::c_void = std::ptr::null_mut();
                dxgi.GetResource(&ID3D11Texture2D::IID, &mut tex).map_err(|e| win("decoded frame", e))?;
                let texture = ID3D11Texture2D::from_raw(tex);
                let slice = dxgi.GetSubresourceIndex().map_err(|e| win("decoded frame", e))?;
                return Ok(Some(DecodedFrame {
                    texture,
                    slice,
                    width: self.visible.0,
                    height: self.visible.1,
                    _sample: sample,
                }));
            }
        }
        Ok(None)
    }
}
