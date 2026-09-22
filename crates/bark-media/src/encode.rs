//! H.264 encoding through Media Foundation.
//!
//! Prefers the graphics card's own encoder (NVENC, Quick Sync, AMF), fed
//! straight from GPU textures. Falls back to the software encoder that ships
//! with Windows when there is none — virtual machines, very old hardware —
//! which is slower and uses the processor, and says so in diagnostics.
//!
//! Settings are chosen for latency, not file size: low-latency mode, no
//! B-frames, constant bitrate, and a keyframe only when the viewer asks for
//! one. Which of those a particular encoder accepted is logged, because
//! drivers differ and "the encoder ignored low-latency mode" is exactly the
//! kind of thing that otherwise costs a day to find.

use crate::gpu::{win, Gpu};
use crate::h264;
use crate::mf::{self, set_codec, variant_bool, variant_u32};
use bark_core::{BarkError, Result};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows::core::Interface;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_NV12;
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoCreateInstance, CoTaskMemFree, CLSCTX_INPROC_SERVER};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncoderSettings {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
}

/// Bitrate that keeps text readable at a given size and rate, before any
/// network feedback. About 0.08 bits per pixel per frame, within 4-40 Mbit/s.
/// A starting point from experience with screen content, not a measurement.
pub fn default_bitrate_kbps(width: u32, height: u32, fps: u32) -> u32 {
    let bits = width as f64 * height as f64 * fps as f64 * 0.08;
    ((bits / 1000.0) as u32).clamp(4_000, 40_000)
}

/// Where the time went in the last `encode` call, in microseconds.
#[derive(Debug, Clone, Copy, Default)]
pub struct EncodeTiming {
    /// Waiting for the encoder to ask for input.
    pub wait_input_us: u32,
    /// Handing the frame over.
    pub process_input_us: u32,
    /// From handing it over to the bitstream coming back.
    pub wait_output_us: u32,
}

#[derive(Debug, Clone)]
pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub keyframe: bool,
}

/// Why an event arrived from an asynchronous encoder.
enum AsyncEvent {
    NeedInput,
    HaveOutput,
    Other,
}

/// An encoder's event generator, moved to the thread that waits on it.
/// Hardware encoders are free-threaded; that is what makes this sound.
struct EventSource(IMFMediaEventGenerator);
unsafe impl Send for EventSource {}

enum Mode {
    /// Hardware encoders: input and output are announced by events.
    Async { events: mpsc::Receiver<AsyncEvent>, need_input: u32 },
    /// Software encoder: fed from system memory, output pulled directly.
    Sync { staging: ID3D11Texture2D },
}

pub struct H264Encoder {
    transform: IMFTransform,
    codec: Option<ICodecAPI>,
    _manager: Option<IMFDXGIDeviceManager>,
    gpu: Gpu,
    mode: Mode,
    settings: EncoderSettings,
    provides_samples: bool,
    output_size: u32,
    sequence_header: Vec<u8>,
    frame_index: i64,
    /// Encoder name as the driver reports it.
    pub name: String,
    pub hardware: bool,
    /// Settings the encoder refused, for diagnostics.
    pub declined: Vec<&'static str>,
    pub timing: EncodeTiming,
}

impl Drop for H264Encoder {
    fn drop(&mut self) {
        mf::shutdown(&self.transform);
    }
}

fn activates(flags: MFT_ENUM_FLAG) -> Vec<IMFActivate> {
    let input = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_NV12 };
    let output = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_H264 };
    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    let mut out = Vec::new();
    unsafe {
        if MFTEnumEx(MFT_CATEGORY_VIDEO_ENCODER, flags, Some(&input), Some(&output), &mut list, &mut count).is_ok()
            && !list.is_null()
        {
            for a in std::slice::from_raw_parts_mut(list, count as usize) {
                if let Some(a) = a.take() {
                    out.push(a);
                }
            }
            CoTaskMemFree(Some(list as *const _));
        }
    }
    out
}

fn friendly_name(a: &IMFActivate) -> String {
    unsafe {
        let Ok(len) = a.GetStringLength(&MFT_FRIENDLY_NAME_Attribute) else {
            return "hardware encoder".into();
        };
        let mut buf = vec![0u16; len as usize + 1];
        if a.GetString(&MFT_FRIENDLY_NAME_Attribute, &mut buf, None).is_err() {
            return "hardware encoder".into();
        }
        String::from_utf16_lossy(&buf[..len as usize])
    }
}

impl H264Encoder {
    /// Opens the best encoder for `gpu`: its hardware encoder if it has one
    /// that accepts the settings, otherwise Windows' software encoder.
    pub fn new(gpu: &Gpu, settings: EncoderSettings) -> Result<Self> {
        mf::init_thread()?;
        let mut failures = Vec::new();
        for a in activates(MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER) {
            let name = friendly_name(&a);
            match Self::open_hardware(gpu, settings, &a, &name) {
                Ok(e) => {
                    tracing::info!(encoder = %e.name, declined = ?e.declined, "hardware H.264 encoder ready");
                    return Ok(e);
                }
                Err(e) => {
                    tracing::info!("{name} could not be used: {e}");
                    failures.push(format!("{name}: {e}"));
                    unsafe {
                        let _ = a.ShutdownObject();
                    }
                }
            }
        }
        match Self::open_software(gpu, settings) {
            Ok(e) => {
                tracing::warn!(
                    "no usable hardware H.264 encoder ({}); using the software encoder",
                    if failures.is_empty() { "none found".to_string() } else { failures.join("; ") }
                );
                Ok(e)
            }
            Err(e) => Err(BarkError::Encode(format!(
                "No H.264 video encoder could be started on this computer.\n\n\
                 Hardware: {}\nSoftware: {e}",
                if failures.is_empty() { "none found".to_string() } else { failures.join("; ") }
            ))),
        }
    }

    fn open_hardware(gpu: &Gpu, settings: EncoderSettings, a: &IMFActivate, name: &str) -> Result<Self> {
        unsafe {
            let transform: IMFTransform = a.ActivateObject().map_err(|e| win("could not start it", e))?;
            let attrs = transform.GetAttributes().map_err(|e| win("no attributes", e))?;
            let is_async = attrs.GetUINT32(&MF_TRANSFORM_ASYNC).unwrap_or(0) != 0;
            if is_async {
                attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1).map_err(|e| win("could not unlock it", e))?;
            }
            let manager = mf::device_manager(gpu)?;
            transform
                .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize)
                .map_err(|e| win("it does not work with this graphics adapter", e))?;

            let mut enc = Self::configure(gpu, settings, transform, Some(manager), name.to_string(), true)?;
            if is_async {
                let source = EventSource(enc.transform.cast().map_err(|e| win("no event generator", e))?);
                let (tx, rx) = mpsc::channel();
                std::thread::Builder::new()
                    .name("bark-encoder-events".into())
                    .spawn(move || {
                        let _ = mf::init_thread();
                        let source = source;
                        loop {
                            let ev = match source.0.GetEvent(MEDIA_EVENT_GENERATOR_GET_EVENT_FLAGS(0)) {
                                Ok(ev) => ev,
                                // Shut down, or the encoder failed.
                                Err(_) => break,
                            };
                            let t = ev.GetType().map(|t| MF_EVENT_TYPE(t as i32)).unwrap_or_default();
                            let kind = if t == METransformNeedInput {
                                AsyncEvent::NeedInput
                            } else if t == METransformHaveOutput {
                                AsyncEvent::HaveOutput
                            } else {
                                AsyncEvent::Other
                            };
                            if tx.send(kind).is_err() {
                                break;
                            }
                        }
                    })
                    .map_err(|e| BarkError::Encode(format!("could not start the encoder thread: {e}")))?;
                enc.mode = Mode::Async { events: rx, need_input: 0 };
            }
            enc.start()?;
            Ok(enc)
        }
    }

    fn open_software(gpu: &Gpu, settings: EncoderSettings) -> Result<Self> {
        unsafe {
            let transform: IMFTransform = CoCreateInstance(&CLSID_MSH264EncoderMFT, None, CLSCTX_INPROC_SERVER)
                .map_err(|e| win("the Windows H.264 encoder is not installed", e))?;
            let mut enc =
                Self::configure(gpu, settings, transform, None, "Microsoft H.264 software encoder".into(), false)?;
            enc.start()?;
            Ok(enc)
        }
    }

    /// Settings, media types, and the sync-mode defaults. Async mode is
    /// switched on by the caller once events are wired up.
    fn configure(
        gpu: &Gpu,
        settings: EncoderSettings,
        transform: IMFTransform,
        manager: Option<IMFDXGIDeviceManager>,
        name: String,
        hardware: bool,
    ) -> Result<Self> {
        let EncoderSettings { width, height, fps, bitrate_kbps } = settings;
        let codec: Option<ICodecAPI> = transform.cast().ok();
        let mut declined = Vec::new();

        // Latency settings go in before the media types: some encoders only
        // honour them if they are set first.
        if let Some(api) = &codec {
            let wanted: [(&'static str, windows::core::GUID, windows::Win32::System::Variant::VARIANT); 6] = [
                ("low-latency mode", CODECAPI_AVLowLatencyMode, variant_bool(true)),
                ("constant bitrate", CODECAPI_AVEncCommonRateControlMode, variant_u32(eAVEncCommonRateControlMode_CBR.0 as u32)),
                ("bitrate", CODECAPI_AVEncCommonMeanBitRate, variant_u32(bitrate_kbps * 1000)),
                ("no B-frames", CODECAPI_AVEncMPVDefaultBPictureCount, variant_u32(0)),
                // Effectively "never": keyframes are sent when the viewer asks.
                ("long keyframe interval", CODECAPI_AVEncMPVGOPSize, variant_u32(fps * 3600)),
                ("speed over quality", CODECAPI_AVEncCommonQualityVsSpeed, variant_u32(40)),
            ];
            for (what, key, value) in wanted {
                if !set_codec(api, what, &key, value) {
                    declined.push(what);
                }
            }
        }

        unsafe {
            let out = mf::video_type(&MFVideoFormat_H264, width, height, fps)?;
            out.SetUINT32(&MF_MT_AVG_BITRATE, bitrate_kbps * 1000).map_err(|e| win("media type", e))?;
            // High profile for its better compression of text edges; with
            // B-frames off it adds no latency. Main if High is refused.
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_High.0 as u32).map_err(|e| win("media type", e))?;
            if transform.SetOutputType(0, &out, 0).is_err() {
                out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main.0 as u32).map_err(|e| win("media type", e))?;
                transform
                    .SetOutputType(0, &out, 0)
                    .map_err(|e| win(&format!("it refused {width}x{height} at {fps} fps"), e))?;
            }

            let input = mf::video_type(&MFVideoFormat_NV12, width, height, fps)?;
            if transform.SetInputType(0, &input, 0).is_err() {
                // Some encoders insist on one of their own advertised types.
                let mut set = false;
                let mut i = 0;
                while let Ok(t) = transform.GetInputAvailableType(0, i) {
                    i += 1;
                    if t.GetGUID(&MF_MT_SUBTYPE).ok() == Some(MFVideoFormat_NV12) {
                        let _ = t.SetUINT64(&MF_MT_FRAME_SIZE, mf::pack(width, height));
                        let _ = t.SetUINT64(&MF_MT_FRAME_RATE, mf::pack(fps, 1));
                        if transform.SetInputType(0, &t, 0).is_ok() {
                            set = true;
                            break;
                        }
                    }
                }
                if !set {
                    return Err(BarkError::Encode("it does not accept NV12 input".into()));
                }
            }

            let info = transform.GetOutputStreamInfo(0).map_err(|e| win("output stream", e))?;
            let provides_samples = (info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32
                | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0 as u32))
                != 0;
            let sequence_header = transform
                .GetOutputCurrentType(0)
                .ok()
                .and_then(|t| {
                    let mut len = 0u32;
                    t.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER).ok().map(|l| len = l)?;
                    let mut buf = vec![0u8; len as usize];
                    t.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut buf, None).ok()?;
                    Some(h264::to_annex_b(&buf))
                })
                .unwrap_or_default();

            let staging = gpu.staging_nv12(width, height)?;
            Ok(H264Encoder {
                transform,
                codec,
                _manager: manager,
                gpu: gpu.clone(),
                mode: Mode::Sync { staging },
                settings,
                provides_samples,
                output_size: info.cbSize.max(width * height * 3 / 2),
                sequence_header,
                frame_index: 0,
                name,
                hardware,
                declined,
                timing: EncodeTiming::default(),
            })
        }
    }

    fn start(&mut self) -> Result<()> {
        unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| win("could not start streaming", e))?;
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(|e| win("could not start the stream", e))?;
        }
        Ok(())
    }

    pub fn settings(&self) -> EncoderSettings {
        self.settings
    }

    /// Changes the bitrate on the fly, where the encoder allows it.
    pub fn set_bitrate(&mut self, kbps: u32) -> bool {
        self.settings.bitrate_kbps = kbps;
        match &self.codec {
            Some(api) => set_codec(api, "bitrate", &CODECAPI_AVEncCommonMeanBitRate, variant_u32(kbps * 1000)),
            None => false,
        }
    }

    /// Encodes one NV12 texture of the configured size.
    ///
    /// Usually returns exactly that frame's bitstream. May return nothing
    /// (the encoder is still working on it) or more than one frame (earlier
    /// output that arrived late); every frame returned should be sent.
    pub fn encode(&mut self, nv12: &ID3D11Texture2D, keyframe: bool) -> Result<Vec<EncodedFrame>> {
        let duration = 10_000_000 / self.settings.fps.max(1) as i64;
        let time = self.frame_index * duration;
        self.frame_index += 1;

        if keyframe {
            if let Some(api) = &self.codec {
                set_codec(api, "force keyframe", &CODECAPI_AVEncVideoForceKeyFrame, variant_u32(1));
            }
        }

        let sample = match &self.mode {
            Mode::Async { .. } => self.gpu_sample(nv12, time, duration)?,
            Mode::Sync { staging } => self.memory_sample_from(nv12, staging, time, duration)?,
        };

        let mut out = Vec::new();
        if matches!(self.mode, Mode::Async { .. }) {
            self.encode_async(&sample, &mut out)?;
        } else {
            unsafe { self.transform.ProcessInput(0, &sample, 0) }.map_err(|e| win("the encoder refused a frame", e))?;
            while let Some(f) = self.pull()? {
                out.push(f);
            }
        }
        Ok(out)
    }

    fn encode_async(&mut self, sample: &IMFSample, out: &mut Vec<EncodedFrame>) -> Result<()> {
        // A frame normally takes a few milliseconds; half a second without
        // an answer means the encoder has stalled.
        let deadline = Instant::now() + Duration::from_millis(500);
        let t0 = Instant::now();
        loop {
            let Mode::Async { need_input, .. } = &self.mode else { unreachable!() };
            if *need_input > 0 {
                break;
            }
            self.wait_event(deadline, out)?;
        }
        let t1 = Instant::now();
        unsafe { self.transform.ProcessInput(0, sample, 0) }.map_err(|e| win("the encoder refused a frame", e))?;
        let t2 = Instant::now();
        if let Mode::Async { need_input, .. } = &mut self.mode {
            *need_input -= 1;
        }

        // Wait for this frame's output, but not forever: an encoder that
        // holds one frame back delivers it with the next call instead.
        let before = out.len();
        let wait_until = Instant::now() + Duration::from_millis(50);
        while out.len() == before && Instant::now() < wait_until {
            if !self.wait_event(wait_until, out)? {
                break;
            }
        }
        let t3 = Instant::now();
        self.timing = EncodeTiming {
            wait_input_us: (t1 - t0).as_micros() as u32,
            process_input_us: (t2 - t1).as_micros() as u32,
            wait_output_us: (t3 - t2).as_micros() as u32,
        };
        // Whatever else is already queued.
        loop {
            let Mode::Async { events, .. } = &self.mode else { unreachable!() };
            match events.try_recv() {
                Ok(ev) => self.handle_event(ev, out)?,
                Err(_) => break,
            }
        }
        Ok(())
    }

    /// Waits for one encoder event until `deadline`. Returns false on
    /// timeout; errors if the encoder has gone away.
    fn wait_event(&mut self, deadline: Instant, out: &mut Vec<EncodedFrame>) -> Result<bool> {
        let Mode::Async { events, .. } = &self.mode else { unreachable!() };
        let left = deadline.saturating_duration_since(Instant::now());
        match events.recv_timeout(left) {
            Ok(ev) => {
                self.handle_event(ev, out)?;
                Ok(true)
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if deadline <= Instant::now() && out.is_empty() {
                    let Mode::Async { need_input, .. } = &self.mode else { unreachable!() };
                    if *need_input == 0 {
                        return Err(BarkError::Encode(format!("{} stopped responding", self.name)));
                    }
                }
                Ok(false)
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(BarkError::Encode(format!("{} stopped", self.name))),
        }
    }

    fn handle_event(&mut self, ev: AsyncEvent, out: &mut Vec<EncodedFrame>) -> Result<()> {
        match ev {
            AsyncEvent::NeedInput => {
                if let Mode::Async { need_input, .. } = &mut self.mode {
                    *need_input += 1;
                }
            }
            AsyncEvent::HaveOutput => {
                if let Some(f) = self.pull()? {
                    out.push(f);
                }
            }
            AsyncEvent::Other => {}
        }
        Ok(())
    }

    /// Takes one encoded frame from the encoder, if it has one.
    fn pull(&mut self) -> Result<Option<EncodedFrame>> {
        unsafe {
            let provided = if self.provides_samples {
                None
            } else {
                let buffer = MFCreateMemoryBuffer(self.output_size).map_err(|e| win("output buffer", e))?;
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
                    if let Ok(t) = self.transform.GetOutputAvailableType(0, 0) {
                        let _ = self.transform.SetOutputType(0, &t, 0);
                    }
                    return Ok(None);
                }
                Err(e) => return Err(win("the encoder failed", e)),
            }
            let Some(sample) = sample else { return Ok(None) };
            let mut data = mf::sample_bytes(&sample)?;
            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) != 0 || h264::is_keyframe(&data);
            if keyframe && !h264::has_parameter_sets(&data) && !self.sequence_header.is_empty() {
                // A decoder joining here needs the parameter sets.
                let mut with = self.sequence_header.clone();
                with.extend_from_slice(&data);
                data = with;
            }
            Ok(Some(EncodedFrame { data, keyframe }))
        }
    }

    fn gpu_sample(&self, nv12: &ID3D11Texture2D, time: i64, duration: i64) -> Result<IMFSample> {
        unsafe {
            let buffer = MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, nv12, 0, false)
                .map_err(|e| win("could not hand a frame to the encoder", e))?;
            if let Ok(b2) = buffer.cast::<IMF2DBuffer>() {
                if let Ok(len) = b2.GetContiguousLength() {
                    let _ = buffer.SetCurrentLength(len);
                }
            }
            let sample = MFCreateSample().map_err(|e| win("sample", e))?;
            sample.AddBuffer(&buffer).map_err(|e| win("sample", e))?;
            sample.SetSampleTime(time).map_err(|e| win("sample", e))?;
            sample.SetSampleDuration(duration).map_err(|e| win("sample", e))?;
            Ok(sample)
        }
    }

    /// The software encoder needs the frame in system memory: copy it out of
    /// the GPU through a staging texture.
    fn memory_sample_from(&self, nv12: &ID3D11Texture2D, staging: &ID3D11Texture2D, time: i64, duration: i64) -> Result<IMFSample> {
        let (w, h) = (self.settings.width as usize, self.settings.height as usize);
        let mut bytes = vec![0u8; w * h * 3 / 2];
        unsafe {
            self.gpu.context.CopyResource(staging, nv12);
            let mut map = D3D11_MAPPED_SUBRESOURCE::default();
            self.gpu
                .context
                .Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut map))
                .map_err(|e| win("could not read the frame back from the GPU", e))?;
            let pitch = map.RowPitch as usize;
            let src = map.pData as *const u8;
            // Luma rows, then the interleaved chroma rows that follow them
            // in the same allocation.
            for row in 0..h {
                std::ptr::copy_nonoverlapping(src.add(row * pitch), bytes.as_mut_ptr().add(row * w), w);
            }
            for row in 0..h / 2 {
                std::ptr::copy_nonoverlapping(
                    src.add((h + row) * pitch),
                    bytes.as_mut_ptr().add(w * h + row * w),
                    w,
                );
            }
            self.gpu.context.Unmap(staging, 0);
        }
        mf::memory_sample(&bytes, time, duration)
    }
}

impl Gpu {
    fn staging_nv12(&self, width: u32, height: u32) -> Result<ID3D11Texture2D> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_NV12,
            SampleDesc: windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
            Usage: D3D11_USAGE_STAGING,
            BindFlags: 0,
            CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
            MiscFlags: 0,
        };
        let mut tex = None;
        unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }
            .map_err(|e| win("could not create a staging texture", e))?;
        tex.ok_or_else(|| BarkError::Windows("no staging texture".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bitrate_scales_with_pixels_and_stays_in_bounds() {
        assert_eq!(default_bitrate_kbps(640, 360, 30), 4_000, "floor");
        assert_eq!(default_bitrate_kbps(7680, 4320, 60), 40_000, "ceiling");
        let hd = default_bitrate_kbps(1920, 1080, 60);
        assert!((9_000..=11_000).contains(&hd), "1080p60 is about 10 Mbit/s: {hd}");
    }
}
