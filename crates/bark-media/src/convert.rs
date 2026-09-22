//! Colour conversion and scaling on the graphics card.
//!
//! Uses the Direct3D 11 video processor — dedicated fixed-function hardware
//! on every modern GPU — so converting a 4K frame costs almost nothing and no
//! shader is needed.
//!
//! Colour space is set explicitly on both ends (BT.709, limited range for the
//! YUV side, full range for RGB). Leaving it to defaults gives BT.601 on some
//! drivers and BT.709 on others, and the picture comes out subtly wrong —
//! reds too orange, greys slightly green.

use crate::gpu::{win, Gpu};
use bark_core::{BarkError, Result};
use windows::core::Interface;
use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::DXGI_RATIONAL;

/// Which way the conversion goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Desktop image (BGRA) to encoder input (NV12).
    RgbToYuv,
    /// Decoder output (NV12) to the screen (BGRA).
    YuvToRgb,
}

/// D3D11_VIDEO_PROCESSOR_COLOR_SPACE bit layout: Usage (bit 0), RGB_Range
/// (bit 1, 1 = limited), YCbCr_Matrix (bit 2, 1 = BT.709), YCbCr_xvYCC
/// (bit 3), Nominal_Range (bits 4-5: 1 = 16-235, 2 = 0-255).
const RGB_FULL: u32 = 0;
const YUV_709_LIMITED: u32 = (1 << 2) | (1 << 4);

pub struct Converter {
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    pub input_size: (u32, u32),
    pub output_size: (u32, u32),
}

impl Converter {
    pub fn new(gpu: &Gpu, direction: Direction, input: (u32, u32), output: (u32, u32)) -> Result<Self> {
        let video_device: ID3D11VideoDevice =
            gpu.device.cast().map_err(|e| win("this graphics driver has no video processor", e))?;
        let video_context: ID3D11VideoContext =
            gpu.context.cast().map_err(|e| win("this graphics driver has no video processor", e))?;
        let desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL { Numerator: 60, Denominator: 1 },
            InputWidth: input.0,
            InputHeight: input.1,
            OutputFrameRate: DXGI_RATIONAL { Numerator: 60, Denominator: 1 },
            OutputWidth: output.0,
            OutputHeight: output.1,
            // Speed over quality: a remote desktop cannot afford the extra
            // filtering passes, and at 1:1 there is nothing to filter.
            Usage: D3D11_VIDEO_USAGE_OPTIMAL_SPEED,
        };
        let enumerator = unsafe { video_device.CreateVideoProcessorEnumerator(&desc) }
            .map_err(|e| win("could not set up colour conversion", e))?;
        let processor = unsafe { video_device.CreateVideoProcessor(&enumerator, 0) }
            .map_err(|e| win("could not set up colour conversion", e))?;

        let (input_cs, output_cs) = match direction {
            Direction::RgbToYuv => (RGB_FULL, YUV_709_LIMITED),
            Direction::YuvToRgb => (YUV_709_LIMITED, RGB_FULL),
        };
        unsafe {
            video_context.VideoProcessorSetStreamFrameFormat(&processor, 0, D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
            video_context.VideoProcessorSetStreamColorSpace(
                &processor,
                0,
                &D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: input_cs },
            );
            video_context
                .VideoProcessorSetOutputColorSpace(&processor, &D3D11_VIDEO_PROCESSOR_COLOR_SPACE { _bitfield: output_cs });
            // No automatic "enhancement": it is not deterministic across
            // drivers and costs time.
            video_context.VideoProcessorSetStreamAutoProcessingMode(&processor, 0, false);
            // Black bars where the picture does not fill the window.
            let black = D3D11_VIDEO_COLOR {
                Anonymous: D3D11_VIDEO_COLOR_0 { RGBA: D3D11_VIDEO_COLOR_RGBA { R: 0.0, G: 0.0, B: 0.0, A: 1.0 } },
            };
            video_context.VideoProcessorSetOutputBackgroundColor(&processor, false, &black);
        }

        Ok(Converter { video_device, video_context, enumerator, processor, input_size: input, output_size: output })
    }

    /// Converts `input` (array slice `slice`) into `output`, drawing the
    /// picture into `dest` within the output (the whole output if `None`).
    pub fn run(
        &self,
        input: &ID3D11Texture2D,
        slice: u32,
        output: &ID3D11Texture2D,
        dest: Option<RECT>,
    ) -> Result<()> {
        let in_desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV { MipSlice: 0, ArraySlice: slice },
            },
        };
        let out_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 { Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 } },
        };
        let mut in_view = None;
        let mut out_view = None;
        unsafe {
            self.video_device
                .CreateVideoProcessorInputView(input, &self.enumerator, &in_desc, Some(&mut in_view))
                .map_err(|e| win("could not read a video frame for conversion", e))?;
            self.video_device
                .CreateVideoProcessorOutputView(output, &self.enumerator, &out_desc, Some(&mut out_view))
                .map_err(|e| win("could not write a converted video frame", e))?;
        }
        let out_view = out_view.ok_or_else(|| BarkError::Windows("no output view".into()))?;

        let full = RECT { left: 0, top: 0, right: self.output_size.0 as i32, bottom: self.output_size.1 as i32 };
        let dest = dest.unwrap_or(full);
        let source = RECT { left: 0, top: 0, right: self.input_size.0 as i32, bottom: self.input_size.1 as i32 };
        unsafe {
            self.video_context.VideoProcessorSetStreamSourceRect(&self.processor, 0, true, Some(&source));
            self.video_context.VideoProcessorSetStreamDestRect(&self.processor, 0, true, Some(&dest));
            self.video_context.VideoProcessorSetOutputTargetRect(&self.processor, true, Some(&full));
        }

        let stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            pInputSurface: std::mem::ManuallyDrop::new(in_view),
            ..Default::default()
        };
        let streams = [stream];
        let r = unsafe { self.video_context.VideoProcessorBlt(&self.processor, &out_view, 0, &streams) };
        // The stream struct holds its view in a ManuallyDrop; release it.
        let [mut s] = streams;
        unsafe { std::mem::ManuallyDrop::drop(&mut s.pInputSurface) };
        r.map_err(|e| win("colour conversion failed", e))
    }
}

/// The largest rectangle with the picture's shape that fits in the window,
/// centred. The rest is black bars.
pub fn fit(picture: (u32, u32), window: (u32, u32)) -> RECT {
    let (pw, ph) = (picture.0.max(1) as u64, picture.1.max(1) as u64);
    let (ww, wh) = (window.0.max(1) as u64, window.1.max(1) as u64);
    let (w, h) = if pw * wh > ph * ww { (ww, ph * ww / pw) } else { (pw * wh / ph, wh) };
    let left = ((ww - w) / 2) as i32;
    let top = ((wh - h) / 2) as i32;
    RECT { left, top, right: left + w as i32, bottom: top + h as i32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wide_picture_in_a_square_window_gets_bars_top_and_bottom() {
        let r = fit((1920, 1080), (1000, 1000));
        assert_eq!((r.left, r.right), (0, 1000));
        assert_eq!(r.bottom - r.top, 562);
        assert_eq!(r.top, (1000 - 562) / 2);
    }

    #[test]
    fn a_tall_picture_gets_bars_at_the_sides() {
        let r = fit((1080, 1920), (1000, 1000));
        assert_eq!((r.top, r.bottom), (0, 1000));
        assert_eq!(r.right - r.left, 562);
    }

    #[test]
    fn an_exact_fit_has_no_bars() {
        assert_eq!(fit((1920, 1080), (1920, 1080)), RECT { left: 0, top: 0, right: 1920, bottom: 1080 });
    }
}
