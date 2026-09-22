//! Screen capture, video encoding, decoding and display.
//!
//! Everything here uses components that ship with Windows: DXGI Desktop
//! Duplication for capture, the Direct3D 11 video processor for colour
//! conversion and scaling, Media Foundation for H.264 (the graphics card's
//! own hardware encoder and decoder where there is one), and a flip-model
//! swap chain for display. No codec is bundled and nothing is installed.
//!
//! Frames stay on the graphics card from capture to encoder, and from decoder
//! to screen. The only copies over the bus are the compressed bitstream.

pub mod h264;

#[cfg(windows)]
pub mod capture;
#[cfg(windows)]
pub mod convert;
#[cfg(windows)]
pub mod decode;
#[cfg(windows)]
pub mod encode;
#[cfg(windows)]
pub mod gpu;
#[cfg(windows)]
pub mod mf;
#[cfg(windows)]
pub mod present;

#[cfg(windows)]
pub use capture::{Captured, CursorShape, DesktopCapture, Display};
#[cfg(windows)]
pub use convert::{Converter, Direction};
#[cfg(windows)]
pub use decode::{DecodedFrame, H264Decoder};
#[cfg(windows)]
pub use encode::{EncodedFrame, EncoderSettings, H264Encoder};
#[cfg(windows)]
pub use gpu::Gpu;
#[cfg(windows)]
pub use present::Presenter;
