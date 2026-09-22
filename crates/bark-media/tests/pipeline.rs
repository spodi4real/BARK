//! The real video pipeline on this computer's real hardware: capture the
//! screen, convert, encode, decode, convert back. Prints what it measured.
//!
//! These tests need a desktop to capture, so they are skipped (with a message)
//! when run where there is none, such as a service session.

use bark_media::capture::Captured;
use bark_media::convert::{Converter, Direction};
use bark_media::encode::{default_bitrate_kbps, EncoderSettings, H264Encoder};
use bark_media::{h264, DesktopCapture, H264Decoder};
use std::time::Instant;
use windows::Win32::Graphics::Direct3D11::{D3D11_BIND_FLAG, D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_NV12};

fn percentile(v: &mut [f64], p: f64) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[((v.len() as f64 - 1.0) * p).round() as usize]
}

#[test]
fn capture_encode_decode_round_trip() {
    if std::env::var("BARK_NO_TIMER").is_err() {
        bark_media::gpu::raise_timer_resolution();
    }
    let mut cap = match DesktopCapture::open(0) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIPPED: no capturable desktop here: {e}");
            return;
        }
    };
    let (w, h) = cap.size();
    // NV12 needs even dimensions.
    let (ew, eh) = (w & !1, h & !1);
    eprintln!("capturing {w}x{h} on {}", cap.gpu.adapter_name);

    // The first acquire after opening returns the current desktop.
    let t0 = Instant::now();
    let mut got = false;
    for _ in 0..20 {
        if cap.next(100).expect("capture") == Captured::Frame {
            got = true;
            break;
        }
    }
    assert!(got, "no frame captured within 2 seconds");
    eprintln!("first frame after {:.1} ms", t0.elapsed().as_secs_f64() * 1000.0);

    let gpu = cap.gpu.clone();
    let to_nv12 = Converter::new(&gpu, Direction::RgbToYuv, (w, h), (ew, eh)).expect("converter");
    let nv12 = gpu
        .texture(ew, eh, DXGI_FORMAT_NV12, D3D11_BIND_FLAG(D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0))
        .expect("nv12 texture");

    let settings = EncoderSettings { width: ew, height: eh, fps: 60, bitrate_kbps: default_bitrate_kbps(ew, eh, 60) };
    let mut enc = H264Encoder::new(&gpu, settings).expect("an encoder");
    eprintln!(
        "encoder: {} (hardware: {}), {} kbit/s, declined: {:?}",
        enc.name, enc.hardware, settings.bitrate_kbps, enc.declined
    );

    let mut frames = Vec::new();
    let mut encode_ms = Vec::new();
    let mut produced_per_call = Vec::new();
    let mut convert_ms = Vec::new();
    let mut parts = Vec::new();
    for i in 0..120 {
        let t = Instant::now();
        to_nv12.run(cap.texture(), 0, &nv12, None).expect("convert");
        convert_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let out = enc.encode(&nv12, i == 0).expect("encode");
        encode_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        parts.push(enc.timing);
        produced_per_call.push(out.len());
        frames.extend(out);
    }
    if std::env::var("BARK_TIMING").is_ok() {
        for (i, p) in parts.iter().enumerate().take(12) {
            eprintln!("  frame {i}: convert {:.2} ms, {p:?}", convert_ms[i]);
        }
    }
    let first = frames.first().expect("the encoder produced nothing");
    assert!(first.keyframe, "the first frame must be a keyframe");
    assert!(h264::has_parameter_sets(&first.data), "the first frame must carry SPS/PPS");
    let bytes: usize = frames.iter().map(|f| f.data.len()).sum();
    let late = produced_per_call.iter().filter(|&&n| n == 0).count();
    eprintln!(
        "convert+encode per frame: median {:.2} ms, p95 {:.2} ms, max {:.2} ms; {} frames out of 120 in; \
         {} calls returned nothing (frame came out later); keyframe {} bytes; total {} KB",
        percentile(&mut encode_ms.clone(), 0.5),
        percentile(&mut encode_ms.clone(), 0.95),
        percentile(&mut encode_ms.clone(), 1.0),
        frames.len(),
        late,
        first.data.len(),
        bytes / 1024
    );
    assert!(frames.len() >= 110, "most frames should come out: {}", frames.len());

    let mut dec = H264Decoder::new(&gpu).expect("a decoder");
    eprintln!("decoder hardware: {}", dec.hardware);
    let bgra = gpu
        .texture(ew, eh, DXGI_FORMAT_B8G8R8A8_UNORM, D3D11_BIND_FLAG(D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0))
        .expect("bgra texture");
    let mut decode_ms = Vec::new();
    let mut pictures = 0;
    let mut first_picture_after = None;
    let mut to_rgb: Option<Converter> = None;
    for (i, f) in frames.iter().enumerate() {
        let t = Instant::now();
        let pic = dec.decode(&f.data).expect("decode");
        if let Some(p) = pic {
            let c = to_rgb.get_or_insert_with(|| {
                Converter::new(&gpu, Direction::YuvToRgb, (p.width, p.height), (ew, eh)).expect("back converter")
            });
            c.run(&p.texture, p.slice, &bgra, None).expect("convert back");
            decode_ms.push(t.elapsed().as_secs_f64() * 1000.0);
            if pictures == 0 {
                first_picture_after = Some(i);
                assert_eq!((p.width, p.height), (ew, eh), "decoded picture has the captured size");
            }
            pictures += 1;
        }
    }
    eprintln!(
        "decode+convert per frame: median {:.2} ms, p95 {:.2} ms; {} pictures from {} frames; \
         first picture after frame #{}",
        percentile(&mut decode_ms.clone(), 0.5),
        percentile(&mut decode_ms.clone(), 0.95),
        pictures,
        frames.len(),
        first_picture_after.unwrap_or(usize::MAX)
    );
    assert_eq!(first_picture_after, Some(0), "low latency: the first frame must decode immediately");
    assert!(pictures >= frames.len() - 1, "every frame should decode");
}
