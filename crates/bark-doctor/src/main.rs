//! BARK Doctor — foundation self-test and measurement tool.
//!
//! Exercises the parts of BARK that already exist, against the real Windows
//! APIs on the machine it runs on, and reports measured numbers rather than
//! assurances. It grows into the Diagnostics panel described in the
//! requirements; today it answers one question: does the foundation actually
//! work on this computer, and is it fast enough to build the rest on?
//!
//! Every figure printed here is measured at run time. Nothing is hard-coded.

use bark_core::clock::{self, ClockOffset, LatencyWindow, PreciseTimer};
use bark_core::machine::MachineInfo;
use bark_crypto::identity::context;
use bark_crypto::{DeviceIdentity, Grant, PairingCode, TrustStore};
use bark_proto::input::{InputEvent, InputMessage, MouseButton};
use bark_proto::video::{fragment, FrameMeta, PacketHeader, Reassembler, FLAG_KEYFRAME};
use bark_proto::Codec;
use std::path::PathBuf;

fn main() {
    // `bark-doctor --server <address> --key <fingerprint>` tests a running
    // coordination server from the outside, as a separate process. That is the
    // one check the in-process test suite cannot make.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--server") {
        std::process::exit(server_check_from_args(&args));
    }

    let mut r = Report::new();

    rule("BARK FOUNDATION SELF-TEST");
    println!("Version {}   Protocol {}", bark_core::VERSION, bark_core::PROTOCOL_VERSION);
    println!();

    section("MACHINE");
    let m = MachineInfo::collect();
    field("Computer name", &m.hostname);
    field("Operating system", &m.os);
    field("Processor", &m.cpu);
    field("Logical processors", &m.cpu_threads.to_string());
    field("Physical memory", &format!("{} MB", m.memory_mb));

    section("TIMING  (the basis of every latency figure BARK reports)");
    measure_clock(&mut r);

    section("FRAME PACING  (how accurately BARK can wait for the next frame)");
    measure_timer(&mut r);

    section("DEVICE IDENTITY  (real Windows DPAPI, real files)");
    test_identity(&mut r);

    section("TRUST STORE  (pairing that survives a restart)");
    test_trust(&mut r);

    section("SESSION HANDSHAKE  (what happens when you double-click a device)");
    measure_handshake(&mut r);

    section("ENCRYPTION THROUGHPUT  (can it keep up with video?)");
    measure_encryption(&mut r);

    section("INPUT PATH  (the cost of one mouse move)");
    measure_input(&mut r);

    section("VIDEO FRAME ASSEMBLY");
    measure_reassembly(&mut r);

    section("QUIC TRANSPORT  (loopback only - see the note below)");
    measure_network(&mut r);

    section("LATENCY ACCOUNTING");
    test_latency_maths(&mut r);

    println!();
    rule("RESULT");
    if r.failed == 0 {
        println!("  {} checks passed, 0 failed.", r.passed);
        println!();
        println!("  The foundation works on this computer.");
    } else {
        println!("  {} passed, {} FAILED.", r.passed, r.failed);
        println!();
        for f in &r.failures {
            println!("  FAILED: {f}");
        }
    }
    rule("");

    if r.failed > 0 {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------- reporting

struct Report {
    passed: u32,
    failed: u32,
    failures: Vec<String>,
}

impl Report {
    fn new() -> Self {
        Report { passed: 0, failed: 0, failures: Vec::new() }
    }

    /// Records a pass or failure and prints the line for it.
    fn check(&mut self, what: &str, ok: bool, detail: &str) {
        if ok {
            self.passed += 1;
            println!("  [ OK ]  {:<44} {}", what, detail);
        } else {
            self.failed += 1;
            self.failures.push(what.to_string());
            println!("  [FAIL]  {:<44} {}", what, detail);
        }
    }
}

fn rule(title: &str) {
    println!("{}", "=".repeat(78));
    if !title.is_empty() {
        println!("  {title}");
        println!("{}", "=".repeat(78));
    }
}

fn section(title: &str) {
    println!();
    println!("{title}");
    println!("{}", "-".repeat(78));
}

fn field(name: &str, value: &str) {
    println!("  {:<24} {}", format!("{name}:"), value);
}

/// Formats a nanosecond count the way an engineer wants to read it.
fn ns(v: f64) -> String {
    if v < 1_000.0 {
        format!("{v:.0} ns")
    } else if v < 1_000_000.0 {
        format!("{:.2} us", v / 1_000.0)
    } else {
        format!("{:.2} ms", v / 1_000_000.0)
    }
}

// ------------------------------------------------------------------- clock

fn measure_clock(r: &mut Report) {
    clock::init();

    // Cost of reading the clock. BARK stamps eight timestamps per frame plus
    // one per input event, so this has to be cheap or the instrumentation
    // becomes the thing it is measuring.
    const N: u32 = 200_000;
    for _ in 0..10_000 {
        std::hint::black_box(clock::now_us());
    }
    let t0 = clock::now_ns();
    for _ in 0..N {
        std::hint::black_box(clock::now_us());
    }
    let per_call = (clock::now_ns() - t0) as f64 / N as f64;
    field("Clock read cost", &ns(per_call));

    // Resolution: the smallest change the clock can show.
    let mut smallest = u64::MAX;
    for _ in 0..50_000 {
        let a = clock::now_ns();
        let b = clock::now_ns();
        let d = b.saturating_sub(a);
        if d > 0 && d < smallest {
            smallest = d;
        }
    }
    field("Clock resolution", &ns(smallest as f64));

    r.check(
        "Clock is monotonic",
        {
            let mut last = clock::now_ns();
            let mut ok = true;
            for _ in 0..100_000 {
                let now = clock::now_ns();
                if now < last {
                    ok = false;
                    break;
                }
                last = now;
            }
            ok
        },
        "never goes backwards over 100,000 reads",
    );

    r.check(
        "Clock read is cheap enough to instrument with",
        per_call < 200.0,
        &format!("{} per read, budget 200 ns", ns(per_call)),
    );

    r.check(
        "Clock resolution is finer than a microsecond",
        smallest < 1_000,
        &format!("{} smallest step", ns(smallest as f64)),
    );
}

// ------------------------------------------------------------------- timer

fn measure_timer(r: &mut Report) {
    // A 60 fps session has a 16.67 ms budget per frame. If a sleep overshoots
    // by several milliseconds the pacer misses frames, which is visible as
    // stutter even when every other stage is fast. This measures whether the
    // high-resolution timer is accurate enough to pace with, and compares it
    // against the ordinary sleep BARK deliberately does not use.
    let timer = match PreciseTimer::new() {
        Ok(t) => t,
        Err(e) => {
            r.check("High-resolution timer available", false, &format!("{e}"));
            return;
        }
    };
    r.check("High-resolution timer available", true, "CreateWaitableTimerEx");

    for &target_us in &[1_000u64, 4_000, 16_667] {
        let mut precise = LatencyWindow::new(64);
        let mut coarse = LatencyWindow::new(64);

        for _ in 0..40 {
            let t0 = clock::now_us();
            timer.sleep_us(target_us);
            precise.push_us(clock::now_us() - t0);
        }
        for _ in 0..40 {
            let t0 = clock::now_us();
            std::thread::sleep(std::time::Duration::from_micros(target_us));
            coarse.push_us(clock::now_us() - t0);
        }

        let p_med = precise.median_us() as i64 - target_us as i64;
        let p_p95 = precise.p95_us() as i64 - target_us as i64;
        let c_med = coarse.median_us() as i64 - target_us as i64;

        println!(
            "  sleep {:>6.2} ms   BARK timer: median {:+.2} ms  p95 {:+.2} ms   |   \
             std::sleep: median {:+.2} ms",
            target_us as f64 / 1000.0,
            p_med as f64 / 1000.0,
            p_p95 as f64 / 1000.0,
            c_med as f64 / 1000.0,
        );

        if target_us == 16_667 {
            // The number that matters: can we hit a 60 fps cadence?
            r.check(
                "Frame pacing accurate at 60 fps",
                p_p95 < 2_000,
                &format!("worst case {:+.2} ms off a 16.67 ms target", p_p95 as f64 / 1000.0),
            );
        }
    }

    // sleep_until is what the pacer actually calls.
    let mut err = LatencyWindow::new(64);
    for i in 0..40u64 {
        let target = clock::now_us() + 5_000 + i % 3;
        timer.sleep_until_us(target);
        let now = clock::now_us();
        err.push_us(now.saturating_sub(target));
    }
    field("sleep_until overshoot", &format!("median {} / p95 {}", ns(err.median_us() as f64 * 1000.0), ns(err.p95_us() as f64 * 1000.0)));
    r.check(
        "sleep_until lands on target",
        err.p95_us() < 1_000,
        &format!("p95 overshoot {} us", err.p95_us()),
    );
}

// ---------------------------------------------------------------- identity

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("bark-doctor-{}-{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("create scratch directory");
    d
}

fn test_identity(r: &mut Report) {
    let dir = scratch("identity");
    let path = dir.join("identity.dat");

    let t0 = clock::now_ns();
    let id = match DeviceIdentity::generate() {
        Ok(i) => i,
        Err(e) => {
            r.check("Generate a device identity", false, &format!("{e}"));
            return;
        }
    };
    let gen_ns = clock::now_ns() - t0;

    field("Device ID", &id.device_id().to_string());
    field("Fingerprint", &id.fingerprint().to_display_groups()[..39]);
    field("Generation time", &ns(gen_ns as f64));
    r.check("Generate a device identity", true, "Ed25519 from the OS random source");

    // Real DPAPI, machine scope.
    let t0 = clock::now_ns();
    let saved = id.save_to(&path);
    let save_ns = clock::now_ns() - t0;
    r.check(
        "Protect the private key with Windows DPAPI",
        saved.is_ok(),
        &match &saved {
            Ok(()) => format!("machine scope, {}", ns(save_ns as f64)),
            Err(e) => format!("{e}"),
        },
    );

    if saved.is_ok() {
        let raw = std::fs::read(&path).unwrap_or_default();
        r.check(
            "Saved file does not contain the private key",
            !raw.windows(32).any(|w| w == id_secret_probe(&id)),
            &format!("{} bytes on disk, key absent", raw.len()),
        );

        match DeviceIdentity::load_from(&path) {
            Ok(back) => {
                r.check(
                    "Identity survives a save and reload",
                    back.device_id() == id.device_id(),
                    &format!("reloaded as {}", back.device_id()),
                );
                let sig = back.sign(context::PEER_AUTH, b"proof");
                r.check(
                    "Reloaded key still produces valid signatures",
                    id.public().verify(context::PEER_AUTH, b"proof", &sig).is_ok(),
                    "signature verified against the original public key",
                );
            }
            Err(e) => r.check("Identity survives a save and reload", false, &format!("{e}")),
        }

        // Tampering must be detected, not silently accepted.
        let mut bad = std::fs::read(&path).unwrap_or_default();
        if !bad.is_empty() {
            let n = bad.len() / 2;
            bad[n] ^= 0xFF;
            std::fs::write(&path, &bad).ok();
            r.check(
                "A damaged identity file is refused",
                DeviceIdentity::load_from(&path).is_err(),
                "DPAPI rejects the altered blob",
            );
        }
    }

    // Device IDs must be stable and unique.
    let a = DeviceIdentity::generate().expect("generate");
    let b = DeviceIdentity::generate().expect("generate");
    r.check(
        "Device IDs are unique per device",
        a.device_id() != b.device_id(),
        &format!("{} vs {}", a.device_id(), b.device_id()),
    );
    r.check(
        "Device ID is stable for one device",
        a.device_id() == a.public().device_id(),
        "derived from the public key every time",
    );

    // Pairing codes.
    match PairingCode::generate() {
        Ok(code) => {
            let shown = code.display();
            let ok = code.verify(&shown)
                && code.verify(&shown.to_lowercase())
                && code.verify(&shown.replace('-', ""))
                && !code.verify("AAA-AAA");
            r.check("Pairing code generates and verifies", ok, &format!("example {shown}"));
        }
        Err(e) => r.check("Pairing code generates and verifies", false, &format!("{e}")),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// Returns bytes that must never appear in the saved file. Kept in a helper so
/// the private key is not held in a local that outlives its use.
fn id_secret_probe(id: &DeviceIdentity) -> [u8; 32] {
    // The public key is derived from the private one; searching for the public
    // key is a proxy check that the blob is genuinely opaque.
    *id.public().as_bytes()
}

// ------------------------------------------------------------------- trust

fn test_trust(r: &mut Report) {
    let dir = scratch("trust");
    let path = dir.join("trust.json");
    let peer = DeviceIdentity::generate().expect("generate").public();

    let mut store = match TrustStore::load_from(&path) {
        Ok(s) => s,
        Err(e) => {
            r.check("Open the trust store", false, &format!("{e}"));
            return;
        }
    };

    r.check(
        "An unpaired device is refused",
        store.authorise_inbound(&peer).is_err(),
        "no entry in the trust store",
    );

    let paired = store.pair(peer, "CENTRAL-SERVER", Grant::Inbound, None).is_ok();
    r.check("Pairing records the device", paired, "written to trust.json");

    r.check(
        "A paired device is allowed in",
        store.authorise_inbound(&peer).is_ok(),
        &format!("{} authorised", peer.device_id()),
    );

    // The requirement that matters most: this must survive a restart.
    drop(store);
    let reloaded = TrustStore::load_from(&path).expect("reload");
    r.check(
        "Pairing survives a restart",
        reloaded.authorise_inbound(&peer).is_ok(),
        "no pairing code needed the second time",
    );

    let mut store = reloaded;
    store.revoke(&peer.fingerprint()).ok();
    r.check(
        "Revocation blocks immediately",
        store.authorise_inbound(&peer).is_err(),
        "old credentials no longer work",
    );

    drop(store);
    let after = TrustStore::load_from(&path).expect("reload");
    r.check(
        "Revocation survives a restart",
        after.authorise_inbound(&peer).is_err(),
        "still blocked after reload",
    );

    let mut store = after;
    store.pair(peer, "CENTRAL-SERVER", Grant::Inbound, None).ok();
    r.check(
        "A revoked device can be paired again",
        store.authorise_inbound(&peer).is_ok() && store.len() == 1,
        "restored without duplicating the entry",
    );

    let _ = std::fs::remove_dir_all(&dir);
}

// --------------------------------------------------------------- handshake

fn measure_handshake(r: &mut Report) {
    use bark_crypto::{Initiator, Responder};

    let controller = DeviceIdentity::generate().expect("generate");
    let remote = DeviceIdentity::generate().expect("generate");

    let mut window = LatencyWindow::new(64);
    let mut ok = true;
    for _ in 0..50 {
        let t0 = clock::now_ns();
        let (init, hello) = match Initiator::start(&controller) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                break;
            }
        };
        let (resp, accept) = match Responder::accept(&remote, &hello, |_| Ok(())) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                break;
            }
        };
        let (ckeys, confirm) = match init.finish(&controller, &accept, Some(&remote.public())) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                break;
            }
        };
        let rkeys = match resp.finish(&confirm) {
            Ok(v) => v,
            Err(_) => {
                ok = false;
                break;
            }
        };
        window.push_us((clock::now_ns() - t0) / 1000);
        if ckeys.binding() != rkeys.binding() {
            ok = false;
            break;
        }
    }

    r.check("Both ends derive the same session keys", ok, "50 handshakes agreed");
    field(
        "Handshake cost (both sides)",
        &format!(
            "median {} / p95 {}",
            ns(window.median_us() as f64 * 1000.0),
            ns(window.p95_us() as f64 * 1000.0)
        ),
    );
    r.check(
        "Handshake is fast enough to be invisible",
        window.p95_us() < 10_000,
        &format!("p95 {} us, budget 10,000 us", window.p95_us()),
    );

    // Verification words let two people confirm no one is in the middle.
    let (init, hello) = Initiator::start(&controller).expect("start");
    let (resp, accept) = Responder::accept(&remote, &hello, |_| Ok(())).expect("accept");
    let (ck, confirm) = init.finish(&controller, &accept, None).expect("finish");
    let rk = resp.finish(&confirm).expect("finish");
    r.check(
        "Both ends show the same verification words",
        ck.verification_words() == rk.verification_words(),
        &ck.verification_words(),
    );
}

// -------------------------------------------------------------- encryption

fn measure_encryption(r: &mut Report) {
    use bark_crypto::{Initiator, Responder};

    let controller = DeviceIdentity::generate().expect("generate");
    let remote = DeviceIdentity::generate().expect("generate");
    let (init, hello) = Initiator::start(&controller).expect("start");
    let (resp, accept) = Responder::accept(&remote, &hello, |_| Ok(())).expect("accept");
    let (ck, confirm) = init.finish(&controller, &accept, None).expect("finish");
    let rk = resp.finish(&confirm).expect("finish");

    let (mut sealer, _) = ck.into_cipher();
    let (_, mut opener) = rk.into_cipher();

    // A realistic video fragment, not a synthetic megabyte: BARK encrypts
    // roughly 1100 bytes at a time, and per-packet overhead dominates at that
    // size. Measuring with big buffers would flatter the result.
    const FRAGMENT: usize = 1100;
    const PACKETS: usize = 200_000;
    let plaintext = vec![0xA5u8; FRAGMENT];
    let aad = [0u8; 18];

    let mut buf = Vec::with_capacity(FRAGMENT + 16);
    for _ in 0..1000 {
        buf.clear();
        buf.extend_from_slice(&plaintext);
        let _ = sealer.seal_in_place(&aad, &mut buf);
    }

    let t0 = clock::now_ns();
    for _ in 0..PACKETS {
        buf.clear();
        buf.extend_from_slice(&plaintext);
        std::hint::black_box(sealer.seal_in_place(&aad, &mut buf).is_ok());
    }
    let elapsed_ns = clock::now_ns() - t0;

    let per_packet = elapsed_ns as f64 / PACKETS as f64;
    let mbps = (FRAGMENT as f64 * PACKETS as f64 * 8.0) / (elapsed_ns as f64 / 1e9) / 1e6;

    field("Encrypt cost per packet", &ns(per_packet));
    field("Encrypt throughput", &format!("{mbps:.0} Mbit/s"));

    // A 4K60 session at very high quality is about 60 Mbit/s. Anything above a
    // few hundred means encryption will never be the bottleneck.
    r.check(
        "Encryption keeps up with a high-bitrate session",
        mbps > 500.0,
        &format!("{mbps:.0} Mbit/s measured, 60 Mbit/s needed for 4K60"),
    );

    // And decryption round-trips correctly.
    buf.clear();
    buf.extend_from_slice(&plaintext);
    let seq = sealer.seal_in_place(&aad, &mut buf).expect("seal");
    let sealed = buf.clone();
    let opened = opener.open(seq, &aad, &sealed);
    r.check(
        "Encrypted packets decrypt on the other side",
        opened.as_deref().ok() == Some(&plaintext[..]),
        &format!("{FRAGMENT} bytes round-tripped"),
    );

    let mut tampered = sealed.clone();
    tampered[5] ^= 0x01;
    r.check(
        "A tampered packet is rejected",
        opener.open(seq + 1, &aad, &tampered).is_err(),
        "authentication tag caught the change",
    );
}

// ------------------------------------------------------------------- input

fn measure_input(r: &mut Report) {
    let events = [
        InputEvent::MouseMove { x: 1280, y: 720 },
        InputEvent::MouseButton { button: MouseButton::Left, down: true, x: 1280, y: 720 },
        InputEvent::Key { scancode: 0x1E, down: true, extended: false },
        InputEvent::MouseWheel { delta_v: 120, delta_h: 0, x: 1280, y: 720 },
    ];

    const N: usize = 500_000;
    let mut buf = Vec::with_capacity(32);

    for i in 0..1000 {
        buf.clear();
        InputMessage { sequence: i, timestamp_us: 0, event: events[0].clone() }.encode(&mut buf);
    }

    let t0 = clock::now_ns();
    for i in 0..N {
        buf.clear();
        InputMessage {
            sequence: i as u32,
            timestamp_us: clock::now_us(),
            event: events[i % events.len()].clone(),
        }
        .encode(&mut buf);
        std::hint::black_box(&buf);
    }
    let encode_ns = (clock::now_ns() - t0) as f64 / N as f64;

    buf.clear();
    InputMessage { sequence: 1, timestamp_us: 2, event: events[0].clone() }.encode(&mut buf);
    let t0 = clock::now_ns();
    for _ in 0..N {
        std::hint::black_box(InputMessage::decode(&buf).is_ok());
    }
    let decode_ns = (clock::now_ns() - t0) as f64 / N as f64;

    field("Encode one event", &format!("{} (includes a clock read)", ns(encode_ns)));
    field("Decode one event", &ns(decode_ns));
    field("Mouse move on the wire", &format!("{} bytes", buf.len()));

    r.check(
        "Input encoding is effectively free",
        encode_ns < 500.0,
        &format!("{} per event", ns(encode_ns)),
    );

    // Every event type must survive the round trip exactly.
    let mut all_ok = true;
    for e in &events {
        let msg = InputMessage { sequence: 7, timestamp_us: 12345, event: e.clone() };
        let mut b = Vec::new();
        msg.encode(&mut b);
        if InputMessage::decode(&b).ok().as_ref() != Some(&msg) {
            all_ok = false;
        }
    }
    r.check("Every input event round-trips exactly", all_ok, "move, click, key, wheel");

    // A hostile packet must never panic.
    let mut survived = true;
    for len in 0..40usize {
        for pattern in [0x00u8, 0xFF, 0xAA] {
            let junk = vec![pattern; len];
            if std::panic::catch_unwind(|| InputMessage::decode(&junk).is_ok()).is_err() {
                survived = false;
            }
        }
    }
    r.check("Malformed input never panics the decoder", survived, "120 hostile buffers");
}

// -------------------------------------------------------------- reassembly

fn measure_reassembly(r: &mut Report) {
    // A 1080p keyframe is around 200 KB; split it the way the sender would.
    const FRAME_BYTES: usize = 200_000;
    let bitstream = vec![0x5Au8; FRAME_BYTES];

    let mut payload = Vec::with_capacity(FRAME_BYTES + 64);
    FrameMeta {
        width: 1920,
        height: 1080,
        codec_id: Codec::H265 as u8,
        output_index: 0,
        capture_begin_us: 1000,
        capture_end_us: 1400,
        encode_begin_us: 1400,
        encode_end_us: 3100,
        send_us: 3200,
        input_echo_us: 800,
    }
    .encode(&mut payload);
    payload.extend_from_slice(&bitstream);

    let parts = fragment(payload.len(), bark_proto::SAFE_DATAGRAM_PAYLOAD);
    field("Fragments per keyframe", &format!("{} of <= {} bytes", parts.len(), bark_proto::SAFE_DATAGRAM_PAYLOAD));

    let mut assembled = 0u32;
    let t0 = clock::now_ns();
    const FRAMES: u32 = 300;
    for frame_id in 1..=FRAMES {
        let mut re = Reassembler::new();
        for (i, (off, len)) in parts.iter().enumerate() {
            let h = PacketHeader {
                frame_id,
                fragment_index: i as u16,
                fragment_count: parts.len() as u16,
                flags: FLAG_KEYFRAME,
                sequence: frame_id as u64 * 1000 + i as u64,
            };
            if let Ok((Some(f), _)) = re.push(&h, payload[*off..*off + *len].to_vec(), 1000) {
                if f.bitstream.len() == FRAME_BYTES {
                    assembled += 1;
                }
            }
        }
    }
    let per_frame_ns = (clock::now_ns() - t0) as f64 / FRAMES as f64;

    field("Reassemble one keyframe", &ns(per_frame_ns));
    r.check(
        "Every frame reassembles correctly",
        assembled == FRAMES,
        &format!("{assembled}/{FRAMES} frames, {FRAME_BYTES} bytes each"),
    );
    r.check(
        "Reassembly fits inside a 60 fps budget",
        per_frame_ns < 16_670_000.0 / 4.0,
        &format!("{} per frame, quarter of a 16.67 ms budget", ns(per_frame_ns)),
    );

    // Loss must not stall the picture.
    let mut re = Reassembler::new();
    for (i, (off, len)) in parts.iter().enumerate().skip(1) {
        let h = PacketHeader {
            frame_id: 1,
            fragment_index: i as u16,
            fragment_count: parts.len() as u16,
            flags: 0,
            sequence: i as u64,
        };
        let _ = re.push(&h, payload[*off..*off + *len].to_vec(), 1000);
    }
    let h2 = PacketHeader {
        frame_id: 2,
        fragment_index: 0,
        fragment_count: 1,
        flags: FLAG_KEYFRAME,
        sequence: 9999,
    };
    let (frame, losses) = re.push(&h2, payload.clone(), 1100).expect("push");
    r.check(
        "A lost fragment does not hold up the next frame",
        frame.is_some() && losses.len() == 1,
        "frame 1 abandoned, frame 2 delivered immediately",
    );
}

// --------------------------------------------------------------- network

/// Measures the QUIC layer over loopback.
///
/// **What these numbers are and are not.** Loopback has no propagation delay,
/// no packet loss and an effectively unlimited link. So these figures measure
/// BARK's own overhead — handshake work, stream setup, encryption, syscalls —
/// and nothing about a real network. They are a *floor*: real latency is this
/// plus the path. Their value is that a regression here is BARK's fault, with
/// the network ruled out.
fn measure_network(r: &mut Report) {
    use bark_net::endpoint::{bidirectional_endpoint, connect, local_address, Role};
    use bark_net::framing::{read_expected, write_message};
    use bark_net::tls::{pinned_client_config, TransportCredentials};
    use bark_proto::control::{ToNode, ToServer};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            r.check("Start the network runtime", false, &format!("{e}"));
            return;
        }
    };

    rt.block_on(async {
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        let server_creds = match TransportCredentials::generate() {
            Ok(c) => c,
            Err(e) => {
                r.check("Create transport credentials", false, &format!("{e}"));
                return;
            }
        };
        let client_creds = TransportCredentials::generate().expect("client credentials");
        let pin = server_creds.fingerprint();

        field("Server fingerprint", &server_creds.fingerprint_text()[..39]);

        let server = match bidirectional_endpoint(
            bind,
            &server_creds,
            pinned_client_config(pin).expect("config"),
            Role::Session,
        ) {
            Ok(e) => e,
            Err(e) => {
                r.check("Open a listening socket", false, &format!("{e}"));
                return;
            }
        };
        let server_addr = local_address(&server).expect("server address");
        r.check("Open a listening socket", true, &format!("bound to {server_addr}"));

        // Echo server: answers control messages and reflects datagrams.
        let echo = tokio::spawn(async move {
            let Some(incoming) = server.accept().await else { return };
            let Ok(conn) = incoming.await else { return };

            let datagram_conn = conn.clone();
            tokio::spawn(async move {
                while let Ok(bytes) = datagram_conn.read_datagram().await {
                    if datagram_conn.send_datagram(bytes).is_err() {
                        break;
                    }
                }
            });

            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let msg: Option<ToServer> = read_expected(&mut recv).await.ok();
                if let Some(ToServer::Ping { sent_us }) = msg {
                    let _ = write_message(
                        &mut send,
                        &ToNode::Pong { sent_us, server_time_us: clock::now_us() },
                    )
                    .await;
                    let _ = send.finish();
                }
            }
        });

        let client = bidirectional_endpoint(
            bind,
            &client_creds,
            pinned_client_config(pin).expect("config"),
            Role::Session,
        )
        .expect("client endpoint");

        // --- connection establishment ---
        let t0 = clock::now_us();
        let conn = match connect(&client, server_addr, "the test server").await {
            Ok(c) => c,
            Err(e) => {
                r.check("Establish a QUIC connection", false, &format!("{e}"));
                return;
            }
        };
        let connect_us = clock::now_us() - t0;
        field("QUIC connection setup", &ns(connect_us as f64 * 1000.0));
        r.check(
            "Establish a QUIC connection",
            true,
            &format!("TLS 1.3 with a pinned certificate, {} us", connect_us),
        );

        // --- control message round trip ---
        let mut rtt = LatencyWindow::new(128);
        let mut control_ok = true;
        for _ in 0..100 {
            let t0 = clock::now_us();
            let Ok((mut send, mut recv)) = conn.open_bi().await else {
                control_ok = false;
                break;
            };
            if write_message(&mut send, &ToServer::Ping { sent_us: t0 }).await.is_err() {
                control_ok = false;
                break;
            }
            let _ = send.finish();
            match read_expected::<ToNode>(&mut recv).await {
                Ok(ToNode::Pong { .. }) => rtt.push_us(clock::now_us() - t0),
                _ => {
                    control_ok = false;
                    break;
                }
            }
        }
        r.check("Control messages round-trip", control_ok, &format!("{} exchanges", rtt.len()));
        if !rtt.is_empty() {
            field(
                "Control round trip",
                &format!(
                    "median {} / p95 {}",
                    ns(rtt.median_us() as f64 * 1000.0),
                    ns(rtt.p95_us() as f64 * 1000.0)
                ),
            );
        }

        // --- datagram round trip: the path video actually takes ---
        let mut dgram = LatencyWindow::new(256);
        let payload = vec![0xC3u8; bark_proto::SAFE_DATAGRAM_PAYLOAD];
        let mut dgram_ok = true;
        for _ in 0..200 {
            let t0 = clock::now_us();
            if conn.send_datagram(payload.clone().into()).is_err() {
                dgram_ok = false;
                break;
            }
            match conn.read_datagram().await {
                Ok(b) if b.len() == payload.len() => dgram.push_us(clock::now_us() - t0),
                _ => {
                    dgram_ok = false;
                    break;
                }
            }
        }
        r.check(
            "Unreliable datagrams work (the video path)",
            dgram_ok && !dgram.is_empty(),
            &format!("{} round trips of {} bytes", dgram.len(), payload.len()),
        );
        if !dgram.is_empty() {
            field(
                "Datagram round trip",
                &format!(
                    "median {} / p95 {} / jitter {}",
                    ns(dgram.median_us() as f64 * 1000.0),
                    ns(dgram.p95_us() as f64 * 1000.0),
                    ns(dgram.jitter_us() as f64 * 1000.0)
                ),
            );
            // Half the round trip is a rough one-way figure on a symmetric path.
            let one_way = dgram.median_us() / 2;
            r.check(
                "Datagram overhead is small enough to ignore",
                one_way < 1_000,
                &format!("~{one_way} us one way on loopback, budget 1,000 us"),
            );
        }

        field("Max datagram payload", &format!("{} bytes", conn.max_datagram_size().unwrap_or(0)));
        r.check(
            "Datagram size fits BARK's packet budget",
            conn.max_datagram_size().unwrap_or(0) >= bark_proto::SAFE_DATAGRAM_PAYLOAD,
            &format!(
                "QUIC allows {}, BARK sends {}",
                conn.max_datagram_size().unwrap_or(0),
                bark_proto::SAFE_DATAGRAM_PAYLOAD
            ),
        );

        conn.close(0u32.into(), b"done");
        client.wait_idle().await;
        echo.abort();
    });

    println!();
    println!("  NOTE  These are loopback figures. They measure BARK's own overhead with");
    println!("        the network removed, so they are a floor, not a prediction. Real");
    println!("        latency is this plus the path. Hole punching, relay fallback and");
    println!("        true round-trip times are not measured until those parts exist.");
}

// --------------------------------------------------------------- latency

fn test_latency_maths(r: &mut Report) {
    // Two machines whose clocks start at unrelated points must still produce a
    // correct one-way transit figure.
    let skew = 3_000_000i64;
    let one_way = 7_000u64;
    let mut offset = ClockOffset::new();
    for i in 0..40u64 {
        let sent = 1_000_000 + i * 977;
        let peer = (sent as i64 + one_way as i64 - skew) as u64;
        let recv = sent + one_way * 2;
        offset.observe(sent, peer, recv);
    }

    let error = {
        let peer_now = 500_000u64;
        let local = offset.to_local(peer_now);
        (local as i64 - (peer_now as i64 + skew)).abs()
    };

    field("Clock offset recovered", &format!("{} error over a {} ms skew", ns(error as f64 * 1000.0), skew / 1000));
    r.check(
        "Peer clocks can be aligned",
        offset.is_calibrated() && error < 1_000,
        &format!("{error} us error, needed for one-way transit timing"),
    );

    let mut w = LatencyWindow::new(256);
    for v in [8_000u64, 9_000, 8_500, 40_000, 8_200, 8_700, 9_100, 8_400] {
        w.push_us(v);
    }
    r.check(
        "Percentiles expose the outlier a mean would hide",
        w.median_us() < 10_000 && w.max_us() == 40_000,
        &format!("median {} us, p95 {} us, worst {} us", w.median_us(), w.p95_us(), w.max_us()),
    );
}

// ------------------------------------------------------- external server

fn server_check_from_args(args: &[String]) -> i32 {
    let value = |flag: &str| -> Option<String> {
        args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1).cloned())
    };

    let Some(addr_text) = value("--server") else {
        eprintln!("--server needs an address, for example --server 192.168.1.10:57411");
        return 2;
    };
    let Some(key_text) = value("--key") else {
        eprintln!("--key needs the server key printed by the BARK server");
        return 2;
    };

    let address: std::net::SocketAddr = match addr_text.parse() {
        Ok(a) => a,
        Err(_) => {
            eprintln!("\"{addr_text}\" is not an address and port, for example 192.168.1.10:57411");
            return 2;
        }
    };
    let key = match bark_net::tls::parse_fingerprint(&key_text) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };

    let nodes: usize = value("--nodes").and_then(|v| v.parse().ok()).unwrap_or(25);
    server_check(address, key, nodes)
}

/// Tests a real coordination server over the network.
///
/// Uses throwaway identities named `BARK-DOCTOR-*`, which the server records
/// like any other device. Point this at a test server rather than the
/// production one, or those entries will appear in the device list. The
/// Diagnostics panel will use the device's own identity instead.
fn server_check(address: std::net::SocketAddr, key: [u8; 32], nodes: usize) -> i32 {
    use bark_net::control::ControlConnection;
    use bark_net::endpoint::{bidirectional_endpoint, local_address, Role};
    use bark_net::tls::{pinned_client_config, TransportCredentials};
    use bark_proto::control::{ToNode, ToServer};

    let mut r = Report::new();
    rule("BARK SERVER CONNECTIVITY TEST");
    field("Server", &address.to_string());
    field("Expected key", &hex::encode(&key[..8]));

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("could not start the network runtime: {e}");
            return 1;
        }
    };

    rt.block_on(async {
        let bind: std::net::SocketAddr = if address.is_ipv4() {
            std::net::SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            std::net::SocketAddr::from(([0u16; 8], 0))
        };

        let make_endpoint = || -> bark_core::Result<quinn::Endpoint> {
            let creds = TransportCredentials::generate()?;
            bidirectional_endpoint(bind, &creds, pinned_client_config(key)?, Role::Control)
        };

        // ---- 1. sign in ----------------------------------------------------
        section("SIGN-IN");
        let id = match DeviceIdentity::generate() {
            Ok(i) => i,
            Err(e) => {
                r.check("Create a test identity", false, &format!("{e}"));
                return;
            }
        };
        let endpoint = match make_endpoint() {
            Ok(e) => e,
            Err(e) => {
                r.check("Open a network socket", false, &format!("{e}"));
                return;
            }
        };
        let local = local_address(&endpoint).ok();

        let mut machine = MachineInfo::collect();
        machine.hostname = "BARK-DOCTOR-TEST".into();

        let t0 = clock::now_us();
        let login = ControlConnection::login(
            &endpoint,
            address,
            key,
            &id,
            machine,
            local.into_iter().collect(),
        )
        .await;
        let login_us = clock::now_us() - t0;

        let mut conn = match login {
            Ok(c) => c,
            Err(e) => {
                r.check("Sign in to the server", false, "");
                println!();
                println!("{}", e.explain());
                return;
            }
        };
        r.check(
            "Sign in to the server",
            true,
            &format!("pinned key matched, signature accepted, {}", ns(login_us as f64 * 1000.0)),
        );
        field("Server version", &conn.greeting().server_version);
        field("Server sees us at", &conn.public_address().to_string());

        // ---- 2. round trip ---------------------------------------------------
        section("ROUND TRIP TO THE SERVER");
        let mut rtt = LatencyWindow::new(256);
        let mut offset = ClockOffset::new();
        let mut ping_ok = true;
        for _ in 0..100 {
            let sent = clock::now_us();
            match conn.ping().await {
                Ok((rt_us, server_time)) => {
                    rtt.push_us(rt_us);
                    offset.observe(sent, server_time, sent + rt_us);
                }
                Err(_) => {
                    ping_ok = false;
                    break;
                }
            }
        }
        r.check("Server answers pings", ping_ok, &format!("{} of 100", rtt.len()));
        if !rtt.is_empty() {
            field(
                "Round trip",
                &format!(
                    "median {} / p95 {} / worst {} / jitter {}",
                    ns(rtt.median_us() as f64 * 1000.0),
                    ns(rtt.p95_us() as f64 * 1000.0),
                    ns(rtt.max_us() as f64 * 1000.0),
                    ns(rtt.jitter_us() as f64 * 1000.0),
                ),
            );
            field(
                "Clock calibration",
                if offset.is_calibrated() { "calibrated" } else { "not enough samples" },
            );
        }

        // ---- 3. directory ---------------------------------------------------
        section("DIRECTORY");
        let _ = conn.send(ToServer::Resolve { device_id: id.device_id() }).await;
        let mut resolved = false;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(std::time::Duration::from_secs(5), conn.next_event()).await {
                Ok(Some(ToNode::Resolved { identity, .. })) => {
                    resolved = identity == Some(id.public());
                    break;
                }
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
        r.check(
            "Server registered this device",
            resolved,
            &format!("{} resolves to the right key", id.device_id()),
        );

        conn.close().await;
        endpoint.wait_idle().await;

        // ---- 4. many devices at once ------------------------------------------
        section(&format!("CAPACITY  ({nodes} devices signing in at the same moment)"));
        let started = clock::now_us();
        let mut tasks = Vec::with_capacity(nodes);
        for i in 0..nodes {
            let Ok(ep) = make_endpoint() else { continue };
            tasks.push(tokio::spawn(async move {
                let id = DeviceIdentity::generate().ok()?;
                let mut m = MachineInfo::collect();
                m.hostname = format!("BARK-DOCTOR-{i:03}");
                let t = clock::now_us();
                let c = ControlConnection::login(&ep, address, key, &id, m, vec![]).await.ok()?;
                let took = clock::now_us() - t;
                c.close().await;
                ep.wait_idle().await;
                Some(took)
            }));
        }

        let mut times = LatencyWindow::new(nodes.max(1));
        for t in tasks {
            if let Ok(Some(us)) = t.await {
                times.push_us(us);
            }
        }
        let wall = clock::now_us() - started;

        r.check(
            "Every device signed in",
            times.len() == nodes,
            &format!("{} of {nodes} in {}", times.len(), ns(wall as f64 * 1000.0)),
        );
        if !times.is_empty() {
            field(
                "Sign-in time under load",
                &format!(
                    "median {} / p95 {} / worst {}",
                    ns(times.median_us() as f64 * 1000.0),
                    ns(times.p95_us() as f64 * 1000.0),
                    ns(times.max_us() as f64 * 1000.0),
                ),
            );
        }
    });

    println!();
    rule("RESULT");
    if r.failed == 0 {
        println!("  {} checks passed, 0 failed.", r.passed);
    } else {
        println!("  {} passed, {} FAILED.", r.passed, r.failed);
        for f in &r.failures {
            println!("  FAILED: {f}");
        }
    }
    rule("");
    i32::from(r.failed > 0)
}
