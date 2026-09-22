# BARK — Measured Baseline

Every number here was measured by `bark-doctor.exe`, not estimated. Re-run it
after any change to the foundation and compare.

```
cargo build -p bark-doctor --release
target\release\bark-doctor.exe
```

---

## Reference machine

| | |
|---|---|
| Machine | DESKTOP-CIKJRFQ |
| OS | Windows 11 Pro 25H2 (build 26200) |
| CPU | Intel Core i7-13650HX, 20 logical processors |
| Memory | 24 GB |
| GPU | NVIDIA RTX 3050 6GB Laptop (NVENC) + Intel UHD (QuickSync) |
| Toolchain | rustc 1.98.1, MSVC 14.44.35207, Windows SDK 10.0.26100 |
| Date | 2026-09-21 |

Build profile: `release` — opt-level 3, fat LTO, one codegen unit.

---

## Baseline, 2026-09-21

### Timing

| Measurement | Result | Why it matters |
|---|---|---|
| Clock read cost | **25 ns** | BARK stamps 8 timestamps per frame plus one per input event. At 25 ns that is ~200 ns per frame — 0.001% of a 16.67 ms budget. Instrumentation is effectively free. |
| Clock resolution | **100 ns** | Fine enough to see a sub-microsecond regression in any stage. |
| Monotonicity | never regressed over 100,000 reads | Stage timings can be subtracted without guarding for negative values. |

### Frame pacing

Sleep accuracy, measured as overshoot beyond the requested duration:

| Requested | BARK high-resolution timer | `std::thread::sleep` |
|---|---|---|
| 1.00 ms | median +0.54 ms, p95 +0.72 ms | median +0.64 ms |
| 4.00 ms | median +0.22 ms, p95 +0.60 ms | median +0.18 ms |
| 16.67 ms | median +0.41 ms, p95 +0.70 ms | median +0.41 ms |

**Honest finding:** on this machine, Windows 11's ordinary sleep is already about
as accurate as the waitable timer for a plain sleep. The architecture document
implied a larger gap; that gap is not there on Windows 11 25H2. The real win is
in `sleep_until`, which spins the final stretch:

| Measurement | Result |
|---|---|
| `sleep_until` overshoot | **median 74 µs, p95 210 µs** |

That is a 5x improvement over the ~410 µs a raw sleep lands at, and it is the
call the frame pacer will actually make. Worth keeping, but the justification is
the spin tail, not the timer object.

### Device identity (real Windows DPAPI, machine scope)

| Measurement | Result |
|---|---|
| Ed25519 keypair generation | **53 µs** |
| DPAPI protect + atomic write | **4.1 ms** |
| Identity file size | 358 bytes |
| Private key present in file | **no** |
| Tampered file detected | **yes** |

4.1 ms is slow relative to everything else here, but it happens once at service
start and once per pairing change. Not on any hot path.

### Session handshake (SIGMA: signed ephemeral Diffie-Hellman)

| Measurement | Result |
|---|---|
| Full handshake, both sides | **median 261 µs, p95 486 µs** |

Sub-millisecond, so handshake cost is invisible next to a single network round
trip. Connection setup time will be dominated by the network, which is correct.

### Session encryption (ChaCha20-Poly1305)

Measured on 1100-byte fragments — the size BARK actually sends — rather than
large buffers, which would flatter the result by amortising per-packet overhead.

| Measurement | Result |
|---|---|
| Encrypt one fragment | **1.82 µs** |
| Throughput | **4,845 Mbit/s** |

A 4K60 session at high quality is roughly 60 Mbit/s, so encryption uses about
**1.2% of one core** at that rate. Encryption will never be the bottleneck, and
end-to-end encryption is therefore free in latency terms — which is what makes
"the relay cannot read your session" cost nothing.

### Input path

| Measurement | Result |
|---|---|
| Encode one event (incl. a clock read) | **24 ns** |
| Decode one event | **2 ns** |
| Mouse move on the wire | **21 bytes** |

At 1000 events/second that is 24 µs of CPU per second and 21 KB/s of bandwidth.
This confirms the design decision to **never coalesce input events**: sending
every single one costs nothing measurable, and coalescing would cost a frame of
responsiveness.

### Video frame assembly

| Measurement | Result |
|---|---|
| Fragments per 200 KB keyframe | **180**, each ≤ 1117 bytes |
| Reassemble one keyframe | **130–178 µs** (varies between runs) |

**Largest CPU cost measured so far.** Still only ~1% of one core at 60 fps for
1080p, and the check passes with a 4x margin against a quarter-frame budget. It
involves 180 heap allocations and one 200 KB copy per frame, both avoidable with
a pooled buffer. Not optimising it now — per the agreed approach, this gets
revisited once real capture and encode exist and we can see whether it matters
against the whole pipeline. Recorded here so the decision is made against a
number rather than a guess.

### QUIC transport — **loopback only**

Read the caveat before the numbers. Loopback has no propagation delay, no loss
and an unlimited link, so these measure **BARK's own overhead with the network
removed**. They are a floor, not a prediction: real latency is this plus the
path. Their value is that a regression here is BARK's fault, with the network
ruled out as a cause.

| Measurement | Result | Meaning |
|---|---|---|
| QUIC connection setup | **1.64 ms** | TLS 1.3 handshake with a pinned certificate. One-off per connection. |
| Control message round trip | **median 45 µs, p95 121 µs** | Opening a stream, sending, replying, reading. |
| **Datagram round trip** | **median 34 µs, p95 45 µs, jitter 5 µs** | The path video takes. ~17 µs one way. |
| Max datagram payload offered | 1414 bytes | BARK currently sends 1117. |

The datagram figure is the important one: **the transport adds roughly 17 µs
each way to a video frame.** Against a 16.67 ms frame budget that is 0.1%, so
the transport layer will not be what makes a session feel slow.

**Follow-up noted, not acted on:** QUIC offered 1414-byte datagrams and BARK
used 1117, because `SAFE_DATAGRAM_PAYLOAD` is a fixed conservative constant
derived from QUIC's 1200-byte guaranteed minimum. Sizing fragments from the
connection's actual `max_datagram_size()` would cut a 200 KB keyframe from 180
fragments to about 145 — fewer packets, and fewer chances for one to be lost and
cost a whole frame. Worth doing, but only once real capture and encode exist and
the gain can be measured end to end rather than assumed.

### Coordination server — real binary, separate process, loopback

Measured by starting `bark-server.exe` as its own process and connecting to it
from `bark-doctor.exe --server` in another. This is the first measurement of
two BARK programs talking the way they will be deployed, rather than inside
one test process. Still loopback, so the network itself is absent.

| Measurement | Result | Meaning |
|---|---|---|
| Sign-in (QUIC + TLS + challenge signature + database write) | **21.5 ms** | Happens once, when the BARK service starts. Not on any interactive path. |
| Control round trip to the server | **median 87 µs, p95 265 µs, jitter 22 µs** | Higher than the in-process 45 µs, as expected: a real process boundary and real socket buffers. |
| 25 devices signing in at the same instant | **all 25 succeeded, 995 ms total** | A whole office rebooting after a power cut. |
| Sign-in time under that load | **median 155 ms, worst 284 ms** | |
| Server log after 26 sign-ins | **0 warnings, 0 errors** | 26 online, 26 offline, all accounted for. |
| Server binary size | **4.6 MB** | Includes SQLite. Nothing else to install. |

**Not yet explained:** one sign-in takes 21 ms alone but 155 ms when 25 arrive
together, so something serialises them. Candidates are the single SQLite
connection (each sign-in writes twice), TLS handshake CPU on the server, or the
test client generating 25 certificates at once on the same machine. It has not
been profiled, so it is recorded as unexplained rather than attributed to a
guess. It does not matter for use — a device signs in once at boot, and even a
simultaneous whole-office restart completes in under a second — but if a
deployment ever grows to hundreds of devices, this is the first thing to
profile.

Also verified against the real binary:

* The server key is **identical across restarts** (checked by running
  `--join-info` twice against the same data folder).
* A client holding the **wrong server key is refused** before signing in, with a
  message that names the expected and received keys and says what to do.

### Latency accounting

| Measurement | Result |
|---|---|
| Clock offset recovery over a 3-second skew | **0 µs error** |
| Percentile reporting | median 8.5 ms, p95 40 ms, worst 40 ms on a deliberately spiky sample |

The offset test is synthetic — it proves the arithmetic, not the behaviour on a
real network. Real one-way transit accuracy cannot be measured until the
networking layer exists.

---

## Build day, 2026-09-22 — sessions, relay, video pipeline

Same reference machine. Display: 1920x1080 on the Intel UHD Graphics (the
laptop panel is driven by the integrated GPU). Everything below ran on this
one laptop; **nothing has crossed a real network yet.**

### Session setup (loopback)

| Measurement | Result | Source |
|---|---|---|
| QUIC connect + channel-bound SIGMA handshake | **9.7 - 11.2 ms** | `bark-net` peer test |
| Same, through the real relay | **10.1 ms** (11.8 KB relayed) | `bark-server` relay_path test |
| Node Connect to authenticated session, direct | **8 - 9 ms** | `bark-node` sessions test |
| Node Connect to authenticated session, relayed (force_relay) | **9 - 12 ms** | `bark-node` sessions test |

Loopback hides the network entirely; these numbers say only that BARK adds a
few milliseconds of its own. Real session setup will be dominated by the
network round trips (about 4 of them).

### Video pipeline, real hardware (`bark-media` pipeline test, 120 frames)

| Stage | Result |
|---|---|
| Encoder chosen | Intel Quick Sync Video H.264 Encoder MFT (hardware), all latency settings accepted |
| Convert (GPU, BGRA to NV12) | 0.55 - 0.9 ms CPU time to submit |
| Convert + encode, **before** the timer fix | median **28.6 - 31.2 ms**, p95 35 ms |
| Convert + encode, **after** the timer fix | median **8.0 ms**, p95 9.2 - 10.0 ms |
| of which: encoder busy (hand-over to bitstream back) | **4 - 6 ms** |
| of which: waiting for the encoder to ask for input | ~1 ms (artefact of the back-to-back test loop) |
| Keyframe size, 1080p desktop | 121 - 127 KB |
| Decode (GPU, DXVA) + convert back | median **1.36 - 1.45 ms**, p95 1.9 ms |
| First frame decodes immediately (low-latency decoder) | yes, frame #0 |

**The timer fix.** Instrumenting the encoder showed every frame waiting two
~15 ms stretches: exactly the default Windows timer tick (15.6 ms). The Intel
driver's worker threads sleep while polling the hardware, and a sleep lasts
at least one tick. Requesting 1 ms timer resolution (`timeBeginPeriod(1)`),
and opting out of Windows 11's habit of ignoring that request for processes
whose windows are hidden (`PROCESS_POWER_THROTTLING_IGNORE_TIMER_RESOLUTION`),
cut the time by 3.6x. The encoder's own "fastest" speed setting made no
measurable difference, so ~5 ms is this encoder's floor at 1080p.

Target from the architecture was capture-to-bitstream under 3 ms. **Not met on
this machine's integrated GPU.** Untried: the RTX 3050's NVENC, which cannot be
fed directly because the display is on the Intel GPU (needs a cross-adapter
copy).

### Live session in the real GUI (two BARK windows on this laptop)

The remote screen is this same screen, so the picture is an infinite mirror
that changes every frame: a worst case for pacing.

| Figure (from the session window's status bar) | Before pacing fix | After |
|---|---|---|
| Frame rate | 40 fps | **55 fps** |
| Remote: screen present to send | 26 ms (included idle waiting — measurement bug) | **11.3 ms** |
| Decode + present | 2.0 ms | 2.4 ms |
| Round trip (QUIC estimator, loopback) | 1.1 ms | 1.1 ms |
| Bitrate | 6.7 Mbit/s | 9.3 Mbit/s |

Pacing bug: the next frame slot was measured from the end of encoding, so the
frame interval was 16.7 ms plus the encode time. Timestamp bug: capture time
was taken before waiting for a frame. "Remote" now starts at DXGI's own
record of when the frame reached the screen (`LastPresentTime`). In this
mirror test most of the remaining 11 ms is a frame waiting for its 60 fps
slot plus ~5 ms of encoding; ordinary use (typing) changes the screen less
often, so the slot is usually open.

**Input-to-frame latency** (the headline number) is measured and displayed by
the session window, but cannot be exercised on one machine: a controller on
the same computer would move the mouse under its own window, so BARK does not
apply input on a loopback session. It is the first thing to read on the
second machine.

### Socket buffers

| | Receive buffer |
|---|---|
| Windows default for a UDP socket | **65,536 bytes** |
| BARK session sockets now | **8,388,608 bytes** |

Found by an intermittently failing test: a 121 KB keyframe arriving as one
burst overflowed the 64 KB default when the machine was busy, the keyframe
could not be reassembled, and the next frame arrived first. The same would
happen on a real network. After the change: 6 consecutive full test runs,
291/291.

---

## What is NOT yet measured

Stated plainly so this document is not mistaken for more than it is:

* **A second physical computer.** Every number in this document comes from
  one laptop. Nothing has crossed a real network cable or Wi-Fi link.
* **Input-to-frame latency** — built, displayed, not yet observed (see above).
* **NAT traversal on real networks** — hole punching is built and tested on
  loopback only. Its success rate across real NATs is the biggest unknown.
  Note: with the BARK server inside the office, it sees office machines by
  their LAN addresses, so sessions from outside the office will use the relay
  (a server on the public internet is needed for hole punching across NATs).
* **Relay over a real network**, including through a port-forwarded router.
* **Congestion control under loss** — BBR is still configured on reasoning.
* **NVENC** on the RTX 3050.
* **Frame pacing on the controller** (present timing against the display's
  refresh) — frames are presented the moment they decode; not yet measured.
* **`harden_directory`** — needs Administrator rights and a real install.

The foundation being fast says nothing about whether BARK will feel fast. It
says the foundation will not be the reason it does not.
