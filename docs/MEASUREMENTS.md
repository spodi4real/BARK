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

### Latency accounting

| Measurement | Result |
|---|---|
| Clock offset recovery over a 3-second skew | **0 µs error** |
| Percentile reporting | median 8.5 ms, p95 40 ms, worst 40 ms on a deliberately spiky sample |

The offset test is synthetic — it proves the arithmetic, not the behaviour on a
real network. Real one-way transit accuracy cannot be measured until the
networking layer exists.

---

## What is NOT yet measured

Stated plainly so this document is not mistaken for more than it is:

* **Screen capture latency** — no capture code exists yet.
* **Encode latency** — no encoder exists yet. NVENC and QuickSync are both
  present on this machine but neither has been touched.
* **Real-network RTT, loss and jitter** — only loopback has been measured.
* **NAT traversal** — hole punching is designed but not written, so its success
  rate on real networks is unknown. This is the single biggest open question in
  the project: if it fails often, sessions fall back to the relay and latency
  rises by a whole extra hop.
* **Relay fallback** — not written.
* **Congestion control under loss** — BBR is configured on reasoning, not on
  measurement. It has never been compared against Cubic on a real link.
* **Decode and render latency** — not built.
* **True input-to-photon latency** — the number that actually matters, and the
  one that can only be measured when every stage above exists.
* **`harden_directory`** — the ACL lockdown on `C:\ProgramData\BARK` is written
  but not yet exercised, because it needs Administrator rights and a real
  install. It will be verified during installer testing.

The foundation being fast says nothing about whether BARK will feel fast. It
says the foundation will not be the reason it does not.
