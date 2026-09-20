# BARK — Architecture and Technology Decisions

Bright Arrow Remote-Access Kit
Document version 1.0

---

## 1. Components

BARK ships as **one installer** producing **one logical product** per machine. Internally it is
four executables, because Windows forces a separation between services and interactive desktops.

| Executable | Runs as | Purpose |
|---|---|---|
| `bark-service.exe` | Windows Service, LocalSystem, auto-start | Owns device identity. Keeps the control connection to the coordination server. Authenticates incoming peers. Launches and supervises the session agent. Survives logout/lock/reboot. |
| `bark-agent.exe`   | LocalSystem, inside the *interactive* Windows session | Screen capture, hardware encode, input injection, clipboard, privacy mode, input blocking. Re-launched automatically on session switch, logon, logoff, and desktop switch (e.g. to the secure/UAC desktop). |
| `BARK.exe`         | Logged-in user | The classic Win32 GUI: favorites, pairing, settings, diagnostics, and the remote session window (decode + render + input capture). |
| `bark-server.exe`  | Windows Service on the always-on company machine | Directory, presence, authentication, connection negotiation, NAT traversal assistance, relay fallback, device management, audit log. |

### Why a service *and* an agent

Windows puts services in **Session 0**, which has no desktop and no screen. A service physically
cannot capture the screen or inject input. The supported, documented way to do this is for the
service to launch a process into the interactive session using `WTSGetActiveConsoleSessionId` +
`WTSQueryUserToken` + `CreateProcessAsUser`. That process is `bark-agent.exe`.

This is the same mechanism every legitimate remote-administration product on Windows uses. It is
not a security bypass — it requires the service to already be SYSTEM, which requires an
administrator to have installed it.

Because the service is the thing that auto-starts and the agent is disposable, BARK keeps working
when nobody is logged in, when the machine is locked, and at the Windows login screen (the agent
attaches to the `Winlogon` desktop in that state).

---

## 2. How devices discover each other

Every node opens **one persistent QUIC connection** to the coordination server and keeps it open
forever, with a low-rate keepalive. This single connection provides:

* **Presence** — if the connection is up, the device is ONLINE. No polling, no 30-second staleness.
* **Signaling** — the server can push a "device X wants to connect to you" message instantly.
* **NAT discovery** — the server observes the public IP and UDP port the packets arrive from.
  That *is* the device's NAT mapping, so the server doubles as its own STUN server. No third-party
  STUN service, no extra configuration.

Because it is QUIC over UDP, the keepalive also holds the NAT mapping open, so the device is
reachable at that address without any port forwarding.

---

## 3. Pairing (happens once, ever)

1. On the machine to be controlled, the operator opens BARK and reads its **Device ID**
   (`BA-XXXX-XXXX`) and a **pairing code**. Alternatively an administrator sets a permanent
   *unattended access password*, which is what the central server will use.
2. On the controlling machine, the operator enters the Device ID and the code.
3. The server verifies both devices exist, is **not** told the code, and forwards the pairing
   request to the target along with the requester's **Ed25519 public key**.
4. The target verifies the code locally, and on success writes the requester's public key into its
   own **local trust store** — permanently.
5. Both sides record each other as trusted and exchange display names.

The code is used exactly once, to bootstrap trust. It is never needed again.

---

## 4. How persistent trust works

On installation, each device generates an **Ed25519 keypair**.

* **Device ID** = `BA-` + Crockford-Base32 of the first 40 bits of `SHA-256(public key)`, formatted
  as two groups of four, with a check character. Short enough to read over the phone, long enough
  to not collide, and **derived from the key** — so a device cannot claim someone else's ID.
* The **private key** is stored in `C:\ProgramData\BARK\identity.dat`, encrypted with
  **DPAPI machine scope** (`CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE`), in a directory
  ACL'd to `SYSTEM` and `Administrators` only. It never leaves the machine and is never written
  in plaintext.
* Every connection is authenticated by **signing a fresh random challenge** issued by *both* the
  server and the peer. Replay is impossible because the challenge is new each time.

Consequences, which are exactly what was asked for:

* A reboot does not break pairing — the key is on disk.
* A new IP address, new network, or new country does not break pairing — trust is key-based, not
  address-based.
* A Windows update does not break pairing — DPAPI machine keys survive updates.
* Pairing ends **only** when an administrator revokes it.

**Revocation**: removing a device from the trust store immediately invalidates its credentials. The
server additionally keeps a revocation list so it refuses to even signal for a revoked pair.

---

## 5. Direct connections

To connect Controller (A) to Target (B):

1. A sends `ConnectRequest{target: B}` on its control channel.
2. Server checks A is in B's trust store and neither is revoked, then pushes `ConnectOffer` to B
   containing A's **candidate addresses**: its public IP:port as seen by the server, plus every
   private LAN address A enumerated locally.
3. B answers with its own candidate list.
4. Both sides begin **simultaneous UDP hole punching**: each sends small probe packets to every
   candidate of the other. The simultaneous outbound packets cause both NATs to open a mapping,
   after which the inbound packets are accepted.
5. LAN candidates are probed first and given a head start, so two machines in the same office
   connect over the local network at sub-millisecond latency and never touch the internet.
6. The first candidate pair to complete a round trip wins. A QUIC connection is established over
   it. **Connection: DIRECT.**

This succeeds for the large majority of real-world networks (full-cone, restricted-cone, and
port-restricted NATs, and most symmetric NATs when only one side is symmetric).

---

## 6. Relay fallback

If no candidate pair completes within ~1.5 seconds (both sides behind symmetric NAT, or a
firewall that blocks UDP entirely), BARK falls back automatically.

Both devices already hold an open QUIC connection to the server. The server allocates a relay
session and forwards datagrams between them. **Connection: RELAYED.**

Two important properties:

* The relay forwards **already-end-to-end-encrypted** bytes. The server cannot read the screen,
  the keystrokes, or the files. It is a dumb pipe.
* Hole punching **continues in the background**. If a direct path becomes available (network
  changed, VPN connected, moved to the office), the session **upgrades to direct mid-session**
  without disconnecting, and the status bar changes from RELAYED to DIRECT.

If UDP is blocked entirely, the relay is reachable over QUIC-on-443 and, as a last resort, a
TCP/TLS fallback on 443 so that BARK works even on hostile guest Wi-Fi.

---

## 7. Screen capture

**Primary: DXGI Desktop Duplication API** (`IDXGIOutputDuplication`).

* Delivers each frame as an `ID3D11Texture2D` **already in GPU memory**. No CPU copy, no readback.
* Reports **dirty rectangles** and **move rectangles** for free — the OS tells us exactly which
  pixels changed, so a mostly-static desktop costs almost nothing.
* Blocks until a frame actually changes, so an idle desktop uses ~0% CPU and ~0 bandwidth.
* Captures the whole output including the cursor position/shape as separate metadata, so the
  cursor can be drawn client-side at zero latency (more on this below).

**Fallback: Windows.Graphics.Capture** (WinRT) for the cases Desktop Duplication refuses: some
virtual displays, some nested-RDP situations, and per-window capture.

**Multiple monitors**: each output is duplicated independently. The controller can view one monitor
at a time or all of them stitched, and switch instantly from the toolbar.

**Headless / no monitor attached** (a real problem on a server with no display): BARK installs an
optional **Indirect Display Driver** so the machine always has a capturable virtual display at a
chosen resolution, even with no physical monitor plugged in.

### Client-side cursor — the single biggest perceived-latency win

The remote cursor is **not** drawn into the video. Its shape and position are sent as tiny separate
messages, and the controller draws it locally as a hardware overlay. The result is that the mouse
pointer responds at local speed even when the video stream is a frame or two behind. This is why a
well-built remote desktop feels "instant" while a naive one feels like a slideshow.

---

## 8. Video encoding

Hardware encode, **zero-copy directly from the captured GPU texture**:

| GPU | Encoder | Codecs |
|---|---|---|
| NVIDIA | NVENC | H.264, HEVC, AV1 (Ada+) |
| Intel  | QuickSync via Media Foundation | H.264, HEVC, AV1 (Arc+) |
| AMD    | AMF | H.264, HEVC, AV1 (RDNA3+) |
| none   | software (openh264) | H.264, reduced settings |

Encoder configuration is tuned for **latency**, not for file size:

* **Ultra-low-latency / low-delay preset**, **zero B-frames** (a B-frame requires a future frame,
  which means buffering, which means latency — unacceptable).
* **Infinite GOP with keyframes only on demand.** Periodic keyframes cause a periodic bandwidth
  spike and a periodic stutter. Instead the decoder asks for one only when it actually needs one.
* **Reference-frame invalidation** on packet loss instead of a full keyframe — the encoder is told
  "frame N never arrived, don't reference it", which repairs the stream at a fraction of the cost.
* **Slice-based output**: the encoder emits slices as they finish, so transmission of a frame
  begins before the frame has finished encoding.
* **Rate control**: CBR with a tiny VBV buffer (one frame), plus adaptive quantization so text and
  window edges stay sharp while smooth gradients absorb the compression.
* **Content-adaptive**: on a static desktop BARK drops to low frame rate and raises quality to
  visually lossless; on video or dragging windows it raises frame rate and lets quality dip. Text
  stays readable because dirty-rectangle encoding keeps unchanged text untouched.

Target: capture-to-encoded-bitstream under **3 ms** on this class of hardware.

---

## 9. Transport

**QUIC** (via `quinn`), which is the correct choice here for one specific reason: **independent
streams**. In TCP, one lost video packet stalls *everything* behind it, including your keystrokes.
That head-of-line blocking is what makes TCP-based remote desktop feel bad on imperfect networks.

BARK uses:

* **Unreliable QUIC datagrams** for video. A retransmitted stale frame is worse than a dropped one;
  BARK handles loss with reference invalidation instead.
* **A dedicated high-priority reliable stream for input.** Keystrokes and clicks can never be
  stuck behind video data.
* Separate streams for clipboard, file transfer, and control, so a 2 GB file transfer cannot
  degrade the interactive experience.
* **Congestion control tuned for interactivity** — a delay-based controller (BBR/GCC-style) that
  reacts to *queue growth* rather than waiting for packet loss, because by the time a bufferbloated
  link is dropping packets it has already added 300 ms of latency.
* **Adaptive bitrate** driven by measured throughput, RTT trend, and loss, reacting within a few
  frames.

---

## 10. Input

* Controller captures mouse with **Raw Input** (`WM_INPUT`) — unfiltered, unaccelerated deltas plus
  absolute position. Windows pointer acceleration is applied once, on the remote machine, not
  twice.
* Input events are **sent immediately and individually**. No coalescing, no "input tick". Each
  carries a sequence number and a high-resolution client timestamp (`QueryPerformanceCounter`).
* Injected remotely with `SendInput`. The agent runs as SYSTEM, which allows injecting into
  elevated windows and the secure desktop where policy permits.
* The remote echoes back the timestamp of the last input it processed, and the next encoded frame
  carries it. That lets the controller compute **true input-to-photon latency** — not a guess, not
  a network ping.

Supported: all buttons, wheel, horizontal wheel, full keyboard including modifiers and the Windows
key, function keys, and Ctrl+Alt+Delete (injected via the documented SAS mechanism).

---

## 11. File transfer

A dedicated QUIC stream, chunked with per-chunk BLAKE3 hashes.

* Drag-and-drop into and out of the session window, plus an explorer-style transfer panel.
* Resume: the receiver reports which chunks it already has, so an interrupted 4 GB transfer
  continues instead of restarting.
* Shows speed, progress, ETA, pause and cancel.
* Never overwrites silently — collisions prompt.
* Rate-limited relative to the video stream so a transfer never destroys interactivity.

---

## 12. Security model

* **Identity**: Ed25519 per device, private key under DPAPI machine scope, never exported.
* **Transport**: QUIC with TLS 1.3 to the server.
* **Session**: an additional **end-to-end** handshake inside the tunnel — X25519 ECDH for key
  agreement, Ed25519 signatures for authentication, ChaCha20-Poly1305 for the session.
  **The server never holds session keys and cannot decrypt a session, relayed or not.**
* **Replay protection**: fresh random challenges plus per-message monotonic nonces.
* **Brute-force protection**: pairing codes are rate-limited with exponential backoff, expire, and
  are single-use. Repeated failures lock pairing and raise an audit event.
* **Revocation**: immediate, enforced at both the peer and the server.
* **Audit log**: append-only, records connections, actions, and transfers. Never records
  keystrokes, screen contents, passwords, or keys.

**Explicitly not implemented**: keylogging, hidden/stealth mode, credential capture, AV/EDR
evasion, hidden persistence, backdoors, unauthenticated access, hardcoded secrets. BARK announces
itself in Programs and Features, runs under its own name, and shows a visible indicator during a
session.

---

## 13. The coordination server

Runs on the always-on company machine. **Not** on the development laptop — nothing in BARK
depends on the laptop being online.

* Single `bark-server.exe`, installed as a Windows service by the same installer (choose
  "This computer is the BARK Server").
* **SQLite embedded** — no database to install, configure, or back up separately.
* **Self-configuring on first run**: generates its server identity, creates its data directory,
  adds its own Windows Firewall rules, and prints the join information the other machines need.
* Optional automatic HTTPS certificate if the company has a domain name; otherwise BARK uses its
  own certificate pinning, which is actually *stronger* than public CA trust for a closed network
  and needs no DNS or certificate administration at all.
* The same machine can simultaneously be the company server, a BARK node you connect to, the
  coordination server, and the relay. That is a supported and recommended configuration for a
  small company. Separating them is only necessary at a scale you do not have.

---

## 14. Why Rust

Ranked against the stated priorities: performance, low latency, Windows integration, reliability,
security, maintainability.

* **No garbage collector.** A GC pause is a visible stutter in a 60 fps interactive session. This
  rules out C# for the capture/encode/network path.
* **C++-equivalent performance** with direct access to DXGI, Direct3D 11, Media Foundation, the
  Service Control Manager, and Win32 — via the `windows` crate, which is Microsoft's own officially
  maintained binding generator. Nothing on Windows is out of reach.
* **Memory safety where it matters most.** BARK listens on a network *as SYSTEM*. In C or C++, one
  buffer-handling mistake in the packet parser is a remote SYSTEM compromise on every company
  machine. Rust eliminates that entire class of vulnerability at compile time. For this specific
  product that is the single strongest technical argument.
* **Single self-contained `.exe`**, a few megabytes, no runtime for the operator to install, fast
  cold start. (.NET would require the runtime; Electron is not a serious option for this.)
* **Best-in-class QUIC and cryptography** already available and audited: `quinn`, `rustls`, `ring`.
* **Fearless concurrency** — capture, encode, send, and input handling run on separate threads with
  the compiler proving there are no data races.

The GUI is **real Win32** — genuine menus, toolbar, ListView, status bar, and dialogs with common
controls v6. Not a web view, not a modern UI framework. That is both the fastest option and
exactly the classic engineering-tool appearance required.

---

## 15. How latency is measured and optimised

Every frame carries timestamps stamped at eight points:

```
capture_begin -> capture_end -> encode_begin -> encode_end
      -> send -> receive -> decode_begin -> decode_end -> present
```

plus the echoed timestamp of the last input the remote processed.

From these the controller computes, per stage, live:

* capture latency
* encode latency
* network transit (one-way, derived from a continuously calibrated clock offset)
* queueing/pacing delay
* decode latency
* render/present latency
* **total input-to-photon latency**

The Connection Information panel shows these as real numbers, not a single FPS figure. When total
latency rises, BARK compares the stages against their normal baselines and names the *specific*
stage that regressed — remote CPU saturation, encoder queue, network RTT, loss-induced
retransmission, or controller render stall — and says so in plain English.

This instrumentation is not a diagnostic afterthought. It is how the system is tuned, and it is
built in from the first commit rather than added later.

---

## 16. Deliberate anti-goals

* No subscriptions, no device limits, no session time limits, no nag screens, no advertising.
* No telemetry to anyone outside the company.
* No cloud dependency. The company's own server is the only infrastructure.
* No modern SaaS visual design.
* No AI branding of any kind.
