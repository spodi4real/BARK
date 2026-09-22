# BARK — Architecture and Technology Decisions

Bright Arrow Remote-Access Kit
Document version 1.0

---

## 1. Components

BARK ships as **one program, `BARK.exe`**, identical on every machine. Windows forces a
separation between services and interactive desktops, so the same executable runs as several
*processes*, chosen by how it is started:

| Started as | Runs as | Purpose |
|---|---|---|
| `BARK.exe` (double-click) | Logged-in user | The classic Win32 GUI: favorites, pairing, settings, diagnostics, and the remote session window (decode + render + input capture). If no BARK service is installed, it hosts the node itself ("standalone" mode, like a portable remote-access tool). |
| `BARK.exe --service` | Windows Service, LocalSystem, auto-start | The **node**: owns the device identity, keeps the connection to the coordination server, authenticates peers, owns the one network socket, launches the session agent. Hosts the optional *coordination server* and *relay* roles. Survives logout/lock/reboot. |
| `BARK.exe --agent` | LocalSystem, inside the *interactive* Windows session | Screen capture, encode, input injection, clipboard, privacy mode, input blocking. Launched by the service into whichever session is on the console; relaunched on logon, logoff, lock and desktop switch. |

There is no separate server product and no separate relay product. Those are **roles** a normal
installation can take on — see section 17.

The GUI and the agent never touch the network or the private key. They talk to the service over
local named pipes; the service is the only process with a socket and the only one that can sign.
That keeps "one socket per device" (which NAT traversal depends on) and keeps the key in a
SYSTEM-only process.

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

**As built (2026-09-22), `bark-net::peer`:** B punches (8-byte packets QUIC discards, sent every
40 ms for 5 s from its one socket, via a duplicate handle of the socket QUIC uses) *before*
answering, so its NAT is open by the time A dials. A then starts a QUIC connection to every
candidate at once; LAN candidates get a 30 ms head start, applied only when there is a LAN
candidate. First to complete wins; the rest are dropped. Direct attempts are given 4 s. B only
completes a handshake with a device it accepted an introduction from in the last 60 s (the
"gate"); an incoming connection with nothing expected is refused before any TLS work.

Limitation to know: the server can only report the address it *sees*. A BARK server inside the
office sees office machines by their LAN addresses, so from outside the office there is no public
address to punch towards and sessions use the relay. Hole punching across the internet needs the
coordination server (or a small reflector) on a public address.

---

## 6. Relay fallback

If no candidate pair completes within about two seconds (both sides behind symmetric NAT, or a
firewall that blocks inbound UDP), BARK falls back automatically. **Connection: RELAYED.**

### How relaying works

A relay is a **UDP packet forwarder**, nothing more. The two peers still run one end-to-end QUIC
connection between themselves; the relay just moves its packets from one side to the other.

1. The controller asks the coordination server for a relay.
2. The server picks a relay (section 17) and issues a **relay ticket** to each peer over their
   authenticated control connections. The ticket names the relay, both peers' fingerprints, a
   random session id and an expiry, and is **signed by the coordination server's device key**.
3. Each peer sends a small *bind* packet carrying its ticket to the relay, from the same socket it
   uses for everything else.
4. The relay checks the signature against the coordination server's public key, checks the ticket
   names *this* relay, checks expiry, and records the sender's address. Once both peers are bound
   it forwards every packet from one to the other.
5. The controller then opens its normal QUIC connection to the relay's address, and the relay
   forwards it to the remote. Session code is identical for direct and relayed paths.

### Why the relay cannot read or hijack a session

* The QUIC connection is end-to-end between the two peers. The relay sees ciphertext.
* The session handshake is **bound to that QUIC connection** (TLS exporter channel binding, see
  section 12). A relay that tried to terminate TLS itself and run two separate connections would
  produce two different exporter values, and both peers' signatures would fail. So even a
  malicious relay can only drop traffic — it can never read it, alter it or impersonate a peer.
* A relay cannot be used as an open proxy: it forwards only between the two addresses that
  presented valid, unexpired tickets signed by the pinned coordination server.

Hole punching **continues in the background** on a relayed session; if a direct path appears, a
new direct connection is established and the session moves to it (planned; see project state).

**As built (2026-09-22), two refinements of the steps above:**

* *One socket per relayed session, not the node's main socket.* A plain forwarder can tell
  sessions apart only by sender address. With the main socket, two relayed sessions through the
  same relay (two people controlling one server, or one controller with two remotes) would be
  indistinguishable. Each peer therefore binds a fresh socket to the relay for each relayed
  session. Hole punching still uses the main socket, where it has to.
* *Tokens instead of signed tickets, for now.* The relay runs inside the coordination-server role,
  in the same process, so the server hands each peer a random single-use token over its
  authenticated control connection and the relay checks it against shared memory. Tokens are
  issued only for a connection the target accepted within the last 60 s. Server-signed tickets
  (step 2 above) become necessary when relays run on other machines, which is not built yet.

Controls implemented and tested: 32 sessions per relay, 60 Mbit/s per session per direction
(token bucket, quarter-second burst), unbound allocations expire after 30 s and silent sessions
after 60 s, no answer at all to unknown senders or forged tokens, a bound side cannot be taken
over, every allocation audited.

UDP blocked entirely (some guest Wi-Fi) is not handled in the first version; a TCP/TLS fallback on
port 443 is planned.

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
* **Session**: the peer-to-peer QUIC connection is TLS 1.3 end to end between the two devices.
  Its certificates are not trusted for identity; instead a signed handshake (SIGMA: ephemeral
  X25519 plus Ed25519 device signatures) runs as the first thing on the connection, and its
  signed transcript includes the connection's **TLS exporter value** (RFC 5705 / RFC 9266
  channel binding). Anyone terminating TLS in the middle — a hostile relay, a rogue server that
  lied about addresses — ends up with two TLS sessions and two different exporter values, so the
  signatures fail and the session is refused. Once the handshake succeeds, all session traffic
  (video, input, clipboard, files) rides the channel-bound QUIC connection.
  **The server never holds session keys and cannot decrypt a session, relayed or not.**

  *Design change, recorded honestly:* the first draft layered a second ChaCha20-Poly1305
  encryption inside QUIC. Channel binding gives the same guarantee — only the two devices can
  read the session, and a man in the middle is detected — without encrypting everything twice or
  reimplementing datagram protection that QUIC already provides. The ChaCha20 session cipher in
  `bark-crypto` remains tested and available but is not on the data path.
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

---

## 17. Roles: one build, several capabilities

Every machine runs the same `BARK.exe`. What differs is which **roles** an administrator has
switched on in that machine's settings (stored in `C:\ProgramData\BARK\config.json`, writable only
by administrators and the service).

| Role | Default | What it does |
|---|---|---|
| **Node** | always on | Can be controlled (if it has paired controllers) and can control devices it has paired with. |
| **Coordination server** | off; chosen at install ("This computer is the BARK server") | Device directory, presence, introductions, relay tickets. Needs one always-on machine. |
| **Relay** | on for the coordination-server machine, off elsewhere | Forwards encrypted packets between two peers that cannot reach each other directly. |

### Why relaying is opt-in rather than automatic on every PC

Turning every desk PC into a relay would sound resilient but would be a bad trade:

* **Resources.** A relayed 4K session is tens of megabits per second through someone's desk PC,
  and its upload link. The owner of that PC did not ask for that.
* **Reachability.** A relay only helps if *it* is reachable from both sides. A typical office PC
  behind the same NAT as one peer is often no better placed than the peers themselves; relays
  are useful precisely because they sit somewhere well connected.
* **Exposure.** Every relay listens on an extra public UDP port. Fewer listeners is less attack
  surface, even though a relay cannot be used to reach the machine it runs on.

So relaying is a deliberate administrator choice per machine, with sensible defaults: the
always-on server relays; anything else relays only if an administrator ticks "Allow this computer
to relay connections for other BARK devices".

### Choosing a relay, and what happens when it disappears

Relay-capable nodes announce the capability when they sign in to the coordination server, along
with a capacity limit. When a relay is needed the server picks, in order:

1. The coordination server's own machine, if its relay role is on and it is under capacity.
2. Any other online relay-capable node, least loaded first.

If the chosen relay goes offline mid-session, the session drops, BARK's automatic reconnection
asks again, and the server picks the next available relay. The operator sees a reconnect, not a
dead session.

### Security and resource controls on a relay

* **No access to the relay machine.** The relay listens on its own port, separate from the
  session endpoint. Packets arriving there are forwarded or dropped; they never reach the BARK
  node's session logic, so relaying for others gives nobody any way into the relay machine.
* **Tickets only.** Forwarding requires a ticket signed by the coordination server the relay
  itself is pinned to, naming this relay, naming both peers, unexpired. No ticket, no forwarding.
  A relay is never an open proxy.
* **Contents unreadable.** Relayed traffic is end-to-end QUIC with a channel-bound handshake
  (section 12). The relay machine cannot read the screen, keystrokes, clipboard or files, and a
  malicious relay can only drop traffic, never read or alter it.
* **Limits.** Maximum concurrent relayed sessions and a per-session bandwidth cap, configurable,
  with conservative defaults. Idle bindings expire.
* **Audited.** Every relay allocation is recorded in the coordination server's audit log.

### As built (2026-09-22)

Relaying runs on the coordination-server machine only (selection step 1). Relay-capable nodes
other than the server (step 2), capacity announcement and relay failover are designed above but
not built. The Settings checkbox is enabled only on the server computer and says so.

### Known limitation

The coordination server itself is a single point of failure for *discovery*: if it is offline,
devices cannot find each other or be introduced. Sessions already running are unaffected. Planned
mitigations: nodes remember a peer's last working direct address and try it first, and a second
coordination server can be designated later.

---

## 18. Video pipeline as built (2026-09-22)

* **Capture:** DXGI Desktop Duplication, one monitor (the first). BARK copies each new frame into
  its own texture at once and releases Windows' copy. The pointer shape travels separately
  (including inverting cursors such as the text I-beam, sent with XOR semantics) and becomes the
  controller's local hardware cursor. "Access lost" (UAC prompt, lock screen, mode change) reopens
  capture and tells the controller why the picture paused.
* **Convert:** Direct3D 11 video processor, BT.709 limited range on the YUV side, set explicitly
  in both directions.
* **Encode:** Media Foundation. The graphics card's hardware H.264 encoder where it accepts the
  settings (asynchronous MFTs, driven by a small event thread), otherwise Windows' software
  encoder. Low-latency mode, constant bitrate, no B-frames, keyframes on request (loss, decoder
  reset, "Refresh Picture"). Starting bitrate ~0.08 bit/pixel/frame within 4-40 Mbit/s. Three NV12
  textures in rotation so the encoder never reads a frame being overwritten.
* **Pacing (remote):** at most 60 frames a second; changes arriving faster are merged into the
  next frame, never queued. Nothing is sent while the screen is still.
* **Transport:** frames split into QUIC datagrams (`bark-proto::video`). No second encryption
  layer (section 12). The controller asks for a keyframe on any lost frame, at most five times a
  second. Session sockets use 8 MB receive / 4 MB send buffers (Windows' 64 KB default dropped
  keyframe bursts; see MEASUREMENTS.md).
* **Decode and display:** Windows' H.264 decoder in low-latency mode with DXVA (GPU), a
  flip-model swap chain with tearing allowed, presented the moment a frame decodes, picture kept
  to its shape with black bars.
* **Timer resolution:** BARK requests 1 ms timer resolution and opts out of Windows 11 ignoring
  that request for hidden windows. Measured: the Intel encoder went from ~30 ms to ~8 ms a frame.
* **Input:** controller window messages (mouse, wheel, keys as scancodes) are sent the moment
  they arrive; the remote applies them with `SendInput` on a dedicated thread and remembers held
  keys so everything is released when focus is lost or the session ends. Raw Input, the Windows
  key and Alt+Tab (which Windows intercepts before any window sees them) are not forwarded yet;
  the Actions menu sends them instead. Ctrl+Alt+Del needs the service (SendSAS), not built.
* **Latency figures** in the session window are all measured: QUIC's RTT estimate; remote time
  from the frame reaching the remote screen (DXGI's own present timestamp) to sending; decode and
  present; and input-to-frame — the remote stamps each frame with the controller's own clock
  reading of the last input it applied, so no clock synchronisation is involved.
* **Visibility:** the controlled computer shows a topmost notice naming the controller with an
  End Session button, for as long as the session lasts. It cannot be closed except by ending the
  session.

Not built: the Windows service and session agent (so no sign-in screen, lock screen or elevated
windows yet — standalone mode is subject to Windows' UIPI), multiple monitors in one session,
monitor switching in the UI, adaptive bitrate from network feedback, clipboard, file transfer,
the TCP/443 fallback.
