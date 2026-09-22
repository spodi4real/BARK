# BARK — Project State

> Read this first at the start of every session. It is the source of truth for
> where the project stands. If it disagrees with the repository, the repository
> wins — then fix this file.

Last updated: 2026-09-22, end of build day. Next: real-world test on two computers
(`docs/TEST-TWO-COMPUTERS.md`).

## Identity

- Product: **BARK — Bright Arrow Remote-Access Kit**. Private remote access for a
  small company's own Windows machines.
- Repo: https://github.com/spodi4real/BARK (public), branch `main`
- Operator: not a programmer. Every manual step must be exact and click-by-click.
- Dev machine: laptop, Windows 11 25H2, i7-13650HX, RTX 3050 (NVENC) + Intel UHD
  (QuickSync; drives the 1920x1080 panel). NOT a permanent server.
- Toolchain: Rust 1.98.1 MSVC, VS 2022 Build Tools 14.44, Windows SDK 10.0.26100.
  Cargo is at `%USERPROFILE%\.cargo\bin` (not on PATH in fresh shells).
  `.cargo/config.toml` links the C runtime statically: BARK.exe needs no VC++ redist.

## Non-negotiable requirements (from the operator)

1. Input latency and responsiveness are first-class features. Measure, never claim.
2. Pair once, forever. Only an explicit revoke ends trust.
3. Direct P2P whenever possible; relay only when necessary; user shouldn't care.
4. Works at login screen / locked / nobody logged in (service + session agent).
5. One BARK application on every machine. Server and relay are *roles*.
6. GUI: old-school Windows XP/7 engineering utility. Dense, system fonts, no SaaS look.
7. Security: no keylogging, stealth, backdoors, hardcoded secrets, AV/EDR evasion,
   unauthenticated access. Private keys never in plaintext (DPAPI).
8. Errors must say what happened, why, and what to do.
9. Discipline: BUILD → TEST → MEASURE → FIX → VERIFY. Be explicit: verified vs designed.

## Architecture (short form — deep version in docs/ARCHITECTURE.md)

- Rust; GUI raw Win32 (`windows` 0.62); transport QUIC (`quinn`); media = Windows only
  (DXGI capture, D3D11 video processor, Media Foundation H.264, flip swap chain).
- Crates: `bark-core`, `bark-crypto`, `bark-proto`, `bark-net` (TLS, endpoints, framing,
  server client, **peer**: punching, dialing, channel-bound handshake, relay client),
  `bark-server` (coordination server library + **relay**), `bark-node` (node runtime,
  **sessions**, **host** pipeline, **viewer** link), `bark-media` (capture, convert,
  encode, decode, present), `bark-input` (SendInput injection), `bark-gui` (BARK.exe),
  `bark-doctor`. `bark-agent`, `bark-service`, `bark-winsvc`, `bark-transfer`: empty.
- Session security: SIGMA handshake whose transcript includes the QUIC TLS exporter
  (channel binding). Session data then rides QUIC's own encryption; no second layer.
- Node↔server TLS pinned; node↔node TLS encryption-only, authenticated by SIGMA.
- The controlled computer only completes a handshake with a device it accepted an
  introduction from in the last 60 s (the "gate"); anything else is refused pre-TLS.

## Status by component

| Component | State |
|---|---|
| Identity, DPAPI, trust store, pairing codes, SIGMA | Built, tested. Channel binding **wired and tested** (incl. MITM test) |
| Coordination server (directory, presence, introductions, per-pair revocation) | Built, tested |
| Hole punching + parallel dial + direct session | **Built, tested on loopback only** |
| Relay (in the server role; tokens, limits, expiry, audit) | **Built, tested on loopback only**. Relays on non-server machines: designed, not built |
| Node sessions (controller + host drivers, gate, fallback direct→relay) | **Built, 5 two-node integration tests** |
| Screen capture (DXGI, one monitor, cursor shape incl. XOR cursors) | **Built, verified on this laptop** |
| Encode (MF hardware, software fallback), decode (MF DXVA), present (flip) | **Built, measured on this laptop** (Intel QSV) |
| Input injection (SendInput, release-all) | Built, unit-tested; **never exercised end to end** (loopback sessions do not apply input by design) |
| Session window (video, input, cursor, measured status bar, Actions menu) | **Built, verified in the real GUI** (one-machine mirror test) |
| "Being controlled" banner with End Session | **Built, verified in the real GUI** |
| Tray icon / keep running when closed, app icon | Built, verified |
| Settings: relay option, Copy/Paste join info, firewall button | Built; Copy/Paste verified; firewall button **not exercised** (needs UAC click) |
| Diagnostics: sessions + relay role | Built |
| Windows service / session agent / installer / named pipe | **NOT STARTED** |
| Clipboard, file transfer, multi-monitor, adaptive bitrate, TCP/443 fallback | NOT STARTED |

## Verified (all on the dev laptop — nothing has crossed a real network yet)

- **291 tests pass, 0 fail**, 0 clippy warnings (`-D warnings`), repeated 8 full runs.
- Two BARK.exe windows (profiles demo-server / demo-laptop): Connect opens a session
  window with live hardware-decoded video; banner appears on the "remote"; closing
  the window ends the session on both sides and removes the banner.
- Channel binding: a relay that terminates QUIC and passes handshake bytes through is
  detected by both sides (test `a_relay_that_terminates_the_connection_...`).
- BARK.exe (release) depends only on Windows system DLLs (dumpbin checked).

## Key measurements (details in docs/MEASUREMENTS.md)

- Connect → authenticated session, loopback: direct 8-9 ms, relayed 9-12 ms.
- 1080p Intel QSV: convert+encode median 8.0 ms (was 28-31 ms before the 1 ms timer
  fix); encoder busy 4-6 ms; decode+convert 1.4 ms (GPU).
- Live mirror session: 55 fps, remote present→send 11.3 ms, decode 2.4 ms.
- Windows default UDP receive buffer 64 KB (< one keyframe); BARK sets 8 MB.
- Input→frame latency: implemented and displayed; **not yet observed** (needs 2 PCs).

## Known open issues

- Capture-to-bitstream target 3 ms not met on Intel UHD (~5-6 ms). NVENC untried
  (display on the Intel GPU; needs a cross-adapter copy).
- With the BARK server inside the office, sessions from outside will use the relay
  (server sees LAN addresses). Needs a publicly reachable server/reflector for punching.
- Standalone mode is subject to UIPI: no control of elevated windows, sign-in screen,
  lock screen, Ctrl+Alt+Del. Needs the service + agent.
- Windows key / Alt+Tab from the controller keyboard are not forwarded (Actions menu).
- Only the first monitor is captured. No adaptive bitrate yet (fixed ~0.08 bpp).
- Sign-in under load (21 ms alone vs 155 ms with 25 at once) still unprofiled.
- BBR vs Cubic never compared on a real link. `harden_directory` never exercised.
- The session window's RTT is QUIC's estimate (includes ack delay), not a ping.
- Single-instance lookup finds the first BARK window by class; with two profiles
  running, the "bring to front" may pick the wrong one (demo only).

## Bugs found and fixed (keep for context)

- Build day: server-role machine advertised only 127.0.0.1 (nobody could control it);
  frame slot measured from encode end (40 fps); capture timestamp included idle wait;
  controller Disconnect overtaken by connection close (wrong reason shown); 64 KB socket
  buffers dropped keyframe bursts (intermittent test failure); 15.6 ms timer tick
  stalls in the Intel encoder; LAN head start applied with no LAN candidates;
  VCRUNTIME140.dll dependency; main-window shortcuts (Del!) firing inside sessions.
- Earlier: per-pair revocation (was network-wide); lingering refusals; credential
  writer ACL self-lockout.

## Decisions worth remembering

- Channel binding instead of double encryption (ARCHITECTURE.md s.12).
- Relay: fresh socket per relayed session on each peer; in-process tokens instead of
  signed tickets until relays run on other machines (s.6).
- Controller never trusts the server for the peer's identity: expected identity comes
  from the local trust store.
- No input applied on loopback sessions (a same-machine controller would chase its own
  cursor). Env `BARK_INJECT_LOOPBACK=1` overrides for experiments.
- 1 ms timer resolution + opt-out of Win11 hidden-window throttling (measured 3.6x win).
- Closing the main window hides to tray; File > Exit quits.
- `force_relay` in config.json (not in the GUI) forces the relay path for testing.

## Deliberately NOT implemented (and why)

- Unattended-access password: pairing code only, one trust path.
- Relay on every PC: opt-in, server machine only in this version (s.17).
- Telemetry of any kind. IPv6 candidates (first version IPv4).

## Current milestone / next steps

1. Operator runs `docs/TEST-TWO-COMPUTERS.md` on two real computers; read back the
   numbers (especially Input→frame) and fix what breaks.
2. Windows service (`--service`) + session agent (`--agent`) + named-pipe IPC +
   installer (Program Files, firewall rule, autostart, identity migration).
3. Raw Input + low-level keyboard hook while the session window is focused (Windows
   key, Alt+Tab); multi-monitor; adaptive bitrate from NetworkFeedback.
4. Public reflector for hole punching across the internet; relays on other machines
   with signed tickets.

## How to run (dev)

- Build: `cargo build --release -p bark-gui` → `target\release\BARK.exe` (single file).
- One-computer demo: double-click `BARK-DEMO.bat` (repo root, not committed): profiles
  `demo-server` (server on 127.0.0.1:57411) and `demo-laptop` (paired). Connect from
  demo-laptop shows a mirror of this screen; input is not applied (loopback).
- Tests: `cargo test --workspace`; media pipeline timings:
  `set BARK_TIMING=1 && cargo test -p bark-media --test pipeline -- --nocapture`.
