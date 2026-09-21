# BARK — Project State

> Read this first at the start of every session. It is the source of truth for
> where the project stands. If it disagrees with the repository, the repository
> wins — then fix this file.

Last updated: 2026-09-22 (build day, GUI checkpoint)

## Identity

- Product: **BARK — Bright Arrow Remote-Access Kit**. Private remote access for a
  small company's own Windows machines.
- Repo: https://github.com/spodi4real/BARK (public), branch `main`
- Operator: not a programmer. Every manual step must be exact and click-by-click.
- Dev machine: laptop, Windows 11 25H2, i7-13650HX, RTX 3050 (NVENC) + Intel UHD
  (QuickSync). NOT a permanent server — nothing may depend on it being online.
- Toolchain: Rust 1.98.1 MSVC, VS 2022 Build Tools 14.44, Windows SDK 10.0.26100.
  Cargo is at `%USERPROFILE%\.cargo\bin` (not on PATH in fresh shells).

## Non-negotiable requirements (from the operator)

1. Input latency and responsiveness are first-class features. Measure, never claim.
2. Pair once, forever. Only an explicit revoke ends trust. Reboots/updates/network
   changes must not break pairing.
3. Direct P2P whenever possible; relay only when necessary; user shouldn't care.
4. Works at login screen / locked / nobody logged in (service + session agent).
5. One BARK application on every machine. Server and relay are *roles* of the same
   install, not separate products. No subscriptions, limits, nags, AI branding.
6. GUI: old-school Windows XP/7 engineering utility. Menus, list views, status
   bar, system fonts, dense. No SaaS/cards/gradients/animations.
7. Security: no keylogging, stealth, backdoors, hardcoded secrets, AV/EDR evasion,
   unauthenticated access. Private keys never in plaintext (DPAPI).
8. Errors must say what happened, why, and what to do.
9. Discipline: BUILD → TEST → MEASURE → FIX → VERIFY. Never pile up uncompiled code.
   Be explicit about verified vs designed.

## Architecture (short form — deep version in docs/ARCHITECTURE.md)

- Language: Rust. GUI: raw Win32 via `windows` 0.62. Transport: QUIC (`quinn`).
- Crates: `bark-core` (ids, clock, paths, logging), `bark-crypto` (identity, DPAPI,
  trust store, pairing codes, SIGMA handshake), `bark-proto` (wire formats),
  `bark-net` (TLS policy, QUIC endpoints, framing, server client),
  `bark-server` (coordination server library + dev binary), `bark-doctor`
  (self-test / external server test).
- Trust: Ed25519 device key under DPAPI machine scope. Device ID `BA-XXXX-XXXX` =
  40 bits of SHA-256(pubkey), lookup handle only; full key is the identity.
  Trust is **directional** (pairing A→B lets A control B, not B control A).
- Server: SQLite directory + in-memory presence + introduction routing. Decides
  nothing about access (targets' own trust stores do). Holds no private keys,
  no session keys, never sees pairing codes (gets a salted hash).
- Node↔server TLS: server cert **pinned** by SHA-256 ("server key" in join info).
- Node↔node TLS: encryption-only; authentication by inner SIGMA handshake.

## Status by component

| Component | State |
|---|---|
| Core ids/clock/paths/logging | Built, tested |
| Identity + DPAPI + trust store + pairing codes | Built, tested on real DPAPI |
| SIGMA handshake + session cipher | Built, tested (channel binding to QUIC exporter: designed, not yet wired) |
| Wire protocol (input, video fragments, control, peer) | Built, tested |
| QUIC endpoints, pinned TLS, framing | Built, tested on loopback |
| Coordination server (directory, sign-in, presence, introductions, per-pair revocation) | Built, tested end-to-end |
| Network address detection (`bark-net::interfaces`) | Built, tested on real adapters |
| Node runtime (`bark-node`): identity, config, server link + reconnect, presence, pairing both sides, introductions, server role | Built, 7 two-node integration tests |
| GUI (`BARK.exe`, raw Win32): main window, Add Device, Pairing Code, Settings, Properties, Diagnostics, About, Unable-to-connect | Early functional version; pairing verified by driving the real GUI |
| Hole punching / direct P2P | NOT STARTED |
| Relay | Designed (ARCHITECTURE.md s.6, s.17), not built |
| Screen capture / encode / decode / render / input | NOT STARTED |
| Windows service / agent / installer | NOT STARTED (GUI runs node in-process, "standalone") |

## Verified (on the dev laptop only — nothing has crossed a real network yet)

- 249 tests pass, 0 fail; 0 clippy warnings.
- Real `bark-server.exe` + `bark-doctor --server`: sign-in 21.5 ms, RTT 87 µs, 25 simultaneous sign-ins OK.
- Two `BARK.exe` windows (`--profile demo-server` hosting the server role, `--profile demo-laptop`):
  pairing driven through the real dialogs succeeded; wrong/expired code refused with a clear
  message; laptop list shows the server ONLINE / "You control it"; Connect produced a real
  accepted introduction. Identities stable across restarts.

## Key measurements (loopback; see docs/MEASUREMENTS.md)

- Encrypt 1100-byte packet 1.82 µs (4.8 Gbit/s). Input encode 24 ns, 21 bytes.
- SIGMA handshake 261 µs. QUIC connect 1.64 ms. Datagram RTT 34 µs.
- `sleep_until` overshoot median 74 µs (spin tail; plain sleep ~410 µs).

## Known open issues

- Sign-in 21 ms alone vs 155 ms median when 25 arrive together — unprofiled.
- Fragment size fixed at 1117 B though QUIC offered 1414 — revisit once media exists.
- BBR chosen on reasoning; never compared to Cubic on a real link.
- `harden_directory` (ProgramData ACL) written but never exercised (needs admin).
- No application icon yet (default Windows icon).
- Email and machine name appear in the public repo (operator informed).

## Bugs found and fixed (keep for context)

- Server `Revoke` banned the revoked device network-wide; now per-pair only, and re-pairing
  with a code lifts it (regression test in `end_to_end.rs`).
- Server refusals were lost when the connection dropped immediately ("connection lost").
- Credentials writer locked itself out by hardening ACLs after writing.

## Decisions worth remembering

- Permissions are applied to the machine directory once, never as a side effect of
  writing a file (a test caught a self-lockout bug).
- Server issues its own exchange ids so requesters can't collide or hijack.
- Refusals linger until the node reads them (otherwise "connection lost").
- High-res waitable timer is kept for the spin-tail `sleep_until`, not because the
  timer object itself beats `std::thread::sleep` on Win11 (it doesn't).

## Deliberately NOT implemented (and why)

- Unattended-access password: pairing code only, to keep one trust path.
- Relay participation is opt-in per machine (default: on for the server machine only).
  Reasons in ARCHITECTURE.md s.17 (resources, reachability, attack surface).
- Telemetry of any kind: requirement.
- IPv6 candidates: first version is IPv4; most company LAN/NAT paths are v4.

## Decisions made on build day

- One executable `BARK.exe` for GUI, service (`--service`) and agent (`--agent`); server and
  relay are roles in settings, not separate products (ARCHITECTURE.md s.1, s.17).
- Session security: SIGMA handshake channel-bound to the QUIC TLS exporter instead of a second
  encryption layer (ARCHITECTURE.md s.12). Relay = UDP forwarder with server-signed tickets.
- Node runtime is one library hosted either in the GUI (standalone) or the service; UI talks
  to it only via serialisable `Command`/`Event`, so a named pipe can replace channels.
- Standalone profiles (`BARK.exe --profile NAME`) under %LOCALAPPDATA%\BARK\profiles allow two
  nodes on one machine for testing.

## Current milestone

Build day. Done: address detection, node runtime, pairing, GUI shell. Stopped here to show
the operator the GUI for feedback. Next: hole punching + direct session with channel-bound
handshake → relay → capture/encode/decode/render/input → service/agent/installer → update
diagnostics → state file.

## How to run the GUI (dev)

`targetelease\BARK.exe` (default profile) or `BARK.exe --profile NAME`.
Demo profiles used on 2026-09-22: `demo-server` (server role, bound to 127.0.0.1:57411) and
`demo-laptop` (paired to it).
