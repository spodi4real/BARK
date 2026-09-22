//! Two real nodes opening remote sessions to each other: direct, through the
//! relay, refused, and ended from either side.
//!
//! Everything binds to loopback, so running the tests never raises a Windows
//! Firewall prompt.

use bark_node::api::{Command, Event, NodeStatus};
use bark_node::config::{NodeConfig, NodeDirs, ServerTarget};
use bark_node::{start, EventSink, NodeHandle, ViewerCommand, ViewerEvent};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Default)]
struct Events {
    inner: Arc<(Mutex<Vec<Event>>, Condvar)>,
}

impl Events {
    fn sink(&self) -> EventSink {
        let inner = self.inner.clone();
        Arc::new(move |e| {
            let (lock, cv) = &*inner;
            lock.lock().unwrap().push(e);
            cv.notify_all();
        })
    }

    fn wait<F: FnMut(&Event) -> bool>(&self, timeout: Duration, mut want: F) -> Event {
        let deadline = Instant::now() + timeout;
        let (lock, cv) = &*self.inner;
        let mut guard = lock.lock().unwrap();
        loop {
            if let Some(i) = guard.iter().position(&mut want) {
                return guard.remove(i);
            }
            let now = Instant::now();
            assert!(now < deadline, "timed out; events so far: {:#?}", *guard);
            guard = cv.wait_timeout(guard, deadline - now).unwrap().0;
        }
    }

    fn status_where<F: FnMut(&NodeStatus) -> bool>(&self, mut want: F) -> NodeStatus {
        match self.wait(Duration::from_secs(15), |e| matches!(e, Event::Status(s) if want(s))) {
            Event::Status(s) => s,
            _ => unreachable!(),
        }
    }
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("bark-node-st-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct Pair {
    server: NodeHandle,
    server_events: Events,
    server_status: NodeStatus,
    client: NodeHandle,
    client_events: Events,
    client_status: NodeStatus,
    dirs: Vec<std::path::PathBuf>,
}

impl Drop for Pair {
    fn drop(&mut self) {
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// "CENTRAL-SERVER" hosts the server role (and the relay, if asked);
/// "LAPTOP" pairs with it so it may control it.
fn paired(tag: &str, relay: bool, force_relay: bool) -> Pair {
    let sdir = tempdir(&format!("{tag}-s"));
    let cdir = tempdir(&format!("{tag}-c"));
    let port = free_port();

    let mut sconf = NodeConfig { device_name: "CENTRAL-SERVER".into(), ..Default::default() };
    sconf.roles.coordination_server = true;
    sconf.roles.server_port = port;
    sconf.roles.server_bind = "127.0.0.1".into();
    sconf.roles.relay = relay;
    sconf.roles.relay_port = free_port();
    sconf.save(&NodeDirs::at(&sdir, "t").config()).unwrap();
    let server_events = Events::default();
    let server = start(NodeDirs::at(&sdir, "t"), server_events.sink());
    let server_status = server_events.status_where(|s| s.server.is_online() && s.server_role.is_some());
    let key = server_status.server_role.as_ref().unwrap().key_text.clone();

    let cconf = NodeConfig {
        device_name: "LAPTOP".into(),
        server: Some(ServerTarget { address: format!("127.0.0.1:{port}"), key }),
        force_relay,
        ..Default::default()
    };
    cconf.save(&NodeDirs::at(&cdir, "t").config()).unwrap();
    let client_events = Events::default();
    let client = start(NodeDirs::at(&cdir, "t"), client_events.sink());
    let client_status = client_events.status_where(|s| s.server.is_online());

    server.send(Command::ShowPairingCode);
    let code = match server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::PairingCode(Some(_)))) {
        Event::PairingCode(Some(c)) => c.code,
        _ => unreachable!(),
    };
    client.send(Command::Pair { device_id: server_status.device_id.clone(), code, name: String::new() });
    match client_events.wait(Duration::from_secs(15), |e| matches!(e, Event::PairFinished { .. })) {
        Event::PairFinished { ok, message, .. } => assert!(ok, "pairing failed: {message}"),
        _ => unreachable!(),
    }
    // Presence must show the server online before connecting.
    client_events.wait(Duration::from_secs(10), |e| {
        matches!(e, Event::Devices(d) if d.iter().any(|x| x.online && x.we_may_control))
    });

    Pair { server, server_events, server_status, client, client_events, client_status, dirs: vec![sdir, cdir] }
}

/// Connects and returns (session id, path, connect time, verification words)
/// or the failure text.
fn connect(p: &Pair) -> Result<(u64, String, u32, String), String> {
    p.client.send(Command::Connect { device: p.server_status.fingerprint });
    match p.client_events.wait(Duration::from_secs(30), |e| {
        matches!(e, Event::SessionOpened { .. } | Event::ConnectFinished { .. })
    }) {
        Event::SessionOpened { session_id, path, connect_ms, verification, .. } => {
            Ok((session_id, path, connect_ms, verification))
        }
        Event::ConnectFinished { message, .. } => Err(message),
        _ => unreachable!(),
    }
}

fn next_viewer_event<F: FnMut(&ViewerEvent) -> bool>(
    rx: &std::sync::mpsc::Receiver<ViewerEvent>,
    mut want: F,
) -> ViewerEvent {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let e = rx.recv_timeout(left).expect("the viewer event never came");
        if want(&e) {
            return e;
        }
    }
}

#[test]
fn a_direct_session_opens_and_both_computers_know_it() {
    let p = paired("direct", false, false);
    let (id, path, ms, words) = connect(&p).expect("the session should open");
    assert_eq!(path, "DIRECT (LAN)", "loopback is a local path");
    eprintln!("direct session: Connect to authenticated session took {ms} ms");

    // The controlled computer must show that it is being controlled.
    match p.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::HostSessionStarted { .. })) {
        Event::HostSessionStarted { name, path, verification, .. } => {
            assert_eq!(name, "LAPTOP");
            assert_eq!(path, "DIRECT (LAN)");
            // Both computers derive the words from the session; equal words
            // are what the operator compares to rule out a man in the middle.
            assert_eq!(verification, words, "both sides must show the same verification words");
            assert!(!words.is_empty());
        }
        _ => unreachable!(),
    }

    // The window's end of the session works: the remote answers Start, and
    // measured stats arrive.
    let viewer = p.client.take_viewer(id).expect("the viewer link");
    assert!(p.client.take_viewer(id).is_none(), "a viewer link can be taken once");
    match next_viewer_event(&viewer.events, |e| matches!(e, ViewerEvent::Ready { .. })) {
        ViewerEvent::Ready { remote_name, .. } => assert_eq!(remote_name, "CENTRAL-SERVER"),
        _ => unreachable!(),
    }
    // Real video: the remote captures its screen, encodes it and sends it.
    // A keyframe must arrive. (If the first one is lost the viewer asks for
    // another, so it need not be the very first frame.)
    match next_viewer_event(&viewer.events, |e| matches!(e, ViewerEvent::Frame(f) if f.keyframe)) {
        ViewerEvent::Frame(f) => {
            assert!(f.meta.width > 0 && f.meta.height > 0);
            eprintln!(
                "first video frame: {}x{}, {} KB, remote capture-to-send {} us",
                f.meta.width,
                f.meta.height,
                f.bitstream.len() / 1024,
                f.meta.send_us.saturating_sub(f.meta.capture_begin_us)
            );
        }
        _ => unreachable!(),
    }
    match next_viewer_event(&viewer.events, |e| matches!(e, ViewerEvent::Stats(_))) {
        ViewerEvent::Stats(s) => {
            assert_eq!(s.path, "DIRECT (LAN)");
            assert!(s.rtt_us > 0, "a real round-trip measurement: {s:?}");
            eprintln!("session RTT on loopback: {} us", s.rtt_us);
        }
        _ => unreachable!(),
    }

    // The device list shows the path while the session runs.
    p.client_events.wait(Duration::from_secs(5), |e| {
        matches!(e, Event::Devices(d) if d.iter().any(|x| x.connection == "DIRECT"))
    });

    // Closing the window ends it on both sides.
    viewer.commands.send(ViewerCommand::Disconnect).unwrap();
    p.client_events.wait(Duration::from_secs(5), |e| matches!(e, Event::SessionClosed { .. }));
    match p.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::HostSessionEnded { .. })) {
        Event::HostSessionEnded { reason, .. } => assert!(reason.contains("closed"), "got {reason}"),
        _ => unreachable!(),
    }
    let _ = &p.client_status;
}

#[test]
fn a_session_falls_back_to_the_relay() {
    // force_relay makes the controller skip the direct attempt, which is the
    // only way to exercise the relay between two processes on one computer.
    let p = paired("relay", true, true);
    let (id, path, ms, _) = connect(&p).expect("the relayed session should open");
    assert_eq!(path, "RELAYED");
    eprintln!("relayed session: Connect to authenticated session took {ms} ms");
    match p.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::HostSessionStarted { .. })) {
        Event::HostSessionStarted { path, .. } => assert_eq!(path, "RELAYED"),
        _ => unreachable!(),
    }
    let viewer = p.client.take_viewer(id).unwrap();
    next_viewer_event(&viewer.events, |e| matches!(e, ViewerEvent::Ready { .. }));
}

#[test]
fn no_relay_available_is_explained() {
    let p = paired("norelay", false, true);
    let err = connect(&p).expect_err("there is no relay to fall back to");
    assert!(err.contains("relay"), "the message should mention the relay: {err}");
    assert!(err.contains("Settings"), "and say where to enable it: {err}");
}

#[test]
fn the_person_at_the_controlled_computer_can_end_the_session() {
    let p = paired("hostend", false, false);
    let (id, _, _, _) = connect(&p).expect("the session should open");
    let host_id = match p.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::HostSessionStarted { .. })) {
        Event::HostSessionStarted { session_id, .. } => session_id,
        _ => unreachable!(),
    };
    let _viewer = p.client.take_viewer(id).unwrap();
    p.server.send(Command::EndHostSession { session_id: host_id });
    match p.client_events.wait(Duration::from_secs(5), |e| matches!(e, Event::SessionClosed { .. })) {
        Event::SessionClosed { reason, .. } => {
            assert!(reason.contains("remote computer ended"), "the controller is told why: {reason}")
        }
        _ => unreachable!(),
    }
}

#[test]
fn a_revoked_controller_cannot_open_a_session() {
    let p = paired("revoked", false, false);
    p.server.send(Command::Revoke { device: p.client_status.fingerprint });
    // Give the revocation a moment to reach the server.
    std::thread::sleep(Duration::from_millis(300));
    let err = connect(&p).expect_err("revocation must stop the session");
    assert!(err.to_lowercase().contains("revoked") || err.contains("not paired"), "got: {err}");
}
