//! Two real nodes, one hosting the coordination-server role, pairing and
//! introducing each other through the actual node runtime — the same code the
//! GUI and the service host.
//!
//! Everything binds to loopback, so running the tests never raises a Windows
//! Firewall prompt.

use bark_node::api::{Command, Event, NodeStatus, ServerLink};
use bark_node::config::{NodeConfig, NodeDirs, ServerTarget};
use bark_node::{start, EventSink, NodeHandle};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Collects every event a node emits so a test can wait for a specific one.
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

    /// Waits for an event matching `want`, looking at everything received so
    /// far and anything that arrives within `timeout`. Consumes it.
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
    let d = std::env::temp_dir().join(format!("bark-node-it-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A free UDP port on loopback, so parallel test runs do not collide.
fn free_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct TwoNodes {
    server_node: NodeHandle,
    server_events: Events,
    server_status: NodeStatus,
    client_node: NodeHandle,
    client_events: Events,
    client_status: NodeStatus,
    dirs: Vec<std::path::PathBuf>,
}

impl Drop for TwoNodes {
    fn drop(&mut self) {
        for d in &self.dirs {
            let _ = std::fs::remove_dir_all(d);
        }
    }
}

/// Starts "CENTRAL-SERVER" (hosting the server role) and "LAPTOP" (using it),
/// and waits until both are signed in.
fn two_nodes(tag: &str) -> TwoNodes {
    let sdir = tempdir(&format!("{tag}-server"));
    let cdir = tempdir(&format!("{tag}-client"));
    let port = free_port();

    let mut sconf = NodeConfig { device_name: "CENTRAL-SERVER".into(), ..Default::default() };
    sconf.roles.coordination_server = true;
    sconf.roles.server_port = port;
    sconf.roles.server_bind = "127.0.0.1".into();
    sconf.save(&NodeDirs::at(&sdir, "test").config()).unwrap();

    let server_events = Events::default();
    let server_node = start(NodeDirs::at(&sdir, "test"), server_events.sink());
    let server_status = server_events.status_where(|s| s.server.is_online() && s.server_role.is_some());
    let key = server_status.server_role.as_ref().unwrap().key_text.clone();

    let cconf = NodeConfig {
        device_name: "LAPTOP".into(),
        server: Some(ServerTarget { address: format!("127.0.0.1:{port}"), key }),
        ..Default::default()
    };
    cconf.save(&NodeDirs::at(&cdir, "test").config()).unwrap();

    let client_events = Events::default();
    let client_node = start(NodeDirs::at(&cdir, "test"), client_events.sink());
    let client_status = client_events.status_where(|s| s.server.is_online());

    TwoNodes {
        server_node,
        server_events,
        server_status,
        client_node,
        client_events,
        client_status,
        dirs: vec![sdir, cdir],
    }
}

fn show_code(n: &TwoNodes) -> String {
    n.server_node.send(Command::ShowPairingCode);
    match n.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::PairingCode(Some(_)))) {
        Event::PairingCode(Some(c)) => c.code,
        _ => unreachable!(),
    }
}

fn pair(n: &TwoNodes, code: &str) -> (bool, String) {
    n.client_node.send(Command::Pair {
        device_id: n.server_status.device_id.clone(),
        code: code.into(),
        name: String::new(),
    });
    match n.client_events.wait(Duration::from_secs(15), |e| matches!(e, Event::PairFinished { .. })) {
        Event::PairFinished { ok, message, .. } => (ok, message),
        _ => unreachable!(),
    }
}

#[test]
fn a_node_hosting_the_server_role_signs_in_to_itself() {
    let n = two_nodes("self");
    let role = n.server_status.server_role.as_ref().unwrap();
    assert_eq!(role.key_text.len(), 64 + 15, "the join key is shown in groups");
    assert!(matches!(n.server_status.server, ServerLink::Online { .. }));
    assert_eq!(n.server_status.device_name, "CENTRAL-SERVER");
    assert!(n.server_status.device_id.starts_with("BA-"));
    assert!(matches!(n.client_status.server, ServerLink::Online { .. }));
}

#[test]
fn pairing_with_the_code_on_screen_works_and_is_directional() {
    let n = two_nodes("pair");

    let code = show_code(&n);
    let (ok, message) = pair(&n, &code);
    assert!(ok, "pairing should succeed: {message}");
    assert!(message.contains("CENTRAL-SERVER"), "names the device: {message}");

    // The other side learns who paired with it, and the code is used up.
    let paired_by = n.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::PairedBy { .. }));
    match paired_by {
        Event::PairedBy { device } => {
            assert_eq!(device.name, "LAPTOP");
            assert!(device.may_control_us, "the laptop may now control the server");
            assert!(!device.we_may_control, "the server gained no control of the laptop");
        }
        _ => unreachable!(),
    }
    n.server_events.wait(Duration::from_secs(5), |e| matches!(e, Event::PairingCode(None)));

    // The laptop's favourites now list the server, online, controllable.
    let listed = n.client_events.wait(Duration::from_secs(10), |e| {
        matches!(e, Event::Devices(d) if d.iter().any(|x| x.name == "CENTRAL-SERVER" && x.online))
    });
    match listed {
        Event::Devices(d) => {
            let s = d.iter().find(|x| x.name == "CENTRAL-SERVER").unwrap();
            assert!(s.we_may_control);
            assert!(!s.may_control_us);
            assert_eq!(s.device_id, n.server_status.device_id);
        }
        _ => unreachable!(),
    }

    // The introduction path works in the permitted direction...
    n.client_node.send(Command::Connect { device: n.server_status.fingerprint });
    match n.client_events.wait(Duration::from_secs(10), |e| matches!(e, Event::ConnectFinished { .. })) {
        Event::ConnectFinished { ok, message, .. } => assert!(ok, "should be accepted: {message}"),
        _ => unreachable!(),
    }

    // ...and is refused locally in the other direction, before any network
    // traffic, with a message that says why.
    n.server_node.send(Command::Connect { device: n.client_status.fingerprint });
    match n.server_events.wait(Duration::from_secs(10), |e| matches!(e, Event::ConnectFinished { .. })) {
        Event::ConnectFinished { ok, message, .. } => {
            assert!(!ok);
            assert!(message.contains("not permitted"), "got {message}");
        }
        _ => unreachable!(),
    }
}

#[test]
fn a_wrong_code_is_refused_with_a_useful_message() {
    let n = two_nodes("wrong");
    let real = show_code(&n);
    // Change one character to make a wrong but well-formed code.
    let mut wrong: Vec<char> = real.chars().collect();
    wrong[0] = if wrong[0] == '7' { '8' } else { '7' };
    let wrong: String = wrong.into_iter().collect();

    let (ok, message) = pair(&n, &wrong);
    assert!(!ok);
    assert!(message.contains("not correct"), "got {message}");
    assert!(message.contains("Show Pairing Code"), "tells the operator what to do: {message}");

    // The real code still works afterwards: one typo must not burn it.
    let (ok, message) = pair(&n, &real);
    assert!(ok, "the correct code should still work: {message}");
}

#[test]
fn pairing_without_a_code_on_screen_is_refused() {
    let n = two_nodes("nocode");
    let (ok, message) = pair(&n, "ABC-DEF");
    assert!(!ok);
    assert!(message.contains("not correct"), "got {message}");
}

#[test]
fn an_unknown_device_id_is_explained() {
    let n = two_nodes("unknown");
    n.client_node.send(Command::Pair {
        device_id: "BA-0000-0000".into(),
        code: "ABC-DEF".into(),
        name: String::new(),
    });
    match n.client_events.wait(Duration::from_secs(10), |e| matches!(e, Event::PairFinished { .. })) {
        Event::PairFinished { ok, message, .. } => {
            assert!(!ok);
            assert!(message.contains("No device with ID"), "got {message}");
            assert!(message.contains("same BARK server"), "suggests a cause: {message}");
        }
        _ => unreachable!(),
    }
}

#[test]
fn obviously_bad_input_is_rejected_before_touching_the_network() {
    let n = two_nodes("input");
    for (id, code, expect) in [
        ("not an id", "ABC-DEF", "not a valid Device ID"),
        (n.client_status.device_id.as_str(), "ABC-DEF", "own Device ID"),
        (n.server_status.device_id.as_str(), "??", "six letters"),
    ] {
        n.client_node.send(Command::Pair { device_id: id.into(), code: code.into(), name: String::new() });
        match n.client_events.wait(Duration::from_secs(5), |e| matches!(e, Event::PairFinished { .. })) {
            Event::PairFinished { ok, message, .. } => {
                assert!(!ok);
                assert!(message.contains(expect), "for {id}/{code} expected {expect:?}, got {message}");
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn pairing_survives_restarting_both_nodes() {
    // The operator's central requirement: pair once, and a restart changes
    // nothing.
    let sdir = tempdir("restart-server");
    let cdir = tempdir("restart-client");
    let port = free_port();

    let mut sconf = NodeConfig { device_name: "CENTRAL-SERVER".into(), ..Default::default() };
    sconf.roles.coordination_server = true;
    sconf.roles.server_port = port;
    sconf.roles.server_bind = "127.0.0.1".into();
    sconf.save(&NodeDirs::at(&sdir, "t").config()).unwrap();

    let start_both = |key_holder: &mut Option<String>| {
        let se = Events::default();
        let sn = start(NodeDirs::at(&sdir, "t"), se.sink());
        let ss = se.status_where(|s| s.server.is_online() && s.server_role.is_some());
        let key = ss.server_role.as_ref().unwrap().key_text.clone();
        if let Some(k) = key_holder.as_ref() {
            assert_eq!(*k, key, "the server key must not change across restarts");
        }
        *key_holder = Some(key.clone());
        let cconf = NodeConfig {
            device_name: "LAPTOP".into(),
            server: Some(ServerTarget { address: format!("127.0.0.1:{port}"), key }),
            ..Default::default()
        };
        cconf.save(&NodeDirs::at(&cdir, "t").config()).unwrap();
        let ce = Events::default();
        let cn = start(NodeDirs::at(&cdir, "t"), ce.sink());
        let cs = ce.status_where(|s| s.server.is_online());
        (sn, se, ss, cn, ce, cs)
    };

    let mut key = None;
    let (sn, se, ss, cn, ce, cs) = start_both(&mut key);
    sn.send(Command::ShowPairingCode);
    let code = match se.wait(Duration::from_secs(5), |e| matches!(e, Event::PairingCode(Some(_)))) {
        Event::PairingCode(Some(c)) => c.code,
        _ => unreachable!(),
    };
    cn.send(Command::Pair { device_id: ss.device_id.clone(), code, name: String::new() });
    match ce.wait(Duration::from_secs(15), |e| matches!(e, Event::PairFinished { .. })) {
        Event::PairFinished { ok, message, .. } => assert!(ok, "{message}"),
        _ => unreachable!(),
    }
    let first_ids = (ss.device_id.clone(), cs.device_id.clone());
    sn.shutdown();
    cn.shutdown();

    // Restart both. Same identities, still paired, no code needed.
    let (sn2, _se2, ss2, cn2, ce2, cs2) = start_both(&mut key);
    assert_eq!((ss2.device_id.clone(), cs2.device_id.clone()), first_ids, "identities are permanent");

    ce2.wait(Duration::from_secs(10), |e| {
        matches!(e, Event::Devices(d) if d.iter().any(|x| x.name == "CENTRAL-SERVER" && x.online && x.we_may_control))
    });
    cn2.send(Command::Connect { device: ss2.fingerprint });
    match ce2.wait(Duration::from_secs(10), |e| matches!(e, Event::ConnectFinished { .. })) {
        Event::ConnectFinished { ok, message, .. } => assert!(ok, "still trusted after restart: {message}"),
        _ => unreachable!(),
    }

    drop(sn2);
    drop(cn2);
    let _ = std::fs::remove_dir_all(&sdir);
    let _ = std::fs::remove_dir_all(&cdir);
}
