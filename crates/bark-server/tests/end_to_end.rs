//! End-to-end tests: a real coordination server, real QUIC, real node clients.
//!
//! Everything here runs the actual code paths a deployed BARK would run —
//! certificate pinning, the challenge/signature login, SQLite, presence
//! notifications, and the introduction routing. The only thing missing from a
//! real deployment is that all of it is on loopback.
//!
//! These tests exist because the unit tests can only show that each piece
//! behaves; they cannot show that the pieces agree with each other. The
//! challenge payload in particular is built independently on both sides, and a
//! mismatch there would break every login in the field while every unit test
//! still passed.

use bark_core::machine::MachineInfo;
use bark_crypto::DeviceIdentity;
use bark_net::control::ControlConnection;
use bark_net::endpoint::{bidirectional_endpoint, local_address, Role};
use bark_net::tls::{pinned_client_config, TransportCredentials};
use bark_proto::control::{FailureReason, ToNode, ToServer};
use bark_server::db::Db;
use bark_server::registry::Registry;
use bark_server::session::ServerState;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

fn loopback() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn machine(name: &str) -> MachineInfo {
    MachineInfo {
        hostname: name.to_string(),
        os: "Windows 11 Pro".to_string(),
        bark_version: bark_core::VERSION.to_string(),
        cpu: "Test CPU".to_string(),
        cpu_threads: 4,
        memory_mb: 8192,
    }
}

/// A running coordination server on loopback.
struct TestServer {
    address: SocketAddr,
    fingerprint: [u8; 32],
    state: Arc<ServerState>,
    _tasks: (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>),
}

impl TestServer {
    async fn start() -> TestServer {
        let creds = TransportCredentials::generate().expect("server credentials");
        let fingerprint = creds.fingerprint();

        let endpoint = bidirectional_endpoint(
            loopback(),
            &creds,
            pinned_client_config(fingerprint).expect("client config"),
            Role::Control,
        )
        .expect("server endpoint");
        let address = local_address(&endpoint).expect("server address");

        let state = Arc::new(ServerState {
            db: Arc::new(Db::open_in_memory().expect("database")),
            registry: Arc::new(Registry::new()),
            cert_fingerprint: fingerprint,
            version: bark_core::VERSION.to_string(),
        });

        let tasks = bark_server::serve::spawn(state.clone(), endpoint);
        TestServer { address, fingerprint, state, _tasks: tasks }
    }
}

/// Connects a node to the server and logs in.
async fn login(server: &TestServer, identity: &DeviceIdentity, name: &str) -> ControlConnection {
    let creds = TransportCredentials::generate().expect("node credentials");
    let endpoint = bidirectional_endpoint(
        loopback(),
        &creds,
        pinned_client_config(server.fingerprint).expect("client config"),
        Role::Control,
    )
    .expect("node endpoint");
    let local = local_address(&endpoint).expect("node address");

    // The endpoint must outlive the connection; leaking it here is fine for a
    // test and keeps the helper's signature simple.
    let endpoint = Box::leak(Box::new(endpoint));

    ControlConnection::login(
        endpoint,
        server.address,
        server.fingerprint,
        identity,
        machine(name),
        vec![local],
    )
    .await
    .expect("login should succeed")
}

/// Waits for a pushed message matching a predicate, ignoring anything else.
async fn wait_for<F>(conn: &mut ControlConnection, mut want: F) -> ToNode
where
    F: FnMut(&ToNode) -> bool,
{
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for the expected message");
        match tokio::time::timeout(remaining, conn.next_event()).await {
            Ok(Some(msg)) => {
                if want(&msg) {
                    return msg;
                }
            }
            Ok(None) => panic!("the connection closed while waiting"),
            Err(_) => panic!("timed out waiting for the expected message"),
        }
    }
}

#[tokio::test]
async fn a_node_logs_in_and_the_server_records_it() {
    let server = TestServer::start().await;
    let id = DeviceIdentity::generate().expect("identity");

    let conn = login(&server, &id, "CENTRAL-SERVER").await;

    // The server told us the address it sees us from. This is our NAT mapping
    // in a real deployment, and the thing a peer aims hole punches at.
    assert!(conn.public_address().ip().is_loopback());
    assert_ne!(conn.public_address().port(), 0);
    assert_eq!(conn.greeting().server_version, bark_core::VERSION);
    assert!(conn.is_connected());

    // And it is in the directory, under the name it gave.
    let record = server
        .state
        .db
        .by_fingerprint(&id.fingerprint())
        .expect("query")
        .expect("the device should be registered");
    assert_eq!(record.name, "CENTRAL-SERVER");
    assert_eq!(record.os, "Windows 11 Pro");
    assert_eq!(record.identity, id.public());
    assert!(!record.revoked);

    assert!(server.state.registry.is_online(&id.fingerprint()));
}

#[tokio::test]
async fn a_node_that_cannot_sign_is_refused() {
    // The login signature is the whole of the server's authentication. This
    // drives the real login path with a key that does not match the claimed
    // identity, which is what an impersonation attempt looks like.
    let server = TestServer::start().await;

    let real = DeviceIdentity::generate().expect("identity");
    let impostor = DeviceIdentity::generate().expect("identity");

    let creds = TransportCredentials::generate().expect("credentials");
    let endpoint = bidirectional_endpoint(
        loopback(),
        &creds,
        pinned_client_config(server.fingerprint).expect("config"),
        Role::Control,
    )
    .expect("endpoint");

    let conn = bark_net::endpoint::connect(&endpoint, server.address, "server")
        .await
        .expect("transport connects");
    let (mut send, mut recv) = conn.open_bi().await.expect("stream");

    bark_net::framing::write_message(
        &mut send,
        &ToServer::Hello { protocol: bark_core::PROTOCOL_VERSION },
    )
    .await
    .expect("hello");

    let challenge: ToNode = bark_net::framing::read_expected(&mut recv).await.expect("challenge");
    let ToNode::Challenge { nonce, .. } = challenge else {
        panic!("expected a challenge, got {challenge:?}");
    };

    // Claim to be `real` while signing with `impostor`'s key.
    let payload = bark_net::control::challenge_payload(&nonce, &server.fingerprint);
    let bad_signature = impostor.sign(bark_crypto::identity::context::SERVER_AUTH, &payload);

    bark_net::framing::write_message(
        &mut send,
        &ToServer::Authenticate {
            identity: real.public(),
            signature: bad_signature.into(),
            machine: machine("IMPOSTOR"),
            local_candidates: vec![],
        },
    )
    .await
    .expect("authenticate");

    let reply: ToNode = bark_net::framing::read_expected(&mut recv).await.expect("reply");
    match reply {
        ToNode::Rejected { reason, .. } => assert_eq!(reason, FailureReason::BadRequest),
        other => panic!("an invalid signature must be refused, got {other:?}"),
    }

    assert!(
        !server.state.registry.is_online(&real.fingerprint()),
        "the impersonated device must not be marked online"
    );
}

#[tokio::test]
async fn a_revoked_device_cannot_log_in() {
    let server = TestServer::start().await;
    let id = DeviceIdentity::generate().expect("identity");

    // Log in once so the device exists, then revoke it.
    let first = login(&server, &id, "OFFICE-PC").await;
    first.close().await;
    server
        .state
        .db
        .set_revoked(&id.fingerprint(), true)
        .expect("revoke");

    // A second login must be refused.
    let creds = TransportCredentials::generate().expect("credentials");
    let endpoint = bidirectional_endpoint(
        loopback(),
        &creds,
        pinned_client_config(server.fingerprint).expect("config"),
        Role::Control,
    )
    .expect("endpoint");

    let result = ControlConnection::login(
        &endpoint,
        server.address,
        server.fingerprint,
        &id,
        machine("OFFICE-PC"),
        vec![],
    )
    .await;

    match result {
        Err(bark_core::BarkError::Revoked(_)) => {}
        Err(other) => panic!("expected a revocation error, got {other:?}"),
        Ok(_) => panic!("a revoked device must not be able to log in"),
    }
}

#[tokio::test]
async fn presence_is_pushed_when_a_watched_device_arrives_and_leaves() {
    let server = TestServer::start().await;
    let watcher_id = DeviceIdentity::generate().expect("identity");
    let subject_id = DeviceIdentity::generate().expect("identity");

    let mut watcher = login(&server, &watcher_id, "LAPTOP").await;

    watcher
        .send(ToServer::WatchPresence { devices: vec![subject_id.public().fingerprint()] })
        .await
        .expect("watch");

    // The immediate snapshot says the device is not online yet.
    let snapshot = wait_for(&mut watcher, |m| {
        matches!(m, ToNode::Presence { device, .. } if *device == subject_id.public().fingerprint())
    })
    .await;
    match snapshot {
        ToNode::Presence { online, .. } => assert!(!online, "not connected yet"),
        other => panic!("unexpected: {other:?}"),
    }

    // Now it connects.
    let subject = login(&server, &subject_id, "WAREHOUSE-PC").await;
    let arrival = wait_for(&mut watcher, |m| {
        matches!(m, ToNode::Presence { device, online, .. }
            if *device == subject_id.public().fingerprint() && *online)
    })
    .await;
    assert!(matches!(arrival, ToNode::Presence { online: true, .. }));

    // And goes away again.
    subject.close().await;
    let departure = wait_for(&mut watcher, |m| {
        matches!(m, ToNode::Presence { device, online, .. }
            if *device == subject_id.public().fingerprint() && !*online)
    })
    .await;
    assert!(matches!(departure, ToNode::Presence { online: false, .. }));
}

#[tokio::test]
async fn a_short_device_id_resolves_to_a_full_identity() {
    // This is what happens when an operator types BA-XXXX-XXXX into Add Device.
    let server = TestServer::start().await;
    let target_id = DeviceIdentity::generate().expect("identity");
    let asker_id = DeviceIdentity::generate().expect("identity");

    let target = login(&server, &target_id, "CENTRAL-SERVER").await;
    let mut asker = login(&server, &asker_id, "LAPTOP").await;

    asker
        .send(ToServer::Resolve { device_id: target_id.device_id() })
        .await
        .expect("resolve");

    let reply = wait_for(&mut asker, |m| matches!(m, ToNode::Resolved { .. })).await;
    match reply {
        ToNode::Resolved { device_id, identity } => {
            assert_eq!(device_id, target_id.device_id());
            assert_eq!(identity, Some(target_id.public()), "the full public key comes back");
        }
        other => panic!("unexpected: {other:?}"),
    }

    // An unknown ID resolves to nothing rather than to an error.
    let unknown = DeviceIdentity::generate().expect("identity").device_id();
    asker.send(ToServer::Resolve { device_id: unknown }).await.expect("resolve");
    let reply = wait_for(&mut asker, |m| {
        matches!(m, ToNode::Resolved { device_id, .. } if *device_id == unknown)
    })
    .await;
    match reply {
        ToNode::Resolved { identity, .. } => assert_eq!(identity, None),
        other => panic!("unexpected: {other:?}"),
    }

    drop(target);
}

#[tokio::test]
async fn an_introduction_is_routed_to_the_target_and_the_answer_comes_back() {
    // The core of the whole architecture: A asks to be introduced to B, B is
    // told, B answers, and A learns where to aim.
    let server = TestServer::start().await;
    let a_id = DeviceIdentity::generate().expect("identity");
    let b_id = DeviceIdentity::generate().expect("identity");

    let mut a = login(&server, &a_id, "LAPTOP").await;
    let mut b = login(&server, &b_id, "CENTRAL-SERVER").await;

    a.send(ToServer::ConnectRequest {
        target: b_id.public().fingerprint(),
        request_id: 4242,
        candidates: vec![],
    })
    .await
    .expect("connect request");

    // B receives the offer.
    let a_seen_from = a.public_address();
    let offer = wait_for(&mut b, |m| matches!(m, ToNode::ConnectOffer { .. })).await;
    let (offer_id, from) = match offer {
        ToNode::ConnectOffer { request_id, from, candidates, .. } => {
            assert_eq!(from, a_id.public(), "the offer names the real requester");

            // The property that matters: the target is told the address the
            // server observed the requester at, because that is the NAT
            // mapping a hole punch has to aim for and only the server can know
            // it.
            //
            // Not asserted by candidate *kind*: on loopback the requester's own
            // interface address and the address the server sees are the same
            // one, and the server correctly collapses the duplicate, keeping
            // the `Local` label because a directly reachable address should be
            // probed first. Behind a real NAT the two differ and both appear.
            assert!(
                candidates.iter().any(|c| c.addr == a_seen_from),
                "the offer must contain the address the server saw {a_seen_from}, got {candidates:?}"
            );
            (request_id, from)
        }
        other => panic!("unexpected: {other:?}"),
    };

    assert_ne!(offer_id, 4242, "the server issues its own exchange identifier");

    // B accepts.
    b.send(ToServer::ConnectAnswer {
        request_id: offer_id,
        accept: true,
        reason: None,
        candidates: vec![],
    })
    .await
    .expect("connect answer");

    // A gets the result, under its own original request id.
    let result = wait_for(&mut a, |m| matches!(m, ToNode::ConnectResult { .. })).await;
    match result {
        ToNode::ConnectResult { request_id, accepted, peer, candidates, .. } => {
            assert_eq!(request_id, 4242, "routed back under the requester's own number");
            assert!(accepted);
            assert_eq!(peer, Some(b_id.public()), "so the handshake can verify who answered");
            assert!(!candidates.is_empty(), "A needs somewhere to aim");
        }
        other => panic!("unexpected: {other:?}"),
    }

    assert_eq!(from, a_id.public());
}

#[tokio::test]
async fn an_introduction_to_an_offline_device_fails_immediately() {
    let server = TestServer::start().await;
    let a_id = DeviceIdentity::generate().expect("identity");
    let b_id = DeviceIdentity::generate().expect("identity");

    // B registers, then goes away.
    login(&server, &b_id, "WAREHOUSE-PC").await.close().await;
    let mut a = login(&server, &a_id, "LAPTOP").await;

    a.send(ToServer::ConnectRequest {
        target: b_id.public().fingerprint(),
        request_id: 7,
        candidates: vec![],
    })
    .await
    .expect("connect request");

    let result = wait_for(&mut a, |m| matches!(m, ToNode::ConnectResult { .. })).await;
    match result {
        ToNode::ConnectResult { request_id, accepted, reason, .. } => {
            assert_eq!(request_id, 7);
            assert!(!accepted);
            assert_eq!(reason, Some(FailureReason::DeviceOffline));
            // And the message is something an operator can act on.
            assert!(FailureReason::DeviceOffline.message().contains("not connected"));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn an_introduction_to_an_unknown_device_says_so() {
    let server = TestServer::start().await;
    let a_id = DeviceIdentity::generate().expect("identity");
    let stranger = DeviceIdentity::generate().expect("identity");

    let mut a = login(&server, &a_id, "LAPTOP").await;
    a.send(ToServer::ConnectRequest {
        target: stranger.public().fingerprint(),
        request_id: 9,
        candidates: vec![],
    })
    .await
    .expect("connect request");

    let result = wait_for(&mut a, |m| matches!(m, ToNode::ConnectResult { .. })).await;
    match result {
        ToNode::ConnectResult { reason, .. } => {
            assert_eq!(reason, Some(FailureReason::UnknownDevice));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn a_third_device_cannot_answer_an_introduction_it_was_not_sent() {
    // If this were possible, a rogue device could inject itself into someone
    // else's connection attempt.
    let server = TestServer::start().await;
    let a_id = DeviceIdentity::generate().expect("identity");
    let b_id = DeviceIdentity::generate().expect("identity");
    let c_id = DeviceIdentity::generate().expect("identity");

    let mut a = login(&server, &a_id, "LAPTOP").await;
    let mut b = login(&server, &b_id, "CENTRAL-SERVER").await;
    let c = login(&server, &c_id, "ROGUE-PC").await;

    a.send(ToServer::ConnectRequest {
        target: b_id.public().fingerprint(),
        request_id: 1,
        candidates: vec![],
    })
    .await
    .expect("connect request");

    let offer = wait_for(&mut b, |m| matches!(m, ToNode::ConnectOffer { .. })).await;
    let ToNode::ConnectOffer { request_id: offer_id, .. } = offer else {
        panic!("expected an offer");
    };

    // C answers B's offer, having observed or guessed the identifier.
    c.send(ToServer::ConnectAnswer {
        request_id: offer_id,
        accept: true,
        reason: None,
        candidates: vec![],
    })
    .await
    .expect("rogue answer");

    // A must not receive a result naming C.
    let got = tokio::time::timeout(Duration::from_millis(600), a.next_event()).await;
    match got {
        Err(_) => { /* nothing arrived, which is correct */ }
        Ok(Some(ToNode::ConnectResult { peer, .. })) => {
            panic!("the rogue answer was routed through, naming {peer:?}");
        }
        Ok(other) => panic!("unexpected: {other:?}"),
    }

    // And the real target can still answer normally.
    b.send(ToServer::ConnectAnswer {
        request_id: offer_id,
        accept: true,
        reason: None,
        candidates: vec![],
    })
    .await
    .expect("real answer");

    let result = wait_for(&mut a, |m| matches!(m, ToNode::ConnectResult { .. })).await;
    match result {
        ToNode::ConnectResult { peer, accepted, .. } => {
            assert!(accepted);
            assert_eq!(peer, Some(b_id.public()), "only the real target's answer counts");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn a_node_cannot_introduce_itself_to_itself() {
    let server = TestServer::start().await;
    let id = DeviceIdentity::generate().expect("identity");
    let mut a = login(&server, &id, "LAPTOP").await;

    a.send(ToServer::ConnectRequest {
        target: id.public().fingerprint(),
        request_id: 5,
        candidates: vec![],
    })
    .await
    .expect("connect request");

    let result = wait_for(&mut a, |m| matches!(m, ToNode::ConnectResult { .. })).await;
    match result {
        ToNode::ConnectResult { accepted, reason, .. } => {
            assert!(!accepted);
            assert_eq!(reason, Some(FailureReason::BadRequest));
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn a_round_trip_to_the_server_can_be_measured() {
    let server = TestServer::start().await;
    let id = DeviceIdentity::generate().expect("identity");
    let mut conn = login(&server, &id, "LAPTOP").await;

    let (rtt_us, server_time) = conn.ping().await.expect("ping should answer");
    assert!(rtt_us > 0, "a round trip takes some time");
    assert!(rtt_us < 2_000_000, "two seconds on loopback would be absurd: {rtt_us} us");
    assert!(server_time > 0, "the server reports its clock for offset calibration");
}

#[tokio::test]
async fn the_audit_log_records_logins_and_introductions() {
    let server = TestServer::start().await;
    let a_id = DeviceIdentity::generate().expect("identity");
    let b_id = DeviceIdentity::generate().expect("identity");

    let a = login(&server, &a_id, "LAPTOP").await;
    let _b = login(&server, &b_id, "CENTRAL-SERVER").await;

    a.send(ToServer::ConnectRequest {
        target: b_id.public().fingerprint(),
        request_id: 1,
        candidates: vec![],
    })
    .await
    .expect("connect request");

    // Give the server a moment to write the entry.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let entries = server.state.db.recent_audit(50).expect("audit");
    assert!(
        entries.iter().any(|e| e.action == "authenticate" && e.success),
        "logins must be recorded: {entries:?}"
    );
    assert!(
        entries.iter().any(|e| e.action == "connect-request"),
        "introductions must be recorded: {entries:?}"
    );

    // And nothing secret ever reaches the log.
    for e in &entries {
        let text = format!("{} {}", e.action, e.detail).to_lowercase();
        for banned in ["private", "secret", "password", "signature", "session key"] {
            assert!(!text.contains(banned), "audit entry leaks {banned:?}: {e:?}");
        }
    }
}

#[tokio::test]
async fn reconnecting_replaces_the_earlier_session_without_losing_presence() {
    // A laptop that sleeps and wakes reconnects before the server has noticed
    // the old link died. The device must end up online exactly once.
    let server = TestServer::start().await;
    let id = DeviceIdentity::generate().expect("identity");

    let first = login(&server, &id, "LAPTOP").await;
    assert!(server.state.registry.is_online(&id.fingerprint()));

    let second = login(&server, &id, "LAPTOP").await;
    assert!(server.state.registry.is_online(&id.fingerprint()));
    assert_eq!(server.state.registry.online_count(), 1, "not counted twice");

    // Dropping the stale connection must not mark the device offline.
    drop(first);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(
        server.state.registry.is_online(&id.fingerprint()),
        "the newer connection must survive the older one ending"
    );

    second.close().await;
}

#[tokio::test]
async fn revoking_blocks_only_that_pair_and_re_pairing_lifts_it() {
    // Regression test. The first server version turned one device's revocation
    // into a network-wide ban on the revoked device.
    let server = TestServer::start().await;
    let laptop_id = DeviceIdentity::generate().expect("identity");
    let office_id = DeviceIdentity::generate().expect("identity");
    let other_id = DeviceIdentity::generate().expect("identity");

    let mut laptop = login(&server, &laptop_id, "LAPTOP").await;
    let mut office = login(&server, &office_id, "OFFICE-PC").await;
    let mut other = login(&server, &other_id, "WAREHOUSE-PC").await;

    // OFFICE-PC stops trusting LAPTOP, proving it with a signature.
    let mut signed = Vec::new();
    signed.extend_from_slice(laptop_id.fingerprint().as_bytes());
    signed.extend_from_slice(office_id.fingerprint().as_bytes());
    let sig = office_id.sign(bark_crypto::identity::context::REVOCATION, &signed);
    office
        .send(ToServer::Revoke { peer: laptop_id.fingerprint(), signature: sig.into() })
        .await
        .expect("revoke");
    tokio::time::sleep(Duration::from_millis(200)).await;

    // LAPTOP can no longer be introduced to OFFICE-PC...
    laptop
        .send(ToServer::ConnectRequest {
            target: office_id.fingerprint(),
            request_id: 1,
            candidates: vec![],
        })
        .await
        .expect("request");
    match wait_for(&mut laptop, |m| matches!(m, ToNode::ConnectResult { request_id: 1, .. })).await {
        ToNode::ConnectResult { accepted, reason, .. } => {
            assert!(!accepted);
            assert_eq!(reason, Some(FailureReason::Revoked));
        }
        other => panic!("unexpected: {other:?}"),
    }

    // ...but is NOT banned from the network: still signed in, still able to
    // reach a third machine.
    assert!(server.state.registry.is_online(&laptop_id.fingerprint()));
    let record = server.state.db.by_fingerprint(&laptop_id.fingerprint()).unwrap().unwrap();
    assert!(!record.revoked, "a per-pair revocation must not ban the device");

    laptop
        .send(ToServer::ConnectRequest {
            target: other_id.fingerprint(),
            request_id: 2,
            candidates: vec![],
        })
        .await
        .expect("request");
    let offer = wait_for(&mut other, |m| matches!(m, ToNode::ConnectOffer { .. })).await;
    let ToNode::ConnectOffer { request_id: offer_id, .. } = offer else { unreachable!() };
    other
        .send(ToServer::ConnectAnswer { request_id: offer_id, accept: true, reason: None, candidates: vec![] })
        .await
        .expect("answer");
    match wait_for(&mut laptop, |m| matches!(m, ToNode::ConnectResult { request_id: 2, .. })).await {
        ToNode::ConnectResult { accepted, .. } => assert!(accepted, "other machines must still work"),
        other => panic!("unexpected: {other:?}"),
    }

    // Re-pairing is still possible (it needs OFFICE-PC's code, i.e. its
    // owner's consent), and it lifts the block.
    laptop
        .send(ToServer::PairRequest {
            target: office_id.fingerprint(),
            request_id: 3,
            code_nonce: [1u8; 16],
            code_digest: [2u8; 32],
            our_name: "LAPTOP".into(),
            machine: machine("LAPTOP"),
        })
        .await
        .expect("pair request");
    let offer = wait_for(&mut office, |m| matches!(m, ToNode::PairOffer { .. })).await;
    let ToNode::PairOffer { request_id: pair_offer, .. } = offer else { unreachable!() };
    office
        .send(ToServer::PairAnswer {
            request_id: pair_offer,
            accept: true,
            reason: None,
            machine: Some(machine("OFFICE-PC")),
            name: Some("OFFICE-PC".into()),
        })
        .await
        .expect("pair answer");
    let _ = wait_for(&mut laptop, |m| matches!(m, ToNode::PairResult { request_id: 3, .. })).await;

    assert!(
        !server.state.db.is_blocked(&office_id.fingerprint(), &laptop_id.fingerprint()).unwrap(),
        "re-pairing must lift the revocation"
    );
}
