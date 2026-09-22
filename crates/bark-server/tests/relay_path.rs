//! A whole session through the relay: bind, QUIC through the forwarder, and
//! the channel-bound handshake on top.

use bark_crypto::DeviceIdentity;
use bark_net::peer::{accept_relay, accept_session, dial_relay, open_session};
use bark_server::relay::{Relay, RelayLimits};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

fn lo() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

#[tokio::test]
async fn a_session_runs_end_to_end_through_the_relay() {
    let relay = Relay::bind(lo(), RelayLimits::default()).await.unwrap();
    tokio::spawn(relay.clone().run());
    let at = relay.listening();

    let controller = DeviceIdentity::generate().unwrap();
    let remote = DeviceIdentity::generate().unwrap();
    let remote_pub = remote.public();
    let controller_fp = controller.public().fingerprint();
    let (tc, tr) = relay.allocate(controller_fp, remote_pub.fingerprint()).unwrap();

    let t0 = Instant::now();
    let remote_side = tokio::spawn(async move {
        let (ep, conn) = accept_relay(at, tr).await?;
        let s = accept_session(conn, &remote, |who| {
            assert_eq!(who.fingerprint(), controller_fp);
            Ok(())
        })
        .await?;
        Ok::<_, bark_core::BarkError>((ep, s))
    });

    let (_ep, conn) = dial_relay(at, tc).await.expect("dial through the relay");
    let ours = open_session(conn, &controller, &remote_pub).await.expect("handshake through the relay");
    let (_rep, theirs) = remote_side.await.unwrap().expect("remote side");
    let took = t0.elapsed();

    assert_eq!(ours.verification, theirs.verification);
    assert_eq!(ours.conn.remote_address(), at, "the controller's peer address is the relay");

    // Datagrams (how video will travel) cross the relay too.
    ours.conn.send_datagram(bytes::Bytes::from_static(b"frame")).unwrap();
    let got = tokio::time::timeout(Duration::from_secs(2), theirs.conn.read_datagram()).await.unwrap().unwrap();
    assert_eq!(&got[..], b"frame");

    let stats = relay.stats();
    assert_eq!(stats.active, 1);
    assert!(stats.bytes_forwarded > 1000, "the handshake crossed the relay: {stats:?}");
    eprintln!("relayed connect + authenticated setup on loopback: {took:?}; {stats:?}");
}

#[tokio::test]
async fn a_forged_token_gets_no_path() {
    let relay = Relay::bind(lo(), RelayLimits::default()).await.unwrap();
    tokio::spawn(relay.clone().run());
    let err = bark_net::peer::bind_relay(relay.listening(), [0xEE; 16], Duration::from_millis(500)).await;
    assert!(err.is_err(), "a token the server never issued must not bind");
}
