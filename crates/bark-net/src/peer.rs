//! Connections between two paired devices.
//!
//! Getting two machines behind two different NATs to talk directly takes three
//! moves, all from each node's one socket:
//!
//! 1. **Punch.** The remote sends a few tiny packets towards every address the
//!    controller might be reachable at. Its own NAT records "this computer
//!    talked to that address", and will now let packets from there back in.
//! 2. **Dial.** The controller starts a QUIC connection to every address the
//!    remote might be reachable at, all at once, LAN addresses first. Its own
//!    outgoing packets open its NAT the same way. The first attempt to
//!    complete wins; the rest are dropped.
//! 3. **Prove.** The QUIC connection is encrypted but not authenticated — the
//!    peer's transport certificate could be anybody's. So before anything else
//!    crosses it, the two devices run the signed handshake from
//!    `bark_crypto::handshake`, bound to this exact connection. Only then is
//!    the connection a session.
//!
//! The same code runs over a relay: a relayed path is just one more address to
//! dial, and the handshake is what guarantees the relay cannot read or alter
//! what it forwards.

use crate::endpoint::session_client_config;
use crate::framing::{read_message, write_message};
use crate::tls::CERT_NAME;
use bark_core::{BarkError, Result};
use bark_crypto::{DeviceIdentity, Initiator, PublicIdentity, Responder};
use bark_proto::control::{Candidate, CandidateKind, FailureReason};
use bark_proto::peer::Setup;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

/// The hole-punching packet.
///
/// Eight bytes whose first byte has QUIC's "fixed bit" clear and which is too
/// short to hold even a short-header packet, so every QUIC stack — including
/// the one on the receiving socket — discards it without replying. Its only
/// purpose is the NAT state it creates on the way out.
pub const PUNCH_PACKET: [u8; 8] = [0x00, b'B', b'A', b'R', b'K', b'-', b'H', b'P'];

/// Gap between punch rounds. Several rounds, because the first ones often
/// arrive before the other side's NAT is open and are dropped.
pub const PUNCH_INTERVAL: Duration = Duration::from_millis(40);

/// How long the remote keeps punching after accepting an introduction.
pub const PUNCH_DURATION: Duration = Duration::from_secs(5);

/// How long the controller tries direct paths before reporting failure (and,
/// once relaying exists, falling back to a relay).
pub const DIRECT_TIMEOUT: Duration = Duration::from_secs(4);

/// Head start given to LAN addresses. A LAN path is so much better than an
/// internet one that it is worth a moment's wait for it to win the race.
pub const LAN_HEAD_START: Duration = Duration::from_millis(30);

/// Upper bound on the handshake once a connection exists.
pub const SETUP_TIMEOUT: Duration = Duration::from_secs(10);

/// The label under which the channel binding is exported from TLS.
const EXPORTER_LABEL: &[u8] = b"EXPORTER-BARK-v1-peer-session";

/// Application close codes, so the far side can tell a refusal from a crash.
pub mod close {
    pub const NORMAL: u32 = 0;
    pub const REFUSED: u32 = 1;
    pub const HANDSHAKE_FAILED: u32 = 2;
    pub const DUPLICATE: u32 = 3;
}

/// The value both ends of one QUIC connection derive, and nobody else can.
pub fn channel_binding(conn: &Connection) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, b"")
        .map_err(|_| BarkError::crypto("could not derive the connection's channel binding"))?;
    Ok(out)
}

/// Sends punch packets to `targets` every [`PUNCH_INTERVAL`] for `duration`.
///
/// Errors are ignored on purpose: a target on a network this computer cannot
/// route to simply fails, and the other targets still matter.
pub async fn punch(raw: Arc<UdpSocket>, targets: Vec<SocketAddr>, duration: Duration) {
    if targets.is_empty() {
        return;
    }
    let deadline = tokio::time::Instant::now() + duration;
    let mut tick = tokio::time::interval(PUNCH_INTERVAL);
    while tokio::time::Instant::now() < deadline {
        tick.tick().await;
        for t in &targets {
            let _ = raw.send_to(&PUNCH_PACKET, t);
        }
    }
}

/// A connection that completed, and which address it went to.
pub struct Dialled {
    pub conn: Connection,
    pub candidate: Candidate,
}

/// Connects to whichever of the peer's candidate addresses answers first.
///
/// All attempts run at once; LAN addresses get [`LAN_HEAD_START`]. Relay
/// candidates are ignored here — relaying is set up separately.
pub async fn dial(endpoint: &Endpoint, candidates: &[Candidate], timeout: Duration) -> Result<Dialled> {
    let config = session_client_config()?;
    let direct: Vec<Candidate> =
        candidates.iter().copied().filter(|c| c.kind != CandidateKind::Relay).collect();
    if direct.is_empty() {
        return Err(BarkError::network(
            "The remote computer did not report any address it can be reached at.",
        ));
    }

    // The head start only means something when there is a LAN address to
    // prefer; otherwise it would just delay the connection.
    let head_start = direct.iter().any(|c| c.kind == CandidateKind::Local);
    let mut attempts = tokio::task::JoinSet::new();
    for c in direct.iter().copied() {
        let endpoint = endpoint.clone();
        let config = config.clone();
        attempts.spawn(async move {
            if head_start && c.kind != CandidateKind::Local {
                tokio::time::sleep(LAN_HEAD_START).await;
            }
            let connecting = endpoint
                .connect_with(config, c.addr, CERT_NAME)
                .map_err(|e| (c, e.to_string()))?;
            match connecting.await {
                Ok(conn) => Ok((conn, c)),
                Err(e) => Err((c, e.to_string())),
            }
        });
    }

    let mut failures: Vec<String> = Vec::new();
    let race = async {
        while let Some(joined) = attempts.join_next().await {
            match joined {
                Ok(Ok((conn, candidate))) => return Some(Dialled { conn, candidate }),
                Ok(Err((c, e))) => failures.push(format!("{} ({}): {e}", c.addr, kind_word(c.kind))),
                Err(_) => {}
            }
        }
        None
    };
    let winner = tokio::time::timeout(timeout, race).await.ok().flatten();
    // Whatever is still running lost the race (or ran out of time).
    attempts.abort_all();

    match winner {
        Some(d) => Ok(d),
        None => {
            let tried: Vec<String> =
                direct.iter().map(|c| format!("{} ({})", c.addr, kind_word(c.kind))).collect();
            let mut text = format!(
                "No direct path to the remote computer was found within {} seconds.\n\n\
                 Addresses tried: {}",
                timeout.as_secs(),
                tried.join(", ")
            );
            if !failures.is_empty() {
                text.push_str("\nFailures: ");
                text.push_str(&failures.join("; "));
            }
            Err(BarkError::Network(text))
        }
    }
}

/// How long a peer keeps trying to bind to a relay.
pub const RELAY_BIND_TIMEOUT: Duration = Duration::from_secs(10);

/// Opens a fresh socket and binds it to a relay with `token`.
///
/// Returns once the relay reports both peers bound, which is when it starts
/// forwarding. A fresh socket per relayed session is what lets the relay tell
/// sessions apart (see `bark_server::relay`).
pub async fn bind_relay(relay: SocketAddr, token: [u8; 16], timeout: Duration) -> Result<UdpSocket> {
    use bark_proto::relay as rp;
    let local = if relay.ip().is_loopback() {
        SocketAddr::new(relay.ip(), 0)
    } else if relay.is_ipv4() {
        SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), 0)
    } else {
        SocketAddr::new(std::net::Ipv6Addr::UNSPECIFIED.into(), 0)
    };
    let socket = tokio::net::UdpSocket::bind(local)
        .await
        .map_err(|e| BarkError::Network(format!("could not open a socket for the relay: {e}")))?;
    crate::endpoint::size_buffers(&socket);
    let bind = rp::encode_bind(&token);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(BarkError::Network(format!(
                "The relay at {relay} did not answer.\n\n\
                 Possible causes:\n\
                 \u{2022} UDP port {} is not open or not forwarded to the BARK server\n\
                 \u{2022} A firewall between this computer and the server blocks UDP",
                relay.port()
            )));
        }
        let _ = socket.send_to(&bind, relay).await;
        let wait = tokio::time::sleep(Duration::from_millis(100));
        tokio::pin!(wait);
        loop {
            tokio::select! {
                _ = &mut wait => break,
                r = socket.recv_from(&mut buf) => {
                    let Ok((n, from)) = r else { continue };
                    if from != relay {
                        continue;
                    }
                    match rp::decode_ack(&buf[..n]) {
                        Some(true) => return into_std(socket),
                        Some(false) => {}
                        // Anything else from the relay is the other peer's
                        // traffic, so forwarding has already begun. That one
                        // datagram is lost; QUIC resends it.
                        None => return into_std(socket),
                    }
                }
            }
        }
    }
}

fn into_std(socket: tokio::net::UdpSocket) -> Result<UdpSocket> {
    let s = socket.into_std()?;
    s.set_nonblocking(true)?;
    Ok(s)
}

/// Controller side of a relayed path: binds, then connects through the relay.
///
/// The returned endpoint owns the session's socket and must be kept for as
/// long as the connection is used.
pub async fn dial_relay(relay: SocketAddr, token: [u8; 16]) -> Result<(Endpoint, Connection)> {
    let socket = bind_relay(relay, token, RELAY_BIND_TIMEOUT).await?;
    let mut endpoint =
        Endpoint::new(quinn::EndpointConfig::default(), None, socket, Arc::new(quinn::TokioRuntime))
            .map_err(|e| BarkError::Network(format!("could not start networking for the relay: {e}")))?;
    endpoint.set_default_client_config(session_client_config()?);
    let connecting = endpoint
        .connect(relay, CERT_NAME)
        .map_err(|e| BarkError::Network(format!("could not start connecting through the relay: {e}")))?;
    let conn = tokio::time::timeout(DIRECT_TIMEOUT * 2, connecting)
        .await
        .map_err(|_| BarkError::network("The remote computer did not answer through the relay."))?
        .map_err(|e| BarkError::Network(format!("Connecting through the relay failed: {e}")))?;
    Ok((endpoint, conn))
}

/// Remote side of a relayed path: binds, then accepts the one connection the
/// relay forwards.
pub async fn accept_relay(relay: SocketAddr, token: [u8; 16]) -> Result<(Endpoint, Connection)> {
    let socket = bind_relay(relay, token, RELAY_BIND_TIMEOUT).await?;
    let creds = crate::tls::TransportCredentials::generate()?;
    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(crate::endpoint::session_server_config(&creds)?),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| BarkError::Network(format!("could not start networking for the relay: {e}")))?;
    let incoming = tokio::time::timeout(RELAY_BIND_TIMEOUT, endpoint.accept())
        .await
        .map_err(|_| BarkError::network("The controlling computer did not connect through the relay."))?
        .ok_or_else(|| BarkError::network("the relay socket closed"))?;
    let conn = incoming
        .await
        .map_err(|e| BarkError::Network(format!("A connection through the relay failed: {e}")))?;
    Ok((endpoint, conn))
}

/// How an address was learned, in words for diagnostics.
pub fn kind_word(kind: CandidateKind) -> &'static str {
    match kind {
        CandidateKind::Local => "LAN",
        CandidateKind::ServerReflexive => "internet",
        CandidateKind::Relay => "relay",
    }
}

/// An authenticated connection to a paired device.
pub struct PeerSession {
    pub conn: Connection,
    /// The stream the handshake ran on. It carries the session's control
    /// messages from here on.
    pub control_send: SendStream,
    pub control_recv: RecvStream,
    /// Who is on the other end — proven, not claimed.
    pub peer: PublicIdentity,
    /// Words both ends can read out to confirm nothing is in the middle.
    pub verification: String,
}

impl std::fmt::Debug for PeerSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PeerSession({} via {})", self.peer.device_id(), self.conn.remote_address())
    }
}

/// Controller side: proves who we are to the remote and checks it is the
/// device we meant to reach.
pub async fn open_session(
    conn: Connection,
    identity: &DeviceIdentity,
    expected: &PublicIdentity,
) -> Result<PeerSession> {
    let work = async {
        let binding = channel_binding(&conn)?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| BarkError::Network(format!("could not open the session stream: {e}")))?;

        let (init, hello) = Initiator::start(identity, &binding)?;
        write_message(&mut send, &Setup::from(hello)).await?;

        let reply: Setup = read_message(&mut recv)
            .await?
            .ok_or_else(|| BarkError::network("The remote computer closed the connection during setup."))?;
        let accept = match reply {
            Setup::Refused { reason, detail } => {
                let mut text = reason.message().to_string();
                if !detail.is_empty() {
                    text.push_str("\n\n");
                    text.push_str(&detail);
                }
                return Err(BarkError::Network(text));
            }
            other => other
                .into_accept()
                .ok_or_else(|| BarkError::protocol("the remote computer answered out of order"))?,
        };

        let (keys, confirm) = init.finish(identity, &accept, Some(expected))?;
        write_message(&mut send, &Setup::from(confirm)).await?;

        Ok(PeerSession {
            conn: conn.clone(),
            control_send: send,
            control_recv: recv,
            peer: accept.identity,
            verification: keys.verification_words(),
        })
    };

    match tokio::time::timeout(SETUP_TIMEOUT, work).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            conn.close(close::HANDSHAKE_FAILED.into(), b"setup failed");
            Err(e)
        }
        Err(_) => {
            conn.close(close::HANDSHAKE_FAILED.into(), b"setup timed out");
            Err(BarkError::network("The remote computer connected but did not finish setting up the session."))
        }
    }
}

/// Remote side: learns who is connecting, asks `authorise` whether they may,
/// and completes the handshake if so.
///
/// `authorise` runs before any key agreement. Its error is sent back to the
/// controller as the reason for refusal.
pub async fn accept_session<F>(conn: Connection, identity: &DeviceIdentity, authorise: F) -> Result<PeerSession>
where
    F: FnOnce(&PublicIdentity) -> std::result::Result<(), (FailureReason, String)>,
{
    let work = async {
        let binding = channel_binding(&conn)?;
        let (mut send, mut recv) = conn
            .accept_bi()
            .await
            .map_err(|e| BarkError::Network(format!("the connecting computer opened no session stream: {e}")))?;

        let first: Setup = read_message(&mut recv)
            .await?
            .ok_or_else(|| BarkError::network("the connecting computer closed the stream during setup"))?;
        let hello = first
            .into_hello()
            .ok_or_else(|| BarkError::protocol("the connecting computer did not start with a hello"))?;

        if let Err((reason, detail)) = authorise(&hello.identity) {
            refuse(&conn, &mut send, reason, detail.clone()).await;
            return Err(BarkError::Network(format!(
                "Refused a session from {}: {}",
                hello.identity.device_id(),
                if detail.is_empty() { reason.message().to_string() } else { detail }
            )));
        }

        let (resp, accept) = match Responder::accept(identity, &hello, &binding, |_| Ok(())) {
            Ok(v) => v,
            Err(e) => {
                let reason = match &e {
                    BarkError::Protocol(_) => FailureReason::VersionMismatch,
                    _ => FailureReason::Refused,
                };
                refuse(&conn, &mut send, reason, e.to_string()).await;
                return Err(e);
            }
        };
        write_message(&mut send, &Setup::from(accept)).await?;

        let second: Setup = read_message(&mut recv)
            .await?
            .ok_or_else(|| BarkError::network("the connecting computer closed the stream during setup"))?;
        let confirm = second
            .into_confirm()
            .ok_or_else(|| BarkError::protocol("the connecting computer answered out of order"))?;
        let keys = resp.finish(&confirm)?;

        Ok(PeerSession {
            conn: conn.clone(),
            control_send: send,
            control_recv: recv,
            peer: hello.identity,
            verification: keys.verification_words(),
        })
    };

    match tokio::time::timeout(SETUP_TIMEOUT, work).await {
        Ok(Ok(s)) => Ok(s),
        Ok(Err(e)) => {
            conn.close(close::HANDSHAKE_FAILED.into(), b"setup failed");
            Err(e)
        }
        Err(_) => {
            conn.close(close::HANDSHAKE_FAILED.into(), b"setup timed out");
            Err(BarkError::network("a connecting computer did not finish setting up a session in time"))
        }
    }
}

/// Tells the controller why, then closes. The short wait gives the refusal a
/// chance to arrive before the close overtakes it.
async fn refuse(conn: &Connection, send: &mut SendStream, reason: FailureReason, detail: String) {
    let _ = write_message(send, &Setup::Refused { reason, detail }).await;
    let _ = send.finish();
    let _ = tokio::time::timeout(Duration::from_millis(500), send.stopped()).await;
    conn.close(close::REFUSED.into(), b"refused");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::NodeSocket;
    use crate::tls::{pinned_client_config, TransportCredentials};
    use std::net::{IpAddr, Ipv4Addr};

    fn node() -> NodeSocket {
        let creds = TransportCredentials::generate().unwrap();
        // The default client config only matters for server connections,
        // which these tests do not make.
        NodeSocket::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &creds,
            pinned_client_config([0u8; 32]).unwrap(),
        )
        .unwrap()
    }

    fn local(addr: SocketAddr) -> Candidate {
        Candidate { addr, kind: CandidateKind::Local }
    }

    /// Accepts one connection on `node` and runs the remote side.
    fn serve_one<F>(
        node: &NodeSocket,
        identity: DeviceIdentity,
        authorise: F,
    ) -> tokio::task::JoinHandle<Result<PeerSession>>
    where
        F: FnOnce(&PublicIdentity) -> std::result::Result<(), (FailureReason, String)> + Send + 'static,
    {
        let ep = node.endpoint.clone();
        tokio::spawn(async move {
            let incoming = ep.accept().await.expect("an incoming connection");
            let conn = incoming.await.map_err(|e| BarkError::Network(e.to_string()))?;
            accept_session(conn, &identity, authorise).await
        })
    }

    #[tokio::test]
    async fn two_paired_devices_connect_and_agree_on_the_session() {
        let (a, b) = (node(), node());
        let (a_id, b_id) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        let a_pub = a_id.public();
        let b_pub = b_id.public();

        let remote = serve_one(&b, b_id, move |who| {
            assert_eq!(who.fingerprint(), a_pub.fingerprint());
            Ok(())
        });

        let t0 = std::time::Instant::now();
        let d = dial(&a.endpoint, &[local(b.local_address().unwrap())], DIRECT_TIMEOUT).await.unwrap();
        let ours = open_session(d.conn, &a_id, &b_pub).await.unwrap();
        let theirs = remote.await.unwrap().unwrap();
        let took = t0.elapsed();

        assert_eq!(ours.peer.fingerprint(), b_pub.fingerprint());
        assert_eq!(theirs.peer.fingerprint(), a_id.public().fingerprint());
        assert_eq!(ours.verification, theirs.verification);
        eprintln!("loopback connect + authenticated session setup: {took:?}");
    }

    #[tokio::test]
    async fn a_dead_address_does_not_stop_a_live_one_from_winning() {
        let (a, b) = (node(), node());
        let (a_id, b_id) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        let b_pub = b_id.public();
        let remote = serve_one(&b, b_id, |_| Ok(()));

        // An address nothing listens on, listed first and as a LAN address so
        // it even gets the head start.
        let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        let live = Candidate { addr: b.local_address().unwrap(), kind: CandidateKind::ServerReflexive };
        let d = dial(&a.endpoint, &[local(dead), live], DIRECT_TIMEOUT).await.unwrap();
        assert_eq!(d.candidate.addr, live.addr);
        // Held until both sides finish: dropping a QUIC connection closes it.
        let _ours = open_session(d.conn, &a_id, &b_pub).await.unwrap();
        let _theirs = remote.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_refusal_reaches_the_controller_with_its_reason() {
        let (a, b) = (node(), node());
        let (a_id, b_id) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        let b_pub = b_id.public();
        let remote = serve_one(&b, b_id, |_| Err((FailureReason::NotPaired, String::new())));

        let d = dial(&a.endpoint, &[local(b.local_address().unwrap())], DIRECT_TIMEOUT).await.unwrap();
        let err = open_session(d.conn, &a_id, &b_pub).await.unwrap_err();
        assert!(format!("{err}").contains("not paired"), "got: {err}");
        assert!(remote.await.unwrap().is_err());
    }

    #[tokio::test]
    async fn answering_as_a_different_device_is_caught() {
        let (a, b) = (node(), node());
        let a_id = DeviceIdentity::generate().unwrap();
        let impostor = DeviceIdentity::generate().unwrap();
        let intended = DeviceIdentity::generate().unwrap().public();
        let remote = serve_one(&b, impostor, |_| Ok(()));

        let d = dial(&a.endpoint, &[local(b.local_address().unwrap())], DIRECT_TIMEOUT).await.unwrap();
        let err = open_session(d.conn, &a_id, &intended).await.unwrap_err();
        assert!(format!("{err}").contains("wrong computer"), "got: {err}");
        let _ = remote.await;
    }

    #[tokio::test]
    async fn punch_packets_are_ignored_by_the_receiving_endpoint() {
        let (a, b) = (node(), node());
        let (a_id, b_id) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        let b_pub = b_id.public();
        let b_addr = b.local_address().unwrap();
        let a_addr = a.local_address().unwrap();

        // Both sides punch at each other while the connection is made.
        let p1 = tokio::spawn(punch(a.raw(), vec![b_addr], Duration::from_millis(400)));
        let p2 = tokio::spawn(punch(b.raw(), vec![a_addr], Duration::from_millis(400)));
        let remote = serve_one(&b, b_id, |_| Ok(()));
        let d = dial(&a.endpoint, &[local(b_addr)], DIRECT_TIMEOUT).await.unwrap();
        let s = open_session(d.conn, &a_id, &b_pub).await.unwrap();
        let _theirs = remote.await.unwrap().unwrap();
        p1.await.unwrap();
        p2.await.unwrap();
        // Still healthy after the punches finished.
        assert!(s.conn.close_reason().is_none(), "the connection must survive punching");
    }

    #[tokio::test]
    async fn nothing_listening_anywhere_fails_with_the_addresses_tried() {
        let a = node();
        let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
        let err = dial(&a.endpoint, &[local(dead)], Duration::from_secs(1)).await.err().unwrap();
        let text = format!("{err}");
        assert!(text.contains("127.0.0.1:9"), "should list what was tried: {text}");
    }

    /// The attack channel binding exists to stop: something in the path that
    /// terminates QUIC itself, keeps one connection to each device, and passes
    /// the handshake messages through unmodified. Without the binding this
    /// would succeed and the middle would see everything in the clear.
    #[tokio::test]
    async fn a_relay_that_terminates_the_connection_cannot_complete_the_handshake() {
        let (a, b, middle) = (node(), node(), node());
        let (a_id, b_id) = (DeviceIdentity::generate().unwrap(), DeviceIdentity::generate().unwrap());
        let b_pub = b_id.public();
        let b_addr = b.local_address().unwrap();

        let remote = serve_one(&b, b_id, |_| Ok(()));

        // The middle accepts A's connection and opens its own to B, then
        // copies stream bytes both ways.
        let mid_ep = middle.endpoint.clone();
        let mitm = tokio::spawn(async move {
            let from_a = mid_ep.accept().await.unwrap().await.unwrap();
            let to_b = mid_ep
                .connect_with(session_client_config().unwrap(), b_addr, CERT_NAME)
                .unwrap()
                .await
                .unwrap();
            let (mut a_send, mut a_recv) = from_a.accept_bi().await.unwrap();
            let (mut b_send, mut b_recv) = to_b.open_bi().await.unwrap();
            let up = async { tokio::io::copy(&mut a_recv, &mut b_send).await };
            let down = async { tokio::io::copy(&mut b_recv, &mut a_send).await };
            let _ = tokio::time::timeout(Duration::from_secs(3), async { tokio::join!(up, down) }).await;
        });

        let d = dial(&a.endpoint, &[local(middle.local_address().unwrap())], DIRECT_TIMEOUT)
            .await
            .unwrap();
        let result = open_session(d.conn, &a_id, &b_pub).await;
        assert!(result.is_err(), "the controller must detect the man in the middle");
        assert!(remote.await.unwrap().is_err(), "the remote must not accept either");
        mitm.abort();
    }
}
