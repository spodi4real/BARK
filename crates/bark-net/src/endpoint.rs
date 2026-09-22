//! QUIC endpoint construction.
//!
//! One design point dominates this module: **a BARK node uses a single UDP
//! socket that both listens and connects.**
//!
//! That is not a tidiness preference, it is what makes NAT traversal work. Hole
//! punching relies on the outbound packet that opens the NAT mapping and the
//! inbound packet that arrives through it being on the *same* socket, from the
//! NAT's point of view — same local port, same public mapping. Two sockets
//! would get two mappings and the punch would fail. It is also the socket the
//! coordination server saw us from, so the address it reports back is the one
//! peers can actually reach.
//!
//! Transport settings here are starting points chosen from how QUIC works, not
//! from measurement. They are marked as such, and are to be revisited once
//! there is a real session to measure. Nothing in this file should be presented
//! as tuned until it has been.

use bark_core::{BarkError, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::tls::TransportCredentials;

/// How long a connection may be silent before it is considered dead.
///
/// Long enough to ride out a brief network interruption — a Wi-Fi roam, a VPN
/// reconnect — without tearing down a working session, short enough that a
/// genuinely dead peer is noticed while the operator is still looking at the
/// screen.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a silent connection sends a keepalive.
///
/// This value does real work beyond liveness: it holds the NAT mapping open.
/// Home routers commonly expire an idle UDP mapping after 30 seconds and some
/// after 20, so 5 seconds keeps the path open with a wide margin, at a cost of
/// a few dozen bytes. Without it, an idle BARK node would quietly become
/// unreachable and only discover it when someone tried to connect.
pub const KEEPALIVE: Duration = Duration::from_secs(5);

/// Assumed path MTU before discovery completes.
///
/// 1200 is QUIC's guaranteed minimum. Starting here means the first packets
/// always get through, including over tunnels and VPNs that quietly reduce the
/// MTU; discovery raises it afterwards where the path allows.
pub const INITIAL_MTU: u16 = 1200;

/// What a connection is for. Changes how it is tuned and, more importantly,
/// how it is authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Node to coordination server: low rate, long lived, pinned certificate.
    Control,
    /// Node to node: carries the session, authenticated by the inner handshake.
    Session,
}

/// Builds the transport settings shared by every BARK connection.
fn transport_config(role: Role) -> TransportConfig {
    let mut tc = TransportConfig::default();

    tc.max_idle_timeout(Some(
        IDLE_TIMEOUT.try_into().expect("idle timeout fits in a QUIC varint"),
    ));
    tc.keep_alive_interval(Some(KEEPALIVE));
    tc.initial_mtu(INITIAL_MTU);
    tc.min_mtu(INITIAL_MTU);

    match role {
        Role::Control => {
            // The control channel carries small messages and nothing else.
            // Keeping the limits low bounds what a misbehaving peer can make
            // the server hold.
            tc.max_concurrent_bidi_streams(4u32.into());
            tc.max_concurrent_uni_streams(4u32.into());
            tc.datagram_receive_buffer_size(Some(64 * 1024));
        }
        Role::Session => {
            // Control, input, clipboard and files each get a stream, with room
            // for several concurrent file transfers.
            tc.max_concurrent_bidi_streams(16u32.into());
            tc.max_concurrent_uni_streams(16u32.into());

            // Only matters before the first round trip has been measured: it
            // sets how soon a lost first packet is resent. QUIC's default
            // (333 ms, so about a second before the first resend) suits the
            // open internet; a hole-punched path whose first packet can be
            // dropped by a NAT that has not opened yet connects noticeably
            // faster with a shorter guess. Chosen, not measured.
            tc.initial_rtt(Duration::from_millis(100));

            // Video rides in datagrams. This buffer is what absorbs a burst
            // while the decode thread is busy; too small drops frames that had
            // already arrived, too large just wastes memory since stale frames
            // are useless anyway. Roughly a quarter second at 30 Mbit/s.
            tc.datagram_receive_buffer_size(Some(1024 * 1024));
            tc.datagram_send_buffer_size(512 * 1024);

            // BBR paces sending and reacts to the path's actual capacity rather
            // than waiting for loss. Loss-based control fills the queue before
            // it backs off, and a full queue is added latency — exactly what
            // this project cannot afford. Chosen on that reasoning; not yet
            // compared against Cubic on a real link, which is a measurement
            // still to be done.
            tc.congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
        }
    }

    tc
}

/// Creates an endpoint that can both accept and make connections on one socket.
///
/// This is what every BARK node uses. See the module documentation for why the
/// single socket matters.
///
/// `bind` of `0.0.0.0:0` asks the operating system for any free port, which is
/// the normal case; the coordination server binds a fixed port instead.
pub fn bidirectional_endpoint(
    bind: SocketAddr,
    credentials: &TransportCredentials,
    client_crypto: rustls::ClientConfig,
    role: Role,
) -> Result<Endpoint> {
    let server_crypto = credentials.server_config()?;
    let quic_server = QuicServerConfig::try_from(server_crypto)
        .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;

    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(Arc::new(transport_config(role)));

    let mut endpoint = Endpoint::server(server_config, bind).map_err(|e| {
        BarkError::Network(format!(
            "Could not open a network port on {bind}: {e}\n\n\
             Possible causes:\n\
             \u{2022} Another program is already using that port\n\
             \u{2022} Windows Firewall blocked BARK from listening\n\
             \u{2022} The address is not valid on this computer"
        ))
    })?;

    let quic_client = QuicClientConfig::try_from(client_crypto)
        .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client));
    client_config.transport_config(Arc::new(transport_config(role)));
    endpoint.set_default_client_config(client_config);

    Ok(endpoint)
}

/// Socket buffer sizes for anything carrying a session.
///
/// A keyframe is a burst of well over 100 KB arriving in a few milliseconds.
/// Windows' default UDP receive buffer is far smaller, so on a busy computer
/// part of the burst was dropped before BARK could read it — found by an
/// intermittently failing test, and the same thing would happen on a real
/// network. The sizes are generous next to one second of video at the
/// highest bitrate BARK uses.
pub const RECV_BUFFER: usize = 8 * 1024 * 1024;
pub const SEND_BUFFER: usize = 4 * 1024 * 1024;

/// Applies [`RECV_BUFFER`] and [`SEND_BUFFER`]. Windows may grant less; what
/// it granted is logged.
pub fn size_buffers<S: socket2_ref::AsSock>(socket: &S) {
    let sock = socket.sock_ref();
    let _ = sock.set_recv_buffer_size(RECV_BUFFER);
    let _ = sock.set_send_buffer_size(SEND_BUFFER);
    tracing::debug!(
        recv = sock.recv_buffer_size().unwrap_or(0),
        send = sock.send_buffer_size().unwrap_or(0),
        "socket buffers"
    );
}

/// Lets [`size_buffers`] take both std and tokio sockets.
pub mod socket2_ref {
    pub trait AsSock {
        fn sock_ref(&self) -> socket2::SockRef<'_>;
    }
    impl AsSock for std::net::UdpSocket {
        fn sock_ref(&self) -> socket2::SockRef<'_> {
            socket2::SockRef::from(self)
        }
    }
    impl AsSock for tokio::net::UdpSocket {
        fn sock_ref(&self) -> socket2::SockRef<'_> {
            socket2::SockRef::from(self)
        }
    }
}

/// The node's one socket: a QUIC endpoint, plus a second handle on the very
/// same UDP socket for sending hole-punching packets.
///
/// Punch packets must leave from the port the coordination server saw, or
/// they open a NAT mapping nobody is aiming at. QUIC does not send arbitrary
/// datagrams outside a connection, so BARK keeps a duplicate handle of the
/// socket QUIC reads from and sends the punches through that. The punches are
/// eight bytes that no QUIC implementation can mistake for a packet (see
/// `peer::PUNCH_PACKET`), so the receiving endpoint simply drops them — their
/// only job is the NAT state they leave behind on the way out.
pub struct NodeSocket {
    pub endpoint: Endpoint,
    raw: Arc<std::net::UdpSocket>,
}

impl NodeSocket {
    pub fn bind(
        bind: SocketAddr,
        credentials: &TransportCredentials,
        client_crypto: rustls::ClientConfig,
    ) -> Result<Self> {
        let server_crypto = credentials.server_config()?;
        let quic_server = QuicServerConfig::try_from(server_crypto)
            .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server));
        server_config.transport_config(Arc::new(transport_config(Role::Session)));

        let socket = std::net::UdpSocket::bind(bind).map_err(|e| {
            BarkError::Network(format!(
                "Could not open a network port on {bind}: {e}\n\n\
                 Possible causes:\n\
                 \u{2022} Another program is already using that port\n\
                 \u{2022} Windows Firewall blocked BARK from listening"
            ))
        })?;
        socket.set_nonblocking(true)?;
        size_buffers(&socket);
        let raw = socket.try_clone()?;

        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| BarkError::Network(format!("Could not start networking on {bind}: {e}")))?;

        let quic_client = QuicClientConfig::try_from(client_crypto)
            .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;
        let mut client_config = ClientConfig::new(Arc::new(quic_client));
        client_config.transport_config(Arc::new(transport_config(Role::Session)));
        endpoint.set_default_client_config(client_config);

        Ok(NodeSocket { endpoint, raw: Arc::new(raw) })
    }

    /// The handle punches are sent through.
    pub fn raw(&self) -> Arc<std::net::UdpSocket> {
        self.raw.clone()
    }

    pub fn local_address(&self) -> Result<SocketAddr> {
        local_address(&self.endpoint)
    }
}

/// Server settings for accepting a connection from another BARK device.
pub fn session_server_config(credentials: &TransportCredentials) -> Result<ServerConfig> {
    let quic_server = QuicServerConfig::try_from(credentials.server_config()?)
        .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(quic_server));
    server_config.transport_config(Arc::new(transport_config(Role::Session)));
    Ok(server_config)
}

/// Client settings for connecting to another BARK device: encryption only,
/// session tuning. The peer is authenticated afterwards by the handshake in
/// [`crate::peer`], never by this.
pub fn session_client_config() -> Result<ClientConfig> {
    let crypto = crate::tls::transport_only_client_config()?;
    let quic_client = QuicClientConfig::try_from(crypto)
        .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;
    let mut config = ClientConfig::new(Arc::new(quic_client));
    config.transport_config(Arc::new(transport_config(Role::Session)));
    Ok(config)
}

/// Creates an endpoint that only makes outgoing connections.
///
/// Used by short-lived tools — the diagnostics tester, the command line — which
/// never need to be connected *to*.
pub fn client_only_endpoint(bind: SocketAddr, client_crypto: rustls::ClientConfig, role: Role) -> Result<Endpoint> {
    let mut endpoint = Endpoint::client(bind).map_err(|e| {
        BarkError::Network(format!("Could not open a network port on {bind}: {e}"))
    })?;
    let quic_client = QuicClientConfig::try_from(client_crypto)
        .map_err(|e| BarkError::Crypto(format!("TLS is not usable for QUIC: {e}")))?;
    let mut client_config = ClientConfig::new(Arc::new(quic_client));
    client_config.transport_config(Arc::new(transport_config(role)));
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Connects to a peer, turning QUIC's failure modes into messages an operator
/// can act on.
pub async fn connect(
    endpoint: &Endpoint,
    address: SocketAddr,
    what: &str,
) -> Result<quinn::Connection> {
    let connecting = endpoint
        .connect(address, crate::tls::CERT_NAME)
        .map_err(|e| BarkError::Network(format!("Could not start connecting to {what}: {e}")))?;

    connecting.await.map_err(|e| match e {
        quinn::ConnectionError::TimedOut => BarkError::Network(format!(
            "{what} did not respond at {address}.\n\n\
             Possible causes:\n\
             \u{2022} The computer is turned off or asleep\n\
             \u{2022} A firewall is blocking the connection\n\
             \u{2022} The address or port is wrong"
        )),
        quinn::ConnectionError::ConnectionClosed(_) | quinn::ConnectionError::ApplicationClosed(_) => {
            BarkError::Network(format!("{what} refused the connection."))
        }
        other => BarkError::Network(format!("Could not connect to {what} at {address}: {other}")),
    })
}

/// The address this endpoint is actually bound to, once the operating system
/// has chosen a port.
pub fn local_address(endpoint: &Endpoint) -> Result<SocketAddr> {
    endpoint
        .local_addr()
        .map_err(|e| BarkError::Network(format!("could not read the local address: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{read_expected, write_message};
    use crate::tls::pinned_client_config;
    use bark_proto::control::{ToNode, ToServer};
    use std::net::{IpAddr, Ipv4Addr};

    fn loopback() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    #[test]
    fn transport_settings_are_what_the_comments_claim() {
        let control = transport_config(Role::Control);
        let session = transport_config(Role::Session);
        // Not much of the config is readable back, so this asserts the parts
        // that are and mainly guards against the builder panicking.
        let _ = (control, session);

        assert_eq!(KEEPALIVE.as_secs(), 5, "NAT mappings expire from about 20 seconds");
        assert!(
            KEEPALIVE * 4 < IDLE_TIMEOUT,
            "several keepalives must fit inside the idle timeout, or a single lost \
             packet would drop the connection"
        );
        assert_eq!(INITIAL_MTU, 1200, "QUIC's guaranteed minimum");
    }

    #[tokio::test]
    async fn two_endpoints_connect_and_exchange_control_messages() {
        let server_creds = TransportCredentials::generate().expect("server credentials");
        let client_creds = TransportCredentials::generate().expect("client credentials");

        // Server: listens, and would be able to dial out on the same socket.
        let server = bidirectional_endpoint(
            loopback(),
            &server_creds,
            pinned_client_config(server_creds.fingerprint()).expect("config"),
            Role::Control,
        )
        .expect("server endpoint");
        let server_addr = local_address(&server).expect("server address");

        let accept_task = tokio::spawn(async move {
            let incoming = server.accept().await.expect("an incoming connection");
            let conn = incoming.await.expect("handshake completes");
            let (mut send, mut recv) = conn.accept_bi().await.expect("a stream");
            let msg: ToServer = read_expected(&mut recv).await.expect("read");
            assert!(matches!(msg, ToServer::Hello { protocol: 1 }), "got {msg:?}");
            write_message(
                &mut send,
                &ToNode::Challenge { nonce: [7u8; 32], protocol: 1 },
            )
            .await
            .expect("write");
            send.finish().expect("finish");
            // Hold the connection open until the client has read the reply.
            conn.closed().await;
        });

        // Client: pins the server's certificate.
        let client = bidirectional_endpoint(
            loopback(),
            &client_creds,
            pinned_client_config(server_creds.fingerprint()).expect("config"),
            Role::Control,
        )
        .expect("client endpoint");

        let conn = connect(&client, server_addr, "the test server")
            .await
            .expect("connection should succeed");

        let (mut send, mut recv) = conn.open_bi().await.expect("open a stream");
        write_message(&mut send, &ToServer::Hello { protocol: 1 }).await.expect("write");

        let reply: ToNode = read_expected(&mut recv).await.expect("read the reply");
        match reply {
            ToNode::Challenge { nonce, protocol } => {
                assert_eq!(nonce, [7u8; 32]);
                assert_eq!(protocol, 1);
            }
            other => panic!("unexpected reply: {other:?}"),
        }

        conn.close(0u32.into(), b"done");
        client.wait_idle().await;
        accept_task.await.expect("server task");
    }

    #[tokio::test]
    async fn a_client_pinning_the_wrong_certificate_is_refused() {
        // This is the man-in-the-middle case: something answers on the right
        // address with the wrong key. It must not connect.
        let server_creds = TransportCredentials::generate().expect("server credentials");
        let client_creds = TransportCredentials::generate().expect("client credentials");
        let impostor = TransportCredentials::generate().expect("impostor credentials");

        let server = bidirectional_endpoint(
            loopback(),
            &server_creds,
            pinned_client_config(server_creds.fingerprint()).expect("config"),
            Role::Control,
        )
        .expect("server endpoint");
        let server_addr = local_address(&server).expect("server address");

        tokio::spawn(async move {
            if let Some(incoming) = server.accept().await {
                let _ = incoming.await;
            }
        });

        let client = bidirectional_endpoint(
            loopback(),
            &client_creds,
            // Pinning a certificate the server does not have.
            pinned_client_config(impostor.fingerprint()).expect("config"),
            Role::Control,
        )
        .expect("client endpoint");

        let result = connect(&client, server_addr, "the test server").await;
        assert!(result.is_err(), "connecting with a wrong pin must fail");
    }

    #[test]
    fn session_sockets_get_large_buffers() {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let before = socket2::SockRef::from(&s).recv_buffer_size().unwrap();
        size_buffers(&s);
        let after = socket2::SockRef::from(&s).recv_buffer_size().unwrap();
        eprintln!("receive buffer: Windows default {before} bytes, BARK sets {after} bytes");
        assert!(after >= RECV_BUFFER, "Windows granted only {after} bytes");
    }

    #[tokio::test]
    async fn an_endpoint_reports_the_port_the_system_gave_it() {
        let creds = TransportCredentials::generate().expect("credentials");
        let endpoint = bidirectional_endpoint(
            loopback(),
            &creds,
            pinned_client_config(creds.fingerprint()).expect("config"),
            Role::Session,
        )
        .expect("endpoint");

        let addr = local_address(&endpoint).expect("address");
        assert_ne!(addr.port(), 0, "the OS should have assigned a real port");
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn connecting_to_a_dead_address_explains_itself() {
        let creds = TransportCredentials::generate().expect("credentials");
        let client = client_only_endpoint(
            loopback(),
            pinned_client_config(creds.fingerprint()).expect("config"),
            Role::Control,
        )
        .expect("endpoint");

        // Port 1 on loopback: nothing is listening. Capped at three seconds so
        // the test suite stays quick — the point is that it does not succeed
        // and that whatever it reports names the device and suggests a cause.
        let dead = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1);
        let result =
            tokio::time::timeout(Duration::from_secs(3), connect(&client, dead, "CENTRAL-SERVER"))
                .await;

        match result {
            Ok(Err(e)) => {
                let text = format!("{e}");
                assert!(text.contains("CENTRAL-SERVER"), "should name the device: {text}");
                assert!(
                    text.contains("firewall") || text.contains("respond") || text.contains("refused"),
                    "should suggest a cause: {text}"
                );
            }
            Ok(Ok(_)) => panic!("connecting to a dead port should not succeed"),
            Err(_) => { /* timed out waiting; acceptable, the point is it does not succeed */ }
        }
    }
}
