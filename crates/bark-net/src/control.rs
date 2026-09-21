//! The node's connection to the coordination server.
//!
//! One QUIC connection, one bidirectional stream, held open for as long as the
//! node is running. Keeping it open rather than reconnecting per request is
//! what makes presence instant — a device is online exactly while this
//! connection lives — and it is also what holds the NAT mapping open so peers
//! can reach it without any port forwarding.
//!
//! The connection is split in two the moment it is authenticated: a task
//! reading pushed messages from the server into an event queue, and a task
//! writing queued requests out. The caller then talks to it with ordinary
//! channels and never has to think about streams.

use bark_core::{BarkError, Fingerprint, Result};
use bark_crypto::identity::context;
use bark_crypto::{DeviceIdentity, PublicIdentity};
use bark_core::machine::MachineInfo;
use bark_proto::control::{FailureReason, ToNode, ToServer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::endpoint::connect;
use crate::framing::{read_message, write_message};

/// How many requests may be queued before the caller has to wait.
const REQUEST_QUEUE: usize = 64;
/// How many pushed messages may queue before the connection is considered
/// wedged. Presence updates and offers are small and infrequent; a backlog this
/// deep means nobody is reading.
const EVENT_QUEUE: usize = 256;

/// How long to wait for the server to complete the login exchange.
pub const LOGIN_TIMEOUT_SECS: u64 = 15;

/// What the server told us when we logged in.
#[derive(Debug, Clone)]
pub struct ServerGreeting {
    /// The address the server saw us from — our NAT mapping, and the address a
    /// peer will aim hole-punch probes at. We cannot determine this ourselves;
    /// only something outside the NAT can observe it.
    pub our_public_address: SocketAddr,
    /// The server's monotonic clock when it answered, for offset calibration.
    pub server_time_us: u64,
    pub server_version: String,
    /// Our own monotonic clock either side of the login, so the caller can
    /// bound the error on the server clock offset.
    pub sent_us: u64,
    pub received_us: u64,
}

/// A live, authenticated connection to the coordination server.
pub struct ControlConnection {
    greeting: ServerGreeting,
    requests: mpsc::Sender<ToServer>,
    events: mpsc::Receiver<ToNode>,
    connection: quinn::Connection,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

impl std::fmt::Debug for ControlConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ControlConnection(server={})", self.connection.remote_address())
    }
}

impl ControlConnection {
    /// Logs in to the coordination server.
    ///
    /// `server_cert_fingerprint` must be the same value the endpoint pinned.
    /// It is folded into what we sign, which binds our proof of identity to
    /// this specific server — so a hostile server cannot take our signature and
    /// present it to the real one.
    pub async fn login(
        endpoint: &quinn::Endpoint,
        server_address: SocketAddr,
        server_cert_fingerprint: [u8; 32],
        identity: &DeviceIdentity,
        machine: MachineInfo,
        local_candidates: Vec<SocketAddr>,
    ) -> Result<Self> {
        let sent_us = bark_core::clock::now_us();

        let connection = connect(endpoint, server_address, "the BARK server").await?;
        let (mut send, mut recv) = connection.open_bi().await.map_err(|e| {
            BarkError::Network(format!("could not open a control stream to the server: {e}"))
        })?;

        let deadline = std::time::Duration::from_secs(LOGIN_TIMEOUT_SECS);

        write_message(&mut send, &ToServer::Hello { protocol: bark_core::PROTOCOL_VERSION })
            .await?;

        let challenge: ToNode = tokio::time::timeout(deadline, read_message(&mut recv))
            .await
            .map_err(|_| BarkError::Timeout(LOGIN_TIMEOUT_SECS * 1000))??
            .ok_or_else(|| {
                BarkError::Network("the BARK server closed the connection without replying".into())
            })?;

        let nonce = match challenge {
            ToNode::Challenge { nonce, protocol } => {
                if protocol != bark_core::PROTOCOL_VERSION {
                    return Err(BarkError::Protocol(format!(
                        "The BARK server speaks protocol {protocol}; this computer speaks {}. \
                         Update BARK so both are the same version.",
                        bark_core::PROTOCOL_VERSION
                    )));
                }
                nonce
            }
            ToNode::Rejected { reason, detail } => return Err(rejected(reason, &detail)),
            other => {
                return Err(BarkError::protocol(format!(
                    "the BARK server sent an unexpected reply: {other:?}"
                )))
            }
        };

        let signed = challenge_payload(&nonce, &server_cert_fingerprint);
        let signature = identity.sign(context::SERVER_AUTH, &signed);

        write_message(
            &mut send,
            &ToServer::Authenticate {
                identity: identity.public(),
                signature: signature.into(),
                machine,
                local_candidates,
            },
        )
        .await?;

        let welcome: ToNode = tokio::time::timeout(deadline, read_message(&mut recv))
            .await
            .map_err(|_| BarkError::Timeout(LOGIN_TIMEOUT_SECS * 1000))??
            .ok_or_else(|| {
                BarkError::Network(
                    "the BARK server closed the connection during sign-in".into(),
                )
            })?;

        let received_us = bark_core::clock::now_us();

        let greeting = match welcome {
            ToNode::Welcome { your_address, server_time_us, server_version } => ServerGreeting {
                our_public_address: your_address,
                server_time_us,
                server_version,
                sent_us,
                received_us,
            },
            ToNode::Rejected { reason, detail } => return Err(rejected(reason, &detail)),
            other => {
                return Err(BarkError::protocol(format!(
                    "the BARK server sent an unexpected reply: {other:?}"
                )))
            }
        };

        // From here the stream is pumped by two tasks and the caller uses
        // channels.
        let (request_tx, mut request_rx) = mpsc::channel::<ToServer>(REQUEST_QUEUE);
        let (event_tx, event_rx) = mpsc::channel::<ToNode>(EVENT_QUEUE);

        let writer = tokio::spawn(async move {
            while let Some(msg) = request_rx.recv().await {
                if write_message(&mut send, &msg).await.is_err() {
                    break;
                }
            }
        });

        let reader = tokio::spawn(async move {
            // Ends on a clean close or a read error; either way the connection
            // is finished and the caller sees the event queue end.
            while let Ok(Some(msg)) = read_message::<ToNode>(&mut recv).await {
                if event_tx.send(msg).await.is_err() {
                    break;
                }
            }
        });

        Ok(ControlConnection { greeting, requests: request_tx, events: event_rx, connection, reader, writer })
    }

    pub fn greeting(&self) -> &ServerGreeting {
        &self.greeting
    }

    /// Our address as the server sees it.
    pub fn public_address(&self) -> SocketAddr {
        self.greeting.our_public_address
    }

    /// Sends a request. Waits only if the outgoing queue is full.
    pub async fn send(&self, msg: ToServer) -> Result<()> {
        self.requests.send(msg).await.map_err(|_| {
            BarkError::Network("the connection to the BARK server has closed".into())
        })
    }

    /// Waits for the next message pushed by the server.
    ///
    /// Returns `None` when the connection has ended.
    pub async fn next_event(&mut self) -> Option<ToNode> {
        self.events.recv().await
    }

    /// Takes whatever has already arrived, without waiting.
    pub fn try_next_event(&mut self) -> Option<ToNode> {
        self.events.try_recv().ok()
    }

    /// Measures the round trip to the server and feeds the clock offset.
    ///
    /// Sends a ping and waits for its pong, discarding anything else that
    /// arrives meanwhile — those are pushed messages that will be delivered
    /// again by `next_event` only if the caller re-queues them, so this is
    /// intended for diagnostics rather than for use alongside a live event
    /// loop.
    pub async fn ping(&mut self) -> Result<(u64, u64)> {
        let sent = bark_core::clock::now_us();
        self.send(ToServer::Ping { sent_us: sent }).await?;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(BarkError::Timeout(10_000));
            }
            match tokio::time::timeout(remaining, self.events.recv()).await {
                Ok(Some(ToNode::Pong { sent_us, server_time_us })) if sent_us == sent => {
                    return Ok((bark_core::clock::now_us() - sent, server_time_us));
                }
                Ok(Some(_)) => continue,
                Ok(None) => {
                    return Err(BarkError::Network(
                        "the connection to the BARK server has closed".into(),
                    ))
                }
                Err(_) => return Err(BarkError::Timeout(10_000)),
            }
        }
    }

    /// True while the underlying QUIC connection is alive.
    pub fn is_connected(&self) -> bool {
        self.connection.close_reason().is_none()
    }

    /// Says goodbye so the server marks us offline immediately rather than
    /// waiting for a timeout.
    pub async fn close(self) {
        let _ = self.requests.send(ToServer::Goodbye).await;
        // Give the writer a moment to flush before tearing the connection down.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        self.connection.close(0u32.into(), b"goodbye");
        self.reader.abort();
        self.writer.abort();
    }
}

impl Drop for ControlConnection {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// The bytes a node signs to prove its identity to a particular server.
///
/// Must match the server's own construction exactly; see
/// `bark_server::session::challenge_payload`.
pub fn challenge_payload(nonce: &[u8; 32], server_cert_fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(nonce);
    v.extend_from_slice(server_cert_fingerprint);
    v
}

fn rejected(reason: FailureReason, detail: &str) -> BarkError {
    let text = if detail.is_empty() { reason.message().to_string() } else { detail.to_string() };
    match reason {
        FailureReason::Revoked => BarkError::Revoked(text),
        FailureReason::NotPaired => BarkError::NotTrusted(text),
        FailureReason::VersionMismatch => BarkError::Protocol(text),
        _ => BarkError::Network(text),
    }
}

/// A device this node is watching, as the favourites list sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct PresenceEntry {
    pub device: Fingerprint,
    pub online: bool,
    pub last_seen_unix_us: u64,
}

/// Keeps track of which watched devices are online.
///
/// Fed from the server's pushed `Presence` messages. Separated from the
/// connection so the user interface can own it and survive a reconnection
/// without losing what it knew.
#[derive(Debug, Default)]
pub struct PresenceTable {
    entries: std::collections::HashMap<Fingerprint, PresenceEntry>,
}

impl PresenceTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Applies a pushed message. Returns true if it was a presence update.
    pub fn apply(&mut self, msg: &ToNode) -> bool {
        match msg {
            ToNode::Presence { device, online, last_seen_unix_us, .. } => {
                self.entries.insert(
                    *device,
                    PresenceEntry {
                        device: *device,
                        online: *online,
                        last_seen_unix_us: *last_seen_unix_us,
                    },
                );
                true
            }
            _ => false,
        }
    }

    pub fn is_online(&self, device: &Fingerprint) -> bool {
        self.entries.get(device).map(|e| e.online).unwrap_or(false)
    }

    pub fn get(&self, device: &Fingerprint) -> Option<&PresenceEntry> {
        self.entries.get(device)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Everything is unknown again after a reconnection, because presence the
    /// server told us before the disconnection may no longer be true.
    pub fn invalidate(&mut self) {
        for e in self.entries.values_mut() {
            e.online = false;
        }
    }
}

/// Identity of a peer, resolved from the short Device ID an operator typed.
pub fn resolved_identity(msg: &ToNode) -> Option<(bark_core::DeviceId, Option<PublicIdentity>)> {
    match msg {
        ToNode::Resolved { device_id, identity } => Some((*device_id, *identity)),
        _ => None,
    }
}

/// Convenience for sharing one connection between tasks.
pub type SharedControl = Arc<tokio::sync::Mutex<ControlConnection>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_payload_matches_what_the_server_builds() {
        // Both sides construct this independently; if they ever drift, every
        // login fails with a confusing signature error. This pins the format.
        let nonce = [0x11u8; 32];
        let cert = [0x22u8; 32];
        let p = challenge_payload(&nonce, &cert);

        assert_eq!(p.len(), 64);
        assert_eq!(&p[..32], &nonce[..], "the nonce comes first");
        assert_eq!(&p[32..], &cert[..], "the server fingerprint comes second");
    }

    #[test]
    fn presence_starts_unknown_and_follows_updates() {
        let mut t = PresenceTable::new();
        let d = bark_crypto::DeviceIdentity::generate().unwrap().public().fingerprint();

        assert!(!t.is_online(&d), "an unheard-of device is not online");
        assert!(t.is_empty());

        assert!(t.apply(&ToNode::Presence {
            device: d,
            online: true,
            last_seen_unix_us: 1234,
            machine: None,
        }));
        assert!(t.is_online(&d));
        assert_eq!(t.get(&d).unwrap().last_seen_unix_us, 1234);

        t.apply(&ToNode::Presence {
            device: d,
            online: false,
            last_seen_unix_us: 5678,
            machine: None,
        });
        assert!(!t.is_online(&d));
        assert_eq!(t.len(), 1, "the device is still known, just offline");
    }

    #[test]
    fn unrelated_messages_are_not_presence_updates() {
        let mut t = PresenceTable::new();
        assert!(!t.apply(&ToNode::Pong { sent_us: 1, server_time_us: 2 }));
        assert!(t.is_empty());
    }

    #[test]
    fn reconnecting_invalidates_what_we_thought_we_knew() {
        // After a disconnection the server's last word about who was online is
        // stale. Showing a device as ONLINE when we have no idea is worse than
        // showing it as offline until the server says otherwise.
        let mut t = PresenceTable::new();
        let d = bark_crypto::DeviceIdentity::generate().unwrap().public().fingerprint();
        t.apply(&ToNode::Presence {
            device: d,
            online: true,
            last_seen_unix_us: 1,
            machine: None,
        });
        assert!(t.is_online(&d));

        t.invalidate();
        assert!(!t.is_online(&d));
        assert_eq!(t.len(), 1, "the device is still in the list");
    }

    #[test]
    fn a_rejection_becomes_the_right_kind_of_error() {
        assert!(matches!(rejected(FailureReason::Revoked, "gone"), BarkError::Revoked(_)));
        assert!(matches!(rejected(FailureReason::NotPaired, ""), BarkError::NotTrusted(_)));
        assert!(matches!(
            rejected(FailureReason::VersionMismatch, "old"),
            BarkError::Protocol(_)
        ));

        // An empty detail falls back to the standard sentence for that reason.
        let e = rejected(FailureReason::DeviceOffline, "");
        assert_eq!(format!("{e}"), FailureReason::DeviceOffline.message());
    }

    #[test]
    fn resolved_identity_reads_only_resolution_replies() {
        let id = bark_crypto::DeviceIdentity::generate().unwrap().public();
        let msg = ToNode::Resolved { device_id: id.device_id(), identity: Some(id) };
        let (did, found) = resolved_identity(&msg).expect("should read it");
        assert_eq!(did, id.device_id());
        assert_eq!(found, Some(id));

        assert!(resolved_identity(&ToNode::Pong { sent_us: 0, server_time_us: 0 }).is_none());
    }
}
