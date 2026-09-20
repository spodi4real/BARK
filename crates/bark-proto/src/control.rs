//! Messages between a BARK node and the coordination server.
//!
//! This channel is one long-lived QUIC stream that stays open for as long as
//! the node is running. Keeping it open, rather than reconnecting per request,
//! is what makes presence instant and what holds the NAT mapping open so peers
//! can reach each other without port forwarding.
//!
//! The server's role is deliberately small. It introduces devices to each other
//! and forwards opaque bytes when a direct path cannot be found. It never holds
//! session keys, never sees screen data, and cannot authorise itself onto a
//! device — authorisation lives in each device's own trust store.

use bark_crypto::{PublicIdentity, Signature64};
use bark_core::machine::MachineInfo;
use bark_core::Fingerprint;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// One address a peer might be reachable at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub addr: SocketAddr,
    pub kind: CandidateKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CandidateKind {
    /// An address on a network interface of the device itself. Tried first and
    /// given a head start: two machines in the same office should talk over the
    /// LAN and never leave the building.
    Local,
    /// The public address the server saw the device's packets arrive from —
    /// that is, its NAT mapping. This is what hole punching aims at.
    ServerReflexive,
    /// The server's relay. Always works, always costs an extra hop.
    Relay,
}

impl Candidate {
    /// Ordering used when probing. Lower is tried first.
    ///
    /// Local addresses come first because a LAN path is dramatically better
    /// than anything else and costs nothing to try. IPv6 is preferred over IPv4
    /// within each class because an IPv6 path usually avoids NAT entirely.
    pub fn priority(&self) -> u32 {
        let class = match self.kind {
            CandidateKind::Local => 0,
            CandidateKind::ServerReflexive => 100,
            CandidateKind::Relay => 200,
        };
        let family = u32::from(self.addr.is_ipv4());
        class + family
    }
}

/// Why a connection attempt or a request failed. Each maps to a specific,
/// actionable message in the user interface rather than a generic failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailureReason {
    /// No device with that identifier is registered with the server.
    UnknownDevice,
    /// The device exists but is not currently connected.
    DeviceOffline,
    /// The target's trust store does not contain the requester.
    NotPaired,
    /// Trust existed and was revoked.
    Revoked,
    /// The target refused the request.
    Refused,
    /// The target did not answer in time.
    NoAnswer,
    /// Too many attempts; try later.
    RateLimited,
    /// The two devices speak different protocol versions.
    VersionMismatch,
    /// The server is unable to relay right now.
    RelayUnavailable,
    /// The pairing code did not match.
    BadPairingCode,
    /// The request was malformed or made out of order.
    BadRequest,
    /// Something went wrong on the server.
    ServerError,
}

impl FailureReason {
    /// The sentence shown to the operator.
    pub fn message(self) -> &'static str {
        match self {
            FailureReason::UnknownDevice => {
                "No device with that ID is registered with the BARK server."
            }
            FailureReason::DeviceOffline => "The remote computer is not connected right now.",
            FailureReason::NotPaired => {
                "This computer is not paired with the remote computer. Pair them once first."
            }
            FailureReason::Revoked => {
                "Access to the remote computer was revoked by an administrator."
            }
            FailureReason::Refused => "The remote computer refused the connection.",
            FailureReason::NoAnswer => "The remote computer did not respond.",
            FailureReason::RateLimited => "Too many attempts. Wait a moment and try again.",
            FailureReason::VersionMismatch => {
                "The two computers are running different versions of BARK. Update both."
            }
            FailureReason::RelayUnavailable => {
                "A direct connection could not be made and the BARK server could not relay."
            }
            FailureReason::BadPairingCode => "The pairing code was not correct.",
            FailureReason::BadRequest => "The request was not understood by the BARK server.",
            FailureReason::ServerError => "The BARK server reported an internal problem.",
        }
    }

    /// Whether retrying the same thing might work. Drives whether the error
    /// dialog offers a Retry button.
    pub fn worth_retrying(self) -> bool {
        matches!(
            self,
            FailureReason::DeviceOffline
                | FailureReason::NoAnswer
                | FailureReason::RelayUnavailable
                | FailureReason::ServerError
                | FailureReason::RateLimited
        )
    }
}

/// Node to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToServer {
    /// First message on a fresh connection. The server replies with a
    /// challenge; nothing else is accepted until authentication completes.
    Hello { protocol: u16 },

    /// Answer to the server's challenge, proving possession of the private key
    /// for `identity`.
    Authenticate {
        identity: PublicIdentity,
        /// Signature over the server's challenge, in the `SERVER_AUTH` context.
        signature: Signature64,
        machine: MachineInfo,
        /// Addresses this device believes it has, for hole punching.
        local_candidates: Vec<SocketAddr>,
    },

    /// Keeps the connection and the NAT mapping alive, and measures round-trip
    /// time to the server for the diagnostics page.
    Ping { sent_us: u64 },

    /// Asks to be told when these devices come and go.
    WatchPresence { devices: Vec<Fingerprint> },

    /// Looks up a device by the short handle an operator typed.
    Resolve { device_id: bark_core::DeviceId },

    /// Asks the server to introduce us to a peer.
    ConnectRequest {
        target: Fingerprint,
        /// Correlates the offer, the answer and the relay allocation.
        request_id: u64,
        candidates: Vec<Candidate>,
    },

    /// Answer to a `ConnectOffer` pushed by the server.
    ConnectAnswer {
        request_id: u64,
        accept: bool,
        reason: Option<FailureReason>,
        candidates: Vec<Candidate>,
    },

    /// Asks the server to forward a pairing request to a device we are not yet
    /// trusted by. The server never learns the pairing code.
    PairRequest {
        target: Fingerprint,
        request_id: u64,
        /// Hash of the code plus a nonce. Only the target can check it.
        code_nonce: [u8; 16],
        code_digest: [u8; 32],
        /// Name we would like to be known by on the target.
        our_name: String,
        machine: MachineInfo,
    },

    /// The target's verdict on a pairing request.
    PairAnswer {
        request_id: u64,
        accept: bool,
        reason: Option<FailureReason>,
        /// Sent on success so the requester can record the target.
        machine: Option<MachineInfo>,
        name: Option<String>,
    },

    /// Asks for a relay allocation because hole punching failed.
    RelayRequest { request_id: u64 },

    /// Tells the server this device no longer trusts a peer, so the server can
    /// refuse to signal for it rather than wasting a round trip.
    Revoke {
        peer: Fingerprint,
        signature: Signature64,
    },

    /// Graceful shutdown notice, so the server marks us offline immediately
    /// rather than after a timeout.
    Goodbye,
}

/// Server to node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ToNode {
    /// Random bytes to sign. New every connection, so a captured signature
    /// cannot be replayed.
    Challenge { nonce: [u8; 32], protocol: u16 },

    /// Authentication succeeded.
    Welcome {
        /// The address the server saw us from — our NAT mapping.
        your_address: SocketAddr,
        /// Server's monotonic clock, for offset calibration.
        server_time_us: u64,
        server_version: String,
    },

    /// Authentication failed, with a reason the operator can act on.
    Rejected { reason: FailureReason, detail: String },

    Pong { sent_us: u64, server_time_us: u64 },

    /// A watched device changed state.
    Presence {
        device: Fingerprint,
        online: bool,
        last_seen_unix_us: u64,
        /// Present when the device is online and has published it.
        machine: Option<MachineInfo>,
    },

    Resolved {
        device_id: bark_core::DeviceId,
        /// `None` when no such device is registered.
        identity: Option<PublicIdentity>,
    },

    /// Someone wants to connect to us. Pushed without being asked for.
    ConnectOffer {
        from: PublicIdentity,
        request_id: u64,
        candidates: Vec<Candidate>,
        machine: MachineInfo,
    },

    /// The outcome of our own `ConnectRequest`.
    ConnectResult {
        request_id: u64,
        accepted: bool,
        reason: Option<FailureReason>,
        /// The peer's candidates, to punch towards.
        candidates: Vec<Candidate>,
        /// The peer's identity, so the handshake can verify it answered.
        peer: Option<PublicIdentity>,
    },

    /// Someone wants to pair with us.
    PairOffer {
        from: PublicIdentity,
        request_id: u64,
        code_nonce: [u8; 16],
        code_digest: [u8; 32],
        their_name: String,
        machine: MachineInfo,
    },

    /// The outcome of our own `PairRequest`.
    PairResult {
        request_id: u64,
        accepted: bool,
        reason: Option<FailureReason>,
        peer: Option<PublicIdentity>,
        machine: Option<MachineInfo>,
        name: Option<String>,
    },

    /// A relay path is ready. Both peers send their session traffic to the
    /// server's relay address tagged with this token, and the server forwards
    /// it. The bytes are already end-to-end encrypted.
    RelayReady {
        request_id: u64,
        relay_address: SocketAddr,
        /// Opaque, single-use, unguessable.
        token: [u8; 16],
    },

    /// Something went wrong that was not tied to one request.
    Error { reason: FailureReason, detail: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{decode_framed, encode_framed};
    use bark_crypto::DeviceIdentity;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), port)
    }

    #[test]
    fn local_candidates_are_tried_before_reflexive_before_relay() {
        let local = Candidate { addr: addr(1), kind: CandidateKind::Local };
        let srflx = Candidate { addr: addr(2), kind: CandidateKind::ServerReflexive };
        let relay = Candidate { addr: addr(3), kind: CandidateKind::Relay };
        assert!(local.priority() < srflx.priority());
        assert!(srflx.priority() < relay.priority());
    }

    #[test]
    fn ipv6_is_preferred_within_a_class() {
        let v4 = Candidate { addr: addr(1), kind: CandidateKind::Local };
        let v6 = Candidate {
            addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1),
            kind: CandidateKind::Local,
        };
        assert!(v6.priority() < v4.priority(), "IPv6 should be tried first");
    }

    #[test]
    fn candidate_sorting_produces_a_sensible_probe_order() {
        let mut cands = [
            Candidate { addr: addr(3), kind: CandidateKind::Relay },
            Candidate { addr: addr(2), kind: CandidateKind::ServerReflexive },
            Candidate { addr: addr(1), kind: CandidateKind::Local },
        ];
        cands.sort_by_key(|c| c.priority());
        assert_eq!(cands[0].kind, CandidateKind::Local);
        assert_eq!(cands[1].kind, CandidateKind::ServerReflexive);
        assert_eq!(cands[2].kind, CandidateKind::Relay);
    }

    #[test]
    fn every_failure_reason_has_a_usable_message() {
        let all = [
            FailureReason::UnknownDevice,
            FailureReason::DeviceOffline,
            FailureReason::NotPaired,
            FailureReason::Revoked,
            FailureReason::Refused,
            FailureReason::NoAnswer,
            FailureReason::RateLimited,
            FailureReason::VersionMismatch,
            FailureReason::RelayUnavailable,
            FailureReason::BadPairingCode,
            FailureReason::BadRequest,
            FailureReason::ServerError,
        ];
        for r in all {
            let m = r.message();
            assert!(m.len() > 15, "{r:?} has a uselessly short message: {m}");
            assert!(m.ends_with('.'), "{r:?} message should be a sentence: {m}");
            assert!(
                !m.to_lowercase().contains("error code"),
                "{r:?} message should be plain English, got {m}"
            );
        }
    }

    #[test]
    fn transient_failures_offer_a_retry_and_permanent_ones_do_not() {
        assert!(FailureReason::DeviceOffline.worth_retrying());
        assert!(FailureReason::NoAnswer.worth_retrying());
        assert!(!FailureReason::NotPaired.worth_retrying());
        assert!(!FailureReason::Revoked.worth_retrying());
        assert!(!FailureReason::BadPairingCode.worth_retrying());
    }

    #[test]
    fn node_messages_round_trip_over_the_wire() {
        let id = DeviceIdentity::generate().unwrap();
        let msgs = vec![
            ToServer::Hello { protocol: 1 },
            ToServer::Authenticate {
                identity: id.public(),
                signature: Signature64([7u8; 64]),
                machine: MachineInfo::collect(),
                local_candidates: vec![addr(5000), addr(5001)],
            },
            ToServer::Ping { sent_us: 123456 },
            ToServer::ConnectRequest {
                target: id.public().fingerprint(),
                request_id: 99,
                candidates: vec![Candidate { addr: addr(1), kind: CandidateKind::Local }],
            },
            ToServer::Goodbye,
        ];

        for m in msgs {
            let bytes = encode_framed(&m).unwrap();
            let (back, used): (ToServer, usize) = decode_framed(&bytes).unwrap().unwrap();
            assert_eq!(used, bytes.len());
            // Compare the debug rendering; these types carry no PartialEq and
            // do not need one outside tests.
            assert_eq!(format!("{back:?}"), format!("{m:?}"));
        }
    }

    #[test]
    fn server_messages_round_trip_over_the_wire() {
        let id = DeviceIdentity::generate().unwrap();
        let msgs = vec![
            ToNode::Challenge { nonce: [3u8; 32], protocol: 1 },
            ToNode::Welcome {
                your_address: addr(41234),
                server_time_us: 999,
                server_version: "0.1.0".into(),
            },
            ToNode::Rejected {
                reason: FailureReason::NotPaired,
                detail: "not in trust store".into(),
            },
            ToNode::ConnectOffer {
                from: id.public(),
                request_id: 5,
                candidates: vec![Candidate { addr: addr(2), kind: CandidateKind::ServerReflexive }],
                machine: MachineInfo::collect(),
            },
            ToNode::RelayReady {
                request_id: 5,
                relay_address: addr(57411),
                token: [9u8; 16],
            },
        ];

        for m in msgs {
            let bytes = encode_framed(&m).unwrap();
            let (back, _): (ToNode, usize) = decode_framed(&bytes).unwrap().unwrap();
            assert_eq!(format!("{back:?}"), format!("{m:?}"));
        }
    }

    #[test]
    fn a_control_message_is_small_enough_to_be_cheap() {
        let m = ToServer::Ping { sent_us: u64::MAX };
        let bytes = encode_framed(&m).unwrap();
        assert!(bytes.len() < 32, "a ping encoded to {} bytes", bytes.len());
    }
}
