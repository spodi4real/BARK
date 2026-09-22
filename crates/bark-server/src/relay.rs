//! The relay: forwards a session's UDP datagrams when two devices cannot
//! reach each other directly.
//!
//! It is a packet forwarder and nothing more. The two peers run one QUIC
//! connection end to end *through* it; the relay sees only ciphertext and,
//! because the session handshake is bound to that QUIC connection, cannot
//! terminate it and read what passes (see `bark_net::peer`).
//!
//! ## Who may use it
//!
//! Only two addresses per session, and only after each proved it holds a
//! token the coordination server issued over that device's authenticated
//! control connection. Tokens are issued only for a connection the target
//! device itself has just accepted. Datagrams from any other address are
//! dropped without an answer, so the relay cannot be used as an open proxy
//! or to reach anything behind it.
//!
//! ## One session per peer socket
//!
//! Sessions are told apart purely by sender address, so each peer uses a fresh
//! socket for each relayed session. (Using a device's main socket would make
//! two relayed sessions through the same relay indistinguishable.)
//!
//! ## Limits
//!
//! A cap on concurrent sessions, a per-session rate limit, and expiry of
//! allocations nobody bound and of sessions that fell silent. They exist so a
//! relay on an ordinary office PC cannot be made to eat its whole uplink.

use bark_core::{BarkError, Fingerprint, Result};
use bark_proto::relay;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

/// Resource limits for one relay.
#[derive(Debug, Clone, Copy)]
pub struct RelayLimits {
    pub max_sessions: usize,
    /// Per session, per direction, in bytes per second.
    pub max_bytes_per_sec: u64,
    /// How long an allocation waits for both peers to bind.
    pub bind_timeout: Duration,
    /// How long a bound session may be completely silent. QUIC keepalives
    /// arrive every few seconds on a live session, so silence means it ended.
    pub idle_timeout: Duration,
}

impl Default for RelayLimits {
    fn default() -> Self {
        RelayLimits {
            max_sessions: 32,
            // 60 Mbit/s: comfortably above what one remote-desktop stream
            // needs, well below what would saturate a typical office uplink
            // several times over.
            max_bytes_per_sec: 60_000_000 / 8,
            bind_timeout: Duration::from_secs(30),
            idle_timeout: Duration::from_secs(60),
        }
    }
}

/// Figures for diagnostics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayStats {
    pub sessions: usize,
    pub active: usize,
    pub bytes_forwarded: u64,
    pub packets_dropped: u64,
}

struct Side {
    token: [u8; 16],
    addr: Option<SocketAddr>,
    /// Token bucket for traffic *from* this side.
    allowance: f64,
    refilled: Instant,
}

struct Allocation {
    sides: [Side; 2],
    peers: [Fingerprint; 2],
    created: Instant,
    last_traffic: Instant,
}

impl Allocation {
    fn ready(&self) -> bool {
        self.sides[0].addr.is_some() && self.sides[1].addr.is_some()
    }
}

#[derive(Default)]
struct Table {
    next_id: u64,
    allocations: HashMap<u64, Allocation>,
    by_token: HashMap<[u8; 16], (u64, usize)>,
    by_addr: HashMap<SocketAddr, (u64, usize)>,
    bytes_forwarded: u64,
    packets_dropped: u64,
}

impl Table {
    fn remove(&mut self, id: u64) {
        if let Some(a) = self.allocations.remove(&id) {
            for s in &a.sides {
                self.by_token.remove(&s.token);
                if let Some(addr) = s.addr {
                    self.by_addr.remove(&addr);
                }
            }
        }
    }
}

pub struct Relay {
    socket: Arc<UdpSocket>,
    listening: SocketAddr,
    limits: RelayLimits,
    table: Mutex<Table>,
}

impl std::fmt::Debug for Relay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Relay({})", self.listening)
    }
}

/// What to do with one received datagram, decided under the lock and carried
/// out after it is released.
enum Action {
    Nothing,
    Reply(SocketAddr, [u8; relay::ACK_LEN]),
    /// Ack both peers: the second one has just bound.
    Both([SocketAddr; 2], [u8; relay::ACK_LEN]),
    Forward(SocketAddr),
}

impl Relay {
    pub async fn bind(address: SocketAddr, limits: RelayLimits) -> Result<Arc<Relay>> {
        let socket = UdpSocket::bind(address).await.map_err(|e| {
            BarkError::Network(format!(
                "The relay could not open UDP port {}: {e}\n\n\
                 Another program may be using the port, or the address is not valid on this computer.",
                address.port()
            ))
        })?;
        let listening = socket.local_addr()?;
        // Every relayed session's video passes through this one socket.
        bark_net::endpoint::size_buffers(&socket);
        Ok(Arc::new(Relay { socket: Arc::new(socket), listening, limits, table: Mutex::new(Table::default()) }))
    }

    pub fn listening(&self) -> SocketAddr {
        self.listening
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Table> {
        // Every operation is a handful of map updates; a panic cannot leave a
        // half-applied invariant worth taking the relay down over.
        self.table.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Reserves a session for two devices and returns one token for each:
    /// `(controller_token, remote_token)`.
    pub fn allocate(&self, controller: Fingerprint, remote: Fingerprint) -> Result<([u8; 16], [u8; 16])> {
        let mut t = self.lock();
        if t.allocations.len() >= self.limits.max_sessions {
            return Err(BarkError::network("the relay is at its session limit"));
        }
        let tokens = [random_token()?, random_token()?];
        let now = Instant::now();
        let burst = self.limits.max_bytes_per_sec as f64 / 4.0;
        let side = |token| Side { token, addr: None, allowance: burst, refilled: now };
        let id = t.next_id;
        t.next_id += 1;
        t.allocations.insert(
            id,
            Allocation {
                sides: [side(tokens[0]), side(tokens[1])],
                peers: [controller, remote],
                created: now,
                last_traffic: now,
            },
        );
        t.by_token.insert(tokens[0], (id, 0));
        t.by_token.insert(tokens[1], (id, 1));
        Ok((tokens[0], tokens[1]))
    }

    pub fn stats(&self) -> RelayStats {
        let t = self.lock();
        RelayStats {
            sessions: t.allocations.len(),
            active: t.allocations.values().filter(|a| a.ready()).count(),
            bytes_forwarded: t.bytes_forwarded,
            packets_dropped: t.packets_dropped,
        }
    }

    /// Drops allocations nobody bound and sessions that went silent.
    pub fn expire(&self) -> usize {
        let mut t = self.lock();
        let now = Instant::now();
        let dead: Vec<u64> = t
            .allocations
            .iter()
            .filter(|(_, a)| {
                if a.ready() {
                    now.duration_since(a.last_traffic) > self.limits.idle_timeout
                } else {
                    now.duration_since(a.created) > self.limits.bind_timeout
                }
            })
            .map(|(id, _)| *id)
            .collect();
        for id in &dead {
            if let Some(a) = t.allocations.get(id) {
                tracing::info!(
                    a = %a.peers[0].short_id(),
                    b = %a.peers[1].short_id(),
                    "relay session ended"
                );
            }
            t.remove(*id);
        }
        dead.len()
    }

    fn decide(&self, from: SocketAddr, len: usize, packet: &[u8]) -> Action {
        let mut t = self.lock();
        let now = Instant::now();

        if relay::is_relay_packet(packet) {
            let Ok(token) = relay::decode_bind(packet) else { return Action::Nothing };
            let Some(&(id, side)) = t.by_token.get(&token) else {
                t.packets_dropped += 1;
                return Action::Nothing;
            };
            let a = t.allocations.get_mut(&id).expect("indexes follow allocations");
            match a.sides[side].addr {
                // A repeated bind from the same place: answer again.
                Some(existing) if existing == from => {
                    let ready = a.ready();
                    return Action::Reply(from, relay::encode_ack(ready));
                }
                // The side is already taken by someone else. The token is only
                // ever sent over the owner's authenticated connection, so this
                // is a replay or a stale retry; either way it gets nothing.
                Some(_) => {
                    t.packets_dropped += 1;
                    return Action::Nothing;
                }
                None => {}
            }
            // One address cannot be both ends, or be in two sessions.
            if t.by_addr.contains_key(&from) {
                t.packets_dropped += 1;
                return Action::Nothing;
            }
            let a = t.allocations.get_mut(&id).expect("indexes follow allocations");
            a.sides[side].addr = Some(from);
            let ready = a.ready();
            let both = [a.sides[0].addr, a.sides[1].addr];
            t.by_addr.insert(from, (id, side));
            return if ready {
                Action::Both([both[0].expect("ready"), both[1].expect("ready")], relay::encode_ack(true))
            } else {
                Action::Reply(from, relay::encode_ack(false))
            };
        }

        let Some(&(id, side)) = t.by_addr.get(&from) else {
            // Not part of any session. Silence, not an error reply: the relay
            // must not be usable to probe or reflect traffic.
            t.packets_dropped += 1;
            return Action::Nothing;
        };
        let rate = self.limits.max_bytes_per_sec as f64;
        let a = t.allocations.get_mut(&id).expect("indexes follow allocations");
        let Some(to) = a.sides[1 - side].addr else {
            return Action::Nothing;
        };
        let s = &mut a.sides[side];
        let elapsed = now.duration_since(s.refilled).as_secs_f64();
        // Allow a burst of a quarter second's worth.
        s.allowance = (s.allowance + elapsed * rate).min(rate / 4.0);
        s.refilled = now;
        if s.allowance < len as f64 {
            t.packets_dropped += 1;
            return Action::Nothing;
        }
        s.allowance -= len as f64;
        a.last_traffic = now;
        t.bytes_forwarded += len as u64;
        Action::Forward(to)
    }

    /// Forwards until the task is cancelled.
    pub async fn run(self: Arc<Self>) {
        tracing::info!(listening = %self.listening, "relay forwarding");
        let mut buf = vec![0u8; 65536];
        let mut last_expiry = Instant::now();
        loop {
            let (len, from) = match self.socket.recv_from(&mut buf).await {
                Ok(v) => v,
                // Windows reports an ICMP "port unreachable" for an earlier
                // send as an error on the next receive. It concerns one dead
                // peer, not the relay.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(e) => {
                    tracing::warn!("relay receive failed: {e}");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            match self.decide(from, len, &buf[..len]) {
                Action::Nothing => {}
                Action::Reply(to, ack) => {
                    let _ = self.socket.send_to(&ack, to).await;
                }
                Action::Both(peers, ack) => {
                    for p in peers {
                        let _ = self.socket.send_to(&ack, p).await;
                    }
                }
                Action::Forward(to) => {
                    let _ = self.socket.send_to(&buf[..len], to).await;
                }
            }
            if last_expiry.elapsed() > Duration::from_secs(5) {
                self.expire();
                last_expiry = Instant::now();
            }
        }
    }
}

fn random_token() -> Result<[u8; 16]> {
    let mut t = [0u8; 16];
    getrandom::fill(&mut t).map_err(|e| BarkError::crypto(format!("no secure random source available: {e}")))?;
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn lo() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    async fn peer() -> UdpSocket {
        UdpSocket::bind(lo()).await.unwrap()
    }

    async fn recv(s: &UdpSocket) -> Option<Vec<u8>> {
        let mut buf = [0u8; 2048];
        match tokio::time::timeout(Duration::from_millis(300), s.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) => Some(buf[..n].to_vec()),
            _ => None,
        }
    }

    async fn relay(limits: RelayLimits) -> (Arc<Relay>, tokio::task::JoinHandle<()>) {
        let r = Relay::bind(lo(), limits).await.unwrap();
        let task = tokio::spawn(r.clone().run());
        (r, task)
    }

    fn fp(n: u8) -> Fingerprint {
        Fingerprint([n; 32])
    }

    #[tokio::test]
    async fn two_bound_peers_can_talk_through_the_relay() {
        let (r, _task) = relay(RelayLimits::default()).await;
        let (ta, tb) = r.allocate(fp(1), fp(2)).unwrap();
        let (a, b) = (peer().await, peer().await);
        let at = r.listening();

        a.send_to(&relay::encode_bind(&ta), at).await.unwrap();
        assert_eq!(relay::decode_ack(&recv(&a).await.unwrap()), Some(false), "alone: not ready");
        b.send_to(&relay::encode_bind(&tb), at).await.unwrap();
        assert_eq!(relay::decode_ack(&recv(&b).await.unwrap()), Some(true));
        assert_eq!(relay::decode_ack(&recv(&a).await.unwrap()), Some(true), "first peer told too");

        a.send_to(b"hello from a", at).await.unwrap();
        assert_eq!(recv(&b).await.unwrap(), b"hello from a");
        b.send_to(b"hello from b", at).await.unwrap();
        assert_eq!(recv(&a).await.unwrap(), b"hello from b");
        assert_eq!(r.stats().active, 1);
    }

    #[tokio::test]
    async fn strangers_get_nothing_forwarded_and_no_reply() {
        let (r, _task) = relay(RelayLimits::default()).await;
        let (ta, tb) = r.allocate(fp(1), fp(2)).unwrap();
        let (a, b, stranger) = (peer().await, peer().await, peer().await);
        let at = r.listening();
        a.send_to(&relay::encode_bind(&ta), at).await.unwrap();
        recv(&a).await;
        b.send_to(&relay::encode_bind(&tb), at).await.unwrap();
        recv(&b).await;
        recv(&a).await;

        stranger.send_to(b"let me in", at).await.unwrap();
        stranger.send_to(&relay::encode_bind(&[9u8; 16]), at).await.unwrap();
        assert!(recv(&stranger).await.is_none(), "no answer to strangers");
        assert!(recv(&a).await.is_none(), "nothing forwarded to A");
        assert!(recv(&b).await.is_none(), "nothing forwarded to B");
    }

    #[tokio::test]
    async fn a_token_already_bound_cannot_be_taken_over() {
        let (r, _task) = relay(RelayLimits::default()).await;
        let (ta, _tb) = r.allocate(fp(1), fp(2)).unwrap();
        let (a, thief) = (peer().await, peer().await);
        a.send_to(&relay::encode_bind(&ta), r.listening()).await.unwrap();
        recv(&a).await;
        thief.send_to(&relay::encode_bind(&ta), r.listening()).await.unwrap();
        assert!(recv(&thief).await.is_none(), "the second claimant is ignored");
    }

    #[tokio::test]
    async fn the_session_limit_is_enforced() {
        let (r, _task) = relay(RelayLimits { max_sessions: 2, ..Default::default() }).await;
        r.allocate(fp(1), fp(2)).unwrap();
        r.allocate(fp(3), fp(4)).unwrap();
        assert!(r.allocate(fp(5), fp(6)).is_err());
    }

    #[tokio::test]
    async fn unbound_allocations_expire() {
        let (r, _task) =
            relay(RelayLimits { bind_timeout: Duration::from_millis(50), ..Default::default() }).await;
        r.allocate(fp(1), fp(2)).unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(r.expire(), 1);
        assert_eq!(r.stats().sessions, 0);
    }

    #[tokio::test]
    async fn the_rate_limit_drops_excess_traffic() {
        // 10 kB/s with a quarter-second burst allowance: about 2.5 kB passes,
        // then the rest of a sudden 20 kB burst is dropped.
        let (r, _task) = relay(RelayLimits { max_bytes_per_sec: 10_000, ..Default::default() }).await;
        let (ta, tb) = r.allocate(fp(1), fp(2)).unwrap();
        let (a, b) = (peer().await, peer().await);
        let at = r.listening();
        a.send_to(&relay::encode_bind(&ta), at).await.unwrap();
        recv(&a).await;
        b.send_to(&relay::encode_bind(&tb), at).await.unwrap();
        recv(&b).await;
        recv(&a).await;

        for _ in 0..20 {
            a.send_to(&[0x41u8; 1000], at).await.unwrap();
        }
        let mut got = 0;
        while recv(&b).await.is_some() {
            got += 1;
        }
        assert!(got <= 3, "forwarded {got} of 20 packets; the limit allows about 2");
        assert!(r.stats().packets_dropped >= 17);
    }
}
