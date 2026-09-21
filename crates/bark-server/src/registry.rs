//! Who is online right now, and routing between them.
//!
//! Everything here is in memory and dies with the process, deliberately.
//! Presence written to disk is presence that survives a crash and lies about
//! it; a device is online exactly when it has a live connection to this server,
//! and that fact has nowhere to be but memory.
//!
//! ## Why request identifiers are rewritten
//!
//! When device A asks to be introduced to device B, A chooses the request
//! identifier. If the server passed that identifier straight through to B, two
//! problems follow. Two different requesters could pick the same number for the
//! same target, and the server would not know whose answer it had. Worse, a
//! device could answer an exchange it was never part of by guessing a number.
//!
//! So the server issues its own identifier for the target-facing half and keeps
//! the mapping. An answer is only accepted from the device the offer was
//! actually sent to, and it is routed back using the requester's own original
//! number. Neither side can reach into anyone else's exchange.

use bark_core::{Fingerprint, Result};
use bark_crypto::{AttemptLimiter, PublicIdentity};
use bark_proto::control::{FailureReason, ToNode};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use tokio::sync::mpsc;

/// How many messages may queue for one node before the server gives up on it.
///
/// A node that cannot keep up with a trickle of control messages is wedged.
/// Blocking the server to wait for it would let one bad node stall everyone, so
/// the queue is bounded and overflow disconnects that node alone.
pub const OUTBOX_DEPTH: usize = 64;

/// How long an unanswered introduction is kept before being discarded.
///
/// Generous next to the couple of seconds an answer actually takes; short
/// enough that abandoned exchanges cannot accumulate.
pub const EXCHANGE_TIMEOUT_US: u64 = 30 * 1_000_000;

/// A live, authenticated connection to a node.
#[derive(Debug, Clone)]
pub struct NodeHandle {
    pub identity: PublicIdentity,
    /// The address the server sees this node from — its NAT mapping, and what
    /// peers will aim hole-punch probes at.
    pub address: SocketAddr,
    pub connected_unix_us: u64,
    outbox: mpsc::Sender<ToNode>,
}

impl NodeHandle {
    pub fn fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// Queues a message for this node.
    ///
    /// Never blocks. A full queue means the node is not reading, which is
    /// reported so the caller can drop the connection.
    pub fn try_send(&self, msg: ToNode) -> std::result::Result<(), SendError> {
        self.outbox.try_send(msg).map_err(|e| match e {
            mpsc::error::TrySendError::Full(_) => SendError::Backlogged,
            mpsc::error::TrySendError::Closed(_) => SendError::Gone,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The node has stopped reading its messages.
    Backlogged,
    /// The connection has already gone away.
    Gone,
}

/// An introduction the server is waiting on an answer for.
#[derive(Debug, Clone)]
struct Exchange {
    requester: Fingerprint,
    /// The identifier the requester used, which its answer must come back with.
    requester_request_id: u64,
    target: Fingerprint,
    kind: ExchangeKind,
    opened_unix_us: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeKind {
    Connect,
    Pair,
}

/// Where an answer should be routed, once it has been checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerRoute {
    pub requester: Fingerprint,
    pub requester_request_id: u64,
    pub kind: ExchangeKind,
}

/// Why an answer was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerError {
    /// No such exchange, or it expired.
    Unknown,
    /// The answer came from a device the offer was not sent to.
    WrongDevice,
}

#[derive(Debug, Default)]
struct State {
    online: HashMap<Fingerprint, NodeHandle>,
    /// watcher -> the devices it wants presence updates about.
    watching: HashMap<Fingerprint, Vec<Fingerprint>>,
    /// Server-issued exchange id -> the exchange.
    exchanges: HashMap<u64, Exchange>,
}

/// Presence and routing for all connected nodes.
pub struct Registry {
    state: Mutex<State>,
    /// Failed authentications, counted per source address.
    limiters: Mutex<HashMap<IpAddr, AttemptLimiter>>,
    next_exchange_id: AtomicU64,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Registry(online={})", self.online_count())
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

impl Registry {
    pub fn new() -> Self {
        Registry {
            state: Mutex::new(State::default()),
            limiters: Mutex::new(HashMap::new()),
            // Start from a random-ish point so exchange ids are not predictable
            // across restarts. They are checked against the target anyway, so
            // this is defence in depth rather than the guarantee.
            next_exchange_id: AtomicU64::new(bark_core::clock::unix_us() | 1),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A poisoned lock here means a panic inside a critical section. The
        // registry holds no invariant that a panic could leave half-applied —
        // every operation is a single map insert or removal — so recovering is
        // safe and far better than taking the whole server down.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Records a node as online. Returns the handle it replaced, if the device
    /// was already connected — which happens when a node reconnects before the
    /// server noticed the old connection had died.
    pub fn join(
        &self,
        identity: PublicIdentity,
        address: SocketAddr,
    ) -> (NodeHandle, mpsc::Receiver<ToNode>, Option<NodeHandle>) {
        let (tx, rx) = mpsc::channel(OUTBOX_DEPTH);
        let handle = NodeHandle {
            identity,
            address,
            connected_unix_us: bark_core::clock::unix_us(),
            outbox: tx,
        };

        let fp = identity.fingerprint();
        let previous = {
            let mut s = self.lock();
            s.online.insert(fp, handle.clone())
        };

        self.notify_watchers(fp, true);
        (handle, rx, previous)
    }

    /// Removes a node.
    ///
    /// `handle_id` guards against a stale connection removing the entry a newer
    /// one just installed: only the currently-registered connection may leave.
    pub fn leave(&self, fp: &Fingerprint, connected_unix_us: u64) -> bool {
        let removed = {
            let mut s = self.lock();
            match s.online.get(fp) {
                Some(h) if h.connected_unix_us == connected_unix_us => {
                    s.online.remove(fp);
                    s.watching.remove(fp);
                    true
                }
                _ => false,
            }
        };
        if removed {
            self.notify_watchers(*fp, false);
        }
        removed
    }

    pub fn is_online(&self, fp: &Fingerprint) -> bool {
        self.lock().online.contains_key(fp)
    }

    pub fn get(&self, fp: &Fingerprint) -> Option<NodeHandle> {
        self.lock().online.get(fp).cloned()
    }

    pub fn online_count(&self) -> usize {
        self.lock().online.len()
    }

    pub fn online_devices(&self) -> Vec<NodeHandle> {
        self.lock().online.values().cloned().collect()
    }

    /// Registers interest in some devices' comings and goings.
    pub fn watch(&self, watcher: Fingerprint, devices: Vec<Fingerprint>) {
        self.lock().watching.insert(watcher, devices);
    }

    /// Tells everyone watching `subject` that it came online or went away.
    fn notify_watchers(&self, subject: Fingerprint, online: bool) {
        let recipients: Vec<NodeHandle> = {
            let s = self.lock();
            s.watching
                .iter()
                .filter(|(watcher, targets)| {
                    **watcher != subject && targets.contains(&subject)
                })
                .filter_map(|(watcher, _)| s.online.get(watcher).cloned())
                .collect()
        };

        for r in recipients {
            // A watcher that cannot keep up simply misses the update; its own
            // connection handler will notice the backlog and disconnect it.
            let _ = r.try_send(ToNode::Presence {
                device: subject,
                online,
                last_seen_unix_us: bark_core::clock::unix_us(),
                machine: None,
            });
        }
    }

    /// Opens an introduction and returns the identifier to put in the offer.
    ///
    /// The identifier is the server's own; see the module documentation.
    pub fn open_exchange(
        &self,
        requester: Fingerprint,
        requester_request_id: u64,
        target: Fingerprint,
        kind: ExchangeKind,
    ) -> u64 {
        let id = self.next_exchange_id.fetch_add(1, Ordering::Relaxed);
        let mut s = self.lock();
        s.exchanges.insert(
            id,
            Exchange {
                requester,
                requester_request_id,
                target,
                kind,
                opened_unix_us: bark_core::clock::unix_us(),
            },
        );
        id
    }

    /// Accepts an answer to an introduction, if it is genuine.
    ///
    /// Rejects an answer from any device other than the one the offer was sent
    /// to, which is what stops a third device injecting itself into someone
    /// else's connection attempt.
    pub fn close_exchange(
        &self,
        exchange_id: u64,
        answering: &Fingerprint,
    ) -> std::result::Result<AnswerRoute, AnswerError> {
        let mut s = self.lock();
        match s.exchanges.get(&exchange_id) {
            None => Err(AnswerError::Unknown),
            Some(e) if e.target != *answering => Err(AnswerError::WrongDevice),
            Some(_) => {
                let e = s.exchanges.remove(&exchange_id).expect("just matched");
                Ok(AnswerRoute {
                    requester: e.requester,
                    requester_request_id: e.requester_request_id,
                    kind: e.kind,
                })
            }
        }
    }

    /// Discards exchanges nobody answered, and tells the requesters.
    ///
    /// Called periodically. Without it, a requester whose target never replies
    /// would wait for the connection timeout instead of being told promptly
    /// that nothing happened.
    pub fn expire_exchanges(&self) -> Vec<(Fingerprint, u64, ExchangeKind)> {
        let now = bark_core::clock::unix_us();
        let mut expired = Vec::new();
        {
            let mut s = self.lock();
            let stale: Vec<u64> = s
                .exchanges
                .iter()
                .filter(|(_, e)| now.saturating_sub(e.opened_unix_us) > EXCHANGE_TIMEOUT_US)
                .map(|(k, _)| *k)
                .collect();
            for id in stale {
                if let Some(e) = s.exchanges.remove(&id) {
                    expired.push((e.requester, e.requester_request_id, e.kind));
                }
            }
        }

        for (requester, request_id, kind) in &expired {
            if let Some(h) = self.get(requester) {
                let msg = match kind {
                    ExchangeKind::Connect => ToNode::ConnectResult {
                        request_id: *request_id,
                        accepted: false,
                        reason: Some(FailureReason::NoAnswer),
                        candidates: Vec::new(),
                        peer: None,
                    },
                    ExchangeKind::Pair => ToNode::PairResult {
                        request_id: *request_id,
                        accepted: false,
                        reason: Some(FailureReason::NoAnswer),
                        peer: None,
                        machine: None,
                        name: None,
                    },
                };
                let _ = h.try_send(msg);
            }
        }
        expired
    }

    pub fn pending_exchanges(&self) -> usize {
        self.lock().exchanges.len()
    }

    /// Whether this address may attempt to authenticate right now.
    ///
    /// Counted per source address rather than per claimed identity: an attacker
    /// guessing at keys would otherwise get a fresh allowance for every
    /// identity they invented.
    pub fn check_auth_allowed(&self, addr: IpAddr) -> Result<()> {
        let mut l = self.limiters.lock().unwrap_or_else(|e| e.into_inner());
        l.entry(addr).or_default().check()
    }

    pub fn record_auth_failure(&self, addr: IpAddr) {
        let mut l = self.limiters.lock().unwrap_or_else(|e| e.into_inner());
        l.entry(addr).or_default().record_failure();
    }

    pub fn record_auth_success(&self, addr: IpAddr) {
        let mut l = self.limiters.lock().unwrap_or_else(|e| e.into_inner());
        l.entry(addr).or_default().record_success();
    }

    /// Drops rate-limit records for addresses that are no longer misbehaving,
    /// so a long-running server does not accumulate one entry per address that
    /// ever mistyped something.
    pub fn prune_limiters(&self) {
        let mut l = self.limiters.lock().unwrap_or_else(|e| e.into_inner());
        l.retain(|_, v| v.failure_count() > 0 || v.is_locked());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bark_crypto::DeviceIdentity;
    use std::net::{Ipv4Addr, SocketAddr};

    fn identity() -> PublicIdentity {
        DeviceIdentity::generate().unwrap().public()
    }

    fn addr(n: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, n)), 40000 + n as u16)
    }

    #[test]
    fn a_device_is_online_while_it_is_joined() {
        let r = Registry::new();
        let d = identity();
        assert!(!r.is_online(&d.fingerprint()));

        let (h, _rx, previous) = r.join(d, addr(1));
        assert!(previous.is_none());
        assert!(r.is_online(&d.fingerprint()));
        assert_eq!(r.online_count(), 1);
        assert_eq!(r.get(&d.fingerprint()).unwrap().address, addr(1));

        assert!(r.leave(&d.fingerprint(), h.connected_unix_us));
        assert!(!r.is_online(&d.fingerprint()));
        assert_eq!(r.online_count(), 0);
    }

    #[test]
    fn a_stale_connection_cannot_evict_a_newer_one() {
        // A node reconnects before the server noticed the old link died. When
        // the old handler finally cleans up it must not remove the new session.
        let r = Registry::new();
        let d = identity();

        let (old, _rx1, _) = r.join(d, addr(1));
        std::thread::sleep(std::time::Duration::from_millis(2));
        let (new, _rx2, previous) = r.join(d, addr(2));

        assert!(previous.is_some(), "the replaced handle should be returned");
        assert_ne!(old.connected_unix_us, new.connected_unix_us);

        assert!(!r.leave(&d.fingerprint(), old.connected_unix_us), "stale leave must be ignored");
        assert!(r.is_online(&d.fingerprint()), "the new connection must survive");
        assert_eq!(r.get(&d.fingerprint()).unwrap().address, addr(2));

        assert!(r.leave(&d.fingerprint(), new.connected_unix_us));
        assert!(!r.is_online(&d.fingerprint()));
    }

    #[tokio::test]
    async fn watchers_are_told_when_a_device_arrives_and_leaves() {
        let r = Registry::new();
        let watcher = identity();
        let subject = identity();

        let (_wh, mut wrx, _) = r.join(watcher, addr(1));
        r.watch(watcher.fingerprint(), vec![subject.fingerprint()]);

        let (sh, _srx, _) = r.join(subject, addr(2));
        let msg = wrx.try_recv().expect("should have been told about the arrival");
        match msg {
            ToNode::Presence { device, online, .. } => {
                assert_eq!(device, subject.fingerprint());
                assert!(online);
            }
            other => panic!("unexpected: {other:?}"),
        }

        r.leave(&subject.fingerprint(), sh.connected_unix_us);
        match wrx.try_recv().expect("should have been told about the departure") {
            ToNode::Presence { device, online, .. } => {
                assert_eq!(device, subject.fingerprint());
                assert!(!online);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_device_is_not_told_about_its_own_presence() {
        let r = Registry::new();
        let d = identity();
        let (_h, mut rx, _) = r.join(d, addr(1));
        r.watch(d.fingerprint(), vec![d.fingerprint()]);

        // Re-join to trigger a notification.
        let (_h2, _rx2, _) = r.join(d, addr(1));
        assert!(rx.try_recv().is_err(), "a device should not be told about itself");
    }

    #[tokio::test]
    async fn a_device_only_hears_about_devices_it_watches() {
        let r = Registry::new();
        let watcher = identity();
        let watched = identity();
        let ignored = identity();

        let (_wh, mut wrx, _) = r.join(watcher, addr(1));
        r.watch(watcher.fingerprint(), vec![watched.fingerprint()]);

        r.join(ignored, addr(2));
        assert!(wrx.try_recv().is_err(), "should not hear about an unwatched device");

        r.join(watched, addr(3));
        assert!(wrx.try_recv().is_ok(), "should hear about a watched device");
    }

    #[tokio::test]
    async fn a_full_outbox_is_reported_rather_than_blocking() {
        let r = Registry::new();
        let d = identity();
        let (h, _rx, _) = r.join(d, addr(1));

        // Fill the queue without reading it.
        for _ in 0..OUTBOX_DEPTH {
            h.try_send(ToNode::Pong { sent_us: 0, server_time_us: 0 }).expect("should fit");
        }
        assert_eq!(
            h.try_send(ToNode::Pong { sent_us: 0, server_time_us: 0 }),
            Err(SendError::Backlogged),
            "the queue is bounded so one stuck node cannot stall the server"
        );
    }

    #[tokio::test]
    async fn sending_to_a_dropped_connection_reports_it_is_gone() {
        let r = Registry::new();
        let d = identity();
        let (h, rx, _) = r.join(d, addr(1));
        drop(rx);
        assert_eq!(
            h.try_send(ToNode::Pong { sent_us: 0, server_time_us: 0 }),
            Err(SendError::Gone)
        );
    }

    #[test]
    fn an_exchange_routes_the_answer_back_to_the_requester() {
        let r = Registry::new();
        let a = identity().fingerprint();
        let b = identity().fingerprint();

        let exchange = r.open_exchange(a, 4242, b, ExchangeKind::Connect);
        assert_eq!(r.pending_exchanges(), 1);

        let route = r.close_exchange(exchange, &b).expect("b may answer");
        assert_eq!(route.requester, a);
        assert_eq!(route.requester_request_id, 4242, "the requester's own number comes back");
        assert_eq!(route.kind, ExchangeKind::Connect);
        assert_eq!(r.pending_exchanges(), 0, "the exchange is consumed");
    }

    #[test]
    fn the_server_issued_identifier_is_not_the_requesters() {
        let r = Registry::new();
        let a = identity().fingerprint();
        let b = identity().fingerprint();
        let exchange = r.open_exchange(a, 1, b, ExchangeKind::Connect);
        assert_ne!(exchange, 1, "the identifier must be the server's own");
    }

    #[test]
    fn a_third_device_cannot_answer_someone_elses_exchange() {
        let r = Registry::new();
        let a = identity().fingerprint();
        let b = identity().fingerprint();
        let interloper = identity().fingerprint();

        let exchange = r.open_exchange(a, 1, b, ExchangeKind::Connect);
        assert_eq!(r.close_exchange(exchange, &interloper), Err(AnswerError::WrongDevice));
        assert_eq!(r.pending_exchanges(), 1, "a rejected answer must not consume it");

        // And the real target can still answer.
        assert!(r.close_exchange(exchange, &b).is_ok());
    }

    #[test]
    fn an_unknown_or_reused_exchange_is_rejected() {
        let r = Registry::new();
        let a = identity().fingerprint();
        let b = identity().fingerprint();
        let exchange = r.open_exchange(a, 1, b, ExchangeKind::Connect);

        assert_eq!(r.close_exchange(exchange + 999, &b), Err(AnswerError::Unknown));
        r.close_exchange(exchange, &b).expect("first answer");
        assert_eq!(
            r.close_exchange(exchange, &b),
            Err(AnswerError::Unknown),
            "an exchange must not be answerable twice"
        );
    }

    #[test]
    fn two_requesters_using_the_same_number_do_not_collide() {
        let r = Registry::new();
        let a = identity().fingerprint();
        let b = identity().fingerprint();
        let target = identity().fingerprint();

        // Both pick request id 1, which is exactly what a naive scheme would
        // confuse.
        let ea = r.open_exchange(a, 1, target, ExchangeKind::Connect);
        let eb = r.open_exchange(b, 1, target, ExchangeKind::Connect);
        assert_ne!(ea, eb);

        assert_eq!(r.close_exchange(ea, &target).unwrap().requester, a);
        assert_eq!(r.close_exchange(eb, &target).unwrap().requester, b);
    }

    #[tokio::test]
    async fn an_unanswered_exchange_expires_and_the_requester_is_told() {
        let r = Registry::new();
        let requester = identity();
        let target = identity().fingerprint();
        let (_h, mut rx, _) = r.join(requester, addr(1));

        let _ = r.open_exchange(requester.fingerprint(), 77, target, ExchangeKind::Connect);

        // Not yet expired.
        assert!(r.expire_exchanges().is_empty());
        assert_eq!(r.pending_exchanges(), 1);

        // Force it into the past.
        {
            let mut s = r.lock();
            for e in s.exchanges.values_mut() {
                e.opened_unix_us = bark_core::clock::unix_us() - EXCHANGE_TIMEOUT_US - 1;
            }
        }

        let expired = r.expire_exchanges();
        assert_eq!(expired.len(), 1);
        assert_eq!(r.pending_exchanges(), 0);

        match rx.try_recv().expect("the requester should be told") {
            ToNode::ConnectResult { request_id, accepted, reason, .. } => {
                assert_eq!(request_id, 77);
                assert!(!accepted);
                assert_eq!(reason, Some(FailureReason::NoAnswer));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn repeated_authentication_failures_are_rate_limited_per_address() {
        let r = Registry::new();
        let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7));
        let innocent = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 8));

        for _ in 0..8 {
            let _ = r.check_auth_allowed(attacker);
            r.record_auth_failure(attacker);
        }
        assert!(r.check_auth_allowed(attacker).is_err(), "should be locked out");

        // A different address is unaffected: one attacker must not deny service
        // to everyone else.
        assert!(r.check_auth_allowed(innocent).is_ok());
    }

    #[test]
    fn a_successful_authentication_clears_the_counter() {
        let r = Registry::new();
        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        for _ in 0..3 {
            r.record_auth_failure(ip);
        }
        r.record_auth_success(ip);
        assert!(r.check_auth_allowed(ip).is_ok());
    }

    #[test]
    fn limiter_records_for_well_behaved_addresses_are_pruned() {
        let r = Registry::new();
        let good = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
        let bad = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11));

        r.record_auth_success(good);
        for _ in 0..6 {
            r.record_auth_failure(bad);
        }

        r.prune_limiters();
        let l = r.limiters.lock().unwrap();
        assert!(!l.contains_key(&good), "a clean address should not be remembered");
        assert!(l.contains_key(&bad), "a misbehaving address must still be tracked");
    }
}
