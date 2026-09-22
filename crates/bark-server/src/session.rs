//! Handling one node's connection to the coordination server.
//!
//! The shape of every connection:
//!
//! ```text
//!   node                                         server
//!     |  Hello { protocol }                        |
//!     | -----------------------------------------> |
//!     |  Challenge { nonce }                       |
//!     | <----------------------------------------- |
//!     |  Authenticate { identity, signature, … }   |
//!     | -----------------------------------------> |
//!     |                                            | verifies the signature
//!     |  Welcome { your_address, … }               | registers, marks online
//!     | <----------------------------------------- |
//!     |  … requests and pushed messages …          |
//! ```
//!
//! Two properties worth stating outright.
//!
//! **The challenge is fresh per connection**, so a recorded `Authenticate` is
//! worthless to a replayer. It also covers the server's own certificate
//! fingerprint, which means a signature produced for this server cannot be
//! relayed to a different one — a malicious server cannot borrow a node's
//! identity to log in somewhere else.
//!
//! **The server does not decide who may control whom.** It checks that a device
//! is who it claims to be, and that it is not revoked. Whether device A may open
//! a session on device B is answered by B's own trust store, on B, when B
//! answers the offer. A compromised server can refuse introductions and lie
//! about who is online; it cannot grant itself access to anything.

use crate::db::{AuditEntry, Db, Registration};
use crate::registry::{AnswerError, ExchangeKind, Registry, SendError};
use bark_core::{BarkError, Result};
use bark_crypto::identity::context;
use bark_crypto::PublicIdentity;
use bark_net::framing::{read_message, write_message};
use bark_proto::control::{Candidate, CandidateKind, FailureReason, ToNode, ToServer};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Everything a connection handler needs.
pub struct ServerState {
    pub db: Arc<Db>,
    pub registry: Arc<Registry>,
    /// The server's own TLS certificate fingerprint, mixed into the challenge.
    pub cert_fingerprint: [u8; 32],
    pub version: String,
    /// The relay, when this server provides one.
    pub relay: Option<Arc<crate::relay::Relay>>,
}

impl std::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerState(online={})", self.registry.online_count())
    }
}

/// How long a node may take to get through authentication.
///
/// A connection that opens and then says nothing costs a task and a socket. A
/// legitimate node completes this in milliseconds.
pub const AUTH_TIMEOUT_SECS: u64 = 10;

/// How long the server waits, after refusing a node, for that node to read the
/// refusal.
///
/// Short, because the node only has to read one small message that has already
/// been sent.
const REJECTION_LINGER_SECS: u64 = 3;

/// Refuses a connection *and makes sure the node learns why*.
///
/// The obvious implementation — write the message, return an error — loses it.
/// Returning ends the handler, the `Connection` is dropped, QUIC tears the
/// connection down, and any stream data still in flight is discarded. The node
/// then reports "connection lost", which tells the operator nothing and sends
/// them looking at firewalls instead of at the revoked device in front of them.
///
/// So the stream is finished and the connection is kept alive until the node
/// has read the refusal and closed, or until a short timer expires so a node
/// that never reads cannot pin the task open.
async fn refuse(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    reason: FailureReason,
    detail: String,
) {
    if write_message(send, &ToNode::Rejected { reason, detail }).await.is_ok() {
        let _ = send.finish();
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(REJECTION_LINGER_SECS),
            conn.closed(),
        )
        .await;
    }
}

/// Runs one node connection from start to finish.
pub async fn handle_connection(state: Arc<ServerState>, conn: quinn::Connection) {
    let address = conn.remote_address();

    if let Err(e) = state.registry.check_auth_allowed(address.ip()) {
        tracing::warn!(%address, "refusing connection: {e}");
        let _ = state.db.audit(
            &AuditEntry::new("auth-rate-limited", false).detail(format!("from {address}")),
        );
        conn.close(1u32.into(), b"rate limited");
        return;
    }

    match run(state.clone(), conn.clone(), address).await {
        Ok(()) => {}
        Err(e) => {
            tracing::info!(%address, "connection ended: {e}");
        }
    }
}

async fn run(state: Arc<ServerState>, conn: quinn::Connection, address: SocketAddr) -> Result<()> {
    // The node opens one bidirectional stream and keeps it for the whole
    // conversation.
    let (mut send, mut recv) = tokio::time::timeout(
        std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
        conn.accept_bi(),
    )
    .await
    .map_err(|_| BarkError::Timeout(AUTH_TIMEOUT_SECS * 1000))?
    .map_err(|e| BarkError::Network(format!("the node did not open a control stream: {e}")))?;

    // --- Hello -------------------------------------------------------------
    let hello: ToServer = tokio::time::timeout(
        std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
        read_message(&mut recv),
    )
    .await
    .map_err(|_| BarkError::Timeout(AUTH_TIMEOUT_SECS * 1000))??
    .ok_or_else(|| BarkError::Network("the node closed before saying hello".into()))?;

    let ToServer::Hello { protocol } = hello else {
        return Err(BarkError::protocol("the node did not begin with Hello"));
    };

    if protocol != bark_core::PROTOCOL_VERSION {
        refuse(
            &conn,
            &mut send,
            FailureReason::VersionMismatch,
            format!(
                "This computer speaks BARK protocol {protocol}; the server speaks {}. \
                 Update BARK so both are the same version.",
                bark_core::PROTOCOL_VERSION
            ),
        )
        .await;
        return Err(BarkError::protocol(format!("protocol {protocol} is not supported")));
    }

    // --- Challenge ---------------------------------------------------------
    let mut nonce = [0u8; 32];
    getrandom_nonce(&mut nonce)?;
    write_message(
        &mut send,
        &ToNode::Challenge { nonce, protocol: bark_core::PROTOCOL_VERSION },
    )
    .await?;

    // --- Authenticate ------------------------------------------------------
    let auth: ToServer = tokio::time::timeout(
        std::time::Duration::from_secs(AUTH_TIMEOUT_SECS),
        read_message(&mut recv),
    )
    .await
    .map_err(|_| BarkError::Timeout(AUTH_TIMEOUT_SECS * 1000))??
    .ok_or_else(|| BarkError::Network("the node closed before authenticating".into()))?;

    let ToServer::Authenticate { identity, signature, machine, local_candidates } = auth else {
        return Err(BarkError::protocol("the node did not authenticate"));
    };

    let signed = challenge_payload(&nonce, &state.cert_fingerprint);
    if identity
        .verify(context::SERVER_AUTH, &signed, signature.as_bytes())
        .is_err()
    {
        state.registry.record_auth_failure(address.ip());
        let _ = state.db.audit(
            &AuditEntry::new("authenticate", false)
                .actor(identity.fingerprint())
                .detail(format!("bad signature from {address}")),
        );
        refuse(
            &conn,
            &mut send,
            FailureReason::BadRequest,
            "The device could not prove it holds its private key.".into(),
        )
        .await;
        return Err(BarkError::crypto("signature verification failed"));
    }

    // --- Revocation and registration ---------------------------------------
    if let Some(existing) = state.db.by_fingerprint(&identity.fingerprint())? {
        if existing.revoked {
            let _ = state.db.audit(
                &AuditEntry::new("authenticate", false)
                    .actor(identity.fingerprint())
                    .detail("revoked device"),
            );
            refuse(
                &conn,
                &mut send,
                FailureReason::Revoked,
                "This device has been revoked by an administrator. \
                 Pair it again to restore access."
                    .into(),
            )
            .await;
            return Err(BarkError::Revoked(identity.device_id().to_string()));
        }
    }

    match state.db.register(&identity, &machine.hostname, &machine.os, &machine.bark_version)? {
        Registration::ShortIdCollision { existing } => {
            let _ = state.db.audit(
                &AuditEntry::new("register", false)
                    .actor(identity.fingerprint())
                    .target(existing)
                    .detail("short device ID already in use"),
            );
            refuse(
                &conn,
                &mut send,
                FailureReason::BadRequest,
                format!(
                    "Another device is already registered as {}. \
                     Contact your administrator; this device cannot join until \
                     the conflict is resolved.",
                    identity.device_id()
                ),
            )
            .await;
            return Err(BarkError::config("short device ID collision"));
        }
        outcome => {
            let _ = state.db.audit(
                &AuditEntry::new("authenticate", true)
                    .actor(identity.fingerprint())
                    .detail(format!("{outcome:?} from {address}")),
            );
        }
    }

    state.registry.record_auth_success(address.ip());

    // --- Welcome -----------------------------------------------------------
    let (handle, outbox, previous) = state.registry.join(identity, address);
    if previous.is_some() {
        tracing::info!(device = %identity.device_id(), "replaced an earlier connection");
    }
    let my_connected_at = handle.connected_unix_us;

    write_message(
        &mut send,
        &ToNode::Welcome {
            your_address: address,
            server_time_us: bark_core::clock::now_us(),
            server_version: state.version.clone(),
        },
    )
    .await?;

    tracing::info!(device = %identity.device_id(), %address, name = %machine.hostname, "node online");

    // --- Pump pushed messages out on their own task ------------------------
    let writer = tokio::spawn(async move {
        let mut outbox: mpsc::Receiver<ToNode> = outbox;
        while let Some(msg) = outbox.recv().await {
            if write_message(&mut send, &msg).await.is_err() {
                break;
            }
        }
    });

    // --- Handle requests ---------------------------------------------------
    let ctx = NodeContext {
        state: state.clone(),
        identity,
        address,
        reported_candidates: local_candidates,
    };

    let result = request_loop(&ctx, &mut recv).await;

    // --- Clean up ----------------------------------------------------------
    writer.abort();
    state.registry.leave(&identity.fingerprint(), my_connected_at);
    let _ = state.db.touch_seen(&identity.fingerprint());
    tracing::info!(device = %identity.device_id(), "node offline");

    result
}

struct NodeContext {
    state: Arc<ServerState>,
    identity: PublicIdentity,
    address: SocketAddr,
    reported_candidates: Vec<SocketAddr>,
}

impl NodeContext {
    /// The addresses peers should aim at to reach this node.
    ///
    /// Three sources, combined:
    ///
    /// * the interface addresses the node listed when it authenticated,
    /// * any fresher list it sent with this particular request, because a
    ///   laptop's addresses change when it moves between networks,
    /// * the address the server observed, which is the node's NAT mapping.
    ///
    /// The last one is the important one, and the server is the only party that
    /// can know it — which is why it is added here rather than taken on trust
    /// from the node.
    fn candidates(&self, fresh: Vec<Candidate>) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = self
            .reported_candidates
            .iter()
            .map(|a| Candidate { addr: *a, kind: CandidateKind::Local })
            .collect();
        out.extend(fresh);
        out.push(Candidate { addr: self.address, kind: CandidateKind::ServerReflexive });

        // Sort by address so duplicates become adjacent, with the better kind
        // first for any address that appears twice, then remove the repeats.
        // `dedup_by_key` only collapses neighbours, so the order matters.
        out.sort_by_key(|c| (c.addr, c.priority()));
        out.dedup_by_key(|c| c.addr);
        // Finally put them in the order a peer should probe them.
        out.sort_by_key(|c| c.priority());
        out
    }
}

async fn request_loop(ctx: &NodeContext, recv: &mut quinn::RecvStream) -> Result<()> {
    loop {
        let Some(msg): Option<ToServer> = read_message(recv).await? else {
            return Ok(());
        };
        if handle_request(ctx, msg).await? {
            return Ok(());
        }
    }
}

/// Returns `true` when the node has said goodbye.
async fn handle_request(ctx: &NodeContext, msg: ToServer) -> Result<bool> {
    let me = ctx.identity.fingerprint();
    let reg = &ctx.state.registry;
    let db = &ctx.state.db;

    match msg {
        ToServer::Hello { .. } | ToServer::Authenticate { .. } => {
            // Already authenticated; a second attempt is a protocol error.
            return Err(BarkError::protocol("the node tried to authenticate twice"));
        }

        ToServer::Goodbye => return Ok(true),

        ToServer::Ping { sent_us } => {
            push(reg, &me, ToNode::Pong { sent_us, server_time_us: bark_core::clock::now_us() });
        }

        ToServer::WatchPresence { devices } => {
            // Tell the watcher the current state straight away, so its list is
            // right immediately rather than after the next change.
            let snapshot: Vec<(bark_core::Fingerprint, bool, u64)> = devices
                .iter()
                .map(|d| {
                    let online = reg.is_online(d);
                    let last_seen = db
                        .by_fingerprint(d)
                        .ok()
                        .flatten()
                        .map(|r| r.last_seen_unix_us)
                        .unwrap_or(0);
                    (*d, online, last_seen)
                })
                .collect();

            reg.watch(me, devices);

            for (device, online, last_seen_unix_us) in snapshot {
                push(
                    reg,
                    &me,
                    ToNode::Presence { device, online, last_seen_unix_us, machine: None },
                );
            }
        }

        ToServer::Resolve { device_id } => {
            let identity = db.by_device_id(&device_id)?.map(|r| r.identity);
            push(reg, &me, ToNode::Resolved { device_id, identity });
        }

        ToServer::ConnectRequest { target, request_id, candidates } => {
            handle_introduction(ctx, target, request_id, candidates, ExchangeKind::Connect)
                .await?;
        }

        ToServer::ConnectAnswer { request_id, accept, reason, candidates } => {
            match reg.close_exchange(request_id, &me) {
                Ok(route) => {
                    if accept {
                        reg.note_accepted(route.requester, route.requester_request_id, me, request_id);
                    }
                    let peer = Some(ctx.identity);
                    push(
                        reg,
                        &route.requester,
                        ToNode::ConnectResult {
                            request_id: route.requester_request_id,
                            accepted: accept,
                            reason,
                            candidates: ctx.candidates(candidates),
                            peer,
                        },
                    );
                    let _ = db.audit(
                        &AuditEntry::new("connect-answer", accept)
                            .actor(me)
                            .target(route.requester)
                            .detail(if accept { "accepted" } else { "refused" }),
                    );
                }
                Err(e) => log_bad_answer(ctx, "connect", e),
            }
        }

        ToServer::PairRequest { target, request_id, code_nonce, code_digest, our_name, machine } => {
            let exchange = match prepare_introduction(ctx, &target, request_id, ExchangeKind::Pair)
                .await?
            {
                Some(id) => id,
                None => return Ok(false),
            };
            push(
                reg,
                &target,
                ToNode::PairOffer {
                    from: ctx.identity,
                    request_id: exchange,
                    code_nonce,
                    code_digest,
                    their_name: our_name,
                    machine,
                },
            );
            let _ = db.audit(
                &AuditEntry::new("pair-request", true).actor(me).target(target),
            );
        }

        ToServer::PairAnswer { request_id, accept, reason, machine, name } => {
            match reg.close_exchange(request_id, &me) {
                Ok(route) => {
                    if accept {
                        // The owner has just re-admitted this device with a
                        // pairing code, so any earlier revocation is lifted.
                        let _ = db.unblock_pair(&me, &route.requester);
                    }
                    push(
                        reg,
                        &route.requester,
                        ToNode::PairResult {
                            request_id: route.requester_request_id,
                            accepted: accept,
                            reason,
                            peer: accept.then_some(ctx.identity),
                            machine,
                            name,
                        },
                    );
                    let _ = db.audit(
                        &AuditEntry::new("pair-answer", accept)
                            .actor(me)
                            .target(route.requester)
                            .detail(if accept { "accepted" } else { "refused" }),
                    );
                }
                Err(e) => log_bad_answer(ctx, "pair", e),
            }
        }

        ToServer::Revoke { peer, signature } => {
            // Only the device itself may say "I no longer trust this peer", and
            // it has to prove it by signing the statement.
            let mut signed = Vec::with_capacity(64);
            signed.extend_from_slice(peer.as_bytes());
            signed.extend_from_slice(ctx.identity.fingerprint().as_bytes());

            if ctx
                .identity
                .verify(context::REVOCATION, &signed, signature.as_bytes())
                .is_err()
            {
                let _ = db.audit(
                    &AuditEntry::new("revoke", false)
                        .actor(me)
                        .target(peer)
                        .detail("bad signature"),
                );
                return Err(BarkError::crypto("revocation signature is not valid"));
            }

            // Per pair only: this device stops being introduced to `peer`.
            // It must never ban `peer` from the rest of the network — that
            // was a bug in the first version of this handler.
            db.block_pair(&me, &peer)?;
            let _ = db.audit(&AuditEntry::new("revoke", true).actor(me).target(peer));
        }

        ToServer::RelayRequest { request_id } => {
            handle_relay_request(ctx, request_id);
        }
    }

    Ok(false)
}

/// Sets up a relayed path for a connection the target has accepted.
///
/// Refused, with `RelayUnavailable`, unless: this server runs a relay, the
/// requester is asking about a connection its target accepted within the last
/// minute (so a relay can never be obtained for a pair that was not
/// introduced), and the target is still online.
fn handle_relay_request(ctx: &NodeContext, request_id: u64) {
    let me = ctx.identity.fingerprint();
    let reg = &ctx.state.registry;
    let unavailable = |detail: &str| {
        tracing::info!(requester = %me.short_id(), "relay refused: {detail}");
        push(reg, &me, ToNode::RelayUnavailable { request_id, detail: detail.to_string() });
    };

    let Some(relay) = &ctx.state.relay else {
        return unavailable("This BARK server does not provide relaying. Enable it in Tools > Settings on the server computer.");
    };
    let Some(accepted) = reg.take_accepted(&me, request_id) else {
        return unavailable("The connection this relay was requested for is unknown or too old. Connect again.");
    };
    if !reg.is_online(&accepted.target) {
        return unavailable("The remote computer went offline.");
    }
    let (controller_token, remote_token) = match relay.allocate(me, accepted.target) {
        Ok(t) => t,
        Err(e) => return unavailable(&e.to_string()),
    };
    let relay_address = relay.listening();
    push(reg, &accepted.target, ToNode::RelayReady { request_id: accepted.exchange_id, relay_address, token: remote_token });
    push(reg, &me, ToNode::RelayReady { request_id, relay_address, token: controller_token });
    let _ = ctx.state.db.audit(
        &AuditEntry::new("relay", true).actor(me).target(accepted.target).detail(format!("via {relay_address}")),
    );
}

/// Common checks before forwarding an introduction to a target.
///
/// Returns the server-issued exchange identifier, or `None` if the requester
/// has already been told why it cannot proceed.
async fn prepare_introduction(
    ctx: &NodeContext,
    target: &bark_core::Fingerprint,
    request_id: u64,
    kind: ExchangeKind,
) -> Result<Option<u64>> {
    let me = ctx.identity.fingerprint();
    let reg = &ctx.state.registry;
    let db = &ctx.state.db;

    let fail = |reason: FailureReason| match kind {
        ExchangeKind::Connect => ToNode::ConnectResult {
            request_id,
            accepted: false,
            reason: Some(reason),
            candidates: Vec::new(),
            peer: None,
        },
        ExchangeKind::Pair => ToNode::PairResult {
            request_id,
            accepted: false,
            reason: Some(reason),
            peer: None,
            machine: None,
            name: None,
        },
    };

    if *target == me {
        push(reg, &me, fail(FailureReason::BadRequest));
        return Ok(None);
    }

    let record = db.by_fingerprint(target)?;
    match record {
        None => {
            push(reg, &me, fail(FailureReason::UnknownDevice));
            return Ok(None);
        }
        Some(r) if r.revoked => {
            push(reg, &me, fail(FailureReason::Revoked));
            return Ok(None);
        }
        Some(_) => {}
    }

    // A per-pair revocation stops connection introductions only. Pairing is
    // still allowed through, because pairing needs the code shown on the
    // owner's own screen: that is the owner deliberately restoring access,
    // which is exactly how a revoked device is meant to be re-paired.
    if kind == ExchangeKind::Connect && db.is_blocked(target, &me)? {
        push(reg, &me, fail(FailureReason::Revoked));
        let _ = db.audit(
            &AuditEntry::new("introduce", false)
                .actor(me)
                .target(*target)
                .detail("revoked by the target"),
        );
        return Ok(None);
    }

    if !reg.is_online(target) {
        push(reg, &me, fail(FailureReason::DeviceOffline));
        let _ = db.audit(
            &AuditEntry::new("introduce", false)
                .actor(me)
                .target(*target)
                .detail("target offline"),
        );
        return Ok(None);
    }

    Ok(Some(reg.open_exchange(me, request_id, *target, kind)))
}

async fn handle_introduction(
    ctx: &NodeContext,
    target: bark_core::Fingerprint,
    request_id: u64,
    candidates: Vec<Candidate>,
    kind: ExchangeKind,
) -> Result<()> {
    let Some(exchange) = prepare_introduction(ctx, &target, request_id, kind).await? else {
        return Ok(());
    };

    let machine = ctx
        .state
        .db
        .by_fingerprint(&ctx.identity.fingerprint())?
        .map(|r| bark_core::machine::MachineInfo {
            hostname: r.name,
            os: r.os,
            bark_version: r.bark_version,
            cpu: String::new(),
            cpu_threads: 0,
            memory_mb: 0,
        })
        .unwrap_or_else(|| bark_core::machine::MachineInfo {
            hostname: String::new(),
            os: String::new(),
            bark_version: String::new(),
            cpu: String::new(),
            cpu_threads: 0,
            memory_mb: 0,
        });

    push(
        &ctx.state.registry,
        &target,
        ToNode::ConnectOffer {
            from: ctx.identity,
            request_id: exchange,
            candidates: ctx.candidates(candidates),
            machine,
        },
    );

    let _ = ctx.state.db.audit(
        &AuditEntry::new("connect-request", true)
            .actor(ctx.identity.fingerprint())
            .target(target),
    );
    Ok(())
}

fn push(reg: &Registry, to: &bark_core::Fingerprint, msg: ToNode) {
    if let Some(h) = reg.get(to) {
        match h.try_send(msg) {
            Ok(()) | Err(SendError::Gone) => {}
            Err(SendError::Backlogged) => {
                tracing::warn!(device = %h.identity.device_id(), "node is not reading its messages");
            }
        }
    }
}

fn log_bad_answer(ctx: &NodeContext, what: &str, e: AnswerError) {
    let detail = match e {
        AnswerError::Unknown => "no such exchange, or it expired",
        AnswerError::WrongDevice => "answered an exchange it was not part of",
    };
    tracing::warn!(device = %ctx.identity.device_id(), "{what} answer refused: {detail}");
    let _ = ctx.state.db.audit(
        &AuditEntry::new(format!("{what}-answer"), false)
            .actor(ctx.identity.fingerprint())
            .detail(detail),
    );
}

/// The bytes a node signs to prove its identity to this server.
///
/// Includes the server's certificate fingerprint so the signature is bound to
/// *this* server. Without it, a hostile server could take a node's
/// authentication and replay it to the real one.
pub fn challenge_payload(nonce: &[u8; 32], server_cert_fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(nonce);
    v.extend_from_slice(server_cert_fingerprint);
    v
}

fn getrandom_nonce(out: &mut [u8; 32]) -> Result<()> {
    getrandom::fill(out)
        .map_err(|e| BarkError::Crypto(format!("no secure random source available: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_binds_the_nonce_and_the_server() {
        let a = challenge_payload(&[1u8; 32], &[2u8; 32]);
        let b = challenge_payload(&[1u8; 32], &[3u8; 32]);
        let c = challenge_payload(&[9u8; 32], &[2u8; 32]);

        assert_eq!(a.len(), 64);
        assert_ne!(a, b, "a different server must produce a different payload");
        assert_ne!(a, c, "a different nonce must produce a different payload");
    }

    #[test]
    fn a_signature_for_one_server_does_not_verify_for_another() {
        // This is the property that stops a hostile server relaying a node's
        // authentication to the real one.
        let node = bark_crypto::DeviceIdentity::generate().unwrap();
        let nonce = [7u8; 32];
        let honest = [0xAAu8; 32];
        let hostile = [0xBBu8; 32];

        let sig = node.sign(context::SERVER_AUTH, &challenge_payload(&nonce, &hostile));

        assert!(
            node.public()
                .verify(context::SERVER_AUTH, &challenge_payload(&nonce, &hostile), &sig)
                .is_ok(),
            "it should verify against the server it was made for"
        );
        assert!(
            node.public()
                .verify(context::SERVER_AUTH, &challenge_payload(&nonce, &honest), &sig)
                .is_err(),
            "it must not verify against a different server"
        );
    }

    #[test]
    fn nonces_differ_between_connections() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        getrandom_nonce(&mut a).unwrap();
        getrandom_nonce(&mut b).unwrap();
        assert_ne!(a, b, "a repeated challenge would allow replay");
    }
}
