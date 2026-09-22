//! The node's main loop.
//!
//! One task owns all node state and reacts to three things: commands from the
//! user interface, messages from the coordination server, and a one-second
//! tick. Owning everything in one task means no locks around the trust store
//! or the pairing state, and no way for two events to interleave badly.

use crate::api::*;
use crate::config::{NodeConfig, NodeDirs};
use crate::session::{classify_direct, Established, HostCommand, PathKind};
use crate::viewer::{ViewerLink, ViewerSlots};
use bark_core::machine::MachineInfo;
use bark_core::{BarkError, DeviceId, Fingerprint, Result};
use bark_crypto::identity::context;
use bark_crypto::{AttemptLimiter, CodeCommitment, DeviceIdentity, Grant, PairingCode, PublicIdentity, TrustStore};
use bark_net::control::{ControlConnection, PresenceTable};
use bark_net::endpoint::{bidirectional_endpoint, NodeSocket, Role};
use bark_net::peer;
use bark_net::tls::{pinned_client_config, TransportCredentials};
use bark_proto::control::{Candidate, FailureReason, ToNode, ToServer};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

/// Receives everything the node reports. Called from the node's own thread;
/// implementations must be quick and must not block (the GUI's queues the
/// event and wakes its window).
pub type EventSink = Arc<dyn Fn(Event) + Send + Sync>;

/// How often the node measures its round trip to the server.
const PING_EVERY: Duration = Duration::from_secs(5);
/// A pairing attempt with no answer after this long is reported as failed.
const PAIR_TIMEOUT: Duration = Duration::from_secs(30);
/// Reconnection back-off: start fast, settle at a gentle retry rate.
const BACKOFF_START: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// How long after accepting an introduction this computer waits for the
/// controller's connection. Anything later is refused.
const INBOUND_WINDOW: Duration = Duration::from_secs(60);
/// Sessions other computers may run on this one at the same time.
const MAX_HOST_SESSIONS: usize = 4;
/// Size the controller asks for before its window has measured itself.
const DEFAULT_VIEW: (u16, u16) = (1920, 1080);

/// A running node. Dropping it shuts the node down.
pub struct NodeHandle {
    tx: mpsc::UnboundedSender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
    viewers: ViewerSlots,
}

impl NodeHandle {
    pub fn send(&self, cmd: Command) {
        let _ = self.tx.send(cmd);
    }

    /// Collects the video and input channels of a session announced by
    /// `Event::SessionOpened`. Each can be taken once.
    pub fn take_viewer(&self, session_id: u64) -> Option<ViewerLink> {
        self.viewers.lock().unwrap_or_else(|e| e.into_inner()).remove(&session_id)
    }

    /// Asks the node to stop and waits for it.
    pub fn shutdown(mut self) {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for NodeHandle {
    fn drop(&mut self) {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Starts a node on its own thread with its own async runtime.
///
/// Returns immediately. Everything the node learns — including a failure to
/// start at all — arrives through `sink`.
pub fn start(dirs: NodeDirs, sink: EventSink) -> NodeHandle {
    let (tx, rx) = mpsc::unbounded_channel();
    let viewers: ViewerSlots = Arc::default();
    let viewers_for_node = viewers.clone();
    let thread = std::thread::Builder::new()
        .name("bark-node".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("bark-net")
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    sink(Event::Fatal(format!("BARK could not start its network runtime: {e}")));
                    return;
                }
            };
            rt.block_on(async move {
                if let Err(e) = run(dirs, rx, sink.clone(), viewers_for_node).await {
                    tracing::error!("node stopped: {e}");
                    sink(Event::Fatal(e.explain()));
                }
            });
        })
        .expect("spawning a thread only fails when the process is out of resources");
    NodeHandle { tx, thread: Some(thread), viewers }
}

/// The node's connection to the coordination server.
enum Link {
    /// No server configured.
    Idle,
    Connecting { task: JoinHandle<Result<ControlConnection>>, address: String },
    Online { conn: Box<ControlConnection>, address: String },
    Waiting { until: Instant, address: String, error: String, delay: Duration },
}

enum Step {
    Command(Option<Command>),
    Connected(Result<ControlConnection>),
    Server(Option<ToNode>),
    Internal(Internal),
    Retry,
    Tick,
}

/// Reports from the node's own background tasks.
enum Internal {
    /// Someone is connecting to this computer's socket.
    Incoming(quinn::Incoming),
    /// A connection this computer asked for finished setting up, or failed.
    Outgoing { request_id: u64, result: Result<Established> },
    /// A connection to this computer finished setting up, or failed.
    Inbound(Result<Established>),
    Ended { session_id: u64, reason: String },
}

/// A `Connect` in progress.
struct Outgoing {
    device: Fingerprint,
    /// Taken from this computer's own trust store, never from the server: the
    /// handshake must prove the answer came from the device the operator meant.
    expected: PublicIdentity,
    started: Instant,
    stage: OutStage,
}

enum OutStage {
    /// Waiting for the remote to accept the introduction.
    Introducing,
    Direct,
    /// Direct failed (or was skipped); waiting on the relay.
    Relay { direct_error: String },
}

/// A connection this computer has agreed to accept, and until when.
struct Expected {
    exchange_id: u64,
    until: std::time::Instant,
}

/// Which devices may complete a session handshake with this computer right
/// now. Filled only when this computer accepts an introduction, emptied as
/// each is used or expires; an incoming connection with nothing expected is
/// refused before any cryptography happens.
type Gate = Arc<Mutex<HashMap<Fingerprint, Expected>>>;

fn gate_take(gate: &Gate, who: &PublicIdentity) -> std::result::Result<(), (FailureReason, String)> {
    let mut g = gate.lock().unwrap_or_else(|e| e.into_inner());
    match g.remove(&who.fingerprint()) {
        Some(e) if e.until > std::time::Instant::now() => Ok(()),
        _ => Err((FailureReason::Refused, "This computer was not expecting a session from you.".into())),
    }
}

/// A running session, in either direction.
struct SessionEntry {
    device: Fingerprint,
    name: String,
    remote_address: String,
    started_unix_us: u64,
    controller: bool,
    path: PathKind,
    host_cmd: Option<mpsc::UnboundedSender<HostCommand>>,
    task: JoinHandle<()>,
}

async fn wait_link(link: &mut Link) -> Step {
    match link {
        Link::Idle => std::future::pending().await,
        Link::Connecting { task, .. } => Step::Connected(match task.await {
            Ok(r) => r,
            Err(e) => Err(BarkError::other(format!("the connection task failed: {e}"))),
        }),
        Link::Online { conn, .. } => Step::Server(conn.next_event().await),
        Link::Waiting { until, .. } => {
            tokio::time::sleep_until(*until).await;
            Step::Retry
        }
    }
}

/// The coordination-server role, when this computer hosts it.
struct ServerRole {
    state: Arc<bark_server::ServerState>,
    tasks: (JoinHandle<()>, JoinHandle<()>),
    relay_task: Option<JoinHandle<()>>,
    listening: SocketAddr,
    bind: String,
    relay_wanted: (bool, u16),
    key: [u8; 32],
    key_text: String,
}

impl Drop for ServerRole {
    fn drop(&mut self) {
        self.tasks.0.abort();
        self.tasks.1.abort();
        if let Some(t) = &self.relay_task {
            t.abort();
        }
    }
}

/// A pairing this computer asked for, while it is in progress.
struct PendingPair {
    device_id: DeviceId,
    code: String,
    name: String,
    started: Instant,
    stage: PairStage,
}

enum PairStage {
    Resolving,
    Waiting { peer: PublicIdentity, request_id: u64 },
}

struct Node {
    dirs: NodeDirs,
    sink: EventSink,
    identity: Arc<DeviceIdentity>,
    trust: TrustStore,
    config: NodeConfig,
    machine: MachineInfo,
    presence: PresenceTable,

    /// The node's one socket, the server key it was made for, and the task
    /// accepting connections on it.
    socket: Option<(NodeSocket, [u8; 32], JoinHandle<()>)>,
    server_role: Option<ServerRole>,
    server_addr: Option<SocketAddr>,
    internal: mpsc::UnboundedSender<Internal>,
    gate: Gate,
    outgoing: HashMap<u64, Outgoing>,
    sessions: HashMap<u64, SessionEntry>,
    next_session_id: u64,
    viewers: ViewerSlots,

    pairing_code: Option<PairingCode>,
    pair_limiters: HashMap<Fingerprint, AttemptLimiter>,
    pending_pair: Option<PendingPair>,
    next_request_id: u64,

    ping_sent: Option<u64>,
    last_ping: Instant,
    rtt_us: Option<u32>,
    public_address: String,
    server_version: String,

    last_status: Option<NodeStatus>,
    last_devices: Option<Vec<DeviceView>>,

    /// Cached, because listing adapters is a system call and the list only
    /// changes when the machine moves networks.
    local_addresses: Vec<String>,
    addresses_checked: Instant,
}

async fn run(
    dirs: NodeDirs,
    mut rx: mpsc::UnboundedReceiver<Command>,
    sink: EventSink,
    viewers: ViewerSlots,
) -> Result<()> {
    dirs.ensure()?;
    let (identity, created) = DeviceIdentity::load_or_create_at(&dirs.identity())?;
    if created {
        tracing::info!(device = %identity.device_id(), "created a new device identity");
    }
    let trust = TrustStore::load_from(&dirs.trust())?;
    let config = NodeConfig::load(&dirs.config())?;
    let (internal, mut internal_rx) = mpsc::unbounded_channel();

    let mut node = Node {
        dirs,
        sink,
        identity: Arc::new(identity),
        trust,
        config,
        machine: MachineInfo::collect(),
        presence: PresenceTable::new(),
        socket: None,
        server_role: None,
        server_addr: None,
        internal,
        gate: Arc::default(),
        outgoing: HashMap::new(),
        sessions: HashMap::new(),
        next_session_id: 1,
        viewers,
        pairing_code: None,
        pair_limiters: HashMap::new(),
        pending_pair: None,
        next_request_id: 1,
        ping_sent: None,
        last_ping: Instant::now(),
        rtt_us: None,
        public_address: String::new(),
        server_version: String::new(),
        last_status: None,
        last_devices: None,
        local_addresses: describe_local_addresses(),
        addresses_checked: Instant::now(),
    };

    node.apply_server_role().await;
    let mut link = node.start_link();
    node.publish(&link, true);

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let step = tokio::select! {
            cmd = rx.recv() => Step::Command(cmd),
            s = wait_link(&mut link) => s,
            Some(i) = internal_rx.recv() => Step::Internal(i),
            _ = tick.tick() => Step::Tick,
        };

        match step {
            Step::Command(None) | Step::Command(Some(Command::Shutdown)) => {
                for (_, s) in node.sessions.drain() {
                    s.task.abort();
                }
                if let Link::Online { conn, .. } = link {
                    conn.close().await;
                }
                let _ = node.trust.flush_presence();
                return Ok(());
            }
            Step::Command(Some(cmd)) => node.handle_command(cmd, &mut link).await,
            Step::Connected(Ok(conn)) => {
                let address = match &link {
                    Link::Connecting { address, .. } => address.clone(),
                    _ => String::new(),
                };
                node.public_address = conn.public_address().to_string();
                node.server_version = conn.greeting().server_version.clone();
                node.rtt_us = Some((conn.greeting().received_us - conn.greeting().sent_us) as u32);
                node.server_addr = Some(conn.server_address());
                tracing::info!(%address, public = %node.public_address, "signed in to the BARK server");
                link = Link::Online { conn: Box::new(conn), address };
                node.watch_presence(&link).await;
            }
            Step::Connected(Err(e)) => {
                link = node.link_failed(&link, e.to_string());
            }
            Step::Server(Some(msg)) => node.handle_server(msg, &mut link).await,
            Step::Internal(i) => node.handle_internal(i, &link).await,
            Step::Server(None) => {
                link = node.link_failed(&link, "the connection to the BARK server was lost".into());
            }
            Step::Retry => link = node.start_link(),
            Step::Tick => node.on_tick(&link).await,
        }

        node.publish(&link, false);
    }
}

impl Node {
    // ------------------------------------------------------------ plumbing

    fn emit(&self, e: Event) {
        (self.sink)(e);
    }

    fn notice(&self, level: NoticeLevel, text: impl Into<String>) {
        self.emit(Event::Notice { level, text: text.into() });
    }

    fn request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id += 1;
        id
    }

    async fn send(&self, link: &Link, msg: ToServer) -> bool {
        match link {
            Link::Online { conn, .. } => conn.send(msg).await.is_ok(),
            _ => false,
        }
    }

    fn machine_for_peers(&self) -> MachineInfo {
        let mut m = self.machine.clone();
        m.hostname = self.config.effective_name();
        m
    }

    // ------------------------------------------------------ server link

    /// Where to sign in, and which key to pin.
    fn effective_server(&self) -> Option<Result<(String, [u8; 32])>> {
        if let Some(role) = &self.server_role {
            return Some(Ok((format!("127.0.0.1:{}", role.listening.port()), role.key)));
        }
        let target = self.config.server.as_ref()?;
        Some(target.key_bytes().map(|k| (target.address_with_port(), k)))
    }

    /// The node's one socket, recreated only when the pinned key changes.
    fn endpoint_for(&mut self, key: [u8; 32], loopback: bool) -> Result<quinn::Endpoint> {
        if let Some((s, k, _)) = &self.socket {
            if *k == key {
                return Ok(s.endpoint.clone());
            }
        }
        if let Some((_, _, accepting)) = self.socket.take() {
            accepting.abort();
        }
        // A node whose server is on this very computer is a single-machine
        // setup; binding to loopback there avoids a pointless firewall prompt.
        let bind = if loopback {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
        } else {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
        };
        let creds = TransportCredentials::generate()?;
        let socket = NodeSocket::bind(bind, &creds, pinned_client_config(key)?)?;
        let ep = socket.endpoint.clone();
        let tx = self.internal.clone();
        let accepting_ep = ep.clone();
        let accepting = tokio::spawn(async move {
            while let Some(incoming) = accepting_ep.accept().await {
                if tx.send(Internal::Incoming(incoming)).is_err() {
                    break;
                }
            }
        });
        self.socket = Some((socket, key, accepting));
        Ok(ep)
    }

    fn start_link(&mut self) -> Link {
        let (address, key) = match self.effective_server() {
            None => return Link::Idle,
            Some(Err(e)) => {
                return Link::Waiting {
                    until: Instant::now() + BACKOFF_MAX,
                    address: String::new(),
                    error: e.to_string(),
                    delay: BACKOFF_MAX,
                }
            }
            Some(Ok(v)) => v,
        };
        // Loopback only for a genuinely single-machine setup. A computer that
        // hosts the server role for others signs in to itself over 127.0.0.1,
        // but must still listen on its real network addresses, or no other
        // computer could ever open a session to it.
        let loopback = match &self.server_role {
            Some(role) => role.listening.ip().is_loopback(),
            None => address.starts_with("127.") || address.to_ascii_lowercase().starts_with("localhost"),
        };
        let endpoint = match self.endpoint_for(key, loopback) {
            Ok(e) => e,
            Err(e) => {
                return Link::Waiting {
                    until: Instant::now() + BACKOFF_MAX,
                    address,
                    error: e.to_string(),
                    delay: BACKOFF_MAX,
                }
            }
        };

        let port = endpoint.local_addr().map(|a| a.port()).unwrap_or(0);
        let locals: Vec<SocketAddr> = if loopback {
            Vec::new()
        } else {
            bark_net::interfaces::local_ipv4_addresses()
                .into_iter()
                .map(|a| SocketAddr::new(IpAddr::V4(a.ip), port))
                .collect()
        };

        let identity = self.identity.clone();
        let machine = self.machine_for_peers();
        let addr_for_task = address.clone();
        let task = tokio::spawn(async move {
            let target = resolve(&addr_for_task).await?;
            ControlConnection::login(&endpoint, target, key, &identity, machine, locals).await
        });
        Link::Connecting { task, address }
    }

    fn link_failed(&mut self, link: &Link, error: String) -> Link {
        let (address, delay) = match link {
            Link::Waiting { address, delay, .. } => (address.clone(), (*delay * 2).min(BACKOFF_MAX)),
            Link::Connecting { address, .. } | Link::Online { address, .. } => {
                (address.clone(), BACKOFF_START)
            }
            Link::Idle => (String::new(), BACKOFF_START),
        };
        tracing::info!(%address, "not connected to the BARK server: {error}");
        self.presence.invalidate();
        self.rtt_us = None;
        self.ping_sent = None;
        // Connection attempts still waiting on the server cannot finish.
        let stalled: Vec<u64> = self
            .outgoing
            .iter()
            .filter(|(_, o)| !matches!(o.stage, OutStage::Direct))
            .map(|(id, _)| *id)
            .collect();
        for id in stalled {
            if let Some(o) = self.outgoing.remove(&id) {
                self.emit(Event::ConnectFinished {
                    device: o.device,
                    ok: false,
                    message: "The connection to the BARK server was lost while connecting. Try again.".into(),
                });
            }
        }
        // An in-flight pairing cannot complete without the server.
        if self.pending_pair.take().is_some() {
            self.emit(Event::PairFinished {
                ok: false,
                message: "The connection to the BARK server was lost before pairing finished. Try again.".into(),
                device: None,
            });
        }
        Link::Waiting { until: Instant::now() + delay, address, error, delay }
    }

    async fn watch_presence(&self, link: &Link) {
        let devices: Vec<Fingerprint> = self
            .trust
            .iter()
            .filter(|e| !e.revoked)
            .map(|e| e.fingerprint())
            .collect();
        self.send(link, ToServer::WatchPresence { devices }).await;
    }

    // ----------------------------------------------------- server role

    /// Starts or stops the coordination-server role to match the settings.
    async fn apply_server_role(&mut self) {
        let want = self.config.roles.coordination_server;
        let port = self.config.roles.server_port;
        let bind = self.config.roles.server_bind.trim().to_string();
        let relay = (self.config.roles.relay, self.config.roles.relay_port);
        match (&self.server_role, want) {
            (Some(r), true) if r.listening.port() == port && r.bind == bind && r.relay_wanted == relay => return,
            (None, false) => return,
            _ => {}
        }
        self.server_role = None;
        if !want {
            return;
        }
        match start_server_role(&self.dirs, &bind, port, relay).await {
            Ok(role) => {
                tracing::info!(listening = %role.listening, "coordination server role started");
                self.server_role = Some(role);
            }
            Err(e) => {
                self.notice(
                    NoticeLevel::Error,
                    format!("This computer could not start as the BARK server.\n\n{}", e.explain()),
                );
            }
        }
    }

    // --------------------------------------------------------- commands

    async fn handle_command(&mut self, cmd: Command, link: &mut Link) {
        match cmd {
            Command::Shutdown => {}
            Command::Refresh => {
                self.last_status = None;
                self.last_devices = None;
            }
            Command::ShowPairingCode => {
                let reuse = self.pairing_code.as_ref().is_some_and(|c| !c.is_expired());
                if !reuse {
                    match PairingCode::generate() {
                        Ok(c) => self.pairing_code = Some(c),
                        Err(e) => {
                            self.notice(NoticeLevel::Error, e.explain());
                            return;
                        }
                    }
                }
                self.emit_pairing_code();
            }
            Command::HidePairingCode => {
                self.pairing_code = None;
                self.emit(Event::PairingCode(None));
            }
            Command::Pair { device_id, code, name } => self.start_pair(link, device_id, code, name).await,
            Command::Connect { device } => self.start_connect(link, device).await,
            Command::Remove { device } => {
                if let Err(e) = self.trust.remove(&device) {
                    self.notice(NoticeLevel::Error, e.explain());
                }
                self.watch_presence(link).await;
            }
            Command::Revoke { device } => {
                if let Err(e) = self.trust.revoke(&device) {
                    self.notice(NoticeLevel::Error, e.explain());
                    return;
                }
                // Revocation takes effect now, not at the next session.
                self.gate.lock().unwrap_or_else(|e| e.into_inner()).remove(&device);
                for s in self.sessions.values().filter(|s| s.device == device) {
                    match &s.host_cmd {
                        Some(tx) => {
                            let _ = tx.send(HostCommand::End);
                        }
                        None => s.task.abort(),
                    }
                }
                // Tell the server too, so it stops introducing that device to
                // us. This affects only this pair; see the server's handler.
                let mut signed = Vec::with_capacity(64);
                signed.extend_from_slice(device.as_bytes());
                signed.extend_from_slice(self.identity.fingerprint().as_bytes());
                let signature = self.identity.sign(context::REVOCATION, &signed);
                self.send(link, ToServer::Revoke { peer: device, signature: signature.into() }).await;
                self.watch_presence(link).await;
            }
            Command::Rename { device, name } => {
                if let Err(e) = self.trust.rename(&device, name.trim()) {
                    self.notice(NoticeLevel::Error, e.explain());
                }
            }
            Command::SetDetails { device, description, group } => {
                let r = self
                    .trust
                    .set_description(&device, description.trim())
                    .and_then(|_| self.trust.set_group(&device, group.trim()));
                if let Err(e) = r {
                    self.notice(NoticeLevel::Error, e.explain());
                }
            }
            Command::EndHostSession { session_id } => {
                if let Some(tx) = self.sessions.get(&session_id).and_then(|s| s.host_cmd.as_ref()) {
                    let _ = tx.send(HostCommand::End);
                }
            }
            Command::SetConfig(new) => {
                if let Err(e) = new.validate() {
                    self.notice(NoticeLevel::Error, e.explain());
                    return;
                }
                let server_changed = new.server != self.config.server || new.roles != self.config.roles;
                if let Err(e) = new.save(&self.dirs.config()) {
                    self.notice(NoticeLevel::Error, format!("The settings could not be saved.\n\n{}", e.explain()));
                    return;
                }
                self.config = new;
                if server_changed {
                    if let Link::Online { conn, .. } = std::mem::replace(link, Link::Idle) {
                        conn.close().await;
                    }
                    self.presence.invalidate();
                    self.apply_server_role().await;
                    *link = self.start_link();
                }
                self.notice(NoticeLevel::Info, "Settings saved.");
            }
        }
    }

    fn emit_pairing_code(&self) {
        let view = self.pairing_code.as_ref().filter(|c| !c.is_expired()).map(|c| PairingCodeView {
            code: c.display(),
            seconds_left: c.seconds_remaining(),
        });
        self.emit(Event::PairingCode(view));
    }

    async fn start_pair(&mut self, link: &Link, device_id: String, code: String, name: String) {
        let fail = |this: &Self, msg: String| {
            this.emit(Event::PairFinished { ok: false, message: msg, device: None });
        };

        let Some(id) = DeviceId::parse(&device_id) else {
            return fail(self, format!("\"{}\" is not a valid Device ID. A Device ID looks like BA-4K7P-2WQX.", device_id.trim()));
        };
        if id == self.identity.device_id() {
            return fail(self, "That is this computer's own Device ID. Enter the ID shown on the other computer.".into());
        }
        if CodeCommitment::create(&code).is_err() {
            return fail(self, "The pairing code should be six letters and digits, like 7KQ-2WX.".into());
        }
        if !matches!(link, Link::Online { .. }) {
            return fail(self, "This computer is not connected to the BARK server, so it cannot pair right now. Check Tools > Settings and the status bar.".into());
        }
        if self.pending_pair.is_some() {
            return fail(self, "A pairing is already in progress. Wait for it to finish.".into());
        }

        self.pending_pair = Some(PendingPair {
            device_id: id,
            code,
            name: name.trim().to_string(),
            started: Instant::now(),
            stage: PairStage::Resolving,
        });
        self.send(link, ToServer::Resolve { device_id: id }).await;
    }

    async fn start_connect(&mut self, link: &Link, device: Fingerprint) {
        let fail = |this: &Self, msg: &str| {
            this.emit(Event::ConnectFinished { device, ok: false, message: msg.to_string() });
        };
        let Some(entry) = self.trust.get(&device) else {
            return fail(self, "That device is not paired with this computer.");
        };
        if entry.revoked {
            return fail(self, "That device's pairing was revoked. Pair it again to connect.");
        }
        if !entry.we_may_control {
            return fail(self, "This computer is not permitted to control that device. It paired with you, not the other way round.");
        }
        if !matches!(link, Link::Online { .. }) {
            return fail(self, "This computer is not connected to the BARK server.");
        }
        if self.outgoing.values().any(|o| o.device == device) {
            return fail(self, "A connection to that device is already being made.");
        }
        let expected = entry.public;
        let request_id = self.request_id();
        self.outgoing.insert(
            request_id,
            Outgoing { device, expected, started: Instant::now(), stage: OutStage::Introducing },
        );
        self.emit(Event::ConnectProgress { device, text: "Asking the remote computer...".into() });
        // Candidates are added by the server: the addresses this computer
        // listed when it signed in, plus the public address it sees.
        self.send(link, ToServer::ConnectRequest { target: device, request_id, candidates: Vec::new() }).await;
    }

    fn fail_outgoing(&mut self, request_id: u64, message: String) {
        if let Some(o) = self.outgoing.remove(&request_id) {
            tracing::info!(device = %o.device.short_id(), "connect failed: {message}");
            self.emit(Event::ConnectFinished { device: o.device, ok: false, message });
        }
    }

    /// Starts the direct attempt for an accepted introduction.
    fn dial_direct(&mut self, request_id: u64, candidates: Vec<Candidate>) {
        let Some(o) = self.outgoing.get_mut(&request_id) else { return };
        let Some((socket, _, _)) = &self.socket else { return };
        o.stage = OutStage::Direct;
        let device = o.device;
        let expected = o.expected;
        let endpoint = socket.endpoint.clone();
        let identity = self.identity.clone();
        let tx = self.internal.clone();
        let tried = candidates.iter().map(|c| c.addr.to_string()).collect::<Vec<_>>().join(", ");
        self.emit(Event::ConnectProgress { device, text: format!("Connecting directly ({tried})...") });
        tokio::spawn(async move {
            let result = async {
                let d = peer::dial(&endpoint, &candidates, peer::DIRECT_TIMEOUT).await?;
                let path = classify_direct(d.conn.remote_address());
                let session = peer::open_session(d.conn, &identity, &expected).await?;
                Ok(Established { session, path, endpoint: None })
            }
            .await;
            let _ = tx.send(Internal::Outgoing { request_id, result });
        });
    }

    /// Asks the server for a relay after direct failed or was skipped.
    async fn request_relay(&mut self, link: &Link, request_id: u64, direct_error: String) {
        let Some(o) = self.outgoing.get_mut(&request_id) else { return };
        o.stage = OutStage::Relay { direct_error };
        let device = o.device;
        self.emit(Event::ConnectProgress { device, text: "No direct path. Trying the relay...".into() });
        if !self.send(link, ToServer::RelayRequest { request_id }).await {
            self.fail_outgoing(request_id, "The connection to the BARK server was lost while connecting.".into());
        }
    }

    /// A relay the server announced as listening on "any address" is reached
    /// at the address this computer reaches the server on.
    fn relay_target(&self, announced: SocketAddr) -> SocketAddr {
        match (announced.ip().is_unspecified(), self.server_addr) {
            (true, Some(server)) => SocketAddr::new(server.ip(), announced.port()),
            _ => announced,
        }
    }

    // ------------------------------------------------------ server messages

    async fn handle_server(&mut self, msg: ToNode, link: &mut Link) {
        if self.presence.apply(&msg) {
            if let ToNode::Presence { device, online: true, last_seen_unix_us, .. } = &msg {
                self.trust.note_seen(device, (*last_seen_unix_us).max(bark_core::clock::unix_us()));
            }
            return;
        }

        match msg {
            ToNode::Pong { sent_us, .. } => {
                if self.ping_sent == Some(sent_us) {
                    self.rtt_us = Some(bark_core::clock::now_us().saturating_sub(sent_us) as u32);
                    self.ping_sent = None;
                }
            }

            ToNode::Resolved { device_id, identity } => {
                let Some(p) = &self.pending_pair else { return };
                if p.device_id != device_id || !matches!(p.stage, PairStage::Resolving) {
                    return;
                }
                let Some(peer) = identity else {
                    self.pending_pair = None;
                    self.emit(Event::PairFinished {
                        ok: false,
                        message: format!(
                            "No device with ID {device_id} is registered with the BARK server.\n\n\
                             Check the ID, and check that the other computer is set up to use the \
                             same BARK server."
                        ),
                        device: None,
                    });
                    return;
                };
                let commitment = match CodeCommitment::create(&p.code) {
                    Ok(c) => c,
                    Err(e) => {
                        self.pending_pair = None;
                        self.emit(Event::PairFinished { ok: false, message: e.to_string(), device: None });
                        return;
                    }
                };
                let request_id = self.request_id();
                let our_name = self.config.effective_name();
                let machine = self.machine_for_peers();
                if let Some(p) = &mut self.pending_pair {
                    p.stage = PairStage::Waiting { peer, request_id };
                }
                self.send(
                    link,
                    ToServer::PairRequest {
                        target: peer.fingerprint(),
                        request_id,
                        code_nonce: commitment.nonce,
                        code_digest: commitment.digest,
                        our_name,
                        machine,
                    },
                )
                .await;
            }

            ToNode::PairResult { request_id, accepted, reason, peer, machine, name } => {
                let Some(p) = &self.pending_pair else { return };
                let PairStage::Waiting { peer: expected, request_id: rid } = &p.stage else { return };
                if *rid != request_id {
                    return;
                }
                let expected = *expected;
                let chosen_name = if !p.name.is_empty() {
                    p.name.clone()
                } else {
                    name.clone().or_else(|| machine.as_ref().map(|m| m.hostname.clone())).unwrap_or_default()
                };
                self.pending_pair = None;

                if !accepted || peer.map(|x| x.fingerprint()) != Some(expected.fingerprint()) {
                    let why = match reason {
                        Some(FailureReason::BadPairingCode) => {
                            "The pairing code was not correct, or it has expired.\n\n\
                             On the other computer choose Tools > Show Pairing Code and enter the \
                             code it shows. Codes stay valid for 10 minutes."
                                .to_string()
                        }
                        Some(FailureReason::RateLimited) => {
                            "Too many incorrect codes were tried. Wait a few minutes and try again.".to_string()
                        }
                        Some(r) => r.message().to_string(),
                        None => "The other computer did not accept the pairing.".to_string(),
                    };
                    self.emit(Event::PairFinished { ok: false, message: why, device: None });
                    return;
                }

                match self.trust.pair(expected, &chosen_name, Grant::Outbound, machine.as_ref()) {
                    Ok(_) => {
                        let view = self.view_of(&expected.fingerprint());
                        self.emit(Event::PairFinished {
                            ok: true,
                            message: format!("Paired with {chosen_name}. It is now in your favorites."),
                            device: view,
                        });
                        self.watch_presence(link).await;
                    }
                    Err(e) => self.emit(Event::PairFinished { ok: false, message: e.explain(), device: None }),
                }
            }

            ToNode::PairOffer { from, request_id, code_nonce, code_digest, their_name, machine } => {
                let fp = from.fingerprint();
                let limiter = self.pair_limiters.entry(fp).or_default();
                let verdict: std::result::Result<(), FailureReason> = if limiter.check().is_err() {
                    Err(FailureReason::RateLimited)
                } else {
                    match &self.pairing_code {
                        Some(code)
                            if !code.is_expired()
                                && (CodeCommitment { nonce: code_nonce, digest: code_digest }).matches(code) =>
                        {
                            Ok(())
                        }
                        _ => {
                            limiter.record_failure();
                            Err(FailureReason::BadPairingCode)
                        }
                    }
                };

                match verdict {
                    Ok(()) => {
                        if let Some(l) = self.pair_limiters.get_mut(&fp) {
                            l.record_success();
                        }
                        let name = if their_name.trim().is_empty() { machine.hostname.clone() } else { their_name };
                        match self.trust.pair(from, &name, Grant::Inbound, Some(&machine)) {
                            Ok(_) => {
                                // Single use: a code that paired one device is spent.
                                self.pairing_code = None;
                                self.emit(Event::PairingCode(None));
                                let answer = ToServer::PairAnswer {
                                    request_id,
                                    accept: true,
                                    reason: None,
                                    machine: Some(self.machine_for_peers()),
                                    name: Some(self.config.effective_name()),
                                };
                                self.send(link, answer).await;
                                if let Some(v) = self.view_of(&fp) {
                                    self.emit(Event::PairedBy { device: v });
                                }
                                self.watch_presence(link).await;
                            }
                            Err(e) => {
                                self.notice(NoticeLevel::Error, e.explain());
                                self.send(
                                    link,
                                    ToServer::PairAnswer {
                                        request_id,
                                        accept: false,
                                        reason: Some(FailureReason::ServerError),
                                        machine: None,
                                        name: None,
                                    },
                                )
                                .await;
                            }
                        }
                    }
                    Err(reason) => {
                        tracing::info!(from = %from.device_id(), ?reason, "refused a pairing request");
                        self.send(
                            link,
                            ToServer::PairAnswer { request_id, accept: false, reason: Some(reason), machine: None, name: None },
                        )
                        .await;
                    }
                }
            }

            ToNode::ConnectOffer { from, request_id, candidates, .. } => {
                // This is the gate that actually protects this computer: the
                // server introduced someone, and only this trust store decides.
                let verdict = if !self.config.accept_incoming {
                    Err(FailureReason::Refused)
                } else {
                    match self.trust.authorise_inbound(&from) {
                        Ok(_) => Ok(()),
                        Err(BarkError::Revoked(_)) => Err(FailureReason::Revoked),
                        Err(_) => Err(FailureReason::NotPaired),
                    }
                };
                let verdict = verdict.and_then(|()| {
                    let hosting = self.sessions.values().filter(|s| !s.controller).count();
                    if hosting >= MAX_HOST_SESSIONS {
                        Err(FailureReason::RateLimited)
                    } else {
                        Ok(())
                    }
                });
                tracing::info!(from = %from.device_id(), ok = verdict.is_ok(), "connection offer");
                let (accept, reason) = match verdict {
                    Ok(()) => (true, None),
                    Err(r) => (false, Some(r)),
                };
                if accept {
                    self.gate.lock().unwrap_or_else(|e| e.into_inner()).insert(
                        from.fingerprint(),
                        Expected { exchange_id: request_id, until: std::time::Instant::now() + INBOUND_WINDOW },
                    );
                    // Open this computer's NAT towards every address the
                    // controller might dial from, before saying yes.
                    if let Some((socket, _, _)) = &self.socket {
                        let targets: Vec<SocketAddr> = candidates.iter().map(|c| c.addr).collect();
                        tokio::spawn(peer::punch(socket.raw(), targets, peer::PUNCH_DURATION));
                    }
                }
                self.send(link, ToServer::ConnectAnswer { request_id, accept, reason, candidates: Vec::new() })
                    .await;
            }

            ToNode::ConnectResult { request_id, accepted, reason, candidates, .. } => {
                let Some(o) = self.outgoing.get(&request_id) else { return };
                if !matches!(o.stage, OutStage::Introducing) {
                    return;
                }
                if !accepted {
                    let message = reason
                        .map(|r| r.message().to_string())
                        .unwrap_or_else(|| "The connection was refused.".into());
                    return self.fail_outgoing(request_id, message);
                }
                if self.config.force_relay {
                    self.request_relay(link, request_id, "skipped (force_relay is set)".into()).await;
                } else {
                    self.dial_direct(request_id, candidates);
                }
            }

            ToNode::RelayReady { request_id, relay_address, token } => {
                let relay = self.relay_target(relay_address);
                let identity = self.identity.clone();
                let tx = self.internal.clone();
                if let Some(o) = self.outgoing.get(&request_id) {
                    if !matches!(o.stage, OutStage::Relay { .. }) {
                        return;
                    }
                    let expected = o.expected;
                    self.emit(Event::ConnectProgress { device: o.device, text: format!("Connecting through the relay ({relay})...") });
                    tokio::spawn(async move {
                        let result = async {
                            let (endpoint, conn) = peer::dial_relay(relay, token).await?;
                            let session = peer::open_session(conn, &identity, &expected).await?;
                            Ok(Established { session, path: PathKind::Relayed, endpoint: Some(endpoint) })
                        }
                        .await;
                        let _ = tx.send(Internal::Outgoing { request_id, result });
                    });
                    return;
                }
                // Otherwise it is for a connection this computer accepted.
                let expected_here = self
                    .gate
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .values()
                    .any(|e| e.exchange_id == request_id);
                if !expected_here {
                    return;
                }
                let gate = self.gate.clone();
                tokio::spawn(async move {
                    let result = async {
                        let (endpoint, conn) = peer::accept_relay(relay, token).await?;
                        let session = peer::accept_session(conn, &identity, |who| gate_take(&gate, who)).await?;
                        Ok(Established { session, path: PathKind::Relayed, endpoint: Some(endpoint) })
                    }
                    .await;
                    let _ = tx.send(Internal::Inbound(result));
                });
            }

            ToNode::RelayUnavailable { request_id, detail } => {
                let Some(o) = self.outgoing.get(&request_id) else { return };
                let OutStage::Relay { direct_error } = &o.stage else { return };
                let message = format!("{direct_error}\n\nThe relay could not be used either: {detail}");
                self.fail_outgoing(request_id, message);
            }

            ToNode::Error { reason, detail } => {
                self.notice(NoticeLevel::Warning, if detail.is_empty() { reason.message().to_string() } else { detail });
            }

            _ => {}
        }
    }

    // ------------------------------------------------------- sessions

    async fn handle_internal(&mut self, msg: Internal, link: &Link) {
        match msg {
            Internal::Incoming(incoming) => {
                let expecting = {
                    let now = std::time::Instant::now();
                    let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
                    g.retain(|_, e| e.until > now);
                    !g.is_empty()
                };
                if !expecting {
                    // Nothing was introduced, so nobody may connect. Refused
                    // before any TLS or signature work is spent on it.
                    tracing::debug!(from = %incoming.remote_address(), "refused an unexpected connection");
                    incoming.refuse();
                    return;
                }
                let identity = self.identity.clone();
                let gate = self.gate.clone();
                let tx = self.internal.clone();
                tokio::spawn(async move {
                    let result = async {
                        let conn = incoming
                            .await
                            .map_err(|e| BarkError::Network(format!("an incoming connection failed: {e}")))?;
                        let path = classify_direct(conn.remote_address());
                        let session = peer::accept_session(conn, &identity, |who| gate_take(&gate, who)).await?;
                        Ok(Established { session, path, endpoint: None })
                    }
                    .await;
                    let _ = tx.send(Internal::Inbound(result));
                });
            }

            Internal::Outgoing { request_id, result } => {
                let Some(o) = self.outgoing.get(&request_id) else { return };
                match result {
                    Ok(est) => {
                        let o = self.outgoing.remove(&request_id).expect("just found");
                        self.open_controller_session(o, est);
                    }
                    Err(e) => match &o.stage {
                        OutStage::Direct => {
                            tracing::info!(device = %o.device.short_id(), "direct connection failed: {e}");
                            self.request_relay(link, request_id, e.explain()).await;
                        }
                        OutStage::Relay { direct_error } => {
                            let message = format!("{direct_error}\n\nThe relay was tried too: {}", e.explain());
                            self.fail_outgoing(request_id, message);
                        }
                        OutStage::Introducing => {}
                    },
                }
            }

            Internal::Inbound(Ok(est)) => self.open_host_session(est),
            Internal::Inbound(Err(e)) => {
                // Not shown to the user: anyone on the network can cause this.
                tracing::info!("an incoming session did not start: {e}");
            }

            Internal::Ended { session_id, reason } => {
                let Some(s) = self.sessions.remove(&session_id) else { return };
                self.viewers.lock().unwrap_or_else(|e| e.into_inner()).remove(&session_id);
                if s.controller {
                    self.emit(Event::SessionClosed { session_id, device: s.device, reason });
                } else {
                    self.emit(Event::HostSessionEnded { session_id, device: s.device, reason });
                }
            }
        }
    }

    fn open_controller_session(&mut self, o: Outgoing, est: Established) {
        let session_id = self.next_session_id;
        self.next_session_id += 1;
        let name = self.trust.get(&o.device).map(|e| e.name.clone()).unwrap_or_default();
        let path = est.path;
        let remote_address = est.remote_address().to_string();
        let verification = est.session.verification.clone();
        let connect_ms = o.started.elapsed().as_millis() as u32;
        let _ = self.trust.note_connected(&o.device);

        let (viewer, end) = crate::viewer::link(session_id);
        self.viewers.lock().unwrap_or_else(|e| e.into_inner()).insert(session_id, viewer);
        let tx = self.internal.clone();
        let task = tokio::spawn(async move {
            let reason = crate::session::run_controller(est, end, DEFAULT_VIEW).await;
            let _ = tx.send(Internal::Ended { session_id, reason });
        });
        self.sessions.insert(
            session_id,
            SessionEntry {
                device: o.device,
                name: name.clone(),
                remote_address: remote_address.clone(),
                started_unix_us: bark_core::clock::unix_us(),
                controller: true,
                path,
                host_cmd: None,
                task,
            },
        );
        tracing::info!(device = %o.device.short_id(), path = path.describe(), %remote_address, connect_ms, "session opened");
        self.emit(Event::SessionOpened {
            session_id,
            device: o.device,
            name,
            path: path.describe().to_string(),
            remote_address,
            verification,
            connect_ms,
        });
    }

    fn open_host_session(&mut self, est: Established) {
        let device = est.session.peer.fingerprint();
        let session_id = self.next_session_id;
        self.next_session_id += 1;
        let name = self.trust.get(&device).map(|e| e.name.clone()).unwrap_or_else(|| device.short_id().to_string());
        let path = est.path;
        let remote_address = est.remote_address().to_string();
        let verification = est.session.verification.clone();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let tx = self.internal.clone();
        let our_name = self.config.effective_name();
        let task = tokio::spawn(async move {
            let reason = crate::session::run_host(est, our_name, cmd_rx).await;
            let _ = tx.send(Internal::Ended { session_id, reason });
        });
        self.sessions.insert(
            session_id,
            SessionEntry {
                device,
                name: name.clone(),
                remote_address,
                started_unix_us: bark_core::clock::unix_us(),
                controller: false,
                path,
                host_cmd: Some(cmd_tx),
                task,
            },
        );
        tracing::info!(device = %device.short_id(), path = path.describe(), "being controlled");
        self.emit(Event::HostSessionStarted {
            session_id,
            device,
            name,
            path: path.describe().to_string(),
            verification,
        });
    }

    // ------------------------------------------------------------ tick

    async fn on_tick(&mut self, link: &Link) {
        {
            let now = std::time::Instant::now();
            self.gate.lock().unwrap_or_else(|e| e.into_inner()).retain(|_, e| e.until > now);
        }
        let stale: Vec<u64> = self
            .outgoing
            .iter()
            .filter(|(_, o)| o.started.elapsed() > Duration::from_secs(45))
            .map(|(id, _)| *id)
            .collect();
        for id in stale {
            self.fail_outgoing(id, "The remote computer did not answer.".into());
        }

        if self.addresses_checked.elapsed() >= Duration::from_secs(10) {
            self.local_addresses = describe_local_addresses();
            self.addresses_checked = Instant::now();
        }

        if matches!(link, Link::Online { .. }) && self.last_ping.elapsed() >= PING_EVERY {
            let now = bark_core::clock::now_us();
            self.ping_sent = Some(now);
            self.last_ping = Instant::now();
            self.send(link, ToServer::Ping { sent_us: now }).await;
        }

        if self.pairing_code.as_ref().is_some_and(|c| c.is_expired()) {
            self.pairing_code = None;
            self.emit(Event::PairingCode(None));
        }

        if self.pending_pair.as_ref().is_some_and(|p| p.started.elapsed() > PAIR_TIMEOUT) {
            self.pending_pair = None;
            self.emit(Event::PairFinished {
                ok: false,
                message: "The other computer did not answer the pairing request.\n\n\
                          Check that it is switched on, running BARK, and connected to the same BARK server."
                    .into(),
                device: None,
            });
        }
    }

    // --------------------------------------------------------- publishing

    fn view_of(&self, fp: &Fingerprint) -> Option<DeviceView> {
        self.trust.get(fp).map(|e| DeviceView {
            fingerprint: *fp,
            device_id: e.device_id().to_string(),
            name: e.name.clone(),
            online: self.presence.is_online(fp),
            connection: self
                .sessions
                .values()
                .find(|s| s.device == *fp)
                .map(|s| s.path.word().to_string())
                .unwrap_or_else(|| "--".into()),
            last_seen_unix_us: self
                .presence
                .get(fp)
                .map(|p| p.last_seen_unix_us)
                .unwrap_or(0)
                .max(e.last_seen_unix_us),
            os: e.os.clone(),
            bark_version: e.bark_version.clone(),
            description: e.description.clone(),
            group: e.group.clone(),
            may_control_us: e.may_control_us,
            we_may_control: e.we_may_control,
            revoked: e.revoked,
            paired_unix_us: e.paired_unix_us,
            last_connected_unix_us: e.last_connected_unix_us,
        })
    }

    fn status(&self, link: &Link) -> NodeStatus {
        let server = match link {
            Link::Idle => ServerLink::NotConfigured,
            Link::Connecting { address, .. } => ServerLink::Connecting { address: address.clone() },
            Link::Online { address, .. } => ServerLink::Online {
                address: address.clone(),
                rtt_us: self.rtt_us,
                public_address: self.public_address.clone(),
                server_version: self.server_version.clone(),
            },
            Link::Waiting { address, error, until, .. } => ServerLink::Offline {
                address: address.clone(),
                error: error.clone(),
                retry_in_secs: until.saturating_duration_since(Instant::now()).as_secs() as u32,
            },
        };
        NodeStatus {
            device_name: self.config.effective_name(),
            device_id: self.identity.device_id().to_string(),
            fingerprint: self.identity.fingerprint(),
            version: bark_core::VERSION.to_string(),
            mode: self.dirs.label().to_string(),
            server,
            server_role: self.server_role.as_ref().map(|r| ServerRoleStatus {
                listening: r.listening.to_string(),
                key_text: r.key_text.clone(),
                devices_online: r.state.registry.online_count(),
                relay: r.state.relay.as_ref().map(|x| x.listening().to_string()),
                devices_known: r.state.db.device_count().unwrap_or(0),
            }),
            config: self.config.clone(),
            local_addresses: self.local_addresses.clone(),
            sessions: {
                let mut v: Vec<SessionView> = self
                    .sessions
                    .iter()
                    .map(|(id, s)| SessionView {
                        session_id: *id,
                        device_name: s.name.clone(),
                        controlling: s.controller,
                        path: s.path.describe().to_string(),
                        remote_address: s.remote_address.clone(),
                        started_unix_us: s.started_unix_us,
                    })
                    .collect();
                v.sort_by_key(|s| s.session_id);
                v
            },
        }
    }

    /// Sends status and the device list if they changed since last time.
    ///
    /// While offline the status is always sent, because it carries the
    /// countdown to the next retry and the interface shows it.
    fn publish(&mut self, link: &Link, force: bool) {
        let status = self.status(link);
        let offline = matches!(status.server, ServerLink::Offline { .. });
        if force || offline || self.last_status.as_ref() != Some(&status) {
            self.last_status = if offline { None } else { Some(status.clone()) };
            self.emit(Event::Status(status));
        }

        let devices: Vec<DeviceView> = self
            .trust
            .sorted()
            .iter()
            .filter_map(|e| self.view_of(&e.fingerprint()))
            .collect();
        if force || self.last_devices.as_ref() != Some(&devices) {
            self.last_devices = Some(devices.clone());
            self.emit(Event::Devices(devices));
        }
    }
}

fn describe_local_addresses() -> Vec<String> {
    bark_net::interfaces::local_ipv4_addresses()
        .into_iter()
        .map(|a| format!("{} ({})", a.ip, a.adapter))
        .collect()
}

/// Looks up `host:port`, preferring IPv4.
async fn resolve(address: &str) -> Result<SocketAddr> {
    let found: Vec<SocketAddr> = tokio::net::lookup_host(address)
        .await
        .map_err(|e| {
            BarkError::Network(format!(
                "The BARK server address \"{address}\" could not be found: {e}.\n\n\
                 Check the address in Tools > Settings. An IP address such as 192.168.1.10 always works."
            ))
        })?
        .collect();
    found
        .iter()
        .find(|a| a.is_ipv4())
        .or(found.first())
        .copied()
        .ok_or_else(|| BarkError::Network(format!("\"{address}\" did not resolve to any address")))
}

async fn start_server_role(dirs: &NodeDirs, bind_text: &str, port: u16, relay: (bool, u16)) -> Result<ServerRole> {
    let dir = dirs.server();
    let (creds, _created) = TransportCredentials::load_or_create(&dir)?;
    let db = Arc::new(bark_server::Db::open(&dir.join("bark-server.sqlite"))?);
    let ip: IpAddr = if bind_text.is_empty() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        bind_text.parse().map_err(|_| BarkError::config(format!("\"{bind_text}\" is not an IP address")))?
    };
    let endpoint = bidirectional_endpoint(
        SocketAddr::new(ip, port),
        &creds,
        pinned_client_config(creds.fingerprint())?,
        Role::Control,
    )?;
    let listening = endpoint
        .local_addr()
        .map_err(|e| BarkError::Network(format!("could not read the server's address: {e}")))?;
    let relay_server = if relay.0 {
        let r = bark_server::relay::Relay::bind(SocketAddr::new(ip, relay.1), Default::default()).await?;
        Some(r)
    } else {
        None
    };
    let relay_task = relay_server.clone().map(|r| tokio::spawn(r.run()));
    let state = Arc::new(bark_server::ServerState {
        db,
        registry: Arc::new(bark_server::Registry::new()),
        cert_fingerprint: creds.fingerprint(),
        version: bark_core::VERSION.to_string(),
        relay: relay_server,
    });
    bark_server::serve::note_start(&state, listening)?;
    let tasks = bark_server::serve::spawn(state.clone(), endpoint);
    Ok(ServerRole {
        state,
        tasks,
        relay_task,
        listening,
        bind: bind_text.to_string(),
        relay_wanted: relay,
        key: creds.fingerprint(),
        key_text: creds.fingerprint_text(),
    })
}
