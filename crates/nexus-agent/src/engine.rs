//! The data-plane engine: one task owning the TUN device, the UDP socket, all
//! peer sessions, NAT-punch bursts, and IPC command dispatch.
//!
//! Packet flow:
//!   kernel → TUN → encrypt (peer session) → UDP → peer
//!   peer   → UDP → decrypt → kernel via TUN
//!
//! Signaling runs over a supervised WebSocket (`signal.rs`); control-plane
//! REST calls are spawned tasks reporting back through the event channel.

use crate::config::AgentConfig;
use crate::http;
use crate::peers::{PeerState, PendingHandshake, Session};
use crate::signal::{self, SignalEvent};
use crate::sysnet;
use crate::tun::TunDevice;
use anyhow::{Context, Result};
use nexus_core::crypto::{is_authkey, tai64n_after, IdentityKey, StaticKeyPair, KEY_LEN};
use nexus_core::ipc::{IpcRequest, IpcResponse, NodeStatus, PeerStatus, StatusReport};
use nexus_core::noise::{
    self, build_response, consume_cookie_reply, consume_response, cookie_for_addr, cookie_key,
    create_cookie_reply, create_initiation, decode_initiation, random_index, COOKIE_LIFETIME_SECS,
    MSG_TYPE_COOKIE_REPLY, MSG_TYPE_INITIATION, MSG_TYPE_RESPONSE, MSG_TYPE_TRANSPORT,
    REKEY_AFTER_MESSAGES,
};
use nexus_core::packet::{
    build_punch, icmpv4_echo_request, packet_type, parse_punch, MSG_TYPE_PUNCH,
};
use nexus_core::protocol::{PeerInfo, RegisterRequest, RegisterResponse, SignalMessage};
use nexus_core::stun;
use rand::RngCore;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc::UnboundedReceiver, mpsc::UnboundedSender, oneshot};
use tracing::{debug, info, warn};

/// Wait between handshake retries to the same peer.
const HANDSHAKE_RETRY: Duration = Duration::from_secs(5);
/// Give up a pending handshake after this many attempts.
const HANDSHAKE_MAX_ATTEMPTS: u8 = 8;
/// Idle sessions get a WireGuard-style empty keepalive this often.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
/// Rekey sessions after this age.
const REKEY_AFTER: Duration = Duration::from_secs(110);
/// Hard kill for sessions.
const REJECT_AFTER: Duration = Duration::from_secs(180);
/// Re-run STUN and re-report endpoints this often.
const STUN_REFRESH: Duration = Duration::from_secs(30);
/// Ask the server to re-coordinate a punch when a peer is online but
/// sessionless this long.
const REPUNCH_AFTER: Duration = Duration::from_secs(15);
/// Punch burst cadence/duration.
const PUNCH_TICK: Duration = Duration::from_millis(20);
const PUNCH_BURSTS: u32 = 40;
/// Pending ICMP echo timeout.
const PING_TIMEOUT: Duration = Duration::from_secs(5);
/// Inbound initiations/sec allowed before cookies are required.
const HANDSHAKE_RATE_LIMIT: usize = 12;
/// `nexus up` reports failure if the mesh isn't joined within this window.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Messages from outside tasks into the engine loop.
pub enum EngineEvent {
    /// IPC request from `nexus` / `nexus-tui`.
    Ipc {
        req: IpcRequest,
        reply: oneshot::Sender<IpcResponse>,
    },
    /// Event from the signaling supervisor.
    Signal(SignalEvent),
    /// Result of a spawned `/v1/register` call.
    Registered(std::result::Result<RegisterResponse, String>),
    /// Graceful stop (SIGTERM/SIGINT or IPC shutdown).
    Shutdown,
}

#[derive(Clone, Copy, PartialEq)]
enum Phase {
    Down,
    Connecting,
    Connected,
}

impl Phase {
    fn as_str(&self) -> &'static str {
        match self {
            Phase::Down => "down",
            Phase::Connecting => "connecting",
            Phase::Connected => "connected",
        }
    }
}

fn push_event(events: &mut VecDeque<String>, msg: String) {
    info!("{msg}");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let (h, m, s) = (now / 3600 % 24, now / 60 % 60, now % 60);
    events.push_back(format!("{h:02}:{m:02}:{s:02}Z  {msg}"));
    while events.len() > 200 {
        events.pop_front();
    }
}

pub struct Engine {
    cfg: AgentConfig,
    cfg_path: std::path::PathBuf,
    identity: IdentityKey,
    wg_key: StaticKeyPair,
    evt_tx: UnboundedSender<EngineEvent>,

    udp: Arc<UdpSocket>,
    tun: Option<TunDevice>,
    phase: Phase,

    peers: HashMap<Ipv4Addr, PeerState>,
    peer_by_pub: HashMap<[u8; KEY_LEN], Ipv4Addr>,
    /// Our session/pending indices → peer VIP.
    index_to_vip: HashMap<u32, Ipv4Addr>,

    signal_task: Option<tokio::task::JoinHandle<()>>,
    signal_tx: Option<UnboundedSender<String>>,
    signal_connected: bool,

    stun_server: Option<SocketAddr>,
    pending_stun: Option<([u8; 12], Instant)>,
    next_stun: Instant,
    public_endpoint: Option<SocketAddr>,

    pending_connect: Vec<oneshot::Sender<IpcResponse>>,
    connect_deadline: Option<Instant>,
    pending_pings: HashMap<u16, (Ipv4Addr, Instant, oneshot::Sender<IpcResponse>)>,
    ping_seq: u16,
    ping_ident: u16,

    handshake_times: Vec<Instant>,
    events: VecDeque<String>,
    started: Instant,
    shutdown: bool,
    last_housekeep: Instant,
}

impl Engine {
    pub fn new(
        cfg: AgentConfig,
        cfg_path: std::path::PathBuf,
        identity: IdentityKey,
        wg_key: StaticKeyPair,
        udp: Arc<UdpSocket>,
        evt_tx: UnboundedSender<EngineEvent>,
    ) -> Self {
        Self {
            cfg,
            cfg_path,
            identity,
            wg_key,
            evt_tx,
            udp,
            tun: None,
            phase: Phase::Down,
            peers: HashMap::new(),
            peer_by_pub: HashMap::new(),
            index_to_vip: HashMap::new(),
            signal_task: None,
            signal_tx: None,
            signal_connected: false,
            stun_server: None,
            pending_stun: None,
            next_stun: Instant::now(),
            public_endpoint: None,
            pending_connect: Vec::new(),
            connect_deadline: None,
            pending_pings: HashMap::new(),
            ping_seq: 0,
            ping_ident: (rand::rngs::OsRng.next_u32() & 0xFFFF) as u16,
            handshake_times: Vec::new(),
            events: VecDeque::new(),
            started: Instant::now(),
            shutdown: false,
            last_housekeep: Instant::now(),
        }
    }

    fn event(&mut self, msg: impl Into<String>) {
        push_event(&mut self.events, msg.into());
    }

    /// Main loop: multiplex TUN, UDP, engine events, and housekeeping ticks.
    pub async fn run(mut self, mut evt_rx: UnboundedReceiver<EngineEvent>) -> Result<()> {
        if self.cfg.token.is_some() && !self.cfg.server_url.is_empty() {
            self.event("restored session — reconnecting to mesh".to_string());
            self.enter_mesh();
        }

        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let mut udp_buf = [0u8; 4096];
        let mut tun_buf = [0u8; 4096];

        loop {
            if self.shutdown {
                return Ok(());
            }
            tokio::select! {
                res = self.udp.recv_from(&mut udp_buf) => {
                    match res {
                        Ok((n, src)) => self.on_udp(&udp_buf[..n], src).await,
                        Err(e) => {
                            warn!(error = %e, "udp recv failed");
                            tokio::time::sleep(Duration::from_millis(50)).await;
                        }
                    }
                }
                res = async {
                    match &self.tun {
                        Some(t) => t.recv(&mut tun_buf).await,
                        None => std::future::pending::<std::io::Result<usize>>().await,
                    }
                } => {
                    match res {
                        Ok(n) => self.on_tun(&tun_buf[..n]).await,
                        Err(e) => warn!(error = %e, "tun read failed"),
                    }
                }
                ev = evt_rx.recv() => {
                    match ev {
                        Some(EngineEvent::Ipc { req, reply }) => self.on_ipc(req, reply).await,
                        Some(EngineEvent::Signal(e)) => self.on_signal_event(e).await,
                        Some(EngineEvent::Registered(r)) => self.on_registered(r).await,
                        Some(EngineEvent::Shutdown) | None => self.shutdown = true,
                    }
                }
                _ = tick.tick() => self.housekeep().await,
            }
        }
    }

    // ------------------------------------------------------------------
    // Connect / register
    // ------------------------------------------------------------------

    fn begin_connect(&mut self, server_url: String, authkey: Option<String>) {
        self.cfg.server_url = normalize_server_url(&server_url);
        if let Some(k) = authkey {
            self.cfg.authkey = Some(k);
        }
        self.phase = Phase::Connecting;
        self.connect_deadline = Some(Instant::now() + CONNECT_TIMEOUT);

        if self.cfg.token.is_some() {
            self.event(format!("reattaching to {}", self.cfg.server_url));
            self.enter_mesh();
            return;
        }
        let Some(authkey) = self.cfg.authkey.clone() else {
            self.fail_connect("no authkey — first connect requires --authkey");
            return;
        };
        if !is_authkey(&authkey) {
            self.fail_connect("malformed authkey");
            return;
        }

        let evt_tx = self.evt_tx.clone();
        let body = RegisterRequest {
            authkey,
            node_name: self.cfg.name.clone(),
            identity_pubkey: self.identity.public_hex(),
            wg_pubkey: self.wg_key.public_hex(),
            signature: hex::encode(self.identity.sign(&self.wg_key.public())),
            endpoints: self
                .local_endpoint_candidates()
                .iter()
                .map(|a| a.to_string())
                .collect(),
        };
        let url = format!("{}/v1/register", self.cfg.server_url.trim_end_matches('/'));
        tokio::spawn(async move {
            let res = async {
                let body = serde_json::to_string(&body).map_err(|e| e.to_string())?;
                let (status, text) = http::post_json(&url, None, &body)
                    .await
                    .map_err(|e| e.to_string())?;
                if status != 200 {
                    return Err(format!("server returned {status}: {text}"));
                }
                serde_json::from_str::<RegisterResponse>(&text).map_err(|e| e.to_string())
            }
            .await;
            let _ = evt_tx.send(EngineEvent::Registered(res));
        });
        self.event(format!("registering with {}", self.cfg.server_url));
    }

    async fn on_registered(&mut self, res: std::result::Result<RegisterResponse, String>) {
        match res {
            Err(e) => self.fail_connect(&format!("registration failed: {e}")),
            Ok(resp) => {
                self.cfg.node_id = Some(resp.node_id);
                match resp.vip.parse::<Ipv4Addr>() {
                    Ok(v) => self.cfg.vip = Some(v),
                    Err(_) => {
                        self.fail_connect("server assigned invalid VIP");
                        return;
                    }
                }
                self.cfg.token = Some(resp.token);
                self.stun_server = self.resolve_stun(resp.stun_port).await;
                self.event(format!(
                    "registered as node {} ({})",
                    resp.node_id, resp.vip
                ));
                if let Err(e) = self.cfg.save(&self.cfg_path) {
                    warn!(error = %e, "failed to persist config");
                }
                for p in &resp.peers {
                    self.upsert_peer(p);
                }
                self.enter_mesh();
            }
        }
    }

    /// Everything after we hold a valid token: TUN up, signal on, STUN out.
    fn enter_mesh(&mut self) {
        self.phase = Phase::Connecting;
        if let Err(e) = self.ensure_tun() {
            self.fail_connect(&format!("interface setup failed: {e}"));
            return;
        }
        self.spawn_signal();
        self.send_stun_query();
    }

    fn ensure_tun(&mut self) -> Result<()> {
        if self.tun.is_some() {
            return Ok(());
        }
        let vip = self.cfg.vip.context("no VIP assigned yet")?;
        let dev = TunDevice::create()?;
        sysnet::setup_interface(dev.name(), vip, self.cfg.mtu)
            .with_context(|| format!("configuring {}", dev.name()))?;
        self.event(format!("interface {} up with {}", dev.name(), vip));
        self.tun = Some(dev);
        Ok(())
    }

    fn spawn_signal(&mut self) {
        if let Some(h) = self.signal_task.take() {
            h.abort();
        }
        let Some(token) = self.cfg.token.clone() else {
            return;
        };
        // Bridge SignalEvent → EngineEvent so the engine owns one event queue.
        let (sig_tx, mut sig_rx) = tokio::sync::mpsc::unbounded_channel::<SignalEvent>();
        let evt_tx = self.evt_tx.clone();
        tokio::spawn(async move {
            while let Some(e) = sig_rx.recv().await {
                if evt_tx.send(EngineEvent::Signal(e)).is_err() {
                    return;
                }
            }
        });
        let (handle, tx) = signal::spawn(self.cfg.signal_url(), token, sig_tx);
        self.signal_task = Some(handle);
        self.signal_tx = Some(tx);
    }

    async fn resolve_stun(&self, stun_port: u16) -> Option<SocketAddr> {
        // Authority = after scheme, before first '/', minus any :port.
        let base = self
            .cfg
            .server_url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let authority = base.split('/').next().unwrap_or("");
        let host = if let Some(inner) = authority
            .strip_prefix('[')
            .and_then(|s| s.split(']').next())
        {
            inner // [v6]:port
        } else {
            authority.split(':').next().unwrap_or("")
        };
        if host.is_empty() {
            return None;
        }
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Some(SocketAddr::new(ip, stun_port));
        }
        tokio::net::lookup_host(format!("{host}:{stun_port}"))
            .await
            .ok()
            .and_then(|mut it| it.next())
    }

    fn local_endpoint_candidates(&self) -> Vec<SocketAddr> {
        let port = self.udp.local_addr().map(|a| a.port()).unwrap_or(0);
        sysnet::local_ipv4_addrs()
            .into_iter()
            .map(|ip| SocketAddr::new(IpAddr::V4(ip), port))
            .collect()
    }

    // ------------------------------------------------------------------
    // UDP receive path
    // ------------------------------------------------------------------

    async fn on_udp(&mut self, data: &[u8], src: SocketAddr) {
        match packet_type(data) {
            Some(MSG_TYPE_INITIATION) => self.on_initiation(data, src).await,
            Some(MSG_TYPE_RESPONSE) => self.on_response(data, src).await,
            Some(MSG_TYPE_COOKIE_REPLY) => self.on_cookie_reply(data, src).await,
            Some(MSG_TYPE_TRANSPORT) => self.on_transport(data, src).await,
            Some(MSG_TYPE_PUNCH) => self.on_punch(data, src).await,
            _ if stun::is_stun_message(data) => self.on_stun_response(data).await,
            _ => {}
        }
    }

    async fn on_initiation(&mut self, data: &[u8], src: SocketAddr) {
        self.handshake_times
            .retain(|t| t.elapsed() < Duration::from_secs(1));
        let require_cookie = self.handshake_times.len() > HANDSHAKE_RATE_LIMIT;
        let own_pub = self.wg_key.public();

        if require_cookie && data.len() >= 148 {
            let mac2 = &data[132..148];
            let ck = cookie_key(&own_pub);
            if mac2 == [0u8; 16] {
                // Stateless cookie reply bound to this source address.
                let sender_index = u32::from_le_bytes(data[4..8].try_into().unwrap_or_default());
                if let Ok(reply) =
                    create_cookie_reply(&self.wg_key, sender_index, &data[116..132], src)
                {
                    let _ = self.udp.send_to(&reply, src).await;
                }
                return;
            }
            let cookie = cookie_for_addr(&ck, &src);
            if nexus_core::crypto::mac(&cookie, &data[..132]) != *mac2 {
                return;
            }
        }
        self.handshake_times.push(Instant::now());

        let dec = match decode_initiation(data, &self.wg_key, src, false) {
            Ok(d) => d,
            Err(_) => return, // mac1/auth failure — drop silently
        };

        let Some(&vip) = self.peer_by_pub.get(&dec.peer_static) else {
            debug!(%src, "initiation from unknown peer — dropped");
            return;
        };

        // All peer-state mutations in one scoped borrow.
        {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            if let Some(last) = peer.last_initiation_ts {
                if !tai64n_after(&dec.timestamp, &last) {
                    return; // replayed initiation
                }
            }
            // Simultaneous-initiation tiebreak: higher sender_index wins; both
            // sides compute the same comparison so exactly one handshake lives.
            if let Some(p) = &peer.pending {
                if dec.initiator_index <= p.pending.sender_index {
                    return;
                }
                self.index_to_vip.remove(&p.pending.sender_index);
                peer.pending = None;
            }
            peer.last_initiation_ts = Some(dec.timestamp);
        }

        let mut our_index = random_index();
        while self.index_to_vip.contains_key(&our_index) {
            our_index = random_index();
        }
        let (resp, keys) = match build_response(&dec, our_index) {
            Ok(r) => r,
            Err(e) => {
                warn!(%vip, error = %e, "building handshake response");
                return;
            }
        };
        let _ = self.udp.send_to(&resp, src).await;
        self.install_session(vip, keys, src, true).await;
    }

    async fn on_response(&mut self, data: &[u8], src: SocketAddr) {
        if data.len() < 12 {
            return;
        }
        let receiver_index = u32::from_le_bytes(data[8..12].try_into().unwrap_or_default());
        let Some(&vip) = self.index_to_vip.get(&receiver_index) else {
            return;
        };
        let pending = match self.peers.get_mut(&vip) {
            Some(p) => p.pending.take(),
            None => None,
        };
        let Some(pending) = pending else {
            return;
        };
        match consume_response(data, &pending.pending, &self.wg_key) {
            Ok(keys) => self.install_session(vip, keys, src, false).await,
            Err(e) => debug!(%vip, error = %e, "handshake response rejected"),
        }
    }

    async fn on_cookie_reply(&mut self, data: &[u8], _src: SocketAddr) {
        if data.len() < 8 {
            return;
        }
        let our_index = u32::from_le_bytes(data[4..8].try_into().unwrap_or_default());
        let Some(&vip) = self.index_to_vip.get(&our_index) else {
            return;
        };
        let ok = {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            let Some(pending) = &peer.pending else {
                return;
            };
            let mac1 = pending.msg.get(116..132).unwrap_or(&[]);
            match consume_cookie_reply(data, &pending.pending.responder_static, our_index, mac1) {
                Ok(cookie) => {
                    peer.cookie = Some((Instant::now(), cookie));
                    true
                }
                Err(_) => false,
            }
        };
        if ok {
            self.event(format!("cookie challenge answered — retrying {vip}"));
            self.kick_handshake(vip).await;
        }
    }

    async fn on_transport(&mut self, data: &[u8], src: SocketAddr) {
        let view = match noise::parse_transport(data) {
            Ok(v) => v,
            Err(_) => return,
        };
        let Some(&vip) = self.index_to_vip.get(&view.receiver_index) else {
            return;
        };

        let mut new_endpoint = false;
        let plaintext = {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            let Some(session) = &mut peer.session else {
                return;
            };
            if session.our_index != view.receiver_index {
                return;
            }
            if !session.replay.check_and_update(view.counter) {
                return;
            }
            let plaintext = match noise::open_transport(&session.recv_key, &view) {
                Ok(p) => p,
                Err(_) => return,
            };
            peer.last_rx = Some(Instant::now());
            peer.stats.rx_bytes += data.len() as u64;
            peer.stats.rx_packets += 1;
            // Authenticated packet → trust the source as the active endpoint
            // (WireGuard-style roaming).
            if peer.active_endpoint != Some(src) {
                peer.active_endpoint = Some(src);
                new_endpoint = true;
            }
            plaintext
        };
        if new_endpoint {
            self.event(format!("{vip} endpoint → {src}"));
        }
        if plaintext.is_empty() {
            return; // keepalive
        }

        // Inner-source binding: a peer may only claim its own VIP.
        if plaintext.len() >= 20 && plaintext[0] >> 4 == 4 {
            let inner_src =
                Ipv4Addr::new(plaintext[12], plaintext[13], plaintext[14], plaintext[15]);
            if inner_src != vip {
                debug!(%vip, %inner_src, "dropping packet with spoofed inner src");
                return;
            }
        }

        // Intercept ICMP echo replies for `nexus ping`.
        if let Some((seq, _)) =
            nexus_core::packet::parse_icmpv4_echo_reply(&plaintext, self.ping_ident)
        {
            if let Some((_, sent, reply)) = self.pending_pings.remove(&seq) {
                let rtt = sent.elapsed().as_secs_f64() * 1000.0;
                if let Some(p) = self.peers.get_mut(&vip) {
                    p.rtt_ms = Some(rtt);
                }
                let _ = reply.send(IpcResponse::Pong {
                    vip: vip.to_string(),
                    rtt_ms: rtt,
                });
            }
            return;
        }

        if let Some(tun) = &self.tun {
            if let Err(e) = tun.send(&plaintext).await {
                warn!(error = %e, "tun write failed");
            }
        }
    }

    async fn on_punch(&mut self, data: &[u8], src: SocketAddr) {
        let Some(their_pub) = parse_punch(data) else {
            return;
        };
        let Some(&vip) = self.peer_by_pub.get(&their_pub) else {
            return;
        };
        let mut learned_new = false;
        {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            if peer.active_endpoint != Some(src) {
                peer.active_endpoint = Some(src);
                learned_new = true;
            }
        }
        if learned_new {
            self.event(format!("punch path to {vip} via {src}"));
        }
        // Symmetric reply keeps both NAT mappings open.
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        let msg = build_punch(&self.wg_key.public(), nonce);
        let _ = self.udp.send_to(&msg, src).await;

        // Drive a handshake over the punched path.
        let (needs_kick, pending_msg) = match self.peers.get(&vip) {
            Some(p) => (
                p.session.is_none() && p.pending.is_none(),
                p.pending.as_ref().map(|h| h.msg.clone()),
            ),
            None => (false, None),
        };
        if needs_kick {
            self.kick_handshake(vip).await;
        } else if let Some(msg) = pending_msg {
            // Re-send the in-flight initiation over the proven path.
            let _ = self.udp.send_to(&msg, src).await;
        }
    }

    async fn on_stun_response(&mut self, data: &[u8]) {
        let Some((txid, _)) = self.pending_stun else {
            return;
        };
        if let Ok(observed) = stun::parse_binding_response(data, &txid) {
            self.pending_stun = None;
            if self.public_endpoint != Some(observed) {
                self.public_endpoint = Some(observed);
                self.event(format!("public endpoint (STUN): {observed}"));
                self.report_endpoints();
            }
        }
    }

    // ------------------------------------------------------------------
    // Sessions / handshakes
    // ------------------------------------------------------------------

    async fn install_session(
        &mut self,
        vip: Ipv4Addr,
        keys: noise::SessionKeys,
        src: SocketAddr,
        responder: bool,
    ) {
        let name = {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            if let Some(old) = peer.session.take() {
                self.index_to_vip.remove(&old.our_index);
            }
            peer.session = Some(Session::new(keys.clone()));
            peer.active_endpoint = Some(src);
            peer.last_handshake = Some(Instant::now());
            peer.punching_until = None;
            peer.name.clone()
        };
        self.index_to_vip.insert(keys.our_index, vip);
        self.event(format!(
            "handshake {} with {} ({vip})",
            if responder { "answered" } else { "completed" },
            name,
        ));
        let queued: Vec<u16> = self
            .pending_pings
            .iter()
            .filter(|(_, (v, _, _))| *v == vip)
            .map(|(s, _)| *s)
            .collect();
        for seq in queued {
            self.fire_ping(seq).await;
        }
    }

    async fn kick_handshake(&mut self, vip: Ipv4Addr) {
        let (wg_pub, targets) = {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            if let Some(p) = peer.pending.take() {
                self.index_to_vip.remove(&p.pending.sender_index);
            }
            (peer.wg_pub, peer.candidate_endpoints())
        };
        let mut sender_index = random_index();
        while self.index_to_vip.contains_key(&sender_index) {
            sender_index = random_index();
        }
        let cookie = self
            .peers
            .get(&vip)
            .and_then(|p| p.cookie)
            .filter(|(t, _)| t.elapsed() < Duration::from_secs(COOKIE_LIFETIME_SECS))
            .map(|(_, c)| c);
        let (msg, pending) =
            match create_initiation(&self.wg_key, &wg_pub, sender_index, cookie.as_ref()) {
                Ok(r) => r,
                Err(e) => {
                    warn!(%vip, error = %e, "creating initiation");
                    return;
                }
            };
        for dst in &targets {
            let _ = self.udp.send_to(&msg, dst).await;
        }
        if let Some(peer) = self.peers.get_mut(&vip) {
            peer.pending = Some(PendingHandshake {
                pending,
                msg,
                sent_at: Instant::now(),
                attempts: 1,
            });
        }
        self.index_to_vip.insert(sender_index, vip);
    }

    // ------------------------------------------------------------------
    // TUN → tunnel path
    // ------------------------------------------------------------------

    async fn on_tun(&mut self, pkt: &[u8]) {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return; // IPv4 only on the overlay
        }
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

        let (need_kick, targets) = match self.peers.get_mut(&dst) {
            Some(peer) => {
                if let Some(session) = &mut peer.session {
                    // Encrypt and send via the authenticated endpoint.
                    let Some(counter) = session.next_counter() else {
                        peer.session = None;
                        return;
                    };
                    let sealed = match noise::seal_transport(
                        &session.send_key,
                        session.their_index,
                        counter,
                        pkt,
                    ) {
                        Ok(s) => s,
                        Err(_) => return,
                    };
                    let Some(ep) = peer.active_endpoint else {
                        return;
                    };
                    match self.udp.send_to(&sealed, ep).await {
                        Ok(n) => {
                            peer.stats.tx_bytes += n as u64;
                            peer.stats.tx_packets += 1;
                            peer.last_tx = Some(Instant::now());
                        }
                        Err(e) => debug!(%ep, error = %e, "udp send failed"),
                    }
                    return;
                }
                let need_kick = peer
                    .pending
                    .as_ref()
                    .map(|p| p.sent_at.elapsed() > Duration::from_secs(2))
                    .unwrap_or(true);
                (need_kick, peer.candidate_endpoints())
            }
            None => return,
        };

        // No session: kick a handshake and opportunistically punch candidates.
        if need_kick {
            self.kick_handshake(dst).await;
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        let punch = build_punch(&self.wg_key.public(), nonce);
        for ep in targets {
            let _ = self.udp.send_to(&punch, ep).await;
        }
        // The packet is dropped — the initiator's stack will retransmit once
        // the tunnel comes up (sub-second typical).
    }

    // ------------------------------------------------------------------
    // Signaling
    // ------------------------------------------------------------------

    async fn on_signal_event(&mut self, ev: SignalEvent) {
        match ev {
            SignalEvent::Connected => {
                self.signal_connected = true;
                self.event("signaling channel up".to_string());
                self.report_endpoints();
            }
            SignalEvent::Disconnected => {
                if self.signal_connected {
                    self.event("signaling channel lost".to_string());
                }
                self.signal_connected = false;
            }
            SignalEvent::AuthRejected => {
                self.event("session token rejected — re-registering".to_string());
                if let Some(h) = self.signal_task.take() {
                    h.abort();
                }
                self.cfg.token = None;
                if self.cfg.authkey.is_some() && !self.cfg.server_url.is_empty() {
                    self.begin_connect(self.cfg.server_url.clone(), None);
                } else {
                    self.teardown();
                }
            }
            SignalEvent::Message(m) => self.on_signal_message(m).await,
        }
    }

    async fn on_signal_message(&mut self, msg: SignalMessage) {
        match msg {
            SignalMessage::Welcome { peers, .. } => {
                let online_ids: Vec<u64> = peers
                    .iter()
                    .filter(|p| p.online)
                    .map(|p| p.node_id)
                    .collect();
                for p in &peers {
                    self.upsert_peer(p);
                }
                self.phase = Phase::Connected;
                self.event("mesh joined — peer table synced".to_string());
                for reply in self.pending_connect.drain(..) {
                    let vip = self.cfg.vip.map(|v| v.to_string()).unwrap_or_default();
                    let _ = reply.send(IpcResponse::Ok {
                        message: format!("connected — vip {vip}"),
                    });
                }
                self.connect_deadline = None;
                for id in online_ids {
                    self.send_signal(&SignalMessage::PunchRequest { target_node_id: id });
                }
            }
            SignalMessage::PeerJoined { peer } | SignalMessage::PeerUpdated { peer } => {
                let vip = peer.vip.parse().unwrap_or(Ipv4Addr::UNSPECIFIED);
                let was_online = self.peers.get(&vip).map(|p| p.online).unwrap_or(false);
                let node_id = peer.node_id;
                let name = peer.name.clone();
                let online_now = peer.online;
                self.upsert_peer(&peer);
                if !was_online && online_now {
                    self.event(format!("peer {name} ({vip}) online"));
                    self.send_signal(&SignalMessage::PunchRequest {
                        target_node_id: node_id,
                    });
                }
            }
            SignalMessage::PeerLeft { node_id } => {
                let vip = self
                    .peers
                    .iter()
                    .find(|(_, p)| p.node_id == node_id)
                    .map(|(v, _)| *v);
                if let Some(vip) = vip {
                    if let Some(p) = self.peers.get_mut(&vip) {
                        p.online = false;
                        if let Some(old) = p.session.take() {
                            self.index_to_vip.remove(&old.our_index);
                        }
                        p.active_endpoint = None;
                    }
                    self.event(format!("peer {vip} went offline"));
                }
            }
            SignalMessage::Punch {
                peer_node_id,
                peer_vip,
                peer_wg_pubkey,
                endpoints,
                start_at_ms,
            } => {
                self.on_punch_order(
                    peer_node_id,
                    &peer_vip,
                    &peer_wg_pubkey,
                    &endpoints,
                    start_at_ms,
                )
                .await;
            }
            _ => {}
        }
    }

    fn upsert_peer(&mut self, info: &PeerInfo) {
        let Ok(vip) = info.vip.parse::<Ipv4Addr>() else {
            return;
        };
        let Ok(wg_pub) = info.wg_key_bytes() else {
            return;
        };
        let eps: Vec<SocketAddr> = info
            .endpoints
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        match self.peers.get_mut(&vip) {
            Some(p) => {
                p.online = info.online;
                p.name = info.name.clone();
                if !eps.is_empty() {
                    p.endpoints = eps;
                }
            }
            None => {
                let mut p = PeerState::new(info.node_id, info.name.clone(), wg_pub);
                p.online = info.online;
                p.endpoints = eps;
                self.peers.insert(vip, p);
                self.peer_by_pub.insert(wg_pub, vip);
            }
        }
    }

    async fn on_punch_order(
        &mut self,
        peer_node_id: u64,
        peer_vip: &str,
        peer_wg_pubkey: &str,
        endpoints: &[String],
        start_at_ms: u64,
    ) {
        let Ok(vip) = peer_vip.parse::<Ipv4Addr>() else {
            return;
        };
        let eps: Vec<SocketAddr> = endpoints.iter().filter_map(|s| s.parse().ok()).collect();
        if eps.is_empty() {
            return;
        }
        if let std::collections::hash_map::Entry::Vacant(entry) = self.peers.entry(vip) {
            if let Ok(pub_bytes) = hex::decode(peer_wg_pubkey) {
                if let Ok(wg_pub) = <[u8; KEY_LEN]>::try_from(pub_bytes.as_slice()) {
                    let mut p = PeerState::new(peer_node_id, peer_vip.to_string(), wg_pub);
                    p.online = true;
                    p.endpoints = eps.clone();
                    entry.insert(p);
                    self.peer_by_pub.insert(wg_pub, vip);
                }
            }
        }
        if let Some(p) = self.peers.get_mut(&vip) {
            for e in &eps {
                if !p.endpoints.contains(e) {
                    p.endpoints.push(*e);
                }
            }
            p.online = true;
            p.punching_until =
                Some(Instant::now() + PUNCH_TICK * PUNCH_BURSTS + Duration::from_millis(500));
        }
        self.event(format!("punch ordered → {vip} ({} candidates)", eps.len()));

        let udp = self.udp.clone();
        let our_pub = self.wg_key.public();
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let start_delay = start_at_ms.saturating_sub(now_ms);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(start_delay)).await;
            for i in 0..PUNCH_BURSTS {
                let msg = build_punch(&our_pub, i as u64);
                for ep in &eps {
                    let _ = udp.send_to(&msg, ep).await;
                }
                tokio::time::sleep(PUNCH_TICK).await;
            }
        });
    }

    fn send_signal(&mut self, msg: &SignalMessage) {
        if let Some(tx) = &self.signal_tx {
            if let Ok(text) = serde_json::to_string(msg) {
                let _ = tx.send(text);
            }
        }
    }

    fn report_endpoints(&mut self) {
        let mut eps: Vec<String> = self
            .local_endpoint_candidates()
            .iter()
            .map(|a| a.to_string())
            .collect();
        if let Some(pub_ep) = self.public_endpoint {
            eps.push(pub_ep.to_string());
        }
        self.send_signal(&SignalMessage::ReportEndpoints { endpoints: eps });
    }

    fn send_stun_query(&mut self) {
        let Some(server) = self.stun_server else {
            return;
        };
        let (msg, txid) = stun::build_binding_request();
        self.pending_stun = Some((txid, Instant::now()));
        let udp = self.udp.clone();
        tokio::spawn(async move {
            let _ = udp.send_to(&msg, server).await;
        });
    }

    // ------------------------------------------------------------------
    // IPC commands
    // ------------------------------------------------------------------

    async fn on_ipc(&mut self, req: IpcRequest, reply: oneshot::Sender<IpcResponse>) {
        match req {
            IpcRequest::Connect {
                server_url,
                authkey,
            } => {
                if matches!(self.phase, Phase::Down) {
                    self.pending_connect.push(reply);
                    self.begin_connect(server_url, Some(authkey));
                } else {
                    let _ = reply.send(IpcResponse::Ok {
                        message: format!("already {}", self.phase.as_str()),
                    });
                }
            }
            IpcRequest::Disconnect => {
                self.teardown();
                let _ = reply.send(IpcResponse::Ok {
                    message: "disconnected".into(),
                });
            }
            IpcRequest::Shutdown => {
                self.teardown();
                let _ = reply.send(IpcResponse::Ok {
                    message: "daemon stopping".into(),
                });
                self.shutdown = true;
            }
            IpcRequest::Status => {
                let report = self.build_status();
                let _ = reply.send(IpcResponse::Status { report });
            }
            IpcRequest::Ping { vip } => self.on_ping_request(vip, reply).await,
        }
    }

    async fn on_ping_request(&mut self, vip_str: String, reply: oneshot::Sender<IpcResponse>) {
        let Ok(vip) = vip_str.parse::<Ipv4Addr>() else {
            let _ = reply.send(IpcResponse::Error {
                message: format!("invalid vip {vip_str}"),
            });
            return;
        };
        let has_session = self
            .peers
            .get(&vip)
            .map(|p| p.session.is_some())
            .unwrap_or(false);
        if !self.peers.contains_key(&vip) {
            let _ = reply.send(IpcResponse::Error {
                message: format!("no peer {vip}"),
            });
            return;
        }
        self.ping_seq = self.ping_seq.wrapping_add(1);
        let seq = self.ping_seq;
        self.pending_pings.insert(seq, (vip, Instant::now(), reply));
        if has_session {
            self.fire_ping(seq).await;
        } else {
            self.kick_handshake(vip).await;
        }
    }

    async fn fire_ping(&mut self, seq: u16) {
        let Some((vip, _, _)) = self.pending_pings.get(&seq).map(|(v, t, _)| (*v, *t, ())) else {
            return;
        };
        let Some(my_vip) = self.cfg.vip else {
            return;
        };
        let mut sent = false;
        {
            let Some(peer) = self.peers.get_mut(&vip) else {
                return;
            };
            let Some(session) = &mut peer.session else {
                return;
            };
            let Some(ep) = peer.active_endpoint else {
                return;
            };
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let Ok(pkt) =
                icmpv4_echo_request(my_vip, vip, self.ping_ident, seq, &nanos.to_be_bytes())
            else {
                return;
            };
            let Some(counter) = session.next_counter() else {
                return;
            };
            if let Ok(sealed) =
                noise::seal_transport(&session.send_key, session.their_index, counter, &pkt)
            {
                if self.udp.send_to(&sealed, ep).await.is_ok() {
                    peer.stats.tx_bytes += sealed.len() as u64;
                    peer.last_tx = Some(Instant::now());
                    sent = true;
                }
            }
        }
        let _ = sent;
    }

    fn build_status(&mut self) -> StatusReport {
        let now = Instant::now();
        let mut peers = Vec::new();
        for (vip, p) in self.peers.iter_mut() {
            let (t0, rx0, tx0) = p.last_sample;
            let dt = now.duration_since(t0).as_secs_f64().max(0.1);
            p.rx_bps = (p.stats.rx_bytes - rx0) as f64 / dt;
            p.tx_bps = (p.stats.tx_bytes - tx0) as f64 / dt;
            p.last_sample = (now, p.stats.rx_bytes, p.stats.tx_bytes);
            peers.push(PeerStatus {
                node_id: p.node_id,
                name: p.name.clone(),
                vip: vip.to_string(),
                wg_pubkey_short: hex::encode(&p.wg_pub[..4]),
                endpoint: p.active_endpoint.map(|a| a.to_string()),
                mode: p.mode(),
                rtt_ms: p.rtt_ms,
                rx_bytes: p.stats.rx_bytes,
                tx_bytes: p.stats.tx_bytes,
                rx_bps: p.rx_bps,
                tx_bps: p.tx_bps,
                last_handshake_secs: p.last_handshake.map(|t| t.elapsed().as_secs()),
            });
        }
        peers.sort_by_key(|p| p.node_id);
        StatusReport {
            node: NodeStatus {
                state: self.phase.as_str().into(),
                node_id: self.cfg.node_id,
                vip: self.cfg.vip.map(|v| v.to_string()),
                server_url: if self.cfg.server_url.is_empty() {
                    None
                } else {
                    Some(self.cfg.server_url.clone())
                },
                public_endpoint: self.public_endpoint.map(|a| a.to_string()),
                listen_port: self.udp.local_addr().ok().map(|a| a.port()),
                uptime_secs: self.started.elapsed().as_secs(),
            },
            peers,
            events: self.events.iter().cloned().collect(),
        }
    }

    // ------------------------------------------------------------------
    // Teardown & housekeeping
    // ------------------------------------------------------------------

    fn teardown(&mut self) {
        if let Some(h) = self.signal_task.take() {
            h.abort();
        }
        self.signal_tx = None;
        self.signal_connected = false;
        if let Some(tun) = self.tun.take() {
            let name = tun.name().to_string();
            drop(tun); // fd closes → kernel removes the interface
            sysnet::teardown_interface(&name);
            push_event(&mut self.events, format!("interface {name} down"));
        }
        for (_, (_, _, reply)) in self.pending_pings.drain() {
            let _ = reply.send(IpcResponse::Error {
                message: "tunnel down".into(),
            });
        }
        for reply in self.pending_connect.drain(..) {
            let _ = reply.send(IpcResponse::Error {
                message: "tunnel down".into(),
            });
        }
        self.peers.clear();
        self.peer_by_pub.clear();
        self.index_to_vip.clear();
        self.phase = Phase::Down;
        self.cfg.token = None;
        let _ = self.cfg.save(&self.cfg_path);
        self.event("disconnected from mesh".to_string());
    }

    fn fail_connect(&mut self, why: &str) {
        self.event(format!("connect failed: {why}"));
        for reply in self.pending_connect.drain(..) {
            let _ = reply.send(IpcResponse::Error {
                message: why.to_string(),
            });
        }
        self.phase = Phase::Down;
        self.connect_deadline = None;
    }

    async fn housekeep(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_housekeep) < Duration::from_millis(240) {
            return;
        }
        self.last_housekeep = now;

        if let Some(deadline) = self.connect_deadline {
            if now > deadline && !matches!(self.phase, Phase::Connected) {
                self.fail_connect("timed out waiting for the control plane");
            }
        }

        // Ping timeouts.
        let expired: Vec<u16> = self
            .pending_pings
            .iter()
            .filter(|(_, (_, t, _))| t.elapsed() > PING_TIMEOUT)
            .map(|(s, _)| *s)
            .collect();
        for seq in expired {
            if let Some((vip, _, reply)) = self.pending_pings.remove(&seq) {
                let _ = reply.send(IpcResponse::Error {
                    message: format!("ping to {vip} timed out"),
                });
            }
        }

        // Periodic STUN refresh.
        if matches!(self.phase, Phase::Connected) && now >= self.next_stun {
            self.next_stun = now + STUN_REFRESH;
            self.send_stun_query();
        }

        // Per-peer maintenance — collect follow-ups to run after the loop.
        let mut kicks = Vec::new();
        let mut expired_sessions = Vec::new();
        let mut keepalives = Vec::new();
        let mut retransmits = Vec::new();
        for (vip, p) in self.peers.iter_mut() {
            if let Some(s) = &p.session {
                if s.born.elapsed() > REJECT_AFTER || s.send_counter >= REKEY_AFTER_MESSAGES {
                    expired_sessions.push(*vip);
                } else if s.born.elapsed() > REKEY_AFTER && p.pending.is_none() {
                    kicks.push(*vip);
                }
            }
            if let Some(pend) = &p.pending {
                if pend.sent_at.elapsed() > HANDSHAKE_RETRY {
                    if pend.attempts >= HANDSHAKE_MAX_ATTEMPTS {
                        retransmits.push((*vip, None));
                    } else {
                        retransmits.push((*vip, Some(pend.msg.clone())));
                    }
                }
            }
            if p.session.is_some() {
                let idle = p
                    .last_tx
                    .map(|t| t.elapsed() > KEEPALIVE_INTERVAL)
                    .unwrap_or(true);
                if idle {
                    if let (Some(ep), Some(_)) = (p.active_endpoint, p.session.as_ref()) {
                        keepalives.push((*vip, ep));
                    }
                }
            }
        }
        for vip in expired_sessions {
            if let Some(p) = self.peers.get_mut(&vip) {
                if let Some(old) = p.session.take() {
                    self.index_to_vip.remove(&old.our_index);
                }
                p.cookie = None;
            }
        }
        for vip in kicks {
            self.kick_handshake(vip).await;
        }
        for (vip, msg) in retransmits {
            match msg {
                None => {
                    if let Some(p) = self.peers.get_mut(&vip) {
                        if let Some(pend) = p.pending.take() {
                            self.index_to_vip.remove(&pend.pending.sender_index);
                        }
                    }
                }
                Some(msg) => {
                    let mut attempts_ok = true;
                    if let Some(p) = self.peers.get_mut(&vip) {
                        if let Some(pend) = &mut p.pending {
                            pend.attempts += 1;
                            pend.sent_at = Instant::now();
                        } else {
                            attempts_ok = false;
                        }
                    }
                    if attempts_ok {
                        let eps = self
                            .peers
                            .get(&vip)
                            .map(|p| p.candidate_endpoints())
                            .unwrap_or_default();
                        for ep in eps {
                            let _ = self.udp.send_to(&msg, ep).await;
                        }
                    }
                }
            }
        }
        for (vip, ep) in keepalives {
            let msg = {
                let Some(p) = self.peers.get_mut(&vip) else {
                    continue;
                };
                let Some(s) = &mut p.session else {
                    continue;
                };
                let Some(c) = s.next_counter() else {
                    continue;
                };
                noise::seal_transport(&s.send_key, s.their_index, c, &[]).ok()
            };
            if let Some(msg) = msg {
                if self.udp.send_to(&msg, ep).await.is_ok() {
                    if let Some(p) = self.peers.get_mut(&vip) {
                        p.last_tx = Some(now);
                    }
                }
            }
        }

        // Re-punch online peers that never established a session.
        if matches!(self.phase, Phase::Connected) {
            let mut repunch = Vec::new();
            for (vip, p) in self.peers.iter() {
                if !p.online || p.session.is_some() || p.pending.is_some() {
                    continue;
                }
                if p.punching_until.map(|t| t > now).unwrap_or(false) {
                    continue;
                }
                let stale = p
                    .last_rx
                    .map(|t| t.elapsed() > REPUNCH_AFTER)
                    .unwrap_or(true);
                if stale {
                    repunch.push((*vip, p.node_id));
                }
            }
            for (vip, node_id) in repunch {
                if let Some(p) = self.peers.get_mut(&vip) {
                    p.last_rx = Some(now); // paces further requests
                }
                self.send_signal(&SignalMessage::PunchRequest {
                    target_node_id: node_id,
                });
                self.kick_handshake(vip).await;
            }
        }
    }
}

/// Ensure the URL carries a scheme (default http).
fn normalize_server_url(url: &str) -> String {
    let u = url.trim().trim_end_matches('/');
    if u.starts_with("http://") || u.starts_with("https://") {
        u.to_string()
    } else {
        format!("http://{u}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_normalization() {
        assert_eq!(
            normalize_server_url("vpn.example.com"),
            "http://vpn.example.com"
        );
        assert_eq!(
            normalize_server_url("https://vpn.example.com/"),
            "https://vpn.example.com"
        );
        assert_eq!(normalize_server_url(" http://a:8080/ "), "http://a:8080");
    }
}
