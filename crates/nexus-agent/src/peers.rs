//! Per-peer session state on the data plane.

use nexus_core::crypto::KEY_LEN;
use nexus_core::model::{ConnMode, TrafficStats};
use nexus_core::noise::{PendingInitiation, ReplayWindow, SessionKeys};
use std::net::SocketAddr;
use std::time::Instant;

/// A completed Noise handshake's live keys and counters.
pub struct Session {
    pub send_key: [u8; KEY_LEN],
    pub recv_key: [u8; KEY_LEN],
    /// Index the peer expects as `receiver_index`.
    pub their_index: u32,
    /// Index we chose; inbound packets with it map back to this peer.
    pub our_index: u32,
    pub send_counter: u64,
    pub replay: ReplayWindow,
    pub born: Instant,
}

impl Session {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            send_key: keys.send_key,
            recv_key: keys.recv_key,
            their_index: keys.their_index,
            our_index: keys.our_index,
            send_counter: 0,
            replay: ReplayWindow::new(),
            born: Instant::now(),
        }
    }

    /// Next outbound counter, or `None` if exhausted (forces rekey).
    pub fn next_counter(&mut self) -> Option<u64> {
        if self.send_counter >= nexus_core::noise::REJECT_AFTER_MESSAGES {
            return None;
        }
        let c = self.send_counter;
        self.send_counter += 1;
        Some(c)
    }
}

/// An initiation we sent that hasn't been answered yet.
pub struct PendingHandshake {
    pub pending: PendingInitiation,
    /// Raw initiation bytes — needed for retransmission and as the AAD when
    /// consuming a cookie reply.
    pub msg: Vec<u8>,
    pub sent_at: Instant,
    pub attempts: u8,
}

/// Everything the engine knows about one mesh peer.
pub struct PeerState {
    pub node_id: u64,
    pub name: String,
    pub wg_pub: [u8; KEY_LEN],
    /// Candidate endpoints reported by the control plane.
    pub endpoints: Vec<SocketAddr>,
    /// Endpoint that has produced or accepted traffic recently.
    pub active_endpoint: Option<SocketAddr>,
    pub session: Option<Session>,
    pub pending: Option<PendingHandshake>,
    /// Last accepted TAI64N timestamp for responder-role replay checks.
    pub last_initiation_ts: Option<[u8; 12]>,
    /// Cookie handed to us by a rate-limited responder (with issue time).
    pub cookie: Option<(Instant, [u8; 16])>,
    /// A punch burst is currently spraying for this peer until this instant.
    pub punching_until: Option<Instant>,
    pub last_rx: Option<Instant>,
    pub last_tx: Option<Instant>,
    pub last_handshake: Option<Instant>,
    pub rtt_ms: Option<f64>,
    pub online: bool,
    pub stats: TrafficStats,
    /// Byte counters at the last sampling tick — for rate computation.
    pub last_sample: (Instant, u64, u64),
    pub rx_bps: f64,
    pub tx_bps: f64,
}

impl PeerState {
    pub fn new(node_id: u64, name: String, wg_pub: [u8; KEY_LEN]) -> Self {
        Self {
            node_id,
            name,
            wg_pub,
            endpoints: Vec::new(),
            active_endpoint: None,
            session: None,
            pending: None,
            last_initiation_ts: None,
            cookie: None,
            punching_until: None,
            last_rx: None,
            last_tx: None,
            last_handshake: None,
            rtt_ms: None,
            online: false,
            stats: TrafficStats::default(),
            last_sample: (Instant::now(), 0, 0),
            rx_bps: 0.0,
            tx_bps: 0.0,
        }
    }

    pub fn mode(&self) -> ConnMode {
        if self.session.is_some() {
            ConnMode::Direct
        } else if self.punching_until.is_some() {
            ConnMode::Punching
        } else {
            ConnMode::Pending
        }
    }

    /// All endpoints worth trying right now: active first, then candidates.
    pub fn candidate_endpoints(&self) -> Vec<SocketAddr> {
        let mut v = Vec::with_capacity(self.endpoints.len() + 1);
        if let Some(a) = self.active_endpoint {
            v.push(a);
        }
        for e in &self.endpoints {
            if !v.contains(e) {
                v.push(*e);
            }
        }
        v
    }
}
