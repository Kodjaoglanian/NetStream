//! Shared server state: database handle, online-peer registry, and metrics.

use crate::db::Db;
use nexus_core::protocol::{PeerInfo, SignalMessage};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::sync::mpsc::UnboundedSender;

/// A node currently holding a signaling WebSocket.
pub struct OnlinePeer {
    pub node_id: u64,
    pub name: String,
    pub vip: String,
    pub wg_pub: String,
    /// Current candidate endpoints reported via signaling/registration.
    pub endpoints: Vec<SocketAddr>,
    /// Channel feeding the agent's WebSocket.
    pub tx: UnboundedSender<String>,
}

#[derive(Default)]
pub struct Metrics {
    pub http_requests: AtomicU64,
    pub registrations: AtomicU64,
    pub punches_coordinated: AtomicU64,
    pub stun_queries: AtomicU64,
    pub ws_connects: AtomicU64,
}

impl Metrics {
    pub fn render_prometheus(&self, registered: u64, online: u64, uptime: u64) -> String {
        format!(
            "# HELP nexus_nodes_registered Total registered nodes\n\
             # TYPE nexus_nodes_registered gauge\n\
             nexus_nodes_registered {registered}\n\
             # HELP nexus_nodes_online Nodes holding a signaling socket\n\
             # TYPE nexus_nodes_online gauge\n\
             nexus_nodes_online {online}\n\
             # HELP nexus_http_requests_total HTTP API requests served\n\
             # TYPE nexus_http_requests_total counter\n\
             nexus_http_requests_total {}\n\
             # HELP nexus_registrations_total Successful node registrations\n\
             # TYPE nexus_registrations_total counter\n\
             nexus_registrations_total {}\n\
             # HELP nexus_punches_coordinated_total Hole-punch coordinations issued\n\
             # TYPE nexus_punches_coordinated_total counter\n\
             nexus_punches_coordinated_total {}\n\
             # HELP nexus_stun_queries_total STUN binding queries answered\n\
             # TYPE nexus_stun_queries_total counter\n\
             nexus_stun_queries_total {}\n\
             # HELP nexus_ws_connects_total Signaling WebSocket connections\n\
             # TYPE nexus_ws_connects_total counter\n\
             nexus_ws_connects_total {}\n\
             # HELP nexus_uptime_seconds Server uptime\n\
             # TYPE nexus_uptime_seconds gauge\n\
             nexus_uptime_seconds {uptime}\n",
            self.http_requests.load(Ordering::Relaxed),
            self.registrations.load(Ordering::Relaxed),
            self.punches_coordinated.load(Ordering::Relaxed),
            self.stun_queries.load(Ordering::Relaxed),
            self.ws_connects.load(Ordering::Relaxed),
        )
    }
}

pub struct AppState {
    pub db: Mutex<Db>,
    pub online: Mutex<HashMap<u64, OnlinePeer>>,
    /// Shared counters, also handed to the STUN responder.
    pub metrics: Arc<Metrics>,
    /// UDP port where the STUN responder listens (advertised to agents).
    pub stun_port: u16,
    pub started: Instant,
}

impl AppState {
    pub fn new(db: Db, stun_port: u16) -> Self {
        Self {
            db: Mutex::new(db),
            online: Mutex::new(HashMap::new()),
            metrics: Arc::new(Metrics::default()),
            stun_port,
            started: Instant::now(),
        }
    }

    pub fn db(&self) -> MutexGuard<'_, Db> {
        match self.db.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    fn online(&self) -> MutexGuard<'_, HashMap<u64, OnlinePeer>> {
        match self.online.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Queue a signaling message for an online node. Returns false if offline.
    pub fn send_to(&self, node_id: u64, msg: &SignalMessage) -> bool {
        let guard = self.online();
        if let Some(peer) = guard.get(&node_id) {
            match serde_json::to_string(msg) {
                Ok(text) => return peer.tx.send(text).is_ok(),
                Err(_) => return false,
            }
        }
        false
    }

    /// Queue a signaling message for every online node except `except`.
    pub fn broadcast(&self, except: u64, msg: &SignalMessage) {
        if let Ok(text) = serde_json::to_string(msg) {
            for (id, peer) in self.online().iter() {
                if *id != except {
                    let _ = peer.tx.send(text.clone());
                }
            }
        }
    }

    /// Build the `PeerInfo` view of a node for a requesting peer.
    pub fn peer_info(&self, node: &crate::db::NodeRow) -> PeerInfo {
        let online_guard = self.online();
        let (online, endpoints) = match online_guard.get(&node.id) {
            Some(p) => (true, p.endpoints.iter().map(|a| a.to_string()).collect()),
            None => (
                false,
                node.endpoints.iter().map(|a| a.to_string()).collect(),
            ),
        };
        PeerInfo {
            node_id: node.id,
            name: node.name.clone(),
            vip: node.vip.to_string(),
            wg_pubkey: node.wg_pub.clone(),
            endpoints,
            online,
            last_seen_secs: Some((crate::db::now_secs() - node.last_seen).max(0) as u64),
        }
    }
}
