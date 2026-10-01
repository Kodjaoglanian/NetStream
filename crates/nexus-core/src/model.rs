//! Shared domain models for peers and connection state.

use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};

/// How a peer path is currently operating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnMode {
    /// No live session — handshake pending or peer offline.
    Pending,
    /// A punch coordination burst is in flight for this peer.
    Punching,
    /// Live encrypted session over a directly punched UDP path.
    Direct,
}

impl std::fmt::Display for ConnMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnMode::Pending => write!(f, "pending"),
            ConnMode::Punching => write!(f, "punching"),
            ConnMode::Direct => write!(f, "direct"),
        }
    }
}

/// A mesh peer as tracked by an agent.
#[derive(Debug, Clone)]
pub struct Peer {
    pub node_id: u64,
    pub name: String,
    pub vip: Ipv4Addr,
    pub wg_pubkey: [u8; 32],
    /// Candidate `ip:port` endpoints, LAN candidates first.
    pub endpoints: Vec<SocketAddr>,
    /// Endpoint currently carrying traffic, if any.
    pub active_endpoint: Option<SocketAddr>,
    pub online: bool,
    pub mode: ConnMode,
}

/// Rolling byte/packet counters for one direction of a peer session.
#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}
