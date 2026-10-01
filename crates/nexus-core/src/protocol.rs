//! Control-plane protocol types shared between `nexus-server` and
//! `nexus-agent`. REST bodies and WebSocket signaling frames are serde-JSON.

use crate::crypto::KEY_LEN;
use crate::error::{NexusError, Result};
use serde::{Deserialize, Serialize};

/// POST `/v1/register` — a node presents an auth key and both public keys.
/// `signature` is an Ed25519 signature (hex) over the raw 32-byte WG public
/// key, proving possession of the claimed identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub authkey: String,
    pub node_name: String,
    /// Hex-encoded Ed25519 identity public key.
    pub identity_pubkey: String,
    /// Hex-encoded X25519 static (WireGuard) public key.
    pub wg_pubkey: String,
    /// Hex-encoded Ed25519 signature over the raw WG public key bytes.
    pub signature: String,
    /// `ip:port` endpoint candidates this node believes it has (LAN reflexive
    /// candidates; the public candidate is added by the server from the
    /// observed source address and STUN).
    pub endpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub node_id: u64,
    /// Assigned virtual IP inside `100.64.0.0/16`.
    pub vip: String,
    /// Bearer token for all subsequent authenticated calls.
    pub token: String,
    /// Port where the server's STUN responder listens.
    pub stun_port: u16,
    /// Current peer table.
    pub peers: Vec<PeerInfo>,
}

/// A peer as advertised by the control plane.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: u64,
    pub name: String,
    pub vip: String,
    /// Hex-encoded WG static public key.
    pub wg_pubkey: String,
    /// Candidate endpoints as `ip:port` strings.
    pub endpoints: Vec<String>,
    /// Whether the peer currently holds a signaling connection.
    pub online: bool,
    /// Seconds since the peer was last seen (signal connect or endpoint report).
    pub last_seen_secs: Option<u64>,
}

impl PeerInfo {
    /// Decode the hex WG public key.
    pub fn wg_key_bytes(&self) -> Result<[u8; KEY_LEN]> {
        let raw = hex::decode(&self.wg_pubkey)?;
        raw.try_into()
            .map_err(|_| NexusError::Protocol("bad wg_pubkey length".into()))
    }
}

/// POST `/v1/endpoint` — agent reports refreshed endpoint candidates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointReport {
    pub endpoints: Vec<String>,
}

/// Error envelope returned by the control plane on non-2xx responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

/// WebSocket signaling frames on `/v1/signal`. Serialized as tagged JSON
/// text messages, e.g. `{"type":"punch","peer_node_id":7,...}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalMessage {
    // ---- server → agent ----
    /// Sent immediately after the WS upgrade completes.
    Welcome {
        node_id: u64,
        vip: String,
        peers: Vec<PeerInfo>,
    },
    PeerJoined {
        peer: PeerInfo,
    },
    PeerUpdated {
        peer: PeerInfo,
    },
    PeerLeft {
        node_id: u64,
    },
    /// Coordinated punch order: both sides spray UDP at `endpoints`
    /// starting at `start_at_ms` (unix epoch millis).
    Punch {
        peer_node_id: u64,
        peer_vip: String,
        peer_wg_pubkey: String,
        endpoints: Vec<String>,
        start_at_ms: u64,
    },

    // ---- agent → server ----
    /// Refresh candidate endpoints observed via STUN.
    ReportEndpoints {
        endpoints: Vec<String>,
    },
    /// Ask the server to coordinate a punch with `target_node_id`.
    PunchRequest {
        target_node_id: u64,
    },
    Heartbeat,
}

/// GET `/health` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub nodes_registered: u64,
    pub nodes_online: u64,
}
