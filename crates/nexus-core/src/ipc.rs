//! Local IPC protocol between `nexus`/`nexus-tui` (clients) and the running
//! `nexus-agent` daemon over a Unix domain socket.
//!
//! Framing: one JSON object per line (newline-delimited JSON).

use crate::error::{NexusError, Result};
use crate::model::ConnMode;
use serde::{Deserialize, Serialize};

/// Default Unix socket path.
pub const IPC_SOCK_PATH: &str = "/var/run/nexus.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Attach to the mesh: `nexus up --server <URL> --authkey <KEY>`.
    Connect { server_url: String, authkey: String },
    /// Tear down the tunnel but keep the daemon alive.
    Disconnect,
    /// Tear down and exit the daemon: `nexus down`.
    Shutdown,
    /// Full status snapshot for `nexus status` / the TUI.
    Status,
    /// Send an ICMP echo to a peer VIP through the tunnel and measure RTT.
    Ping { vip: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok { message: String },
    Error { message: String },
    Status { report: StatusReport },
    Pong { vip: String, rtt_ms: f64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusReport {
    pub node: NodeStatus,
    pub peers: Vec<PeerStatus>,
    /// Most recent log/audit events, oldest first.
    pub events: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    /// Daemon lifecycle state: `down`, `connecting`, `connected`.
    pub state: String,
    pub node_id: Option<u64>,
    pub vip: Option<String>,
    pub server_url: Option<String>,
    /// Our STUN-observed public endpoint, once discovered.
    pub public_endpoint: Option<String>,
    pub listen_port: Option<u16>,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub node_id: u64,
    pub name: String,
    pub vip: String,
    pub wg_pubkey_short: String,
    pub endpoint: Option<String>,
    pub mode: ConnMode,
    pub rtt_ms: Option<f64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Smoothed throughput over the last sampling window.
    pub rx_bps: f64,
    pub tx_bps: f64,
    /// Seconds since the last completed handshake.
    pub last_handshake_secs: Option<u64>,
}

/// Serialize one IPC message to a JSON line.
pub fn encode<T: Serialize>(msg: &T) -> Result<String> {
    let mut s = serde_json::to_string(msg)?;
    s.push('\n');
    Ok(s)
}

/// Parse one JSON line into an IPC message.
pub fn decode<'a, T: Deserialize<'a>>(line: &'a str) -> Result<T> {
    serde_json::from_str(line.trim_end())
        .map_err(|e| NexusError::Ipc(format!("invalid IPC frame: {e}")))
}

/// Synchronous request/response against a running `nexus-agent` socket.
/// Used by `nexus` and `nexus-tui` — neither needs an async runtime.
#[cfg(unix)]
pub fn request(path: &std::path::Path, req: &IpcRequest) -> Result<IpcResponse> {
    use std::io::{BufRead, BufReader, Write};

    let mut stream = std::os::unix::net::UnixStream::connect(path)
        .map_err(|e| NexusError::Ipc(format!("connect {}: {e}", path.display())))?;
    stream.write_all(encode(req)?.as_bytes())?;
    let mut line = String::new();
    let mut reader = BufReader::new(stream);
    reader.read_line(&mut line)?;
    if line.is_empty() {
        return Err(NexusError::Ipc("daemon closed the connection".into()));
    }
    decode(&line)
}

/// Human-readable byte count (`1.5 MiB`).
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} {}", UNITS[u])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Human-readable bit/byte rate (`812 B/s`, `4.2 KiB/s`).
pub fn human_rate(bps: f64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    let mut v = bps.max(0.0);
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if v >= 100.0 || u == 0 {
        format!("{v:.0} {}", UNITS[u])
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
