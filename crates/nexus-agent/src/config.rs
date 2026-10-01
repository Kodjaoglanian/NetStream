//! On-disk agent configuration at `/etc/nexus/`.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::Path;

pub const CONFIG_DIR: &str = "/etc/nexus";
pub const CONFIG_FILE: &str = "/etc/nexus/config.json";
pub const IDENTITY_KEY_FILE: &str = "/etc/nexus/identity.key";
pub const WG_KEY_FILE: &str = "/etc/nexus/wg.key";

/// Persisted agent state — written after a successful registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Control-plane base URL, e.g. `http://vpn.example.com:8080`.
    pub server_url: String,
    /// Auth key used for the (re)registration — kept so credential rotation
    /// can re-register transparently when marked reusable.
    pub authkey: Option<String>,
    /// Bearer session token issued by the server.
    pub token: Option<String>,
    pub node_id: Option<u64>,
    pub vip: Option<Ipv4Addr>,
    /// UDP port the data-plane socket binds.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    /// Human-readable node name shown in peer tables.
    pub name: String,
    /// TUN MTU. 1400 leaves headroom for UDP + Noise overhead on 1500-MTU links.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

fn default_listen_port() -> u16 {
    51820
}
fn default_mtu() -> u16 {
    1400
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            server_url: String::new(),
            authkey: None,
            token: None,
            node_id: None,
            vip: None,
            listen_port: default_listen_port(),
            name: hostname(),
            mtu: default_mtu(),
        }
    }
}

impl AgentConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = match std::fs::read_to_string(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => {
                return Err(e).with_context(|| format!("reading {}", path.display()));
            }
        };
        serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self)? + "\n")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Derive `ws://`/`wss://` signaling URL from `server_url`.
    pub fn signal_url(&self) -> String {
        let base = self.server_url.trim_end_matches('/');
        let ws_base = if let Some(rest) = base.strip_prefix("https://") {
            format!("wss://{rest}")
        } else if let Some(rest) = base.strip_prefix("http://") {
            format!("ws://{rest}")
        } else {
            base.to_string()
        };
        format!("{ws_base}/v1/signal")
    }
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "node".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nexus-agent-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let cfg = AgentConfig {
            server_url: "http://vpn.example.com:8080".into(),
            vip: Some("100.64.0.7".parse().unwrap()),
            ..Default::default()
        };
        cfg.save(&path).unwrap();
        let loaded = AgentConfig::load(&path).unwrap();
        assert_eq!(loaded.server_url, cfg.server_url);
        assert_eq!(loaded.vip, cfg.vip);
        assert_eq!(loaded.listen_port, cfg.listen_port);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn missing_config_is_default() {
        let cfg = AgentConfig::load(Path::new("/nonexistent/nexus-x.json")).unwrap();
        assert!(cfg.server_url.is_empty());
    }

    #[test]
    fn signal_url_scheme_swap() {
        let mut cfg = AgentConfig {
            server_url: "https://vpn.example.com".into(),
            ..Default::default()
        };
        assert_eq!(cfg.signal_url(), "wss://vpn.example.com/v1/signal");
        cfg.server_url = "http://10.0.0.1:8080/".into();
        assert_eq!(cfg.signal_url(), "ws://10.0.0.1:8080/v1/signal");
    }
}
