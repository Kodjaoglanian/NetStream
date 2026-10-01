//! nexus-agent — the NexusMesh node daemon.
//!
//! Requires root (or CAP_NET_ADMIN) for the TUN device and interface
//! configuration. Run directly, via `nexus up` (which spawns it), or through
//! the packaged systemd unit.

mod config;
mod engine;
mod http;
mod ipc;
mod peers;
mod signal;
mod sysnet;
mod tun;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::AgentConfig;
use engine::{Engine, EngineEvent};
use nexus_core::crypto::{IdentityKey, StaticKeyPair};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "nexus-agent", version, about = "NexusMesh node daemon")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Command>,

    /// Config file path.
    #[arg(long, default_value = config::CONFIG_FILE, env = "NEXUS_CONFIG", global = true)]
    config: PathBuf,

    /// IPC socket path.
    #[arg(long, default_value = nexus_core::ipc::IPC_SOCK_PATH, env = "NEXUS_SOCK", global = true)]
    sock: PathBuf,

    /// UDP listen port for the data plane.
    #[arg(long, env = "NEXUS_LISTEN_PORT", global = true)]
    listen_port: Option<u16>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon in the foreground (the default when no subcommand).
    Run,
    /// Print this node's public keys.
    ShowKeys,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let cli = Cli::parse();

    if unsafe { libc::geteuid() } != 0 {
        bail!("nexus-agent must run as root (TUN device + ip configuration)");
    }
    std::fs::create_dir_all(config::CONFIG_DIR)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(config::CONFIG_DIR, std::fs::Permissions::from_mode(0o700))?;
    }

    let identity = IdentityKey::load_or_create(&PathBuf::from(config::IDENTITY_KEY_FILE))?;
    let wg_key = StaticKeyPair::load_or_create(&PathBuf::from(config::WG_KEY_FILE))?;

    if let Some(Command::ShowKeys) = cli.cmd {
        println!("identity (ed25519): {}", identity.public_hex());
        println!("wg static (x25519): {}", wg_key.public_hex());
        return Ok(());
    }

    let mut cfg = AgentConfig::load(&cli.config)?;
    if let Some(p) = cli.listen_port {
        cfg.listen_port = p;
    }

    // Data-plane UDP socket.
    let std_sock = match sysnet::bind_udp(cfg.listen_port) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(error = %e, port = cfg.listen_port, "port busy — falling back to ephemeral");
            sysnet::bind_udp(0)?
        }
    };
    let udp = Arc::new(tokio::net::UdpSocket::from_std(std_sock)?);
    tracing::info!(port = udp.local_addr()?.port(), "data-plane socket bound");

    let (evt_tx, evt_rx) = tokio::sync::mpsc::unbounded_channel::<EngineEvent>();

    // IPC listener for `nexus`/`nexus-tui`.
    ipc::spawn(&cli.sock, evt_tx.clone())?;
    tracing::info!(sock = %cli.sock.display(), "IPC listening");

    // SIGTERM/SIGINT → engine shutdown.
    {
        let tx = evt_tx.clone();
        tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = signal(SignalKind::terminate()).ok();
            let mut int = signal(SignalKind::interrupt()).ok();
            tokio::select! {
                _ = async { term.as_mut().unwrap().recv().await }, if term.is_some() => {},
                _ = async { int.as_mut().unwrap().recv().await }, if int.is_some() => {},
                else => return,
            }
            let _ = tx.send(EngineEvent::Shutdown);
        });
    }

    let engine = Engine::new(cfg, cli.config.clone(), identity, wg_key, udp, evt_tx);
    engine.run(evt_rx).await?;
    let _ = std::fs::remove_file(&cli.sock);
    Ok(())
}
