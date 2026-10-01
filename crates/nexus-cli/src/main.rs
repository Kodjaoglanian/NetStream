//! nexus — command line client for the NexusMesh agent.
//!
//! Talks to `nexus-agent` over the Unix IPC socket. `nexus up` starts the
//! daemon automatically (systemd unit when available, direct spawn otherwise).

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use nexus_core::ipc::{
    self, human_bytes, human_rate, IpcRequest, IpcResponse, StatusReport, IPC_SOCK_PATH,
};
use nexus_core::model::ConnMode;
use std::path::{Path, PathBuf};
use std::process::Command as ProcCommand;
use std::time::{Duration, Instant};

#[derive(Parser)]
#[command(name = "nexus", version, about = "NexusMesh mesh VPN client")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,

    /// Path to the agent's IPC socket.
    #[arg(long, env = "NEXUS_SOCK", default_value = IPC_SOCK_PATH, global = true)]
    sock: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Join the mesh: `nexus up --server <URL> --authkey <KEY>`.
    Up {
        /// Control-plane URL, e.g. https://vpn.example.com:8080
        #[arg(long)]
        server: String,
        /// Registration auth key (`nexus_sec_...`). Required on first join;
        /// optional afterwards if the daemon has a saved session.
        #[arg(long)]
        authkey: Option<String>,
    },
    /// Disconnect from the mesh and remove the tunnel interface.
    Down,
    /// Print node and peer status.
    Status {
        /// Open the interactive dashboard instead of printing a table.
        #[arg(long)]
        tui: bool,
    },
    /// Send an encrypted ICMP echo to a peer's virtual IP.
    Ping { vip: String },
    /// Manage the local daemon itself.
    Daemon {
        #[command(subcommand)]
        op: DaemonOp,
    },
}

#[derive(Subcommand)]
enum DaemonOp {
    /// Stop the daemon entirely.
    Stop,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Command::Up { server, authkey } => cmd_up(&cli.sock, &server, authkey.as_deref()),
        Command::Down => simple_cmd(&cli.sock, &IpcRequest::Disconnect),
        Command::Status { tui: true } => cmd_tui(),
        Command::Status { tui: false } => cmd_status(&cli.sock),
        Command::Ping { vip } => cmd_ping(&cli.sock, &vip),
        Command::Daemon { op: DaemonOp::Stop } => simple_cmd(&cli.sock, &IpcRequest::Shutdown),
    }
}

fn request(sock: &Path, req: &IpcRequest) -> Result<IpcResponse> {
    ipc::request(sock, req).map_err(|e| anyhow::anyhow!(e))
}

fn simple_cmd(sock: &Path, req: &IpcRequest) -> Result<()> {
    match request(sock, req)? {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

// ----------------------------------------------------------------------
// up
// ----------------------------------------------------------------------

fn cmd_up(sock: &Path, server: &str, authkey: Option<&str>) -> Result<()> {
    ensure_daemon(sock)?;
    let resp = request(
        sock,
        &IpcRequest::Connect {
            server_url: server.to_string(),
            authkey: authkey.unwrap_or_default().to_string(),
        },
    )?;
    match resp {
        IpcResponse::Ok { message } => {
            println!("{message}");
            Ok(())
        }
        IpcResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

/// Make sure `nexus-agent` is running and its IPC socket answers.
fn ensure_daemon(sock: &Path) -> Result<()> {
    if request(sock, &IpcRequest::Status).is_ok() {
        return Ok(());
    }
    eprintln!("nexus-agent not running — starting it");

    // Prefer the packaged systemd unit when this host has it.
    let unit_present = ProcCommand::new("systemctl")
        .args(["cat", "nexus-agent.service"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if unit_present {
        let st = ProcCommand::new("systemctl")
            .args(["start", "nexus-agent.service"])
            .status()
            .context("systemctl start nexus-agent")?;
        if !st.success() {
            bail!("systemctl start nexus-agent failed");
        }
    } else {
        spawn_agent()?;
    }

    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        if request(sock, &IpcRequest::Status).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!(
        "nexus-agent did not come up (socket {} never answered)",
        sock.display()
    )
}

/// Locate `nexus-agent` next to this binary or on PATH, then spawn it
/// detached (new session, stdio to /dev/null).
fn spawn_agent() -> Result<()> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("nexus-agent"));
        }
    }
    candidates.push(PathBuf::from("nexus-agent"));

    let exe = candidates
        .iter()
        .find(|p| p.is_absolute() && p.exists())
        .cloned()
        .unwrap_or_else(|| PathBuf::from("nexus-agent"));

    let devnull = std::fs::File::open("/dev/null")?;
    let devnull2 = devnull.try_clone()?;
    let devnull3 = devnull.try_clone()?;
    let mut cmd = ProcCommand::new(&exe);
    cmd.stdin(devnull).stdout(devnull2).stderr(devnull3);
    #[cfg(unix)]
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    let _child = cmd
        .spawn()
        .with_context(|| format!("spawning {}", exe.display()))?;
    Ok(())
}

// ----------------------------------------------------------------------
// status / ping / tui
// ----------------------------------------------------------------------

fn cmd_status(sock: &Path) -> Result<()> {
    let resp = request(sock, &IpcRequest::Status)?;
    let IpcResponse::Status { report } = resp else {
        bail!("unexpected response: {resp:?}");
    };
    print_report(&report);
    Ok(())
}

fn print_report(r: &StatusReport) {
    let n = &r.node;
    println!("NexusMesh node");
    println!("  state:    {}", n.state);
    println!(
        "  node id:  {}",
        n.node_id
            .map(|i| i.to_string())
            .unwrap_or_else(|| "—".into())
    );
    println!("  vip:      {}", n.vip.as_deref().unwrap_or("—"));
    println!("  server:   {}", n.server_url.as_deref().unwrap_or("—"));
    println!(
        "  endpoint: {}",
        n.public_endpoint.as_deref().unwrap_or("—")
    );
    println!(
        "  listen:   {}",
        n.listen_port
            .map(|p| format!("{p}/udp"))
            .unwrap_or_else(|| "—".into())
    );
    println!("  uptime:   {}", fmt_uptime(n.uptime_secs));
    println!();

    if r.peers.is_empty() {
        println!("no peers");
        return;
    }
    println!(
        "{:<15} {:<16} {:<5} {:<9} {:<22} {:<9} {:>12} {:>12}",
        "VIP", "NAME", "ID", "MODE", "ENDPOINT", "RTT", "RX", "TX"
    );
    for p in &r.peers {
        let rtt = p
            .rtt_ms
            .map(|r| format!("{r:.1} ms"))
            .unwrap_or_else(|| "—".into());
        let mode = match p.mode {
            ConnMode::Direct => "direct",
            ConnMode::Punching => "punching",
            ConnMode::Pending => "pending",
        };
        println!(
            "{:<15} {:<16} {:<5} {:<9} {:<22} {:<9} {:>12} {:>12}",
            p.vip,
            truncate(&p.name, 16),
            p.node_id,
            mode,
            p.endpoint.as_deref().unwrap_or("—"),
            rtt,
            human_rate(p.rx_bps),
            human_rate(p.tx_bps),
        );
        let hs = p
            .last_handshake_secs
            .map(|s| format!("{s}s ago"))
            .unwrap_or_else(|| "never".into());
        println!(
            "{:<15} {:<16} {:<5} {:<9} {:<22} {:<9} {:>12} {:>12}",
            "",
            "",
            "",
            "",
            format!("handshake: {hs}"),
            "",
            format!("({})", human_bytes(p.rx_bytes)),
            format!("({})", human_bytes(p.tx_bytes)),
        );
    }
}

fn cmd_ping(sock: &Path, vip: &str) -> Result<()> {
    let t0 = Instant::now();
    match request(
        sock,
        &IpcRequest::Ping {
            vip: vip.to_string(),
        },
    )? {
        IpcResponse::Pong { vip, rtt_ms } => {
            println!(
                "reply from {vip}: rtt={rtt_ms:.1} ms (ipc {:.1} ms)",
                t0.elapsed().as_secs_f64() * 1000.0
            );
            Ok(())
        }
        IpcResponse::Error { message } => bail!("{message}"),
        other => bail!("unexpected response: {other:?}"),
    }
}

fn cmd_tui() -> Result<()> {
    // `nexus-tui` lives next to this binary or on PATH.
    let exe = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.join("nexus-tui")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("nexus-tui"));
    let status = ProcCommand::new(&exe)
        .status()
        .with_context(|| format!("launching {}", exe.display()))?;
    if !status.success() {
        bail!("nexus-tui exited with {status}");
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

fn fmt_uptime(secs: u64) -> String {
    let (h, m, s) = (secs / 3600, secs / 60 % 60, secs % 60);
    let d = secs / 86400;
    if d > 0 {
        format!("{d}d{h:02}h{m:02}m")
    } else if h > 0 {
        format!("{h}h{m:02}m{s:02}s")
    } else {
        format!("{m}m{s:02}s")
    }
}
