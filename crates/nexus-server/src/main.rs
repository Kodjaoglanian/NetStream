//! nexus-server — the NexusMesh control plane daemon.
//!
//! Subcommands:
//!   serve         run the HTTP + signaling + STUN services
//!   issue-key     mint a `nexus_sec_…` registration key
//!   list-keys     show issued keys (hashes, labels, usage)
//!   list-nodes    show the registered node table
//!   revoke-node   delete a node by id (its VIP returns to the pool)

mod api;
mod db;
mod signal;
mod state;
mod stun;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use state::AppState;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const DEFAULT_DB: &str = "/var/lib/nexus/nexus.db";

#[derive(Parser)]
#[command(
    name = "nexus-server",
    version,
    about = "NexusMesh control plane daemon"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the coordination server (HTTP API + WebSocket signaling + STUN).
    Serve {
        /// HTTP/WebSocket listen address.
        #[arg(long, default_value = "0.0.0.0:8080", env = "NEXUS_LISTEN")]
        listen: SocketAddr,
        /// UDP listen address for the STUN responder.
        #[arg(long, default_value = "0.0.0.0:3478", env = "NEXUS_STUN_LISTEN")]
        stun_listen: SocketAddr,
        /// SQLite database path.
        #[arg(long, default_value = DEFAULT_DB, env = "NEXUS_DB")]
        db: PathBuf,
    },
    /// Issue a registration auth key (`nexus_sec_…`).
    IssueKey {
        #[arg(long, default_value = DEFAULT_DB, env = "NEXUS_DB")]
        db: PathBuf,
        /// Free-form label to remember what this key is for.
        #[arg(long, default_value = "")]
        label: String,
        /// Allow the key to register more than one node.
        #[arg(long)]
        reusable: bool,
    },
    /// List issued auth keys (hashes only — plaintext keys are never stored).
    ListKeys {
        #[arg(long, default_value = DEFAULT_DB, env = "NEXUS_DB")]
        db: PathBuf,
    },
    /// List registered nodes.
    ListNodes {
        #[arg(long, default_value = DEFAULT_DB, env = "NEXUS_DB")]
        db: PathBuf,
    },
    /// Revoke a node registration, freeing its VIP.
    RevokeNode {
        #[arg(long, default_value = DEFAULT_DB, env = "NEXUS_DB")]
        db: PathBuf,
        /// Node id (see `list-nodes`).
        node_id: u64,
    },
    /// Rotate a node's session token (invalidates its current credentials).
    RotateToken {
        #[arg(long, default_value = DEFAULT_DB, env = "NEXUS_DB")]
        db: PathBuf,
        /// Node id (see `list-nodes`).
        node_id: u64,
    },
}

fn open_db(path: &Path) -> Result<db::Db> {
    db::Db::open(path).with_context(|| format!("opening database {}", path.display()))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    match Cli::parse().cmd {
        Command::Serve {
            listen,
            stun_listen,
            db,
        } => serve(listen, stun_listen, &db).await,
        Command::IssueKey {
            db,
            label,
            reusable,
        } => {
            let db = open_db(&db)?;
            let key = db.issue_key(&label, reusable)?;
            println!(
                "Issued auth key{}:",
                if reusable { " (reusable)" } else { "" }
            );
            println!();
            println!("  {key}");
            println!();
            println!("Join nodes with:");
            println!("  curl -fsSL <install-agent.sh> | sudo sh -s -- --server http://<server>:8080 --authkey {key}");
            Ok(())
        }
        Command::ListKeys { db } => {
            let db = open_db(&db)?;
            println!(
                "{:<18} {:<20} {:<9} {:<20} USED",
                "HASH", "LABEL", "REUSABLE", "CREATED"
            );
            for k in db.list_keys()? {
                let created_str = chrono_free_ts(k.created_at);
                let used_str = k.used_at.map(chrono_free_ts).unwrap_or_else(|| "no".into());
                println!(
                    "{:<18} {:<20} {:<9} {:<20} {}",
                    &k.hash[..16.min(k.hash.len())],
                    if k.label.is_empty() { "-" } else { &k.label },
                    if k.reusable { "yes" } else { "no" },
                    created_str,
                    used_str
                );
            }
            Ok(())
        }
        Command::ListNodes { db } => {
            let db = open_db(&db)?;
            println!(
                "{:<4} {:<16} {:<16} {:<18} {:<22} {:<18} LAST-SEEN",
                "ID", "NAME", "VIP", "IDENTITY", "ENDPOINTS", "CREATED"
            );
            for n in db.list_nodes()? {
                let eps = n
                    .endpoints
                    .iter()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "{:<4} {:<16} {:<16} {:<18} {:<22} {:<18} {}",
                    n.id,
                    n.name,
                    n.vip,
                    &n.identity_pub[..16.min(n.identity_pub.len())],
                    if eps.is_empty() { "-" } else { &eps },
                    chrono_free_ts(n.created_at),
                    chrono_free_ts(n.last_seen)
                );
            }
            Ok(())
        }
        Command::RevokeNode { db, node_id } => {
            let db = open_db(&db)?;
            if db.remove_node(node_id)? {
                println!("Node {node_id} revoked; its VIP was returned to the pool.");
            } else {
                println!("No node with id {node_id}.");
            }
            Ok(())
        }
        Command::RotateToken { db, node_id } => {
            let db = open_db(&db)?;
            if db.node_by_id(node_id)?.is_none() {
                println!("No node with id {node_id}.");
                return Ok(());
            }
            let token = db.rotate_token(node_id)?;
            println!("Rotated session token for node {node_id}:");
            println!();
            println!("  {token}");
            println!();
            println!("Update the node's /etc/nexus/config.json or re-register.");
            Ok(())
        }
    }
}

/// Seconds → `YYYY-MM-DD HH:MM` UTC without pulling in a datetime crate.
fn chrono_free_ts(secs: i64) -> String {
    if secs <= 0 {
        return "never".into();
    }
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m) = (rem / 3600, (rem % 3600) / 60);
    // Civil date from days since epoch (Howard Hinnant's algorithm).
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mo <= 2 { y + 1 } else { y };
    format!("{year:04}-{mo:02}-{d:02} {h:02}:{m:02}Z")
}

async fn serve(listen: SocketAddr, stun_listen: SocketAddr, db_path: &PathBuf) -> Result<()> {
    let db = open_db(db_path)?;
    let stun_port = stun_listen.port();
    let state = Arc::new(AppState::new(db, stun_port));

    // STUN responder on its own UDP port.
    let stun_metrics = state.metrics.clone();
    tokio::spawn(async move {
        if let Err(e) = stun::run_stun(stun_listen, stun_metrics).await {
            tracing::error!(error = %e, "STUN responder exited");
        }
    });

    let app = api::router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, stun_port, "control plane listening");
    println!("NexusMesh control plane on http://{listen}  (STUN :{stun_port}/udp)");
    println!("Issue a join key with:  nexus-server issue-key");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutdown requested");
}
