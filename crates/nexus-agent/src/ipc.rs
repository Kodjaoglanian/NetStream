//! Unix-socket IPC server: `nexus`/`nexus-tui` talk to the daemon here.
//! Newline-delimited JSON; each connection serves request→response pairs.

use crate::engine::EngineEvent;
use anyhow::Result;
use nexus_core::ipc::{decode, encode, IpcRequest, IpcResponse};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc::UnboundedSender, oneshot};

/// Bind the IPC socket and spawn the accept loop. Stale socket files are
/// removed first. Returns the bound path actually used.
pub fn spawn(path: &Path, evt_tx: UnboundedSender<EngineEvent>) -> Result<String> {
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let listener = UnixListener::bind(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Root-only control channel.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    }
    let bound = path.display().to_string();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let tx = evt_tx.clone();
                    tokio::spawn(handle_conn(stream, tx));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "IPC accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    });
    Ok(bound)
}

async fn handle_conn(stream: UnixStream, evt_tx: UnboundedSender<EngineEvent>) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    loop {
        let line = match lines.next_line().await {
            Ok(Some(l)) => l,
            _ => return, // closed or error
        };
        let req: IpcRequest = match decode(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = IpcResponse::Error {
                    message: format!("bad request frame: {e}"),
                };
                if let Ok(text) = encode(&resp) {
                    let _ = write_half.write_all(text.as_bytes()).await;
                }
                continue;
            }
        };
        let (tx, rx) = oneshot::channel::<IpcResponse>();
        if evt_tx.send(EngineEvent::Ipc { req, reply: tx }).is_err() {
            return;
        }
        let resp = match rx.await {
            Ok(r) => r,
            Err(_) => IpcResponse::Error {
                message: "daemon engine dropped the request".into(),
            },
        };
        match encode(&resp) {
            Ok(text) => {
                if write_half.write_all(text.as_bytes()).await.is_err() {
                    return;
                }
            }
            Err(_) => return,
        }
    }
}
