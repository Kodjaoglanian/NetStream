//! STUN binding responder (RFC 5389 minimal) — agents discover their public
//! reflexive UDP endpoint by sending binding requests here.

use crate::state::Metrics;
use nexus_core::stun::{build_binding_response, is_stun_message, parse_binding_request};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Run the STUN responder on `bind` until the task is aborted.
pub async fn run_stun(bind: SocketAddr, metrics: Arc<Metrics>) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(bind).await?;
    tracing::info!(%bind, "STUN responder listening");
    let mut buf = [0u8; 2048];
    loop {
        match sock.recv_from(&mut buf).await {
            Ok((n, src)) => {
                let msg = &buf[..n];
                if !is_stun_message(msg) {
                    continue;
                }
                match parse_binding_request(msg) {
                    Ok(txid) => {
                        metrics.stun_queries.fetch_add(1, Ordering::Relaxed);
                        let resp = build_binding_response(&txid, src);
                        if let Err(e) = sock.send_to(&resp, src).await {
                            warn!(%src, error = %e, "STUN response send failed");
                        } else {
                            debug!(%src, "answered STUN binding request");
                        }
                    }
                    Err(e) => debug!(%src, error = %e, "ignoring malformed STUN message"),
                }
            }
            Err(e) => {
                warn!(error = %e, "STUN socket recv failed");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}
