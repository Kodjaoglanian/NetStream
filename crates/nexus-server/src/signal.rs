//! Signaling WebSocket: agent connections, peer-table fan-out, and the
//! NAT hole-punch coordinator.
//!
//! When two nodes should open a direct path, the server sends each of them a
//! `Punch` message containing the other's endpoint candidates and a common
//! start timestamp. Both agents then spray UDP packets at those endpoints
//! simultaneously, opening the NAT mappings for each other.

use crate::db::NodeRow;
use crate::state::{AppState, OnlinePeer};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use nexus_core::protocol::{PeerInfo, SignalMessage};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Milliseconds between punch order dispatch and simultaneous burst start —
/// gives both agents time to receive and arm before spraying.
const PUNCH_LEAD_MS: u64 = 400;

#[derive(Deserialize)]
pub struct SignalQuery {
    token: String,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Query(q): Query<SignalQuery>,
    State(state): State<Arc<AppState>>,
) -> axum::response::Response {
    let node = match state.db().node_by_token(&q.token) {
        Ok(Some(node)) => node,
        _ => return StatusCode::UNAUTHORIZED.into_response(),
    };
    ws.on_upgrade(move |sock| handle_socket(sock, state, node))
        .into_response()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Issue a symmetric punch order: tell `a` to punch `b`'s endpoints and `b`
/// to punch `a`'s, both starting at the same wall-clock instant.
pub fn coordinate_punch(state: &Arc<AppState>, a_id: u64, b_id: u64) {
    let (a, b) = {
        let online = match state.online.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let get = |id: u64| {
            online.get(&id).map(|p| {
                (
                    p.node_id,
                    p.name.clone(),
                    p.vip.clone(),
                    p.wg_pub.clone(),
                    p.endpoints.clone(),
                )
            })
        };
        (get(a_id), get(b_id))
    };
    let (Some((_, a_name, a_vip, a_pub, a_eps)), Some((_, b_name, b_vip, b_pub, b_eps))) = (a, b)
    else {
        return; // one side offline — nothing to coordinate
    };
    let start = now_ms() + PUNCH_LEAD_MS;
    let eps_to_str = |v: &[SocketAddr]| v.iter().map(|a| a.to_string()).collect::<Vec<_>>();

    state.send_to(
        a_id,
        &SignalMessage::Punch {
            peer_node_id: b_id,
            peer_vip: b_vip,
            peer_wg_pubkey: b_pub,
            endpoints: eps_to_str(&b_eps),
            start_at_ms: start,
        },
    );
    state.send_to(
        b_id,
        &SignalMessage::Punch {
            peer_node_id: a_id,
            peer_vip: a_vip,
            peer_wg_pubkey: a_pub,
            endpoints: eps_to_str(&a_eps),
            start_at_ms: start,
        },
    );
    state
        .metrics
        .punches_coordinated
        .fetch_add(1, Ordering::Relaxed);
    debug!(a_id, %a_name, b_id, %b_name, start, "coordinated punch");
}

async fn handle_socket(sock: WebSocket, state: Arc<AppState>, node: NodeRow) {
    let node_id = node.id;
    let (mut ws_tx, mut ws_rx) = sock.split();
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();

    // Forward task: channel → WebSocket.
    let fwd = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if ws_tx.send(Message::Text(text)).await.is_err() {
                break;
            }
        }
    });

    // Register in the online map (replace any stale connection for this node).
    {
        let mut online = state.online.lock().unwrap_or_else(|p| p.into_inner());
        online.insert(
            node_id,
            OnlinePeer {
                node_id,
                name: node.name.clone(),
                vip: node.vip.to_string(),
                wg_pub: node.wg_pub.clone(),
                endpoints: node.endpoints.clone(),
                tx: tx.clone(),
            },
        );
    }
    state.metrics.ws_connects.fetch_add(1, Ordering::Relaxed);
    state.db().touch(node_id).ok();
    info!(node_id, name = %node.name, vip = %node.vip, "node came online");

    // Welcome with the full peer table, then announce the join.
    let peers: Vec<PeerInfo> = state
        .db()
        .list_nodes()
        .unwrap_or_default()
        .into_iter()
        .filter(|n| n.id != node_id)
        .map(|n| state.peer_info(&n))
        .collect();
    state.send_to(
        node_id,
        &SignalMessage::Welcome {
            node_id,
            vip: node.vip.to_string(),
            peers,
        },
    );
    let me_info = state.peer_info(&node);
    state.broadcast(node_id, &SignalMessage::PeerJoined { peer: me_info });

    // Coordinate a punch toward every other online node: full mesh, and the
    // newcomer gets a symmetric order for each existing member.
    let others: Vec<u64> = {
        let online = state.online.lock().unwrap_or_else(|p| p.into_inner());
        online.keys().copied().filter(|id| *id != node_id).collect()
    };
    for other in others {
        coordinate_punch(&state, node_id, other);
    }

    // Read loop: incoming control messages from the agent.
    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(text)) => match serde_json::from_str::<SignalMessage>(&text) {
                Ok(SignalMessage::ReportEndpoints { endpoints }) => {
                    let eps: Vec<SocketAddr> = endpoints
                        .iter()
                        .filter_map(|s| s.parse::<SocketAddr>().ok())
                        .collect();
                    debug!(node_id, ?eps, "endpoint report");
                    {
                        let mut online = state.online.lock().unwrap_or_else(|p| p.into_inner());
                        if let Some(p) = online.get_mut(&node_id) {
                            p.endpoints = eps.clone();
                        }
                    }
                    let _ = state.db().update_endpoints(node_id, &eps);
                    if let Ok(Some(n)) = state.db().node_by_id(node_id) {
                        let info = state.peer_info(&n);
                        state.broadcast(node_id, &SignalMessage::PeerUpdated { peer: info });
                    }
                }
                Ok(SignalMessage::PunchRequest { target_node_id }) => {
                    coordinate_punch(&state, node_id, target_node_id);
                }
                Ok(SignalMessage::Heartbeat) => {
                    let _ = state.db().touch(node_id);
                }
                Ok(_) => {}
                Err(e) => debug!(node_id, error = %e, "ignoring invalid signal frame"),
            },
            Ok(Message::Close(_)) => break,
            Err(e) => {
                warn!(node_id, error = %e, "signaling socket error");
                break;
            }
            Ok(_) => {}
        }
    }

    // Teardown: mark offline and tell the remaining mesh.
    {
        let mut online = state.online.lock().unwrap_or_else(|p| p.into_inner());
        online.remove(&node_id);
    }
    state.broadcast(node_id, &SignalMessage::PeerLeft { node_id });
    fwd.abort();
    info!(node_id, "node went offline");
    let _ = state.db().touch(node_id);
    drop(state);
}
