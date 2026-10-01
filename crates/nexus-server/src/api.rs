//! HTTP control-plane API: registration, peer table, endpoint reports,
//! health, and Prometheus metrics.

use crate::db::NodeRow;
use crate::signal;
use crate::state::AppState;
use axum::extract::{ConnectInfo, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use nexus_core::crypto::{generate_session_token, is_authkey, verify_identity, KEY_LEN};
use nexus_core::protocol::{
    ApiError, EndpointReport, HealthResponse, RegisterRequest, RegisterResponse,
};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

type ApiResult<T> = Result<T, (StatusCode, Json<ApiError>)>;

fn err(status: StatusCode, msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (status, Json(ApiError { error: msg.into() }))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/register", post(register))
        .route("/v1/peers", get(list_peers))
        .route("/v1/endpoint", post(report_endpoint))
        .route("/v1/signal", get(signal::ws_handler))
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .with_state(state)
}

fn decode_hex32(s: &str, what: &str) -> ApiResult<[u8; KEY_LEN]> {
    let raw = hex::decode(s)
        .map_err(|_| err(StatusCode::BAD_REQUEST, format!("{what} is not valid hex")))?;
    raw.try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, format!("{what} must be 32 bytes")))
}

fn decode_hex64(s: &str, what: &str) -> ApiResult<[u8; 64]> {
    let raw = hex::decode(s)
        .map_err(|_| err(StatusCode::BAD_REQUEST, format!("{what} is not valid hex")))?;
    raw.try_into()
        .map_err(|_| err(StatusCode::BAD_REQUEST, format!("{what} must be 64 bytes")))
}

fn parse_endpoints(list: &[String]) -> Vec<SocketAddr> {
    list.iter()
        .filter_map(|s| s.trim().parse::<SocketAddr>().ok())
        .collect()
}

/// Authenticate via `Authorization: Bearer <session token>`.
fn auth_node(state: &AppState, headers: &HeaderMap) -> ApiResult<NodeRow> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    state
        .db()
        .node_by_token(token)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "invalid session token"))
}

async fn register(
    State(state): State<Arc<AppState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    Json(req): Json<RegisterRequest>,
) -> ApiResult<Json<RegisterResponse>> {
    state.metrics.http_requests.fetch_add(1, Ordering::Relaxed);

    if !is_authkey(&req.authkey) {
        return Err(err(StatusCode::UNAUTHORIZED, "malformed auth key"));
    }
    let identity_pub = decode_hex32(&req.identity_pubkey, "identity_pubkey")?;
    let wg_pub = decode_hex32(&req.wg_pubkey, "wg_pubkey")?;
    let signature = decode_hex64(&req.signature, "signature")?;

    // The identity key must prove ownership of the presented WG key so an
    // auth-key leak cannot be used to impersonate an existing node.
    verify_identity(&identity_pub, &wg_pub, &signature)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "identity signature invalid"))?;

    let endpoints = parse_endpoints(&req.endpoints);

    let db = state.db();
    if !db
        .consume_key(&req.authkey)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        return Err(err(StatusCode::UNAUTHORIZED, "auth key invalid or used"));
    }
    let token = generate_session_token();
    let (node_id, vip) = db
        .register_node(
            &req.node_name,
            &req.identity_pubkey,
            &req.wg_pubkey,
            &token,
            &endpoints,
        )
        .map_err(|e| err(StatusCode::CONFLICT, format!("registration failed: {e}")))?;
    drop(db);

    state.metrics.registrations.fetch_add(1, Ordering::Relaxed);
    tracing::info!(node_id, %vip, %remote, name = %req.node_name, "node registered");

    let peers = state
        .db()
        .list_nodes()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .filter(|n| n.id != node_id)
        .map(|n| state.peer_info(&n))
        .collect();

    Ok(Json(RegisterResponse {
        node_id,
        vip: vip.to_string(),
        token,
        stun_port: state.stun_port,
        peers,
    }))
}

async fn list_peers(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> ApiResult<Json<Vec<nexus_core::protocol::PeerInfo>>> {
    state.metrics.http_requests.fetch_add(1, Ordering::Relaxed);
    let me = auth_node(&state, &headers)?;
    let peers = state
        .db()
        .list_nodes()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_iter()
        .filter(|n| n.id != me.id)
        .map(|n| state.peer_info(&n))
        .collect();
    Ok(Json(peers))
}

async fn report_endpoint(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<EndpointReport>,
) -> ApiResult<Json<serde_json::Value>> {
    state.metrics.http_requests.fetch_add(1, Ordering::Relaxed);
    let me = auth_node(&state, &headers)?;
    let endpoints = parse_endpoints(&req.endpoints);

    state
        .db()
        .update_endpoints(me.id, &endpoints)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Reflect into the live registry and notify other online nodes.
    {
        let mut online = state.online.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(p) = online.get_mut(&me.id) {
            p.endpoints = endpoints;
        }
    }
    if let Some(node) = state
        .db()
        .node_by_id(me.id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        let info = state.peer_info(&node);
        state.broadcast(
            me.id,
            &nexus_core::protocol::SignalMessage::PeerUpdated { peer: info },
        );
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn health(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let registered = state.db().list_nodes().map(|v| v.len() as u64).unwrap_or(0);
    let online = state.online.lock().map(|m| m.len() as u64).unwrap_or(0);
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        nodes_registered: registered,
        nodes_online: online,
    })
}

async fn metrics(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let registered = state.db().list_nodes().map(|v| v.len() as u64).unwrap_or(0);
    let online = state.online.lock().map(|m| m.len() as u64).unwrap_or(0);
    let uptime = state.started.elapsed().as_secs();
    (
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render_prometheus(registered, online, uptime),
    )
}
