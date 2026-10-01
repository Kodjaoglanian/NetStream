//! Signaling WebSocket client: persistent connection to the control plane
//! with exponential-backoff reconnect, heartbeats, and channel bridging.

use futures_util::{SinkExt, StreamExt};
use nexus_core::protocol::SignalMessage;
use std::time::Duration;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::{interval, sleep};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Events the signaling task feeds to the engine.
pub enum SignalEvent {
    /// The WS connection is up and authenticated.
    Connected,
    /// The WS connection dropped (or failed); the supervisor retries itself.
    Disconnected,
    /// Server rejected our session token (HTTP 401) — credentials invalid.
    AuthRejected,
    /// A decoded signaling message from the server.
    Message(SignalMessage),
}

/// Spawn the supervisor. Returns the join handle plus the channel the engine
/// uses to send `SignalMessage`s upstream.
pub fn spawn(
    url: String,
    token: String,
    evt_tx: UnboundedSender<SignalEvent>,
) -> (tokio::task::JoinHandle<()>, UnboundedSender<String>) {
    let (out_tx, out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let handle = tokio::spawn(supervisor(url, token, evt_tx, out_rx));
    (handle, out_tx)
}

async fn supervisor(
    url: String,
    token: String,
    evt_tx: UnboundedSender<SignalEvent>,
    mut out_rx: UnboundedReceiver<String>,
) {
    let full_url = format!("{url}?token={token}");
    let mut backoff = Duration::from_secs(1);
    loop {
        match connect_async(&full_url).await {
            Ok((ws, _resp)) => {
                tracing::info!(%url, "signaling connected");
                let _ = evt_tx.send(SignalEvent::Connected);
                let (mut wtx, mut wrx) = ws.split();
                let mut hb = interval(HEARTBEAT_INTERVAL);
                hb.tick().await; // first tick is immediate — skip it

                let disconnect_reason = loop {
                    tokio::select! {
                        msg = wrx.next() => match msg {
                            Some(Ok(Message::Text(t))) => {
                                match serde_json::from_str::<SignalMessage>(&t) {
                                    Ok(m) => {
                                        if evt_tx.send(SignalEvent::Message(m)).is_err() {
                                            return; // engine gone
                                        }
                                    }
                                    Err(e) => {
                                        tracing::debug!(error = %e, "bad signal frame");
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => break "closed".to_string(),
                            Some(Ok(_)) => {}
                            Some(Err(e)) => break e.to_string(),
                        },
                        out = out_rx.recv() => match out {
                            Some(text) => {
                                if wtx.send(Message::Text(text)).await.is_err() {
                                    break "send failed".to_string();
                                }
                            }
                            None => return, // engine dropped the sender — shut down
                        },
                        _ = hb.tick() => {
                            let hb_json = serde_json::to_string(&SignalMessage::Heartbeat)
                                .unwrap_or_else(|_| "{}".into());
                            if wtx.send(Message::Text(hb_json)).await.is_err() {
                                break "heartbeat failed".to_string();
                            }
                        }
                    }
                };
                let _ = evt_tx.send(SignalEvent::Disconnected);
                tracing::warn!(reason = %disconnect_reason, "signaling lost; reconnecting");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                // A 401 means our session token is invalid — tell the engine
                // so it can re-register instead of retrying forever.
                let rejected = matches!(
                    &e,
                    tokio_tungstenite::tungstenite::Error::Http(resp)
                        if resp.status().as_u16() == 401
                );
                if rejected {
                    let _ = evt_tx.send(SignalEvent::AuthRejected);
                }
                tracing::warn!(error = %e, retry_in = ?backoff, "signaling connect failed");
                let _ = evt_tx.send(SignalEvent::Disconnected);
                sleep(backoff).await;
                backoff = (backoff * 2).min(BACKOFF_MAX);
            }
        }
    }
}
