//! WebSocket client for real-time subscriptions.
//!
//! Connects to the authenticated WebSocket endpoint (/api/v1/ws)
//! and provides an async stream of events.

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, warn};

use crate::auth::{NodeBinding, WalletSigner};
use crate::error::SdkError;
use crate::types::{Health, WsEvent};

// Inbound frame/message size caps (audit 2026-06-07 W2). The SDK connects to
// nodes discovered from untrusted SC/gossip; a hostile node could otherwise
// stream a multi-GB frame and OOM the client. These bounds reject oversized
// frames during the protocol read instead of buffering them.
const MAX_WS_MESSAGE_SIZE: usize = 16 * 1024 * 1024; // 16 MiB
const MAX_WS_FRAME_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

/// Fetch the node's auth binding (`network` + `node_id`) from
/// `GET {http_base}/api/v1/health`. Used by the WS connect path, which has
/// no client instance to cache it on.
async fn fetch_node_binding(http_base: &str) -> Result<NodeBinding, SdkError> {
    let url = format!("{}/api/v1/health", http_base);
    let health: Health = reqwest::get(&url)
        .await?
        .error_for_status()?
        .json()
        .await?;
    match (health.node_id, health.network) {
        (Some(node_id), Some(network)) if !node_id.is_empty() && !network.is_empty() => {
            Ok(NodeBinding { network, node_id })
        }
        _ => Err(SdkError::Protocol(
            "node /health lacks node_id/network — too old for host-bound auth".into(),
        )),
    }
}

/// A handle to an active WebSocket subscription.
pub struct WsSubscription {
    /// Receiver for incoming events. Private because `WsSubscription` now
    /// implements `Drop` (audit 2026-06-07 W5), which forbids moving fields
    /// out of the struct — use [`Self::recv`] / [`Self::events_mut`] instead.
    events: mpsc::Receiver<WsEvent>,
    /// Sender for outgoing commands (subscribe, unsubscribe, etc.).
    command_tx: mpsc::Sender<WsCommand>,
    /// Handle to the background event loop task (audit 2026-06-07 W5).
    /// Retained so `Drop` can abort it promptly — otherwise dropping the
    /// subscription while the event receiver is gone would leave the task,
    /// socket, and channels alive until the next inbound message.
    task: JoinHandle<()>,
}

/// Commands that can be sent to the WebSocket.
#[derive(Debug)]
enum WsCommand {
    Subscribe(Vec<String>),
    Unsubscribe(Vec<String>),
    SubscribeDm,
    Close,
}

impl WsSubscription {
    /// Receive the next event, or `None` once the connection closes.
    ///
    /// Replaces direct access to the (now private) `events` field, which `Drop`
    /// (audit 2026-06-07 W5) prevents moving out of the struct.
    pub async fn recv(&mut self) -> Option<WsEvent> {
        self.events.recv().await
    }

    /// Mutable access to the underlying event receiver, for callers that need
    /// `select!`/stream adapters over it.
    pub fn events_mut(&mut self) -> &mut mpsc::Receiver<WsEvent> {
        &mut self.events
    }

    /// Subscribe to additional channels.
    pub async fn subscribe(&self, channels: Vec<String>) -> Result<(), SdkError> {
        self.command_tx
            .send(WsCommand::Subscribe(channels))
            .await
            .map_err(|_| SdkError::WebSocket("connection closed".into()))
    }

    /// Unsubscribe from channels.
    pub async fn unsubscribe(&self, channels: Vec<String>) -> Result<(), SdkError> {
        self.command_tx
            .send(WsCommand::Unsubscribe(channels))
            .await
            .map_err(|_| SdkError::WebSocket("connection closed".into()))
    }

    /// Subscribe to DMs for the authenticated user.
    pub async fn subscribe_dm(&self) -> Result<(), SdkError> {
        self.command_tx
            .send(WsCommand::SubscribeDm)
            .await
            .map_err(|_| SdkError::WebSocket("connection closed".into()))
    }

    /// Close the WebSocket connection.
    pub async fn close(&self) -> Result<(), SdkError> {
        self.command_tx
            .send(WsCommand::Close)
            .await
            .map_err(|_| SdkError::WebSocket("connection closed".into()))
    }
}

impl Drop for WsSubscription {
    /// Tear down the background task promptly when the subscription is dropped
    /// (audit 2026-06-07 W5). Best-effort signal a graceful close, then abort
    /// the task so an idle connection can't outlive its handle and leak the
    /// task, socket, and channels.
    fn drop(&mut self) {
        // try_send (non-blocking) — Drop isn't async. If the loop is alive and
        // the command buffer has room, it sees Close and shuts down cleanly.
        let _ = self.command_tx.try_send(WsCommand::Close);
        // Unconditionally abort: if the loop was wedged (e.g. stuck awaiting a
        // never-arriving inbound message), this guarantees teardown. Aborting a
        // task that has already finished is a no-op.
        self.task.abort();
    }
}

/// Connect to the node's authenticated WebSocket endpoint.
///
/// Returns a subscription handle with an event receiver and command sender.
pub async fn connect(
    node_url: &str,
    signer: &WalletSigner,
    channels: Vec<String>,
) -> Result<WsSubscription, SdkError> {
    // Resolve the node identity the auth signature binds to (audit
    // 2026-06-07 host-binding) from an unauthenticated /health fetch.
    let http_base = node_url.trim_end_matches('/');
    let binding = fetch_node_binding(http_base).await?;

    // Build WebSocket URL
    let ws_url = node_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let ws_url = format!("{}/api/v1/ws", ws_url);

    debug!(url = %ws_url, "Connecting to WebSocket");

    // Cap inbound frame/message sizes so an untrusted node can't OOM the
    // client with an oversized payload (audit 2026-06-07 W2). 0.26 signature:
    // connect_async_with_config(request, Option<WebSocketConfig>, disable_nagle).
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS_MESSAGE_SIZE))
        .max_frame_size(Some(MAX_WS_FRAME_SIZE));
    let (ws_stream, _) =
        tokio_tungstenite::connect_async_with_config(&ws_url, Some(ws_config), false)
            .await
            .map_err(|e| SdkError::WebSocket(format!("connect failed: {}", e)))?;

    let (mut write, mut read) = ws_stream.split();

    // Send auth as first message. Bound to {network, node_id} + a single-use
    // nonce so a captured frame is neither fleet-portable nor replayable.
    let (auth, address, timestamp, nonce) =
        signer.sign_request(&binding.network, &binding.node_id, "GET", "/api/v1/ws");
    // W5 dm-sync backfill authorization — proves the wallet itself (not
    // just this connection) authorized this node to backfill its DMs.
    let (dm_sync_ts, dm_sync_sig) = signer.dm_sync_claim(&binding.network, &binding.node_id);
    let auth_msg = serde_json::json!({
        "address": address,
        "timestamp": timestamp.parse::<u64>().unwrap_or(0),
        "signature": auth,
        "nonce": nonce,
        "dm_sync_timestamp": dm_sync_ts.parse::<u64>().unwrap_or(0),
        "dm_sync_signature": dm_sync_sig,
    });
    write
        .send(Message::Text(serde_json::to_string(&auth_msg).unwrap().into()))
        .await
        .map_err(|e| SdkError::WebSocket(format!("auth send failed: {}", e)))?;

    // Subscribe to initial channels
    if !channels.is_empty() {
        let sub_msg = serde_json::json!({
            "type": "subscribe",
            "channels": channels,
        });
        write
            .send(Message::Text(serde_json::to_string(&sub_msg).unwrap().into()))
            .await
            .map_err(|e| SdkError::WebSocket(format!("subscribe failed: {}", e)))?;
    }

    // Create channels for bidirectional communication
    let (event_tx, event_rx) = mpsc::channel(256);
    let (cmd_tx, mut cmd_rx) = mpsc::channel(32);

    // Spawn the WebSocket event loop. The JoinHandle is retained on the
    // subscription (audit 2026-06-07 W5) so Drop can abort it.
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                // Read from WebSocket
                msg = read.next() => {
                    match msg {
                        Some(Ok(Message::Text(text))) => {
                            match serde_json::from_str::<WsEvent>(text.as_ref()) {
                                Ok(event) => {
                                    if event_tx.send(event).await.is_err() {
                                        break; // receiver dropped
                                    }
                                }
                                Err(e) => {
                                    debug!(error = %e, "Failed to parse WS event");
                                }
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            debug!("WebSocket closed");
                            break;
                        }
                        Some(Err(e)) => {
                            warn!(error = %e, "WebSocket error");
                            break;
                        }
                        _ => {}
                    }
                }
                // Process outgoing commands
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(WsCommand::Subscribe(channels)) => {
                            let msg = serde_json::json!({
                                "type": "subscribe",
                                "channels": channels,
                            });
                            let _ = write.send(Message::Text(
                                serde_json::to_string(&msg).unwrap().into()
                            )).await;
                        }
                        Some(WsCommand::Unsubscribe(channels)) => {
                            let msg = serde_json::json!({
                                "type": "unsubscribe",
                                "channels": channels,
                            });
                            let _ = write.send(Message::Text(
                                serde_json::to_string(&msg).unwrap().into()
                            )).await;
                        }
                        Some(WsCommand::SubscribeDm) => {
                            let msg = serde_json::json!({ "type": "subscribe_dm" });
                            let _ = write.send(Message::Text(
                                serde_json::to_string(&msg).unwrap().into()
                            )).await;
                        }
                        Some(WsCommand::Close) | None => {
                            let _ = write.send(Message::Close(None)).await;
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(WsSubscription {
        events: event_rx,
        command_tx: cmd_tx,
        task,
    })
}
