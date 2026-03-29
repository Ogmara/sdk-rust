//! WebSocket client for real-time subscriptions.
//!
//! Connects to the authenticated WebSocket endpoint (/api/v1/ws)
//! and provides an async stream of events.

use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, error, warn};

use crate::auth::WalletSigner;
use crate::error::SdkError;
use crate::types::WsEvent;

/// A handle to an active WebSocket subscription.
pub struct WsSubscription {
    /// Receiver for incoming events.
    pub events: mpsc::Receiver<WsEvent>,
    /// Sender for outgoing commands (subscribe, unsubscribe, etc.).
    command_tx: mpsc::Sender<WsCommand>,
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

/// Connect to the node's authenticated WebSocket endpoint.
///
/// Returns a subscription handle with an event receiver and command sender.
pub async fn connect(
    node_url: &str,
    signer: &WalletSigner,
    channels: Vec<String>,
) -> Result<WsSubscription, SdkError> {
    // Build WebSocket URL
    let ws_url = node_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let ws_url = format!("{}/api/v1/ws", ws_url);

    debug!(url = %ws_url, "Connecting to WebSocket");

    let (ws_stream, _) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .map_err(|e| SdkError::WebSocket(format!("connect failed: {}", e)))?;

    let (mut write, mut read) = ws_stream.split();

    // Send auth as first message
    let (auth, address, timestamp) = signer.sign_request("GET", "/api/v1/ws");
    let auth_msg = serde_json::json!({
        "address": address,
        "timestamp": timestamp.parse::<u64>().unwrap_or(0),
        "signature": auth,
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

    // Spawn the WebSocket event loop
    tokio::spawn(async move {
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
    })
}
