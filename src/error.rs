//! SDK error types.

use thiserror::Error;

/// Errors returned by the Ogmara SDK.
#[derive(Debug, Error)]
pub enum SdkError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON parsing error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// WebSocket error.
    #[error("WebSocket error: {0}")]
    WebSocket(String),

    /// API returned an error response.
    #[error("API error ({status}): {message}")]
    Api { status: u16, message: String },

    /// Invalid key material.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Authentication required but no signer configured.
    #[error("authentication required — configure a WalletSigner")]
    AuthRequired,

    /// Node unreachable.
    #[error("node unreachable: {0}")]
    NodeUnreachable(String),

    /// All nodes failed (failover exhausted).
    #[error("all nodes unreachable")]
    AllNodesDown,

    /// MessagePack serialization error.
    #[error("MessagePack error: {0}")]
    MsgPack(String),
}
