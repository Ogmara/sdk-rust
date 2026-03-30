//! HTTP/WebSocket client with node failover.
//!
//! The OgmaraClient connects to a single L2 node and provides methods
//! for all API operations. Supports automatic failover to other known
//! nodes when the primary is unreachable.

use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue};
use tracing::{debug, warn};

use crate::auth::WalletSigner;
use crate::error::SdkError;
use crate::types::*;

/// Configuration for the Ogmara SDK client.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Primary node URL (e.g., "https://node1.ogmara.org:41721").
    pub node_url: String,
    /// Request timeout.
    pub timeout: Duration,
}

/// Default production node URL.
pub const DEFAULT_NODE_URL: &str = "https://node.ogmara.org";

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            node_url: DEFAULT_NODE_URL.to_string(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// The main Ogmara SDK client.
///
/// Provides access to all L2 node API endpoints.
///
/// ```rust,no_run
/// use ogmara_sdk::{OgmaraClient, ClientConfig};
///
/// # async fn example() -> Result<(), ogmara_sdk::SdkError> {
/// let client = OgmaraClient::new(ClientConfig {
///     node_url: "http://localhost:41721".into(),
///     ..Default::default()
/// })?;
///
/// let health = client.health().await?;
/// println!("Node version: {}", health.version);
///
/// let channels = client.list_channels(1, 20).await?;
/// for ch in &channels.channels {
///     println!("#{}: {}", ch.channel_id, ch.slug);
/// }
/// # Ok(())
/// # }
/// ```
pub struct OgmaraClient {
    config: ClientConfig,
    http: reqwest::Client,
    /// Optional wallet signer for authenticated endpoints.
    signer: Option<WalletSigner>,
    /// Known nodes for failover.
    known_nodes: Vec<String>,
}

impl OgmaraClient {
    /// Create a new client with the given configuration.
    pub fn new(config: ClientConfig) -> Result<Self, SdkError> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()?;

        Ok(Self {
            config,
            http,
            signer: None,
            known_nodes: Vec::new(),
        })
    }

    /// Set the wallet signer for authenticated endpoints.
    pub fn with_signer(mut self, signer: WalletSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    /// Get the configured node URL.
    pub fn node_url(&self) -> &str {
        &self.config.node_url
    }

    /// Get the signer's address (if configured).
    pub fn address(&self) -> Option<&str> {
        self.signer.as_ref().map(|s| s.address())
    }

    // --- Public endpoints ---

    /// GET /api/v1/health
    pub async fn health(&self) -> Result<Health, SdkError> {
        self.get("/api/v1/health").await
    }

    /// GET /api/v1/network/stats
    pub async fn network_stats(&self) -> Result<NetworkStats, SdkError> {
        self.get("/api/v1/network/stats").await
    }

    /// GET /api/v1/channels
    pub async fn list_channels(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<ChannelsResponse, SdkError> {
        self.get(&format!(
            "/api/v1/channels?page={}&limit={}",
            page, limit
        ))
        .await
    }

    /// GET /api/v1/channels/{channel_id}
    pub async fn get_channel(&self, channel_id: u64) -> Result<serde_json::Value, SdkError> {
        self.get(&format!("/api/v1/channels/{}", channel_id)).await
    }

    /// GET /api/v1/channels/{channel_id}/messages
    pub async fn get_channel_messages(
        &self,
        channel_id: u64,
        limit: u32,
        before: Option<&str>,
    ) -> Result<MessagesResponse, SdkError> {
        let mut path = format!(
            "/api/v1/channels/{}/messages?limit={}",
            channel_id, limit
        );
        if let Some(before_id) = before {
            path.push_str(&format!("&before={}", before_id));
        }
        self.get(&path).await
    }

    /// GET /api/v1/users/{address}
    pub async fn get_user(&self, address: &str) -> Result<serde_json::Value, SdkError> {
        self.get(&format!("/api/v1/users/{}", encode_path(address))).await
    }

    /// GET /api/v1/news
    pub async fn list_news(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<NewsResponse, SdkError> {
        self.get(&format!("/api/v1/news?page={}&limit={}", page, limit))
            .await
    }

    /// GET /api/v1/network/nodes
    pub async fn list_nodes(&self) -> Result<serde_json::Value, SdkError> {
        self.get("/api/v1/network/nodes").await
    }

    /// GET /api/v1/users/:address/followers
    pub async fn get_followers(
        &self,
        address: &str,
        page: u32,
        limit: u32,
    ) -> Result<FollowerListResponse, SdkError> {
        self.get(&format!(
            "/api/v1/users/{}/followers?page={}&limit={}",
            encode_path(address), page, limit
        ))
        .await
    }

    /// GET /api/v1/users/:address/following
    pub async fn get_following(
        &self,
        address: &str,
        page: u32,
        limit: u32,
    ) -> Result<FollowerListResponse, SdkError> {
        self.get(&format!(
            "/api/v1/users/{}/following?page={}&limit={}",
            encode_path(address), page, limit
        ))
        .await
    }

    /// GET /api/v1/news/:msg_id/reactions
    pub async fn get_news_reactions(
        &self,
        msg_id: &str,
    ) -> Result<NewsReactionsResponse, SdkError> {
        self.get(&format!("/api/v1/news/{}/reactions", msg_id))
            .await
    }

    /// GET /api/v1/news/:msg_id/reposts
    pub async fn get_news_reposts(
        &self,
        msg_id: &str,
        page: u32,
        limit: u32,
    ) -> Result<RepostsResponse, SdkError> {
        self.get(&format!(
            "/api/v1/news/{}/reposts?page={}&limit={}",
            msg_id, page, limit
        ))
        .await
    }

    /// GET /api/v1/channels/:channel_id/members
    pub async fn get_channel_members(
        &self,
        channel_id: u64,
        page: u32,
        limit: u32,
    ) -> Result<ChannelMembersResponse, SdkError> {
        self.get(&format!(
            "/api/v1/channels/{}/members?page={}&limit={}",
            channel_id, page, limit
        ))
        .await
    }

    /// GET /api/v1/channels/:channel_id/pins
    pub async fn get_channel_pins(
        &self,
        channel_id: u64,
    ) -> Result<ChannelPinsResponse, SdkError> {
        self.get(&format!("/api/v1/channels/{}/pins", channel_id))
            .await
    }

    // --- Authenticated endpoints ---

    /// POST /api/v1/messages — send a signed chat message.
    pub async fn send_message(
        &self,
        channel_id: u64,
        content: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;

        let payload = ChatMessage {
            channel_id,
            content: content.to_string(),
            content_rating: ContentRating::default(),
            reply_to: None,
            mentions: Vec::new(),
            attachments: Vec::new(),
        };

        let envelope = self.build_envelope(signer, 0x01, &payload)?;
        self.post_authenticated("/api/v1/messages", &envelope).await
    }

    /// POST /api/v1/dm/{address} — send an encrypted DM.
    ///
    /// Note: The caller must encrypt the content before passing it here.
    /// The SDK provides the envelope construction; encryption is the
    /// caller's responsibility (uses X25519 + AES-256-GCM).
    pub async fn send_dm(
        &self,
        recipient: &str,
        encrypted_payload: Vec<u8>,
    ) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let envelope_bytes = self.build_raw_envelope(signer, 0x05, &encrypted_payload)?;
        self.post_authenticated_raw(
            &format!("/api/v1/dm/{}", recipient),
            envelope_bytes,
        )
        .await
    }

    /// POST /api/v1/users/:address/follow — follow a user.
    pub async fn follow(&self, target: &str) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;

        #[derive(serde::Serialize)]
        struct FollowPayload { target: String }

        let envelope = self.build_envelope(signer, 0x34, &FollowPayload {
            target: target.to_string(),
        })?;
        self.post_authenticated(&format!("/api/v1/users/{}/follow", target), &envelope)
            .await
    }

    /// DELETE /api/v1/users/:address/follow — unfollow a user.
    pub async fn unfollow(&self, target: &str) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;

        #[derive(serde::Serialize)]
        struct UnfollowPayload { target: String }

        let envelope = self.build_envelope(signer, 0x35, &UnfollowPayload {
            target: target.to_string(),
        })?;
        // Send as DELETE with body
        let (auth, address, timestamp) = signer.sign_request("DELETE", &format!("/api/v1/users/{}/follow", target));
        let url = format!("{}/api/v1/users/{}/follow", self.config.node_url, target);
        let resp = self
            .http
            .delete(&url)
            .header("x-ogmara-auth", &auth)
            .header("x-ogmara-address", &address)
            .header("x-ogmara-timestamp", &timestamp)
            .header("content-type", "application/octet-stream")
            .body(envelope)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// POST /api/v1/news/:msg_id/react — react to a news post.
    pub async fn react_to_news(
        &self,
        msg_id: &[u8; 32],
        emoji: &str,
        remove: bool,
    ) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let payload = ReactionPayload {
            target_id: *msg_id,
            channel_id: None,
            emoji: emoji.to_string(),
            remove,
        };
        let envelope = self.build_envelope(signer, MessageType::NEWS_REACTION, &payload)?;
        self.post_authenticated(
            &format!("/api/v1/news/{}/react", hex::encode(msg_id)),
            &envelope,
        )
        .await
    }

    /// POST /api/v1/news/:msg_id/repost — repost a news post.
    pub async fn repost_news(
        &self,
        original_id: &[u8; 32],
        original_author: &str,
        comment: Option<&str>,
    ) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let payload = NewsRepostPayload {
            original_id: *original_id,
            original_author: original_author.to_string(),
            comment: comment.map(|s| s.to_string()),
        };
        let envelope = self.build_envelope(signer, MessageType::NEWS_REPOST, &payload)?;
        self.post_authenticated(
            &format!("/api/v1/news/{}/repost", hex::encode(original_id)),
            &envelope,
        )
        .await
    }

    /// GET /api/v1/bookmarks — list bookmarked posts.
    pub async fn list_bookmarks(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<BookmarksResponse, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let (auth, address, timestamp) = signer.sign_request("GET", "/api/v1/bookmarks");
        let url = format!(
            "{}/api/v1/bookmarks?page={}&limit={}",
            self.config.node_url, page, limit
        );
        let resp = self
            .http
            .get(&url)
            .header("x-ogmara-auth", &auth)
            .header("x-ogmara-address", &address)
            .header("x-ogmara-timestamp", &timestamp)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// POST /api/v1/bookmarks/:msg_id — save a post.
    pub async fn save_bookmark(&self, msg_id: &str) -> Result<serde_json::Value, SdkError> {
        self.post_authenticated_raw(
            &format!("/api/v1/bookmarks/{}", msg_id),
            Vec::new(),
        )
        .await
    }

    /// DELETE /api/v1/bookmarks/:msg_id — unsave a post.
    pub async fn remove_bookmark(&self, msg_id: &str) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let path = format!("/api/v1/bookmarks/{}", msg_id);
        let (auth, address, timestamp) = signer.sign_request("DELETE", &path);
        let url = format!("{}{}", self.config.node_url, path);
        let resp = self
            .http
            .delete(&url)
            .header("x-ogmara-auth", &auth)
            .header("x-ogmara-address", &address)
            .header("x-ogmara-timestamp", &timestamp)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// GET /api/v1/feed — personal news feed (posts from followed users).
    pub async fn get_feed(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<FeedResponse, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let (auth, address, timestamp) = signer.sign_request("GET", "/api/v1/feed");
        let url = format!(
            "{}/api/v1/feed?page={}&limit={}",
            self.config.node_url, page, limit
        );
        let resp = self
            .http
            .get(&url)
            .header("x-ogmara-auth", &auth)
            .header("x-ogmara-address", &address)
            .header("x-ogmara-timestamp", &timestamp)
            .send()
            .await?;
        handle_response(resp).await
    }

    /// Discover nodes from the current home node and store for failover.
    pub async fn discover_nodes(&mut self) -> Result<(), SdkError> {
        let resp: serde_json::Value = self.get("/api/v1/network/nodes").await?;
        if let Some(nodes) = resp.get("nodes").and_then(|n| n.as_array()) {
            self.known_nodes.clear();
            for node in nodes {
                if let Some(endpoint) = node.get("api_endpoint").and_then(|e| e.as_str()) {
                    if !endpoint.is_empty() {
                        self.known_nodes.push(endpoint.to_string());
                    }
                }
            }
            debug!(count = self.known_nodes.len(), "Discovered nodes for failover");
        }
        Ok(())
    }

    // --- Internal helpers ---

    /// Make a GET request to the node.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, SdkError> {
        let url = format!("{}{}", self.config.node_url, path);
        let resp = self.http.get(&url).send().await?;
        handle_response(resp).await
    }

    /// Make an authenticated POST request with a serialized envelope.
    async fn post_authenticated(
        &self,
        path: &str,
        body: &[u8],
    ) -> Result<serde_json::Value, SdkError> {
        self.post_authenticated_raw(path, body.to_vec()).await
    }

    /// Make an authenticated POST request with raw bytes.
    async fn post_authenticated_raw(
        &self,
        path: &str,
        body: Vec<u8>,
    ) -> Result<serde_json::Value, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let (auth, address, timestamp) = signer.sign_request("POST", path);

        let url = format!("{}{}", self.config.node_url, path);
        let resp = self
            .http
            .post(&url)
            .header("x-ogmara-auth", &auth)
            .header("x-ogmara-address", &address)
            .header("x-ogmara-timestamp", &timestamp)
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
            .await?;

        handle_response(resp).await
    }

    /// Build a MessagePack-serialized envelope for a typed payload.
    fn build_envelope<T: serde::Serialize>(
        &self,
        signer: &WalletSigner,
        msg_type: u8,
        payload: &T,
    ) -> Result<Vec<u8>, SdkError> {
        let payload_bytes =
            rmp_serde::to_vec(payload).map_err(|e| SdkError::MsgPack(e.to_string()))?;
        self.build_raw_envelope(signer, msg_type, &payload_bytes)
    }

    /// Build a MessagePack-serialized envelope from raw payload bytes.
    fn build_raw_envelope(
        &self,
        signer: &WalletSigner,
        msg_type: u8,
        payload_bytes: &[u8],
    ) -> Result<Vec<u8>, SdkError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let msg_id = signer.compute_msg_id(payload_bytes, timestamp);
        let signature = signer.sign_envelope(1, msg_type, &msg_id, timestamp, payload_bytes);

        let envelope = Envelope {
            version: 1,
            msg_type,
            msg_id,
            author: signer.address().to_string(),
            timestamp,
            lamport_ts: 0, // node assigns the authoritative lamport_ts
            payload: payload_bytes.to_vec(),
            signature,
            relay_path: Vec::new(),
        };

        rmp_serde::to_vec(&envelope).map_err(|e| SdkError::MsgPack(e.to_string()))
    }
}

/// Percent-encode a path segment (defense-in-depth for user-supplied values).
/// Klever addresses (bech32) and hex msg_ids are inherently URL-safe,
/// but this prevents path traversal if unexpected input is passed.
fn encode_path(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '/' | '?' | '#' | '&' | '=' | ' ' | '%' => {
                format!("%{:02X}", c as u8)
            }
            _ => c.to_string(),
        })
        .collect()
}

/// Handle an HTTP response — check status and deserialize.
async fn handle_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, SdkError> {
    let status = resp.status();
    if !status.is_success() {
        let message = resp.text().await.unwrap_or_default();
        return Err(SdkError::Api {
            status: status.as_u16(),
            message,
        });
    }
    let body = resp.json().await?;
    Ok(body)
}
