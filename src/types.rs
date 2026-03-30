//! Shared types for the Ogmara SDK.
//!
//! These types mirror the L2 node API responses and protocol spec
//! definitions, providing a clean Rust interface for consumers.

use serde::{Deserialize, Serialize};

// --- User ---

/// A registered Ogmara user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub address: String,
    pub public_key: String,
    pub registered_at: u64,
    pub display_name: Option<String>,
    pub avatar_cid: Option<String>,
    pub bio: Option<String>,
}

// --- Channel ---

/// A channel in the Ogmara network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub channel_id: u64,
    pub slug: String,
    pub creator: String,
    pub channel_type: u8,
    pub created_at: u64,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub member_count: Option<u64>,
}

// --- Message Envelope ---

/// A message envelope as returned by the API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u8,
    pub msg_type: u8,
    #[serde(with = "hex_bytes_32")]
    pub msg_id: [u8; 32],
    pub author: String,
    pub timestamp: u64,
    pub lamport_ts: u64,
    /// Raw MessagePack payload bytes.
    #[serde(with = "base64_bytes")]
    pub payload: Vec<u8>,
    /// Ed25519 signature bytes.
    #[serde(with = "base64_bytes")]
    pub signature: Vec<u8>,
    #[serde(default)]
    pub relay_path: Vec<String>,
}

// --- Content Rating ---

/// Voluntary content rating for messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ContentRating {
    General = 0x00,
    Teen = 0x01,
    Mature = 0x02,
    Explicit = 0x03,
}

impl Default for ContentRating {
    fn default() -> Self {
        Self::General
    }
}

// --- Chat Message ---

/// Chat message payload for sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub channel_id: u64,
    pub content: String,
    #[serde(default)]
    pub content_rating: ContentRating,
    pub reply_to: Option<[u8; 32]>,
    #[serde(default)]
    pub mentions: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

/// Media attachment reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub cid: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub filename: Option<String>,
    pub thumbnail_cid: Option<String>,
}

// --- News ---

/// News post payload for sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsPost {
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub content_rating: ContentRating,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
}

// --- DM ---

/// DM conversation summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmConversation {
    pub conversation_id: String,
    pub peer: String,
    pub last_message_at: u64,
    pub unread_count: u32,
}

// --- Pagination ---

/// Paginated response wrapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Paginated<T> {
    #[serde(flatten)]
    pub items: T,
    pub total: u64,
    pub page: u32,
}

/// Messages response with pagination cursor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub messages: Vec<Envelope>,
    pub has_more: bool,
}

/// Channel list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelsResponse {
    pub channels: Vec<Channel>,
    pub total: u64,
    pub page: u32,
}

/// News list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsResponse {
    pub posts: Vec<Envelope>,
    pub total: u64,
    pub page: u32,
}

// --- Social / Followers ---

/// Follower/following list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowerListResponse {
    #[serde(alias = "followers", alias = "following")]
    pub addresses: Vec<String>,
    pub total: u64,
    pub page: u32,
}

/// Personal feed response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedResponse {
    pub posts: Vec<Envelope>,
    pub total: u64,
    pub page: u32,
}

// --- Node info ---

/// Network node info for failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub node_id: String,
    pub api_endpoint: Option<String>,
    pub channels: Option<Vec<u64>>,
    pub user_count: Option<u32>,
    pub last_seen: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_status: Option<AnchorStatus>,
}

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    pub status: String,
    pub version: String,
    pub peers: u32,
}

/// Network stats response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    pub node_id: String,
    pub peers: u32,
    pub total_messages: u64,
    pub total_channels: u64,
    pub total_users: u64,
    pub uptime_seconds: u64,
    pub protocol_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_status: Option<SelfAnchorStatus>,
}

/// Anchor verification status for a network node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorStatus {
    pub verified: bool,
    /// "active", "verified", or "none"
    pub level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_anchor_age_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchoring_since: Option<u64>,
    #[serde(default)]
    pub total_anchors: u64,
}

/// Self anchor status reported by a node in /network/stats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelfAnchorStatus {
    pub is_anchorer: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_anchor_height: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_anchor_age_seconds: Option<u64>,
    pub total_anchors: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchoring_since: Option<u64>,
}

/// Network nodes list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodesResponse {
    pub nodes: Vec<NodeInfo>,
    pub total: u64,
    pub page: u32,
}

/// Media upload response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub cid: String,
    pub size: u64,
    pub thumbnail_cid: Option<String>,
}

// --- WebSocket ---

/// WebSocket message types received from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
pub enum WsEvent {
    Message { envelope: Envelope },
    Dm { envelope: Envelope },
    Notification { mention: serde_json::Value },
    Presence { channel_id: String, online: Vec<String> },
    Error { code: u16, message: String },
}

// --- MessageType identifiers (protocol spec 3.2) ---

/// Protocol message type identifiers.
pub struct MessageType;

impl MessageType {
    // Chat
    pub const CHAT_MESSAGE: u8 = 0x01;
    pub const CHAT_EDIT: u8 = 0x02;
    pub const CHAT_DELETE: u8 = 0x03;
    pub const CHAT_REACTION: u8 = 0x04;
    // Direct Messages
    pub const DIRECT_MESSAGE: u8 = 0x05;
    pub const DIRECT_MESSAGE_EDIT: u8 = 0x06;
    pub const DIRECT_MESSAGE_DELETE: u8 = 0x07;
    pub const DIRECT_MESSAGE_REACTION: u8 = 0x08;
    // Channels
    pub const CHANNEL_CREATE: u8 = 0x10;
    pub const CHANNEL_UPDATE: u8 = 0x11;
    pub const CHANNEL_JOIN: u8 = 0x12;
    pub const CHANNEL_LEAVE: u8 = 0x13;
    // Channel Administration
    pub const CHANNEL_ADD_MODERATOR: u8 = 0x14;
    pub const CHANNEL_REMOVE_MODERATOR: u8 = 0x15;
    pub const CHANNEL_KICK: u8 = 0x16;
    pub const CHANNEL_BAN: u8 = 0x17;
    pub const CHANNEL_UNBAN: u8 = 0x18;
    pub const CHANNEL_PIN_MESSAGE: u8 = 0x19;
    pub const CHANNEL_UNPIN_MESSAGE: u8 = 0x1A;
    pub const CHANNEL_INVITE: u8 = 0x1B;
    // News
    pub const NEWS_POST: u8 = 0x20;
    pub const NEWS_EDIT: u8 = 0x21;
    pub const NEWS_DELETE: u8 = 0x22;
    pub const NEWS_COMMENT: u8 = 0x23;
    pub const NEWS_REACTION: u8 = 0x24;
    pub const NEWS_REPOST: u8 = 0x25;
    // Profile & Identity
    pub const PROFILE_UPDATE: u8 = 0x30;
    pub const DEVICE_DELEGATION: u8 = 0x31;
    pub const DEVICE_REVOCATION: u8 = 0x32;
    pub const SETTINGS_SYNC: u8 = 0x33;
    pub const FOLLOW: u8 = 0x34;
    pub const UNFOLLOW: u8 = 0x35;
    // Moderation
    pub const REPORT: u8 = 0x40;
    pub const COUNTER_VOTE: u8 = 0x41;
    pub const CHANNEL_MUTE: u8 = 0x42;
    // Account Management
    pub const DELETION_REQUEST: u8 = 0x50;
}

// --- News Engagement types ---

/// Reaction data for a specific emoji on a news post.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionInfo {
    pub count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_reacted: Option<bool>,
}

/// News reactions response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsReactionsResponse {
    pub reactions: std::collections::HashMap<String, ReactionInfo>,
}

/// Reaction payload for sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReactionPayload {
    pub target_id: [u8; 32],
    pub channel_id: Option<u64>,
    pub emoji: String,
    pub remove: bool,
}

/// News repost payload for sending.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsRepostPayload {
    pub original_id: [u8; 32],
    pub original_author: String,
    pub comment: Option<String>,
}

/// Reposts list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepostsResponse {
    pub reposters: Vec<String>,
    pub total: u64,
}

/// Bookmarks list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BookmarksResponse {
    pub bookmarks: Vec<Envelope>,
    pub total: u64,
}

// --- Channel Administration types ---

/// Moderator permissions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModeratorPermissions {
    pub can_mute: bool,
    pub can_kick: bool,
    pub can_ban: bool,
    pub can_pin: bool,
    pub can_edit_info: bool,
    pub can_delete_msgs: bool,
}

/// Channel member info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMember {
    pub address: String,
    pub role: String,
    pub joined_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub permissions: Option<ModeratorPermissions>,
}

/// Channel members response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMembersResponse {
    pub members: Vec<ChannelMember>,
    pub total: u64,
}

/// Channel pins response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelPinsResponse {
    pub pinned_messages: Vec<Envelope>,
}

// --- Serde helpers ---

mod hex_bytes_32 {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(arr)
    }
}

mod base64_bytes {
    use base64::Engine;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(serde::de::Error::custom)
    }
}
