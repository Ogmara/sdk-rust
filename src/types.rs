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

/// Channel type constants (mirrors `ChannelType` in protocol spec §3.6).
///
/// Stored on the channel record as a numeric value. `Public` and `ReadPublic`
/// are L2-mutable via `ChannelUpdate`; `Private` is set at creation and
/// cannot be flipped post-creation.
pub const CHANNEL_TYPE_PUBLIC: u8 = 0;
pub const CHANNEL_TYPE_READ_PUBLIC: u8 = 1;
pub const CHANNEL_TYPE_PRIVATE: u8 = 2;

/// A channel in the Ogmara network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub channel_id: u64,
    pub slug: String,
    pub creator: String,
    /// Runtime channel type (L2-mutable). The L2 node may flip a channel
    /// between `Public` (0) and `ReadPublic` (1) at runtime via
    /// `ChannelUpdate`. The on-chain immutable type is the directory-listing
    /// type only — clients should treat this field as authoritative for
    /// posting policy. `Private` is 2.
    pub channel_type: u8,
    pub created_at: u64,
    pub display_name: Option<String>,
    pub description: Option<String>,
    pub member_count: Option<u64>,
    /// When `Some(true)`, the channel renders in threaded mode. L2-mutable
    /// via `ChannelUpdate`. Older nodes (pre-0.31.0) won't surface this
    /// field — `None` is treated identically to `Some(false)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threads_enabled: Option<bool>,
}

impl Channel {
    /// Whether `address` is permitted to post `ChatMessage` / `ChatEdit` /
    /// `ChatDelete` to this channel under its runtime posting policy.
    ///
    /// Posting rules (protocol spec §3.6):
    /// - `Public` (0): any member with a valid signature can post.
    /// - `ReadPublic` (1, broadcast): only the creator and moderators can
    ///   post; members may still react.
    /// - `Private` (2): same as `Public` for the membership-set; non-members
    ///   are filtered out at the membership layer upstream.
    ///
    /// Pass the moderator-status flag the caller already knows (e.g. from a
    /// prior `get_channel_members` lookup). When in doubt, pass `false` —
    /// the function errs on the safe side and returns `false` for ReadPublic
    /// channels, which prompts the UI to hide the composer.
    pub fn can_post(&self, address: &str, is_moderator: bool) -> bool {
        if self.channel_type != CHANNEL_TYPE_READ_PUBLIC {
            // Public and Private channels: posting is gated elsewhere
            // (membership, bans, mutes). Read-only policy is permissive.
            return true;
        }
        // ReadPublic: creator + moderators only.
        self.creator == address || is_moderator
    }
}

// --- Message Envelope ---

/// Current Ogmara envelope protocol version (spec 3.1).
///
/// Bumped 1 -> 2 for the audit 2026-08-16 C1 fix: signed envelope preimages
/// now fold in the target network_id (see `WalletSigner::sign_envelope`/
/// `compute_msg_id` in `auth.rs`). Mirrors `PROTOCOL_VERSION` in the node
/// (l2-node `messages/envelope.rs`) and sdk-js `types.ts` — must never drift
/// apart; the node hard-rejects any other version.
pub const PROTOCOL_VERSION: u8 = 2;

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
    /// This node's Ogmara `node_id` (anchorer identity). Used to bind auth
    /// signatures to a specific node (audit 2026-06-07 host-binding). Older
    /// nodes omit it → `None`.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Klever network name ("testnet" / "mainnet"). The other half of the
    /// auth binding. Older nodes omit it → `None`.
    #[serde(default)]
    pub network: Option<String>,
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

// --- Presence gossip (spec 13 §10, sdk-rust 0.6.0+, l2-node 0.48.0+) ---

/// Spec 13 §10.8 attestation taxonomy. Describes how a node makes
/// itself discoverable. Orthogonal to the existing discovery-tier
/// `source` field — here we only care about what the NODE attests,
/// not how the CLIENT learned about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attestation {
    OnChain,
    Gossip,
    Both,
}

impl Attestation {
    /// `true` for `OnChain` and `Both` — i.e., the node has an SC
    /// registration. Used by `compute_trust_score`.
    pub fn includes_on_chain(self) -> bool {
        matches!(self, Attestation::OnChain | Attestation::Both)
    }
}

/// Spec 03 §4.1 — `GET /api/v1/network/identity`. Lightweight self-
/// description used by the Reachable probe (spec 13 §10.9).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub peer_id: String,
    pub network_id: String,
    pub version: String,
    pub public_url: Option<String>,
    pub presence_broadcasting: bool,
}

/// Spec 13 §10.2 / §10.6 — single presence record as exposed by
/// `GET /api/v1/network/presence`. The L2 node enriches each row
/// with `verified_on_chain` / `anchored` / `last_anchor_at` by
/// cross-referencing the local SC view cache.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceRecord {
    pub peer_id: String,
    pub public_url: Option<String>,
    pub version: String,
    pub timestamp: u64,
    pub ttl_secs: u32,
    pub first_heard: u64,
    pub last_heard: u64,
    pub expires_at: u64,
    pub verified_on_chain: bool,
    pub anchored: bool,
    pub last_anchor_at: Option<u64>,
}

/// Response shape of `GET /api/v1/network/presence`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceResponse {
    pub self_peer_id: String,
    pub broadcasting: bool,
    pub cache_size: u32,
    pub cache_cap: u32,
    pub records: Vec<PresenceRecord>,
}

/// Spec 5 §1.1 — merged client-side view of a network node.
///
/// Built by [`crate::client::OgmaraClient::get_known_nodes`] by
/// joining the SC-derived `/network/nodes` response with the
/// off-chain `/network/presence` response by libp2p PeerId.
///
/// Apps that want the +10 reachability contribution to `trust_score`
/// pass a probe-cache map into `get_known_nodes`; the next call
/// incorporates the timestamp. Without a probe, scores top out at
/// 90.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownNode {
    pub peer_id: String,
    pub url: Option<String>,
    pub attestation: Attestation,
    pub anchoring: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub anchor_age_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reachable_probe_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presence_timestamp_ms: Option<u64>,
    pub trust_score: u8,
}

/// Spec 5 §1.1 trust-score derivation. Returns `0..=100`. Pure
/// function so callers can re-score after an external reachability
/// probe lands without re-fetching the whole list.
///
/// Contributions (locked, spec 13 §10.8 / planning doc §4.2):
///  - +50 if `attestation` includes `on-chain`
///  - +30 if `anchoring == true` (active or verified anchor in 7d)
///  - +10 if `attestation == Both` (cross-source consistency)
///  - +10 if `reachable_probe_at_ms` is within the last 24 hours
pub fn compute_trust_score(node: &KnownNode) -> u8 {
    let mut s: u32 = 0;
    if node.attestation.includes_on_chain() {
        s += 50;
    }
    if node.anchoring {
        s += 30;
    }
    if matches!(node.attestation, Attestation::Both) {
        s += 10;
    }
    if let Some(probe_ms) = node.reachable_probe_at_ms {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        if now_ms.saturating_sub(probe_ms) < 86_400_000 {
            s += 10;
        }
    }
    s.min(100) as u8
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
    pub const CHANNEL_UNMUTE: u8 = 0x43;
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

/// Channel mute payload for sending. First mute/unmute support in sdk-rust
/// (audit W30) — ban/kick/unban are a separate, larger pre-existing gap not
/// addressed here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelMutePayload {
    pub channel_id: u64,
    pub target_user: String,
    /// 0 = permanent.
    pub duration_secs: u64,
    pub reason: Option<String>,
}

/// Reverses a `ChannelMutePayload` (l2-node 0.93.0+, audit W30). Minimal
/// shape — just enough to key the delete, no reason/duration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelUnmutePayload {
    pub channel_id: u64,
    pub target_user: String,
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

/// A single hit from `GET /api/v1/users/search` (mention autocomplete).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSearchHit {
    /// Resolved klever wallet address (always `klv1...`).
    pub address: String,
    /// Display name as the user set it (with original casing); `None` if unset.
    pub display_name: Option<String>,
    /// IPFS CID of the user's avatar; `None` if unset.
    pub avatar_cid: Option<String>,
    /// `true` when the user is on-chain registered (`registered_at > 0`).
    pub verified: bool,
}

/// Response shape for `GET /api/v1/users/search`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSearchResponse {
    pub users: Vec<UserSearchHit>,
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

#[cfg(test)]
mod presence_tests {
    use super::*;

    fn node(attestation: Attestation, anchoring: bool) -> KnownNode {
        KnownNode {
            peer_id: "12D3KooWTest".to_string(),
            url: Some("https://node.example.org".to_string()),
            attestation,
            anchoring,
            anchor_age_seconds: None,
            reachable_probe_at_ms: None,
            presence_timestamp_ms: None,
            trust_score: 0,
        }
    }

    /// Spec 5 §1.1 / spec 13 §10.8: locked trust-score formula.
    /// Gossip-only with no probe: 0. Anchoring on-chain: 80. Both
    /// with anchor + recent probe: 100. Locks the contribution
    /// weights so a future regression on the score is caught.
    #[test]
    fn compute_trust_score_table() {
        // Gossip-only, no probe → 0
        assert_eq!(compute_trust_score(&node(Attestation::Gossip, false)), 0);

        // On-chain, no anchoring → 50
        assert_eq!(compute_trust_score(&node(Attestation::OnChain, false)), 50);

        // On-chain + anchoring → 80
        assert_eq!(compute_trust_score(&node(Attestation::OnChain, true)), 80);

        // Both + anchoring → 90 (cross-source +10 bonus)
        assert_eq!(compute_trust_score(&node(Attestation::Both, true)), 90);

        // Both + anchoring + fresh probe → 100 (cap)
        let mut n = node(Attestation::Both, true);
        n.reachable_probe_at_ms = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
        assert_eq!(compute_trust_score(&n), 100);

        // Stale probe (older than 24h) does NOT contribute.
        let mut stale = node(Attestation::Both, true);
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        stale.reachable_probe_at_ms = Some(now_ms.saturating_sub(25 * 3600 * 1000));
        assert_eq!(compute_trust_score(&stale), 90);
    }

    /// Cap is enforced at 100 even if a future contribution would push higher.
    #[test]
    fn trust_score_caps_at_100() {
        // Score 100 — saturate; we just want to confirm no overflow.
        let mut n = node(Attestation::Both, true);
        n.reachable_probe_at_ms = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        );
        let score = compute_trust_score(&n);
        assert!(score <= 100, "trust_score must not exceed 100, got {score}");
    }
}
