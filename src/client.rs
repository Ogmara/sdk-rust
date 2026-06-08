//! HTTP/WebSocket client with node failover.
//!
//! The OgmaraClient connects to a single L2 node and provides methods
//! for all API operations. Supports automatic failover to other known
//! nodes when the primary is unreachable.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tracing::debug;

use crate::auth::{NodeBinding, WalletSigner};
use crate::error::SdkError;
use crate::pow::{PowChallenge, PowSolution};
use crate::types::*;

/// Maximum HTTP response body the SDK will buffer (audit 2026-06-07 W3).
/// Nodes are discovered from untrusted SC/gossip; an oversized body would
/// otherwise OOM the client. Bodies past this cap are rejected before
/// deserialization. 32 MiB comfortably covers paginated API responses.
const MAX_RESPONSE_BODY: u64 = 32 * 1024 * 1024;

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
    /// Cached node identity the auth signatures bind to (audit 2026-06-07
    /// host-binding). Lazily fetched from `/api/v1/health` on the first
    /// authenticated request, then reused.
    binding: tokio::sync::OnceCell<NodeBinding>,
    /// Whether this client has already solved a PoW challenge for the node
    /// (audit 2026-06-07 W4). Once verified the wallet is "known", so we don't
    /// re-solve or retry on subsequent requests. Interior mutability keeps the
    /// public API `&self`.
    pow_verified: AtomicBool,
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
            binding: tokio::sync::OnceCell::new(),
            pow_verified: AtomicBool::new(false),
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
    ///
    /// `after` returns messages newer than the given msg_id (incremental fetch).
    /// `before` and `after` are mutually exclusive; `after` takes precedence.
    pub async fn get_channel_messages(
        &self,
        channel_id: u64,
        limit: u32,
        before: Option<&str>,
        after: Option<&str>,
    ) -> Result<MessagesResponse, SdkError> {
        let mut path = format!(
            "/api/v1/channels/{}/messages?limit={}",
            channel_id, limit
        );
        if let Some(after_id) = after {
            path.push_str(&format!("&after={}", after_id));
        } else if let Some(before_id) = before {
            path.push_str(&format!("&before={}", before_id));
        }
        self.get(&path).await
    }

    /// GET /api/v1/users/{address}
    pub async fn get_user(&self, address: &str) -> Result<serde_json::Value, SdkError> {
        self.get(&format!("/api/v1/users/{}", encode_path(address))).await
    }

    /// GET /api/v1/users/search — `@`-mention autocomplete.
    ///
    /// Case-insensitive prefix search on `display_name`. When `q` looks
    /// like a `klv1...` prefix the L2 node also matches addresses, so
    /// callers can complete `@klv1abc` even if no display name is set.
    ///
    /// `limit` is clamped server-side to 1..=50 (default 20). `q` is
    /// required and capped at 64 chars after trim — empty/whitespace
    /// returns 400.
    ///
    /// No authentication required. Pairs with `l2-node` v0.32.0+; older
    /// nodes return 404.
    pub async fn search_users(
        &self,
        q: &str,
        limit: u32,
    ) -> Result<UserSearchResponse, SdkError> {
        // Use query-string encoding (stricter than path encoding) so '@', '+',
        // '&' etc. round-trip correctly. `+` is the silent failure here:
        // path encoding leaves it alone, but query strings decode it as
        // space — searching for "a+b" would corrupt to "a b" server-side.
        self.get(&format!(
            "/api/v1/users/search?q={}&limit={}",
            encode_query(q),
            limit,
        ))
        .await
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
    pub async fn list_nodes(&self) -> Result<NodesResponse, SdkError> {
        self.get("/api/v1/network/nodes").await
    }

    /// GET /api/v1/network/identity (spec 03 §4.1, l2-node 0.48.0+).
    ///
    /// Lightweight self-description used by the Reachable probe in
    /// spec 13 §10.9. When `url` is `Some`, queries that node
    /// instead of the configured home — useful when verifying that
    /// a presence-gossip claim resolves to the same PeerId.
    pub async fn get_network_identity(
        &self,
        url: Option<&str>,
    ) -> Result<NetworkIdentity, SdkError> {
        match url {
            Some(base) => {
                let stripped = base.trim_end_matches('/');
                self.get_absolute(&format!("{}/api/v1/network/identity", stripped))
                    .await
            }
            None => self.get("/api/v1/network/identity").await,
        }
    }

    /// GET /api/v1/network/presence (spec 13 §10.6, l2-node 0.48.0+).
    ///
    /// Returns the home node's cached presence-gossip records.
    /// Each row is enriched server-side with `verified_on_chain` /
    /// `anchored` / `last_anchor_at`. Returns an empty `records`
    /// array on nodes with presence disabled.
    pub async fn get_presence_records(&self) -> Result<PresenceResponse, SdkError> {
        self.get("/api/v1/network/presence").await
    }

    /// GET /api/v1/network/presence/:peer_id (l2-node 0.48.0+).
    ///
    /// Returns the single cached record for `peer_id`, or `Ok(None)`
    /// if the node hasn't cached one (TTL-evicted / not received /
    /// presence disabled).
    pub async fn get_presence_record(
        &self,
        peer_id: &str,
    ) -> Result<Option<PresenceRecord>, SdkError> {
        let path = format!("/api/v1/network/presence/{}", encode_path(peer_id));
        match self.get::<PresenceRecord>(&path).await {
            Ok(rec) => Ok(Some(rec)),
            Err(SdkError::Api { status, .. }) if status == 404 => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Spec 5 §1.1 — merged client-side view of all known nodes.
    ///
    /// Joins the SC-derived `/network/nodes` response with the
    /// off-chain `/network/presence` cache by libp2p PeerId. Each
    /// result carries `attestation` (`OnChain` / `Gossip` / `Both`),
    /// `anchoring`, and `trust_score` (0..=100, locked formula in
    /// [`compute_trust_score`]).
    ///
    /// Results are sorted by `trust_score` descending — the sensible
    /// default for failover selection. Apps building their own UI
    /// may resort by latency, version, or any other field.
    ///
    /// `probe_cache` is an optional `peer_id -> unix_ms` map for the
    /// +10 reachability contribution. Apps that maintain their own
    /// probe state pass it here; otherwise scores top out at 90.
    pub async fn get_known_nodes(
        &self,
        probe_cache: Option<&std::collections::HashMap<String, u64>>,
    ) -> Result<Vec<KnownNode>, SdkError> {
        let sc_resp = self
            .list_nodes()
            .await
            .unwrap_or_else(|_| NodesResponse {
                nodes: Vec::new(),
                total: 0,
                page: 0,
            });
        let presence_resp = self
            .get_presence_records()
            .await
            .unwrap_or_else(|_| PresenceResponse {
                self_peer_id: String::new(),
                broadcasting: false,
                cache_size: 0,
                cache_cap: 4096,
                records: Vec::new(),
            });

        let mut merged: std::collections::HashMap<String, KnownNode> =
            std::collections::HashMap::new();

        // Seed with SC view first — SC URL wins on conflict per
        // spec 9 §3.2.2.
        for n in sc_resp.nodes.iter() {
            if n.node_id.is_empty() {
                continue;
            }
            let anchoring = n
                .anchor_status
                .as_ref()
                .map(|s| s.level == "active" || s.level == "verified")
                .unwrap_or(false);
            let age = n
                .anchor_status
                .as_ref()
                .and_then(|s| s.last_anchor_age_seconds);
            merged.insert(
                n.node_id.clone(),
                KnownNode {
                    peer_id: n.node_id.clone(),
                    url: n.api_endpoint.clone(),
                    attestation: Attestation::OnChain,
                    anchoring,
                    anchor_age_seconds: age,
                    presence_timestamp_ms: None,
                    reachable_probe_at_ms: probe_cache
                        .and_then(|m| m.get(&n.node_id).copied()),
                    trust_score: 0,
                },
            );
        }

        // Layer presence records on top.
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        for rec in presence_resp.records.iter() {
            if rec.peer_id.is_empty() {
                continue;
            }
            if let Some(existing) = merged.get_mut(&rec.peer_id) {
                existing.attestation = Attestation::Both;
                existing.presence_timestamp_ms = Some(rec.timestamp.saturating_mul(1000));
                if existing.url.is_none() && rec.public_url.is_some() {
                    existing.url = rec.public_url.clone();
                }
            } else {
                let age = rec.last_anchor_at.map(|t| now_secs.saturating_sub(t));
                merged.insert(
                    rec.peer_id.clone(),
                    KnownNode {
                        peer_id: rec.peer_id.clone(),
                        url: rec.public_url.clone(),
                        attestation: Attestation::Gossip,
                        anchoring: rec.anchored,
                        anchor_age_seconds: age,
                        presence_timestamp_ms: Some(rec.timestamp.saturating_mul(1000)),
                        reachable_probe_at_ms: probe_cache
                            .and_then(|m| m.get(&rec.peer_id).copied()),
                        trust_score: 0,
                    },
                );
            }
        }

        // Score and sort desc.
        let mut out: Vec<KnownNode> = merged.into_values().collect();
        for node in out.iter_mut() {
            node.trust_score = compute_trust_score(node);
        }
        out.sort_by(|a, b| b.trust_score.cmp(&a.trust_score));
        Ok(out)
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
            mentions: extract_mentions(content),
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
        let path = format!("/api/v1/users/{}/follow", target);
        let (auth, address, timestamp, nonce) = self.sign_auth(signer, "DELETE", &path).await?;
        let url = format!("{}{}", self.config.node_url, path);
        self.send(|| {
            self.http
                .delete(&url)
                .header("x-ogmara-auth", &auth)
                .header("x-ogmara-address", &address)
                .header("x-ogmara-timestamp", &timestamp)
                .header("x-ogmara-nonce", &nonce)
                .header("content-type", "application/octet-stream")
                .body(envelope.clone())
        })
        .await
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
        let (auth, address, timestamp, nonce) =
            self.sign_auth(signer, "GET", "/api/v1/bookmarks").await?;
        let url = format!(
            "{}/api/v1/bookmarks?page={}&limit={}",
            self.config.node_url, page, limit
        );
        self.send(|| {
            self.http
                .get(&url)
                .header("x-ogmara-auth", &auth)
                .header("x-ogmara-address", &address)
                .header("x-ogmara-timestamp", &timestamp)
                .header("x-ogmara-nonce", &nonce)
        })
        .await
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
        let (auth, address, timestamp, nonce) = self.sign_auth(signer, "DELETE", &path).await?;
        let url = format!("{}{}", self.config.node_url, path);
        self.send(|| {
            self.http
                .delete(&url)
                .header("x-ogmara-auth", &auth)
                .header("x-ogmara-address", &address)
                .header("x-ogmara-timestamp", &timestamp)
                .header("x-ogmara-nonce", &nonce)
        })
        .await
    }

    /// GET /api/v1/feed — personal news feed (posts from followed users).
    pub async fn get_feed(
        &self,
        page: u32,
        limit: u32,
    ) -> Result<FeedResponse, SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let (auth, address, timestamp, nonce) =
            self.sign_auth(signer, "GET", "/api/v1/feed").await?;
        let url = format!(
            "{}/api/v1/feed?page={}&limit={}",
            self.config.node_url, page, limit
        );
        self.send(|| {
            self.http
                .get(&url)
                .header("x-ogmara-auth", &auth)
                .header("x-ogmara-address", &address)
                .header("x-ogmara-timestamp", &timestamp)
                .header("x-ogmara-nonce", &nonce)
        })
        .await
    }

    /// Discover nodes from the current home node and store for failover.
    pub async fn discover_nodes(&mut self) -> Result<(), SdkError> {
        let resp: NodesResponse = self.get("/api/v1/network/nodes").await?;
        self.known_nodes.clear();
        for node in &resp.nodes {
            if let Some(endpoint) = &node.api_endpoint {
                if !endpoint.is_empty() {
                    self.known_nodes.push(endpoint.clone());
                }
            }
        }
        debug!(count = self.known_nodes.len(), "Discovered nodes for failover");
        Ok(())
    }

    // --- Internal helpers ---

    /// Make a GET request to the node. Public reads; goes through the
    /// PoW-aware sender (audit 2026-06-07 W4) since unknown wallets can be
    /// challenged even on reads when a signer is attached.
    async fn get<T: serde::de::DeserializeOwned>(&self, path: &str) -> Result<T, SdkError> {
        let url = format!("{}{}", self.config.node_url, path);
        self.send(|| self.http.get(&url)).await
    }

    /// Like [`Self::get`] but takes a fully-qualified URL — used to
    /// target a node other than `self.config.node_url`. Currently
    /// only [`Self::get_network_identity`] (spec 13 §10.9 Reachable
    /// probe). No auth headers, no PoW retry: a probe shouldn't
    /// burn the caller's PoW budget on the target.
    async fn get_absolute<T: serde::de::DeserializeOwned>(
        &self,
        url: &str,
    ) -> Result<T, SdkError> {
        let resp = self.http.get(url).send().await?;
        handle_response(resp).await
    }

    /// Resolve (and cache) the node identity that auth signatures bind to
    /// (audit 2026-06-07 host-binding), from an unauthenticated
    /// `GET /api/v1/health`. Must NOT route through the auth path, which
    /// itself depends on this binding.
    async fn node_binding(&self) -> Result<&NodeBinding, SdkError> {
        self.binding
            .get_or_try_init(|| async {
                let health: Health = self.get("/api/v1/health").await?;
                match (health.node_id, health.network) {
                    (Some(node_id), Some(network))
                        if !node_id.is_empty() && !network.is_empty() =>
                    {
                        Ok(NodeBinding { network, node_id })
                    }
                    _ => Err(SdkError::Protocol(
                        "node /health lacks node_id/network — too old for host-bound auth"
                            .into(),
                    )),
                }
            })
            .await
    }

    /// Sign auth headers for `method path`, binding to the cached node
    /// identity. Returns `(auth_b64, address, timestamp, nonce)`.
    async fn sign_auth(
        &self,
        signer: &WalletSigner,
        method: &str,
        path: &str,
    ) -> Result<(String, String, String, String), SdkError> {
        let b = self.node_binding().await?;
        Ok(signer.sign_request(&b.network, &b.node_id, method, path))
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
        let (auth, address, timestamp, nonce) = self.sign_auth(signer, "POST", path).await?;

        let url = format!("{}{}", self.config.node_url, path);
        // PoW-aware send (audit 2026-06-07 W4): the closure rebuilds the request
        // (incl. body clone) so it can be re-issued after solving a challenge.
        self.send(|| {
            self.http
                .post(&url)
                .header("x-ogmara-auth", &auth)
                .header("x-ogmara-address", &address)
                .header("x-ogmara-timestamp", &timestamp)
                .header("x-ogmara-nonce", &nonce)
                .header("content-type", "application/octet-stream")
                .body(body.clone())
        })
        .await
    }

    /// Send a request with automatic PoW handling (audit 2026-06-07 W4).
    ///
    /// `build` must produce a fresh `RequestBuilder` each call so the request
    /// can be re-issued for the retry. On a 429 whose JSON body is
    /// `{ error: "pow_required", challenge, address }`, this solves the
    /// challenge, POSTs the solution to `/api/v1/pow/verify`, and retries the
    /// original request exactly ONCE. The challenge difficulty is clamped
    /// client-side (see [`crate::pow::MAX_POW_DIFFICULTY`]) so a hostile node
    /// can't force unbounded work. All response bodies are size-bounded.
    async fn send<T: serde::de::DeserializeOwned>(
        &self,
        build: impl Fn() -> reqwest::RequestBuilder,
    ) -> Result<T, SdkError> {
        let resp = build().send().await?;

        // Only attempt PoW once per client: if already verified, or this is a
        // non-PoW 429, fall through to normal handling.
        if resp.status().as_u16() == 429 && !self.pow_verified.load(Ordering::Relaxed) {
            let status = resp.status();
            let body = read_bounded_body(resp).await?;
            // Inspect the body for a pow_required challenge.
            if let Ok(challenge_resp) = serde_json::from_slice::<PowChallengeResponse>(&body) {
                if challenge_resp.error.as_deref() == Some("pow_required") {
                    if let Some(challenge) = challenge_resp.challenge {
                        self.solve_pow(&challenge, challenge_resp.address).await?;
                        // Retry the original request exactly once.
                        let retry = build().send().await?;
                        return handle_response(retry).await;
                    }
                }
            }
            // 429 that isn't a solvable PoW challenge — surface as an API error.
            return Err(SdkError::Api {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&body).into_owned(),
            });
        }

        handle_response(resp).await
    }

    /// Solve a PoW challenge and submit the solution to the node, mirroring
    /// sdk-js `solvePow` (audit 2026-06-07 W4).
    ///
    /// Uses the address from the node's 429 body when provided — it is the exact
    /// `resolved_author` the node bound the challenge to (e.g. a device key that
    /// resolves to a wallet), avoiding a klv1.../ogd1... mismatch. Sets
    /// `pow_verified` on success so later requests skip PoW.
    async fn solve_pow(
        &self,
        challenge: &PowChallenge,
        resolved_address: Option<String>,
    ) -> Result<(), SdkError> {
        let signer = self.signer.as_ref().ok_or(SdkError::AuthRequired)?;
        let nonce = crate::pow::solve_challenge(challenge)?;

        let solution = PowSolution {
            challenge_id: challenge.challenge_id.clone(),
            address: resolved_address.unwrap_or_else(|| signer.address().to_string()),
            nonce,
        };

        let url = format!("{}/api/v1/pow/verify", self.config.node_url);
        let resp = self.http.post(&url).json(&solution).send().await?;
        let status = resp.status();
        let body = read_bounded_body(resp).await?;
        if !status.is_success() {
            return Err(SdkError::Api {
                status: status.as_u16(),
                message: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        // Node returns `{ "ok": true, ... }` on success.
        let verify: PowVerifyResponse = serde_json::from_slice(&body)?;
        if !verify.ok {
            return Err(SdkError::Protocol(format!(
                "PoW verification rejected: {}",
                verify.error.unwrap_or_else(|| "unknown".into())
            )));
        }
        self.pow_verified.store(true, Ordering::Relaxed);
        debug!("PoW challenge solved and verified");
        Ok(())
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

/// Percent-encode a query string value. Stricter than `encode_path` because
/// query strings interpret additional characters specially: `+` decodes to
/// space, `&` separates pairs, `=` separates key/value, `#` starts the
/// fragment. Anything outside the unreserved set is percent-encoded.
///
/// RFC 3986 unreserved: `ALPHA / DIGIT / "-" / "." / "_" / "~"`.
fn encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        let c = *b as char;
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '.' | '_' | '~' => out.push(c),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Shape of a node 429 PoW challenge body (audit 2026-06-07 W4):
/// `{ "error": "pow_required", "challenge": {...}, "address": "..." }`.
#[derive(serde::Deserialize)]
struct PowChallengeResponse {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    challenge: Option<PowChallenge>,
    /// The `resolved_author` the node bound the challenge to.
    #[serde(default)]
    address: Option<String>,
}

/// Shape of the `/api/v1/pow/verify` response: `{ "ok": bool, "error"?: str }`.
#[derive(serde::Deserialize)]
struct PowVerifyResponse {
    ok: bool,
    #[serde(default)]
    error: Option<String>,
}

/// Read an HTTP response body, enforcing [`MAX_RESPONSE_BODY`] (audit
/// 2026-06-07 W3) so an untrusted node can't OOM the client with a huge body.
/// Rejects up front on an oversized `Content-Length`, then enforces the cap on
/// the bytes actually received (the header is advisory and may be absent/false).
async fn read_bounded_body(resp: reqwest::Response) -> Result<Vec<u8>, SdkError> {
    if let Some(len) = resp.content_length() {
        if len > MAX_RESPONSE_BODY {
            return Err(SdkError::Protocol(format!(
                "response body too large: {} bytes (max {})",
                len, MAX_RESPONSE_BODY
            )));
        }
    }
    // `bytes()` buffers the whole body; with the Content-Length guard above an
    // honest node is already bounded. Re-check the actual length to catch a node
    // that lies about (or omits) Content-Length.
    let bytes = resp.bytes().await?;
    if bytes.len() as u64 > MAX_RESPONSE_BODY {
        return Err(SdkError::Protocol(format!(
            "response body too large: {} bytes (max {})",
            bytes.len(),
            MAX_RESPONSE_BODY
        )));
    }
    Ok(bytes.to_vec())
}

/// Check status and deserialize a (size-bounded) JSON response body.
/// Used for the non-PoW paths (public reads, probes) where no retry applies.
async fn handle_response<T: serde::de::DeserializeOwned>(
    resp: reqwest::Response,
) -> Result<T, SdkError> {
    let status = resp.status();
    let body = read_bounded_body(resp).await?;
    if !status.is_success() {
        return Err(SdkError::Api {
            status: status.as_u16(),
            message: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    Ok(serde_json::from_slice(&body)?)
}

/// Extract @klv1... addresses from message content for auto-mention detection.
fn extract_mentions(content: &str) -> Vec<String> {
    let mut mentions = Vec::new();
    for word in content.split_whitespace() {
        if let Some(addr) = word.strip_prefix('@') {
            if addr.starts_with("klv1") && addr.len() == 62 && addr[4..].chars().all(|c| c.is_ascii_alphanumeric()) {
                if !mentions.contains(&addr.to_string()) {
                    mentions.push(addr.to_string());
                }
            }
        }
    }
    mentions
}
