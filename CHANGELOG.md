# Changelog

All notable changes to the Ogmara Rust SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-06-01

Presence-gossip consumer surface — spec 13 §10 + spec 5 §1.1.
Parity with `sdk-js` v0.19.0. Lands alongside l2-node v0.48.0 which
started serving the `/api/v1/network/presence*` and
`/api/v1/network/identity` endpoints.

### Added

- **`OgmaraClient::get_known_nodes(probe_cache)` — high-level
  merged view** of all network nodes. Joins `/network/nodes` (SC
  view) with `/network/presence` (off-chain gossip cache) by
  libp2p PeerId, returns `Vec<KnownNode>` sorted by `trust_score`
  desc. Each row exposes `attestation` (`OnChain` / `Gossip` /
  `Both` per spec 13 §10.8), `anchoring`, `anchor_age_seconds`,
  optional `reachable_probe_at_ms`, and `trust_score: u8`
  in `0..=100`.
- **`OgmaraClient::get_network_identity(url)`** — wraps
  `GET /api/v1/network/identity`. Optionally targets a non-home
  URL so the Reachable probe (spec 13 §10.9) can verify gossip
  claims.
- **`OgmaraClient::get_presence_records()`** — wraps
  `GET /api/v1/network/presence`.
- **`OgmaraClient::get_presence_record(peer_id)`** — single-record
  lookup, returns `Ok(None)` on 404.
- **New types:** `NetworkIdentity`, `PresenceRecord`,
  `PresenceResponse`, `KnownNode`, `Attestation`. The
  `Attestation` enum serializes kebab-case (`on-chain`, `gossip`,
  `both`) to match the cross-SDK + website JSON shape.
- **`compute_trust_score(&KnownNode) -> u8`** — pure re-scoring
  helper. Locked formula: +50 on-chain base, +30 anchoring (7d),
  +10 cross-source consistency for `Both`, +10 reachable probe
  within 24h. Caps at 100.
- Unit tests (`types::presence_tests`) lock the score-table
  contributions and the 100-cap saturation so future regressions
  on the trust formula are caught at build.

### References

- Spec 13 §10: <https://github.com/Ogmara/ogmara/blob/main/docs/specs/13-node-discovery.md#10-presence-gossip-layer>
- Spec 5 §1.1: <https://github.com/Ogmara/ogmara/blob/main/docs/specs/05-clients.md#11-node-failover--auto-discovery>
- Planning: `docs/planning/presence-gossip-plan.md` (Ogmara hub)

## [0.5.0] - 2026-05-06

### Added
- **`Client::search_users(q, limit)` method** — wraps
  `GET /api/v1/users/search` for `@`-mention autocomplete.
  Case-insensitive prefix search on `display_name`; when `q` starts
  with `klv1...` the L2 node also matches addresses. Returns
  `UserSearchResponse { users: Vec<UserSearchHit> }` with `address`,
  `display_name`, `avatar_cid`, and `verified`. No auth required.
  Pairs with `l2-node` v0.32.0+; older nodes return 404.
- **`UserSearchHit` and `UserSearchResponse` types** added to
  `types.rs` and re-exported via the crate root.

### Notes
- Server clamps `limit` to 1..=50 (default 20) and rejects empty `q`
  with 400. Callers should validate locally before calling.

## [0.4.0] - 2026-05-05

### Added
- **Read-only / broadcast channel awareness (paired with `l2-node` v0.31.0).**
  - New `Channel::threads_enabled: Option<bool>` field reflects the runtime
    threaded-mode flag. Older nodes (pre-0.31.0) won't surface the field;
    `None` is treated identically to `Some(false)`.
  - New `Channel::can_post(&self, address, is_moderator) -> bool` method —
    returns whether a wallet may post `ChatMessage` / `ChatEdit` /
    `ChatDelete` under the channel's runtime posting policy. Returns `true`
    for non-ReadPublic channels and for the creator/moderators of
    ReadPublic channels.
  - New constants exported from the crate root:
    `CHANNEL_TYPE_PUBLIC` (0), `CHANNEL_TYPE_READ_PUBLIC` (1),
    `CHANNEL_TYPE_PRIVATE` (2).

### Notes
- The `Channel.channel_type` doc comment now clarifies it reflects the
  runtime (L2-mutable) value, not the on-chain immutable type.
- This release does NOT add a `ChannelUpdate` envelope builder. Clients
  needing to flip channel type or threads_enabled use the JS SDK or call
  the L2 node API directly. A Rust envelope builder is a future addition.

## [0.3.2] - 2026-04-05

### Added
- `after` parameter on `get_channel_messages` — enables incremental fetching
  of only new messages since a known msg_id cursor

## [0.3.1] - 2026-04-04

### Added
- Auto-extract `@klv1...` mentions from message content in `send_message` —
  the mentions field was hardcoded empty, preventing the L2 node's notification
  engine from detecting mentions in CLI-sent messages

## [0.3.0] - 2026-03-30

### Added

- `AnchorStatus` struct — anchor verification level for network nodes
  (`verified`, `level`, `last_anchor_age_seconds`, `anchoring_since`)
- `SelfAnchorStatus` struct — self-reported anchor status from `/network/stats`
- `NodesResponse` typed response for `GET /api/v1/network/nodes`
- `anchor_status` field on `NodeInfo` (backwards-compatible `Option` with
  `#[serde(default)]`)
- `anchor_status` field on `NetworkStats` (backwards-compatible `Option` with
  `#[serde(default)]`)

### Changed

- `list_nodes()` now returns typed `NodesResponse` instead of raw JSON

## [0.2.0] - 2026-03-30

### Changed
- Default node URL changed to `https://node.ogmara.org`
- URL path encoding via `encode_path()` for defense-in-depth

### Added
- MessageType constants (all 35+ protocol message types)
- News engagement: react_to_news(), repost_news(), list_bookmarks(), save_bookmark(), remove_bookmark()
- News queries: get_news_reactions(), get_news_reposts()
- Channel admin: get_channel_members(), get_channel_pins()
- Response types: NewsReactionsResponse, RepostsResponse, BookmarksResponse, ChannelMembersResponse, ChannelPinsResponse
- Payload types: ReactionPayload, NewsRepostPayload, ModeratorPermissions, ChannelMember

## [0.1.0] - 2026-03-29

### Added
- OgmaraClient HTTP client for all L2 node REST endpoints
  - Public: health, stats, channels, messages, users, news, nodes
  - Authenticated: send message, update profile, send DM
  - Social: follow, unfollow, get feed, get followers, get following
- WalletSigner for Klever wallet signing (Ed25519 + Keccak-256)
  - Klever message format signing for auth headers
  - Ogmara protocol format signing for envelope construction
  - Message ID computation (Keccak-256)
  - Key creation from private key bytes or hex string
- WebSocket subscription client with async event/command channels
  - Authenticated mode (Klever sig in first frame)
  - Channel subscribe/unsubscribe, DM subscription
- Full type definitions: Envelope, Channel, User, ChatMessage, NewsPost,
  Attachment, DmConversation, WsEvent, Health, NetworkStats, etc.
- Custom serde helpers for hex [u8;32] and base64 Vec<u8>
- Node discovery for failover (discover_nodes)
- Error types: Http, Json, WebSocket, Api, InvalidKey, AuthRequired, MsgPack
