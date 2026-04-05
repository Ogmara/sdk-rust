# Changelog

All notable changes to the Ogmara Rust SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
