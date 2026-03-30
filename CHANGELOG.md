# Changelog

All notable changes to the Ogmara Rust SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
