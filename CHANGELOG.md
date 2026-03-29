# Changelog

All notable changes to the Ogmara Rust SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
