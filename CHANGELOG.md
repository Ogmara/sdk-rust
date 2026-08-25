# Changelog

All notable changes to the Ogmara Rust SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.15.0] - 2026-08-25

Pre-mainnet dependency-security pass. `cargo audit` now reports
**0 vulnerabilities and 0 warnings** for this component (was 1 vulnerability,
2 warnings). Lockfile-only — no source, API, or behaviour changes.

### Security

- **Bumped `h2` 0.4.13 → 0.4.19** (RUSTSEC-2026-0258, unbounded empty DATA
  frames). Reached through `reqwest`. Affects code paths that ship in the SDK,
  though as a library our `Cargo.lock` binds only our own builds and tests —
  downstream consumers resolve `h2` themselves and should re-audit their own
  lockfiles.
- **Bumped `rand` 0.8.5 → 0.8.8 and 0.9.2 → 0.9.5** (RUSTSEC-2026-0097,
  unsoundness with a custom logger using `rand::rng()`). Informational
  advisory, cleared for completeness.

## [0.14.0] - 2026-08-18

### Added

- **`build_dm_sync_auth_claim` + `WalletSigner::dm_sync_claim` + automatic
  header/WS-frame attachment** (l2-node final pre-mainnet audit W5).
  l2-node 0.94.0 now requires a wallet-signed authorization claim before it
  will backfill a wallet's missed DMs to a requesting node — closing a gap
  where any freshly-generated node identity could pull any wallet's entire
  DM history. `OgmaraClient`'s REST auth (`sign_auth`, now returning an
  `AuthAttempt` struct instead of a growing tuple) and `ws::connect` both
  transparently sign (and cache, per target node) this claim and attach it
  — no application code needs to change. The cache re-signs after 4 minutes
  (server freshness window is 5) rather than caching indefinitely — an
  early review pass caught that an unbounded cache would silently and
  permanently break backfill for any long-lived signer once its one claim
  aged past the server's window.

## [0.13.0] - 2026-08-17

### Added

- **`ChannelMutePayload`/`ChannelUnmutePayload` + `mute_user()`/
  `unmute_user()`** (l2-node final pre-mainnet audit W30). First
  moderation-action client support of any kind in sdk-rust — `ban_user`/
  `kick_user`/`unban_user` remain unimplemented here (a separate,
  pre-existing gap, not addressed by this fix). `unmute_user` reverses
  `mute_user` — the node's `remove_channel_mute` existed but had zero
  callers before l2-node 0.93.0, so a permanent mute (`duration_secs: 0`)
  was previously irrevocable from any client. `POST`/`DELETE
  /api/v1/channels/:channel_id/mute/:address`, mirroring the `follow`/
  `unfollow` inline-DELETE pattern (no shared `delete_authenticated`
  helper exists yet in this SDK).

## [0.12.0] - 2026-08-17

### Security

- **Cross-network envelope replay (l2-node final pre-mainnet audit C1) —
  coordinated wire-format cutover.** `WalletSigner::compute_msg_id` /
  `sign_envelope` now fold the target Klever `network` ("testnet"/"mainnet")
  into the msg_id and signing preimage, matching l2-node 0.83.0's
  `PROTOCOL_VERSION` 1 → 2 hard cutover and sdk-js 0.42.0's equivalent fix
  (byte-for-byte parity verified by `cross_impl_vector_matches_sdk_js`).
  `OgmaraClient::build_raw_envelope` (and thus every write method) is now
  network-aware: it resolves the target node's network via the existing
  cached `node_binding()` before building an envelope, so no public API
  signature changed there. `build_device_enc_binding`/`build_device_enc_revoke`
  (`encryption.rs`) gain a new **required** `network: &str` parameter — these
  build wallet-authored envelopes outside `OgmaraClient`, so callers must
  supply it explicitly.
- **Breaking:** hard wire-format cutover paired with l2-node 0.83.0 —
  envelopes built by this version are rejected by any l2-node older than
  0.83.0, and vice versa. Ships together with matching bumps in `sdk-js`,
  `web`, `desktop`, and `mobile`.
- **Same finding, second signing scheme (post-fix internal audit).** The
  envelope fix above doesn't cover `DeviceDelegation`/`DeviceEncBinding`/
  `DeviceEncRevoke` — these sign a fixed **claim string**, never a msg_id,
  so folding `network` into `compute_msg_id` gave them no real protection
  (msg_id is a public hash, not a MAC). Fixed by folding `network` into
  `enc_bind_claim`/`enc_revoke_claim` (`encryption.rs`), now required
  parameters — `cross_impl_vector_matches_sdk_js` re-verified byte-for-byte
  parity against sdk-js's equivalent fix.

### Fixed

- `cargo audit`: bumped `quinn-proto` 0.11.14 → 0.11.16 past a high-severity
  remote memory-exhaustion advisory (RUSTSEC-2026-0185). It's an unused
  optional dependency of `reqwest`'s `http3` feature (not enabled by this
  crate, confirmed absent from `cargo tree`) — build-tooling/lockfile residue
  only, never compiled into the shipped binary — but bumped anyway for
  lockfile hygiene.

## [0.11.0] - 2026-06-15

### Added

- **Encrypted media crypto (P5 / D6 — protocol §8, spec 04 §9).** New `media`
  module: `encrypt_file` / `encrypt_thumbnail` / `decrypt_media` seal file bytes
  with a fresh per-file XChaCha20-Poly1305 key (`aad = "ogmara-media-v1"`) before
  IPFS upload, plus `MediaDescriptor` (the per-file key + real mime/filename that
  rides inside the message's already-encrypted content). Mirrors sdk-js `media.ts`;
  a fixed KAT asserts byte-for-byte parity (`dabfaaef…` for key 1..=32 / nonce
  1..=24 / "ogmara"). The higher-level send/render orchestration stays in the JS
  SDK + clients (no Rust media consumer yet — same scope as the deferred DM mirror).

## [0.10.0] - 2026-06-11

E2E encryption P1 — shared crypto core (matches sdk-js `crypto.ts` byte-for-byte).

### Added

- **`crypto` module** — the symmetric content-encryption + key-wrapping core for
  E2E (protocol §8). Audited primitives wrapped behind Ogmara-native names:
  - `aead_encrypt` / `aead_decrypt` — XChaCha20-Poly1305 (24-byte nonce); `aad`
    binds ciphertext to its envelope.
  - `hkdf_sha256` — HKDF-SHA256 (RFC 5869).
  - `x25519_dh` / `x25519_public` — X25519 DH with all-zero (low-order) rejection.
  - `wrap_key` / `wrap_key_with` / `unwrap_key` + `WrappedKey` — ECIES key wrap to
    a recipient device enc pubkey: `wk = HKDF(X25519(eph, R_pub), salt=context,
    info="ogmara-keywrap-v1")`, `wrapped = AEAD(wk, nonce, K, aad=eph_pub)`.
  - Constants `KEY_LEN` (32), `AEAD_NONCE_LEN` (24), `AEAD_TAG_LEN` (16).
- **Cross-impl test vectors** asserted identically in sdk-js: RFC 5869 HKDF case 1,
  draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD KAT, and an Ogmara deterministic wrap KAT.
- `SdkError::Crypto` variant for opaque crypto failures (no oracle leakage).

### Dependencies

- Added `chacha20poly1305 0.10` and `hkdf 0.12`. `hkdf` is pinned to the `0.12`
  line (not `0.13`) to stay in the `digest 0.10` / `sha2 0.10` ecosystem that
  `ed25519-dalek 2.2` requires — `hkdf 0.13` pulls `hmac 0.13`/`digest 0.11` and
  would fracture the digest trait ecosystem.

## [0.9.1] - 2026-06-08

### Removed

- Cleanup (audit 2026-06-07 Batch 5 / N3): dropped the unused `url` dependency
  and dead imports (`HeaderMap`/`HeaderValue`, `warn`).

## [0.9.0] - 2026-06-08

Transport hardening + PoW (audit 2026-06-07 fix-plan B4.3).

### Added

- **Proof-of-Work flow (W4).** On HTTP 429 `pow_required`, the client solves the
  challenge (SHA-256 leading-zero-bits, matching the node + sdk-js byte-for-byte)
  with a client-side difficulty clamp, verifies, and retries once. New `pow`
  module (`PowChallenge`/`PowSolution`).

### Security

- **Inbound WS frame/message size caps (W2)** via `connect_async_with_config`
  (16 MiB message / 4 MiB frame) — a hostile node can't OOM the client.
- **HTTP response body cap (W3)** — bounded read (32 MiB) before deserialize.

### Changed

- **BREAKING:** `WsSubscription` now `impl Drop` (aborts the background task on
  drop — fixes the W5 idle task/socket leak), so its `events` field is private;
  use `recv()` / `events_mut()`. Added `sha2` dep.

## [0.8.0] - 2026-06-08

### Security

- **Auth host-binding (audit C1, fix-plan B1.3).** `WalletSigner::sign_request`
  now binds each auth signature to the target node's `network` + `node_id` plus
  a fresh single-use `nonce` (CSPRNG), signing
  `ogmara-auth:{network}:{node_id}:{nonce}:{timestamp}:{method}:{path}` and
  sending a new `x-ogmara-nonce` header. A captured header can no longer be
  replayed against another node/network or reused on the same node. The client
  lazily fetches and caches the node identity from `GET /api/v1/health` (now
  returns `node_id`/`network`); the WS connect path fetches it too and includes
  the nonce in its auth frame. Requires l2-node ≥0.61.0.
- **rustls-webpki 0.103.10 → 0.103.13 (RUSTSEC-2026-0098/0099/0104,
  cross-cutting B1.5)** — fixes weakened cert-chain validation + a reachable CRL
  panic on `wss://`/`https://` connections.

### Changed

- **BREAKING:** `WalletSigner::sign_request(method, path) -> (auth, address,
  timestamp)` → `sign_request(network, node_id, method, path) -> (auth, address,
  timestamp, nonce)`. New public items: `auth::NodeBinding`,
  `auth::random_nonce_hex`, `SdkError::Protocol`. `Health` gains optional
  `node_id` / `network` fields. Most consumers use `OgmaraClient` and need no
  changes.

## [0.7.0] - 2026-06-07

### Added

- **Device encryption keys (E2E P0, protocol §2.4)** — new `encryption` module,
  byte-for-byte parity with `sdk-js` v0.24.0 (shared cross-impl test vector):
  - `generate_device_enc_keypair()` / `enc_public_key_hex()` — per-device X25519
    keypair (distinct from the Ed25519 signing key); private key stays on-device.
  - `build_device_enc_binding()` / `build_device_enc_revoke()` — wallet-authored
    `DeviceEncBinding` (0x36) / `DeviceEncRevoke` (0x37) envelopes (author = wallet,
    `msg_id` keyed to the wallet pubkey, signature = wallet Klever-message signature
    over the canonical claim). `enc_bind_claim()` / `enc_revoke_claim()` expose the
    exact claim; `klever_message_hash()` the signing preimage.
  - `normalize_wallet_sig()` — canonicalizes a wallet `signMessage` return (hex /
    base64-of-hex / raw bytes) into the 64 raw Ed25519 signature bytes.
- New dependency `x25519-dalek` (with `static_secrets`).

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
