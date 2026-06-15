//! # Ogmara Rust SDK
//!
//! Client library for the [Ogmara](https://ogmara.org) decentralized chat
//! and news platform on [Klever](https://klever.org) blockchain.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ogmara_sdk::{OgmaraClient, ClientConfig, WalletSigner};
//!
//! # async fn example() -> Result<(), ogmara_sdk::SdkError> {
//! // Create a client (no auth — read-only)
//! let client = OgmaraClient::new(ClientConfig {
//!     node_url: "http://localhost:41721".into(),
//!     ..Default::default()
//! })?;
//!
//! // Read public data
//! let health = client.health().await?;
//! println!("Connected to node v{}", health.version);
//!
//! let channels = client.list_channels(1, 20).await?;
//! for ch in &channels.channels {
//!     println!("#{} — {}", ch.channel_id, ch.slug);
//! }
//!
//! // Authenticated usage (requires private key)
//! let signer = WalletSigner::from_hex("your_hex_private_key")?;
//! let client = client.with_signer(signer);
//!
//! // Send a message
//! let result = client.send_message(1, "Hello Ogmara!").await?;
//! println!("Sent: {:?}", result);
//! # Ok(())
//! # }
//! ```
//!
//! ## WebSocket Subscriptions
//!
//! ```rust,no_run
//! use ogmara_sdk::{WalletSigner, ws};
//!
//! # async fn example() -> Result<(), ogmara_sdk::SdkError> {
//! let signer = WalletSigner::from_hex("your_hex_private_key")?;
//! let mut sub = ws::connect(
//!     "http://localhost:41721",
//!     &signer,
//!     vec!["1".into(), "2".into()], // channel IDs
//! ).await?;
//!
//! // Receive events
//! while let Some(event) = sub.recv().await {
//!     println!("Event: {:?}", event);
//! }
//! # Ok(())
//! # }
//! ```

pub mod auth;
pub mod client;
pub mod crypto;
pub mod encryption;
pub mod error;
pub mod media;
pub mod pow;
pub mod types;
pub mod ws;

// Re-export main types for convenience
pub use auth::WalletSigner;
pub use client::{ClientConfig, OgmaraClient};
pub use crypto::{
    aead_decrypt, aead_encrypt, hkdf_sha256, unwrap_key, wrap_key, wrap_key_with, x25519_dh,
    x25519_public, WrappedKey, AEAD_NONCE_LEN, AEAD_TAG_LEN, KEY_LEN,
};
pub use encryption::{
    build_device_enc_binding, build_device_enc_revoke, enc_bind_claim, enc_public_key_hex,
    enc_revoke_claim, generate_device_enc_keypair, normalize_wallet_sig, DeviceEncKeypair,
};
pub use error::SdkError;
pub use pow::{PowChallenge, PowSolution};
pub use types::*;
