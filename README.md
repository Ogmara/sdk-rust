# Ogmara Rust SDK

Client library for the [Ogmara](https://ogmara.org) decentralized chat and news platform on [Klever](https://klever.org) blockchain.

## Features

- REST API client for all L2 node endpoints (public + authenticated)
- WebSocket client for real-time subscriptions (channels, DMs, notifications)
- Klever wallet signing (Ed25519 + Keccak-256, Klever message format)
- Envelope construction with automatic msg_id computation and signing
- Node failover support (discover + store known nodes)
- Full type definitions for messages, channels, users, news, DMs

## Quick Start

```rust
use ogmara_sdk::{OgmaraClient, ClientConfig, WalletSigner};

#[tokio::main]
async fn main() -> Result<(), ogmara_sdk::SdkError> {
    // Read-only client (no auth)
    let client = OgmaraClient::new(ClientConfig {
        node_url: "http://localhost:41721".into(),
        ..Default::default()
    })?;

    let health = client.health().await?;
    println!("Connected to node v{}", health.version);

    // List channels
    let channels = client.list_channels(1, 20).await?;
    for ch in &channels.channels {
        println!("#{} -- {}", ch.channel_id, ch.slug);
    }

    // Authenticated client (requires private key)
    let signer = WalletSigner::from_hex("your_hex_private_key")?;
    let client = client.with_signer(signer);

    // Send a message
    client.send_message(1, "Hello Ogmara!").await?;

    Ok(())
}
```

## WebSocket Subscriptions

```rust
use ogmara_sdk::{WalletSigner, ws};

async fn subscribe() -> Result<(), ogmara_sdk::SdkError> {
    let signer = WalletSigner::from_hex("your_hex_private_key")?;
    let sub = ws::connect(
        "http://localhost:41721",
        &signer,
        vec!["1".into(), "2".into()],
    ).await?;

    let mut events = sub.events;
    while let Some(event) = events.recv().await {
        println!("{:?}", event);
    }
    Ok(())
}
```

## Modules

| Module | What |
|--------|------|
| `client` | HTTP client with all REST endpoints |
| `auth` | Klever wallet signing and envelope construction |
| `ws` | WebSocket real-time subscription client |
| `types` | All shared types (Envelope, Channel, User, etc.) |
| `error` | SDK error types |

## License

MIT
