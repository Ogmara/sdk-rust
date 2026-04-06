# Building the Ogmara Rust SDK

## Prerequisites

- **Rust** 1.70+ (via [rustup](https://rustup.rs/))
- System packages: `build-essential pkg-config libssl-dev`

## Build

```bash
git clone https://github.com/Ogmara/sdk-rust.git
cd sdk-rust
cargo build
```

## Test

```bash
cargo test
```

All tests are unit tests (no network access required).

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ogmara-sdk = { git = "https://github.com/Ogmara/sdk-rust.git" }
```

```rust
use ogmara_sdk::{OgmaraClient, Config};

let client = OgmaraClient::new(Config {
    node_url: "https://ogmara.org".into(),
    ..Default::default()
});

let health = client.health().await?;
let channels = client.list_channels(1, 20).await?;
```

See `src/lib.rs` doc comments for full API reference.
