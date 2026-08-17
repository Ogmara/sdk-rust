//! Device encryption keys (E2E P0, protocol §2.4). Mirrors sdk-js `encryption.ts`
//! byte-for-byte (shared cross-impl test vector below).
//!
//! Each device holds an X25519 *encryption* keypair, distinct from its Ed25519
//! signing key and the wallet key. The wallet authorizes the binding by signing a
//! canonical claim string (browser/K5 wallets can only `signMessage`), so senders
//! can later wrap message keys to every device of a recipient.

use serde::Serialize;
use sha3::{Digest, Keccak256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::SdkError;

const KLEVER_MSG_PREFIX: &[u8] = b"\x17Klever Signed Message:\n";

/// A device X25519 encryption keypair. The private key never leaves the device.
pub struct DeviceEncKeypair {
    /// 32-byte X25519 secret key. Persist in the device vault; never transmit.
    pub private_key: [u8; 32],
    /// 32-byte X25519 public key, hex-encoded. Bound to the wallet and published.
    pub public_key_hex: String,
}

/// Generate a fresh device X25519 encryption keypair.
pub fn generate_device_enc_keypair() -> DeviceEncKeypair {
    let secret = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = PublicKey::from(&secret);
    DeviceEncKeypair {
        private_key: secret.to_bytes(),
        public_key_hex: hex::encode(public.as_bytes()),
    }
}

/// Recover the public key hex from a stored 32-byte X25519 secret key.
pub fn enc_public_key_hex(private_key: &[u8; 32]) -> String {
    let secret = StaticSecret::from(*private_key);
    hex::encode(PublicKey::from(&secret).as_bytes())
}

/// Klever message hash (`0x17` + prefix + ascii(len) + msg → Keccak-256) — the
/// preimage the wallet signs over with Ed25519. Matches l2-node `klever_message_hash`.
pub fn klever_message_hash(message: &[u8]) -> [u8; 32] {
    let len = message.len().to_string();
    let mut data = Vec::with_capacity(KLEVER_MSG_PREFIX.len() + len.len() + message.len());
    data.extend_from_slice(KLEVER_MSG_PREFIX);
    data.extend_from_slice(len.as_bytes());
    data.extend_from_slice(message);
    Keccak256::digest(&data).into()
}

fn hex_to_64(s: &str) -> Result<[u8; 64], SdkError> {
    let bytes = hex::decode(s).map_err(|e| SdkError::InvalidKey(format!("hex: {}", e)))?;
    if bytes.len() != 64 {
        return Err(SdkError::InvalidKey(format!(
            "expected 64 signature bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Normalize a wallet `signMessage` return into the 64 raw Ed25519 signature bytes.
/// The Klever Extension returns 128-char hex; K5 returns base64-of-hex; some return
/// base64 of the raw bytes. Downstream code MUST use these canonical bytes so any
/// signature-derived value reproduces across wallets. See sdk-js `normalizeWalletSig`.
pub fn normalize_wallet_sig(sig: &str) -> Result<[u8; 64], SdkError> {
    use base64::Engine;
    // 1. raw 128-char hex (Klever Extension)
    if sig.len() == 128 && sig.bytes().all(|b| b.is_ascii_hexdigit()) {
        return hex_to_64(sig);
    }
    // 2. base64 wrapping
    if let Ok(bin) = base64::engine::general_purpose::STANDARD.decode(sig) {
        // 2a. base64 of the raw 64 signature bytes
        if bin.len() == 64 {
            let mut out = [0u8; 64];
            out.copy_from_slice(&bin);
            return Ok(out);
        }
        // 2b. base64 of an ASCII hex string (K5, double-encoded)
        if bin.len() == 128 && bin.iter().all(|b| b.is_ascii_hexdigit()) {
            if let Ok(hex_str) = std::str::from_utf8(&bin) {
                return hex_to_64(hex_str);
            }
        }
    }
    Err(SdkError::InvalidKey(
        "could not interpret wallet signature".into(),
    ))
}

/// Decode a bech32 address (`klv1…`/`ogd1…`) to its 32-byte Ed25519 public key.
pub fn address_to_pubkey(address: &str) -> Result<[u8; 32], SdkError> {
    let (_hrp, data) =
        bech32::decode(address).map_err(|e| SdkError::InvalidKey(format!("bech32: {}", e)))?;
    if data.len() != 32 {
        return Err(SdkError::InvalidKey(format!(
            "expected 32-byte pubkey, got {}",
            data.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&data);
    Ok(out)
}

/// Canonical claim the WALLET signs to bind a device encryption key (§2.4).
/// `network` binds the claim to a single Klever network (audit 2026-08-16 C1
/// follow-up — this signature is the sole authority and never covers a
/// msg_id, so it needs its own network binding).
pub fn enc_bind_claim(
    network: &str,
    enc_pub_hex: &str,
    device_id_hex: &str,
    wallet: &str,
    ts: u64,
) -> String {
    format!(
        "ogmara-enc-bind:{}:{}:{}:{}:{}",
        network,
        enc_pub_hex.to_lowercase(),
        device_id_hex.to_lowercase(),
        wallet,
        ts
    )
}

/// Canonical claim the WALLET signs to revoke a device encryption key (§2.4).
/// See [`enc_bind_claim`] for `network`.
pub fn enc_revoke_claim(network: &str, enc_pub_hex: &str, wallet: &str, ts: u64) -> String {
    format!(
        "ogmara-enc-revoke:{}:{}:{}:{}",
        network,
        enc_pub_hex.to_lowercase(),
        wallet,
        ts
    )
}

#[derive(Serialize)]
struct BindPayload {
    device_id: String,
    enc_pub: String,
}

#[derive(Serialize)]
struct RevokePayload {
    enc_pub: String,
}

/// Wire form of a wallet-authored enc envelope. Serialized with `to_vec_named`
/// (MessagePack map with string keys) to match the JS client and the node.
#[derive(Serialize)]
struct EncEnvelopeWire<'a> {
    version: u8,
    msg_type: &'a str,
    msg_id: [u8; 32],
    author: &'a str,
    timestamp: u64,
    lamport_ts: u64,
    payload: Vec<u8>,
    signature: Vec<u8>,
    relay_path: Vec<String>,
}

/// Compute a message ID (protocol v2, audit 2026-08-16 C1):
/// `Keccak-256(network_len(1) + network + author_pubkey + payload + timestamp)`.
/// Mirrors `WalletSigner::compute_msg_id` (auth.rs) and sdk-js's
/// `computeMsgIdForAuthor` — must never drift apart.
fn compute_msg_id_for_author(
    network: &str,
    author_pubkey: &[u8; 32],
    payload: &[u8],
    ts: u64,
) -> [u8; 32] {
    let network_bytes = network.as_bytes();
    let mut data = Vec::with_capacity(1 + network_bytes.len() + 32 + payload.len() + 8);
    data.push(network_bytes.len() as u8);
    data.extend_from_slice(network_bytes);
    data.extend_from_slice(author_pubkey);
    data.extend_from_slice(payload);
    data.extend_from_slice(&ts.to_be_bytes());
    Keccak256::digest(&data).into()
}

fn build_enc_envelope(
    msg_type: &str,
    wallet: &str,
    payload: Vec<u8>,
    sig: [u8; 64],
    ts: u64,
    network: &str,
) -> Result<Vec<u8>, SdkError> {
    // WALLET-authored: author = wallet, msg_id keyed to the wallet pubkey, signature
    // is the wallet's Klever-message signature over the canonical claim.
    let msg_id = compute_msg_id_for_author(network, &address_to_pubkey(wallet)?, &payload, ts);
    let env = EncEnvelopeWire {
        version: crate::types::PROTOCOL_VERSION,
        msg_type,
        msg_id,
        author: wallet,
        timestamp: ts,
        lamport_ts: 0,
        payload,
        signature: sig.to_vec(),
        relay_path: vec![],
    };
    rmp_serde::to_vec_named(&env).map_err(|e| SdkError::MsgPack(e.to_string()))
}

/// Build a wallet-authored `DeviceEncBinding` (0x36) envelope. `sig` is the wallet's
/// 64-byte Klever-message signature over [`enc_bind_claim`] (run it through
/// [`normalize_wallet_sig`] first if it came from an external wallet as a string).
///
/// `network` ("testnet"/"mainnet", e.g. from the client's cached `/health`
/// binding) binds both the envelope's msg_id AND — since the caller built
/// `sig` externally — MUST be the exact same value passed to
/// [`enc_bind_claim`] when the claim was signed (audit 2026-08-16 C1);
/// required since this builder has no client/signer object to resolve it
/// from.
pub fn build_device_enc_binding(
    wallet: &str,
    enc_pub_hex: &str,
    device_id_hex: &str,
    sig: [u8; 64],
    ts: u64,
    network: &str,
) -> Result<Vec<u8>, SdkError> {
    let payload = rmp_serde::to_vec_named(&BindPayload {
        device_id: device_id_hex.to_lowercase(),
        enc_pub: enc_pub_hex.to_lowercase(),
    })
    .map_err(|e| SdkError::MsgPack(e.to_string()))?;
    build_enc_envelope("DeviceEncBinding", wallet, payload, sig, ts, network)
}

/// Build a wallet-authored `DeviceEncRevoke` (0x37) envelope. See
/// [`build_device_enc_binding`] for the `network` parameter.
pub fn build_device_enc_revoke(
    wallet: &str,
    enc_pub_hex: &str,
    sig: [u8; 64],
    ts: u64,
    network: &str,
) -> Result<Vec<u8>, SdkError> {
    let payload = rmp_serde::to_vec_named(&RevokePayload {
        enc_pub: enc_pub_hex.to_lowercase(),
    })
    .map_err(|e| SdkError::MsgPack(e.to_string()))?;
    build_enc_envelope("DeviceEncRevoke", wallet, payload, sig, ts, network)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn normalize_wallet_sig_variants() {
        let raw: [u8; 64] = core::array::from_fn(|i| (i as u8).wrapping_mul(7));
        let hex = hex::encode(raw);
        use base64::Engine;
        let b64_hex = base64::engine::general_purpose::STANDARD.encode(hex.as_bytes());
        let b64_raw = base64::engine::general_purpose::STANDARD.encode(raw);
        assert_eq!(normalize_wallet_sig(&hex).unwrap(), raw);
        assert_eq!(normalize_wallet_sig(&b64_hex).unwrap(), raw); // K5
        assert_eq!(normalize_wallet_sig(&b64_raw).unwrap(), raw);
        assert!(normalize_wallet_sig("garbage!!").is_err());
    }

    #[test]
    fn enc_keypair_public_reproducible() {
        let kp = generate_device_enc_keypair();
        assert_eq!(kp.public_key_hex.len(), 64);
        assert_eq!(enc_public_key_hex(&kp.private_key), kp.public_key_hex);
    }

    // CROSS-IMPL VECTOR — identical literals are asserted in sdk-js
    // `encryption.test.ts`. Wallet private key = bytes 0x01..0x20,
    // network = "testnet" (audit 2026-08-16 C1 — msg_id is now network-bound).
    // Any byte-drift between the two SDKs (or vs the L2 node) breaks one of
    // these suites.
    #[test]
    fn cross_impl_vector_matches_sdk_js() {
        let priv_bytes: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
        let sk = SigningKey::from_bytes(&priv_bytes);
        let signer = crate::auth::WalletSigner::from_private_key(&priv_bytes).unwrap();
        let wallet = signer.address();
        assert_eq!(
            wallet,
            "klv10x64vt50ue20jsrckyfw32vt57gplpf6u62ma4lquwgshtgyjejq9d4x8v"
        );

        let enc_pub = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let device_id = "aabbccddeeff0011223344556677889900112233445566778899aabbccddeeff";
        let ts: u64 = 1_717_958_400_000;

        // Sign the canonical claim in Klever message format (deterministic Ed25519).
        let claim = enc_bind_claim("testnet", enc_pub, device_id, wallet, ts);
        let sig = sk.sign(&klever_message_hash(claim.as_bytes())).to_bytes();
        assert_eq!(
            hex::encode(sig),
            "cb6056cd0ad6b4fb1bcd29f104733f21ae5decb8d365a7dfb530671349a28006d92bdb2f82bbd20e5a236fc8d2c8ddcf073afc171c0fef80174ea29e74de470a"
        );

        // Payload bytes (and thus msg_id) must match the JS @msgpack map encoding.
        let payload = rmp_serde::to_vec_named(&BindPayload {
            device_id: device_id.to_string(),
            enc_pub: enc_pub.to_string(),
        })
        .unwrap();
        let msg_id = compute_msg_id_for_author(
            "testnet",
            &address_to_pubkey(wallet).unwrap(),
            &payload,
            ts,
        );
        assert_eq!(
            hex::encode(msg_id),
            "4c9a58d20d839495766428e144641a6d0a94213e7bc604d030d5c7053138e99e"
        );

        // The full builder runs without error.
        assert!(build_device_enc_binding(wallet, enc_pub, device_id, sig, ts, "testnet").is_ok());
    }
}
